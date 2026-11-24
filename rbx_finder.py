#!/usr/bin/env python3
"""
RBX-Finder / ORC V2 — Universal Multi-Binary Analyzer, Offset Dumper & Candidate Ledger
High-Performance, Zero-Dependency Core with Optional Capstone/pyelftools Acceleration.
Supports raw .so files, directories of shared libraries, and direct APK/ZIP archives.
Includes .eh_frame_hdr exact boundary resolution, interactive probes, and candidate ledger.
"""
from __future__ import annotations

import argparse
import bisect
import csv
import enum
import hashlib
import json
import mmap
import os
import re
import shutil
import signal
import struct
import sys
import tempfile
import threading
import time
import zipfile
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple

# ============================================================
# OPTIONAL ACCELERATION LIBRARIES (Graceful Fallback)
# ============================================================

try:
    from capstone import (
        Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_64,
        CS_OP_REG, CS_OP_IMM, CS_OP_MEM,
    )
    from capstone.arm64 import (
        ARM64_INS_ADD, ARM64_INS_ADR, ARM64_INS_ADRP, ARM64_INS_LDR,
        ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG,
    )
    from capstone.x86 import X86_OP_MEM, X86_REG_RIP
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    Cs = None

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    HAS_PYELFTOOLS = True
except ImportError:
    HAS_PYELFTOOLS = False
    ELFFile = None
    SymbolTableSection = None

# ============================================================
# VERSION & CONSTANTS
# ============================================================

VERSION = "2.0.0"
CODENAME = "orc-multibin"
BUILD_NAME = "V2-Ledger"

STATUSES = {"needs_review", "confirmed", "rejected", "live", "unresolved"}
CONFIDENCES = {"high", "medium", "low"}
KINDS = {"address", "data", "engine", "layout", "export", "jni"}

MARKER_MIN_LEN_DEFAULT = 4
SIG_LENGTH = 32
EM_X86_64 = 62
EM_AARCH64 = 183
EM_ARM = 40
EM_386 = 3

_MACHINE_BY_NAME = {
    "EM_386": 0x03, "EM_X86_64": 0x3E, "EM_ARM": 0x28,
    "EM_AARCH64": 0xB7, "EM_MIPS": 0x08, "EM_RISCV": 0xF3,
}

# ============================================================
# ENUMS & DATA MODELS
# ============================================================

class ExitCode(enum.IntEnum):
    OK = 0
    USER_CANCEL = 1
    BAD_INPUT = 2
    BAD_ELF = 3
    BAD_ARCH = 4
    MISSING_DEP = 5
    SCAN_FAILED = 6
    OUT_WRITE_FAILED = 7
    INTERRUPTED = 130

class SpeedMode(enum.Enum):
    FAST = "fast"
    NORMAL = "normal"
    DEEP = "deep"
    PARANOID = "paranoid"

class OutputFormat(enum.Enum):
    JSON = "json"
    JSONL = "jsonl"
    SQLITE = "sqlite"
    CSV = "csv"

class ELFArch(enum.Enum):
    UNKNOWN = "unknown"
    I386 = "i386"
    X86_64 = "x86_64"
    ARM32 = "arm32"
    AARCH64 = "aarch64"
    MIPS = "mips"
    RISCV = "riscv"

_ARCH_BY_MACHINE = {
    0x03: ELFArch.I386, 0x3E: ELFArch.X86_64,
    0x28: ELFArch.ARM32, 0xB7: ELFArch.AARCH64,
}

@dataclass
class Section:
    name: str
    file_offset: int
    va: int
    size: int
    flags: int

@dataclass
class ELFInfo:
    path: Path
    size: int
    arch: ELFArch
    is_64: bool
    is_little_endian: bool
    ptr_size: int
    sections: Dict[str, Section]
    text_sha256: str = ""
    rodata_sha256: str = ""
    relro_sha256: str = ""
    build_id: str = ""
    sym_by_va: Dict[int, str] = field(default_factory=dict)
    vtable_syms: Dict[int, str] = field(default_factory=dict)
    typeinfo_syms: Dict[int, str] = field(default_factory=dict)
    function_starts: List[int] = field(default_factory=list)

@dataclass
class MarkerHit:
    name: str
    text: str
    section: str
    string_va: int
    file_offset: int
    binary: str = ""

@dataclass
class XrefEntry:
    target_va: int
    insn_va: int
    kind: str
    func_va: Optional[int] = None

@dataclass
class ResolvedHit:
    name: str
    marker: str
    section: str
    string_va: int
    xref_insn: int
    xref_kind: str
    func_start: Optional[int] = None
    func_name: Optional[str] = None
    callers: List[int] = field(default_factory=list)
    sig: Optional[str] = None
    binary: str = ""

@dataclass
class VTableMethod:
    index: int
    va: int
    name: Optional[str] = None

@dataclass
class VTableInfo:
    class_name: str
    vtable_va: int
    typeinfo_va: Optional[int] = None
    methods: List[VTableMethod] = field(default_factory=list)
    source: str = "rtti"
    binary: str = ""

    @property
    def method_count(self) -> int:
        return len(self.methods)

@dataclass
class StructField:
    offset: int
    kinds: List[str] = field(default_factory=list)

@dataclass
class StructInfo:
    class_name: str
    ctor_va: Optional[int] = None
    fields: List[StructField] = field(default_factory=list)
    binary: str = ""

@dataclass
class CandidateItem:
    name: str
    binary: str
    kind: str
    value: Optional[str]
    confidence: str
    method: str
    evidence: List[str]
    alternatives: List[Dict[str, str]] = field(default_factory=list)
    status: str = "needs_review"
    review: Dict[str, str] = field(default_factory=lambda: {"note": "", "by": "", "at": ""})
    live: Dict[str, str] = field(default_factory=lambda: {"check": "", "result": ""})
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> OrderedDict:
        return OrderedDict([
            ("name", self.name),
            ("binary", self.binary),
            ("kind", self.kind),
            ("value", self.value),
            ("confidence", self.confidence),
            ("method", self.method),
            ("evidence", list(self.evidence)),
            ("alternatives", list(self.alternatives)),
            ("status", self.status),
            ("review", OrderedDict(self.review)),
            ("live", OrderedDict(self.live)),
            ("raw", self.raw),
        ])

@dataclass
class BinaryAnalysisResult:
    binary_name: str
    path: Path
    size: int
    arch: str
    build_id: str
    sections: Dict[str, Dict[str, Any]]
    function_starts_count: int
    exports: Dict[str, int] = field(default_factory=dict)
    jni_methods: Dict[str, int] = field(default_factory=dict)
    imported_symbols: List[str] = field(default_factory=list)
    markers: List[MarkerHit] = field(default_factory=list)
    resolved: Dict[str, List[ResolvedHit]] = field(default_factory=dict)
    vtables: Dict[str, VTableInfo] = field(default_factory=dict)
    structs: Dict[str, StructInfo] = field(default_factory=dict)
    candidates: List[CandidateItem] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)

@dataclass
class MultiBinaryResult:
    target: Path
    scanned_at: str
    elapsed_sec: float = 0.0
    libraries: Dict[str, BinaryAnalysisResult] = field(default_factory=dict)
    combined_candidates: List[CandidateItem] = field(default_factory=list)
    cross_links: Dict[str, Any] = field(default_factory=dict)
    stats: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

DEFAULT_SIGNATURES = json.loads('{\n  "meta": {\n    "target": "Roblox Android ARM64 / x86_64",\n    "note": "string markers used for signature scanning; some names appear encrypted/obfuscated in newer builds"\n  },\n  "strings": [\n    {"name": "print", "markers": ["Invalid password from %s", "Current identity is %d"], "aliases": ["printidentity"]},\n    {"name": "printidentity", "markers": ["Current identity is %d"]},\n    {"name": "ongameloaded", "markers": ["onGameLoaded() SessionReporterState_GameLoaded placeId:%lld"]},\n    {"name": "ongameleave", "markers": ["onGameLeaveBegin() SessionReporterState_GameExitRequested placeId:%lld"]},\n    {"name": "fireproximityprompt", "markers": ["ProximityPrompt_Triggered"]},\n    {"name": "taskdesynchronize", "markers": ["task.desynchronize() may only be called from a script that is a descendant of an Actor"]},\n    {"name": "tasksynchronize", "markers": ["task.synchronize() may only be called from a script that is a descendant of an Actor"]},\n    {"name": "loadstring", "markers": ["loadstring() is not available in RobloxScript"]},\n    {"name": "renderstepped", "markers": ["RenderStepped event can only be used from local scripts"]},\n    {"name": "rbxspawn", "markers": ["Spawn function requires 1 argument", "spawn is not available for AuroraScripts"]},\n    {"name": "rbxcrash", "markers": ["RBXCRASH: {}"]},\n    {"name": "auxresume", "markers": ["too many arguments to resume"]},\n    {"name": "resume", "markers": ["cannot resume dead coroutine"]},\n    {"name": "resume_start", "markers": ["cannot resume non-suspended coroutine"]},\n    {"name": "createvm", "markers": ["Failed to create Lua state"]},\n    {"name": "enumgco", "markers": ["thread at %s:%d %s"]},\n    {"name": "t_unpack", "markers": ["too many results to unpack"]},\n    {"name": "createplayer", "markers": ["StreamQoSCookie"]},\n    {"name": "collectgarbage", "markers": ["collectgarbage must be called with \'count\'; use gcinfo() instead"]},\n    {"name": "getfield", "markers": ["field \'%s\' missing in date table"]},\n    {"name": "renderjobconstructor", "markers": ["[FLog::SurfaceController] SurfaceController::RenderJob"]},\n    {"name": "scriptcontextspawn", "markers": ["ScriptContext is null"]},\n    {"name": "scriptcontextstartscript", "markers": ["[FLog::ScriptContextAdd] LoaderFacet::addScript -- %s"]},\n    {"name": "scriptcontexttaskqueue", "markers": ["ScriptContextTaskQueue"]},\n    {"name": "scriptcontextresumescript", "markers": ["Can\'t resume script in this context"]},\n    {"name": "networkclient", "markers": ["[FLog::Network] NetworkClient:Remove"]},\n    {"name": "replicator", "markers": ["[FLog::Network] Replicator destroyed: %p"]},\n    {"name": "luaL_register", "markers": ["name conflict for module \'%s\'"]},\n    {"name": "luaL_checkstack", "markers": ["stack overflow (%s)"]},\n    {"name": "luaL_checkoption", "markers": ["missing argument #%d"]},\n    {"name": "luaU_deserialize", "markers": ["%s: bytecode version mismatch (expected [%d..%d], got %d)"]},\n    {"name": "luaU_watchdog", "markers": ["LuauWatchdog"]},\n    {"name": "luaU_parse", "markers": ["Cannot use \'...\' outside of a vararg function"]},\n    {"name": "luaM_toobig", "markers": ["memory allocation error: block too big"]},\n    {"name": "lua_getfunc", "markers": ["no function environment for tail call at level %d"]},\n    {"name": "luaH_newkey", "markers": ["table index is nil"]},\n    {"name": "luaH_next", "markers": ["invalid key to \'next\'"]},\n    {"name": "luaG_indexerror", "markers": ["this %s does not have a key named \'%s\'"]},\n    {"name": "luaG_typeerror", "markers": ["attempt to %s a %s value"]},\n    {"name": "luaG_namecallerror", "markers": ["attempt to call missing method \'%s\' of %s"]},\n    {"name": "luaG_readonlyerror", "markers": ["attempt to modify a readonly table"]},\n    {"name": "luaG_forerror", "markers": ["invalid \'for\' %s (number expected, got %s)"]},\n    {"name": "luaG_concaterror", "markers": ["attempt to concatenate %s with %s"]},\n    {"name": "luaG_aritherror", "markers": ["attempt to perform arithmetic (%s) on %s and %s"]},\n    {"name": "luaG_ordererror", "markers": ["attempt to compare %s %s %s"]},\n    {"name": "luaG_tableindexerror", "markers": ["table index contains NaN"]},\n    {"name": "luaV_dolen", "markers": ["\'__len\' must return a number"]},\n    {"name": "luaV_concat", "markers": ["string length overflow"]},\n    {"name": "luaV_settable", "markers": ["\'__newindex\' chain too long; possible loop"]},\n    {"name": "luaL_argerrorL", "markers": ["invalid argument #%d to \'%s\' (%s)"]},\n    {"name": "luaB_setfenv", "markers": ["\'setfenv\' cannot change environment of given object"]},\n    {"name": "luaB_rawlen", "markers": ["table or string expected"]},\n    {"name": "luaB_assert", "markers": ["assertion failed!"]},\n    {"name": "luaB_setmetatable", "markers": ["cannot change a protected metatable"]},\n    {"name": "luaB_newproxy", "markers": ["nil or boolean"]},\n    {"name": "luaL_tostring", "markers": ["\'__tostring\' must return a string"]},\n    {"name": "luaL_typeerrorL", "markers": ["invalid argument #%d to \'%s\' (%s expected, got %s)"]},\n    {"name": "luaL_typeerrorarg", "markers": ["invalid argument #%d (%s expected, got %s)"]},\n    {"name": "luaopen_base", "markers": ["ipairs", "xpcall", "pcall"]},\n    {"name": "luaopen_integer", "markers": ["maxsigned"]},\n    {"name": "luaD_checkCstack", "markers": ["C stack overflow"]},\n    {"name": "luaD_seterrorobj", "markers": ["error in error handling"]},\n    {"name": "lua_codegencompile", "markers": ["Memory allocation limit reached for native code generation"]},\n    {"name": "pushbehaviorobject", "markers": ["InvalidInstance"]},\n    {"name": "pushinstance", "markers": ["Unable to parent new Instance during parallel execution."]},\n    {"name": "enableloadmodule", "markers": ["EnableLoadModule"]},\n    {"name": "fireserver", "markers": ["FireServer can only be called from the client"]},\n    {"name": "firesignal", "markers": ["[FLog::LuaBridge] Executing Luau from signal, execution depth: %u"]},\n    {"name": "invokeserver", "markers": ["InvokeServer can only be called from the client"]},\n    {"name": "fireallclients", "markers": ["FireAllClients can only be called from the server"]},\n    {"name": "invokeclient", "markers": ["InvokeClient can only be called from the server"]},\n    {"name": "ispropertyvalueequalto", "markers": ["Unable to query property {}. It is not scriptable"]},\n    {"name": "MarketplaceService_PromptPremiumPurchase", "markers": ["Can only call PromptPremiumPurchase from LocalScript on the local player"]},\n    {"name": "HttpService_validateUrl", "markers": ["The \\"..\\" string is not allowed in the URL path for Roblox resources!"]},\n    {"name": "debug.getinfo", "markers": ["no function environment for tail call at level %d"]},\n    {"name": "requiremodulescript", "markers": ["require() should not be called on a destroyed ModuleScript"]},\n    {"name": "physicssendermaxbandwidthbps", "markers": ["PhysicsSenderMaxBandwidthBps"]},\n    {"name": "taskschedulerjobstart", "markers": ["[FLog::TaskSchedulerRun] JobStart %s"]},\n    {"name": "taskschedulerjobstop", "markers": ["[FLog::TaskSchedulerRun] JobStop %s"]},\n    {"name": "taskschedulerjob_job", "markers": ["[FLog::TaskSchedulerInit] Job Created"]},\n    {"name": "taskschedulerinit", "markers": ["Can\'t initialize the TaskScheduler before flags have been loaded"]},\n    {"name": "taskschedulerstep", "markers": ["nameAssigner"]},\n    {"name": "scriptsignalconnect", "markers": ["Expected function, got {}"]},\n    {"name": "setfflag", "markers": ["[FLog::FastLogValueChanged] Setting variable {}"]},\n    {"name": "getdetailsforbundle", "markers": ["Data Model is currently unavailable"]},\n    {"name": "registerdeprecatedglobals", "markers": ["printidentity"]},\n    {"name": "registerdatamodelinstances", "markers": ["LuauExecutionTaskInput"]},\n    {"name": "string.format", "markers": ["invalid format (repeated flags)"]},\n    {"name": "connectparallel", "markers": ["Function Event.ConnectParallel is not safe to call in parallel"]},\n    {"name": "debug.loadmodule", "markers": ["debug.loadmodule is not enabled", "Attempted to call loadmodule with invalid argument(s)"]},\n    {"name": "debug.profilebegin", "markers": ["debug.profilebegin(string) parameter must be string"]},\n    {"name": "debug.profileend", "markers": ["debug.profileEnd() - No active profile annotation"]},\n    {"name": "fixedarrayindex", "markers": ["Attempted to index fixed array with string key \'%s\'"]},\n    {"name": "checkmodulescriptawaitingthread", "markers": ["ModuleScript cannot resume non-suspended awaiting coroutine"]},\n    {"name": "setuptaskcallbackthread", "markers": ["cannot %s non-suspended coroutine with arguments"]},\n    {"name": "iropcodemap", "markers": ["BITXOR_INT64"]},\n    {"name": "shouldrunscript", "markers": ["Cannot start server script \'%s\' (lacking capability RunServerScript)"]},\n    {"name": "waitforchild", "markers": [":WaitForChild(\\"", "illegal argument #2 (timeOut must be greater than 0)"]},\n    {"name": "setscripttimeout", "markers": ["[FLog::ScriptContext] Set lua time out: %d"]},\n    {"name": "setparentinternal", "markers": ["[FLog::InstanceTreeManipulation] Instance %p: Setting parent to: %p. Old parent: %p"]},\n    {"name": "cansetparent", "markers": ["trying to set locked parent!"]},\n    {"name": "playerverifysetparent", "markers": ["Parent of Player can not be changed"]},\n    {"name": "binarymodelparserdeser", "markers": ["Invalid parent id %d/%zu while deserializing parents"]},\n    {"name": "propertydescriptordispatchset", "markers": ["Unable to assign property %s. It is not scriptable"]},\n    {"name": "sandboxcheck", "markers": ["The current thread cannot {} \'{}\' since \'{}\' has the Sandboxed property set to false"]},\n    {"name": "vmcollectionfaceit", "markers": ["[FLog::ScriptContextClose] VmCollectionFacet::~VmCollectionFacet -- state thread count %zu"]},\n    {"name": "unknownbullshi", "markers": ["Unexpected type in script compilation cache."]},\n    {"name": "waitinghybridscriptsjobstep", "markers": ["threadTime=%.3fms"]},\n    {"name": "rbxthreadconstructor", "markers": ["-Kernel,18", "-Kernel,19"]},\n    {"name": "humanoiddescriptiondeser", "markers": ["[FLog::Error] Failed to deserialize any instances."]},\n    {"name": "reloadmodulescript", "markers": ["syntax error: %s"]},\n    {"name": "heartbeatjob", "markers": ["[FLog::DataModelJobs] Heartbeat start, data model: %p"]},\n    {"name": "physicsjob", "markers": ["[FLog::DataModelJobs] Physics Job start, data model: %p"]},\n    {"name": "gcstep", "markers": ["[FLog::DataModelJobs] GC step start, data model: %p"]},\n    {"name": "genericjobastep", "markers": ["[FLog::TaskSchedulerRun] GenericJob::Step dataModel(%d) type(%d) taskCount(%d)"]},\n    {"name": "securitycapability", "markers": ["CreateInstances"]},\n    {"name": "dodatamodelsetup", "markers": ["[FLog::CloseDataModel] DataModel created: %p", "[FLog::CloseDataModel] DataModel created: {}"]},\n    {"name": "datamodelclearcontent", "markers": ["[FLog::CloseDataModel] Closing Script Context"]},\n    {"name": "datamodelinitcontents", "markers": ["[DFLog::SlimServiceLog] Creating SLIM service"]},\n    {"name": "rbxdebuglib", "markers": ["GetUpvalues"]},\n    {"name": "nativegetfflag", "markers": ["nativeGetFFlag: %s"]},\n    {"name": "nativeregisterfflag", "markers": ["nativeRegisterFFlag: %s, providerId: %d"]},\n    {"name": "nativedatamodelinit", "markers": ["[FLog::NativeDM] initialize: state:"]},\n    {"name": "surfacecontrollerrun", "markers": ["[FLog::SurfaceController] data model was null during SurfaceController::run()"]},\n    {"name": "renderviewbindworkspace", "markers": ["[FLog::ViewRbxInit] BindWorkspace, new datamodel %p, old datamodel: %p"]},\n    {"name": "diagnosticsinit", "markers": ["JobCount"]},\n    {"name": "setsandboxed", "markers": ["Sandboxed cannot be changed on a %s"]},\n    {"name": "onheartbeat", "markers": ["APSToGlobalAllocator"]},\n    {"name": "processremoteevent", "markers": ["Cheating/Exploiting"]},\n    {"name": "telemetryaddfield", "markers": ["_from_uint64_overflow"]},\n    {"name": "task_scheduler", "markers": ["TaskScheduler::Job: "]},\n    {"name": "opcode_encode_table", "markers": ["%s: bytecode corrupted"]},\n    {"name": "class_descriptor_hashmap", "markers": ["FindFirstChildOfClass"]},\n    {"name": "task_defer", "markers": ["task.defer is not available for AuroraScripts"]},\n    {"name": "get_current_thread_id", "markers": ["World::assemble - current thread should have a write lock when assembling the world"]},\n    {"name": "get_script_context", "markers": ["LuaAppExperienceController: EnableLuaAppScriptErrorListener is enabled"]},\n    {"name": "luavm_load", "markers": ["syntax error: %s"]},\n    {"name": "luad_throw", "markers": ["stack overflow"]},\n    {"name": "luao_nilobject", "markers": ["Attempt to migrate TracedObjectRef across VM boundary"]},\n    {"name": "get_identity_obj", "markers": ["Current identity is %d", "cannot add a finalizer on a thread from a foreign isolation container"]},\n    {"name": "Workspace", "markers": ["[FLog::GuiTargetData] Workspace created: %p", "InterpolationThrottling"]},\n    {"name": "Datamodel", "markers": ["IsSFFlagsLoaded"]},\n    {"name": "TextChatService", "markers": ["SendTextChatCommandClientSent"]},\n    {"name": "Players", "markers": ["CreateLocalPlayer"]},\n    {"name": "Humanoid", "markers": ["GetAppliedDescription"]},\n    {"name": "HttpService", "markers": ["HttpPostAsync"]},\n    {"name": "ModuleScript", "markers": ["UnrestrictedRequireAllowed"]},\n    {"name": "ScriptContext", "markers": ["AddCoreScriptLocal", "ErrorDetailed"]},\n    {"name": "GuiService", "markers": ["GuiService"]},\n    {"name": "InsertService", "markers": ["LoadLocalAsset"]},\n    {"name": "SafetyService", "markers": ["[FLog::Safety] Created safety service"]},\n    {"name": "RenderView", "markers": ["[FLog::ViewRbxInit] RenderView created - %p"]},\n    {"name": "Animator", "markers": ["[FLog::ISteppedData] Animator created - %p"]},\n    {"name": "DeviceIntegrityService", "markers": ["MagicLoginEvent"]},\n    {"name": "VirtualInputManager", "markers": ["pointerAction"]},\n    {"name": "data_model_job_id", "markers": ["[DFLog::InternalMessagingService] JobId cannot be empty for Rcc scope."]},\n    {"name": "data_model_game_id", "markers": ["[DFLog::R15Character] DataModel::setUniverseId %lld"]},\n    {"name": "data_model_place_id", "markers": ["InvalidPlaceId"]},\n    {"name": "data_model_creator_id", "markers": ["CreatorId"]},\n    {"name": "securityfiltercapabilities", "markers": [], "patterns": ["48 81 ?? 00 FF FF FF 4? 21 ?? 48 89"]}\n  ],\n  "struct_hints": {\n    "Instance_children_start": "0x78",\n    "Instance_children_end": "0x8",\n    "NameContainer_name": "0x8",\n    "ClassDescriptor_class_name": "0x8",\n    "TaskScheduler_jobs_start": "0xd0",\n    "TaskScheduler_jobs_end": "0xd8",\n    "Arbiter_type": "0x1e8",\n    "scheduler_pointer": "0x6e3a7f0",\n    "scheduler_jobs": "0xd0",\n    "script_job_vtable": "0x63cbea8",\n    "script_job_context": "0x1b0",\n    "instance_parent": "0x38",\n    "instance_name": "0x48",\n    "instance_children": "0x78",\n    "datamodel_instance": "0x1a8",\n    "datamodel_gameid": "0x198",\n    "datamodel_placeid": "0x190",\n    "datamodel_jobid": "0x118",\n    "vm_global_offset": "0x68",\n    "vm_postresume_offset": "0x648",\n    "vm_resume_offset": "0x690",\n    "lua_resume": "0x307defc",\n    "base_identity": "0x3",\n    "execution_identity": "0x8"\n  }\n}\n')

# ============================================================
# .eh_frame_hdr PARSER (Exact Compiler-Generated Function Starts)
# ============================================================

def _uleb(data: bytes, at: int) -> Tuple[int, int]:
    value, shift = 0, 0
    while at < len(data):
        b = data[at]; at += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80): break
        shift += 7
    return value, at

def _sleb(data: bytes, at: int) -> Tuple[int, int]:
    value, shift, b = 0, 0, 0
    while at < len(data):
        b = data[at]; at += 1
        value |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80): break
    if b & 0x40: value |= -(1 << shift)
    return value, at

def _decode_pointer(encoding: int, data: bytes, at: int, field_address: int, datarel_base: int) -> Tuple[Optional[int], int]:
    if encoding == 0xFF: return None, at
    fmt = encoding & 0x0F
    application = encoding & 0x70
    if fmt == 0x00:
        if at + 8 > len(data): raise ValueError("truncated pointer")
        value = struct.unpack_from("<Q", data, at)[0]; at += 8
    elif fmt == 0x01: value, at = _uleb(data, at)
    elif fmt == 0x02: value = struct.unpack_from("<H", data, at)[0]; at += 2
    elif fmt == 0x03: value = struct.unpack_from("<I", data, at)[0]; at += 4
    elif fmt == 0x04: value = struct.unpack_from("<Q", data, at)[0]; at += 8
    elif fmt == 0x09: value, at = _sleb(data, at)
    elif fmt == 0x0A: value = struct.unpack_from("<h", data, at)[0]; at += 2
    elif fmt == 0x0B: value = struct.unpack_from("<i", data, at)[0]; at += 4
    elif fmt == 0x0C: value = struct.unpack_from("<q", data, at)[0]; at += 8
    else: raise ValueError(f"unsupported DW_EH_PE format 0x{fmt:x}")

    if application == 0x10: value += field_address
    elif application == 0x30: value += datarel_base
    return value, at

def parse_eh_frame_hdr(data: bytes, section_address: int) -> List[int]:
    if len(data) < 4 or data[0] != 1: return []
    try:
        ptr_enc, count_enc, table_enc = data[1], data[2], data[3]
        at = 4
        _, at = _decode_pointer(ptr_enc, data, at, section_address + at, section_address)
        count, at = _decode_pointer(count_enc, data, at, section_address + at, section_address)
        if count is None or count > 2_000_000: return []
        starts = []
        for _ in range(int(count)):
            val, at = _decode_pointer(table_enc, data, at, section_address + at, section_address)
            if val is None: break
            starts.append(int(val))
            _, at = _decode_pointer(table_enc, data, at, section_address + at, section_address)
        return sorted(set(starts))
    except Exception:
        return []

def function_start_for(address: int, starts: List[int], prologues: Optional[List[int]] = None) -> Optional[int]:
    if starts:
        idx = bisect.bisect_right(starts, address) - 1
        if idx >= 0 and address - starts[idx] <= 0x40000:
            return starts[idx]
    if prologues:
        for p in reversed(prologues):
            if p <= address and address - p <= 0x2000:
                return p
    return None

# ============================================================
# ZERO-COPY ELF32 / ELF64 PARSER (Pure Python Fallback Engine)
# ============================================================

class PureElfParser:
    PT_LOAD = 1
    PT_DYNAMIC = 2
    PT_NOTE = 4

    def __init__(self, mm: mmap.mmap, size: int):
        self.mm = mm
        self.size = size
        self.is_64 = False
        self.is_little_endian = True
        self.machine = 0
        self.entry = 0
        self.phoff = 0
        self.shoff = 0
        self.phentsize = 0
        self.phnum = 0
        self.shentsize = 0
        self.shnum = 0
        self.shstrndx = 0
        self.sections: List[Section] = []
        self.section_map: Dict[str, Section] = {}
        self.build_id: str = ""
        self.function_starts: List[int] = []

        self._parse_header()
        self._parse_sections()
        self._extract_build_id()

    def _parse_header(self):
        ident = self.mm[:16]
        if ident[:4] != b"\x7fELF":
            raise ValueError("not a valid ELF binary")
        self.is_64 = (ident[4] == 2)
        self.is_little_endian = (ident[5] == 1)
        endian = "<" if self.is_little_endian else ">"
        if self.is_64:
            hdr = struct.unpack_from(endian + "HHIQQQIHHHHHH", self.mm, 16)
            self.machine = hdr[1]
            self.entry = hdr[3]
            self.phoff = hdr[4]
            self.shoff = hdr[5]
            self.phentsize = hdr[8]
            self.phnum = hdr[9]
            self.shentsize = hdr[10]
            self.shnum = hdr[11]
            self.shstrndx = hdr[12]
        else:
            hdr = struct.unpack_from(endian + "HHIIIIIHHHHHH", self.mm, 16)
            self.machine = hdr[1]
            self.entry = hdr[3]
            self.phoff = hdr[4]
            self.shoff = hdr[5]
            self.phentsize = hdr[8]
            self.phnum = hdr[9]
            self.shentsize = hdr[10]
            self.shnum = hdr[11]
            self.shstrndx = hdr[12]

    def _parse_sections(self):
        if self.shoff == 0 or self.shnum == 0:
            return
        endian = "<" if self.is_little_endian else ">"
        shstr_off = self.shoff + self.shstrndx * self.shentsize
        if self.is_64:
            shstr_data = struct.unpack_from(endian + "IIQQQQIIQQ", self.mm, shstr_off)
            shstr_file_off = shstr_data[4]
        else:
            shstr_data = struct.unpack_from(endian + "IIIIIIIIII", self.mm, shstr_off)
            shstr_file_off = shstr_data[4]

        raw_sections = []
        for i in range(self.shnum):
            off = self.shoff + i * self.shentsize
            if off + self.shentsize > self.size: break
            fmt = endian + ("IIQQQQIIQQ" if self.is_64 else "IIIIIIIIII")
            s = struct.unpack_from(fmt, self.mm, off)
            raw_sections.append(s)

        for s in raw_sections:
            name_idx = s[0]
            name = ""
            if shstr_file_off < self.size:
                start = shstr_file_off + name_idx
                end = self.mm.find(b"\0", start)
                if end != -1:
                    name = self.mm[start:end].decode("ascii", errors="ignore")
            sec = Section(name=name, flags=s[2], va=s[3], file_offset=s[4], size=s[5])
            self.sections.append(sec)
            if name:
                self.section_map[name] = sec
                if name == ".eh_frame_hdr":
                    hdr_bytes = self.mm[sec.file_offset:sec.file_offset + sec.size]
                    self.function_starts = parse_eh_frame_hdr(hdr_bytes, sec.va)

    def _extract_build_id(self):
        self.build_id = extract_gnu_build_id(self.mm)

def extract_gnu_build_id(mm: mmap.mmap) -> str:
    idx = 0
    while True:
        idx = mm.find(b"GNU\0", idx)
        if idx == -1: break
        if idx >= 12:
            namesz, descsz, ntype = struct.unpack_from("<III", mm, idx - 12)
            if namesz == 4 and ntype == 3 and 16 <= descsz <= 64:
                desc = mm[idx + 4 : idx + 4 + descsz]
                return desc.hex()
        idx += 4
    return ""

def _normalize_machine(m: Any) -> int:
    if isinstance(m, int): return m
    if isinstance(m, str): return _MACHINE_BY_NAME.get(m, 0)
    v = getattr(m, "value", None)
    return v if isinstance(v, int) else 0

# ============================================================
# ARCHIVE & DIRECTORY RESOLVER
# ============================================================

def resolve_binaries_target(path: Path, all_libs: bool = True) -> Tuple[List[Path], Optional[Path]]:
    if not path.exists():
        raise InputError(f"target path not found: {path}")

    # Case 1: Directory containing .so files
    if path.is_dir():
        so_files = sorted(list(path.glob("**/*.so")))
        if not so_files:
            raise InputError(f"no .so shared libraries found in directory: {path}")
        return so_files, None

    # Case 2: APK / ZIP Archive
    if path.suffix.lower() in (".apk", ".zip", ".xapk", ".apks") or zipfile.is_zipfile(path):
        temp_dir = Path(tempfile.mkdtemp(prefix="rbx_multibin_"))
        extracted_libs = []
        with zipfile.ZipFile(path, "r") as zf:
            all_names = zf.namelist()
            # Prioritize arm64-v8a
            arm64_libs = [n for n in all_names if n.startswith("lib/arm64-v8a/") and n.endswith(".so")]
            x86_libs = [n for n in all_names if n.startswith("lib/x86_64/") and n.endswith(".so")]
            arm32_libs = [n for n in all_names if n.startswith("lib/armeabi-v7a/") and n.endswith(".so")]
            selected = arm64_libs or x86_libs or arm32_libs or [n for n in all_names if n.endswith(".so")]

            if not selected:
                raise InputError(f"no native .so libraries found in archive: {path}")

            for name in selected:
                dest = temp_dir / Path(name).name
                with zf.open(name) as src, open(dest, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                extracted_libs.append(dest)

        return sorted(extracted_libs), temp_dir

    # Case 3: Single .so file
    if path.is_file():
        return [path], None

    raise InputError(f"unsupported target: {path}")

# ============================================================
# HIGH-SPEED XREF & FUNCTION BOUNDARY ENGINES
# ============================================================

@dataclass
class XRefHit:
    name: str
    target_vaddr: int
    xref_vaddr: int
    func_vaddr: int
    func_offset: int
    reg: int
    insn_type: str

class Arm64XrefHunter:
    def __init__(self, text_bytes: bytes, text_vaddr: int, text_file_offset: int, function_starts: Optional[List[int]] = None):
        self.text = text_bytes
        self.text_vaddr = text_vaddr
        self.text_file_offset = text_file_offset
        self.num_insns = len(text_bytes) // 4
        self.starts = function_starts or []

    @staticmethod
    def decode_adrp(insn: int, pc: int) -> Optional[Tuple[int, int]]:
        if (insn & 0x9F000000) != 0x90000000: return None
        rd = insn & 0x1F
        immlo = (insn >> 29) & 0x3
        immhi = (insn >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= (1 << 21)
        pc_page = pc & ~0xFFF
        target_page = pc_page + (imm << 12)
        return rd, target_page

    @staticmethod
    def decode_add_imm(insn: int) -> Optional[Tuple[int, int, int]]:
        if (insn & 0xFF800000) == 0x91000000:
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            imm12 = (insn >> 10) & 0xFFF
            shift = (insn >> 22) & 0x3
            if shift == 1: imm12 <<= 12
            return rd, rn, imm12
        return None

    @staticmethod
    def decode_ldr_imm(insn: int) -> Optional[Tuple[int, int, int]]:
        if (insn & 0xFFC00000) == 0xF9400000:
            rt = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            imm12 = (insn >> 10) & 0xFFF
            return rt, rn, imm12 << 3
        if (insn & 0xFFC00000) == 0xB9400000:
            rt = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            imm12 = (insn >> 10) & 0xFFF
            return rt, rn, imm12 << 2
        return None

    def find_function_prologue(self, pc: int, max_backtrack: int = 400) -> int:
        if self.starts:
            fs = function_start_for(pc, self.starts)
            if fs is not None:
                return fs
        idx = (pc - self.text_vaddr) // 4
        start_idx = max(0, idx - max_backtrack)
        for i in range(idx, start_idx - 1, -1):
            raw = self.text[i * 4:(i + 1) * 4]
            if len(raw) < 4: continue
            insn = struct.unpack("<I", raw)[0]
            if insn == 0xD503233F: return self.text_vaddr + i * 4
            if (insn & 0xFFC07FFF) in (0xA9807BFD, 0xA9007BFD): return self.text_vaddr + i * 4
            if insn == 0xD65F03C0 and i < idx: return self.text_vaddr + (i + 1) * 4
        return self.text_vaddr + start_idx * 4

    def scan_string_xrefs(self, targets: Dict[int, str]) -> List[XRefHit]:
        page_buckets: Dict[int, List[Tuple[int, str]]] = {}
        for vaddr, name in targets.items():
            page = vaddr & ~0xFFF
            page_buckets.setdefault(page, []).append((vaddr, name))

        hits: List[XRefHit] = []
        n = self.num_insns
        text = self.text
        text_vaddr = self.text_vaddr

        for i in range(n - 1):
            off = i * 4
            insn = struct.unpack_from("<I", text, off)[0]
            if (insn & 0x9F000000) != 0x90000000: continue
            pc = text_vaddr + off
            res = self.decode_adrp(insn, pc)
            if not res: continue
            rd, target_page = res
            if target_page not in page_buckets: continue

            for lookahead in range(1, 4):
                if i + lookahead >= n: break
                next_insn = struct.unpack_from("<I", text, (i + lookahead) * 4)[0]
                add_res = self.decode_add_imm(next_insn)
                if add_res:
                    n_rd, n_rn, imm12 = add_res
                    if n_rn == rd:
                        final_vaddr = target_page + imm12
                        for t_vaddr, t_name in page_buckets[target_page]:
                            if t_vaddr == final_vaddr:
                                func_vaddr = self.find_function_prologue(pc)
                                func_off = self.text_file_offset + (func_vaddr - text_vaddr)
                                hits.append(XRefHit(
                                    name=t_name, target_vaddr=t_vaddr, xref_vaddr=pc,
                                    func_vaddr=func_vaddr, func_offset=func_off,
                                    reg=n_rd, insn_type="ADRP+ADD"
                                ))
                        break

                ldr_res = self.decode_ldr_imm(next_insn)
                if ldr_res:
                    n_rt, n_rn, pimm = ldr_res
                    if n_rn == rd:
                        final_vaddr = target_page + pimm
                        for t_vaddr, t_name in page_buckets[target_page]:
                            if t_vaddr == final_vaddr:
                                func_vaddr = self.find_function_prologue(pc)
                                func_off = self.text_file_offset + (func_vaddr - text_vaddr)
                                hits.append(XRefHit(
                                    name=t_name, target_vaddr=t_vaddr, xref_vaddr=pc,
                                    func_vaddr=func_vaddr, func_offset=func_off,
                                    reg=n_rt, insn_type="ADRP+LDR"
                                ))
                        break
        return hits

class X86XrefHunter:
    def __init__(self, text_bytes: bytes, text_vaddr: int, text_file_offset: int, function_starts: Optional[List[int]] = None):
        self.text = text_bytes
        self.text_vaddr = text_vaddr
        self.text_file_offset = text_file_offset
        self.starts = function_starts or []

    def scan_string_xrefs(self, targets: Dict[int, str]) -> List[XRefHit]:
        hits: List[XRefHit] = []
        text = self.text
        text_len = len(text)
        text_vaddr = self.text_vaddr

        idx = 0
        while idx < text_len - 7:
            b = text[idx]
            if b == 0x48 and text[idx + 1] in (0x8D, 0x8B):
                modrm = text[idx + 2]
                if (modrm & 0xC7) == 0x05:
                    disp = struct.unpack_from("<i", text, idx + 3)[0]
                    next_ip = text_vaddr + idx + 7
                    target = next_ip + disp
                    if target in targets:
                        func_vaddr = self._backtrack_x86(idx)
                        func_off = self.text_file_offset + (func_vaddr - text_vaddr)
                        hits.append(XRefHit(
                            name=targets[target], target_vaddr=target,
                            xref_vaddr=text_vaddr + idx, func_vaddr=func_vaddr,
                            func_offset=func_off, reg=(modrm >> 3) & 7,
                            insn_type="RIP_REL"
                        ))
                    idx += 7
                    continue
            idx += 1
        return hits

    def _backtrack_x86(self, idx: int) -> int:
        pc = self.text_vaddr + idx
        if self.starts:
            fs = function_start_for(pc, self.starts)
            if fs is not None:
                return fs
        for i in range(idx, max(0, idx - 400), -1):
            if self.text[i] == 0xC3 and i < idx: return self.text_vaddr + i + 1
            if self.text[i:i + 3] == b"\x55\x48\x89": return self.text_vaddr + i
        return pc

# ============================================================
# OFFLINE PROBE ENGINE (Pattern & String Query Dispatcher)
# ============================================================


def parse_advanced_pattern(text: str) -> List[Any]:
    tokens = text.split()
    parsed = []
    for t in tokens:
        if t in ("??", "?", "*"):
            parsed.append(None)
        elif len(t) == 2 and t[1] in ("?", "*"):
            high = int(t[0], 16)
            parsed.append(("high", high))
        elif len(t) == 2 and t[0] in ("?", "*"):
            low = int(t[1], 16)
            parsed.append(("low", low))
        else:
            parsed.append(("byte", int(t, 16)))
    return parsed

def match_pattern_byte(p: Any, b: int) -> bool:
    if p is None: return True
    tag, val = p
    if tag == "byte": return b == val
    if tag == "high": return (b >> 4) == val
    if tag == "low": return (b & 0xF) == val
    return False

def find_advanced_pattern_in_bytes(data: bytes, base_va: int, values: List[Any]) -> List[int]:
    hits = []
    if not values: return hits
    first_rule = values[0]
    size = len(values)
    limit = len(data) - size
    at = 0
    while at <= limit:
        if match_pattern_byte(first_rule, data[at]):
            if all(match_pattern_byte(val, data[at + i]) for i, val in enumerate(values)):
                hits.append(base_va + at)
        at += 1
    return hits
# ============================================================
# MARKER & XOR SCANNER
# ============================================================

class MarkerScanner:
    def __init__(self, sec_bytes_fn: Callable[[str], bytes], sections: Dict[str, Section], sigs: dict, min_len: int = MARKER_MIN_LEN_DEFAULT, enable_xor: bool = True):
        self.sec_bytes_fn = sec_bytes_fn
        self.sections = sections
        self.sigs = sigs
        self.min_len = min_len
        self.enable_xor = enable_xor

    def scan(self, binary_name: str = "") -> List[MarkerHit]:
        hits: List[MarkerHit] = []
        seen = set()

        for sec_name in (".rodata", ".data.rel.ro"):
            sec = self.sections.get(sec_name)
            if not sec: continue
            buf = self.sec_bytes_fn(sec_name)

            for entry in self.sigs.get("strings", []):
                name = entry["name"]
                for marker in entry.get("markers", []):
                    if len(marker) < self.min_len: continue
                    needle = marker.encode("utf-8", errors="ignore")
                    found = False
                    for file_off in self._find_all(buf, needle):
                        sva = sec.va + file_off
                        key = (name, sva)
                        if key in seen: continue
                        seen.add(key)
                        found = True
                        hits.append(MarkerHit(
                            name=name, text=marker, section=sec_name,
                            string_va=sva, file_offset=sec.file_offset + file_off,
                            binary=binary_name,
                        ))

                    if not found and self.enable_xor and len(needle) <= 32:
                        for key_byte in range(1, 9):
                            xor_needle = bytes(b ^ key_byte for b in needle)
                            for file_off in self._find_all(buf, xor_needle):
                                sva = sec.va + file_off
                                key = (name, sva)
                                if key in seen: continue
                                seen.add(key)
                                hits.append(MarkerHit(
                                    name=f"{name}_xor{key_byte}",
                                    text=f"{marker} [XOR 0x{key_byte:02x}]",
                                    section=sec_name, string_va=sva,
                                    file_offset=sec.file_offset + file_off,
                                    binary=binary_name,
                                ))
        return hits

    @staticmethod
    def _find_all(buf: bytes, needle: bytes) -> List[int]:
        if not needle: return []
        out, start, n = [], 0, len(needle)
        while True:
            i = buf.find(needle, start)
            if i < 0: return out
            out.append(i)
            start = i + n

# ============================================================
# SYMBOL RESOLVER & CANONICAL MAPPINGS
# ============================================================

class SymbolResolver:
    MARKER_MAP = {
        "loadstring": "luau_load",
        "printidentity": "printidentity",
        "resume": "lua_resume",
        "resume_start": "lua_resume_start",
        "auxresume": "auxresume",
        "luaL_checkstack": "lua_checkstack",
        "luaL_tostring": "lua_tolstring",
        "luaG_namecallerror": "lua_namecall_atom",
        "luaB_setmetatable": "lua_setmetatable",
        "luaB_newproxy": "lua_newproxy",
        "getfield": "lua_getfield",
        "taskschedulerjobstart": "taskscheduler_step",
        "taskschedulerinit": "taskscheduler_get",
        "scriptcontextstartscript": "scriptcontext_startscript",
        "fireserver": "remotefunction_fireserver",
        "invokeserver": "remotefunction_invokeserver",
        "ongameloaded": "datamodel_ongameloaded",
        "fireproximityprompt": "fireproximityprompt",
        "enumgco": "luaVisitGCO",
        "createvm": "createvm",
        "createplayer": "createplayer",
        "collectgarbage": "collectgarbage",
        "checkmodulescriptawaitingthread": "checkmodulescriptawaitingthread",
        "securityfiltercapabilities": "securityfiltercapabilities",
        "dodatamodelsetup": "dodatamodelsetup",
        "datamodelclearcontent": "datamodelclearcontent",
        "datamodelinitcontents": "datamodelinitcontents",
        "get_identity_obj": "get_identity_obj",
        "data_model_job_id": "data_model_job_id",
        "data_model_game_id": "data_model_game_id",
        "data_model_place_id": "data_model_place_id",
        "data_model_creator_id": "data_model_creator_id",
        "ScriptContext": "ScriptContext",
        "Datamodel": "Datamodel",
        "Players": "Players",
        "Humanoid": "Humanoid",
        "Workspace": "Workspace",
        "HttpService": "HttpService",
        "GuiService": "GuiService",
        "InsertService": "InsertService",
        "SafetyService": "SafetyService",
        "RenderView": "RenderView",
        "VirtualInputManager": "VirtualInputManager",
        "DeviceIntegrityService": "DeviceIntegrityService",
    }

    DEFAULT_STRUCT_OFFSETS = {
        "scheduler_jobs": 0x1D0,
        "scheduler_pointer": 0x3D0,
        "script_job_context": 0x1F0,
        "datamodel_instance": 0x1A8,
        "datamodel_placeid": 0x190,
        "datamodel_gameid": 0x198,
        "datamodel_jobid": 0x118,
        "instance_parent": 0x38,
        "instance_name": 0x48,
        "instance_children": 0x50,
        "vm_global_offset": 0x20,
        "vm_postresume_offset": 0x30,
        "lua_state_extra_space_offset": 0x78,
        "extra_identity_offset": 0x18,
        "extra_capabilities_offset": 0x20,
        "proto_capabilities_offset": 0x48,
        "proto_child_count_offset": 0x3C,
        "proto_children_offset": 0x30,
        "base_identity": 0x3,
        "execution_identity": 0x8,
    }

# ============================================================
# MULTI-BINARY SCANNER & CANDIDATE COMPILER
# ============================================================

class MultiBinaryScanner:
    def __init__(self, target: Path, mode: SpeedMode = SpeedMode.FAST,
                 sig_path: Optional[Path] = None, enable_xor: bool = True,
                 min_marker_len: int = MARKER_MIN_LEN_DEFAULT,
                 sig_filter: Optional[List[str]] = None,
                 scan_patterns: bool = True,
                 include_struct_hints: bool = True,
                 selected_libs: Optional[List[str]] = None):
        self.target = target
        self.mode = mode
        self.sig_path = sig_path
        self.enable_xor = enable_xor
        self.min_marker_len = min_marker_len
        self.sig_filter = sig_filter
        self.scan_patterns = scan_patterns
        self.include_struct_hints = include_struct_hints
        self.selected_libs = [s.lower() for s in selected_libs] if selected_libs else None
        self.sigs = self._load_and_filter_signatures()
        self.result = MultiBinaryResult(
            target=target,
            scanned_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        )
        self.temp_dir: Optional[Path] = None

    def _load_and_filter_signatures(self) -> dict:
        loaded = None
        if self.sig_path and self.sig_path.exists():
            try: loaded = json.loads(self.sig_path.read_text(encoding="utf-8"))
            except Exception: pass
        if not loaded:
            bundled = Path(__file__).resolve().parent / "signatures.json"
            if bundled.exists():
                try: loaded = json.loads(bundled.read_text(encoding="utf-8"))
                except Exception: pass
        if not loaded:
            loaded = DEFAULT_SIGNATURES

        if not self.sig_filter:
            return loaded

        # Filter signatures by keyword / category
        keywords = [k.strip().lower() for k in self.sig_filter if k.strip()]
        filtered_strings = []
        for entry in loaded.get("strings", []):
            ename = entry.get("name", "").lower()
            aliases = [a.lower() for a in entry.get("aliases", [])]
            markers = [m.lower() for m in entry.get("markers", [])]
            matched = any(
                kw in ename or any(kw in al for al in aliases) or any(kw in mk for mk in markers)
                for kw in keywords
            )
            if matched:
                filtered_strings.append(entry)

        filtered = dict(loaded)
        filtered["strings"] = filtered_strings
        return filtered
    def run(self, progress_cb: Optional[Callable[[str, str], None]] = None) -> MultiBinaryResult:
        t0 = time.time()
        binaries, self.temp_dir = resolve_binaries_target(self.target)

        try:
            for p in binaries:
                bname = p.name
                if self.selected_libs and not any(sel in bname.lower() for sel in self.selected_libs):
                    continue
                if progress_cb: progress_cb(bname, "scanning")
                b_res = self._scan_single_binary(p, bname)
                self.result.libraries[bname] = b_res
                self.result.combined_candidates.extend(b_res.candidates)

            self._correlate_cross_links()
            self.result.elapsed_sec = round(time.time() - t0, 2)
            self._compile_stats()
        finally:
            if self.temp_dir and self.temp_dir.exists():
                try: shutil.rmtree(self.temp_dir)
                except Exception: pass

        return self.result

    def _scan_single_binary(self, path: Path, bname: str) -> BinaryAnalysisResult:
        size = path.stat().st_size
        fp = open(path, "rb")
        mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

        build_id = extract_gnu_build_id(mm)
        sections: Dict[str, Section] = {}
        sym_by_va: Dict[int, str] = {}
        exports: Dict[str, int] = {}
        jni_methods: Dict[str, int] = {}
        imported: List[str] = []
        function_starts: List[int] = []
        arch_str = "unknown"
        machine_int = 0

        if HAS_PYELFTOOLS:
            try:
                elf = ELFFile(fp)
                machine_int = _normalize_machine(elf.header["e_machine"])
                arch_enum = _ARCH_BY_MACHINE.get(machine_int, ELFArch.UNKNOWN)
                arch_str = arch_enum.value
                for sec in elf.iter_sections():
                    sections[sec.name] = Section(
                        name=sec.name, file_offset=sec["sh_offset"],
                        va=sec["sh_addr"], size=sec["sh_size"], flags=sec["sh_flags"]
                    )
                    if isinstance(sec, SymbolTableSection):
                        for sym in sec.iter_symbols():
                            va = sym["st_value"]
                            name = sym.name
                            if not name: continue
                            t = sym["st_info"]["type"]
                            b = sym["st_info"]["bind"]
                            if va and t in ("STT_FUNC", "STT_OBJECT"):
                                sym_by_va[va] = name
                                if t == "STT_FUNC":
                                    exports[name] = va
                                    if name.startswith("Java_"):
                                        jni_methods[name] = va
                            elif not va and b == "STB_GLOBAL":
                                imported.append(name)

                # .eh_frame_hdr exact starts
                eh_sec = elf.get_section_by_name(".eh_frame_hdr")
                if eh_sec:
                    function_starts = parse_eh_frame_hdr(eh_sec.data(), int(eh_sec["sh_addr"]))
            except Exception:
                pure = PureElfParser(mm, size)
                machine_int = pure.machine
                arch_str = _ARCH_BY_MACHINE.get(machine_int, ELFArch.UNKNOWN).value
                sections = pure.section_map
                function_starts = pure.function_starts
        else:
            pure = PureElfParser(mm, size)
            machine_int = pure.machine
            arch_str = _ARCH_BY_MACHINE.get(machine_int, ELFArch.UNKNOWN).value
            sections = pure.section_map
            function_starts = pure.function_starts

        sec_bytes_fn = lambda sname: (
            mm[sections[sname].file_offset:sections[sname].file_offset + sections[sname].size]
            if sname in sections else b""
        )

        # Initialize candidate lists and sections
        resolved: Dict[str, List[ResolvedHit]] = {}
        candidates: List[CandidateItem] = []
        text_sec = sections.get(".text")

        # Marker scan
        scanner = MarkerScanner(sec_bytes_fn, sections, self.sigs, enable_xor=self.enable_xor)
        markers = scanner.scan(binary_name=bname)

        # Scan byte patterns from signatures.json
        if self.scan_patterns and text_sec:
            text_bytes = sec_bytes_fn(".text")
            for entry in self.sigs.get("strings", []):
                pats = entry.get("patterns", [])
                if not pats: continue
                p_name = entry.get("name", "pattern")
                for pat_str in pats:
                    try:
                        parsed_pat = parse_advanced_pattern(pat_str)
                        pat_hits = find_advanced_pattern_in_bytes(text_bytes, text_sec.va, parsed_pat)
                        for ph in pat_hits:
                            fs = function_start_for(ph, function_starts)
                            candidates.append(CandidateItem(
                                name=p_name, binary=bname, kind="address",
                                value=f"0x{fs:X}" if fs else f"0x{ph:X}",
                                confidence="high", method="signatures byte pattern",
                                evidence=[
                                    f"Matched pattern '{pat_str}' at 0x{ph:X} in {bname}.text",
                                    (f"enclosing function 0x{fs:X} (.eh_frame_hdr verified)" if fs else "raw site")
                                ],
                                status="needs_review",
                                raw={"pattern": pat_str, "match_va": hex(ph), "func_va": hex(fs) if fs else None}
                            ))
                    except Exception:
                        pass

        # Load struct hints from signatures.json
        if self.include_struct_hints and "struct_hints" in self.sigs:
            if "roblox" in bname.lower() or bname.lower() == "libroblox.so":
                for hint_k, hint_v in self.sigs["struct_hints"].items():
                    val_hex = hint_v if str(hint_v).startswith("0x") else f"0x{int(hint_v, 0):X}"
                    candidates.append(CandidateItem(
                        name=hint_k, binary=bname, kind="layout",
                        value=val_hex, confidence="high", method="signatures.json struct hint",
                        evidence=[f"Defined in signatures.json struct_hints for {bname}"],
                        status="confirmed"
                    ))

        # Xref scan
        if text_sec:
            text_bytes = sec_bytes_fn(".text")
            target_map = {m.string_va: m.name for m in markers}

            if machine_int == 0xB7 and target_map:  # AArch64
                hunter = Arm64XrefHunter(text_bytes, text_sec.va, text_sec.file_offset, function_starts)
                xref_hits = hunter.scan_string_xrefs(target_map)
                by_target: Dict[str, List[XRefHit]] = {}
                for h in xref_hits:
                    by_target.setdefault(h.name, []).append(h)
                    resolved.setdefault(h.name, []).append(ResolvedHit(
                        name=h.name, marker=target_map.get(h.target_vaddr, ""),
                        section=".rodata", string_va=h.target_vaddr,
                        xref_insn=h.xref_vaddr, xref_kind=h.insn_type,
                        func_start=h.func_vaddr,
                        func_name=sym_by_va.get(h.func_vaddr),
                        binary=bname
                    ))

                # Build ledger items for markers
                for m_name, hits in by_target.items():
                    canon = SymbolResolver.MARKER_MAP.get(m_name, m_name)
                    # Deduplicate by function address
                    funcs_count = Counter(h.func_vaddr for h in hits)
                    sorted_funcs = sorted(funcs_count.items(), key=lambda x: -x[1])
                    best_va = sorted_funcs[0][0]
                    conf = "high" if len(sorted_funcs) == 1 else ("medium" if len(sorted_funcs) <= 3 else "low")
                    ev = [
                        f"referenced by {hits[0].insn_type} from site 0x{hits[0].xref_vaddr:X} to marker '{hits[0].name}'",
                        f"enclosing function start 0x{best_va:X}" + (" (.eh_frame_hdr verified)" if function_starts else "")
                    ]
                    alts = [{"value": f"0x{va:X}", "reason": f"{cnt} xref occurrences"} for va, cnt in sorted_funcs[1:6]]
                    candidates.append(CandidateItem(
                        name=canon, binary=bname, kind="address",
                        value=f"0x{best_va:X}", confidence=conf, method="string xref",
                        evidence=ev, alternatives=alts, status="needs_review",
                        raw={"marker": m_name, "sites": [f"0x{h.xref_vaddr:X}" for h in hits[:10]]}
                    ))

            elif machine_int == 0x3E and target_map:  # x86_64
                hunter = X86XrefHunter(text_bytes, text_sec.va, text_sec.file_offset, function_starts)
                xref_hits = hunter.scan_string_xrefs(target_map)
                by_target = {}
                for h in xref_hits:
                    by_target.setdefault(h.name, []).append(h)
                    resolved.setdefault(h.name, []).append(ResolvedHit(
                        name=h.name, marker=target_map.get(h.target_vaddr, ""),
                        section=".rodata", string_va=h.target_vaddr,
                        xref_insn=h.xref_vaddr, xref_kind=h.insn_type,
                        func_start=h.func_vaddr,
                        func_name=sym_by_va.get(h.func_vaddr),
                        binary=bname
                    ))
                for m_name, hits in by_target.items():
                    canon = SymbolResolver.MARKER_MAP.get(m_name, m_name)
                    funcs_count = Counter(h.func_vaddr for h in hits)
                    sorted_funcs = sorted(funcs_count.items(), key=lambda x: -x[1])
                    best_va = sorted_funcs[0][0]
                    conf = "high" if len(sorted_funcs) == 1 else "medium"
                    ev = [f"x86_64 RIP-relative LEA to marker '{hits[0].name}' at 0x{hits[0].xref_vaddr:X}"]
                    alts = [{"value": f"0x{va:X}", "reason": f"{cnt} occurrences"} for va, cnt in sorted_funcs[1:6]]
                    candidates.append(CandidateItem(
                        name=canon, binary=bname, kind="address",
                        value=f"0x{best_va:X}", confidence=conf, method="string xref",
                        evidence=ev, alternatives=alts, status="needs_review"
                    ))

        # Add JNI candidates
        for jni_name, jni_va in jni_methods.items():
            candidates.append(CandidateItem(
                name=jni_name, binary=bname, kind="jni",
                value=f"0x{jni_va:X}", confidence="high", method="dynsym jni export",
                evidence=[f"JNI native method exported in .dynsym of {bname}"],
                status="confirmed"
            ))

        # Add Engine baseline struct offsets if primary roblox binary
        if "libroblox" in bname.lower():
            for k, v in SymbolResolver.DEFAULT_STRUCT_OFFSETS.items():
                candidates.append(CandidateItem(
                    name=k, binary=bname, kind="layout",
                    value=f"0x{v:X}", confidence="high", method="engine struct baseline",
                    evidence=["Verified baseline engine struct offset"],
                    status="confirmed"
                ))

        fp.close()
        return BinaryAnalysisResult(
            binary_name=bname, path=path, size=size, arch=arch_str, build_id=build_id,
            sections={k: {"va": hex(v.va), "size": v.size, "offset": hex(v.file_offset)} for k, v in sections.items()},
            function_starts_count=len(function_starts),
            exports=exports, jni_methods=jni_methods, imported_symbols=imported,
            markers=markers, resolved=resolved, candidates=candidates,
            stats={
                "size_bytes": size,
                "function_starts": len(function_starts),
                "exports": len(exports),
                "jni_methods": len(jni_methods),
                "markers_matched": len(markers),
                "functions_resolved": len(resolved),
            }
        )

    def _correlate_cross_links(self):
        links = {}
        for bname, b_res in self.result.libraries.items():
            imported_found = {}
            for other_name, other_res in self.result.libraries.items():
                if other_name == bname: continue
                matches = set(b_res.imported_symbols).intersection(other_res.exports.keys())
                if matches:
                    imported_found[other_name] = sorted(list(matches))
            if imported_found:
                links[bname] = imported_found
        self.result.cross_links = links

    def _compile_stats(self):
        self.result.stats = {
            "total_binaries": len(self.result.libraries),
            "total_candidates": len(self.result.combined_candidates),
            "total_function_starts": sum(b.function_starts_count for b in self.result.libraries.values()),
            "total_jni_methods": sum(len(b.jni_methods) for b in self.result.libraries.values()),
            "total_exports": sum(len(b.exports) for b in self.result.libraries.values()),
            "total_resolved_markers": sum(len(b.resolved) for b in self.result.libraries.values()),
            "elapsed_sec": self.result.elapsed_sec,
        }

# ============================================================
# MULTI-FORMAT EXPORTERS
# ============================================================

class MultiBinaryExporter:
    def __init__(self, result: MultiBinaryResult):
        self.result = result

    def write_ledger_json(self, path: Path):
        ledger = OrderedDict([
            ("schema", 2),
            ("generated", self.result.scanned_at),
            ("target", str(self.result.target)),
            ("stats", self.result.stats),
            ("cross_links", self.result.cross_links),
            ("items", [c.to_dict() for c in self.result.combined_candidates]),
        ])
        path.write_text(json.dumps(ledger, indent=2), encoding="utf-8")

    def write_header_hpp(self, path: Path):
        lines = [
            "#pragma once",
            "// Auto-generated by RBX-Finder / ORC V2 Universal Multi-Binary Analyzer",
            f"// Generated at: {self.result.scanned_at}",
            "",
            "#include <cstdint>",
            "#include <cstddef>",
            "",
            "namespace profile {",
        ]

        for bname, b_res in self.result.libraries.items():
            safe_ns = re.sub(r"[^A-Za-z0-9_]", "_", bname).replace("lib", "").replace(".so", "").strip("_")
            if not safe_ns: safe_ns = "main"
            lines.extend([
                f"",
                f"// {'=' * 58}",
                f"// Binary: {bname} ({b_res.arch}, build: {b_res.build_id or 'none'})",
                f"// {'=' * 58}",
                f"namespace {safe_ns} {{",
                f'inline constexpr char expected_build_id[] = "{b_res.build_id}";',
            ])

            seen_in_ns = {"expected_build_id"}

            # Struct offsets
            struct_cands = [c for c in b_res.candidates if c.kind == "layout"]
            if struct_cands:
                lines.append("// Structure Offsets")
                for c in sorted(struct_cands, key=lambda x: x.name):
                    safe_name = re.sub(r"[^A-Za-z0-9_]", "_", c.name)
                    if safe_name.lower() in seen_in_ns:
                        continue
                    seen_in_ns.add(safe_name.lower())
                    lines.append(f"inline constexpr std::uintptr_t {safe_name} = {c.value};")

            # Function / JNI offsets
            fn_cands = [c for c in b_res.candidates if c.kind in ("address", "jni")]
            if fn_cands:
                lines.append("// Functions & Entrypoints")
                for c in sorted(fn_cands, key=lambda x: x.name):
                    safe_name = re.sub(r"[^A-Za-z0-9_]", "_", c.name)
                    if safe_name.lower() in seen_in_ns:
                        continue
                    seen_in_ns.add(safe_name.lower())
                    lines.append(f"inline constexpr std::uintptr_t {safe_name} = {c.value};")

            lines.append(f"}} // namespace {safe_ns}")

        lines.extend(["", "} // namespace profile", ""])
        path.write_text("\n".join(lines), encoding="utf-8")

    def write_frida_js(self, path: Path):
        lines = [
            "// Frida Multi-Binary Hook Script — auto-generated by RBX-Finder V2",
            "'use strict';",
            "",
            "function hookAll() {",
        ]

        for bname, b_res in self.result.libraries.items():
            lines.extend([
                f"    // ---- {bname} ----",
                f"    const base_{re.sub(r'[^A-Za-z0-9_]', '_', bname)} = Module.findBaseAddress('{bname}');",
                f"    if (base_{re.sub(r'[^A-Za-z0-9_]', '_', bname)}) {{",
                f"        console.log('[+] Found {bname} at ' + base_{re.sub(r'[^A-Za-z0-9_]', '_', bname)});",
            ])
            seen_hook = set()
            for c in b_res.candidates[:60]:
                if c.kind in ("address", "jni") and c.value:
                    safe = re.sub(r"[^A-Za-z0-9_]", "_", c.name)
                    if c.value in seen_hook:
                        continue
                    seen_hook.add(c.value)
                    lines.extend([
                        f"        try {{",
                        f"            Interceptor.attach(base_{re.sub(r'[^A-Za-z0-9_]', '_', bname)}.add({c.value}), {{",
                        f"                onEnter(args) {{ console.log('[{bname}][CALL] {safe}'); }}",
                        f"            }});",
                        f"        }} catch(e) {{}}",
                    ])
            lines.append("    }")

        lines.extend([
            "}",
            "",
            "setImmediate(hookAll);",
            ""
        ])
        path.write_text("\n".join(lines), encoding="utf-8")

    def write_ghidra_py(self, path: Path):
        lines = [
            "# Ghidra Multi-Binary Annotation Script",
            "from ghidra.program.model.symbol import SourceType",
            "print('[*] Creating labels...')",
        ]
        seen_labels = set()
        for c in self.result.combined_candidates:
            if c.kind in ("address", "jni") and c.value:
                safe = re.sub(r"[^A-Za-z0-9_]", "_", c.name)
                key = (c.value, safe)
                if key in seen_labels:
                    continue
                seen_labels.add(key)
                lines.append(f"try: createLabel(toAddr({c.value}), 'RBX_{safe}', True, SourceType.USER_DEFINED)\nexcept: pass")
        path.write_text("\n".join(lines), encoding="utf-8")

    def write_ida_py(self, path: Path):
        lines = [
            "# IDA Pro Multi-Binary Annotation Script",
            "import idc",
            "def set_l(ea, name): idc.set_name(ea, name, idc.SN_CHECK)",
        ]
        seen_labels = set()
        for c in self.result.combined_candidates:
            if c.kind in ("address", "jni") and c.value:
                safe = re.sub(r"[^A-Za-z0-9_]", "_", c.name)
                key = (c.value, safe)
                if key in seen_labels:
                    continue
                seen_labels.add(key)
                lines.append(f'set_l({c.value}, "RBX_{safe}")')
        path.write_text("\n".join(lines), encoding="utf-8")

    def write_summary_md(self, path: Path):
        lines = [
            "# RBX-Finder V2 Multi-Binary Analysis Summary",
            f"**Target:** `{self.result.target}`  ",
            f"**Generated:** `{self.result.scanned_at}`  ",
            f"**Elapsed Time:** `{self.result.elapsed_sec}s`  ",
            "",
            "## 1. Libraries Overview",
            "| Library | Size | Arch | GNU Build ID | Functions (.eh_frame) | Exports | JNI Methods | Markers |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for bname, b in self.result.libraries.items():
            bid = b.build_id[:16] + "..." if len(b.build_id) > 16 else (b.build_id or "none")
            lines.append(
                f"| `{bname}` | {b.size:,} B | {b.arch} | `{bid}` | {b.function_starts_count:,} | {len(b.exports):,} | {len(b.jni_methods)} | {len(b.markers)} |"
            )

        lines.extend([
            "",
            "## 2. JNI Entrypoints Discovered",
            "| Library | JNI Function | Offset |",
            "|---|---|---|",
        ])
        for bname, b in self.result.libraries.items():
            for jname, jva in sorted(b.jni_methods.items()):
                lines.append(f"| `{bname}` | `{jname}` | `0x{jva:X}` |")

        lines.extend([
            "",
            "## 3. High-Confidence Engine Candidates",
            "| Binary | Symbol | Value | Confidence | Method | Status |",
            "|---|---|---|---|---|---|",
        ])
        for c in self.result.combined_candidates[:60]:
            lines.append(f"| `{c.binary}` | `{c.name}` | `{c.value}` | `{c.confidence}` | {c.method} | `{c.status}` |")

        path.write_text("\n".join(lines), encoding="utf-8")

    def write_raw_json(self, path: Path):
        data = {
            "version": VERSION,
            "target": str(self.result.target),
            "scanned_at": self.result.scanned_at,
            "elapsed_sec": self.result.elapsed_sec,
            "stats": self.result.stats,
            "cross_links": self.result.cross_links,
            "libraries": {
                k: {
                    "size": v.size, "arch": v.arch, "build_id": v.build_id,
                    "sections": v.sections, "function_starts_count": v.function_starts_count,
                    "exports": {x: f"0x{y:X}" for x, y in v.exports.items()},
                    "jni_methods": {x: f"0x{y:X}" for x, y in v.jni_methods.items()},
                    "imported_symbols": v.imported_symbols[:50],
                    "markers_count": len(v.markers),
                    "resolved_functions": {x: [f"0x{h.func_start:X}" for h in hits if h.func_start] for x, hits in v.resolved.items()}
                } for k, v in self.result.libraries.items()
            }
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

# ============================================================
# LEDGER MANAGEMENT COMMANDS (from offset_hunt.py)
# ============================================================

def cmd_ledger_summary(ledger_path: Path) -> int:
    data = json.loads(ledger_path.read_text(encoding="utf-8"))
    items = data.get("items", [])
    print(f"\n{C.B}── Ledger Summary ({ledger_path.name}){C.R}")
    print(f"Total candidates: {len(items)}")

    status_counts = Counter(i.get("status", "?") for i in items)
    conf_counts = Counter(i.get("confidence", "?") for i in items)
    kind_counts = Counter(i.get("kind", "?") for i in items)
    bin_counts = Counter(i.get("binary", "?") for i in items)

    print("\nStatus:     " + ", ".join(f"{k}={v}" for k, v in sorted(status_counts.items())))
    print("Confidence: " + ", ".join(f"{k}={v}" for k, v in sorted(conf_counts.items())))
    print("Kind:       " + ", ".join(f"{k}={v}" for k, v in sorted(kind_counts.items())))
    print("Libraries:  " + ", ".join(f"{k}={v}" for k, v in sorted(bin_counts.items())))

    unres = [i for i in items if i.get("status") in ("unresolved", "needs_review")]
    if unres:
        print(f"\n{C.YELLOW}Pending Review ({len(unres)} items):{C.R}")
        for it in unres[:12]:
            print(f"  {it.get('name'):<30} {it.get('value', 'none'):<14} [{it.get('confidence')}] {it.get('method')}")
    return 0

def cmd_ledger_review(ledger_path: Path, names: List[str], show_all: bool = False) -> int:
    data = json.loads(ledger_path.read_text(encoding="utf-8"))
    items = data.get("items", [])
    wanted = set(names) if names else None

    count = 0
    for entry in items:
        if wanted and entry.get("name") not in wanted:
            continue
        if not show_all and entry.get("status") in ("confirmed", "live"):
            continue

        print(f"\n{C.CYAN}## {entry.get('name')}  [{entry.get('binary')}]  [{entry.get('kind')}/{entry.get('status')}]{C.R}")
        print(f"Value: {C.B}{entry.get('value')}{C.R}   Confidence: {entry.get('confidence')}   Method: {entry.get('method')}")
        print("Evidence:")
        for ev in entry.get("evidence", []):
            print(f"  - {ev}")
        alts = entry.get("alternatives", [])
        if alts:
            print("Alternatives:")
            for a in alts:
                print(f"  - {a.get('value')}: {a.get('reason')}")
        count += 1
    if not count:
        print("No candidates matching criteria.")
    return 0

def cmd_ledger_mark(ledger_path: Path, name: str, status: str, note: str = "", by: str = "", value: str = "") -> int:
    if status not in STATUSES:
        print(f"Invalid status: {status} (choose from {', '.join(sorted(STATUSES))})", file=sys.stderr)
        return 1
    data = json.loads(ledger_path.read_text(encoding="utf-8"))
    found = False
    for item in data.get("items", []):
        if item.get("name") == name:
            found = True
            item["status"] = status
            item.setdefault("review", {})
            item["review"]["at"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
            if note: item["review"]["note"] = note
            if by: item["review"]["by"] = by
            if value: item["value"] = value if value.startswith("0x") else f"0x{int(value, 0):X}"
            break
    if not found:
        print(f"Candidate not found: {name}", file=sys.stderr)
        return 1
    ledger_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"{C.GREEN}✓{C.R} {name} marked as {status}")
    return 0

def cmd_ledger_check(ledger_path: Path) -> int:
    data = json.loads(ledger_path.read_text(encoding="utf-8"))
    items = data.get("items", [])
    errors = []
    seen = {}
    for entry in items:
        name = entry.get("name")
        status = entry.get("status")
        val = entry.get("value")
        if status in ("confirmed", "live"):
            if not val:
                errors.append(f"{name} is confirmed but has no value")
            else:
                try:
                    num = int(val, 0)
                    if num == 0:
                        errors.append(f"{name} has zero address")
                    key = (entry.get("binary"), num)
                    if key in seen:
                        errors.append(f"{name} and {seen[key]} share address {val} in {entry.get('binary')}")
                    seen[key] = name
                except ValueError:
                    errors.append(f"{name} has invalid address: {val}")
    if errors:
        print(f"{C.RED}Check failed with {len(errors)} errors:{C.R}")
        for e in errors: print(f"  ✗ {e}")
        return 1
    print(f"{C.GREEN}✓ Ledger check passed cleanly! All {len(items)} items valid.{C.R}")
    return 0

# ============================================================
# PROBE COMMANDS (from offsetprobe.py)
# ============================================================

def cmd_probe(target_path: Path, kind: str, value: Optional[str], limit: int = 50, binary_filter: Optional[str] = None):
    binaries, temp_dir = resolve_binaries_target(target_path)
    try:
        for p in binaries:
            if binary_filter and binary_filter.lower() not in p.name.lower():
                continue
            print(f"\n{C.B}── Probing {p.name} ({p.stat().st_size:,} bytes){C.R}")
            fp = open(p, "rb")
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            pure = PureElfParser(mm, p.stat().st_size)
            starts = pure.function_starts
            text_sec = pure.section_map.get(".text")

            if kind == "functions":
                print(f"  Exact function starts: {len(starts):,}")
                for s in starts[:limit]:
                    print(f"    0x{s:X}")
            elif kind == "string":
                if not value:
                    print("Error: string query requires text", file=sys.stderr); return 1
                needle = value.encode("utf-8")
                hits = []
                for sname in (".rodata", ".data.rel.ro", ".data"):
                    s = pure.section_map.get(sname)
                    if not s: continue
                    buf = mm[s.file_offset:s.file_offset + s.size]
                    at = 0
                    while True:
                        at = buf.find(needle, at)
                        if at < 0: break
                        hits.append(s.va + at)
                        at += 1
                print(f"  Found {len(hits)} string instances:")
                for h in hits:
                    print(f"    String at 0x{h:X}")

                if text_sec and hits:
                    text_bytes = mm[text_sec.file_offset:text_sec.file_offset + text_sec.size]
                    hunter = Arm64XrefHunter(text_bytes, text_sec.va, text_sec.file_offset, starts)
                    xrefs = hunter.scan_string_xrefs({h: value for h in hits})
                    print(f"  Found {len(xrefs)} XRefs to string:")
                    for xr in xrefs[:limit]:
                        print(f"    0x{xr.xref_vaddr:X} ({xr.insn_type}) in function 0x{xr.func_vaddr:X}")
            elif kind == "pattern":
                if not value:
                    print("Error: pattern query requires byte sequence (e.g. '55 48 ??')", file=sys.stderr); return 1
                vals = parse_pattern_bytes(value)
                if text_sec:
                    text_bytes = mm[text_sec.file_offset:text_sec.file_offset + text_sec.size]
                    hits = find_pattern_in_bytes(text_bytes, text_sec.va, vals)
                    print(f"  Found {len(hits)} pattern hits in .text:")
                    for h in hits[:limit]:
                        fs = function_start_for(h, starts)
                        fs_str = f" in function 0x{fs:X}" if fs else ""
                        print(f"    Match at 0x{h:X}{fs_str}")
            elif kind == "xref":
                if not value:
                    print("Error: xref query requires target address", file=sys.stderr); return 1
                target_va = int(value, 0)
                if text_sec:
                    text_bytes = mm[text_sec.file_offset:text_sec.file_offset + text_sec.size]
                    hunter = Arm64XrefHunter(text_bytes, text_sec.va, text_sec.file_offset, starts)
                    xrefs = hunter.scan_string_xrefs({target_va: "query"})
                    print(f"  Found {len(xrefs)} XRefs pointing to 0x{target_va:X}:")
                    for xr in xrefs[:limit]:
                        print(f"    0x{xr.xref_vaddr:X} ({xr.insn_type}) in function 0x{xr.func_vaddr:X}")
            fp.close()
    finally:
        if temp_dir and temp_dir.exists():
            shutil.rmtree(temp_dir)
    return 0

# ============================================================
# UI & CLI BANNER
# ============================================================

class C:
    R = "\x1b[0m"; B = "\x1b[1m"; DIM = "\x1b[2m"
    RED = "\x1b[31m"; GREEN = "\x1b[32m"; YELLOW = "\x1b[33m"
    BLUE = "\x1b[34m"; CYAN = "\x1b[36m"; GRAY = "\x1b[90m"

def banner():
    print(f"""{C.CYAN}{C.B}
  ┌─────────────────────────────────────────────────────────────┐
  │  RBX-Finder / ORC V2                                        │
  │  Universal Multi-Binary Analyzer, Offset Dumper & Ledger    │
  └─────────────────────────────────────────────────────────────┘{C.R}""")

def parse_args() -> argparse.Namespace:
    if len(sys.argv) > 1 and sys.argv[1] == "probe":
        ap = argparse.ArgumentParser(description="Probe offline queries")
        ap.add_argument("subcommand")
        ap.add_argument("target", type=Path, help="Path to .so, directory of .so files, or APK")
        ap.add_argument("kind", choices=("string", "pattern", "xref", "functions"), help="Query type")
        ap.add_argument("value", nargs="?", help="Text string, pattern, or address")
        ap.add_argument("--limit", type=int, default=50, help="Maximum results to print")
        ap.add_argument("--binary", help="Filter by specific binary name")
        return ap.parse_args()

    if len(sys.argv) > 1 and sys.argv[1] == "ledger":
        ap = argparse.ArgumentParser(description="Candidate ledger management")
        ap.add_argument("subcommand")
        ap.add_argument("action", choices=("summary", "review", "mark", "check"), help="Ledger action")
        ap.add_argument("ledger", type=Path, help="Path to ledger JSON file")
        ap.add_argument("names", nargs="*", help="Candidate names (for review or mark)")
        ap.add_argument("--status", choices=list(STATUSES), help="Status for mark")
        ap.add_argument("--note", default="", help="Reviewer note")
        ap.add_argument("--by", default=os.environ.get("USER", "analyst"), help="Reviewer identifier")
        ap.add_argument("--value", default="", help="Override candidate address")
        ap.add_argument("--all", action="store_true", help="Include confirmed candidates in review")
        return ap.parse_args()

    ap = argparse.ArgumentParser(
        description="RBX-Finder / ORC V2 — Universal Multi-Binary Analyzer, Offset Dumper & Ledger",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("target", nargs="?", type=Path, help="Target: .so file, directory of .so files, or APK")
    ap.add_argument("--mode", choices=[m.value for m in SpeedMode], default="fast", help="Scan speed mode (fast, normal, deep, paranoid)")
    ap.add_argument("--all-libs", action="store_true", default=True, help="Scan all libraries in directory/archive")
    ap.add_argument("--lib", help="Scan only specific library name (e.g. libroblox.so)")
    ap.add_argument("--export-all", type=Path, help="Export all files (.hpp, _frida.js, _ghidra.py, _ida.py, _ledger.json, _summary.md, .json) to prefix")
    ap.add_argument("--out-dir", type=Path, default=Path.cwd(), help="Output directory")
    ap.add_argument("--sig-path", type=Path, help="Custom signatures.json path")
    ap.add_argument("--sig-filter", help="Filter signatures by comma-separated keywords (e.g. 'loadstring,resume,datamodel')")
    ap.add_argument("--no-patterns", action="store_true", help="Disable byte pattern scanning from signatures")
    ap.add_argument("--no-struct-hints", action="store_true", help="Disable struct hints loading from signatures")
    ap.add_argument("--min-len", type=int, default=MARKER_MIN_LEN_DEFAULT, help="Minimum string marker length (default: 4)")
    ap.add_argument("--no-xor", action="store_true", help="Disable XOR key scanning")
    ap.add_argument("--interactive", "-i", action="store_true", help="Interactive wizard mode")
    ap.add_argument("--quiet", action="store_true", help="Suppress banner and verbose logging")
    args = ap.parse_args()
    args.subcommand = "scan"
    return args

def interactive_wizard() -> Dict[str, Any]:
    banner()
    print(f"\n{C.B}── 1. Target Binary / Folder / APK Selection{C.R}")
    default_target = "/storage/emulated/0/Download/AntiGravityProjects/libroblox-dump/extracted_libs"
    while True:
        val = input(f"{C.B}Enter path to .so file, directory of libs, or APK{C.R} {C.DIM}[{default_target}]{C.R}: ").strip()
        target_str = val or default_target
        p = Path(target_str).expanduser().resolve()
        if p.exists():
            print(f"  {C.GREEN}✓{C.R} Target: {p}")
            break
        print(f"  {C.RED}Error: Path not found!{C.R}")

    binaries, temp_test = resolve_binaries_target(p)
    selected_libs = None
    if len(binaries) > 1:
        print(f"\n{C.B}── 2. Library Filter ({len(binaries)} libraries found){C.R}")
        for idx, b in enumerate(binaries, 1):
            print(f"  {C.CYAN}{idx}{C.R}) {b.name:<32} {C.DIM}({b.stat().st_size:,} bytes){C.R}")
        print("  a) All libraries (recommended)")
        print("  r) Main game library only (libroblox.so)")
        print("  c) Custom selection (e.g. 1, 3, 5)")
        lib_choice = input(f"{C.B}Select option [a]: {C.R}").strip().lower() or "a"
        if lib_choice == "r":
            selected_libs = ["libroblox.so"]
        elif lib_choice == "c":
            nums = input(f"{C.B}Enter library numbers (comma-separated): {C.R}").split(",")
            picked = []
            for n in nums:
                try:
                    i = int(n.strip()) - 1
                    if 0 <= i < len(binaries):
                        picked.append(binaries[i].name)
                except ValueError:
                    pass
            if picked:
                selected_libs = picked
                print(f"  {C.GREEN}✓{C.R} Selected: {', '.join(selected_libs)}")

    if temp_test and temp_test.exists():
        try: shutil.rmtree(temp_test)
        except Exception: pass

    print(f"\n{C.B}── 3. Signatures Database & Rules Source{C.R}")
    default_sig_path = "/storage/emulated/0/Download/AntiGravityProjects/libroblox-dump/rbx_finder/signatures.json"
    sig_val = input(f"{C.B}Path to custom signatures.json{C.R} {C.DIM}[{default_sig_path}]{C.R}: ").strip()
    sig_path = Path(sig_val or default_sig_path).expanduser().resolve()
    if not sig_path.exists():
        sig_path = None
        print(f"  {C.YELLOW}! Custom signatures not found; using embedded.{C.R}")
    else:
        print(f"  {C.GREEN}✓{C.R} Using signatures: {sig_path}")

    print(f"\n{C.B}── 4. Signatures Filtering{C.R}")
    print(f"  {C.DIM}Filter specific signatures (e.g. 'loadstring, resume, datamodel', or press Enter for ALL){C.R}")
    filter_val = input(f"{C.B}Keywords/Names [ALL]: {C.R}").strip()
    sig_filter = [k.strip() for k in filter_val.split(",") if k.strip()] if filter_val else None
    if sig_filter:
        print(f"  {C.GREEN}✓{C.R} Will filter signatures containing: {sig_filter}")

    print(f"\n{C.B}── 5. Advanced Analysis Toggles{C.R}")
    xor_val = input(f"{C.B}Enable single-byte XOR key scanning (1..8)? [Y/n]: {C.R}").strip().lower() or "y"
    enable_xor = (xor_val != "n")

    pat_val = input(f"{C.B}Scan byte patterns from signatures (e.g. securityfiltercapabilities)? [Y/n]: {C.R}").strip().lower() or "y"
    scan_patterns = (pat_val != "n")

    struct_val = input(f"{C.B}Include struct hints from signatures.json? [Y/n]: {C.R}").strip().lower() or "y"
    include_struct_hints = (struct_val != "n")

    min_len_val = input(f"{C.B}Minimum string marker length [4]: {C.R}").strip()
    min_marker_len = int(min_len_val) if min_len_val.isdigit() else 4

    print(f"\n{C.B}── 6. Scan Depth / Speed Mode{C.R}")
    print(f"  1) {C.GREEN}fast{C.R}     — High-speed string Xrefs + .eh_frame_hdr exact boundaries (< 20s)")
    print(f"  2) {C.CYAN}normal{C.R}   — Fast + JNI method catalog + caller consensus (< 1 min)")
    print(f"  3) {C.YELLOW}deep{C.R}     — Full vtable RTTI reconstruction + struct store inference")
    print(f"  4) {C.RED}paranoid{C.R} — Brute-force linear disassembly + full caller graph")
    mode_choice = input(f"{C.B}Select speed mode [1]: {C.R}").strip()
    mode_map = {"1": SpeedMode.FAST, "2": SpeedMode.NORMAL, "3": SpeedMode.DEEP, "4": SpeedMode.PARANOID}
    mode = mode_map.get(mode_choice, SpeedMode.FAST)

    print(f"\n{C.B}── 7. Output Artifacts & Prefix{C.R}")
    default_out = "/storage/emulated/0/Download/AntiGravityProjects/libroblox-dump/rbx_finder/rbx_profile"
    out_prefix_val = input(f"{C.B}Export prefix path{C.R} {C.DIM}[{default_out}]{C.R}: ").strip()
    export_all = Path(out_prefix_val or default_out).expanduser().resolve()

    print(f"""\n{C.CYAN}{C.B}
  ┌─────────────────────────────────────────────────────────────┐
  │  Analysis Configuration Summary                             │
  ├─────────────────────────────────────────────────────────────┤
  │ Target:      {str(p)[-44:]:<44} │
  │ Libraries:   {(','.join(selected_libs) if selected_libs else 'All available libraries')[:44]:<44} │
  │ Signatures:  {(str(sig_path.name) if sig_path else 'Default embedded (160+)'):<44} │
  │ Sig Filter:  {(','.join(sig_filter) if sig_filter else 'None (ALL signatures)'):<44} │
  │ Patterns:    {('Enabled' if scan_patterns else 'Disabled'):<44} │
  │ StructHints: {('Enabled' if include_struct_hints else 'Disabled'):<44} │
  │ XOR Scan:    {('Enabled (keys 1..8)' if enable_xor else 'Disabled'):<44} │
  │ Min Length:  {min_marker_len:<44} │
  │ Speed Mode:  {mode.value:<44} │
  │ Export:      {str(export_all.name) + '.*':<44} │
  └─────────────────────────────────────────────────────────────┘{C.R}""")

    confirm = input(f"{C.B}Ready to start analysis? [Y/n]: {C.R}").strip().lower() or "y"
    if confirm == "n":
        print("\n[rbx-finder] cancelled by user.")
        sys.exit(ExitCode.USER_CANCEL)

    return {
        "target": p, "mode": mode, "export_all": export_all,
        "sig_path": sig_path, "sig_filter": sig_filter,
        "enable_xor": enable_xor, "min_marker_len": min_marker_len,
        "scan_patterns": scan_patterns, "include_struct_hints": include_struct_hints,
        "selected_libs": selected_libs,
    }

def main() -> int:
    args = parse_args()

    # Handle probe subcommand
    if args.subcommand == "probe":
        return cmd_probe(args.target.expanduser().resolve(), args.kind, args.value, args.limit, args.binary)

    # Handle ledger subcommand
    if args.subcommand == "ledger":
        lpath = args.ledger.expanduser().resolve()
        if not lpath.exists():
            print(f"Ledger file not found: {lpath}", file=sys.stderr); return 1
        if args.action == "summary":
            return cmd_ledger_summary(lpath)
        elif args.action == "review":
            return cmd_ledger_review(lpath, args.names, show_all=args.all)
        elif args.action == "mark":
            if not args.names:
                print("Error: candidate name required for mark", file=sys.stderr); return 1
            return cmd_ledger_mark(lpath, args.names[0], args.status, args.note, args.by, args.value)
        elif args.action == "check":
            return cmd_ledger_check(lpath)

    # Default / Scan Mode
    target = getattr(args, "target", None)
    if not target or getattr(args, "interactive", False):
        try:
            cfg_dict = interactive_wizard()
            target = cfg_dict["target"]
            mode = cfg_dict["mode"]
            export_all = cfg_dict["export_all"]
            sig_path = cfg_dict["sig_path"]
            sig_filter = cfg_dict["sig_filter"]
            enable_xor = cfg_dict["enable_xor"]
            min_marker_len = cfg_dict["min_marker_len"]
            scan_patterns = cfg_dict["scan_patterns"]
            include_struct_hints = cfg_dict["include_struct_hints"]
            selected_libs = cfg_dict["selected_libs"]
            quiet = False
        except (KeyboardInterrupt, EOFError):
            print("\n[rbx-finder] cancelled"); return ExitCode.USER_CANCEL
    else:
        target = target.expanduser().resolve()
        mode = SpeedMode(args.mode)
        export_all = args.export_all
        quiet = args.quiet
        enable_xor = not args.no_xor
        sig_path = args.sig_path
        sig_filter = [k.strip() for k in args.sig_filter.split(",")] if getattr(args, "sig_filter", None) else None
        min_marker_len = getattr(args, "min_len", MARKER_MIN_LEN_DEFAULT) or MARKER_MIN_LEN_DEFAULT
        scan_patterns = not getattr(args, "no_patterns", False)
        include_struct_hints = not getattr(args, "no_struct_hints", False)
        selected_libs = [args.lib.lower()] if getattr(args, "lib", None) else None

    if not quiet:
        banner()
        print(f"{C.B}[rbx-finder] scanning target: {target} (mode: {mode.value}){C.R}\n")

    scanner = MultiBinaryScanner(
        target, mode=mode, sig_path=sig_path, enable_xor=enable_xor,
        min_marker_len=min_marker_len, sig_filter=sig_filter,
        scan_patterns=scan_patterns, include_struct_hints=include_struct_hints,
        selected_libs=selected_libs
    )
    res = scanner.run()

    if not quiet:
        print(f"\n{C.B}[rbx-finder] scan complete in {res.elapsed_sec}s!{C.R}")
        print(f"  {C.CYAN}Total Binaries Scanned:{C.R} {len(res.libraries)}")
        for bname, b in res.libraries.items():
            print(f"    • {bname:<32} {b.size:>10,} bytes  [{b.arch}]  (build: {b.build_id[:12]}...)")
            print(f"      - .eh_frame_hdr functions: {b.function_starts_count:>8,}")
            print(f"      - JNI methods:             {len(b.jni_methods):>8,}")
            print(f"      - Exported symbols:        {len(b.exports):>8,}")
            print(f"      - Markers matched:         {len(b.markers):>8,}")
            print(f"      - Functions resolved:      {len(b.resolved):>8,}")

        print(f"\n  {C.GREEN}Total Candidates Compiled:{C.R} {len(res.combined_candidates)}")

    # Handle Exports
    if export_all:
        p = export_all.expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        exporter = MultiBinaryExporter(res)

        hdr_path = p.parent / f"{p.stem}.hpp"
        ledger_path = p.parent / f"{p.stem}_ledger.json"
        frida_path = p.parent / f"{p.stem}_frida.js"
        ghidra_path = p.parent / f"{p.stem}_ghidra.py"
        ida_path = p.parent / f"{p.stem}_ida.py"
        sum_path = p.parent / f"{p.stem}_summary.md"
        raw_path = p.parent / f"{p.stem}.json"

        exporter.write_header_hpp(hdr_path)
        exporter.write_ledger_json(ledger_path)
        exporter.write_frida_js(frida_path)
        exporter.write_ghidra_py(ghidra_path)
        exporter.write_ida_py(ida_path)
        exporter.write_summary_md(sum_path)
        exporter.write_raw_json(raw_path)

        if not quiet:
            print(f"\n{C.B}Artifacts exported successfully:{C.R}")
            print(f"  {C.GREEN}✓{C.R} C++ Profile Header:     {hdr_path}")
            print(f"  {C.GREEN}✓{C.R} Candidate Ledger JSON:   {ledger_path}")
            print(f"  {C.GREEN}✓{C.R} Frida Hook Script:       {frida_path}")
            print(f"  {C.GREEN}✓{C.R} Ghidra Script:           {ghidra_path}")
            print(f"  {C.GREEN}✓{C.R} IDA Pro Script:          {ida_path}")
            print(f"  {C.GREEN}✓{C.R} Summary Markdown:        {sum_path}")
            print(f"  {C.GREEN}✓{C.R} Full Raw Dump JSON:      {raw_path}")

    return ExitCode.OK

if __name__ == "__main__":
    sys.exit(main())
