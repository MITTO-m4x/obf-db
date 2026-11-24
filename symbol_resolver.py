#!/usr/bin/env python3
"""
Roblox & Luau Symbol & Offset Resolver
Correlates XRef hits, instruction patterns, and structural clues to derive exact offsets.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from xref_engine import XRefHit


@dataclass
class ResolvedProfile:
    engine_build_id: str = ""
    target_arch: str = "arm64"
    
    # Core Function Offsets (relative to ELF base)
    functions: Dict[str, int] = field(default_factory=dict)
    
    # Structure / Member Offsets
    struct_offsets: Dict[str, int] = field(default_factory=dict)
    
    # Raw XRef records
    raw_xrefs: Dict[str, List[int]] = field(default_factory=dict)
    
    # Confidence metrics
    confidence: Dict[str, float] = field(default_factory=dict)


class SymbolResolver:
    """
    Analyzes raw XRefs and pattern hits to pinpoint exact Luau & Roblox entry points.
    """

    # Mapping of marker name to canonical engine function name
    MARKER_MAP = {
        "loadstring": "luau_load",
        "printidentity": "printidentity",
        "resume": "lua_resume",
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
    }

    def __init__(self, build_id: str, arch: str = "arm64"):
        self.profile = ResolvedProfile(engine_build_id=build_id, target_arch=arch)

    def resolve(self, xref_hits: List[XRefHit], pattern_hits: Dict[str, List[int]], struct_hints: Dict[str, Any]) -> ResolvedProfile:
        # Group xrefs by canonical name
        by_name: Dict[str, List[XRefHit]] = {}
        for hit in xref_hits:
            by_name.setdefault(hit.name, []).append(hit)
            self.profile.raw_xrefs.setdefault(hit.name, []).append(hit.func_offset)

        # Resolve function entry points
        for marker_key, fn_name in self.MARKER_MAP.items():
            if marker_key in by_name:
                hits = by_name[marker_key]
                # Filter to unique function offsets
                funcs = sorted(list({h.func_offset for h in hits}))
                if funcs:
                    self.profile.functions[fn_name] = funcs[0]
                    self.profile.confidence[fn_name] = 1.0 if len(funcs) == 1 else 0.85

        # Incorporate struct hints from RE guide / cache
        for k, v in struct_hints.items():
            if isinstance(v, str) and v.startswith("0x"):
                try:
                    self.profile.struct_offsets[k] = int(v, 16)
                except ValueError:
                    pass
            elif isinstance(v, int):
                self.profile.struct_offsets[k] = v

        # Apply standard defaults for missing offsets based on known architecture
        self._apply_heuristics()

        return self.profile

    def _apply_heuristics(self):
        """
        Applies verified engine heuristics where symbols are obfuscated or stripped.
        """
        so = self.profile.struct_offsets
        # Default verified offsets for ARM64 (from known profile baseline)
        defaults = {
            "scheduler_jobs": 0xd0,
            "scheduler_pointer": 0x6e3a7f0,
            "script_job_vtable": 0x63cbea8,
            "script_job_context": 0x1b0,
            "datamodel_instance": 0x1a8,
            "datamodel_placeid": 0x190,
            "datamodel_gameid": 0x198,
            "datamodel_jobid": 0x118,
            "instance_parent": 0x38,
            "instance_name": 0x48,
            "instance_children": 0x78,
            "vm_global_offset": 0x68,
            "vm_postresume_offset": 0x648,
            "vm_resume_offset": 0x690,
            "lua_resume": 0x307defc,
            "lua_state_extra_space_offset": 0x78,
            "extra_identity_offset": 0x18,
            "extra_capabilities_offset": 0x20,
            "proto_capabilities_offset": 0x48,
            "proto_child_count_offset": 0x3c,
            "proto_children_offset": 0x30,
            "base_identity": 0x3,
            "execution_identity": 0x8,
        }
        for k, v in defaults.items():
            if k not in so:
                so[k] = v
