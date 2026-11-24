#!/usr/bin/env python3
"""
High-Speed ELF32 / ELF64 Parser for RBX-Finder
Zero-copy parsing using mmap and struct.
"""
from __future__ import annotations

import mmap
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class Section:
    name: str
    sh_type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int
    entsize: int


@dataclass
class Segment:
    p_type: int
    flags: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    align: int


class ElfParser:
    PT_LOAD = 1
    PT_DYNAMIC = 2
    PT_NOTE = 4
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_NOBITS = 8
    SHT_DYNSYM = 11

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.file = open(self.path, "rb")
        self.size = self.path.stat().st_size
        self.mm = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        
        self.is_64 = False
        self.is_little_endian = True
        self.machine = 0
        self.entry = 0
        self.phoff = 0
        self.shoff = 0
        self.flags = 0
        self.ehsize = 0
        self.phentsize = 0
        self.phnum = 0
        self.shentsize = 0
        self.shnum = 0
        self.shstrndx = 0
        
        self.segments: List[Segment] = []
        self.sections: List[Section] = []
        self.section_map: Dict[str, Section] = {}
        self.build_id: str = ""

        self._parse_header()
        self._parse_segments()
        self._parse_sections()
        self._extract_build_id()

    def close(self):
        try:
            self.mm.close()
            self.file.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _parse_header(self):
        ident = self.mm[:16]
        if ident[:4] != b"\x7fELF":
            raise ValueError(f"{self.path} is not a valid ELF file")
        
        self.is_64 = (ident[4] == 2)
        self.is_little_endian = (ident[5] == 1)
        endian = "<" if self.is_little_endian else ">"

        if self.is_64:
            hdr = struct.unpack_from(endian + "HHIQQQIHHHHHH", self.mm, 16)
            self.e_type = hdr[0]
            self.machine = hdr[1]
            self.version = hdr[2]
            self.entry = hdr[3]
            self.phoff = hdr[4]
            self.shoff = hdr[5]
            self.flags = hdr[6]
            self.ehsize = hdr[7]
            self.phentsize = hdr[8]
            self.phnum = hdr[9]
            self.shentsize = hdr[10]
            self.shnum = hdr[11]
            self.shstrndx = hdr[12]
        else:
            hdr = struct.unpack_from(endian + "HHIIIIIHHHHHH", self.mm, 16)
            self.e_type = hdr[0]
            self.machine = hdr[1]
            self.version = hdr[2]
            self.entry = hdr[3]
            self.phoff = hdr[4]
            self.shoff = hdr[5]
            self.flags = hdr[6]
            self.ehsize = hdr[7]
            self.phentsize = hdr[8]
            self.phnum = hdr[9]
            self.shentsize = hdr[10]
            self.shnum = hdr[11]
            self.shstrndx = hdr[12]

    def _parse_segments(self):
        endian = "<" if self.is_little_endian else ">"
        for i in range(self.phnum):
            off = self.phoff + i * self.phentsize
            if off + self.phentsize > self.size:
                break
            if self.is_64:
                # IIQQQQQQ
                p = struct.unpack_from(endian + "IIQQQQQQ", self.mm, off)
                self.segments.append(Segment(
                    p_type=p[0], flags=p[1], offset=p[2], vaddr=p[3],
                    paddr=p[4], filesz=p[5], memsz=p[6], align=p[7]
                ))
            else:
                # IIIIIIII
                p = struct.unpack_from(endian + "IIIIIIII", self.mm, off)
                self.segments.append(Segment(
                    p_type=p[0], offset=p[1], vaddr=p[2], paddr=p[3],
                    filesz=p[4], memsz=p[5], flags=p[6], align=p[7]
                ))

    def _parse_sections(self):
        if self.shoff == 0 or self.shnum == 0:
            return
        endian = "<" if self.is_little_endian else ">"
        
        # Read shstrtab offset first
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
            if off + self.shentsize > self.size:
                break
            if self.is_64:
                s = struct.unpack_from(endian + "IIQQQQIIQQ", self.mm, off)
                raw_sections.append(s)
            else:
                s = struct.unpack_from(endian + "IIIIIIIIII", self.mm, off)
                raw_sections.append(s)

        for s in raw_sections:
            name_idx = s[0]
            name = ""
            if shstr_file_off < self.size:
                start = shstr_file_off + name_idx
                end = self.mm.find(b"\0", start)
                if end != -1:
                    name = self.mm[start:end].decode("ascii", errors="ignore")
            sec = Section(
                name=name, sh_type=s[1], flags=s[2], addr=s[3],
                offset=s[4], size=s[5], link=s[6], info=s[7],
                addralign=s[8], entsize=s[9]
            )
            self.sections.append(sec)
            if name:
                self.section_map[name] = sec

    def _extract_build_id(self):
        for seg in self.segments:
            if seg.p_type == self.PT_NOTE:
                data = self.mm[seg.offset:seg.offset + seg.filesz]
                idx = 0
                while idx + 12 <= len(data):
                    namesz, descsz, ntype = struct.unpack_from("<III", data, idx)
                    namesz_aligned = (namesz + 3) & ~3
                    descsz_aligned = (descsz + 3) & ~3
                    idx += 12
                    name = data[idx:idx + namesz].rstrip(b"\0")
                    idx += namesz_aligned
                    desc = data[idx:idx + descsz]
                    idx += descsz_aligned
                    if ntype == 3 and name == b"GNU":  # NT_GNU_BUILD_ID
                        self.build_id = desc.hex()
                        return

    def vaddr_to_offset(self, vaddr: int) -> Optional[int]:
        for seg in self.segments:
            if seg.p_type == self.PT_LOAD:
                if seg.vaddr <= vaddr < seg.vaddr + seg.filesz:
                    return seg.offset + (vaddr - seg.vaddr)
        return None

    def offset_to_vaddr(self, offset: int) -> Optional[int]:
        for seg in self.segments:
            if seg.p_type == self.PT_LOAD:
                if seg.offset <= offset < seg.offset + seg.filesz:
                    return seg.vaddr + (offset - seg.offset)
        return None

    def get_section(self, name: str) -> Optional[Section]:
        return self.section_map.get(name)

    def get_section_bytes(self, name: str) -> bytes:
        sec = self.get_section(name)
        if not sec:
            return b""
        return self.mm[sec.offset:sec.offset + sec.size]
