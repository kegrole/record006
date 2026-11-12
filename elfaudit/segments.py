"""Program header (segment) parsing, including the dynamic segment."""

import struct
from dataclasses import dataclass, field
from typing import List, Optional

from .elf_header import ELFHeader, ELFParseError
from .sections import SHT_DYNAMIC, Section

PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_TLS = 7
PT_GNU_EH_FRAME = 0x6474E550
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PT_GNU_PROPERTY = 0x6474E553

PT_NAMES = {
    PT_NULL: "PT_NULL",
    PT_LOAD: "PT_LOAD",
    PT_DYNAMIC: "PT_DYNAMIC",
    PT_INTERP: "PT_INTERP",
    PT_NOTE: "PT_NOTE",
    PT_SHLIB: "PT_SHLIB",
    PT_PHDR: "PT_PHDR",
    PT_TLS: "PT_TLS",
    PT_GNU_EH_FRAME: "PT_GNU_EH_FRAME",
    PT_GNU_STACK: "PT_GNU_STACK",
    PT_GNU_RELRO: "PT_GNU_RELRO",
    PT_GNU_PROPERTY: "PT_GNU_PROPERTY",
}

PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_STRSZ = 10
DT_SONAME = 14
DT_INIT = 12
DT_FINI = 13
DT_BIND_NOW = 24
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB

DT_NAMES = {
    DT_NULL: "DT_NULL",
    DT_NEEDED: "DT_NEEDED",
    DT_PLTRELSZ: "DT_PLTRELSZ",
    DT_HASH: "DT_HASH",
    DT_STRTAB: "DT_STRTAB",
    DT_SYMTAB: "DT_SYMTAB",
    DT_RELA: "DT_RELA",
    DT_RELASZ: "DT_RELASZ",
    DT_STRSZ: "DT_STRSZ",
    DT_INIT: "DT_INIT",
    DT_FINI: "DT_FINI",
    DT_SONAME: "DT_SONAME",
    DT_BIND_NOW: "DT_BIND_NOW",
    DT_INIT_ARRAY: "DT_INIT_ARRAY",
    DT_FINI_ARRAY: "DT_FINI_ARRAY",
    DT_FLAGS: "DT_FLAGS",
    DT_FLAGS_1: "DT_FLAGS_1",
}

DF_1_NOW = 0x1
DF_BIND_NOW = 0x8


@dataclass
class Segment:
    index: int
    p_type: int
    flags: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    align: int

    @property
    def type_name(self) -> str:
        return PT_NAMES.get(self.p_type, "PT_%#x" % self.p_type)

    def flags_string(self) -> str:
        chars = "R" if self.flags & PF_R else "-"
        chars += "W" if self.flags & PF_W else "-"
        chars += "X" if self.flags & PF_X else "-"
        return chars


@dataclass
class DynamicEntry:
    tag: int
    value: int

    @property
    def tag_name(self) -> str:
        return DT_NAMES.get(self.tag, "DT_%#x" % self.tag)


@dataclass
class DynamicInfo:
    entries: List[DynamicEntry] = field(default_factory=list)

    def has_tag(self, tag: int) -> bool:
        return any(entry.tag == tag for entry in self.entries)

    def value_of(self, tag: int) -> Optional[int]:
        for entry in self.entries:
            if entry.tag == tag:
                return entry.value
        return None


def parse_segments(data: bytes, header: ELFHeader) -> List[Segment]:
    if header.e_phoff == 0 or header.e_phnum == 0:
        return []
    if header.is_64bit:
        fmt = header.endianness + "IIQQQQQQ"
        entry_size = 56
    else:
        fmt = header.endianness + "IIIIIIII"
        entry_size = 32
    step = header.e_phentsize or entry_size

    segments: List[Segment] = []
    for index in range(header.e_phnum):
        pos = header.e_phoff + index * step
        if pos + entry_size > len(data):
            raise ELFParseError(
                "program header %d runs past end of file" % index)
        fields = struct.unpack_from(fmt, data, pos)
        if header.is_64bit:
            (p_type, flags, offset, vaddr, paddr, filesz, memsz,
             align) = fields
        else:
            (p_type, offset, vaddr, paddr, filesz, memsz, flags,
             align) = fields
        segments.append(Segment(
            index=index,
            p_type=p_type,
            flags=flags,
            offset=offset,
            vaddr=vaddr,
            paddr=paddr,
            filesz=filesz,
            memsz=memsz,
            align=align,
        ))
    return segments


def find_segment(segments: List[Segment], p_type: int) -> Optional[Segment]:
    for segment in segments:
        if segment.p_type == p_type:
            return segment
    return None


def parse_dynamic(data: bytes, header: ELFHeader,
                  segments: List[Segment],
                  sections: Optional[List[Section]] = None
                  ) -> Optional[DynamicInfo]:
    """Decode the dynamic table. Prefer PT_DYNAMIC; fall back to the
    SHT_DYNAMIC section when no usable program header exists."""
    segment = find_segment(segments, PT_DYNAMIC)
    if segment is not None and segment.filesz:
        dyn_offset = segment.offset
        dyn_size = segment.filesz
    else:
        if not sections:
            return None
        dyn_section = next((section for section in sections
                            if section.sh_type == SHT_DYNAMIC), None)
        if dyn_section is None or dyn_section.size == 0:
            return None
        dyn_offset = dyn_section.offset
        dyn_size = dyn_section.size
    fmt = header.endianness + ("qQ" if header.is_64bit else "iI")
    entry_size = 16 if header.is_64bit else 8
    entries: List[DynamicEntry] = []
    pos = dyn_offset
    end = min(dyn_offset + dyn_size, len(data))
    while pos + entry_size <= end:
        tag, value = struct.unpack_from(fmt, data, pos)
        entries.append(DynamicEntry(tag=tag, value=value))
        if tag == DT_NULL:
            break
        pos += entry_size
    return DynamicInfo(entries=entries)
