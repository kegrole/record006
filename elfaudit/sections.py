"""Parsing of section headers (``Shdr``) and section-name resolution via
the section header string table."""

import struct
from dataclasses import dataclass
from typing import List, Optional

from .elf_header import ELFHeader

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11

SHT_NAMES = {
    SHT_NULL: "SHT_NULL",
    SHT_PROGBITS: "SHT_PROGBITS",
    SHT_SYMTAB: "SHT_SYMTAB",
    SHT_STRTAB: "SHT_STRTAB",
    SHT_RELA: "SHT_RELA",
    SHT_HASH: "SHT_HASH",
    SHT_DYNAMIC: "SHT_DYNAMIC",
    SHT_NOTE: "SHT_NOTE",
    SHT_NOBITS: "SHT_NOBITS",
    SHT_REL: "SHT_REL",
    SHT_DYNSYM: "SHT_DYNSYM",
}

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

SHN_UNDEF = 0
SHN_XINDEX = 0xFFFF


@dataclass
class Section:
    index: int
    name: str
    name_offset: int
    sh_type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int
    entsize: int

    @property
    def type_name(self) -> str:
        return SHT_NAMES.get(self.sh_type, "UNKNOWN(0x%x)" % self.sh_type)


def _read_c_string(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("utf-8", errors="replace")


def read_string(blob: bytes, offset: int) -> str:
    """Read a NUL-terminated string from a string-table blob."""
    return _read_c_string(blob, offset)


def _unpack_raw_section(header: ELFHeader, data: bytes, position: int):
    shoff = header.e_shoff
    entsize = header.e_shentsize or (64 if header.is_64bit else 40)
    pos = shoff + position * entsize
    if header.is_64bit:
        return struct.unpack_from(header.endianness + "IIQQQQIIQQ", data, pos)
    return struct.unpack_from(header.endianness + "IIIIIIIIII", data, pos)


def parse_sections(data: bytes, header: ELFHeader) -> List[Section]:
    if header.e_shoff == 0:
        return []

    shnum = header.e_shnum
    shstrndx = header.e_shstrndx
    if shnum == 0:
        # Extended section numbering: real count lives in section 0.
        raw_zero = _unpack_raw_section(header, data, 0)
        shnum = raw_zero[5]
        if shstrndx == SHN_XINDEX:
            shstrndx = raw_zero[6]
    if shnum == 0:
        return []

    raw_entries = [_unpack_raw_section(header, data, i)
                   for i in range(shnum)]

    shstrtab = b""
    if 0 < shstrndx < shnum:
        entry = raw_entries[shstrndx]
        str_offset, str_size = entry[4], entry[5]
        if str_size > 0:
            shstrtab = data[str_offset:str_offset + str_size]

    sections: List[Section] = []
    for index, entry in enumerate(raw_entries):
        (name_offset, sh_type, flags, addr, offset, size, link, info,
         addralign, entsize) = entry
        name = _read_c_string(shstrtab, name_offset) if shstrtab else ""
        sections.append(Section(
            index=index,
            name=name,
            name_offset=name_offset,
            sh_type=sh_type,
            flags=flags,
            addr=addr,
            offset=offset,
            size=size,
            link=link,
            info=info,
            addralign=addralign,
            entsize=entsize,
        ))
    return sections


def find_section(sections: List[Section], name: str) -> Optional[Section]:
    for section in sections:
        if section.name == name:
            return section
    return None


def section_data(data: bytes, section: Optional[Section]) -> bytes:
    if section is None or section.sh_type == SHT_NOBITS:
        return b""
    return data[section.offset:section.offset + section.size]
