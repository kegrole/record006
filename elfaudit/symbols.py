"""Symbol table parsing for ``SHT_SYMTAB`` (``.symtab``) and
``SHT_DYNSYM`` (``.dynsym``) sections."""

import struct
from dataclasses import dataclass
from typing import Dict, List

from .elf_header import ELFHeader, ELFParseError
from .sections import Section, SHT_DYNSYM, SHT_SYMTAB, SHN_UNDEF, read_string

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4

STT_NAMES = {
    STT_NOTYPE: "STT_NOTYPE",
    STT_OBJECT: "STT_OBJECT",
    STT_FUNC: "STT_FUNC",
    STT_SECTION: "STT_SECTION",
    STT_FILE: "STT_FILE",
}

STB_NAMES = {
    STB_LOCAL: "STB_LOCAL",
    STB_GLOBAL: "STB_GLOBAL",
    STB_WEAK: "STB_WEAK",
}


@dataclass
class Symbol:
    index: int
    name_offset: int
    info: int
    other: int
    shndx: int
    value: int
    size: int
    name: str = ""

    @property
    def sym_type(self) -> int:
        return self.info & 0xF

    @property
    def binding(self) -> int:
        return self.info >> 4

    @property
    def type_name(self) -> str:
        return STT_NAMES.get(self.sym_type, "STT_%d" % self.sym_type)

    @property
    def binding_name(self) -> str:
        return STB_NAMES.get(self.binding, "STB_%d" % self.binding)

    @property
    def is_import(self) -> bool:
        # An undefined symbol (SHN_UNDEF) carrying a name is an import that
        # must be resolved by the dynamic linker.
        return self.shndx == SHN_UNDEF and bool(self.name)


def _section_blob(data: bytes, sections: List[Section], section: Section) -> bytes:
    if not (0 <= section.link < len(sections)):
        return b""
    linked = sections[section.link]
    return data[linked.offset:linked.offset + linked.size]


def parse_symbol_table(data: bytes, header: ELFHeader, section: Section,
                       sections: List[Section]) -> List[Symbol]:
    if section is None or section.size == 0:
        return []
    entry_size = 24 if header.is_64bit else 16
    if section.entsize:
        entry_size = section.entsize
    count = section.size // entry_size
    if header.is_64bit:
        fmt = header.endianness + "IBBHQQ"
    else:
        fmt = header.endianness + "IIIBBH"

    strtab_blob = _section_blob(data, sections, section)

    symbols: List[Symbol] = []
    for index in range(count):
        pos = section.offset + index * entry_size
        if pos + entry_size > len(data):
            raise ELFParseError(
                "symbol %d in section %r runs past end of file"
                % (index, section.name))
        fields = struct.unpack_from(fmt, data, pos)
        if header.is_64bit:
            name_offset, info, other, shndx, value, size = fields
        else:
            name_offset, value, size, info, other, shndx = fields
        symbols.append(Symbol(
            index=index,
            name_offset=name_offset,
            info=info,
            other=other,
            shndx=shndx,
            value=value,
            size=size,
            name=read_string(strtab_blob, name_offset),
        ))
    return symbols


def parse_all_symbols(data: bytes, header: ELFHeader,
                      sections: List[Section]) -> Dict[str, List[Symbol]]:
    """Return ``{"dynsym": [...], "symtab": [...]}``; lists are empty when
    the corresponding section is absent."""
    result: Dict[str, List[Symbol]] = {"dynsym": [], "symtab": []}
    for section in sections:
        if section.sh_type == SHT_DYNSYM:
            result["dynsym"] = parse_symbol_table(data, header, section,
                                                   sections)
        elif section.sh_type == SHT_SYMTAB:
            result["symtab"] = parse_symbol_table(data, header, section,
                                                   sections)
    return result


def imported_symbols(symbols: List[Symbol]) -> List[Symbol]:
    return [symbol for symbol in symbols if symbol.is_import]
