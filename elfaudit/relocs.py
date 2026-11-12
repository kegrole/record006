"""Relocation parsing for ``SHT_REL`` and ``SHT_RELA`` sections."""

import struct
from dataclasses import dataclass
from typing import Dict, List

from .elf_header import ELFHeader, ELFParseError
from .sections import Section, SHT_REL, SHT_RELA

# A small best-effort map for the architectures used by the fixtures.
X86_64_RELOC_NAMES = {
    0: "R_X86_64_NONE",
    1: "R_X86_64_64",
    2: "R_X86_64_PC32",
    3: "R_X86_64_GOT32",
    4: "R_X86_64_PLT32",
    6: "R_X86_64_GLOB_DAT",
    7: "R_X86_64_JUMP_SLOT",
    8: "R_X86_64_RELATIVE",
}

I386_RELOC_NAMES = {
    0: "R_386_NONE",
    1: "R_386_32",
    2: "R_386_PC32",
    6: "R_386_GLOB_DAT",
    7: "R_386_JMP_SLOT",
    8: "R_386_RELATIVE",
}


@dataclass
class Relocation:
    section: str
    offset: int
    info: int
    addend: int  # 0 for SHT_REL entries
    reloc_type: int
    symbol_index: int
    type_name: str = ""


def _split_info(header: ELFHeader, info: int):
    if header.is_64bit:
        return info >> 32, info & 0xFFFFFFFF
    return info >> 8, info & 0xFF


def parse_relocations(data: bytes, header: ELFHeader,
                      sections: List[Section]) -> List[Relocation]:
    relocations: List[Relocation] = []
    for section in sections:
        if section.sh_type not in (SHT_REL, SHT_RELA):
            continue
        with_addend = section.sh_type == SHT_RELA
        default_entsize = 24 if header.is_64bit else 12
        if not with_addend:
            default_entsize = 16 if header.is_64bit else 8
        entry_size = section.entsize or default_entsize
        if header.is_64bit:
            fmt = header.endianness + ("QQq" if with_addend else "QQ")
        else:
            fmt = header.endianness + ("IIi" if with_addend else "II")
        count = section.size // entry_size
        for index in range(count):
            pos = section.offset + index * entry_size
            if pos + entry_size > len(data):
                raise ELFParseError(
                    "relocation %d in section %r runs past end of file"
                    % (index, section.name))
            fields = struct.unpack_from(fmt, data, pos)
            r_offset, r_info = fields[0], fields[1]
            r_addend = fields[2] if with_addend else 0
            symbol_index, reloc_type = _split_info(header, r_info)
            relocations.append(Relocation(
                section=section.name,
                offset=r_offset,
                info=r_info,
                addend=r_addend,
                reloc_type=reloc_type,
                symbol_index=symbol_index,
                type_name=_type_name(header, reloc_type),
            ))
    return relocations


def _type_name(header: ELFHeader, reloc_type: int) -> str:
    names = X86_64_RELOC_NAMES if header.is_64bit else I386_RELOC_NAMES
    return names.get(reloc_type, "R_%d" % reloc_type)


def relocations_by_section(
        relocations: List[Relocation]) -> Dict[str, List[Relocation]]:
    grouped: Dict[str, List[Relocation]] = {}
    for relocation in relocations:
        grouped.setdefault(relocation.section, []).append(relocation)
    return grouped
