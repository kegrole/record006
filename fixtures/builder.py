"""A minimal, generic ELF builder used to synthesize test fixtures.

The builder supports ELFCLASS32/ELFCLASS64 and little/big endian so the
auditor cannot rely on a single hand-crafted byte layout.
"""

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional


class StringTable:
    """Collects NUL-terminated strings into an ELF string table."""

    def __init__(self) -> None:
        self._blob = bytearray(b"\x00")
        self._index: Dict[str, int] = {"": 0}

    def add(self, value: str) -> int:
        if value in self._index:
            return self._index[value]
        offset = len(self._blob)
        self._index[value] = offset
        self._blob.extend(value.encode("utf-8"))
        self._blob.append(0)
        return offset

    def blob(self) -> bytes:
        return bytes(self._blob)


@dataclass
class SectionSpec:
    name: str
    sh_type: int
    data: bytes = b""
    flags: int = 0
    addr: int = 0
    link: Optional[str] = None
    info: int = 0
    addralign: int = 1
    entsize: int = 0
    nobits: bool = False


@dataclass
class ProgramHeaderSpec:
    p_type: int
    flags: int = 0
    offset: int = 0
    vaddr: int = 0
    paddr: int = 0
    filesz: int = 0
    memsz: int = 0
    align: int = 0
    offset_from_section: Optional[str] = None


def align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


class ELFBuilder:
    def __init__(self, elf_class: int, endian: str, e_type: int,
                 e_machine: int, entry: int = 0x1000) -> None:
        if elf_class not in (1, 2):
            raise ValueError("elf_class must be ELFCLASS32(1) or ELFCLASS64(2)")
        if endian not in ("<", ">"):
            raise ValueError("endian must be < (little) or > (big)")
        self.elf_class = elf_class
        self.is_64 = elf_class == 2
        self.endian = endian
        self.e_type = e_type
        self.e_machine = e_machine
        self.entry = entry
        self.sections: List[SectionSpec] = []
        self.program_headers: List[ProgramHeaderSpec] = []

    def add_section(self, spec: SectionSpec) -> SectionSpec:
        self.sections.append(spec)
        return spec

    def add_program_header(self, spec: ProgramHeaderSpec) -> ProgramHeaderSpec:
        self.program_headers.append(spec)
        return spec

    def pack_symbol(self, name_offset: int, info: int, other: int,
                    shndx: int, value: int, size: int) -> bytes:
        if self.is_64:
            return struct.pack(self.endian + "IBBHQQ", name_offset, info,
                               other, shndx, value, size)
        return struct.pack(self.endian + "IIIBBH", name_offset, value, size,
                           info, other, shndx)

    def pack_relocation(self, r_offset: int, r_info: int,
                        r_addend: Optional[int] = None) -> bytes:
        if r_addend is None:
            if self.is_64:
                return struct.pack(self.endian + "QQ", r_offset, r_info)
            return struct.pack(self.endian + "II", r_offset, r_info)
        if self.is_64:
            return struct.pack(self.endian + "QQq", r_offset, r_info, r_addend)
        return struct.pack(self.endian + "IIi", r_offset, r_info, r_addend)

    def pack_dynamic(self, tag: int, value: int) -> bytes:
        if self.is_64:
            return struct.pack(self.endian + "qQ", tag, value)
        return struct.pack(self.endian + "iI", tag, value)

    def r_info(self, symbol_index: int, reloc_type: int) -> int:
        if self.is_64:
            return (symbol_index << 32) | (reloc_type & 0xFFFFFFFF)
        return (symbol_index << 8) | (reloc_type & 0xFF)

    def build(self) -> bytes:
        endian = self.endian
        ehsize = 64 if self.is_64 else 52
        phentsize = 56 if self.is_64 else 32
        shentsize = 64 if self.is_64 else 40

        shstrtab = SectionSpec(name=".shstrtab", sh_type=3,
                               data=b"", addralign=1)
        # The section header string table is emitted as the first real
        # section so its own name offset stays aligned with its position.
        all_sections: List[SectionSpec] = [shstrtab] + list(self.sections)

        shstr = StringTable()
        name_offsets: List[int] = [shstr.add(section.name)
                                   for section in all_sections]
        shstrtab.data = shstr.blob()
        total_sections = len(all_sections) + 1
        shstrndx = 1

        index_by_name: Dict[str, int] = {}
        for position, section in enumerate(all_sections, start=1):
            index_by_name[section.name] = position

        phnum = len(self.program_headers)
        phoff = ehsize if phnum else 0
        data_start = ehsize + phnum * phentsize

        cursor = data_start
        offsets: List[int] = []
        for section in all_sections:
            if section.nobits or section.sh_type == 8:
                offsets.append(0)
                continue
            cursor = align_up(cursor, max(section.addralign, 1))
            offsets.append(cursor)
            cursor += len(section.data)

        shoff = align_up(cursor, 8 if self.is_64 else 4)

        # Backfill segment offsets/sizes that must track a section's real
        # layout position so program headers never depend on hard-coded
        # byte offsets.
        for program_header in self.program_headers:
            if program_header.offset_from_section is None:
                continue
            target_position = index_by_name[program_header.offset_from_section]
            target_section = all_sections[target_position - 1]
            target_offset = offsets[target_position - 1]
            program_header.offset = target_offset
            program_header.filesz = len(target_section.data)
            program_header.memsz = len(target_section.data)
        total_size = shoff + total_sections * shentsize
        blob = bytearray(total_size)

        for section, offset in zip(all_sections, offsets):
            if section.nobits or section.sh_type == 8 or not section.data:
                continue
            blob[offset:offset + len(section.data)] = section.data

        ei_class = self.elf_class
        ei_data = 1 if endian == "<" else 2
        e_ident = bytearray(16)
        e_ident[0:4] = b"\x7fELF"
        e_ident[4] = ei_class
        e_ident[5] = ei_data
        e_ident[6] = 1
        if self.is_64:
            struct.pack_into(endian + "16sHHIQQQIHHHHHH", blob, 0,
                             bytes(e_ident), self.e_type, self.e_machine, 1,
                             self.entry, phoff, shoff, 0, ehsize,
                             phentsize, phnum, shentsize, total_sections,
                             shstrndx)
        else:
            struct.pack_into(endian + "16sHHIIIIIHHHHHH", blob, 0,
                             bytes(e_ident), self.e_type, self.e_machine, 1,
                             self.entry, phoff, shoff, 0, ehsize,
                             phentsize, phnum, shentsize, total_sections,
                             shstrndx)

        for position, ph in enumerate(self.program_headers):
            pos = phoff + position * phentsize
            if self.is_64:
                struct.pack_into(endian + "IIQQQQQQ", blob, pos,
                                 ph.p_type, ph.flags, ph.offset, ph.vaddr,
                                 ph.paddr, ph.filesz, ph.memsz, ph.align)
            else:
                struct.pack_into(endian + "IIIIIIII", blob, pos,
                                 ph.p_type, ph.offset, ph.vaddr, ph.paddr,
                                 ph.filesz, ph.memsz, ph.flags, ph.align)

        self._write_section_header(blob, shoff, shentsize, 0,
                                   SectionSpec(name="", sh_type=0), 0,
                                   index_by_name)
        for position, (section, offset) in enumerate(
                zip(all_sections, offsets), start=1):
            self._write_section_header(blob, shoff, shentsize, position,
                                       section, offset, index_by_name,
                                       name_offset=name_offsets[position - 1])
        return bytes(blob)

    def _write_section_header(self, blob: bytearray, shoff: int,
                              shentsize: int, position: int,
                              section: SectionSpec, offset: int,
                              index_by_name: Dict[str, int],
                              name_offset: int = 0) -> None:
        link = 0
        if section.link is not None:
            link = index_by_name.get(section.link, 0)
        size = 0 if (section.nobits or section.sh_type == 8) else len(section.data)
        pos = shoff + position * shentsize
        if self.is_64:
            struct.pack_into(self.endian + "IIQQQQIIQQ", blob, pos,
                             name_offset, section.sh_type, section.flags,
                             section.addr, offset, size, link, section.info,
                             section.addralign, section.entsize)
        else:
            struct.pack_into(self.endian + "IIIIIIIIII", blob, pos,
                             name_offset, section.sh_type, section.flags,
                             section.addr, offset, size, link, section.info,
                             section.addralign, section.entsize)
