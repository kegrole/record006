"""Parsing of the ELF file header (``Ehdr``), ELF32 and ELF64, both
endiannesses."""

import struct
from dataclasses import dataclass

ELF_MAGIC = b"\x7fELF"

ELFCLASS32 = 1
ELFCLASS64 = 2
CLASS_NAMES = {ELFCLASS32: "ELF32", ELFCLASS64: "ELF64"}

ELFDATA2LSB = 1
ELFDATA2MSB = 2
DATA_NAMES = {ELFDATA2LSB: "little", ELFDATA2MSB: "big"}

ET_NONE = 0
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
ET_CORE = 4
ET_NAMES = {
    ET_NONE: "ET_NONE",
    ET_REL: "ET_REL",
    ET_EXEC: "ET_EXEC",
    ET_DYN: "ET_DYN",
    ET_CORE: "ET_CORE",
}

EM_NAMES = {
    0: "EM_NONE",
    2: "EM_SPARC",
    3: "EM_386",
    8: "EM_MIPS",
    20: "EM_PPC",
    21: "EM_PPC64",
    40: "EM_ARM",
    42: "EM_SH",
    50: "EM_IA_64",
    62: "EM_X86_64",
    183: "EM_AARCH64",
    243: "EM_RISCV",
}


class ELFParseError(ValueError):
    """Raised when a blob cannot be interpreted as an ELF file."""


@dataclass
class ELFHeader:
    elf_class: int
    data_encoding: int
    endianness: str  # struct module prefix: "<" or ">"
    e_type: int
    e_machine: int
    e_version: int
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_flags: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int

    @property
    def class_name(self) -> str:
        return CLASS_NAMES.get(self.elf_class, "UNKNOWN(%d)" % self.elf_class)

    @property
    def endian_name(self) -> str:
        return DATA_NAMES.get(self.data_encoding,
                              "UNKNOWN(%d)" % self.data_encoding)

    @property
    def type_name(self) -> str:
        return ET_NAMES.get(self.e_type, "UNKNOWN(%d)" % self.e_type)

    @property
    def machine_name(self) -> str:
        return EM_NAMES.get(self.e_machine, "UNKNOWN(%d)" % self.e_machine)

    @property
    def is_64bit(self) -> bool:
        return self.elf_class == ELFCLASS64


def parse_elf_header(data: bytes) -> ELFHeader:
    if len(data) < 16:
        raise ELFParseError("file is shorter than the e_ident block")
    if data[:4] != ELF_MAGIC:
        raise ELFParseError("bad ELF magic: %r" % data[:4])

    elf_class = data[4]
    if elf_class not in (ELFCLASS32, ELFCLASS64):
        raise ELFParseError("unknown EI_CLASS=%d" % elf_class)
    data_encoding = data[5]
    if data_encoding not in (ELFDATA2LSB, ELFDATA2MSB):
        raise ELFParseError("unknown EI_DATA=%d" % data_encoding)
    endian = "<" if data_encoding == ELFDATA2LSB else ">"

    if elf_class == ELFCLASS64:
        if len(data) < 64:
            raise ELFParseError("truncated ELF64 header")
        (_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
         e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
         e_shstrndx) = struct.unpack_from(endian + "16sHHIQQQIHHHHHH",
                                          data, 0)
    else:
        if len(data) < 52:
            raise ELFParseError("truncated ELF32 header")
        (_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
         e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
         e_shstrndx) = struct.unpack_from(endian + "16sHHIIIIIHHHHHH",
                                          data, 0)

    return ELFHeader(
        elf_class=elf_class,
        data_encoding=data_encoding,
        endianness=endian,
        e_type=e_type,
        e_machine=e_machine,
        e_version=e_version,
        e_entry=e_entry,
        e_phoff=e_phoff,
        e_shoff=e_shoff,
        e_flags=e_flags,
        e_ehsize=e_ehsize,
        e_phentsize=e_phentsize,
        e_phnum=e_phnum,
        e_shentsize=e_shentsize,
        e_shnum=e_shnum,
        e_shstrndx=e_shstrndx,
    )
