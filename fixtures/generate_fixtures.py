"""Generate the synthetic ELF fixtures used by the test-suite and demo.

Run with::

    python fixtures/generate_fixtures.py

All blobs are produced by :mod:`fixtures.builder`, a generic ELF writer
supporting both ELF classes and both byte orders; nothing about the audit
results is hard-coded to a particular byte arrangement.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fixtures.builder import (  # noqa: E402
    ELFBuilder, ProgramHeaderSpec, SectionSpec, StringTable,
)


SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_DYNAMIC = 6
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

STB_GLOBAL = 1
STT_FUNC = 2
STT_OBJECT = 1

DT_NULL = 0
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_BIND_NOW = 24
DT_FLAGS_1 = 0x6FFFFFFB
DF_1_NOW = 0x1

ET_EXEC = 2
ET_DYN = 3
ELFCLASS32 = 1
ELFCLASS64 = 2


def _func_info():
    return (STB_GLOBAL << 4) | STT_FUNC


def build_exec_64_little():
    """ELF64 LSB ET_EXEC: executable stack, no PIE, strcpy import, not
    stripped, full RELRO. Four failed checks (NX, PIE, dangerous, stripped),
    RELRO passes."""
    builder = ELFBuilder(ELFCLASS64, "<", ET_EXEC, e_machine=62,  # EM_X86_64
                         entry=0x401000)

    dynstr = StringTable()
    strcpy_off = dynstr.add("strcpy")
    printf_off = dynstr.add("printf")
    strtab = StringTable()
    main_off = strtab.add("main")

    # .dynsym: null symbol, then the two undefined imports.
    dynsym_blob = b"".join([
        builder.pack_symbol(0, 0, 0, 0, 0, 0),
        builder.pack_symbol(strcpy_off, _func_info(), 0, 0, 0, 0),
        builder.pack_symbol(printf_off, _func_info(), 0, 0, 0, 0),
    ])

    # Full RELRO evidence: DT_FLAGS_1 carrying DF_1_NOW plus DT_BIND_NOW.
    dynamic_blob = b"".join([
        builder.pack_dynamic(DT_SYMTAB, 0x400200),
        builder.pack_dynamic(DT_STRTAB, 0x400300),
        builder.pack_dynamic(DT_STRSZ, len(dynstr.blob())),
        builder.pack_dynamic(DT_FLAGS_1, DF_1_NOW),
        builder.pack_dynamic(DT_BIND_NOW, 0),
        builder.pack_dynamic(DT_NULL, 0),
    ])

    rela_blob = builder.pack_relocation(0x401008, builder.r_info(1, 8),
                                        r_addend=0)

    symtab_blob = b"".join([
        builder.pack_symbol(0, 0, 0, 0, 0, 0),
        builder.pack_symbol(main_off, _func_info(), 0, 1, 0x401000, 32),
    ])

    builder.add_section(SectionSpec(
        name=".text", sh_type=SHT_PROGBITS,
        data=b"\x90\xc3", flags=SHF_ALLOC | SHF_EXECINSTR, addr=0x401000,
        addralign=16))
    builder.add_section(SectionSpec(name=".dynsym", sh_type=SHT_DYNSYM,
                                    data=dynsym_blob,
                                    flags=SHF_ALLOC, addr=0x400200,
                                    link=".dynstr", info=1, addralign=8,
                                    entsize=24))
    builder.add_section(SectionSpec(name=".dynstr", sh_type=SHT_STRTAB,
                                    data=dynstr.blob(), flags=SHF_ALLOC,
                                    addr=0x400300, addralign=1))
    builder.add_section(SectionSpec(name=".dynamic", sh_type=SHT_DYNAMIC,
                                    data=dynamic_blob,
                                    flags=SHF_ALLOC | SHF_WRITE,
                                    addr=0x400400, link=".dynstr",
                                    addralign=8, entsize=16))
    builder.add_section(SectionSpec(name=".rela.dyn", sh_type=SHT_RELA,
                                    data=rela_blob, flags=SHF_ALLOC,
                                    addr=0x400500, link=".dynsym",
                                    addralign=8, entsize=24))
    builder.add_section(SectionSpec(name=".symtab", sh_type=SHT_SYMTAB,
                                    data=symtab_blob, link=".strtab", info=1,
                                    addralign=8, entsize=24))
    builder.add_section(SectionSpec(name=".strtab", sh_type=SHT_STRTAB,
                                    data=strtab.blob(), addralign=1))

    builder.add_program_header(ProgramHeaderSpec(
        p_type=PT_LOAD, flags=PF_R | PF_X, offset=0, vaddr=0x400000,
        paddr=0x400000, filesz=0x2000, memsz=0x2000, align=0x1000))
    builder.add_program_header(ProgramHeaderSpec(
        p_type=PT_DYNAMIC, flags=PF_R | PF_W, vaddr=0x400400,
        paddr=0x400400, align=8, offset_from_section=".dynamic"))
    builder.add_program_header(ProgramHeaderSpec(
        p_type=PT_GNU_STACK, flags=PF_R | PF_W | PF_X, offset=0, vaddr=0,
        paddr=0, filesz=0, memsz=0, align=0x10))
    builder.add_program_header(ProgramHeaderSpec(
        p_type=PT_GNU_RELRO, flags=PF_R, vaddr=0x400400,
        paddr=0x400400, align=1, offset_from_section=".dynamic"))
    return builder.build()


def build_dyn_32_little():
    """ELF32 LSB ET_DYN: non-exec stack, stripped, only imports puts, no
    PT_GNU_RELRO. Only RELRO must fail."""
    builder = ELFBuilder(ELFCLASS32, "<", ET_DYN, e_machine=3,  # EM_386
                         entry=0x500)

    dynstr = StringTable()
    puts_off = dynstr.add("puts")

    dynsym_blob = b"".join([
        builder.pack_symbol(0, 0, 0, 0, 0, 0),
        builder.pack_symbol(puts_off, _func_info(), 0, 0, 0, 0),
    ])
    dynamic_blob = b"".join([
        builder.pack_dynamic(DT_SYMTAB, 0x200),
        builder.pack_dynamic(DT_STRTAB, 0x300),
        builder.pack_dynamic(DT_STRSZ, len(dynstr.blob())),
        builder.pack_dynamic(DT_NULL, 0),
    ])
    rel_blob = builder.pack_relocation(0x510, builder.r_info(1, 6))

    builder.add_section(SectionSpec(
        name=".text", sh_type=SHT_PROGBITS, data=b"\x90\xc3",
        flags=SHF_ALLOC | SHF_EXECINSTR, addr=0x500, addralign=16))
    builder.add_section(SectionSpec(name=".dynsym", sh_type=SHT_DYNSYM,
                                    data=dynsym_blob, flags=SHF_ALLOC,
                                    addr=0x200, link=".dynstr", info=1,
                                    addralign=4, entsize=16))
    builder.add_section(SectionSpec(name=".dynstr", sh_type=SHT_STRTAB,
                                    data=dynstr.blob(), flags=SHF_ALLOC,
                                    addr=0x300, addralign=1))
    builder.add_section(SectionSpec(name=".dynamic", sh_type=SHT_DYNAMIC,
                                    data=dynamic_blob,
                                    flags=SHF_ALLOC | SHF_WRITE, addr=0x400,
                                    link=".dynstr", addralign=4, entsize=8))
    builder.add_section(SectionSpec(name=".rel.dyn", sh_type=SHT_REL,
                                    data=rel_blob, flags=SHF_ALLOC, addr=0x480,
                                    link=".dynsym", addralign=4, entsize=8))

    builder.add_program_header(ProgramHeaderSpec(
        p_type=PT_LOAD, flags=PF_R | PF_X, offset=0, vaddr=0, paddr=0,
        filesz=0x1000, memsz=0x1000, align=0x1000))
    builder.add_program_header(ProgramHeaderSpec(
        p_type=PT_DYNAMIC, flags=PF_R | PF_W, vaddr=0x400,
        paddr=0x400, align=4, offset_from_section=".dynamic"))
    builder.add_program_header(ProgramHeaderSpec(
        p_type=PT_GNU_STACK, flags=PF_R | PF_W, offset=0, vaddr=0, paddr=0,
        filesz=0, memsz=0, align=0x10))
    return builder.build()


def build_exec_32_big():
    """ELF32 MSB ET_EXEC minimal file used to prove big-endian parsing."""
    builder = ELFBuilder(ELFCLASS32, ">", ET_EXEC, e_machine=20,  # EM_PPC
                         entry=0x10000)
    builder.add_section(SectionSpec(
        name=".text", sh_type=SHT_PROGBITS, data=b"\x90\xc3",
        flags=SHF_ALLOC | SHF_EXECINSTR, addr=0x10000, addralign=4))
    return builder.build()


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    fixtures_dir = os.path.join(root, "fixtures")
    demo_dir = os.path.join(root, "demo")
    os.makedirs(fixtures_dir, exist_ok=True)
    os.makedirs(demo_dir, exist_ok=True)

    targets = [
        (os.path.join(fixtures_dir, "exec64_little.elf"),
         build_exec_64_little()),
        (os.path.join(fixtures_dir, "dyn32_little.elf"),
         build_dyn_32_little()),
        (os.path.join(fixtures_dir, "exec32_big.elf"), build_exec_32_big()),
        (os.path.join(demo_dir, "sample.elf"), build_exec_64_little()),
    ]
    for path, blob in targets:
        with open(path, "wb") as handle:
            handle.write(blob)
        print("wrote %s (%d bytes)" % (path, len(blob)))


if __name__ == "__main__":
    main()
