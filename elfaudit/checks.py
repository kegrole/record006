"""Security checks. Every check returns a uniform result mapping with the
keys ``name``, ``passed`` and ``detail``; ``detail`` always carries
verifiable evidence (flag values, symbol names, missing dynamic tags)."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .elf_header import ELFHeader, ET_DYN
from .sections import Section, find_section
from .segments import (
    DynamicInfo, Segment, PT_GNU_RELRO, PT_GNU_STACK, PF_X,
    DT_BIND_NOW, DT_FLAGS_1, DF_1_NOW, find_segment,
)
from .symbols import Symbol, imported_symbols

DANGEROUS_IMPORTS = ("strcpy", "system", "execve", "gets")

CHECK_NX = "nx"
CHECK_PIE = "pie"
CHECK_RELRO = "relro"
CHECK_DANGEROUS_SYMBOLS = "dangerous_symbols"
CHECK_NOT_STRIPPED = "not_stripped"


@dataclass
class AuditContext:
    header: ELFHeader
    sections: List[Section]
    segments: List[Segment]
    dynamic: Optional[DynamicInfo]
    symbols: Dict[str, List[Symbol]]


def _result(name: str, passed: bool, detail: str) -> Dict[str, Any]:
    return {
        "name": name,
        "passed": passed,
        "detail": detail,
    }


def check_nx(context: AuditContext) -> Dict[str, Any]:
    gnu_stack = find_segment(context.segments, PT_GNU_STACK)
    if gnu_stack is None:
        return _result(
            CHECK_NX, True,
            "No PT_GNU_STACK segment present; the loader defaults to a "
            "non-executable stack.")
    if gnu_stack.flags & PF_X:
        return _result(
            CHECK_NX, False,
            "PT_GNU_STACK is executable: flags=%d (0x%x, %s); PF_X=0x1 "
            "is set." % (gnu_stack.flags, gnu_stack.flags,
                         gnu_stack.flags_string()))
    return _result(
        CHECK_NX, True,
        "PT_GNU_STACK present without PF_X: flags=%d (0x%x, %s)."
        % (gnu_stack.flags, gnu_stack.flags, gnu_stack.flags_string()))


def check_pie(context: AuditContext) -> Dict[str, Any]:
    if context.header.e_type == ET_DYN:
        return _result(
            CHECK_PIE, True,
            "e_type=%d (%s): ET_DYN objects are position independent and "
            "can be mapped as PIE."
            % (context.header.e_type, context.header.type_name))
    return _result(
        CHECK_PIE, False,
        "PIE not enabled: e_type=%d (%s) is not ET_DYN."
        % (context.header.e_type, context.header.type_name))


def check_relro(context: AuditContext) -> Dict[str, Any]:
    gnu_relro = find_segment(context.segments, PT_GNU_RELRO)
    if gnu_relro is None:
        return _result(
            CHECK_RELRO, False,
            "RELRO incomplete: PT_GNU_RELRO segment is absent, so no "
            "relocation region is mapped read-only after relocation.")

    dynamic = context.dynamic
    has_bind_now = bool(dynamic and dynamic.has_tag(DT_BIND_NOW))
    flags_1_value = dynamic.value_of(DT_FLAGS_1) if dynamic else None
    has_now_flag = bool(flags_1_value is not None
                        and flags_1_value & DF_1_NOW)

    if has_bind_now or has_now_flag:
        evidence = []
        if has_bind_now:
            evidence.append("DT_BIND_NOW present")
        if has_now_flag:
            evidence.append(
                "DT_FLAGS_1=0x%x carries DF_1_NOW(0x%x)"
                % (flags_1_value, DF_1_NOW))
        return _result(
            CHECK_RELRO, True,
            "Full RELRO: PT_GNU_RELRO present and lazy binding disabled "
            "(%s)." % "; ".join(evidence))

    return _result(
        CHECK_RELRO, False,
        "RELRO incomplete: PT_GNU_RELRO is present but the dynamic "
        "section lacks both DT_BIND_NOW and a DT_FLAGS_1 entry carrying "
        "DF_1_NOW (missing tags: DT_BIND_NOW, DT_FLAGS_1/DF_1_NOW).")


def check_dangerous_symbols(context: AuditContext) -> Dict[str, Any]:
    dynsym = context.symbols.get("dynsym", [])
    hits = [symbol.name for symbol in imported_symbols(dynsym)
            if symbol.name in DANGEROUS_IMPORTS]
    if hits:
        return _result(
            CHECK_DANGEROUS_SYMBOLS, False,
            "Dangerous imported symbol(s) found in .dynsym: %s." % ", ".join(hits))
    return _result(
        CHECK_DANGEROUS_SYMBOLS, True,
        "No dangerous imported symbols (%s) found in .dynsym."
        % ", ".join(DANGEROUS_IMPORTS))


def check_not_stripped(context: AuditContext) -> Dict[str, Any]:
    symtab = find_section(context.sections, ".symtab")
    if symtab is None:
        return _result(
            CHECK_NOT_STRIPPED, True,
            "No .symtab section present: the binary appears stripped.")
    entry_count = 0
    entsize = symtab.entsize or (24 if context.header.is_64bit else 16)
    if entsize:
        entry_count = symtab.size // entsize
    if entry_count == 0:
        return _result(
            CHECK_NOT_STRIPPED, True,
            ".symtab section exists but contains 0 entries.")
    return _result(
        CHECK_NOT_STRIPPED, False,
        "Symbol table not stripped: .symtab (sh_type=%s) contains %d "
        "entries (offset=%d, size=%d)."
        % (symtab.type_name, entry_count, symtab.offset, symtab.size))

CHECK_FUNCTIONS = (
    check_nx,
    check_pie,
    check_relro,
    check_dangerous_symbols,
    check_not_stripped,
)


def run_checks(context: AuditContext) -> List[Dict[str, Any]]:
    return [check(context) for check in CHECK_FUNCTIONS]
