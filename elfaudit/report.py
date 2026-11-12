"""High level audit orchestration and JSON report rendering."""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .checks import AuditContext, run_checks
from .elf_header import ELFHeader, parse_elf_header
from .relocs import Relocation, parse_relocations
from .sections import Section, parse_sections
from .segments import (
    DynamicInfo, Segment, parse_dynamic, parse_segments,
)
from .symbols import parse_all_symbols


@dataclass
class AuditResult:
    header: ELFHeader
    sections: List[Section]
    segments: List[Segment]
    dynamic: Optional[DynamicInfo]
    relocations: List[Relocation]
    checks: List[Dict[str, Any]] = field(default_factory=list)
    data: bytes = b""


def audit_blob(data: bytes) -> AuditResult:
    header = parse_elf_header(data)
    sections = parse_sections(data, header)
    segments = parse_segments(data, header)
    dynamic = parse_dynamic(data, header, segments, sections)
    symbols = parse_all_symbols(data, header, sections)
    relocations = parse_relocations(data, header, sections)
    context = AuditContext(
        header=header,
        sections=sections,
        segments=segments,
        dynamic=dynamic,
        symbols=symbols,
    )
    checks = run_checks(context)
    return AuditResult(
        header=header,
        sections=sections,
        segments=segments,
        dynamic=dynamic,
        relocations=relocations,
        checks=checks,
        data=data,
    )


def audit_file(path: str) -> AuditResult:
    with open(path, "rb") as handle:
        data = handle.read()
    return audit_blob(data)


def _header_summary(header: ELFHeader) -> Dict[str, Any]:
    return {
        "magic": "7f 45 4c 46",
        "class": header.class_name,
        "data": header.endian_name,
        "e_type": header.type_name,
        "e_machine": header.machine_name,
        "e_entry": header.e_entry,
        "e_phoff": header.e_phoff,
        "e_phnum": header.e_phnum,
        "e_shoff": header.e_shoff,
        "e_shnum": header.e_shnum,
        "e_shstrndx": header.e_shstrndx,
    }


def build_report(result: AuditResult, target_path: Optional[str] = None
                 ) -> Dict[str, Any]:
    checks = result.checks
    failed = [check for check in checks if not check["passed"]]
    report: Dict[str, Any] = {
        "target": target_path,
        "elf": _header_summary(result.header),
        "summary": {
            "total_checks": len(checks),
            "passed": len(checks) - len(failed),
            "failed": len(failed),
        },
        "checks": checks,
    }
    return report


def write_report(report: Dict[str, Any], out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=False)
        handle.write("\n")


def summary_line(report: Dict[str, Any]) -> str:
    summary = report["summary"]
    return (
        "elfaudit: %d check(s), %d passed, %d issue(s) reported"
        % (summary["total_checks"], summary["passed"], summary["failed"]))
