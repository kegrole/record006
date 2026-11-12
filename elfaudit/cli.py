"""Command line entry point.

Usage::

    python -m elfaudit.cli --target <elf file> --out <report path>
"""

import argparse
import os
import sys
from typing import List, Optional

from .elf_header import ELFParseError
from .report import audit_file, build_report, summary_line, write_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m elfaudit.cli",
        description="Audit an ELF binary and emit a JSON security report.")
    parser.add_argument("--target", required=True,
                        help="path to the ELF file to audit")
    parser.add_argument("--out", required=True,
                        help="path of the JSON report to write")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if not os.path.isfile(args.target):
        print("elfaudit: target not found: %s" % args.target,
              file=sys.stderr)
        return 1

    try:
        result = audit_file(args.target)
    except ELFParseError as exc:
        print("elfaudit: failed to parse ELF file %s: %s"
              % (args.target, exc), file=sys.stderr)
        return 1

    report = build_report(result, target_path=args.target)
    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    write_report(report, args.out)
    print(summary_line(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
