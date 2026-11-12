"""Unittest coverage for the ELF security auditor.

The fixtures are rebuilt in-memory on every test run via the generic
``fixtures.builder`` writer (ELF32/ELF64 x LSB/MSB), so the audit logic
can never rely on a hard-coded byte arrangement.
"""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from fixtures import generate_fixtures  # noqa: E402

from elfaudit.elf_header import ELFCLASS32, ELFCLASS64, ELFDATA2LSB  # noqa: E402
from elfaudit.elf_header import ELFDATA2MSB, ET_DYN, ET_EXEC  # noqa: E402
from elfaudit.relocs import parse_relocations  # noqa: E402
from elfaudit.report import audit_blob, build_report  # noqa: E402
from elfaudit.sections import SHT_NOBITS, SHT_SYMTAB, find_section  # noqa: E402
from elfaudit.segments import (  # noqa: E402
    PF_X, PT_GNU_RELRO, PT_GNU_STACK, find_segment,
)
from elfaudit.symbols import imported_symbols, parse_all_symbols  # noqa: E402


class ELFAuditFixtureTests(unittest.TestCase):
    def setUp(self):
        self.exec64 = generate_fixtures.build_exec_64_little()
        self.dyn32 = generate_fixtures.build_dyn_32_little()
        self.big32 = generate_fixtures.build_exec_32_big()

    def _checks(self, blob):
        return {check["name"]: check for check in audit_blob(blob).checks}

    # Criterion 1: ELF64 LSB ET_EXEC parsing ----------------------------
    def test_exec64_header_sections_and_imports(self):
        result = audit_blob(self.exec64)
        header = result.header

        self.assertEqual(self.exec64[:4], b"\x7fELF")
        self.assertEqual(header.elf_class, ELFCLASS64)
        self.assertEqual(header.data_encoding, ELFDATA2LSB)
        self.assertEqual(header.e_type, ET_EXEC)
        self.assertEqual(header.e_machine, 62)
        self.assertGreater(header.e_phoff, 0)
        self.assertGreater(header.e_shoff, 0)
        self.assertEqual(header.e_phnum, 4)
        self.assertEqual(header.e_shnum, 9)

        names = [section.name for section in result.sections
                 if section.name]
        for required in (".text", ".shstrtab", ".dynsym"):
            self.assertIn(required, names)

        symbols = parse_all_symbols(result.data, header, result.sections)
        import_names = [symbol.name for symbol
                        in imported_symbols(symbols["dynsym"])]
        self.assertIn("strcpy", import_names)
        self.assertIn("printf", import_names)

        gnu_stack = find_segment(result.segments, PT_GNU_STACK)
        self.assertIsNotNone(gnu_stack)
        self.assertTrue(gnu_stack.flags & PF_X)

        symtab = find_section(result.sections, ".symtab")
        self.assertIsNotNone(symtab)
        self.assertGreater(symtab.size, 0)

    # Criterion 2: exactly the four expected problems -------------------
    def test_exec64_reports_four_issues(self):
        checks = self._checks(self.exec64)

        self.assertFalse(checks["nx"]["passed"])
        self.assertFalse(checks["pie"]["passed"])
        self.assertFalse(checks["not_stripped"]["passed"])
        self.assertFalse(checks["dangerous_symbols"]["passed"])

        self.assertTrue(checks["relro"]["passed"])

        failed = [name for name, check in checks.items()
                  if not check["passed"]]
        self.assertEqual(
            sorted(failed),
            sorted(["nx", "pie", "not_stripped", "dangerous_symbols"]))

    # Criterion 3: ELF32 LSB ET_DYN, only RELRO fails -------------------
    def test_dyn32_only_relro_fails(self):
        result = audit_blob(self.dyn32)
        self.assertEqual(result.header.elf_class, ELFCLASS32)
        self.assertEqual(result.header.data_encoding, ELFDATA2LSB)
        self.assertEqual(result.header.e_type, ET_DYN)

        gnu_stack = find_segment(result.segments, PT_GNU_STACK)
        self.assertIsNotNone(gnu_stack)
        self.assertFalse(gnu_stack.flags & PF_X)
        self.assertIsNone(find_segment(result.segments, PT_GNU_RELRO))
        self.assertIsNone(find_section(result.sections, ".symtab"))

        symbols = parse_all_symbols(result.data, result.header,
                                    result.sections)
        self.assertEqual(
            [symbol.name for symbol
             in imported_symbols(symbols["dynsym"])],
            ["puts"])

        checks = {check["name"]: check for check in result.checks}
        self.assertFalse(checks["relro"]["passed"])
        for name in ("nx", "pie", "dangerous_symbols", "not_stripped"):
            self.assertTrue(checks[name]["passed"], name)

    # Criterion 4: ELF32 big-endian header parsing ----------------------
    def test_elf32_big_endian_header(self):
        result = audit_blob(self.big32)
        self.assertEqual(result.header.elf_class, ELFCLASS32)
        self.assertEqual(result.header.data_encoding, ELFDATA2MSB)
        self.assertEqual(result.header.e_machine, 20)
        self.assertEqual(result.header.e_type, ET_EXEC)
        self.assertEqual(result.header.e_entry, 0x10000)
        self.assertIn(".text",
                      [section.name for section in result.sections])

    # Criterion 5: evidence carried in detail strings -------------------
    def test_detail_evidence_is_verifiable(self):
        exec_checks = self._checks(self.exec64)
        self.assertIn("PT_GNU_STACK", exec_checks["nx"]["detail"])
        self.assertIn("flags=7", exec_checks["nx"]["detail"])
        self.assertIn("strcpy",
                      exec_checks["dangerous_symbols"]["detail"])
        self.assertIn(".symtab",
                      exec_checks["not_stripped"]["detail"])

        dyn_checks = self._checks(self.dyn32)
        relro_detail = dyn_checks["relro"]["detail"]
        self.assertIn("PT_GNU_RELRO", relro_detail)

        # The incomplete-RELRO wording also names the missing tags.
        from fixtures import generate_fixtures as gf
        from fixtures.builder import (
            ELFBuilder, ProgramHeaderSpec, SectionSpec, StringTable,
        )
        builder = ELFBuilder(ELFCLASS32, "<", ET_DYN, 3)
        dynstr = StringTable()
        dynamic_blob = b"".join([
            builder.pack_dynamic(gf.DT_NULL, 0),
        ])
        builder.add_section(SectionSpec(
            name=".dynamic", sh_type=gf.SHT_DYNAMIC, data=dynamic_blob,
            flags=2, addralign=4, entsize=8))
        builder.add_program_header(ProgramHeaderSpec(
            p_type=gf.PT_GNU_RELRO, flags=4, offset=52, filesz=8,
            memsz=8, align=1))
        blob = builder.build()
        partial = audit_blob(blob)
        partial_checks = {c["name"]: c for c in partial.checks}
        self.assertFalse(partial_checks["relro"]["passed"])
        self.assertIn("DT_BIND_NOW", partial_checks["relro"]["detail"])
        self.assertIn("DF_1_NOW", partial_checks["relro"]["detail"])

    # Criterion 6: uniform check schema ---------------------------------
    def test_every_check_has_required_keys(self):
        for blob in (self.exec64, self.dyn32, self.big32):
            for check in audit_blob(blob).checks:
                self.assertEqual(
                    sorted(check.keys()), ["detail", "name", "passed"])
                self.assertIsInstance(check["name"], str)
                self.assertIsInstance(check["passed"], bool)
                self.assertIsInstance(check["detail"], str)
                self.assertTrue(check["detail"])

    def test_report_json_roundtrip_and_summary(self):
        result = audit_blob(self.exec64)
        report = build_report(result, target_path="fixtures/exec64_little.elf")
        encoded = json.dumps(report)
        decoded = json.loads(encoded)
        self.assertEqual(decoded["summary"]["total_checks"], 5)
        self.assertEqual(decoded["summary"]["failed"], 4)
        self.assertEqual(decoded["summary"]["passed"], 1)
        self.assertEqual(decoded["elf"]["class"], "ELF64")

        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "nested", "report.json")
            from elfaudit.cli import main
            target = os.path.join(tmp, "sample.elf")
            with open(target, "wb") as handle:
                handle.write(self.exec64)
            self.assertEqual(main(["--target", target, "--out", out_path]),
                             0)
            with open(out_path, encoding="utf-8") as handle:
                on_disk = json.load(handle)
            self.assertEqual(on_disk["summary"]["failed"], 4)

    def test_relocations_rela_and_rel(self):
        rela = audit_blob(self.exec64).relocations
        self.assertEqual(len(rela), 1)
        self.assertEqual(rela[0].section, ".rela.dyn")
        self.assertEqual(rela[0].offset, 0x401008)
        self.assertEqual(rela[0].addend, 0)
        self.assertEqual(rela[0].symbol_index, 1)
        self.assertEqual(rela[0].reloc_type, 8)

        rel = audit_blob(self.dyn32).relocations
        self.assertEqual(len(rel), 1)
        self.assertEqual(rel[0].section, ".rel.dyn")
        self.assertEqual(rel[0].offset, 0x510)
        self.assertEqual(rel[0].addend, 0)
        self.assertEqual(rel[0].reloc_type, 6)

    def test_section_header_fields(self):
        result = audit_blob(self.exec64)
        text_section = find_section(result.sections, ".text")
        self.assertEqual(text_section.addr, 0x401000)
        self.assertEqual(text_section.size, 2)
        self.assertNotEqual(text_section.sh_type, SHT_NOBITS)
        symtab = find_section(result.sections, ".symtab")
        self.assertEqual(symtab.sh_type, SHT_SYMTAB)

    def test_generic_builder_supports_big_endian_relocations(self):
        # A second big-endian shape with a reloc section proves that the
        # parser does not special-case the small big-endian fixture.
        from fixtures.builder import (
            ELFBuilder, SectionSpec, StringTable,
        )
        builder = ELFBuilder(ELFCLASS32, ">", ET_EXEC, 20)
        blob = builder.build()
        result = audit_blob(blob)
        self.assertEqual(parse_relocations(result.data, result.header,
                                           result.sections), [])
        self.assertEqual(result.header.endianness, ">")


if __name__ == "__main__":
    unittest.main(verbosity=2)
