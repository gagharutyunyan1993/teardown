import json

from retool.formats.domain.elf import MAX_PHNUM, MAX_SHNUM
from retool.reporting import render_json
from retool.reporting.domain.model import MAX_FINDINGS
from retool.reporting.domain.services import MAX_REPORT_CHARS
from retool.reporting.infrastructure.formats_facts import FormatsFactSource
from tests.formats.elf_build import build_worst_elf
from tests.formats.fakes import MemorySource


def test_elf_caps_fit_finding_budget() -> None:
    assert MAX_PHNUM + MAX_SHNUM + 2 <= MAX_FINDINGS


def test_worst_case_elf_report_fits() -> None:
    report = FormatsFactSource(MemorySource(build_worst_elf())).collect()
    text = render_json(report)
    assert len(text) <= MAX_REPORT_CHARS
    assert len(report.stages[0].findings) == 3586
    assert len(json.loads(text)["findings"]) == 3586
