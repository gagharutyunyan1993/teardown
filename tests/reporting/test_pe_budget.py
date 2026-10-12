import json

from retool.formats.domain.pe import MAX_SECTIONS
from retool.reporting import render_json
from retool.reporting.domain.model import MAX_FINDINGS
from retool.reporting.infrastructure.formats_facts import FormatsFactSource
from tests.formats.fakes import MemorySource
from tests.formats.pe_build import build_pe, name


def test_pe_caps_fit_finding_budget() -> None:
    assert MAX_SECTIONS + 3 <= MAX_FINDINGS


def test_worst_case_pe_report_renders() -> None:
    data = build_pe(extra_sections=94)
    for index in range(MAX_SECTIONS):
        data = name(data, 0x148 + 40 * index, b"\xff" * 8)
    text = render_json(FormatsFactSource(MemorySource(data)).collect())
    assert len(json.loads(text)["findings"]) == 99
