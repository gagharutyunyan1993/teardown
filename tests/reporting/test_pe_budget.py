import json
import struct
from dataclasses import replace

from retool.formats.domain.pe import (
    MAX_CERTS,
    MAX_IMPORT_DLLS,
    MAX_SECTIONS,
    MAX_SIGNATURE_MATCHES,
    ImportedDll,
    ImportedFunction,
    ThunkEnd,
    parse_pe,
)
from retool.formats.domain.pe_facts import pe_facts
from retool.reporting import render_json
from retool.reporting.domain.model import MAX_FINDINGS
from retool.reporting.infrastructure.formats_facts import FormatsFactSource
from retool.shared import Address, check_json_value
from tests.formats.fakes import MemorySource
from tests.formats.pe_build import P64, big_data, build_pe, dir_at, name, rva


def test_pe_caps_fit_finding_budget() -> None:
    assert MAX_SECTIONS + 3 <= MAX_FINDINGS


def test_worst_case_pe_report_renders() -> None:
    data = build_pe(extra_sections=94)
    for index in range(MAX_SECTIONS):
        data = name(data, 0x148 + 40 * index, b"\xff" * 8)
    text = render_json(FormatsFactSource(MemorySource(data)).collect())
    assert len(json.loads(text)["findings"]) == 100


# slice 5, 36-39


def test_pe_table_caps_fit_finding_budget() -> None:
    caps = 3 + MAX_SECTIONS + MAX_IMPORT_DLLS + MAX_CERTS + 1 + MAX_SIGNATURE_MATCHES
    assert caps <= MAX_FINDINGS


def _l39(*, ordinals: bool = False) -> bytes:
    """L39: 256 DLLs sharing a 512-thunk ILT; 24-byte b"\\xff" names; 300-byte DLL name."""
    buf = bytearray(big_data(0x6C00))
    for i in range(256):
        struct.pack_into("<5I", buf, 0x400 + 20 * i, rva(0x1900), 0, 0, rva(0x6A00), 0)
    for k in range(512):
        thunk = (1 << 63) | k if ordinals else rva(0x2A00 + 0x20 * k)
        struct.pack_into("<Q", buf, 0x1900 + 8 * k, thunk)
        buf[0x2A00 + 0x20 * k : 0x2A00 + 0x20 * k + 27] = bytes(2) + b"\xff" * 24 + b"\0"
    buf[0x6A00:0x6B2D] = b"\xff" * 300 + b"\0"
    struct.pack_into("<II", buf, dir_at(1), 0x2000, 5140)
    return bytes(buf)


def _import_counts(text: str) -> list[tuple[int, str]]:
    findings = json.loads(text)["findings"]
    return [
        (len(f["value"]["functions"]), f["value"]["end"])
        for f in findings
        if f["subject"] == "pe.import"
    ]


def test_worst_case_import_names_render() -> None:
    text = render_json(FormatsFactSource(MemorySource(_l39())).collect())
    assert _import_counts(text) == [(512, "null")] * 21 + [(170, "cap")] + [(0, "cap")] * 234
    assert len(json.loads(text)["findings"]) == 261


def test_worst_case_import_ordinals_render() -> None:
    text = render_json(FormatsFactSource(MemorySource(_l39(ordinals=True))).collect())
    assert _import_counts(text) == [(512, "null")] * 32 + [(0, "cap")] * 224


def test_worst_case_import_value_fits_json_limits() -> None:
    long = ImportedFunction(None, 0xFFFF, b"\xff" * 256, name_truncated=True)
    empty = ImportedFunction(None, 0xFFFF, b"")
    functions = (long,) * 48 + (empty,) * 464
    dll = ImportedDll(Address(0x400), 0, 0, 0, 0, 0, b"\xff" * 256, True, functions, ThunkEnd.CAP)
    pe = replace(parse_pe(MemorySource(P64)), imports=(dll,))
    (finding,) = [f for f in pe_facts(pe, None, "formats.inspect")[0] if f.subject == "pe.import"]
    check_json_value(finding.value)
