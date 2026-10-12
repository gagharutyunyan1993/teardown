from __future__ import annotations

import json
from pathlib import Path

import pytest

from retool.formats import Format, InspectFile, SectionSummary, SegmentInfo
from retool.formats.application.registry import parser_for
from retool.formats.domain.facts import magic_finding
from retool.formats.domain.parsing import ParsedContainer
from retool.formats.domain.pe import parse_pe
from retool.formats.domain.pe_facts import (
    ENTRY_OUTSIDE_NOTE,
    NOT_PARSED_NOTE,
    STRING_TABLE_NOTE,
    pe_facts,
)
from retool.formats.domain.pe_image import pe_image
from retool.formats.domain.pe_parser import PeParser
from retool.shared import (
    ArchitectureId,
    Finding,
    JsonValue,
    NotAnalysed,
    Provenance,
    Verification,
)
from tests.formats.fakes import MemorySource, ram, sa
from tests.formats.pe_build import P32, P64, build_pe, name, p, p32, patch

FIXTURES = Path(__file__).parent.parent / "fixtures" / "reporting"
PRODUCER = "formats.inspect"
NOT_BUILT = "pe memory image not built: "


def _golden(name: str) -> tuple[tuple[Finding, ...], tuple[NotAnalysed, ...]]:
    doc = json.loads((FIXTURES / name).read_text())
    findings = tuple(
        Finding(
            f["subject"],
            f["value"],
            Provenance(f["provenance"]),
            Verification.unverified(),
            f["producer"],
        )
        for f in doc["findings"]
    )
    return findings, tuple(NotAnalysed(n["reason"]) for n in doc["not_analysed"])


def _parse(data: bytes) -> ParsedContainer:
    return PeParser().parse(MemorySource(data), PRODUCER)


def _optional_value(data: bytes) -> dict[str, JsonValue]:
    pe = parse_pe(MemorySource(data))
    findings, _ = pe_facts(pe, pe_image(pe), PRODUCER)
    value = findings[2].value
    assert findings[2].subject == "pe.optional"
    assert isinstance(value, dict)
    return value


def _section_value(parsed: ParsedContainer, index: int) -> dict[str, JsonValue]:
    finding = parsed.findings[3 + index]
    assert finding.subject == "pe.section"
    assert isinstance(finding.value, dict)
    return finding.value


def _sixty_four_sections() -> bytes:
    """64 mapped sections + headers = 65 segments (test 29's n = 64, as file bytes)."""
    data = build_pe(extra_sections=62)
    for k in range(2, 64):
        data = patch(data, 0x148 + 40 * k + 8, "<I", 0x10)
        data = patch(data, 0x148 + 40 * k + 12, "<I", 0x1000 * (k + 1))
    return data


# 31-32: facts


def test_pe_facts_match_golden() -> None:
    pe = parse_pe(MemorySource(P64))
    assert pe_facts(pe, pe_image(pe), PRODUCER) == _golden("pe64_min.json")


def test_optional_format_and_base_of_data() -> None:
    pe32 = _optional_value(P32)
    assert pe32["format"] == "pe32"
    assert pe32["base_of_data"] == 0x2000
    pe64 = _optional_value(P64)
    assert pe64["format"] == "pe32+"
    assert "base_of_data" not in pe64


# 33-35: image notes


@pytest.mark.parametrize(
    "data",
    [
        p((0x17C, 0x1008)),
        p((0x154, 0x100)),
        p((0x70, 2**64 - 0x1000)),
        p32((0x74, 0xFFFFF000)),
        p32((0x168, 0xFFFFFFFF)),
        p((0x150, 0x80000000), (0x17C, 0x80001000), (0x178, 0x80000000)),
        _sixty_four_sections(),
    ],
    ids=["overlap", "overlap-headers", "base64", "base32", "vs32", "mapped-size", "count"],
)
def test_image_not_built_note(data: bytes) -> None:
    parsed = _parse(data)
    assert parsed.image is None
    assert parsed.not_analysed[0].reason.startswith(NOT_BUILT)
    assert parsed.not_analysed[-1] == NotAnalysed(NOT_PARSED_NOTE)
    assert parsed.findings == pe_facts(parse_pe(MemorySource(data)), None, PRODUCER)[0]


def test_segment_count_note() -> None:
    parsed = _parse(_sixty_four_sections())
    assert parsed.not_analysed[0] == NotAnalysed(NOT_BUILT + "segment count must be 1..64")
    assert len(parsed.findings) == 3 + 64


def test_nothing_to_map_note() -> None:
    parsed = _parse(p((0x94, 0), (0x150, 0), (0x158, 0), (0x178, 0), (0x180, 0)))
    assert parsed.image is None
    assert parsed.not_analysed == (
        NotAnalysed(NOT_BUILT + "no headers or sections to map"),
        NotAnalysed(NOT_PARSED_NOTE),
    )
    assert len(parsed.findings) == 5


def test_entry_outside_note() -> None:
    parsed = _parse(p((0x68, 0x5000)))
    assert parsed.image is not None
    assert parsed.not_analysed == (NotAnalysed(ENTRY_OUTSIDE_NOTE), NotAnalysed(NOT_PARSED_NOTE))


def test_section_address_unclamped() -> None:
    parsed = _parse(p((0x70, 2**64 - 0x1000)))
    assert parsed.image is None
    assert parsed.sections[0].addr == 2**64


# 36-37: names


def test_string_table_name() -> None:
    parsed = _parse(name(P64, 0x170, b"/4"))
    assert _section_value(parsed, 1)["name"] == "/4"
    assert parsed.sections[1].name == "/4"
    assert parsed.not_analysed == (NotAnalysed(STRING_TABLE_NOTE), NotAnalysed(NOT_PARSED_NOTE))


@pytest.mark.parametrize("raw", [b"/4a", b"/"])
def test_string_table_name_fullmatch(raw: bytes) -> None:
    parsed = _parse(name(P64, 0x170, raw))
    assert NotAnalysed(STRING_TABLE_NOTE) not in parsed.not_analysed


def test_hostile_name_escaped() -> None:
    parsed = _parse(name(P64, 0x148, b'\xff\x01"\\abcd'))
    expected = "\\xff\\x01\\x22\\x5cabcd"
    assert _section_value(parsed, 0)["name"] == expected
    assert parsed.sections[0].name == expected


# 38-40: rejection, registry, use case


def test_rejected_structure() -> None:
    parsed = _parse(p((0x58, 0x107)))
    assert parsed.findings == (magic_finding(Format.PE, PRODUCER),)
    assert parsed.not_analysed == (
        NotAnalysed("pe structure rejected: ROM optional header not supported at offset 0x58"),
    )
    assert parsed.arch is None
    assert parsed.image is None
    assert parsed.sections == ()


def test_parser_registry_pe() -> None:
    assert isinstance(parser_for(Format.PE), PeParser)


def test_inspect_file_pe_fields() -> None:
    info = InspectFile(MemorySource(P64)).execute()
    assert info.stage_version == "3"
    assert info.arch == ArchitectureId("x86_64")
    assert info.entry == sa(ram, 0x140001000)
    assert info.segments == (
        SegmentInfo("headers", sa(ram, 0x140000000), 0x200, 0, 0x200),
        SegmentInfo("sec0", sa(ram, 0x140001000), 0x10, 0x200, 0x10),
        SegmentInfo("sec1", sa(ram, 0x140002000), 0x1000, 0x400, 0x200),
    )
    assert info.sections[0] == SectionSummary(0, ".text", "code", 0x140001000, 0x200, 0x10)


def test_image_at_top_of_space_without_entry() -> None:
    parsed = _parse(p((0x70, 2**64 - 0x3000), (0x68, 0xFFFFFFFF)))
    assert parsed.image is not None
    assert parsed.not_analysed == (NotAnalysed(ENTRY_OUTSIDE_NOTE), NotAnalysed(NOT_PARSED_NOTE))
    assert parsed.sections[1].addr == 2**64 - 0x1000
