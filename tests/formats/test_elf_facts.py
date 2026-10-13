from __future__ import annotations

import json
from pathlib import Path

import pytest

from retool.formats import Format, InspectFile, SectionSummary, SegmentInfo
from retool.formats.application.registry import parser_for
from retool.formats.domain.elf import parse_elf
from retool.formats.domain.elf_facts import elf_facts
from retool.formats.domain.elf_image import elf_image
from retool.formats.domain.elf_parser import ElfParser
from retool.formats.domain.model import InputChanged
from retool.formats.domain.parsing import ParsedContainer, guarded_parse
from retool.formats.domain.ports import ByteSource
from retool.shared import (
    ArchitectureId,
    Finding,
    NotAnalysed,
    ParseError,
    Provenance,
    Verification,
)
from tests.formats.elf_build import F64, p
from tests.formats.fakes import MemorySource, ram, sa

FIXTURES = Path(__file__).parent.parent / "fixtures" / "reporting"
PRODUCER = "formats.inspect"
SYMBOLS_NOTE = "elf symbols, dynamic section, relocations and notes not parsed in this version"
G1_BYTES = b"\x7fELF" + b"\0" * 60


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
    return ElfParser().parse(MemorySource(data), PRODUCER)


def test_elf_facts_match_golden() -> None:
    elf = parse_elf(MemorySource(F64))
    assert elf_facts(elf, elf_image(elf), PRODUCER) == _golden("elf64_min.json")


@pytest.mark.parametrize(
    ("data", "note"),
    [
        (p((0x40, 4), (0x78, 4)), "no PT_LOAD segment with p_memsz > 0"),
        (p((0x88, 0x400010)), "segments overlap in space"),
        (p((0xA0, 2**33)), "mapped size exceeds 4294967296 bytes"),
    ],
)
def test_image_not_built_note(data: bytes, note: str) -> None:
    parsed = _parse(data)
    assert parsed.image is None
    assert parsed.arch == ArchitectureId("x86_64")
    assert parsed.not_analysed == (
        NotAnalysed(f"elf memory image not built: {note}"),
        NotAnalysed(SYMBOLS_NOTE),
    )
    assert parsed.findings == elf_facts(parse_elf(MemorySource(data)), None, PRODUCER)[0]
    assert len(parsed.findings) == 8
    assert len(parsed.sections) == 4


def test_entry_outside_note() -> None:
    parsed = _parse(p((24, 0x500000)))
    assert parsed.image is not None
    assert parsed.not_analysed == (
        NotAnalysed("elf entry point outside every PT_LOAD segment"),
        NotAnalysed(SYMBOLS_NOTE),
    )


def test_rejected_structure_matches_g1() -> None:
    parsed = _parse(G1_BYTES)
    assert (parsed.findings, parsed.not_analysed) == _golden("elf_magic.json")
    assert (parsed.arch, parsed.image, parsed.sections) == (None, None, ())


def _raising_build(source: ByteSource, producer: str) -> ParsedContainer:
    raise ParseError("broken", offset=0x10)


def _changing_build(source: ByteSource, producer: str) -> ParsedContainer:
    raise InputChanged(offset=0x20)


def test_guarded_parse_converts_parse_error() -> None:
    parsed = guarded_parse(Format.PE, _raising_build, MemorySource(b"MZ"), PRODUCER)
    assert parsed.not_analysed == (NotAnalysed("pe structure rejected: broken at offset 0x10"),)
    assert parsed.findings == (
        Finding("input", {"magic": "pe"}, Provenance.PARSED, Verification.unverified(), PRODUCER),
    )


def test_guarded_parse_propagates_input_changed() -> None:
    with pytest.raises(InputChanged):
        guarded_parse(Format.PE, _changing_build, MemorySource(b"MZ"), PRODUCER)


def test_parser_registry() -> None:
    assert isinstance(parser_for(Format.ELF), ElfParser)
    for fmt in (Format.MACHO, Format.UNKNOWN, Format.RAW):
        assert parser_for(fmt) is None


def test_inspect_file_elf_fields() -> None:
    info = InspectFile(MemorySource(F64)).execute()
    assert info.stage_version == "5"
    assert info.arch == ArchitectureId("x86_64")
    assert info.entry == sa(ram, 0x4000B0)
    assert info.segments == (
        SegmentInfo("phdr0", sa(ram, 0x400000), 0xC0, 0, 0xC0),
        SegmentInfo("phdr1", sa(ram, 0x4010C0), 0x100, 0xC0, 8),
    )
    assert info.sections[2] == SectionSummary(2, ".bss", "nobits", 0x4010C8, 0xC8, 0xF8)
