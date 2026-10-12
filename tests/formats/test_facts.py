import pytest

from retool.formats import Format, InspectFile, LoadRawImage, RawLoadSpec
from retool.formats.domain.facts import format_facts
from retool.shared import Finding, NotAnalysed, ParseError, Provenance, Verification
from tests.formats.fakes import MemorySource, arm, ram, sa, seg


@pytest.mark.parametrize("fmt", [Format.ELF, Format.PE, Format.MACHO])
def test_format_facts_structured(fmt: Format) -> None:
    assert format_facts(fmt, "p") == (
        (
            Finding(
                "input", {"magic": fmt.value}, Provenance.PARSED, Verification.unverified(), "p"
            ),
        ),
        (NotAnalysed(f"container structure not parsed: no {fmt.value} parser in this version"),),
    )


def test_format_facts_unknown() -> None:
    assert format_facts(Format.UNKNOWN, "p") == (
        (),
        (NotAnalysed("container structure not parsed: unknown format"),),
    )


def test_format_facts_raw() -> None:
    assert format_facts(Format.RAW, "p") == ((), (NotAnalysed("raw image content not analysed"),))
    for fmt in Format:
        _, not_analysed = format_facts(fmt, "p")
        assert all("disassembl" not in n.reason for n in not_analysed)


def test_inspect_file_stage_fields() -> None:
    info = InspectFile(MemorySource(b"\x7fELF" + b"\0" * 60)).execute()
    assert info.stage == InspectFile.STAGE == "formats.inspect"
    assert info.stage_version == "2"
    assert info.findings == (
        Finding(
            "input",
            {"magic": "elf"},
            Provenance.PARSED,
            Verification.unverified(),
            "formats.inspect",
        ),
    )
    assert info.not_analysed == (
        NotAnalysed("elf structure rejected: invalid EI_CLASS at offset 0x4"),
    )


def test_load_raw_stage_fields() -> None:
    source = MemorySource(b"\x7fELF" + b"\0" * 60)
    info = LoadRawImage(source).execute(RawLoadSpec(arm, (seg(0, None, sa(ram, 0)),)))
    assert info.stage == LoadRawImage.STAGE == "formats.raw"
    assert info.stage_version == "1"
    assert info.findings == ()
    assert info.not_analysed == (NotAnalysed("raw image content not analysed"),)


class _ShortReadSource:
    """ByteSource whose size says 32 but whose reads stop at 16 bytes (file shrank)."""

    @property
    def size(self) -> int:
        return 32

    def read(self, offset: int, size: int) -> bytes:
        return bytes(max(0, min(offset + size, 16) - offset))


def test_inspect_file_short_read() -> None:
    with pytest.raises(ParseError, match="input changed during read"):
        InspectFile(_ShortReadSource()).execute()
