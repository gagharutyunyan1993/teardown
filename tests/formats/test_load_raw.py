import pytest

from retool.formats import Format, LoadRawImage, RawLoadSpec, SegmentInfo
from retool.shared import ParseError
from tests.formats.fakes import MemorySource, SparseSource, arm, ram, sa, seg


def test_load_raw_happy() -> None:
    source = MemorySource(bytes(range(256)))
    info = LoadRawImage(source).execute(RawLoadSpec(arm, (seg(0, None, sa(ram, 0x8000000)),)))
    assert info.source_size == 256
    assert info.format is Format.RAW
    assert info.segments == (SegmentInfo("seg0", sa(ram, 0x8000000), 0x100, 0, 0x100),)
    assert info.entry is None
    assert info.shadowed_format is None


def test_check9_bounded_reads() -> None:
    big = SparseSource(1 << 31)
    LoadRawImage(big).execute(RawLoadSpec(arm, (seg(0, None, sa(ram, 0)),)))
    assert big.calls == [(0, 4)]

    past = SparseSource(1 << 31)
    with pytest.raises(ParseError, match="segment file offset outside source") as exc:
        LoadRawImage(past).execute(RawLoadSpec(arm, (seg(1 << 31, None, sa(ram, 0)),)))
    assert exc.value.offset == 1 << 31
    assert past.calls == []

    for data in (b"\0", b"\x7fEL"):
        small = MemorySource(data)
        info = LoadRawImage(small).execute(RawLoadSpec(arm, (seg(0, None, sa(ram, 0)),)))
        assert info.shadowed_format is None
        assert small.calls == [(0, len(data))]


@pytest.mark.parametrize(
    ("data", "shadowed"),
    [
        (b"\x7fELF" + b"\0" * 60, Format.ELF),
        (b"MZ", Format.PE),
        (b"\xcf\xfa\xed\xfe" + b"\0" * 60, Format.MACHO),
        (b"\0" * 64, None),
    ],
)
def test_check10_magic_under_raw(data: bytes, shadowed: Format | None) -> None:
    info = LoadRawImage(MemorySource(data)).execute(RawLoadSpec(arm, (seg(0, None, sa(ram, 0)),)))
    assert info.format is Format.RAW
    assert info.shadowed_format is shadowed
