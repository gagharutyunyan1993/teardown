import pytest

from retool.formats import Format, Image, MappedSegment, MemoryMap, RawLoadSpec, RawSegmentSpec
from retool.formats.domain.image import MAX_IMAGE_SIZE
from retool.formats.domain.services import build_raw_image
from retool.shared import AddressSpace, ArchitectureId, ByteRange, ParseError, SpaceAddress
from tests.formats.fakes import arm, bank1, ram, rom, sa, seg


def build(segs: list[RawSegmentSpec], size: int, entry: SpaceAddress | None = None) -> Image:
    return build_raw_image(RawLoadSpec(arm, tuple(segs), entry), size)


def test_single_mapping() -> None:
    image = build([seg(0, None, sa(ram, 0x8000000))], 0x100)
    assert image.format is Format.RAW
    assert image.entry is None
    (only,) = image.memory.segments
    assert only.file == ByteRange(0, 0x100)
    assert only.mem_size == 0x100
    assert only.name == "seg0"
    assert only.start == sa(ram, 0x8000000)


def test_base_with_offset_length() -> None:
    image = build([seg(0x10, 0x20, sa(ram, 0))], 0x100)
    assert image.memory.segments[0].file == ByteRange(0x10, 0x20)


def test_multi_mapping() -> None:
    image = build(
        [
            seg(0, 0x40, sa(ram, 0)),
            seg(0x40, 0x40, sa(ram, 0x1000)),
            seg(0x80, 0x80, sa(bank1, 0x4000)),
        ],
        0x100,
    )
    memory = image.memory
    assert len(memory.segments) == 3
    hit = memory.segment_at(sa(ram, 0x1010))
    assert hit is not None and hit.name == "seg1"
    assert memory.segment_at(sa(ram, 0x800)) is None
    banked = memory.segment_at(sa(bank1, 0x4000))
    assert banked is not None and banked.name == "seg2"


def test_zero_fill_tail() -> None:
    memory = build([seg(0, 0x10, sa(ram, 0x2000), mem_size=0x100)], 0x10).memory
    assert memory.file_range_for(sa(ram, 0x2008), 0x10) == ByteRange(0x8, 0x8)
    assert memory.file_range_for(sa(ram, 0x2020), 0x10) == ByteRange(0x10, 0)
    for addr, size in ((0x20F8, 0x10), (0x3000, 1), (0x2000, 0)):
        with pytest.raises(ParseError):
            memory.file_range_for(sa(ram, addr), size)


def test_arch_without_disassembler() -> None:
    spec = RawLoadSpec(ArchitectureId("pi32v2"), (seg(0, None, sa(ram, 0)),))
    assert build_raw_image(spec, 16).arch.name == "pi32v2"


def test_check2_no_segment() -> None:
    with pytest.raises(ParseError, match="no segment declared"):
        RawLoadSpec(arm, ())
    with pytest.raises(TypeError):
        RawSegmentSpec(0, None)  # type: ignore[call-arg]  # start has no default by design


@pytest.mark.parametrize(("off", "size"), [(0, 0), (-1, 16), (16, 16), (2**64, 16)])
def test_check3_offset(off: int, size: int) -> None:
    with pytest.raises(ParseError, match="segment file offset outside source") as exc:
        build([seg(off, None, sa(ram, 0))], size)
    assert exc.value.offset == (off if off >= 0 else None)


def test_check3_last_byte_ok() -> None:
    assert build([seg(15, None, sa(ram, 0))], 16).memory.segments[0].file == ByteRange(15, 1)


@pytest.mark.parametrize(
    ("off", "length", "size", "reason"),
    [
        (0, 0, 16, "empty segment"),
        (0, -5, 16, "empty segment"),
        (8, 9, 16, "exceeds"),
        (0, 2**64, 16, "exceeds"),
    ],
)
def test_check4_length(off: int, length: int, size: int, reason: str) -> None:
    with pytest.raises(ParseError, match=reason) as exc:
        build([seg(off, length, sa(ram, 0))], size)
    assert exc.value.offset == off


def test_check4_direct_segment() -> None:
    assert build([seg(8, 8, sa(ram, 0))], 16).memory.segments[0].file == ByteRange(8, 8)
    with pytest.raises(ParseError, match="empty segment"):
        MappedSegment(ByteRange(0, 0), sa(ram, 0), 0, "s")
    bss = MappedSegment(ByteRange(0x10, 0), sa(ram, 0), 0x10, "bss")
    assert bss.file.size == 0


def test_check5_mem_size() -> None:
    with pytest.raises(ParseError, match="memory size smaller"):
        build([seg(0, 0x10, sa(ram, 0), mem_size=0x8)], 0x100)
    build([seg(0, 0x100, sa(bank1, 0xFF00))], 0x100)
    with pytest.raises(ParseError, match="segment exceeds address space"):
        build([seg(0, 0x100, sa(bank1, 0xFF00), mem_size=0x101)], 0x100)
    with pytest.raises(ParseError, match="segment exceeds address space"):
        build([seg(0, 0x20, sa(ram, 2**64 - 0x10))], 0x100)
    with pytest.raises(ParseError, match="invalid segment name") as exc:
        build([seg(0, 1, sa(ram, 0), name="Bad\x1b")], 0x100)
    assert "Bad" not in str(exc.value)


def test_check6_count() -> None:
    with pytest.raises(ParseError, match="segment count"):
        RawLoadSpec(arm, tuple(seg(0, 1, sa(ram, i)) for i in range(65)))
    assert len(build([seg(i, 1, sa(ram, i)) for i in range(64)], 64).memory.segments) == 64
    with pytest.raises(ParseError, match="segment count"):
        MemoryMap(())
    with pytest.raises(ParseError, match="mapped size exceeds"):
        build([seg(0, 0x10, sa(ram, 0), mem_size=MAX_IMAGE_SIZE + 1)], 0x10)
    build([seg(0, 0x10, sa(ram, 0), mem_size=MAX_IMAGE_SIZE)], 0x10)
    half = MAX_IMAGE_SIZE // 2 + 1
    with pytest.raises(ParseError, match="mapped size exceeds"):
        build(
            [seg(0, 0x10, sa(ram, 0), mem_size=half), seg(0, 0x10, sa(rom, 0), mem_size=half)],
            0x10,
        )


def test_check7_overlap() -> None:
    first = seg(0, 0x10, sa(ram, 0))
    with pytest.raises(ParseError, match="segments overlap"):
        build([first, seg(0x10, 0x10, sa(ram, 0xF))], 0x100)
    build([first, seg(0x10, 0x10, sa(ram, 0x10))], 0x100)
    build([first, seg(0x10, 0x10, sa(bank1, 0))], 0x100)
    with pytest.raises(ParseError, match="segments overlap"):
        build([seg(0, 0x10, sa(ram, 0), mem_size=0x100), seg(0x10, 0x10, sa(ram, 0x80))], 0x100)
    with pytest.raises(ParseError, match="segments overlap"):
        build([seg(0, 0x10, sa(ram, 0x100)), seg(0x10, 0x10, sa(ram, 0x108))], 0x100)
    with pytest.raises(ParseError, match="declared with two widths"):
        build(
            [
                seg(0, 0x10, sa(AddressSpace("x", 16), 0)),
                seg(0x10, 0x10, sa(AddressSpace("x", 32), 0x1000)),
            ],
            0x100,
        )


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        (sa(ram, 0x1000), None),
        (sa(ram, 0x10FF), None),
        (sa(ram, 0x1100), "entry outside every segment"),
        (sa(bank1, 0x1000), "entry outside"),
        (sa(AddressSpace("ram", 32), 0x1000), "declared with two widths"),
        (None, None),
    ],
)
def test_check8_entry(entry: SpaceAddress | None, reason: str | None) -> None:
    segs = [seg(0, 0x10, sa(ram, 0x1000), mem_size=0x100)]
    if reason is None:
        assert build(segs, 0x10, entry).entry == entry
    else:
        with pytest.raises(ParseError, match=reason):
            build(segs, 0x10, entry)
