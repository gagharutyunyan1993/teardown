from __future__ import annotations

from dataclasses import replace

import pytest

from retool.formats import Format, Image, MappedSegment, MemoryMap
from retool.formats.domain.pe import CoffHeader, PeFile, PeSection, parse_pe
from retool.formats.domain.pe_image import pe_arch, pe_image
from retool.shared import (
    Address,
    AddressSpace,
    ArchitectureId,
    ByteRange,
    ParseError,
    SpaceAddress,
)
from tests.formats.fakes import MemorySource, ram, sa
from tests.formats.pe_build import P32, P64, p, p32

ram32 = AddressSpace("ram", 32)


def _image(data: bytes) -> Image | None:
    return pe_image(parse_pe(MemorySource(data)))


def _not_built(data: bytes, reason: str) -> None:
    with pytest.raises(ParseError) as exc:
        _image(data)
    assert exc.value.reason == reason


# 19-21: well-formed fixtures and arch


def test_p64_image() -> None:
    assert _image(P64) == Image(
        ArchitectureId("x86_64"),
        MemoryMap(
            (
                MappedSegment(ByteRange(0, 0x200), sa(ram, 0x140000000), 0x200, "headers"),
                MappedSegment(ByteRange(0x200, 0x10), sa(ram, 0x140001000), 0x10, "sec0"),
                MappedSegment(ByteRange(0x400, 0x200), sa(ram, 0x140002000), 0x1000, "sec1"),
            )
        ),
        sa(ram, 0x140001000),
        Format.PE,
    )


def test_p32_image() -> None:
    assert _image(P32) == Image(
        ArchitectureId("x86"),
        MemoryMap(
            (
                MappedSegment(ByteRange(0, 0x200), sa(ram32, 0x400000), 0x200, "headers"),
                MappedSegment(ByteRange(0x200, 0x10), sa(ram32, 0x401000), 0x10, "sec0"),
                MappedSegment(ByteRange(0x400, 0x200), sa(ram32, 0x402000), 0x1000, "sec1"),
            )
        ),
        sa(ram32, 0x401000),
        Format.PE,
    )


def _coff(machine: int) -> CoffHeader:
    return CoffHeader(machine, 0, 0, Address(0), 0, 0, 0)


@pytest.mark.parametrize(
    ("machine", "arch"),
    [
        (0x14C, "x86"),
        (0x8664, "x86_64"),
        (0x1C0, "arm"),
        (0x1C4, "arm"),
        (0xAA64, "aarch64"),
        (0x200, "ia64"),
        (0x6232, "loongarch32"),
        (0x6264, "loongarch64"),
        (0xA641, "pe-machine-42561"),
        (0, "pe-machine-0"),
    ],
)
def test_pe_arch(machine: int, arch: str) -> None:
    assert pe_arch(_coff(machine)) == ArchitectureId(arch)


# 22-25: mapping rules


def _segments(data: bytes) -> tuple[MappedSegment, ...]:
    image = _image(data)
    assert image is not None
    return image.memory.segments


def test_virtual_size_zero_falls_back_to_raw_size() -> None:
    assert _segments(p((0x150, 0)))[1] == MappedSegment(
        ByteRange(0x200, 0x200), sa(ram, 0x140001000), 0x200, "sec0"
    )


def test_virtual_and_raw_size_zero_maps_nothing() -> None:
    assert [s.name for s in _segments(p((0x150, 0), (0x158, 0)))] == ["headers", "sec1"]


@pytest.mark.parametrize("pointer", [0, 0xFFFFFFFF])
def test_bss_only_section(pointer: int) -> None:
    assert _segments(p((0x158, 0), (0x15C, pointer)))[1] == MappedSegment(
        ByteRange(0, 0), sa(ram, 0x140001000), 0x10, "sec0"
    )


@pytest.mark.parametrize(
    "data", [p((0x17C, 0x1008)), p((0x154, 0x100))], ids=["sections", "headers"]
)
def test_overlap_rejected(data: bytes) -> None:
    _not_built(data, "segments overlap in space")


def test_unsorted_sections_accepted() -> None:
    segments = _segments(p((0x154, 0x2000), (0x17C, 0x1000)))
    assert [(s.name, s.start) for s in segments[1:]] == [
        ("sec0", sa(ram, 0x140002000)),
        ("sec1", sa(ram, 0x140001000)),
    ]


# 26-30: overflow, size, entry, segment count, empty


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (p((0x70, 2**64 - 0x1000)), "address exceeds 64-bit space"),
        (p32((0x74, 0xFFFFF000)), "address exceeds 32-bit space"),
        (p32((0x168, 0xFFFFFFFF)), "segment exceeds address space"),
    ],
    ids=["pe64-base", "pe32-base", "pe32-section"],
)
def test_address_overflow(data: bytes, reason: str) -> None:
    _not_built(data, reason)


def test_image_ending_at_top_of_space() -> None:
    image = _image(p((0x70, 2**64 - 0x3000), (0x68, 0xFFFFFFFF)))
    assert image is not None
    assert image.memory.segments[-1].end == 2**64
    assert image.entry is None


def test_mapped_size_limit() -> None:
    data = p((0x150, 0x80000000), (0x17C, 0x80001000), (0x178, 0x80000000))
    _not_built(data, "mapped size exceeds 4294967296 bytes")


@pytest.mark.parametrize(
    ("rva", "entry"),
    [(0, None), (0x5000, None), (0x10, sa(ram, 0x140000010))],
)
def test_entry(rva: int, entry: SpaceAddress | None) -> None:
    image = _image(p((0x68, rva)))
    assert image is not None
    assert image.entry == entry


def _with_sections(n: int) -> PeFile:
    pe = parse_pe(MemorySource(P64))
    zero = Address(0)
    secs = tuple(
        PeSection(b"", 0x10, 0x1000 * (k + 1), 0, zero, zero, zero, 0, 0, 0) for k in range(n)
    )
    return replace(pe, coff=replace(pe.coff, number_of_sections=n), sections=secs)


def test_segment_count_at_limit() -> None:
    image = pe_image(_with_sections(63))
    assert image is not None
    assert len(image.memory.segments) == 64


def test_segment_count_over_limit() -> None:
    with pytest.raises(ParseError) as exc:
        pe_image(_with_sections(64))
    assert exc.value.reason == "segment count must be 1..64"


def test_nothing_to_map() -> None:
    data = p((0x94, 0), (0x150, 0), (0x158, 0), (0x178, 0), (0x180, 0))
    assert _image(data) is None
