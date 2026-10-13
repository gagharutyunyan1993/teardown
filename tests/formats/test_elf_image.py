from __future__ import annotations

from dataclasses import replace

import pytest

from retool.formats import Format, Image, MappedSegment, MemoryMap
from retool.formats.domain.elf import PT_LOAD, ProgramHeader, parse_elf
from retool.formats.domain.elf_image import elf_arch, elf_image
from retool.shared import Address, AddressSpace, ArchitectureId, ByteRange, ParseError
from tests.formats.elf_build import F32, F64, p
from tests.formats.fakes import MemorySource, ram, sa


def _image(data: bytes) -> Image | None:
    return elf_image(parse_elf(MemorySource(data)))


def test_f64_image() -> None:
    assert _image(F64) == Image(
        ArchitectureId("x86_64"),
        MemoryMap(
            (
                MappedSegment(ByteRange(0, 0xC0), sa(ram, 0x400000), 0xC0, "phdr0"),
                MappedSegment(ByteRange(0xC0, 8), sa(ram, 0x4010C0), 0x100, "phdr1"),
            )
        ),
        sa(ram, 0x4000B0),
        Format.ELF,
    )


def test_f32_image() -> None:
    ram32 = AddressSpace("ram", 32)
    assert _image(F32) == Image(
        ArchitectureId("arm"),
        MemoryMap(
            (
                MappedSegment(ByteRange(0, 0x84), sa(ram32, 0x8000), 0x84, "phdr0"),
                MappedSegment(ByteRange(0x84, 8), sa(ram32, 0x9084), 0x100, "phdr1"),
            )
        ),
        sa(ram32, 0x8074),
        Format.ELF,
    )


@pytest.mark.parametrize(
    ("machine", "name"),
    [
        (3, "x86"),
        (8, "mips"),
        (20, "ppc"),
        (21, "ppc64"),
        (22, "s390"),
        (40, "arm"),
        (62, "x86_64"),
        (183, "aarch64"),
        (243, "riscv"),
        (0xBEEF, "elf-em-48879"),
    ],
)
def test_elf_arch(machine: int, name: str) -> None:
    assert elf_arch(parse_elf(MemorySource(p((18, machine)))).header) == ArchitectureId(name)


def test_pure_bss_segment() -> None:
    image = _image(p((0x98, 0)))
    assert image is not None
    assert image.memory.segments[1] == MappedSegment(
        ByteRange(0xC0, 0), sa(ram, 0x4010C0), 0x100, "phdr1"
    )


def test_zero_memsz_load_skipped() -> None:
    image = _image(p((0x98, 0), (0xA0, 0)))
    assert image is not None
    assert [s.name for s in image.memory.segments] == ["phdr0"]


def test_no_load_gives_no_image() -> None:
    assert _image(p((0x40, 4), (0x78, 4))) is None


def test_overlapping_loads_rejected() -> None:
    with pytest.raises(ParseError, match="segments overlap in space"):
        _image(p((0x88, 0x400010)))


def test_mapped_size_cap() -> None:
    with pytest.raises(ParseError, match="mapped size exceeds 4294967296 bytes"):
        _image(p((0xA0, 2**33)))


def test_segment_count_cap() -> None:
    elf = parse_elf(MemorySource(F64))
    load = ProgramHeader(PT_LOAD, 4, Address(0), Address(0), Address(0), 0, 0x10, 0x10)
    phdrs = tuple(replace(load, p_vaddr=Address(i * 0x10)) for i in range(65))
    many = replace(elf, header=replace(elf.header, e_phnum=65), program_headers=phdrs)
    with pytest.raises(ParseError, match=r"segment count must be 1\.\.64"):
        elf_image(many)


@pytest.mark.parametrize("entry", [0x500000, 0])
def test_entry_outside_or_zero_is_none(entry: int) -> None:
    image = _image(p((24, entry)))
    assert image is not None
    assert image.entry is None


def test_unsorted_loads_accepted() -> None:
    swapped = F64[:0x40] + F64[0x78:0xB0] + F64[0x40:0x78] + F64[0xB0:]
    image = _image(swapped)
    assert image is not None
    assert [(s.name, s.start) for s in image.memory.segments] == [
        ("phdr0", sa(ram, 0x4010C0)),
        ("phdr1", sa(ram, 0x400000)),
    ]
