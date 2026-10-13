from __future__ import annotations

import pytest

from retool.formats.domain.elf import (
    ElfClass,
    ElfData,
    ElfFile,
    ElfHeader,
    ProgramHeader,
    SectionHeader,
    parse_elf,
    section_kind,
)
from retool.formats.domain.elf_image import elf_image
from retool.formats.domain.elf_parser import ElfParser
from retool.formats.domain.model import InputChanged
from retool.formats.domain.parsing import SectionSummary, display_name
from retool.shared import Address, ByteRange, ParseError
from tests.formats.elf_build import F32, F64, build_elf, byte, p, patch
from tests.formats.fakes import MemorySource, ShrinkingSource, SparseSource, ram, sa


def _rejected(data: bytes, offset: int, reason: str | None = None) -> ParseError:
    with pytest.raises(ParseError) as exc:
        parse_elf(MemorySource(data))
    assert type(exc.value) is ParseError
    assert exc.value.offset == offset
    if reason is not None:
        assert exc.value.reason == reason
    return exc.value


# 1-3: well-formed fixtures


def test_f64_parses() -> None:
    elf = parse_elf(MemorySource(F64))
    assert elf.header == ElfHeader(
        ei_class=ElfClass.ELF64,
        ei_data=ElfData.LSB,
        ei_osabi=0,
        ei_abiversion=0,
        e_type=2,
        e_machine=62,
        e_entry=Address(0x4000B0),
        e_phoff=Address(0x40),
        e_shoff=Address(0xE0),
        e_flags=0,
        e_ehsize=64,
        e_phentsize=56,
        e_phnum=2,
        e_shentsize=64,
        e_shnum=4,
        e_shstrndx=3,
    )
    assert elf.header.bits == 64
    assert [sh.name for sh in elf.section_headers] == [b"", b".text", b".bss", b".shstrtab"]
    assert elf.program_headers == (
        ProgramHeader(1, 5, Address(0), Address(0x400000), Address(0x400000), 0xC0, 0xC0, 0x1000),
        ProgramHeader(1, 6, Address(0xC0), Address(0x4010C0), Address(0x4010C0), 8, 0x100, 0x1000),
    )


def test_f32_msb_parses() -> None:
    elf = parse_elf(MemorySource(F32))
    h = elf.header
    assert (h.bits, h.ei_class, h.ei_data, h.e_machine) == (32, ElfClass.ELF32, ElfData.MSB, 40)
    assert (h.e_entry, h.e_phoff, h.e_shoff) == (Address(0x8074), Address(0x34), Address(0xA4))
    assert (h.e_ehsize, h.e_phentsize, h.e_shentsize) == (52, 32, 40)
    assert (h.e_phnum, h.e_shnum, h.e_shstrndx) == (2, 4, 3)
    # PHDR32 keeps p_flags at +24, after p_memsz.
    assert elf.program_headers == (
        ProgramHeader(1, 5, Address(0), Address(0x8000), Address(0x8000), 0x84, 0x84, 0x1000),
        ProgramHeader(1, 6, Address(0x84), Address(0x9084), Address(0x9084), 8, 0x100, 0x1000),
    )
    a = Address
    assert elf.section_headers == (
        SectionHeader(0, b"", 0, 0, a(0), a(0), 0, 0, 0, 0, 0),
        SectionHeader(1, b".text", 1, 6, a(0x8074), a(0x74), 0x10, 0, 0, 16, 0),
        SectionHeader(7, b".bss", 8, 3, a(0x908C), a(0x8C), 0xF8, 0, 0, 8, 0),
        SectionHeader(12, b".shstrtab", 3, 0, a(0), a(0x8C), 0x16, 0, 0, 1, 0),
    )


def test_read_order() -> None:
    source = MemorySource(F64)
    parse_elf(source)
    assert source.calls == [
        (0, 16),
        (0, 64),
        (0xE0, 64),
        (0x40, 56),
        (0x78, 56),
        (0x120, 64),
        (0x160, 64),
        (0x1A0, 64),
        (0xC8, 22),
    ]


# 4: identification and header (S1-S8)


@pytest.mark.parametrize(
    ("data", "offset", "reason"),
    [
        (b"", 0, "ELF identification exceeds file"),
        (F64[:15], 0, "ELF identification exceeds file"),
        (b"\x7fELG" + F64[4:], 0, "bad ELF magic"),
        (byte(F64, 4, 0), 4, "invalid EI_CLASS"),
        (byte(F64, 4, 3), 4, "invalid EI_CLASS"),
        (byte(F64, 5, 0), 5, "invalid EI_DATA"),
        (byte(F64, 5, 3), 5, "invalid EI_DATA"),
        (byte(F64, 6, 0), 6, "invalid EI_VERSION"),
        (byte(F64, 6, 2), 6, "invalid EI_VERSION"),
        (F64[:63], 0, "ELF header exceeds file"),
        (F32[:51], 0, "ELF header exceeds file"),
        (p((20, 0)), 20, "invalid e_version"),
        (p((52, 63)), 52, "e_ehsize smaller than ELF header"),
        (patch(F32, 40, ">H", 51), 40, "e_ehsize smaller than ELF header"),
    ],
)
def test_ident_and_header_rejected(data: bytes, offset: int, reason: str) -> None:
    _rejected(data, offset, reason)


def test_larger_ehsize_accepted() -> None:
    assert parse_elf(MemorySource(p((52, 80)))).header.e_ehsize == 80


# 5: precedence (S9, S10, S15, S17)


def test_shnum_without_shoff_reported_before_shstrndx() -> None:
    _rejected(p((40, 0)), 60, "e_shnum set without e_shoff")


@pytest.mark.parametrize("shstrndx", [3, 0xFFFF])
def test_shstrndx_without_shoff(shstrndx: int) -> None:
    data = p((40, 0), (60, 0), (62, shstrndx))
    _rejected(data, 62, "e_shstrndx set without e_shoff")


@pytest.mark.parametrize("extra", [(), ((32, 0),)])
def test_pn_xnum_without_shoff_before_phoff_check(extra: tuple[tuple[int, int], ...]) -> None:
    data = p((40, 0), (60, 0), (62, 0), (56, 0xFFFF), *extra)
    _rejected(data, 56, "PN_XNUM without section header table")


def test_phnum_without_phoff() -> None:
    _rejected(p((32, 0)), 56, "e_phnum set without e_phoff")


def test_phnum_without_phoff_uses_effective_count() -> None:
    _rejected(p((32, 0), (56, 0xFFFF), (0x10C, 2)), 56, "e_phnum set without e_phoff")
    elf = parse_elf(MemorySource(p((32, 0), (56, 0xFFFF))))
    assert elf.program_headers == ()
    assert elf.header.e_phnum == 0


# 6: table geometry (S11-S14, S16, S18, S19)


@pytest.mark.parametrize(
    ("data", "offset", "reason"),
    [
        (p((58, 63)), 58, "e_shentsize smaller than section header"),
        (p((54, 55)), 54, "e_phentsize smaller than program header"),
        (patch(F32, 42, ">H", 31), 42, "e_phentsize smaller than program header"),
        (p((40, 0x1C0)), 0x1C0, "section header table exceeds file"),
        (p((40, 0x120)), 0x120, "section header table exceeds file"),
        (p((60, 0), (0x100, 0)), 0x100, "section count is zero"),
        (p((60, 3073)), 60, "section count exceeds 3072"),
        (p((60, 0), (0x100, 3073)), 0x100, "section count exceeds 3072"),
        (p((56, 513)), 56, "program header count exceeds 512"),
        (p((56, 0xFFFF), (0x10C, 513)), 0x10C, "program header count exceeds 512"),
        (p((32, 0x1A8)), 0x1A8, "program header table exceeds file"),
        (p((40, 2**64 - 1)), 2**64 - 1, "section header table exceeds file"),
        (p((32, 2**64 - 8)), 2**64 - 8, "program header table exceeds file"),
    ],
)
def test_table_geometry_rejected(data: bytes, offset: int, reason: str) -> None:
    _rejected(data, offset, reason)


def test_phdr_table_aliasing_header_accepted() -> None:
    # phdr0 at offset 8 reads as PT_NULL because bytes 8..11 (EI_PAD) are zero; phdr1 at 0x40
    # is the original LOAD0.
    elf = parse_elf(MemorySource(p((32, 8))))
    assert [ph.p_type for ph in elf.program_headers] == [0, 1]
    assert elf.program_headers[1].p_vaddr == Address(0x400000)


# 7: segment checks (S20-S22)


@pytest.mark.parametrize(
    ("data", "offset", "reason"),
    [
        (p((0x80, 2**64 - 16), (0x98, 32)), 0x78, "segment file range exceeds file"),
        (p((0x78, 4), (0x80, 0x1D0), (0x98, 0x20)), 0x78, "segment file range exceeds file"),
        (p((0x98, 0x101)), 0x78, "PT_LOAD filesz exceeds memsz"),
        (p((0x88, 2**64 - 0x80)), 0x78, "PT_LOAD exceeds address space"),
        (patch(F32, 0x5C, ">I", 0xFFFFFF80), 0x54, "PT_LOAD exceeds address space"),
    ],
)
def test_segment_rejected(data: bytes, offset: int, reason: str) -> None:
    _rejected(data, offset, reason)


def test_zero_filesz_segment_exempt_from_file_range() -> None:
    elf = parse_elf(MemorySource(p((0x98, 0), (0x80, 2**64 - 1))))
    assert elf.program_headers[1].p_offset == Address(2**64 - 1)
    # The code builds the image and keeps phdr1 as a pure-BSS segment; its offset is never read.
    image = elf_image(elf)
    assert image is not None
    assert image.memory.segments[1].file == ByteRange(2**64 - 1, 0)
    assert image.memory.segments[1].start == sa(ram, 0x4010C0)


def test_pt_null_exempt_from_file_range() -> None:
    elf = parse_elf(MemorySource(p((0x78, 0), (0x80, 2**64 - 1))))
    assert elf.program_headers[1].p_type == 0


def test_phdr_table_ending_at_eof_accepted() -> None:
    # 0x170 + 2 * 56 == 0x1e0 == file size.
    elf = parse_elf(MemorySource(p((32, 0x1E0 - 0x70))))
    assert len(elf.program_headers) == 2


def test_load_file_range_ending_at_eof_accepted() -> None:
    elf = parse_elf(MemorySource(p((0x80, 0x1D8), (0x98, 8))))
    ph = elf.program_headers[1]
    assert (ph.p_offset, ph.p_filesz, ph.p_memsz) == (Address(0x1D8), 8, 0x100)


def test_load_ending_at_address_space_top_accepted() -> None:
    elf = parse_elf(MemorySource(p((0x88, 2**64 - 0x100))))
    assert elf.program_headers[1].p_vaddr == Address(2**64 - 0x100)


# 8: sections and the name table (S23-S29)


@pytest.mark.parametrize(
    ("data", "offset", "reason"),
    [
        (p((0x138, 2**64 - 8)), 0x120, "section file range exceeds file"),
        (p((62, 4)), 62, "e_shstrndx out of range"),
        (p((62, 0xFFFF), (0x108, 4)), 0x108, "e_shstrndx out of range"),
        (p((0x1A4, 1)), 0x1A4, "section name table is not SHT_STRTAB"),
        (p((0x1A4, 8)), 0x1A4, "section name table is not SHT_STRTAB"),
        (byte(F64, 0xC8, 0x41), 0xC8, "section name table does not start with NUL"),
        (byte(F64, 0xDD, 0x41), 0xDD, "section name table does not end with NUL"),
        (p((0x120, 22)), 0x120, "section name offset past string table"),
        (p((0x1C0, 0)), 0x120, "section name offset past string table"),
    ],
)
def test_section_rejected(data: bytes, offset: int, reason: str) -> None:
    _rejected(data, offset, reason)


def test_nobits_never_checked_against_file() -> None:
    elf = parse_elf(MemorySource(p((0x178, 2**64 - 1), (0x180, 2**63))))
    assert elf.section_headers[2].sh_size == 2**63


def test_name_table_at_cap_is_read() -> None:
    source = SparseSource((1 << 20) + 0x200, head=p((0x1C0, 1 << 20)))
    elf = parse_elf(source)
    assert source.calls[-1] == (0xC8, 1 << 20)
    assert [sh.name for sh in elf.section_headers] == [b"", b".text", b".bss", b".shstrtab"]


def test_name_table_cap_checked_before_read() -> None:
    source = SparseSource((1 << 20) + 0x200, head=p((0x1C0, (1 << 20) + 1)))
    with pytest.raises(ParseError) as exc:
        parse_elf(source)
    assert (exc.value.reason, exc.value.offset) == (
        "section name table exceeds 1048576 bytes",
        0x1A0,
    )
    assert all(size <= 64 for _, size in source.calls[2:])


# 9: name length cap (S30)


def _long_names(count: int) -> bytes:
    table = b"\0" + b"a" * count + b"\0"
    return patch(patch(F64 + table, 0x1B8, "<Q", 0x1E0), 0x1C0, "<Q", len(table))


def test_name_over_cap_rejected() -> None:
    _rejected(_long_names(257), 0x120, "section name exceeds 256 bytes")


def test_name_at_cap_accepted() -> None:
    elf = parse_elf(MemorySource(_long_names(256)))
    assert elf.section_headers[1].name == b"a" * 256


def test_name_window_clipped_by_table_end() -> None:
    assert parse_elf(MemorySource(F64)).section_headers[3].name == b".shstrtab"


# 10: short read (S31)


def test_short_read_raises_input_changed() -> None:
    with pytest.raises(InputChanged) as exc:
        parse_elf(ShrinkingSource(F64, cut=0x120))
    assert exc.value.offset == 0x120
    with pytest.raises(InputChanged) as exc2:
        ElfParser().parse(ShrinkingSource(F64, cut=0x120), "formats.inspect")
    assert exc2.value.offset == 0x120


# 11-14: escapes, absent tables, stride, suffix sharing


def test_escapes_resolved() -> None:
    assert parse_elf(MemorySource(p((56, 0xFFFF), (0x10C, 2)))).header.e_phnum == 2
    assert parse_elf(MemorySource(p((60, 0), (0x100, 4)))).header.e_shnum == 4
    elf = parse_elf(MemorySource(p((62, 0xFFFF), (0x108, 3))))
    assert elf.header.e_shstrndx == 3
    assert [sh.name for sh in elf.section_headers] == [b"", b".text", b".bss", b".shstrtab"]


def test_no_section_header_table() -> None:
    elf = parse_elf(MemorySource(p((40, 0), (60, 0), (62, 0))))
    assert elf.section_headers == ()
    assert len(elf.program_headers) == 2


def test_no_name_table_leaves_names_empty() -> None:
    elf = parse_elf(MemorySource(p((62, 0))))
    assert [sh.name for sh in elf.section_headers] == [b""] * 4


def test_entry_stride_larger_than_struct() -> None:
    source = MemorySource(build_elf(phent_pad=8, shent_pad=16))
    elf = parse_elf(source)
    assert (elf.header.e_phentsize, elf.header.e_shentsize) == (64, 80)
    assert [sh.name for sh in elf.section_headers] == [b"", b".text", b".bss", b".shstrtab"]
    assert tuple(ph.p_type for ph in elf.program_headers) == (1, 1)


@pytest.mark.parametrize(("sh_name", "name"), [(15, b"strtab"), (21, b"")])
def test_suffix_sharing(sh_name: int, name: bytes) -> None:
    assert parse_elf(MemorySource(p((0x120, sh_name)))).section_headers[1].name == name


def test_elf_file_counts_must_match_header() -> None:
    elf = parse_elf(MemorySource(F64))
    with pytest.raises(ParseError, match="ELF table counts inconsistent"):
        ElfFile(elf.header, elf.program_headers[:1], elf.section_headers)


# 15: display helpers


def test_display_name_escapes() -> None:
    assert display_name(b'a"\\\x01\xff ') == "a\\x22\\x5c\\x01\\xff "


def test_section_kind() -> None:
    assert section_kind(8) == "nobits"
    assert section_kind(0x6FFFFFF6) == "type-0x6ffffff6"


@pytest.mark.parametrize(("index", "size"), [(-1, 0), (0, -1)])
def test_section_summary_rejects_negative(index: int, size: int) -> None:
    with pytest.raises(ParseError):
        SectionSummary(index, "", "null", 0, 0, size)
