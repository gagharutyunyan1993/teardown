from __future__ import annotations

import struct
from dataclasses import replace

import pytest

from retool.formats.domain.model import InputChanged
from retool.formats.domain.parsing import read_exact
from retool.formats.domain.pe import (
    CoffHeader,
    DataDirectory,
    DosHeader,
    OptionalHeader,
    PeSection,
    parse_pe,
    pe_section_kind,
)
from retool.formats.domain.pe_parser import PeParser
from retool.shared import Address, ParseError
from tests.formats.fakes import MemorySource, ShrinkingSource
from tests.formats.pe_build import P32, P64, build_pe, name, p, p32

PRODUCER = "formats.inspect"


def _rejected(data: bytes, offset: int, reason: str) -> None:
    with pytest.raises(ParseError) as exc:
        parse_pe(MemorySource(data))
    assert type(exc.value) is ParseError
    assert exc.value.offset == offset
    assert exc.value.reason == reason


def _section(
    nm: bytes, vsize: int, vaddr: int, raw: int, ptr: int, characteristics: int
) -> PeSection:
    zero = Address(0)
    return PeSection(nm, vsize, vaddr, raw, Address(ptr), zero, zero, 0, 0, characteristics)


_SECTIONS = (
    _section(b".text", 0x10, 0x1000, 0x200, 0x200, 0x60000020),
    _section(b".data", 0x1000, 0x2000, 0x200, 0x400, 0xC0000040),
)


# 1-3: well-formed fixtures


def test_p64_parses() -> None:
    pe = parse_pe(MemorySource(P64))
    assert pe.dos == DosHeader(0x5A4D, Address(0x40))
    assert pe.coff == CoffHeader(0x8664, 2, 0x5F000000, Address(0), 0, 0xF0, 0x22)
    assert pe.optional == OptionalHeader(
        magic=0x20B,
        major_linker_version=14,
        minor_linker_version=36,
        size_of_code=0x200,
        size_of_initialized_data=0x200,
        size_of_uninitialized_data=0,
        address_of_entry_point=0x1000,
        base_of_code=0x1000,
        base_of_data=None,
        image_base=0x140000000,
        section_alignment=0x1000,
        file_alignment=0x200,
        major_os_version=6,
        minor_os_version=1,
        major_image_version=2,
        minor_image_version=3,
        major_subsystem_version=5,
        minor_subsystem_version=4,
        win32_version_value=0,
        size_of_image=0x3000,
        size_of_headers=0x200,
        checksum=0xC0FFEE,
        subsystem=3,
        dll_characteristics=0x8160,
        size_of_stack_reserve=0x100000,
        size_of_stack_commit=0x1000,
        size_of_heap_reserve=0x80000,
        size_of_heap_commit=0x2000,
        loader_flags=0,
        number_of_rva_and_sizes=16,
    )
    assert pe.optional.bits == 64
    dirs = [DataDirectory(0, 0)] * 16
    dirs[1] = DataDirectory(0x2000, 0x28)
    assert pe.directories == tuple(dirs)
    assert pe.sections == _SECTIONS


def test_p32_parses() -> None:
    source = MemorySource(P32)
    pe = parse_pe(source)
    assert pe.coff == CoffHeader(0x14C, 2, 0x5F000000, Address(0), 0, 0xE0, 0x102)
    assert pe.optional.magic == 0x10B
    assert pe.optional.base_of_data == 0x2000
    assert pe.optional.image_base == 0x400000
    assert pe.optional.dll_characteristics == 0x8140
    assert pe.optional.bits == 32
    assert pe.directories[1] == DataDirectory(0x2000, 0x28)
    assert source.calls[-1] == (0x138, 80)
    assert pe.sections == _SECTIONS


def test_p64_read_order() -> None:
    source = MemorySource(P64)
    parse_pe(source)
    assert source.calls == [
        (0, 64),
        (0x40, 4),
        (0x44, 20),
        (0x58, 2),
        (0x58, 112),
        (0xC8, 128),
        (0x148, 80),
    ]


# 4-5: truncation, DOS header and signature


@pytest.mark.parametrize(
    ("data", "offset", "reason"),
    [
        (b"", 0, "DOS header exceeds file"),
        (P64[:63], 0, "DOS header exceeds file"),
        (P64[:0x43], 0x3C, "PE signature exceeds file"),
        (P64[:0x57], 0x44, "COFF header exceeds file"),
        (P64[:0x59], 0x58, "optional header exceeds file"),
        (P64[:0xC7], 0x58, "optional header exceeds file"),
        (P64[:0x100], 0xC8, "data directories exceed file"),
        (P64[:0x1FF], 0x94, "SizeOfHeaders exceeds file"),
        (P64[:0x5FF], 0x170, "section raw data exceeds file"),
    ],
)
def test_truncated(data: bytes, offset: int, reason: str) -> None:
    _rejected(data, offset, reason)


def test_bad_dos_magic() -> None:
    _rejected(p((0, 0x4D5A)), 0, "bad DOS magic")


@pytest.mark.parametrize("lfanew", [0, 4, 0x3C, 0x3F])
def test_lfanew_inside_dos_header(lfanew: int) -> None:
    _rejected(p((0x3C, lfanew)), 0x3C, "e_lfanew inside DOS header")


@pytest.mark.parametrize("lfanew", [0x5FD, 0xFFFFFFFF])
def test_signature_exceeds_file(lfanew: int) -> None:
    _rejected(p((0x3C, lfanew)), 0x3C, "PE signature exceeds file")


def test_bad_signature() -> None:
    _rejected(P64[:0x40] + b"PE\0\1" + P64[0x44:], 0x40, "bad PE signature")


def test_signature_at_lfanew() -> None:
    _rejected(p((0x3C, 0x200)), 0x200, "bad PE signature")


# 6-13: COFF, optional header, directories, section table


def test_section_count_limit() -> None:
    data = build_pe(extra_sections=94)
    assert len(data) == 0x1600
    assert len(parse_pe(MemorySource(data)).sections) == 96


def test_section_count_exceeds_limit() -> None:
    _rejected(build_pe(extra_sections=95), 0x46, "section count exceeds 96")


def test_zero_sections() -> None:
    assert parse_pe(MemorySource(p((0x46, 0)))).sections == ()


def test_rom_magic() -> None:
    _rejected(p((0x58, 0x107)), 0x58, "ROM optional header not supported")


@pytest.mark.parametrize("magic", [0, 0x10C])
def test_invalid_magic(magic: int) -> None:
    _rejected(p((0x58, magic)), 0x58, "invalid optional header magic")


@pytest.mark.parametrize(
    "data", [p((0x54, 0x6F)), p((0x54, 0)), p32((0x54, 0x5F))], ids=["6f", "0", "pe32-5f"]
)
def test_optional_header_too_small(data: bytes) -> None:
    _rejected(data, 0x54, "optional header smaller than its fixed part")


def test_directories_exceed_optional_header() -> None:
    _rejected(p((0x54, 0xEF)), 0xC4, "data directories exceed optional header")


def test_no_directories() -> None:
    source = MemorySource(p((0xC4, 0)))
    pe = parse_pe(source)
    assert pe.directories == ()
    assert pe.optional.number_of_rva_and_sizes == 0
    assert source.calls[-2:] == [(0x58, 112), (0x148, 80)]
    assert pe.sections == _SECTIONS


@pytest.mark.parametrize("declared", [17, 0xFFFFFFFF])
def test_directory_count_clamped(declared: int) -> None:
    pe = parse_pe(MemorySource(p((0xC4, declared))))
    assert len(pe.directories) == 16
    assert pe.optional.number_of_rva_and_sizes == declared


def test_ndirs_zero_fixture() -> None:
    source = MemorySource(build_pe(ndirs=0))
    pe = parse_pe(source)
    assert pe.coff.size_of_optional_header == 0x70
    assert source.calls[-2:] == [(0x58, 112), (0xC8, 80)]
    assert [s.name for s in pe.sections] == [b".text", b".data"]


def test_optional_header_padding_honoured() -> None:
    source = MemorySource(build_pe(opt_pad=8))
    pe = parse_pe(source)
    assert pe.coff.size_of_optional_header == 0xF8
    assert source.calls[-1] == (0x150, 80)
    assert pe.sections == _SECTIONS


def test_size_of_headers_exceeds_file() -> None:
    _rejected(p((0x94, 0x601)), 0x94, "SizeOfHeaders exceeds file")


@pytest.mark.parametrize(
    ("data", "offset"),
    [(p((0x94, 0x100))[:0x190], 0x148), (p((0x54, 0xFFFF)), 0x10057)],
    ids=["truncated", "huge-optional-header"],
)
def test_section_table_exceeds_file(data: bytes, offset: int) -> None:
    _rejected(data, offset, "section table exceeds file")


def test_table_past_eof_without_sections() -> None:
    source = MemorySource(p((0x54, 0xFFFF), (0x46, 0)))
    assert parse_pe(source).sections == ()
    assert source.calls[-1] == (0xC8, 128)


@pytest.mark.parametrize(
    ("data", "offset"),
    [(p((0x180, 0x201)), 0x170), (p((0x15C, 0xFFFFFFFF)), 0x148)],
    ids=["raw-size", "pointer"],
)
def test_section_raw_data_exceeds_file(data: bytes, offset: int) -> None:
    _rejected(data, offset, "section raw data exceeds file")


def test_bss_only_section_any_pointer() -> None:
    pe = parse_pe(MemorySource(p((0x158, 0), (0x15C, 0xFFFFFFFF))))
    assert pe.sections[0].pointer_to_raw_data == Address(0xFFFFFFFF)
    assert pe.sections[0].size_of_raw_data == 0


# 14: input changed


def test_short_read_raises_input_changed() -> None:
    with pytest.raises(InputChanged) as exc:
        parse_pe(ShrinkingSource(P64, cut=0x148))
    assert exc.value.offset == 0x148


def test_parser_propagates_input_changed() -> None:
    with pytest.raises(InputChanged) as exc:
        PeParser().parse(ShrinkingSource(P64, cut=0x148), PRODUCER)
    assert exc.value.offset == 0x148


# 15-17: names, invariants, kinds, alignment


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(b"abcdefgh", b"abcdefgh"), (b".a\0junk\0", b".a"), (b"\0" * 8, b"")],
)
def test_section_names(raw: bytes, expected: bytes) -> None:
    assert parse_pe(MemorySource(name(P64, 0x148, raw))).sections[0].name == expected


def test_table_counts_inconsistent() -> None:
    pe = parse_pe(MemorySource(P64))
    with pytest.raises(ParseError, match="PE table counts inconsistent"):
        replace(pe, sections=pe.sections[:1])


@pytest.mark.parametrize(
    ("characteristics", "kind"),
    [
        (0x20, "code"),
        (0x60000020, "code"),
        (0x40, "data"),
        (0x80, "bss"),
        (0, "other"),
        (0x02000000, "other"),
    ],
)
def test_section_kind(characteristics: int, kind: str) -> None:
    assert pe_section_kind(characteristics) == kind


def test_file_alignment_not_enforced() -> None:
    assert parse_pe(MemorySource(p((0x7C, 0x300)))).optional.file_alignment == 0x300


def test_section_alignment_below_file_alignment_accepted() -> None:
    pe = parse_pe(MemorySource(p((0x78, 0x100))))
    assert (pe.optional.section_alignment, pe.optional.file_alignment) == (0x100, 0x200)


# 18: read_exact


def test_read_exact_bounds() -> None:
    with pytest.raises(ParseError) as exc:
        read_exact(MemorySource(bytes(8)), 8, 4, 8)
    assert type(exc.value) is ParseError
    assert exc.value.reason == "range [4, 12) exceeds 8 bytes"
    assert exc.value.offset == 4


def test_read_exact_short_read() -> None:
    with pytest.raises(InputChanged) as exc:
        read_exact(ShrinkingSource(bytes(16), cut=4), 16, 8, 4)
    assert exc.value.offset == 8


# exact-fit boundaries and raw field offsets


def test_signature_exactly_at_end_is_read() -> None:
    _rejected(p((0x3C, 0x5FC)), 0x5FC, "bad PE signature")


def test_coff_header_exact_fit_then_optional_magic_missing() -> None:
    _rejected(P64[:0x58], 0x58, "optional header exceeds file")


def test_optional_fields_at_raw_offsets() -> None:
    buf = bytearray(P64)
    sentinels = {0x5C: 0x11111111, 0x60: 0x22222222, 0x68: 0x33333333, 0x6C: 0x44444444}
    sentinels |= {0x7C: 0x55555555, 0x94: 0x5F0}
    for off, value in sentinels.items():
        struct.pack_into("<I", buf, off, value)
    opt = parse_pe(MemorySource(bytes(buf))).optional
    assert opt.size_of_code == 0x11111111
    assert opt.size_of_initialized_data == 0x22222222
    assert opt.address_of_entry_point == 0x33333333
    assert opt.base_of_code == 0x44444444
    assert opt.file_alignment == 0x55555555
    assert opt.size_of_headers == 0x5F0
