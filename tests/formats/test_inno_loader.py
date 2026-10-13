from __future__ import annotations

import struct
import zlib

import pytest

from retool.formats.domain.inno import (
    InnoBlockHeader,
    InnoCompression,
    InnoData,
    InnoInfo,
    InnoOffsets,
    InnoRoute,
    InnoVersion,
)
from retool.formats.domain.inno_loader import INNO_NOT_PARSED_NOTE, inno_info
from retool.formats.domain.model import InputChanged
from retool.formats.domain.pe import PeFile, parse_pe
from retool.formats.domain.pe_parser import PeParser, attach_tables
from retool.formats.domain.ports import ByteSource
from retool.shared import Address, NotAnalysed
from tests.formats.fakes import MemorySource, ShrinkingSource, SparseSource
from tests.formats.inno_build import (
    MAGIC_515,
    PI32,
    block,
    offset_table,
    put,
    rsrc,
    version_field,
)
from tests.formats.pe_build import REAL_CERT, REAL_SIZE, dir_at, patch, real_shape

SIZE = len(PI32)  # 0x672
DIR2 = dir_at(2, 32)
TABLE_FIELDS = (1, 0, 0x11, 0x22, 0x33, 0x600, 0x66A)
INNO_LIKE = NotAnalysed("inno-like overlay without a loader offset table")
NOT_PARSED = NotAnalysed(INNO_NOT_PARSED_NOTE)
MAGIC_416 = b"rDlPtS07\x87eVx"

PI32_INFO = InnoInfo(
    InnoOffsets(
        InnoRoute.RESOURCE,
        Address(0x460),
        44,
        (5, 1, 5, 0),
        1,
        Address(0x11),
        None,
        0x22,
        0x33,
        None,
        Address(0x600),
        Address(0x66A),
        True,
    ),
    InnoVersion(b"Inno Setup Setup Data (6.4.0.1)", (6, 4, 0, 1), True, True),
    (
        InnoBlockHeader(1, Address(0x640), 0xD1C55009, 16, 1, InnoCompression.LZMA1, True),
        InnoBlockHeader(2, Address(0x659), 0x81558C4A, 8, 1, InnoCompression.LZMA1, True),
    ),
    InnoData(Address(0x66A), True),
)


def _attached(source: ByteSource) -> tuple[PeFile, tuple[NotAnalysed, ...]]:
    return attach_tables(source, parse_pe(source))


def _inno(
    data: bytes,
) -> tuple[InnoInfo | None, tuple[NotAnalysed, ...], list[tuple[int, int]]]:
    """inno_info on the attached PE, with the reads it made."""
    source = MemorySource(data)
    pe, _ = _attached(source)
    before = len(source.calls)
    info, notes = inno_info(source, pe)
    return info, notes, source.calls[before:]


def _with_table(data: bytes = PI32, *fields: int, crc: int | None = None) -> bytes:
    table = offset_table(MAGIC_515, fields or TABLE_FIELDS, crc)
    return data[:0x460] + table + data[0x460 + len(table) :]


def _fields(ho: int = 0x600, do: int = 0x66A, rev: int = 1) -> tuple[int, ...]:
    return (rev, 0, 0x11, 0x22, 0x33, ho, do)


def _pointer(data: bytes, off: int, complement: int | None = None) -> bytes:
    comp = off ^ 0xFFFFFFFF if complement is None else complement
    return put(data, 0x30, "<III", 0x6F6E6E49, off, comp)


def _no_resources(data: bytes) -> bytes:
    return put(data, DIR2, "<II", 0, 0)


TABLE_416 = offset_table(MAGIC_416, (0, 0x11, 0x22, 0x33, 0x600, 0x66A))


# t19: PI32


def test_t19_pi32() -> None:
    source = SparseSource(SIZE, head=PI32)
    pe, _ = _attached(source)
    before = len(source.calls)
    info, notes = inno_info(source, pe)
    reads = source.calls[before:]
    assert info == PI32_INFO
    assert notes == (NOT_PARSED,)
    assert len(reads) <= 7
    assert sum(n for _, n in reads) <= 142


def test_t19_attached() -> None:
    pe, notes = _attached(MemorySource(PI32))
    assert pe.inno == PI32_INFO
    assert notes == (NOT_PARSED,)


# t20-t24: routes


def test_t20_pointer_route() -> None:
    info, notes, _ = _inno(_pointer(_no_resources(PI32), SIZE) + TABLE_416)
    assert info is not None
    o = info.offsets
    assert (o.route, o.table_offset, o.table_size, o.loader_version) == (
        InnoRoute.POINTER,
        Address(SIZE),
        40,
        (4, 1, 6, 0),
    )
    assert (o.revision, o.exe_compressed_size, o.crc_ok) == (None, None, True)
    assert info.blocks == PI32_INFO.blocks
    assert notes == (NOT_PARSED,)


def test_t20_pointer_route_reads() -> None:
    _, _, reads = _inno(_pointer(_no_resources(PI32), SIZE) + TABLE_416)
    assert reads[:3] == [(0x30, 12), (SIZE, 12), (SIZE + 12, 28)]
    assert len(reads) == 7


def test_t21_complement_wrong_without_resource() -> None:
    data = _pointer(_no_resources(PI32), SIZE, complement=0)
    info, notes, _ = _inno(data + TABLE_416)
    assert info is None
    assert notes == (
        NotAnalysed("inno loader pointer at 0x30 fails its complement check"),
        INNO_LIKE,
    )


def test_t22_pointer_wins_over_resource() -> None:
    info, _, _ = _inno(_pointer(PI32, SIZE) + TABLE_416)
    assert info is not None
    assert (info.offsets.route, info.offsets.table_offset) == (InnoRoute.POINTER, Address(SIZE))


def test_t23_complement_wrong_with_resource() -> None:
    data = _pointer(_with_table(PI32, *TABLE_FIELDS, crc=0), 0x460, complement=0)
    info, notes, _ = _inno(data)
    assert info is not None
    assert info.offsets.route is InnoRoute.RESOURCE
    assert notes == (
        NotAnalysed("inno loader pointer at 0x30 fails its complement check"),
        NotAnalysed("inno loader table CRC mismatch at offset 0x460"),
        NOT_PARSED,
    )


@pytest.mark.parametrize("target", [SIZE - 8, SIZE + 4, SIZE - 20])
def test_t24_pointer_past_end_falls_through(target: int) -> None:
    note = NotAnalysed(f"inno loader pointer target {target:#x} past end of file")
    info, notes, _ = _inno(_pointer(PI32, target))
    assert info is not None
    assert info.offsets.route is InnoRoute.RESOURCE
    assert notes == (note, NOT_PARSED)


@pytest.mark.parametrize("target", [0x600 - 8, 0x600 + 4])
def test_t24_pointer_past_end_without_resource(target: int) -> None:
    source = MemorySource(_pointer(_no_resources(PI32[:0x600]), target))
    pe, notes = _attached(source)
    assert pe.inno is None
    assert notes == (NotAnalysed(f"inno loader pointer target {target:#x} past end of file"),)


# t25: resource route failures (part dropped)


def test_t25_resource_smaller_than_table() -> None:
    pe, notes = _attached(MemorySource(patch(PI32, 0x44C, "<I", 43)))
    assert pe.inno is None
    assert notes == (
        NotAnalysed(
            "pe inno not parsed: inno offset table larger than its resource at offset 0x448"
        ),
    )


def test_t25_resource_not_file_backed() -> None:
    pe, notes = _attached(MemorySource(patch(PI32, 0x448, "<I", 0x9000)))
    assert pe.inno is None
    assert notes == (
        NotAnalysed(
            "pe inno not parsed: inno offset table resource not file-backed at offset 0x448"
        ),
    )


def test_t25_resource_failure_keeps_pointer_note() -> None:
    data = _pointer(patch(PI32, 0x448, "<I", 0x9000), 0x5000)
    pe, notes = _attached(MemorySource(data))
    assert pe.inno is None
    assert notes == (
        NotAnalysed("inno loader pointer target 0x5000 past end of file"),
        NotAnalysed(
            "pe inno not parsed: inno offset table resource not file-backed at offset 0x448"
        ),
    )


# t26-t27: setup data version and data chunk


def test_t26_header_at_end_of_file() -> None:
    info, notes, _ = _inno(_with_table(PI32, *_fields(ho=SIZE)))
    assert info is not None
    assert (info.version, info.blocks) == (None, ())
    assert notes[0] == NotAnalysed(f"inno setup data header past end of file at offset {SIZE:#x}")


def test_t26_header_short_reads_only_the_stamp() -> None:
    h = SIZE - 20
    info, notes, reads = _inno(_with_table(PI32, *_fields(ho=h)))
    assert info is not None
    assert info.version is None
    assert notes[0] == NotAnalysed(f"inno setup data header past end of file at offset {h:#x}")
    assert [r for r in reads if r[0] == h] == [(h, 12)]


def test_t26_external_slices() -> None:
    info, notes, _ = _inno(_with_table(PI32, *_fields(do=0)))
    assert info is not None
    assert info.data is None
    assert notes == (NotAnalysed("inno data in external slice files not analysed"), NOT_PARSED)


def test_t26_data_at_end_of_file() -> None:
    info, _, _ = _inno(_with_table(PI32, *_fields(do=SIZE - 4)))
    assert info is not None
    assert info.data == InnoData(Address(SIZE - 4), False)
    info, notes, _ = _inno(_with_table(PI32, *_fields(do=SIZE - 3)))
    assert info is not None
    assert info.data is None
    assert notes[0] == NotAnalysed(f"inno data chunk past end of file at offset {SIZE - 3:#x}")


def test_t26_bad_chunk_magic() -> None:
    info, _, _ = _inno(PI32[:0x66A] + b"zlbX" + PI32[0x66E:])
    assert info is not None
    assert info.data == InnoData(Address(0x66A), False)


def test_t27_legacy_stamp() -> None:
    info, notes, _ = _inno(PI32[:0x600] + b"i1.2.10--16\x1a" + PI32[0x60C:])
    assert info is not None
    assert (info.version, info.blocks) == (None, ())
    assert notes[0] == NotAnalysed("inno legacy setup data stamp not analysed at offset 0x600")


def test_t27_version_before_blocks() -> None:
    data = PI32[:0x600] + version_field(b"Inno Setup Setup Data (4.0.8)") + PI32[0x640:]
    info, notes, _ = _inno(data)
    assert info is not None
    assert info.version is not None
    assert info.version.version == (4, 0, 8, 0)
    assert info.blocks == ()
    assert notes == (NotAnalysed("inno blocks before 4.0.9 not analysed"), NOT_PARSED)


def test_t27_version_not_recognised() -> None:
    data = PI32[:0x600] + version_field(b"Inno Setup Setup Data") + PI32[0x640:]
    info, notes, _ = _inno(data)
    assert info is not None
    assert (info.version, info.blocks) == (None, ())
    assert notes[0] == NotAnalysed("inno setup data version not recognised at offset 0x600")


# t28-t29: block headers


def _header(stored: int) -> bytes:
    """A valid-CRC 9-byte flag-1 header for ``stored`` (no payload)."""
    body = struct.pack("<IB", stored, 1)
    return struct.pack("<I", zlib.crc32(body)) + body


def _block1(header: bytes, data: bytes = PI32) -> bytes:
    return data[:0x640] + header[:9] + data[0x649:]


def test_t28_block1_crc_mismatch() -> None:
    info, notes, _ = _inno(_block1(block(16, 1, crc=0)))
    assert info is not None
    assert len(info.blocks) == 1
    assert info.blocks[0].crc_ok is False
    assert notes == (NotAnalysed("inno block 1 header CRC mismatch at offset 0x640"), NOT_PARSED)


def test_t28_block1_unexpected_flag() -> None:
    info, notes, _ = _inno(_block1(block(16, 2)))
    assert info is not None
    assert info.blocks == ()
    assert notes[0] == NotAnalysed("inno block 1 compression flag 2 unexpected at offset 0x640")


def test_t28_block1_header_past_end() -> None:
    info, notes, _ = _inno(PI32[:0x645])
    assert info is not None
    assert info.blocks == ()
    assert notes[0] == NotAnalysed("inno block 1 header past end of file at offset 0x640")


@pytest.mark.parametrize("stored", [SIZE - 0x640 - 8, 0xFFFFFFFF])
def test_t28_block1_payload_past_end(stored: int) -> None:
    info, notes, _ = _inno(_block1(_header(stored)))
    assert info is not None
    assert info.blocks == ()
    assert notes[0] == NotAnalysed("inno block 1 payload past end of file at offset 0x640")


def test_t29_block2_crc_mismatch() -> None:
    info, notes, _ = _inno(patch(PI32, 0x659, "<I", 0))
    assert info is not None
    assert [b.crc_ok for b in info.blocks] == [True, False]
    assert notes == (NotAnalysed("inno block 2 header CRC mismatch at offset 0x659"), NOT_PARSED)


def test_t29_block2_header_past_end() -> None:
    info, notes, _ = _inno(PI32[:0x660])
    assert info is not None
    assert [b.index for b in info.blocks] == [1]
    assert notes[0] == NotAnalysed("inno block 2 header past end of file at offset 0x659")


def test_t29_block2_payload_past_end() -> None:
    info, notes, _ = _inno((PI32[:0x659] + _header(9) + bytes(8))[:0x66A])
    assert info is not None
    assert [b.index for b in info.blocks] == [1]
    assert notes[0] == NotAnalysed("inno block 2 payload past end of file at offset 0x659")


def test_t29_block2_ending_at_end_of_file_accepted() -> None:
    info, _, _ = _inno(PI32[:0x66A])
    assert info is not None
    assert [(b.index, b.crc_ok) for b in info.blocks] == [(1, True), (2, True)]


def test_t29_block2_on_garbage() -> None:
    info, notes, _ = _inno(_block1(_header(15)))
    assert info is not None
    assert info.blocks[0].stored_size == 15
    assert (info.blocks[1].offset, info.blocks[1].crc_ok) == (Address(0x658), False)
    assert notes[0] == NotAnalysed("inno block 2 header CRC mismatch at offset 0x658")


# t30: table notes


def test_t30_table_crc_note() -> None:
    _, notes, _ = _inno(_with_table(PI32, *TABLE_FIELDS, crc=0))
    assert notes == (NotAnalysed("inno loader table CRC mismatch at offset 0x460"), NOT_PARSED)


def test_t30_revision_note() -> None:
    _, notes, _ = _inno(_with_table(PI32, *_fields(rev=2)))
    assert notes == (NotAnalysed("inno loader revision 2 unexpected"), NOT_PARSED)


def test_t30_unknown_magic_note() -> None:
    table = offset_table(b"rDlPtS99\x87eVx", TABLE_FIELDS)
    info, notes, _ = _inno(PI32[:0x460] + table + PI32[0x48C:])
    assert info is not None
    assert info.offsets.loader_version is None
    assert notes == (
        NotAnalysed("inno loader magic unknown at offset 0x460; read as the 5.1.5 layout"),
        NOT_PARSED,
    )


def test_t30_chunk_overlay_without_table() -> None:
    data = _no_resources(PI32[:0x600]) + b"zlb\x1a" + bytes(12)
    pe, notes = _attached(MemorySource(data))
    assert pe.inno is None
    assert notes == (INNO_LIKE,)


def test_t30_no_route_no_hint() -> None:
    pe, notes = _attached(MemorySource(_no_resources(PI32[:0x600])))
    assert (pe.inno, notes) == (None, ())


# t31: the real sample's shape


def test_t31_real_shape() -> None:
    shape = real_shape()
    head = shape.read(0, 0x800)
    tail = shape.read(REAL_SIZE - REAL_CERT[1], REAL_CERT[1])
    tree = rsrc({10: {11111: {0: (0x60, 44)}}}, 0x2010)
    table = offset_table(MAGIC_515, (1, 0, 0, 0, 0, 0xD3E00, 0xD3E40))
    head = head[:0x610] + tree + head[0x610 + len(tree) : 0x670] + table + head[0x670 + 44 :]
    head = put(head, DIR2, "<II", 0x2010, 0x90)
    source = SparseSource(REAL_SIZE, head=head, tail=tail)
    pe, _ = _attached(source)
    before = len(source.calls)
    info, notes = inno_info(source, pe)
    assert info is not None
    assert info.offsets.route is InnoRoute.RESOURCE
    assert info.offsets.table_offset == Address(0x670)
    assert (info.version, info.blocks) == (None, ())
    assert info.data == InnoData(Address(0xD3E40), False)
    assert notes == (
        NotAnalysed("inno setup data version not recognised at offset 0xd3e00"),
        NOT_PARSED,
    )
    assert len(source.calls) - before <= 7


# t32: input changed


@pytest.mark.parametrize(("at", "cut"), [(0x400, 0x418), (0x460, 0x464)])
def test_t32_input_changed_propagates(at: int, cut: int) -> None:
    # 0x400: the one read of the resource tree; 0x460: the offset table magic.
    probe = MemorySource(PI32)
    PeParser().parse(probe, "formats.inspect")
    honest = next(i for i, (off, _) in enumerate(probe.calls) if off == at)
    source = ShrinkingSource(PI32, cut, honest_reads=honest)
    with pytest.raises(InputChanged):
        PeParser().parse(source, "formats.inspect")
