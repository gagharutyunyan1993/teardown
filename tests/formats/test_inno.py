from __future__ import annotations

import struct

import pytest

from retool.formats.domain.inno import (
    InnoBlockHeader,
    InnoCompression,
    InnoData,
    InnoInfo,
    InnoOffsets,
    InnoRoute,
    InnoVersion,
    _TableLayout,
    is_legacy_stamp,
    offset_table_size,
    parse_block_header,
    parse_offset_table,
    parse_version_field,
)
from retool.shared import Address, ParseError
from tests.formats.inno_build import MAGIC_515, block, offset_table, version_field

# Rows of the spec's offset table layout: magic, loader version, fields in order.
LAYOUTS = [
    (b"rDlPtS02\x87eVx", (1, 2, 10, 0), "U EO EC EU CK MO HO DO"),
    (b"rDlPtS04\x87eVx", (4, 0, 0, 0), "U EO EC EU CK HO DO"),
    (b"rDlPtS05\x87eVx", (4, 0, 3, 0), "U EO EC EU CK HO DO"),
    (b"rDlPtS06\x87eVx", (4, 0, 10, 0), "U EO EC EU CK HO DO T"),
    (b"rDlPtS07\x87eVx", (4, 1, 6, 0), "U EO EU CK HO DO T"),
    (MAGIC_515, (5, 1, 5, 0), "R U EO EU CK HO DO T"),
    (b"nS5W7dT\x83\xaa\x1b\x0fj", (5, 1, 5, 0), "R U EO EU CK HO DO T"),
]


def _table(magic: bytes, names: list[str]) -> tuple[bytes, dict[str, int]]:
    values = {n: 0x100 + i for i, n in enumerate(names)}
    return offset_table(magic, tuple(values.values())), values


@pytest.mark.parametrize(("magic", "version", "layout"), LAYOUTS)
def test_t12_offset_table_layouts(
    magic: bytes, version: tuple[int, int, int, int], layout: str
) -> None:
    names = [n for n in layout.split() if n != "T"]
    raw, v = _table(magic, names)
    assert len(raw) == offset_table_size(magic) == 12 + 4 * len(layout.split())
    offsets = parse_offset_table(raw, InnoRoute.RESOURCE, 0x460)
    assert offsets == InnoOffsets(
        InnoRoute.RESOURCE,
        Address(0x460),
        len(raw),
        version,
        v.get("R"),
        Address(v["EO"]),
        v.get("EC"),
        v["EU"],
        v["CK"],
        Address(v["MO"]) if "MO" in v else None,
        Address(v["HO"]),
        Address(v["DO"]),
        True if "T" in layout else None,
    )


def test_t13_table_crc_mismatch() -> None:
    raw = offset_table(MAGIC_515, (1, 0, 0x11, 0x22, 0x33, 0x600, 0x66A), crc=0x85B3797C)
    assert parse_offset_table(raw, InnoRoute.POINTER, 0).crc_ok is False
    good = offset_table(MAGIC_515, (1, 0, 0x11, 0x22, 0x33, 0x600, 0x66A))
    assert good[-4:] == struct.pack("<I", 0x85B3797D)
    assert parse_offset_table(good, InnoRoute.POINTER, 0).crc_ok is True


def test_t14_unknown_magic_reads_as_newest() -> None:
    magic = b"rDlPtS99\x87eVx"
    assert offset_table_size(magic) == 44
    raw = offset_table(magic, (2, 0, 0x11, 0x22, 0x33, 0x600, 0x66A))
    offsets = parse_offset_table(raw, InnoRoute.RESOURCE, 0x10)
    assert offsets.loader_version is None
    assert (offsets.revision, offsets.exe_offset, offsets.header_offset) == (
        2,
        Address(0x11),
        Address(0x600),
    )
    assert offsets.exe_compressed_size is None
    assert offsets.crc_ok is True


def test_t14_layout_with_wrong_size_raises() -> None:
    with pytest.raises(ParseError, match="layout size inconsistent"):
        _TableLayout((5, 1, 5, 0), 40, True, False, False, True)


@pytest.mark.parametrize(
    ("text", "version", "unicode", "known"),
    [
        (b"Inno Setup Setup Data (6.4.0.1)", (6, 4, 0, 1), True, True),
        (b"Inno Setup Setup Data (5.5.7) (u)", (5, 5, 7, 0), True, True),
        (b"Inno Setup Setup Data (5.5.7) (U)", (5, 5, 7, 0), True, False),
        (b"Inno Setup Setup Data (9.9.9)", (9, 9, 9, 0), True, False),
        (b"Inno Setup Setup Data (5.1.0)", (5, 1, 0, 0), False, False),
        (b"Inno Setup Setup Data (5.1.0) (5.2.3a)", (5, 2, 3, 0), False, False),
        (b"Inno Setup Setup Data (256.0.0) (5.1.0)", (5, 1, 0, 0), False, False),
    ],
)
def test_t15_version_field(
    text: bytes, version: tuple[int, int, int, int], unicode: bool, known: bool
) -> None:
    assert parse_version_field(version_field(text)) == InnoVersion(text, version, unicode, known)


def test_t16_legacy_stamp() -> None:
    assert is_legacy_stamp(b"i1.2.10--16\x1a")
    assert not is_legacy_stamp(b"Inno Setup S")


@pytest.mark.parametrize(
    "text", [b"My Setup Data (6.4.0)", b"Inno Setup Setup Data", b"Inno Setup Setup Data (x)"]
)
def test_t16_version_not_recognised(text: bytes) -> None:
    assert parse_version_field(version_field(text)) is None


def test_t16_field_without_nul_is_all_raw() -> None:
    field = (b"Inno Setup Setup Data (6.4.0) " + b"\xff" * 64)[:64]
    parsed = parse_version_field(field)
    assert parsed is not None
    assert parsed.raw == field
    assert parsed.known is False


def test_t17_block_header_crc() -> None:
    ok = parse_block_header(block(16, 1)[:9], 0x640, 1, (6, 4, 0, 1))
    assert ok == InnoBlockHeader(1, Address(0x640), 0xD1C55009, 16, 1, InnoCompression.LZMA1, True)
    bad = parse_block_header(block(16, 1, crc=0)[:9], 0x640, 1, (6, 4, 0, 1))
    assert bad.crc_ok is False


def test_t17_unexpected_flag_raises() -> None:
    with pytest.raises(ParseError) as err:
        parse_block_header(block(0, 2)[:9], 0x640, 1, (6, 4, 0, 1))
    assert str(err.value) == "inno block 1 compression flag 2 unexpected at offset 0x640"


@pytest.mark.parametrize(
    ("flag", "version", "compression"),
    [
        (0, (6, 4, 0, 1), InnoCompression.STORED),
        (1, (4, 0, 9, 0), InnoCompression.ZLIB),
        (1, (4, 1, 5, 0), InnoCompression.ZLIB),
        (1, (4, 1, 6, 0), InnoCompression.LZMA1),
    ],
)
def test_t17_compression(
    flag: int, version: tuple[int, int, int, int], compression: InnoCompression
) -> None:
    assert parse_block_header(block(4, flag)[:9], 0, 2, version).compression is compression


OFFSETS = InnoOffsets(
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
)
VERSION = InnoVersion(b"Inno Setup Setup Data (6.4.0.1)", (6, 4, 0, 1), True, True)
B1 = InnoBlockHeader(1, Address(0x640), 0, 16, 1, InnoCompression.LZMA1, True)
B2 = InnoBlockHeader(2, Address(0x659), 0, 8, 1, InnoCompression.LZMA1, True)


def test_t18_offsets_invariants() -> None:
    with pytest.raises(ParseError):  # 5.1.5 table without a revision
        InnoOffsets(
            InnoRoute.RESOURCE, Address(0), 44, (5, 1, 5, 0), None, Address(0), None, 0, 0,
            None, Address(0), Address(0), True,
        )  # fmt: skip
    with pytest.raises(ParseError):  # 4.0.3 table with a CRC result
        InnoOffsets(
            InnoRoute.RESOURCE, Address(0), 40, (4, 0, 3, 0), None, Address(0), 0, 0, 0,
            None, Address(0), Address(0), True,
        )  # fmt: skip
    with pytest.raises(ParseError):  # 5.1.5 table with the 4.1.6 size
        InnoOffsets(
            InnoRoute.RESOURCE, Address(0), 40, (5, 1, 5, 0), 1, Address(0), None, 0, 0,
            None, Address(0), Address(0), True,
        )  # fmt: skip
    with pytest.raises(ParseError):  # u32 overflow
        InnoOffsets(
            InnoRoute.RESOURCE, Address(0), 44, None, 1, Address(2**32), None, 0, 0,
            None, Address(0), Address(0), True,
        )  # fmt: skip


def test_t18_block_invariants() -> None:
    with pytest.raises(ParseError):
        InnoBlockHeader(1, Address(0), 0, 0, 1, InnoCompression.STORED, True)
    with pytest.raises(ParseError):
        InnoBlockHeader(1, Address(0), 0, 0, 0, InnoCompression.ZLIB, True)
    with pytest.raises(ParseError):
        InnoBlockHeader(3, Address(0), 0, 0, 0, InnoCompression.STORED, True)


def test_t18_info_invariants() -> None:
    data = InnoData(Address(0x66A), True)
    assert InnoInfo(OFFSETS, VERSION, (B1, B2), data).blocks == (B1, B2)
    with pytest.raises(ParseError):
        InnoInfo(OFFSETS, VERSION, (B1, B2, B2), data)
    with pytest.raises(ParseError):
        InnoInfo(OFFSETS, VERSION, (B2,), data)
    with pytest.raises(ParseError):
        InnoInfo(OFFSETS, None, (B1,), data)
    old = InnoVersion(b"Inno Setup Setup Data (4.0.8)", (4, 0, 8, 0), False, False)
    with pytest.raises(ParseError):
        InnoInfo(OFFSETS, old, (B1,), data)


def test_t18_version_and_address_invariants() -> None:
    with pytest.raises(ParseError):
        InnoVersion(b"Inno\0Setup", (6, 4, 0, 1), True, False)
    with pytest.raises(ParseError):
        InnoVersion(b"", (6, 4, 0, 1), True, False)
    with pytest.raises(ParseError):
        InnoVersion(b"x", (256, 0, 0, 0), True, False)
    with pytest.raises(ParseError):
        InnoData(Address(-1), True)
