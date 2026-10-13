from __future__ import annotations

import struct

import pytest

from retool.formats.domain.pe import CertificateEntry, parse_pe
from retool.formats.domain.pe_certificates import parse_certificates
from retool.shared import Address, NotAnalysed, ParseError
from tests.formats.fakes import MemorySource
from tests.formats.pe_build import P64, PT64, dir_at, patch

DIR4 = dir_at(4)  # 0xe8
TRUNCATED_NOTE = NotAnalysed("pe certificates truncated at 16 entries")


def _with_table(entries: bytes, size: int, va: int = 0x600) -> bytes:
    data = patch(P64 + entries, DIR4, "<I", va)
    return patch(data, DIR4 + 4, "<I", size)


def _entry(length: int, padded: int | None = None) -> bytes:
    raw = struct.pack("<IHH", length, 0x200, 2)
    return raw.ljust(padded if padded is not None else 8, b"\0")


def _certificates(
    data: bytes,
) -> tuple[tuple[CertificateEntry, ...], tuple[NotAnalysed, ...]]:
    source = MemorySource(data)
    return parse_certificates(source, parse_pe(source))


def _calls(data: bytes) -> list[tuple[int, int]]:
    source = MemorySource(data)
    pe = parse_pe(source)
    before = len(source.calls)
    parse_certificates(source, pe)
    return source.calls[before:]


def _fails(data: bytes, reason: str, offset: int) -> None:
    with pytest.raises(ParseError) as err:
        _certificates(data)
    assert (err.value.reason, err.value.offset) == (reason, offset)


# 28: presence


def test_pt64_certificate() -> None:
    assert _certificates(PT64) == ((CertificateEntry(Address(0x20600), 12, 0x200, 2),), ())


@pytest.mark.parametrize(
    "data",
    [P64, _with_table(_entry(8), 0), _with_table(_entry(8), 16, va=0)],
    ids=["p64", "size-0", "va-0"],
)
def test_no_certificate_table(data: bytes) -> None:
    assert _certificates(data) == ((), ())
    assert _calls(data) == []


# 29: 8-byte rounding


def test_entries_rounded_to_eight() -> None:
    entries, notes = _certificates(_with_table(_entry(9, 16) + _entry(8), 24))
    assert [e.offset for e in entries] == [Address(0x600), Address(0x610)]
    assert [e.length for e in entries] == [9, 8]
    assert notes == ()


def test_rounded_sum_differs_from_size() -> None:
    # Spec test 29 says Size 17 -> C7; by C3-C6 Size 17 leaves 1 byte for a second header (C4).
    _fails(_with_table(_entry(9, 16) + _entry(8), 17), "certificate header exceeds table", 0x610)
    _fails(
        _with_table(_entry(9, 16) + _entry(8), 12),
        "certificate lengths do not sum to table size",
        DIR4,
    )


# 30: rejections


@pytest.mark.parametrize(
    ("va", "size"),
    [(0x600, 0x11), (0xFFFFFFFF, 0xFFFFFFFF)],
    ids=["one-past", "max"],
)
def test_table_exceeds_file(va: int, size: int) -> None:
    _fails(_with_table(_entry(16, 16), size, va=va), "certificate table exceeds file", DIR4)


def test_header_exceeds_table() -> None:
    _fails(_with_table(_entry(8), 4), "certificate header exceeds table", 0x600)


@pytest.mark.parametrize("length", [7, 0])
def test_length_below_header(length: int) -> None:
    _fails(_with_table(_entry(length), 8), "certificate length below header size", 0x600)


def test_entry_exceeds_table() -> None:
    _fails(_with_table(_entry(0xFFFFFFFF), 8), "certificate entry exceeds table", 0x600)


def test_second_entry_fails_at_its_offset() -> None:
    _fails(_with_table(_entry(8) + _entry(7), 16), "certificate length below header size", 0x608)


# 31: cap


def test_certificate_cap() -> None:
    entries, notes = _certificates(_with_table(_entry(8) * 17, 136))
    assert len(entries) == 16
    assert notes == (TRUNCATED_NOTE,)


def test_certificate_cap_boundary() -> None:
    entries, notes = _certificates(_with_table(_entry(8) * 16, 128))
    assert len(entries) == 16
    assert notes == ()
