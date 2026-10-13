"""Slice 6b: file list join and decoded-data VO invariants, t71-t72."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from retool.formats.domain.decompress import Codec, DecodeFailure
from retool.formats.domain.inno import InnoDecodeStatus, InnoInfo
from retool.formats.domain.inno_files import InnoFile, join_files
from retool.formats.domain.inno_setup import (
    InnoFileEntry,
    InnoFileLocation,
    InnoHeader,
    parse_locations_643,
    parse_setup_643,
)
from retool.shared import ParseError
from tests.formats.inno_build import G7_BLOCK1, G7_BLOCK2
from tests.formats.test_inno_loader import PI32_INFO

ENTRIES = parse_setup_643(G7_BLOCK1).files
LOCATIONS = parse_locations_643(G7_BLOCK2, 2)
HEADER = parse_setup_643(G7_BLOCK1).header
OK1 = InnoDecodeStatus(1, Codec.LZMA1_RAW, True, None, 752, 149, 0)
OK2 = InnoDecodeStatus(2, Codec.LZMA1_RAW, True, None, 170, 107, 0)


def _entry(location: int) -> InnoFileEntry:
    return InnoFileEntry(0, b"a\0", b"b\0", location, 0, 0)


def test_t71_g7_join() -> None:
    files = join_files(ENTRIES, LOCATIONS)
    assert [(f.entry, f.location) for f in files] == list(zip(ENTRIES, LOCATIONS, strict=True))


def test_t71_no_location_and_shared() -> None:
    files = join_files((_entry(-1), _entry(0), _entry(0)), LOCATIONS)
    assert [f.location for f in files] == [None, LOCATIONS[0], LOCATIONS[0]]


@pytest.mark.parametrize("loc", [2, -2])
def test_t71_out_of_range(loc: int) -> None:
    with pytest.raises(ParseError, match=f"inno file 1 location {loc} out of range 2"):
        join_files((_entry(0), _entry(loc)), LOCATIONS)


@pytest.mark.parametrize(
    "make",
    [
        lambda: InnoFileEntry(-1, b"", b"", -1, 0, 0),
        lambda: InnoFileEntry(0, b"a", b"", -1, 0, 0),
        lambda: InnoFileEntry(0, b"", b"", 1 << 31, 0, 0),
        lambda: InnoFileEntry(0, b"", b"", -1, 1 << 32, 0),
        lambda: InnoFileEntry(0, b"", b"", -1, 0, 256),
        lambda: InnoFileLocation(-1, 0, bytes(32), 0, 0),
        lambda: InnoFileLocation(0, 1 << 64, bytes(32), 0, 0),
        lambda: InnoFileLocation(0, 0, bytes(31), 0, 0),
        lambda: InnoFileLocation(0, 0, bytes(32), -1, 0),
        lambda: InnoFileLocation(0, 0, bytes(32), 0, 256),
        lambda: InnoFile(_entry(-1), LOCATIONS[0]),
        lambda: InnoFile(_entry(0), None),
        lambda: InnoFile(_entry(1), LOCATIONS[0]),
        lambda: InnoHeader(b"", b"", b"", (0,) * 15, 3, bytes(6)),
        lambda: InnoHeader(b"", b"", b"", (0,) * 16, 256, bytes(6)),
        lambda: InnoHeader(b"", b"", b"", (0,) * 16, 3, bytes(8)),
        lambda: InnoHeader(b"a", b"", b"", (0,) * 16, 3, bytes(6)),
        lambda: InnoDecodeStatus(3, Codec.LZMA1_RAW, True, None, 0, 0, 0),
        lambda: InnoDecodeStatus(1, Codec.LZMA1_RAW, True, DecodeFailure.CRC, 0, None, None),
        lambda: InnoDecodeStatus(1, Codec.LZMA1_RAW, False, DecodeFailure.CRC, 0, 0, None),
        lambda: InnoDecodeStatus(1, Codec.LZMA1_RAW, True, None, 0, None, 0),
        lambda: InnoDecodeStatus(1, Codec.LZMA1_RAW, True, None, -1, 0, 0),
    ],
)
def test_t72_vo_invariants(make: Callable[[], object]) -> None:
    with pytest.raises(ParseError):
        make()


FAILED1 = InnoDecodeStatus(1, Codec.LZMA1_RAW, False, DecodeFailure.CRC, 0, None, None)


@pytest.mark.parametrize(
    "kw",
    [
        {"decode": (OK2,)},
        {"decode": (OK1, OK2, OK2)},
        {"header": HEADER},
        {"header": HEADER, "decode": (FAILED1,)},
        {"files": join_files(ENTRIES, LOCATIONS), "decode": (OK1, OK2)},
        {"header": HEADER, "files": join_files(ENTRIES, LOCATIONS), "decode": (OK1,)},
        {"header": HEADER, "files": join_files(ENTRIES[:1], LOCATIONS), "decode": (OK1, OK2)},
    ],
)
def test_t72_info_invariants(kw: dict[str, object]) -> None:
    with pytest.raises(ParseError, match="inno info inconsistent"):
        InnoInfo(PI32_INFO.offsets, PI32_INFO.version, PI32_INFO.blocks, PI32_INFO.data, **kw)  # type: ignore[arg-type]  # kw is a test table


def test_t72_info_valid() -> None:
    files = join_files(ENTRIES, LOCATIONS)
    info = InnoInfo(
        PI32_INFO.offsets,
        PI32_INFO.version,
        PI32_INFO.blocks,
        PI32_INFO.data,
        HEADER,
        files,
        (OK1, OK2),
    )
    assert info.files == files
