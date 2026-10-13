"""Slice 6b: Inno Setup 6.4.3 setup header, entry lists and file locations, t61-t69, t85."""

from __future__ import annotations

import hashlib
import struct

import pytest

from retool.formats.domain import inno_setup
from retool.formats.domain.inno_setup import (
    COUNT_NAMES,
    HEADER_FIELDS,
    LISTS_643,
    MAX_INNO_ENTRIES,
    SETUP_HEADER_643,
    Cursor,
    InnoCompressMethod,
    InnoFileLocation,
    InnoFileType,
    RecordSpec,
    parse_locations_643,
    parse_setup_643,
)
from retool.shared import ParseError
from tests.formats.inno_build import (
    G7_BLOCK1,
    G7_BLOCK2,
    file_entry,
    generic_record,
    inno_string,
    language_entry,
    location_entry,
    setup_header,
)

ZERO = (0,) * 16
WIZ = struct.pack("<ii", 0, 0)


def _counts(**kw: int) -> tuple[int, ...]:
    return tuple(kw.get(name, 0) for name in COUNT_NAMES)


def _rejects(data: bytes, text: str) -> ParseError:
    with pytest.raises(ParseError) as info:
        parse_setup_643(data)
    assert text in str(info.value)
    assert info.value.offset is None
    return info.value


# t61-t62: Cursor


@pytest.mark.parametrize(
    "make",
    [
        lambda: Cursor(b"abc", label="block1").read_fixed(4),
        lambda: Cursor(b"abcd", label="block1", start=3, limit=2),
        lambda: Cursor(b"abcd", label="block1", limit=5),
        lambda: Cursor(b"abcdefg", label="block1", start=4).read_i32(),
        lambda: Cursor(b"abcdefgh", label="block1", limit=6).read_fixed(7),
    ],
)
def test_t61_cursor_bounds(make: object) -> None:
    assert callable(make)
    with pytest.raises(ParseError) as info:
        make()
    assert "decoded offset 0x" in str(info.value)
    assert info.value.offset is None


def test_t61_cursor_reads() -> None:
    cur = Cursor(b"\x01\x00\x00\x00ab", label="block1")
    assert cur.read_fixed(0) == b""
    assert (cur.read_i32(), cur.pos, cur.remaining) == (1, 4, 2)


@pytest.mark.parametrize(
    ("raw", "text"),
    [
        (struct.pack("<i", -1), "string length -1 negative"),
        (struct.pack("<i", 7) + bytes(7), "string length 7 odd"),
        (struct.pack("<i", 8) + bytes(6), "string length 8 past end"),
    ],
)
def test_t62_string_errors(raw: bytes, text: str) -> None:
    with pytest.raises(ParseError, match=text):
        Cursor(raw, label="block1").read_string()


def test_t62_string_too_large(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(inno_setup, "MAX_INNO_STRING", 8)
    with pytest.raises(ParseError, match="string length 10 too large at decoded offset 0x0"):
        Cursor(struct.pack("<i", 10) + bytes(10), label="block1").read_string()


def test_t62_string_values() -> None:
    assert Cursor(struct.pack("<i", 0), label="block1").read_string() == b""
    assert Cursor(inno_string("hi"), label="block1").read_string() == "hi".encode("utf-16-le")
    assert Cursor(struct.pack("<i", 3) + b"abc", label="block1").read_ansi() == b"abc"
    with pytest.raises(ParseError, match="string length -1 negative"):
        Cursor(struct.pack("<i", -1), label="block1").read_ansi()


# t63-t64: G7 block 1 and the header layout


def test_t63_g7_block1() -> None:
    block = parse_setup_643(G7_BLOCK1)
    h = block.header
    assert (h.app_name, h.app_version, h.app_publisher) == tuple(
        t.encode("utf-16-le") for t in ("Demo App", "1.2.3", "Retool Tests")
    )
    assert h.counts == (1, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0)
    assert (h.num_files, h.num_locations) == (2, 2)
    assert (h.compress_method, h.compress_name, h.options) == (3, InnoCompressMethod.LZMA, bytes(6))
    f0, f1 = block.files
    assert (f0.decoded_offset, f1.decoded_offset) == (450, 591)
    assert (f0.source, f0.dest, f0.location) == (
        "C:\\build\\app.exe".encode("utf-16-le"),
        "{app}\\app.exe".encode("utf-16-le"),
        0,
    )
    assert (f1.source, f1.dest, f1.location) == (
        "C:\\build\\readme.txt".encode("utf-16-le"),
        "{app}\\readme.txt".encode("utf-16-le"),
        1,
    )
    assert (f0.options, f0.file_type, f0.file_type_name) == (0, 0, InnoFileType.USER_FILE)


def test_t64_header_fields() -> None:
    at = 0
    for _, offset, size in HEADER_FIELDS:
        assert offset == at
        at += size
    assert at == 177 == SETUP_HEADER_643.fixed
    assert sum(size for _, _, size in HEADER_FIELDS) == 177
    rows = {name: (offset, size) for name, offset, size in HEADER_FIELDS}
    assert rows["counts"] == (0, 64)
    assert rows["compress_method"] == (160, 1)
    assert rows["options"] == (171, 6)
    assert (SETUP_HEADER_643.strings, SETUP_HEADER_643.ansi) == (33, 4)
    assert len(COUNT_NAMES) == 16
    assert [s.name for s in LISTS_643] == [n for n in COUNT_NAMES if n != "file_location"]
    assert SETUP_HEADER_643.count_index is None
    assert all(
        s.count_index is not None and COUNT_NAMES[s.count_index] == s.name for s in LISTS_643
    )
    shapes = {s.name: (s.strings, s.ansi, s.fixed) for s in LISTS_643}
    assert shapes == {
        "language": (6, 4, 21),
        "custom_message": (2, 0, 4),
        "permission": (0, 1, 0),
        "type": (4, 0, 30),
        "component": (5, 0, 42),
        "task": (6, 0, 26),
        "dir": (7, 0, 27),
        "file": (10, 0, 43),
        "icon": (13, 0, 48),
        "ini": (10, 0, 21),
        "registry": (9, 0, 29),
        "install_delete": (7, 0, 21),
        "uninstall_delete": (7, 0, 21),
        "run": (13, 0, 27),
        "uninstall_run": (13, 0, 27),
    }
    file_spec = LISTS_643[7]
    assert (file_spec.strings, file_spec.ansi, file_spec.fixed) == (10, 0, 43)


# t65-t66: counts and exact end


@pytest.mark.parametrize("count", [MAX_INNO_ENTRIES + 1, -1])
def test_t65_count_out_of_range(count: int) -> None:
    _rejects(setup_header(_counts(file=count)) + WIZ, f"inno file count {count} out of range")


def test_t65_total_too_large() -> None:
    counts = _counts(type=60_000, component=60_000, task=60_000, dir=60_000, icon=60_000)
    _rejects(setup_header(counts) + WIZ, "inno entry total 300000 too large")


def test_t65_list_past_end() -> None:
    data = setup_header(_counts(file=2)) + file_entry("a", "b", -1) + WIZ
    _rejects(data, "inno file list past end at decoded offset 0x145")


def test_t65_record_truncated() -> None:
    data = setup_header(_counts(file=2)) + file_entry("a", "b", -1) + file_entry("", "", -1)[:60]
    _rejects(data + bytes(30), "record truncated at decoded offset")


def test_t66_trailing_byte() -> None:
    _rejects(G7_BLOCK1 + b"\0", "inno block1 has 1 trailing bytes")


def test_t66_set_size_sensitivity() -> None:
    counts = (1, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0)
    head = setup_header(counts, app_name="Demo App", fixed_size=179)
    rest = G7_BLOCK1[len(setup_header(counts, app_name="Demo App")) :]
    _rejects(head + rest, "inno block1 string length 50331648 too large at decoded offset 0x165")


# t67: unknown ids (D1)


def test_t67_unknown_compress_method() -> None:
    block = parse_setup_643(setup_header(ZERO, compress=5) + WIZ)
    assert (block.header.compress_method, block.header.compress_name) == (5, None)


def test_t67_unknown_file_type() -> None:
    data = setup_header(_counts(file=1)) + file_entry("a", "b", -1, file_type=2) + WIZ
    (entry,) = parse_setup_643(data).files
    assert (entry.file_type, entry.file_type_name) == (2, None)


def test_t67_unknown_location_flags() -> None:
    (loc,) = parse_locations_643(location_entry(1, bytes(32), 0, 0xF2), 1)
    assert loc.flags == 0xF2
    assert (loc.timestamp_utc, loc.chunk_compressed) == (True, True)
    assert (loc.version_info_valid, loc.call_instruction_optimized, loc.chunk_encrypted) == (
        False,
        False,
        False,
    )


# t68: wizard images and decompressor DLL


@pytest.mark.parametrize(
    ("tail", "text"),
    [
        (struct.pack("<i", 65), "inno wizard image count 65 out of range"),
        (struct.pack("<ii", 1, -1), "inno wizard image size -1 invalid"),
        (struct.pack("<ii", 1, 9) + bytes(8), "inno wizard image size 9 invalid"),
    ],
)
def test_t68_wizard_images(tail: bytes, text: str) -> None:
    _rejects(setup_header(ZERO) + tail, text)


def test_t68_dll_exact_end() -> None:
    data = setup_header(ZERO, compress=1) + WIZ + struct.pack("<i", 3) + b"dll"
    assert parse_setup_643(data).header.compress_name is InnoCompressMethod.ZIP


@pytest.mark.parametrize(
    ("tail", "text"),
    [(struct.pack("<i", -1), "inno decompressor size -1 invalid"), (b"", "record truncated")],
)
def test_t68_dll_errors(tail: bytes, text: str) -> None:
    _rejects(setup_header(ZERO, compress=1) + WIZ + tail, text)


# t69: block 2


def test_t69_g7_locations() -> None:
    a, b = parse_locations_643(G7_BLOCK2, 2)
    assert a == InnoFileLocation(0, 1024, hashlib.sha256(b"app").digest(), 132000000000000000, 0x12)
    assert b == InnoFileLocation(1, 5, hashlib.sha256(b"hello").digest(), 0, 0x10)


def test_t69_block2_size() -> None:
    with pytest.raises(ParseError, match="inno block2 size 169 is not 2 x 85"):
        parse_locations_643(G7_BLOCK2[:169], 2)


# t85: every list, both wizard image lists, a DLL


def test_t85_every_list() -> None:
    counts = [0] * 16
    for spec in LISTS_643:
        assert spec.count_index is not None
        counts[spec.count_index] = 2
    data = bytearray(setup_header(counts, compress=2))
    file_offsets: list[int] = []
    for spec in LISTS_643:
        for seed in range(2):
            if spec.name == "file":
                file_offsets.append(len(data))
                data += file_entry(f"src{seed}", f"dst{seed}", -1)
            else:
                data += generic_record(spec, seed)
    images = struct.pack("<ii", 2, 3) + b"img" + struct.pack("<i", 0)
    data += images + images + struct.pack("<i", 5) + b"12345"
    block = parse_setup_643(bytes(data))
    assert block.header.counts == tuple(counts)
    assert block.header.compress_name is InnoCompressMethod.BZIP
    assert [f.decoded_offset for f in block.files] == file_offsets
    assert [f.dest for f in block.files] == [f"dst{i}".encode("utf-16-le") for i in range(2)]


def test_language_entry_size() -> None:
    assert len(language_entry()) == 75


def test_record_spec_none_is_not_a_list(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ParseError):
        RecordSpec("x", -1, 0, 0, 0)
    monkeypatch.setattr(inno_setup, "LISTS_643", (SETUP_HEADER_643,))
    with pytest.raises(ParseError, match="inno record spec setup_header is not a list"):
        parse_setup_643(setup_header(ZERO) + WIZ)
