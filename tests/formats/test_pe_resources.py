from __future__ import annotations

import struct

import pytest

from retool.formats.domain.pe import parse_pe
from retool.formats.domain.pe_parser import attach_tables
from retool.formats.domain.pe_resources import (
    MAX_RESOURCE_ENTRIES,
    MAX_RESOURCE_READ,
    MAX_RESOURCE_TOTAL,
    ResourceEntry,
    ResourceSummary,
    find_resource,
    parse_resources,
)
from retool.shared import Address, ByteRange, NotAnalysed, ParseError
from tests.formats.fakes import MemorySource, SparseSource
from tests.formats.inno_build import PI32, put, rsrc
from tests.formats.pe_build import dir_at, patch

# Single-leaf layout: root 0x00, name dir 0x18, language dir 0x30, data entry 0x48.
LEAF = rsrc({10: {11111: {0: (0x60, 44)}}}, 0x2000)
INNO_LIKE = "inno-like overlay without a loader offset table"


def _parse(blob: bytes) -> ResourceSummary:
    return parse_resources(MemorySource(blob), ByteRange(0, len(blob)))


def _reject(blob: bytes) -> str:
    with pytest.raises(ParseError) as err:
        _parse(blob)
    return str(err.value)


def test_t01_single_leaf() -> None:
    summary = _parse(LEAF)
    assert summary == ResourceSummary(
        Address(0),
        len(LEAF),
        (ResourceEntry(10, 11111, 0, 0x2060, 44, 0, Address(0x48)),),
    )


def test_t01_root_offset_is_a_file_offset() -> None:
    blob = bytes(0x100) + LEAF
    summary = parse_resources(MemorySource(blob), ByteRange(0x100, len(LEAF)))
    assert summary.offset == Address(0x100)
    assert summary.entries[0].entry_offset == Address(0x148)


def test_t02_named_and_id_types_in_table_order() -> None:
    tree = {3: {5: {0x409: (0x20, 8)}, "": {0: (0x30, 2)}}, "MYTYPE": {1: {0: (0x10, 4)}}}
    keys = [(e.type, e.name, e.lang) for e in _parse(rsrc(tree)).entries]
    assert keys == [
        ("MYTYPE".encode("utf-16-le"), 1, 0),
        (3, b"", 0),
        (3, 5, 0x409),
    ]


def test_t03_find_resource_first_language_wins() -> None:
    summary = _parse(rsrc({10: {7: {0x409: (0, 1), 0x407: (0, 2)}}, 11: {7: {0: (0, 3)}}}))
    found = find_resource(summary, 10, 7)
    assert found is not None
    assert (found.lang, found.size) == (0x409, 1)
    assert find_resource(summary, 10, 8) is None
    assert find_resource(summary, 12, 7) is None


def test_t03_named_entry_never_matches_an_int() -> None:
    named = ResourceEntry(b"\x0a\x00", b"\x07\x00", 0, 0, 1, 0, Address(0))
    summary = ResourceSummary(Address(0), 16, (named,))
    assert find_resource(summary, 10, 7) is None


def test_t04_level_three_directory_rejected() -> None:
    blob = patch(LEAF, 0x44, "<I", 0x80000000)  # language entry -> root as a directory
    assert _reject(blob) == "resource tree not three levels at offset 0x40"


def test_t05_revisited_directory_rejected() -> None:
    blob = patch(LEAF, 0x2C, "<I", 0x80000000)  # name entry -> root
    assert _reject(blob) == "resource directory revisited at offset 0x0"


def test_t06_level_one_data_entry_rejected() -> None:
    blob = patch(LEAF, 0x14, "<I", 0x48)
    assert _reject(blob) == "resource tree not three levels at offset 0x10"


def test_t07_directory_too_large() -> None:
    blob = put(LEAF, 12, "<HH", 0xFFFF, 0xFFFF)
    assert _reject(blob) == "resource directory too large at offset 0x0"


def test_t07_entries_past_directory_rejected_not_clamped() -> None:
    blob = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 3) + bytes(16)
    assert _reject(blob) == "resource entries past directory at offset 0x0"


def _wide_tree(names2: int) -> tuple[bytes, int]:
    """Root with 2 types: 4096 names under type 1, ``names2`` under type 2; one language
    directory per name, all sharing one data entry. Returns the blob and the language base."""
    t1 = 32
    t2 = t1 + 16 + 8 * MAX_RESOURCE_ENTRIES
    lang = t2 + 16 + 8 * names2
    data = lang + 24 * (MAX_RESOURCE_ENTRIES + names2)
    out = bytearray(struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 2))
    out += struct.pack("<IIII", 1, 0x80000000 | t1, 2, 0x80000000 | t2)
    k = 0
    for count in (MAX_RESOURCE_ENTRIES, names2):
        out += struct.pack("<IIHHHH", 0, 0, 0, 0, 0, count)
        for i in range(count):
            out += struct.pack("<II", i, 0x80000000 | (lang + 24 * (k + i)))
        k += count
    for _ in range(k):
        out += struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1) + struct.pack("<II", 0, data)
    out += struct.pack("<IIII", 0x1000, 4, 0, 0)
    return bytes(out), lang


def test_t08_total_at_cap_accepted() -> None:
    blob, _ = _wide_tree(MAX_RESOURCE_ENTRIES - 2)  # 2 + 4096 + 4096 + 4094 + 4094 = 16382
    summary = _parse(blob)
    assert len(summary.entries) == MAX_RESOURCE_ENTRIES * 2 - 2


def test_t08_tree_too_large_at_the_directory_that_crosses() -> None:
    # Totals: root 2, type 1 4098, its languages 8194, type 2 12290; type 2's 4095th
    # language directory makes 16385.
    blob, lang = _wide_tree(MAX_RESOURCE_ENTRIES)
    crossing = lang + 24 * (MAX_RESOURCE_ENTRIES + 4094)
    assert MAX_RESOURCE_TOTAL + 1 == 12290 + 4095
    assert _reject(blob) == f"resource tree too large at offset {crossing:#x}"


# Named-type layout: root 0x00, name dir 0x18, language dir 0x30, string 0x48, data 0x4E.
NAMED = rsrc({"AB": {1: {0: (0, 4)}}})


def test_t09_string_past_end() -> None:
    blob = patch(NAMED, 0x10, "<I", 0x80000000 | (len(NAMED) - 1))
    assert _reject(blob) == f"resource name past end of tree at offset {len(NAMED) - 1:#x}"


def test_t09_string_too_long() -> None:
    assert _parse(NAMED).entries[0].type == "AB".encode("utf-16-le")
    assert _reject(patch(NAMED, 0x48, "<H", 65)) == "resource name too long at offset 0x48"


def test_t10_data_entry_past_end() -> None:
    blob = patch(LEAF, 0x44, "<I", len(LEAF) - 8)
    reason = f"resource data entry past end of tree at offset {len(LEAF) - 8:#x}"
    assert _reject(blob) == reason


def test_t10_directory_size_bounds_the_tree() -> None:
    data = patch(PI32, dir_at(2, 32) + 4, "<I", 0x20)
    source = MemorySource(data)
    attached, notes = attach_tables(source, parse_pe(source))
    assert attached.resources is None
    assert notes == (
        NotAnalysed("pe resources not parsed: resource directory past end of tree at offset 0x418"),
        NotAnalysed(INNO_LIKE),
    )


def test_t11_unmapped_directory_note_and_pointer_route_runs() -> None:
    data = patch(PI32, dir_at(2, 32), "<I", 0x9000)
    data = put(data, 0x30, "<III", 0x6F6E6E49, 0x460, 0x460 ^ 0xFFFFFFFF)
    source = MemorySource(data)
    attached, notes = attach_tables(source, parse_pe(source))
    assert attached.resources is None
    assert notes[0] == NotAnalysed(
        "pe resources not parsed: resource directory not file-backed at offset 0xc8"
    )
    assert attached.inno is not None
    assert attached.inno.offsets.route == "pointer"


def test_t10_tree_read_once() -> None:
    source = MemorySource(PI32)
    pe = parse_pe(source)
    before = len(source.calls)
    attach_tables(source, pe)
    reads = source.calls[before:]
    assert [r for r in reads if 0x400 <= r[0] < 0x490] == [(0x400, 0x90), (0x460, 12), (0x46C, 32)]


def test_t10_structure_past_read_window() -> None:
    far = MAX_RESOURCE_READ + 0x10
    head = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1) + struct.pack("<II", 10, 0x80000000 | far)
    source = SparseSource(MAX_RESOURCE_READ + 0x100, head=head)
    with pytest.raises(ParseError) as err:
        parse_resources(source, ByteRange(0, source.size))
    assert str(err.value) == f"resource structure past the read window at offset {far:#x}"
    assert source.calls == [(0, MAX_RESOURCE_READ)]
