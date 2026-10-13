from __future__ import annotations

import struct
from dataclasses import replace

import pytest

from retool.formats.domain.model import InputChanged
from retool.formats.domain.pe import (
    MAX_IMPORT_DLLS,
    MAX_IMPORT_FUNCS,
    MAX_IMPORT_READ_BYTES,
    CertificateEntry,
    ImportedDll,
    ImportedFunction,
    OverlayInfo,
    PeFile,
    ThunkEnd,
    parse_pe,
)
from retool.formats.domain.pe_image import pe_image, rva_to_file
from retool.formats.domain.pe_imports import parse_imports
from retool.formats.domain.pe_parser import PeParser
from retool.shared import (
    Address,
    AddressSpace,
    ByteRange,
    NotAnalysed,
    ParseError,
    SpaceAddress,
)
from tests.formats.fakes import MemorySource, ShrinkingSource
from tests.formats.pe_build import P64, PT32, PT64, big_data, build_pe, dir_at, patch, rva

PRODUCER = "formats.inspect"
TRUNCATED_NOTE = NotAnalysed(f"pe imports truncated at {MAX_IMPORT_DLLS} DLLs")

KERNEL32 = ImportedDll(
    Address(0x400),
    0x2040,
    0,
    0,
    0x20C0,
    0x2080,
    b"KERNEL32.dll",
    False,
    (ImportedFunction(None, 0x123, b"ExitProcess"), ImportedFunction(16, None, None)),
    ThunkEnd.NULL,
)
USER32 = ImportedDll(
    Address(0x414),
    0,
    0,
    0,
    0x20D0,
    0x20A0,
    b"USER32.dll",
    False,
    (ImportedFunction(None, 2, b"MessageBoxA"),),
    ThunkEnd.NULL,
)


def _imports(data: bytes) -> tuple[tuple[ImportedDll, ...], tuple[NotAnalysed, ...]]:
    source = MemorySource(data)
    return parse_imports(source, parse_pe(source))


def _calls(data: bytes) -> list[tuple[int, int]]:
    """Reads of parse_imports after parse_pe's."""
    source = MemorySource(data)
    pe = parse_pe(source)
    before = len(source.calls)
    parse_imports(source, pe)
    return source.calls[before:]


def _u32(data: bytes, *patches: tuple[int, int]) -> bytes:
    for off, value in patches:
        data = patch(data, off, "<I", value)
    return data


def _u64(data: bytes, off: int, value: int) -> bytes:
    return patch(data, off, "<Q", value)


def _write(data: bytes, off: int, raw: bytes) -> bytes:
    return data[:off] + raw + data[off + len(raw) :]


def _l7(n: int) -> bytes:
    """L7: n descriptors at 0x400 sharing name b"a.dll" (0x5240) and a null IAT (0x5250)."""
    buf = bytearray(big_data(0x5000))
    for i in range(n):
        struct.pack_into("<5I", buf, 0x400 + 20 * i, 0, 0, 0, rva(0x5240), rva(0x5250))
    buf[0x5240:0x5246] = b"a.dll\0"
    struct.pack_into("<II", buf, dir_at(1), 0x2000, 20 * (n + 1))
    return bytes(buf)


def _l13(ndlls: int, thunks: list[int]) -> bytes:
    """L13: ndlls descriptors sharing the ILT at 0x800 (thunks + null) and DLL name b"a.dll"."""
    buf = bytearray(big_data(0x2000))
    for i in range(ndlls):
        struct.pack_into("<5I", buf, 0x400 + 20 * i, rva(0x800), 0, 0, rva(0x1C00), 0)
    for k, value in enumerate(thunks):
        struct.pack_into("<Q", buf, 0x800 + 8 * k, value)
    buf[0x1900:0x1904] = struct.pack("<H", 0) + b"f\0"
    buf[0x1A00:0x1B03] = struct.pack("<H", 7) + b"N" * 256 + b"\0"
    buf[0x1C00:0x1C06] = b"a.dll\0"
    struct.pack_into("<II", buf, dir_at(1), 0x2000, 20 * (ndlls + 1))
    return bytes(buf)


F_RVA = rva(0x1900)
LONG_RVA = rva(0x1A00)


def _one_dll(*, dll_name: bytes = b"a.dll\0", entry: bytes = b"") -> bytes:
    """One descriptor: DLL name at 0x1000; ILT [entry at 0x1A00, 0] at 0x800 if ``entry``."""
    data = big_data(0x2000)
    data = _write(data, 0x1000, dll_name)
    ilt = 0
    if entry:
        ilt = rva(0x800)
        data = _write(data, 0x800, struct.pack("<QQ", rva(0x1A00), 0))
        data = _write(data, 0x1A00, entry)
    data = _write(data, 0x400, struct.pack("<5I", ilt, 0, 0, rva(0x1000), 0))
    return _u32(data, (dir_at(1) + 4, 40))


# 1-2: the PT64/PT32 tables


def test_parse_imports_pt64() -> None:
    assert _imports(PT64) == ((KERNEL32, USER32), ())


def test_parse_imports_pt32_equal() -> None:
    assert _imports(PT32) == _imports(PT64)


@pytest.mark.parametrize("data", [PT64, PT32], ids=["pt64", "pt32"])
def test_import_read_order(data: bytes) -> None:
    source = MemorySource(data)
    parse_pe(source)
    assert len(source.calls) == 7
    assert _calls(data) == [
        (0x400, 60),
        (0x4C0, 257),
        (0x440, 448),
        (0x4E0, 259),
        (0x4D0, 257),
        (0x4A0, 352),
        (0x4F0, 259),
    ]


# 3-4: rva_to_file


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0x2000, ByteRange(0x400, 0x200)),
        (0x21FF, ByteRange(0x5FF, 1)),
        (0x2200, None),
        (0x1008, ByteRange(0x208, 8)),
        (0x1010, None),
        (0x1800, None),
        (0, ByteRange(0, 0x200)),
        (0x1FF, ByteRange(0x1FF, 1)),
        (0x200, None),
        (0xFFFFFFFF, None),
    ],
)
def test_rva_to_file(value: int, expected: ByteRange | None) -> None:
    assert rva_to_file(parse_pe(MemorySource(PT64)), value) == expected


def test_rva_to_file_virtual_size_zero() -> None:
    pe = parse_pe(MemorySource(_u32(PT64, (0x150, 0))))
    assert rva_to_file(pe, 0x1100) == ByteRange(0x300, 0x100)


def test_rva_to_file_first_section_wins() -> None:
    pe = parse_pe(MemorySource(_u32(PT64, (0x17C, 0x1000))))
    assert rva_to_file(pe, 0x1000) == ByteRange(0x200, 0x10)


@pytest.mark.parametrize("data", [PT64, PT32], ids=["pt64", "pt32"])
def test_rva_to_file_agrees_with_memory_map(data: bytes) -> None:
    pe = parse_pe(MemorySource(data))
    img = pe_image(pe)
    assert img is not None
    space: AddressSpace = img.memory.segments[0].start.space
    for value in range(pe.optional.size_of_image):
        a = SpaceAddress(space, Address(pe.optional.image_base + value))
        got = rva_to_file(pe, value)
        if img.memory.segment_at(a) is None:
            assert got is None
            continue
        r = img.memory.file_range_for(a, 1)
        assert (got is None) == (r.size == 0)
        if got is not None:
            assert got.start == r.start


# 5-7: directory, translation, descriptor count (I1-I3)


@pytest.mark.parametrize(
    "data",
    [build_pe(ndirs=1), _u32(P64, (dir_at(1), 0)), _u32(P64, (dir_at(1) + 4, 0))],
    ids=["ndirs-1", "va-0", "size-0"],
)
def test_no_import_directory(data: bytes) -> None:
    assert _imports(data) == ((), ())
    assert _calls(data) == []


@pytest.mark.parametrize("value", [0x2400, 0x1800], ids=["tail", "gap"])
def test_import_directory_not_in_file(value: int) -> None:
    data = _u32(PT64, (dir_at(1), value))
    with pytest.raises(ParseError) as err:
        _imports(data)
    assert err.value.reason == "import directory not in file"
    assert err.value.offset == 0xD0
    parsed = PeParser().parse(MemorySource(data), PRODUCER)
    assert parsed.not_analysed[0] == NotAnalysed(
        "pe imports not parsed: import directory not in file at offset 0xd0"
    )
    subjects = [f.subject for f in parsed.findings]
    assert "pe.import" not in subjects
    assert {"pe.certificate", "pe.overlay", "pe.signature"} <= set(subjects)


@pytest.mark.parametrize(("dir_size", "count"), [(0x29, 2), (0x28, 2), (0x14, 1), (0x13, 0)])
def test_descriptor_count_bounded_by_size(dir_size: int, count: int) -> None:
    data = _u32(PT64, (dir_at(1) + 4, dir_size))
    dlls, notes = _imports(data)
    assert dlls == (KERNEL32, USER32)[:count]
    assert notes == ()
    if count == 0:
        assert _calls(data) == []


def test_descriptor_count_thirty_byte_run() -> None:
    desc0 = PT64[0x400:0x414]
    data = _write(_u32(PT64, (dir_at(1), 0x21E2)), 0x5E2, desc0)  # run (0x5e2, 30)
    assert _imports(data) == ((replace(KERNEL32, descriptor_offset=Address(0x5E2)),), ())


def test_descriptor_count_bounded_by_run() -> None:
    data = _u32(PT64, (dir_at(1), 0x21F0))
    assert _imports(data) == ((), ())
    assert _calls(data) == []


def test_descriptor_cap() -> None:
    data = _l7(1000)
    dlls, notes = _imports(data)
    assert len(dlls) == MAX_IMPORT_DLLS
    assert notes == (TRUNCATED_NOTE,)
    assert _calls(data)[0] == (0x400, 5140)
    assert all(d.name == b"a.dll" and d.end is ThunkEnd.NULL for d in dlls)


@pytest.mark.parametrize(("n", "notes"), [(256, ()), (257, (TRUNCATED_NOTE,))])
def test_descriptor_cap_boundary(n: int, notes: tuple[NotAnalysed, ...]) -> None:
    dlls, got = _imports(_l7(n))
    assert len(dlls) == MAX_IMPORT_DLLS
    assert got == notes


# 8: DLL names (I4)


@pytest.mark.parametrize("value", [0x2400, 0x1800, 0xFFFFFFFF], ids=["tail", "gap", "max"])
def test_dll_name_not_in_file(value: int) -> None:
    (dll, _), _ = _imports(_u32(PT64, (0x40C, value)))
    assert dll.name is None
    assert not dll.name_truncated
    assert dll.functions == KERNEL32.functions


def test_dll_name_in_headers() -> None:
    (dll, _), _ = _imports(_u32(PT64, (0x40C, 0x100)))
    assert dll.name == b""
    assert not dll.name_truncated


@pytest.mark.parametrize(
    ("raw", "expected", "truncated"),
    [(b"D" * 300, b"D" * 256, True), (b"D" * 256 + b"\0", b"D" * 256, False)],
    ids=["300", "256"],
)
def test_dll_name_window(raw: bytes, expected: bytes, truncated: bool) -> None:
    ((dll,), _) = _imports(_one_dll(dll_name=raw))
    assert dll.name == expected
    assert dll.name_truncated is truncated
    assert (dll.functions, dll.end) == ((), ThunkEnd.UNMAPPED)


def test_dll_name_escaped_in_json() -> None:
    parsed = PeParser().parse(MemorySource(_one_dll(dll_name=b'\xff\x01"\\\0')), PRODUCER)
    (finding,) = [f for f in parsed.findings if f.subject == "pe.import"]
    assert isinstance(finding.value, dict)
    assert finding.value["dll"] == "\\xff\\x01\\x22\\x5c"


# 9: thunk array (I5)


def test_thunk_array_rva_zero() -> None:
    (_, dll), _ = _imports(_u32(PT64, (0x424, 0)))
    assert (dll.functions, dll.end) == ((), ThunkEnd.UNMAPPED)


def test_thunk_array_ilt_not_in_file_ignores_iat() -> None:
    (dll, _), _ = _imports(_u32(PT64, (0x400, 0x2400)))
    assert (dll.functions, dll.end) == ((), ThunkEnd.UNMAPPED)


def test_thunk_array_shorter_than_one_thunk() -> None:
    (_, dll), _ = _imports(_u32(PT64, (0x424, 0x21FC)))
    assert (dll.functions, dll.end) == ((), ThunkEnd.DATA_END)


# 10-12: thunks (I6)


@pytest.mark.parametrize(
    ("data", "ordinal"),
    [
        (_u64(PT64, 0x440, 0xC000000000FF0010), 16),
        (_u32(PT32, (0x440, 0xFFFF0010)), 16),
        (_u32(PT32, (0x440, 0x800020E0)), 0x20E0),
    ],
    ids=["pe32+", "pe32", "pe32-rva-bits"],
)
def test_ordinal_thunk(data: bytes, ordinal: int) -> None:
    (dll, _), _ = _imports(data)
    assert dll.functions[0] == ImportedFunction(ordinal, None, None)


@pytest.mark.parametrize("value", [0x800020E0, 0x1000020E0])
def test_pe32plus_name_thunk_high_bits(value: int) -> None:
    (dll, _), _ = _imports(_u64(PT64, 0x440, value))
    assert (dll.functions, dll.end) == ((), ThunkEnd.UNMAPPED)


@pytest.mark.parametrize("value", [0x2400, 0x1800], ids=["tail", "gap"])
def test_hint_name_not_in_file(value: int) -> None:
    (dll, _), _ = _imports(_u64(PT64, 0x440, value))
    assert (dll.functions, dll.end) == ((), ThunkEnd.UNMAPPED)


def test_hint_name_in_headers() -> None:
    (dll, _), _ = _imports(_u64(PT64, 0x440, 0x100))
    assert dll.functions[0] == ImportedFunction(None, 0, b"")


def test_hint_name_run_below_hint() -> None:
    (dll, _), _ = _imports(_u64(PT64, 0x440, 0x21FF))
    assert (dll.functions, dll.end) == ((), ThunkEnd.DATA_END)


def test_hint_name_window() -> None:
    ((dll,), _) = _imports(_one_dll(entry=struct.pack("<H", 5) + b"B" * 300))
    assert dll.functions == (ImportedFunction(None, 5, b"B" * 256, name_truncated=True),)


def test_hint_name_run_end() -> None:
    data = _write(_u64(PT64, 0x440, 0x21F0), 0x5F0, struct.pack("<H", 1) + b"E" * 14)
    (dll, _), _ = _imports(data)
    assert dll.functions[0] == ImportedFunction(None, 1, b"E" * 14, name_truncated=True)


def test_thunk_array_run_end() -> None:
    data = _u64(_u32(PT64, (0x424, 0x21F8)), 0x5F8, 0x20F0)
    (_, dll), _ = _imports(data)
    assert dll.functions == USER32.functions
    assert dll.end is ThunkEnd.DATA_END


# 13-15: caps (L13)


def test_per_dll_function_cap() -> None:
    data = _l13(1, [F_RVA] * 513)
    ((dll,), _) = _imports(data)
    assert len(dll.functions) == MAX_IMPORT_FUNCS
    assert dll.end is ThunkEnd.CAP
    assert (0x800, 4104) in _calls(data)


def test_per_dll_function_cap_null() -> None:
    ((dll,), _) = _imports(_l13(1, [F_RVA] * 512))
    assert len(dll.functions) == MAX_IMPORT_FUNCS
    assert dll.end is ThunkEnd.NULL


def test_global_function_cap() -> None:
    dlls, _ = _imports(_l13(33, [F_RVA] * 512))
    assert [len(d.functions) for d in dlls] == [512] * 32 + [0]
    assert [d.end for d in dlls] == [ThunkEnd.NULL] * 32 + [ThunkEnd.CAP]
    assert dlls[32].name == b"a.dll"


def test_per_dll_name_budget() -> None:
    ((dll,), _) = _imports(_l13(1, [LONG_RVA] * 100))
    assert len(dll.functions) == 48
    assert dll.end is ThunkEnd.CAP


def test_global_name_budget() -> None:
    dlls, _ = _imports(_l13(23, [LONG_RVA] * 100))
    assert [len(d.functions) for d in dlls] == [48] * 21 + [16, 0]
    assert all(d.end is ThunkEnd.CAP for d in dlls)


def test_import_read_budget() -> None:
    """Worst case: 257 descriptors, 513-thunk ILTs, empty names in 259-byte runs."""
    buf = bytearray(big_data(0x3000))
    for i in range(257):
        struct.pack_into("<5I", buf, 0x400 + 20 * i, rva(0x1900), 0, 0, rva(0x2C00), 0)
    for k in range(513):
        struct.pack_into("<Q", buf, 0x1900 + 8 * k, rva(0x2A00))
    buf[0x2C00:0x2C06] = b"a.dll\0"
    struct.pack_into("<II", buf, dir_at(1), 0x2000, 20 * 257)
    calls = _calls(bytes(buf))
    total = sum(n for _, n in calls)
    assert total <= MAX_IMPORT_READ_BYTES
    assert total == MAX_IMPORT_READ_BYTES  # this input reaches the bound


# 16: input changed


def test_input_changed_in_imports() -> None:
    source = ShrinkingSource(PT64, cut=0x400, honest_reads=7)
    pe = parse_pe(source)
    with pytest.raises(InputChanged) as err:
        parse_imports(source, pe)
    assert err.value.offset == 0x400
    with pytest.raises(InputChanged) as err:
        PeParser().parse(ShrinkingSource(PT64, cut=0x400, honest_reads=7), PRODUCER)
    assert err.value.offset == 0x400


# 17: value-object invariants


@pytest.mark.parametrize(
    ("ordinal", "hint", "name", "truncated"),
    [
        (1, 1, b"a", False),
        (None, None, None, False),
        (0x10000, None, None, False),
        (None, -1, b"a", False),
        (None, 1, b"a" * 257, False),
        (1, None, None, True),
    ],
    ids=["both", "neither", "ordinal-range", "hint-range", "name-long", "truncated-no-name"],
)
def test_imported_function_invariants(
    ordinal: int | None, hint: int | None, name: bytes | None, truncated: bool
) -> None:
    with pytest.raises(ParseError):
        ImportedFunction(ordinal, hint, name, truncated)


def _dll(functions: tuple[ImportedFunction, ...]) -> ImportedDll:
    return ImportedDll(Address(0), 0, 0, 0, 0, 0, None, False, functions, ThunkEnd.NULL)


@pytest.mark.parametrize(
    "functions",
    [
        (ImportedFunction(1, None, None),) * 513,
        (ImportedFunction(None, 0, b"x" * 256),) * 48 + (ImportedFunction(None, 0, b"x"),),
    ],
    ids=["513-functions", "12289-name-bytes"],
)
def test_imported_dll_invariants(functions: tuple[ImportedFunction, ...]) -> None:
    with pytest.raises(ParseError):
        _dll(functions)


def _pe_counts_fail(pe: PeFile, **changes: object) -> None:
    with pytest.raises(ParseError, match="PE table counts inconsistent"):
        replace(pe, **changes)


def test_pe_file_table_invariants() -> None:
    pe = parse_pe(MemorySource(P64))
    ordinals = _dll((ImportedFunction(1, None, None),) * 512)
    names = _dll((ImportedFunction(None, 0, b"x" * 256),) * 48)
    _pe_counts_fail(pe, imports=(_dll(()),) * 257)
    _pe_counts_fail(pe, imports=(ordinals,) * 32 + (_dll((ImportedFunction(1, None, None),)),))
    last = _dll((*names.functions[:16], ImportedFunction(None, 0, b"x")))
    _pe_counts_fail(pe, imports=(names,) * 21 + (last,))  # 262145 name bytes
    cert = CertificateEntry(Address(0x600), 8, 0x200, 2)
    _pe_counts_fail(pe, certificates=(cert,) * 17)


@pytest.mark.parametrize(
    ("certificate", "payload", "trailing"),
    [
        (None, 0x10, 0),
        (ByteRange(0x700, 0x10), 0x10, 0x10),
        (None, 0x8, 0x8),
        (ByteRange(0x700, 0x10), 0x8, 0x8),
    ],
    ids=["sizes", "sizes-cert", "trailing-no-cert", "cert-not-after-payload"],
)
def test_overlay_info_invariants(
    certificate: ByteRange | None, payload: int, trailing: int
) -> None:
    with pytest.raises(ParseError):
        OverlayInfo(Address(0x600), 0x20, certificate, payload, trailing, ())
