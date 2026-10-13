"""Domain service: walk the PE Import Directory (Microsoft "PE Format", Import Directory Table).

Every RVA is translated with ``rva_to_file``; walks and name scans stay inside the file-backed
run they start in and every read goes through ``read_exact``. Counts and name bytes are capped
per DLL and over all DLLs; a cap ends a DLL's walk with ``ThunkEnd.CAP``. Only an import
directory that is not file-backed rejects the whole part.
"""

from __future__ import annotations

import struct
from typing import Final

from retool.formats.domain.parsing import read_exact
from retool.formats.domain.pe import (
    IMPORT_DLL_NAME_BYTES,
    IMPORT_TOTAL_NAME_BYTES,
    MAX_IMPORT_DLLS,
    MAX_IMPORT_FUNCS,
    MAX_IMPORT_FUNCS_TOTAL,
    MAX_IMPORT_NAME,
    ImportedDll,
    ImportedFunction,
    PeFile,
    ThunkEnd,
    directory,
    directory_offset,
    function_name_bytes,
)
from retool.formats.domain.pe_image import rva_to_file
from retool.formats.domain.ports import ByteSource
from retool.shared import Address, NotAnalysed, ParseError

_IMPORT_DIR: Final = 1
_DESC_FMT: Final = "<5I"
_DESC_SIZE: Final = 20
_NULL_DESC: Final = bytes(_DESC_SIZE)
_HINT_FMT: Final = "<H"
_HINT_SIZE: Final = 2
_MIN_ENTRY: Final = _HINT_SIZE + 1  # smallest hint/name read: hint + NUL
_ORDINAL_MASK: Final = 0xFFFF
_NAME_RVA_BITS: Final = 31
_TRUNCATED_NOTE: Final = f"pe imports truncated at {MAX_IMPORT_DLLS} DLLs"


def _uints(fmt: str, buf: bytes, offset: int) -> tuple[int, ...]:
    if offset + struct.calcsize(fmt) > len(buf):
        raise ParseError("PE struct size mismatch")
    return tuple(v for v in struct.unpack_from(fmt, buf, offset) if isinstance(v, int))


def _name(window: bytes) -> tuple[bytes, bool]:
    """Bytes before the first NUL; without a NUL the first ``MAX_IMPORT_NAME``, truncated."""
    end = window.find(b"\0")
    if end >= 0:
        return window[:end], False
    return window[:MAX_IMPORT_NAME], True


def _dll_name(source: ByteSource, size: int, pe: PeFile, rva: int) -> tuple[bytes | None, bool]:
    run = rva_to_file(pe, rva)
    if run is None:
        return None, False
    return _name(read_exact(source, size, run.start, min(MAX_IMPORT_NAME + 1, run.size)))


def _walk_thunks(
    source: ByteSource, size: int, pe: PeFile, rva: int, funcs_used: int, names_used: int
) -> tuple[tuple[ImportedFunction, ...], ThunkEnd]:
    """Functions of one thunk array; ``funcs_used``/``names_used`` count all previous DLLs."""
    if rva == 0:
        return (), ThunkEnd.UNMAPPED
    run = rva_to_file(pe, rva)
    if run is None:
        return (), ThunkEnd.UNMAPPED
    width = 8 if pe.optional.bits == 64 else 4
    fmt = "<Q" if width == 8 else "<I"
    ordinal_flag = 1 << (8 * width - 1)
    count = min(MAX_IMPORT_FUNCS + 1, run.size // width)
    if count == 0:
        return (), ThunkEnd.DATA_END
    thunks = read_exact(source, size, run.start, count * width)
    functions: list[ImportedFunction] = []
    name_bytes = 0  # global name budget: name bytes listed
    charged = 0  # per-DLL name budget: every name thunk costs at least the minimum read
    for k in range(count):
        (value,) = _uints(fmt, thunks, k * width)
        if value == 0:
            return tuple(functions), ThunkEnd.NULL
        if k == MAX_IMPORT_FUNCS or funcs_used + len(functions) == MAX_IMPORT_FUNCS_TOTAL:
            return tuple(functions), ThunkEnd.CAP
        if value & ordinal_flag:
            functions.append(ImportedFunction(value & _ORDINAL_MASK, None, None))
            continue
        if value >> _NAME_RVA_BITS:  # PE32+ bits 62-31 must be 0: bound VA or corrupt
            return tuple(functions), ThunkEnd.UNMAPPED
        entry_run = rva_to_file(pe, value)
        if entry_run is None:
            return tuple(functions), ThunkEnd.UNMAPPED
        if entry_run.size < _HINT_SIZE:
            return tuple(functions), ThunkEnd.DATA_END
        entry = read_exact(
            source, size, entry_run.start, min(_HINT_SIZE + MAX_IMPORT_NAME + 1, entry_run.size)
        )
        (hint,) = _uints(_HINT_FMT, entry, 0)
        name, truncated = _name(entry[_HINT_SIZE:])
        charge = max(len(name), _MIN_ENTRY)
        if (
            charged + charge > IMPORT_DLL_NAME_BYTES
            or names_used + name_bytes + len(name) > IMPORT_TOTAL_NAME_BYTES
        ):
            return tuple(functions), ThunkEnd.CAP
        functions.append(ImportedFunction(None, hint, name, truncated))
        name_bytes += len(name)
        charged += charge
    return tuple(functions), ThunkEnd.DATA_END


def parse_imports(
    source: ByteSource, pe: PeFile
) -> tuple[tuple[ImportedDll, ...], tuple[NotAnalysed, ...]]:
    """Import descriptors of directory 1 in table order, and a note if the DLL cap was hit."""
    found = directory(pe, _IMPORT_DIR)
    if found is None:
        return (), ()
    run = rva_to_file(pe, found.virtual_address)
    if run is None:
        raise ParseError("import directory not in file", offset=directory_offset(pe, _IMPORT_DIR))
    n = min(found.size // _DESC_SIZE, run.size // _DESC_SIZE, MAX_IMPORT_DLLS + 1)
    if n == 0:
        return (), ()
    size = source.size
    table = read_exact(source, size, run.start, _DESC_SIZE * n)
    dlls: list[ImportedDll] = []
    notes: list[NotAnalysed] = []
    funcs_used = 0
    names_used = 0
    for i in range(n):
        at = i * _DESC_SIZE
        if table[at : at + _DESC_SIZE] == _NULL_DESC:
            break
        if i == MAX_IMPORT_DLLS:
            notes.append(NotAnalysed(_TRUNCATED_NOTE))
            break
        ilt, stamp, forwarder, name_rva, iat = _uints(_DESC_FMT, table, at)
        name, name_truncated = _dll_name(source, size, pe, name_rva)
        thunk_rva = ilt if ilt != 0 else iat
        functions, end = _walk_thunks(source, size, pe, thunk_rva, funcs_used, names_used)
        funcs_used += len(functions)
        names_used += function_name_bytes(functions)
        dlls.append(
            ImportedDll(
                Address(run.start + at),
                ilt,
                stamp,
                forwarder,
                name_rva,
                iat,
                name,
                name_truncated,
                functions,
                end,
            )
        )
    return tuple(dlls), tuple(notes)
