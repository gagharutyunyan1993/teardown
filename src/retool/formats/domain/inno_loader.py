"""Domain service: locate and read the Inno Setup loader structures of a parsed PE.

Route order mirrors innoextract loader/offsets.cpp: the pointer at file 0x30, then resource
RT_RCDATA 11111. Every read goes through ``read_exact`` after a bounds check; the loader
structures take at most seven reads of 142 bytes (plus one 12-byte read when the pointer falls
through). For 6.4.3 the ``_setup`` stage then decodes the two header blocks (ADR 0003, bounded
by ``MAX_STORED_BLOCK`` / ``MAX_DECODED_TOTAL``) and parses the setup header and file list. A
failed sub-stage adds one note and stops its chain; an unusable resource route drops the part
with one note (pointer notes kept).
"""

from __future__ import annotations

import struct
from typing import Final

from retool.formats.domain.decompress import MAX_DECODED_TOTAL, Codec, Decoded, DecodeError
from retool.formats.domain.inno import (
    BLOCK_HEADER_SIZE,
    BLOCKS_FROM,
    CHUNK_MAGIC,
    EXPECTED_REVISION,
    LEGACY_STAMP_SIZE,
    MAX_INNO_FILE_FINDINGS,
    MAX_VERSION_FIELD,
    POINTER_MAGIC,
    SUPPORTED_SETUP_VERSION,
    TABLE_MAGIC_SIZE,
    InnoBlockHeader,
    InnoCompression,
    InnoData,
    InnoDecodeStatus,
    InnoInfo,
    InnoOffsets,
    InnoRoute,
    InnoVersion,
    is_legacy_stamp,
    offset_table_size,
    parse_block_header,
    parse_offset_table,
    parse_version_field,
)
from retool.formats.domain.inno_block import decode_block
from retool.formats.domain.inno_files import InnoFile, join_files
from retool.formats.domain.inno_setup import (
    LOCATION_SIZE,
    InnoHeader,
    parse_locations_643,
    parse_setup_643,
)
from retool.formats.domain.model import InputChanged
from retool.formats.domain.parsing import read_exact
from retool.formats.domain.pe import PeFile
from retool.formats.domain.pe_image import rva_range
from retool.formats.domain.pe_resources import find_resource
from retool.formats.domain.ports import ByteSource
from retool.shared import Address, NotAnalysed, ParseError

RT_RCDATA: Final = 10  # winuser.h
INNO_RESOURCE_ID: Final = 11111  # innoextract loader/offsets.cpp
INNO_NOT_PARSED_NOTE: Final = (
    "inno data chunks, slices and non-file entries not extracted or reported in this version"
)
_POINTER_AT: Final = 0x30
_POINTER_SIZE: Final = 12
_HINTS: Final = frozenset({"inno-chunk", "inno-setup-data"})


def _note(reason: str, offset: int | None = None) -> NotAnalysed:
    return NotAnalysed(str(ParseError(reason, offset=offset)))


def _pointer(source: ByteSource, notes: list[NotAnalysed]) -> tuple[int, bytes] | None:
    """Table offset and magic named by the pointer at 0x30, or None (with a note if broken)."""
    size = source.size
    magic, off, complement = struct.unpack(
        "<III", read_exact(source, size, _POINTER_AT, _POINTER_SIZE)
    )
    if magic != POINTER_MAGIC:
        return None
    if complement != off ^ 0xFFFFFFFF:
        notes.append(_note("inno loader pointer at 0x30 fails its complement check"))
        return None
    if off + TABLE_MAGIC_SIZE <= size:
        head = read_exact(source, size, off, TABLE_MAGIC_SIZE)
        if off + offset_table_size(head) <= size:
            return off, head
    notes.append(_note(f"inno loader pointer target {off:#x} past end of file"))
    return None


def _resource(source: ByteSource, pe: PeFile) -> tuple[int, int, bytes] | None:
    """Table offset, read limit and magic of the RT_RCDATA 11111 resource, or None."""
    if pe.resources is None:
        return None
    entry = find_resource(pe.resources, RT_RCDATA, INNO_RESOURCE_ID)
    if entry is None:
        return None
    at = entry.entry_offset.value
    rng = rva_range(pe, entry.data_rva, entry.size)
    if rng is None:
        raise ParseError("inno offset table resource not file-backed", offset=at)
    limit = rng.start + entry.size
    if entry.size < TABLE_MAGIC_SIZE:
        raise ParseError("inno offset table larger than its resource", offset=at)
    if rng.start + TABLE_MAGIC_SIZE > source.size:
        raise ParseError("inno offset table past end of file", offset=rng.start)
    head = read_exact(source, limit, rng.start, TABLE_MAGIC_SIZE)
    table_size = offset_table_size(head)
    if table_size > entry.size:
        raise ParseError("inno offset table larger than its resource", offset=at)
    if rng.start + table_size > source.size:
        raise ParseError("inno offset table past end of file", offset=rng.start)
    return rng.start, limit, head


def _table_notes(offsets: InnoOffsets) -> list[NotAnalysed]:
    at = offsets.table_offset.value
    notes: list[NotAnalysed] = []
    if offsets.loader_version is None:
        reason = f"inno loader magic unknown at offset {at:#x}; read as the 5.1.5 layout"
        notes.append(NotAnalysed(reason))
    if offsets.revision is not None and offsets.revision != EXPECTED_REVISION:
        notes.append(_note(f"inno loader revision {offsets.revision} unexpected"))
    if offsets.crc_ok is False:
        notes.append(_note("inno loader table CRC mismatch", at))
    return notes


def _version(source: ByteSource, h: int, notes: list[NotAnalysed]) -> InnoVersion | None:
    size = source.size
    if h + LEGACY_STAMP_SIZE > size:
        notes.append(_note("inno setup data header past end of file", h))
        return None
    full = h + MAX_VERSION_FIELD <= size
    head = read_exact(source, size, h, MAX_VERSION_FIELD if full else LEGACY_STAMP_SIZE)
    if is_legacy_stamp(head[:LEGACY_STAMP_SIZE]):
        notes.append(_note("inno legacy setup data stamp not analysed", h))
        return None
    if not full:
        notes.append(_note("inno setup data header past end of file", h))
        return None
    version = parse_version_field(head)
    if version is None:
        notes.append(_note("inno setup data version not recognised", h))
    return version


def _blocks(
    source: ByteSource, h: int, version: InnoVersion, notes: list[NotAnalysed]
) -> tuple[InnoBlockHeader, ...]:
    if version.version < BLOCKS_FROM:
        notes.append(_note("inno blocks before 4.0.9 not analysed"))
        return ()
    size = source.size
    pos = h + MAX_VERSION_FIELD
    blocks: list[InnoBlockHeader] = []
    for index in (1, 2):
        if pos + BLOCK_HEADER_SIZE > size:
            notes.append(_note(f"inno block {index} header past end of file", pos))
            break
        raw = read_exact(source, size, pos, BLOCK_HEADER_SIZE)
        try:
            block = parse_block_header(raw, pos, index, version.version)
        except ParseError as exc:
            notes.append(NotAnalysed(str(exc)))
            break
        if not block.crc_ok:
            blocks.append(block)
            notes.append(_note(f"inno block {index} header CRC mismatch", pos))
            break
        end = pos + BLOCK_HEADER_SIZE + block.stored_size
        if end > size:
            notes.append(_note(f"inno block {index} payload past end of file", pos))
            break
        blocks.append(block)
        pos = end
    return tuple(blocks)


type _Setup = tuple[InnoHeader | None, tuple[InnoFile, ...], tuple[InnoDecodeStatus, ...]]


def _decode(
    source: ByteSource,
    block: InnoBlockHeader,
    notes: list[NotAnalysed],
    statuses: list[InnoDecodeStatus],
    *,
    cap: int,
    declared: int | None = None,
) -> Decoded | None:
    """Decode one header block; a failure adds its status (if typed) and an N4 note."""
    try:
        out = decode_block(source, block, cap=cap, declared=declared)
    except InputChanged:
        raise
    except DecodeError as exc:
        status = InnoDecodeStatus(
            block.index, Codec.LZMA1_RAW, False, exc.kind, exc.decoded, None, None
        )
        statuses.append(status)
        notes.append(NotAnalysed(f"inno block {block.index} not decoded: {exc}"))
        return None
    except ParseError as exc:
        notes.append(NotAnalysed(f"inno block {block.index} not decoded: {exc}"))
        return None
    statuses.append(
        InnoDecodeStatus(
            block.index, Codec.LZMA1_RAW, out.ended, None, len(out.data), out.consumed, out.trailing
        )
    )
    return out


def _setup(
    source: ByteSource,
    version: InnoVersion,
    blocks: tuple[InnoBlockHeader, ...],
    notes: list[NotAnalysed],
) -> _Setup:
    """Decode and parse the 6.4.3 header blocks; every failure is one note (S13)."""
    if version.version != SUPPORTED_SETUP_VERSION or not version.unicode:
        a, b, c, d = version.version
        notes.append(NotAnalysed(f"inno version {a}.{b}.{c}.{d} unsupported: headers not parsed"))
        return None, (), ()
    if len(blocks) < 2 or not all(block.crc_ok for block in blocks):
        notes.append(NotAnalysed("inno headers not decoded: block headers incomplete"))
        return None, (), ()
    for block in blocks:
        if block.compression is not InnoCompression.LZMA1:
            reason = f"inno block {block.index} compression {block.compression} not decoded"
            notes.append(NotAnalysed(reason))
            return None, (), ()
    statuses: list[InnoDecodeStatus] = []
    first = _decode(source, blocks[0], notes, statuses, cap=MAX_DECODED_TOTAL)
    if first is None:
        return None, (), tuple(statuses)
    try:
        setup = parse_setup_643(first.data)
    except InputChanged:
        raise
    except ParseError as exc:
        notes.append(NotAnalysed(f"inno block 1 not parsed: {exc}"))
        return None, (), tuple(statuses)
    header = setup.header
    cap = MAX_DECODED_TOTAL - len(first.data)
    declared = header.num_locations * LOCATION_SIZE
    second = _decode(source, blocks[1], notes, statuses, cap=cap, declared=declared)
    if second is None:
        return header, (), tuple(statuses)
    try:
        locations = parse_locations_643(second.data, header.num_locations)
        files = join_files(setup.files, locations)
    except InputChanged:
        raise
    except ParseError as exc:
        notes.append(NotAnalysed(f"inno block 2 not parsed: {exc}"))
        return header, (), tuple(statuses)
    if len(files) > MAX_INNO_FILE_FINDINGS:
        reason = (
            f"inno file list truncated: {MAX_INNO_FILE_FINDINGS} of {len(files)} files reported"
        )
        notes.append(NotAnalysed(reason))
    encrypted = sum(location.chunk_encrypted for location in locations)
    if encrypted:
        reason = f"inno file data encrypted: {encrypted} of {len(locations)} file locations"
        notes.append(NotAnalysed(reason))
    return header, files, tuple(statuses)


def _data(source: ByteSource, offset: int, notes: list[NotAnalysed]) -> InnoData | None:
    size = source.size
    if offset == 0:
        notes.append(_note("inno data in external slice files not analysed"))
        return None
    if offset + len(CHUNK_MAGIC) > size:
        notes.append(_note("inno data chunk past end of file", offset))
        return None
    magic = read_exact(source, size, offset, len(CHUNK_MAGIC))
    return InnoData(Address(offset), magic == CHUNK_MAGIC)


def inno_info(source: ByteSource, pe: PeFile) -> tuple[InnoInfo | None, tuple[NotAnalysed, ...]]:
    """The Inno loader structures of ``pe`` and the notes on what was not analysed."""
    notes: list[NotAnalysed] = []
    found = _pointer(source, notes)
    table: tuple[int, int, bytes] | None
    if found is not None:
        route, table = InnoRoute.POINTER, (found[0], source.size, found[1])
    else:
        try:
            route, table = InnoRoute.RESOURCE, _resource(source, pe)
        except InputChanged:
            raise
        except ParseError as exc:  # S8: drop the part, keep the pointer notes
            return None, (*notes, NotAnalysed(f"pe inno not parsed: {exc}"))
    if table is None:
        overlay = pe.overlay
        if overlay is not None and any(m.name in _HINTS for m in overlay.signatures):
            notes.append(_note("inno-like overlay without a loader offset table"))
        return None, tuple(notes)
    start, limit, head = table
    rest = read_exact(
        source, limit, start + TABLE_MAGIC_SIZE, offset_table_size(head) - TABLE_MAGIC_SIZE
    )
    offsets = parse_offset_table(head + rest, route, start)
    notes.extend(_table_notes(offsets))
    h = offsets.header_offset.value
    version = _version(source, h, notes)
    blocks = _blocks(source, h, version, notes) if version is not None else ()
    setup: _Setup = (None, (), ())
    if version is not None and version.version >= BLOCKS_FROM:
        setup = _setup(source, version, blocks, notes)
    data = _data(source, offsets.data_offset.value, notes)
    notes.append(NotAnalysed(INNO_NOT_PARSED_NOTE))
    return InnoInfo(offsets, version, blocks, data, *setup), tuple(notes)
