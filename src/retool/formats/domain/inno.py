"""Inno Setup loader structures (innoextract loader/offsets.cpp, setup/version.cpp, block.cpp).

Leaf module: imports only ``shared`` and stdlib; pure parsers over bytes the caller has read
with explicit sizes. CRC32 checks verify checksum fields the container declares over spans
it defines; no payload byte is decompressed or interpreted.
"""

from __future__ import annotations

import re
import struct
import zlib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from retool.shared import Address, ParseError

type Version = tuple[int, int, int, int]  # (major, minor, patch, build), each 0..255

POINTER_MAGIC: Final = 0x6F6E6E49  # "Inno" at file offset 0x30
TABLE_MAGIC_SIZE: Final = 12
MAX_VERSION_FIELD: Final = 64
LEGACY_STAMP_SIZE: Final = 12
BLOCK_HEADER_SIZE: Final = 9
CHUNK_MAGIC: Final = b"zlb\x1a"
EXPECTED_REVISION: Final = 1

_U32_MAX: Final = 0xFFFFFFFF
BLOCKS_FROM: Final = (4, 0, 9, 0)
_LZMA_FROM: Final = (4, 1, 6, 0)
_REVISION_FROM: Final = (5, 1, 5, 0)
_CRC_FROM: Final = (4, 0, 10, 0)
_UNICODE_FROM: Final = (6, 3, 0, 0)
_VERSION_GROUP: Final = re.compile(rb"\((\d{1,3})\.(\d{1,3})\.(\d{1,3})[a-z]?(?:\.(\d{1,3}))?\)")
_PRODUCT: Final = b"Inno Setup"


class InnoRoute(StrEnum):
    """How the loader offset table was found."""

    POINTER = "pointer"
    RESOURCE = "resource"


class InnoCompression(StrEnum):
    """Block compression declared by a block header flag and the setup data version."""

    STORED = "stored"
    ZLIB = "zlib"
    LZMA1 = "lzma1"


@dataclass(frozen=True, slots=True)
class _TableLayout:
    """Per-magic offset table fields and size; like ``pe._Layout``."""

    loader_version: Version | None
    size: int
    has_revision: bool
    has_exe_compressed: bool
    has_message: bool
    has_crc: bool

    def __post_init__(self) -> None:
        # Always present: unnamed, exe offset, exe uncompressed size, checksum, header, data.
        extra = self.has_revision + self.has_exe_compressed + self.has_message + self.has_crc
        if self.size != TABLE_MAGIC_SIZE + 4 * (6 + extra):
            raise ParseError("inno offset table layout size inconsistent")


_NEWEST: Final = _TableLayout((5, 1, 5, 0), 44, True, False, False, True)
_UNKNOWN: Final = _TableLayout(None, 44, True, False, False, True)
_LAYOUTS: Final[Mapping[bytes, _TableLayout]] = MappingProxyType(
    {
        b"rDlPtS02\x87eVx": _TableLayout((1, 2, 10, 0), 44, False, True, True, False),
        b"rDlPtS04\x87eVx": _TableLayout((4, 0, 0, 0), 40, False, True, False, False),
        b"rDlPtS05\x87eVx": _TableLayout((4, 0, 3, 0), 40, False, True, False, False),
        b"rDlPtS06\x87eVx": _TableLayout((4, 0, 10, 0), 44, False, True, False, True),
        b"rDlPtS07\x87eVx": _TableLayout((4, 1, 6, 0), 40, False, False, False, True),
        b"rDlPtS\xcd\xe6\xd7{\x0b*": _NEWEST,
        b"nS5W7dT\x83\xaa\x1b\x0fj": _NEWEST,
    }
)
_TABLE_SIZES: Final[Mapping[Version | None, int]] = MappingProxyType(
    {row.loader_version: row.size for row in (*_LAYOUTS.values(), _UNKNOWN)}
)

# Evidence subset of innoextract's known versions, matched as the whole NUL-padded field.
_KNOWN_FIELDS: Final = frozenset(
    text.ljust(MAX_VERSION_FIELD, b"\0")
    for text in (
        b"Inno Setup Setup Data (5.1.5)",
        b"Inno Setup Setup Data (5.5.7) (u)",
        b"Inno Setup Setup Data (6.0.0) (u)",
        b"Inno Setup Setup Data (6.1.0) (u)",
        b"Inno Setup Setup Data (6.3.0)",
        b"Inno Setup Setup Data (6.4.0)",
        b"Inno Setup Setup Data (6.4.0.1)",
    )
)


def _u32(*values: int) -> bool:
    return all(0 <= v <= _U32_MAX for v in values)


def _below(version: Version | None, bound: Version) -> bool:
    """True if ``version`` is known and older than ``bound`` (None = newest)."""
    return version is not None and version < bound


@dataclass(frozen=True, slots=True)
class InnoOffsets:
    """The loader offset table: where the setup exe, setup headers and data chunks start."""

    route: InnoRoute
    table_offset: Address
    table_size: int
    loader_version: Version | None
    revision: int | None
    exe_offset: Address
    exe_compressed_size: int | None
    exe_uncompressed_size: int
    exe_checksum: int
    message_offset: Address | None
    header_offset: Address
    data_offset: Address
    crc_ok: bool | None

    def __post_init__(self) -> None:
        v = self.loader_version
        optional = (self.revision, self.exe_compressed_size)
        if not (
            self.table_size == _TABLE_SIZES.get(v)
            and (self.revision is None) == _below(v, _REVISION_FROM)
            and (self.crc_ok is None) == _below(v, _CRC_FROM)
            and (self.exe_compressed_size is not None) == _below(v, _LZMA_FROM)
            and (self.message_offset is not None) == _below(v, (4, 0, 0, 0))
            and _u32(*(x for x in optional if x is not None))
            and _u32(
                self.exe_offset.value,
                self.exe_uncompressed_size,
                self.exe_checksum,
                self.header_offset.value,
                self.data_offset.value,
            )
            and (self.message_offset is None or _u32(self.message_offset.value))
        ):
            raise ParseError("inno offset table fields inconsistent")


@dataclass(frozen=True, slots=True)
class InnoVersion:
    """The setup data version field: its text before the first NUL and the parsed version."""

    raw: bytes
    version: Version
    unicode: bool
    known: bool

    def __post_init__(self) -> None:
        if not (
            1 <= len(self.raw) <= MAX_VERSION_FIELD
            and b"\0" not in self.raw
            and len(self.version) == 4
            and all(0 <= c <= 255 for c in self.version)
        ):
            raise ParseError("inno version field inconsistent")


@dataclass(frozen=True, slots=True)
class InnoBlockHeader:
    """A >= 4.0.9 block header: CRC32 of the next 5 bytes, stored size, compression flag."""

    index: int
    offset: Address
    expected_crc: int
    stored_size: int
    flag: int
    compression: InnoCompression
    crc_ok: bool

    def __post_init__(self) -> None:
        if not (
            self.index in (1, 2)
            and self.flag in (0, 1)
            and (self.flag == 0) == (self.compression is InnoCompression.STORED)
            and _u32(self.expected_crc, self.stored_size)
        ):
            raise ParseError("inno block header fields inconsistent")


@dataclass(frozen=True, slots=True)
class InnoData:
    """The first data chunk position and whether its 4-byte magic is present."""

    offset: Address
    magic_ok: bool


@dataclass(frozen=True, slots=True)
class InnoInfo:
    """What the Inno loader structures declare, up to the first data chunk magic."""

    offsets: InnoOffsets
    version: InnoVersion | None
    blocks: tuple[InnoBlockHeader, ...]
    data: InnoData | None

    def __post_init__(self) -> None:
        if not (
            len(self.blocks) <= 2
            and all(b.index == i + 1 for i, b in enumerate(self.blocks))
            and (
                not self.blocks
                or (self.version is not None and self.version.version >= BLOCKS_FROM)
            )
        ):
            raise ParseError("inno info inconsistent")


def offset_table_size(magic: bytes) -> int:
    """Size of the offset table that starts with ``magic`` (unknown magics: the newest)."""
    return _LAYOUTS.get(magic, _NEWEST).size


def parse_offset_table(raw: bytes, route: InnoRoute, offset: int) -> InnoOffsets:
    """Decode the whole offset table ``raw`` found at file ``offset``."""
    layout = _LAYOUTS.get(raw[:TABLE_MAGIC_SIZE], _UNKNOWN)
    if len(raw) != layout.size:
        raise ParseError("inno offset table size inconsistent", offset=offset)
    fields = iter(struct.unpack_from(f"<{(layout.size - TABLE_MAGIC_SIZE) // 4}I", raw, 12))
    revision = next(fields) if layout.has_revision else None
    next(fields)  # unnamed
    exe_offset = next(fields)
    exe_compressed = next(fields) if layout.has_exe_compressed else None
    exe_uncompressed = next(fields)
    checksum = next(fields)
    message = next(fields) if layout.has_message else None
    header = next(fields)
    data = next(fields)
    crc_ok = zlib.crc32(raw[: layout.size - 4]) == next(fields) if layout.has_crc else None
    return InnoOffsets(
        route,
        Address(offset),
        layout.size,
        layout.loader_version,
        revision,
        Address(exe_offset),
        exe_compressed,
        exe_uncompressed,
        checksum,
        Address(message) if message is not None else None,
        Address(header),
        Address(data),
        crc_ok,
    )


def is_legacy_stamp(head: bytes) -> bool:
    """True for a pre-4 ``i1.2.10--16\\x1a``-style 12-byte stamp."""
    return len(head) == LEGACY_STAMP_SIZE and head[0] == ord("i") and head[11] == 0x1A


def parse_version_field(field: bytes) -> InnoVersion | None:
    """Decode the 64-byte NUL-padded version field; None if it is not recognised."""
    if len(field) != MAX_VERSION_FIELD:
        raise ParseError("inno version field size inconsistent")
    raw = field.split(b"\0", 1)[0]
    if _PRODUCT not in raw:
        return None
    candidates: list[Version] = []
    for match in _VERSION_GROUP.finditer(raw):
        major, minor, patch, build = match.groups()
        parts = (int(major), int(minor), int(patch), int(build) if build is not None else 0)
        if all(c <= 255 for c in parts):
            candidates.append(parts)
    if not candidates:
        return None
    version = max(candidates)
    unicode = version >= _UNICODE_FROM or b"(u)" in raw or b"(U)" in raw
    return InnoVersion(raw, version, unicode, field in _KNOWN_FIELDS)


def parse_block_header(raw: bytes, offset: int, index: int, version: Version) -> InnoBlockHeader:
    """Decode the 9-byte block header at file ``offset``; an unknown flag raises."""
    if len(raw) != BLOCK_HEADER_SIZE:
        raise ParseError("inno block header size inconsistent", offset=offset)
    expected, stored, flag = struct.unpack("<IIB", raw)
    if flag not in (0, 1):
        raise ParseError(f"inno block {index} compression flag {flag} unexpected", offset=offset)
    packed = InnoCompression.LZMA1 if version >= _LZMA_FROM else InnoCompression.ZLIB
    compression = packed if flag else InnoCompression.STORED
    crc_ok = zlib.crc32(raw[4:]) == expected
    return InnoBlockHeader(index, Address(offset), expected, stored, flag, compression, crc_ok)
