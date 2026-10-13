"""PE resource directory (.rsrc, data directory 2): a bounded three-level tree walk.

Leaf module: imports only ``parsing``, ``ports`` and ``shared`` so ``pe.py`` can hold its VOs.
The tree region is read once (at most ``MAX_RESOURCE_READ`` bytes); every offset in the tree is
relative to the directory start and checked against the bound ``root.size`` and that window
before use; counts, depth, names and the walk total are capped; a revisited directory is
rejected. Malformed structure raises ``ParseError`` with the file offset.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

from retool.formats.domain.parsing import read_exact
from retool.formats.domain.ports import ByteSource
from retool.shared import Address, ByteRange, ParseError

MAX_RESOURCE_ENTRIES: Final = 4096  # per directory table (named + id)
MAX_RESOURCE_TOTAL: Final = 16384  # directory entries walked across the whole tree
MAX_RESOURCE_DEPTH: Final = 3  # type -> name -> language; hard cap in the walk
MAX_RESOURCE_NAME: Final = 64  # UTF-16 code units in a named entry
# One read of the tree region. Holds every structure a capped, packed tree can have:
# 16 + MAX_RESOURCE_TOTAL * (8 entry + 16 subdirectory/data entry + 130 name) = 2,785,296 B.
MAX_RESOURCE_READ: Final = 4 * 1024 * 1024

type ResourceKey = int | bytes  # ID (0..0x7FFFFFFF) or raw UTF-16LE name

_HIGH_BIT: Final = 0x80000000  # NAME_IS_STRING / DATA_IS_DIRECTORY (winnt.h)
_LOW_BITS: Final = 0x7FFFFFFF
_U32_MAX: Final = 0xFFFFFFFF
_DIR_SIZE: Final = 16  # "<IIHHHH"
_OFF_COUNTS: Final = 12
_ENTRY_SIZE: Final = 8  # "<II"
_DATA_SIZE: Final = 16  # "<IIII"
_LEN_SIZE: Final = 2  # "<H"


def _valid_key(key: ResourceKey) -> bool:
    if isinstance(key, bytes):
        return len(key) % 2 == 0 and len(key) <= 2 * MAX_RESOURCE_NAME
    return 0 <= key <= _LOW_BITS


@dataclass(frozen=True, slots=True)
class ResourceEntry:
    """One language leaf: its type/name/language keys and IMAGE_RESOURCE_DATA_ENTRY fields."""

    type: ResourceKey
    name: ResourceKey
    lang: ResourceKey
    data_rva: int
    size: int
    code_page: int
    entry_offset: Address  # file offset of the IMAGE_RESOURCE_DATA_ENTRY

    def __post_init__(self) -> None:
        if not (
            _valid_key(self.type)
            and _valid_key(self.name)
            and _valid_key(self.lang)
            and all(0 <= v <= _U32_MAX for v in (self.data_rva, self.size, self.code_page))
        ):
            raise ParseError("resource entry fields out of range")


@dataclass(frozen=True, slots=True)
class ResourceSummary:
    """The resource tree's file range and its leaves in walk order."""

    offset: Address
    size: int
    entries: tuple[ResourceEntry, ...]

    def __post_init__(self) -> None:
        if self.size < 0 or len(self.entries) > MAX_RESOURCE_TOTAL:
            raise ParseError("resource summary inconsistent")


def parse_resources(source: ByteSource, root: ByteRange) -> ResourceSummary:
    """Walk the type -> name -> language tree rooted at ``root.start`` within ``root.size``."""
    bound = root.size
    visited: set[int] = set()
    entries: list[ResourceEntry] = []
    total = 0
    window = memoryview(read_exact(source, root.end, root.start, min(bound, MAX_RESOURCE_READ)))

    def fetch(rel: int, size: int, reason: str) -> memoryview:
        if rel + size > bound:
            raise ParseError(reason, offset=root.start + rel)
        if rel + size > len(window):
            raise ParseError("resource structure past the read window", offset=root.start + rel)
        return window[rel : rel + size]

    def table(rel: int, level: int) -> list[tuple[int, int]]:
        nonlocal total
        at = root.start + rel
        if level > MAX_RESOURCE_DEPTH:
            raise ParseError("resource tree deeper than 3 levels", offset=at)
        if rel in visited:
            raise ParseError("resource directory revisited", offset=at)
        visited.add(rel)
        head = fetch(rel, _DIR_SIZE, "resource directory past end of tree")
        named, ids = struct.unpack_from("<HH", head, _OFF_COUNTS)
        count = named + ids
        if count > MAX_RESOURCE_ENTRIES:
            raise ParseError("resource directory too large", offset=at)
        if rel + _DIR_SIZE + _ENTRY_SIZE * count > bound:
            raise ParseError("resource entries past directory", offset=at)
        total += count
        if total > MAX_RESOURCE_TOTAL:
            raise ParseError("resource tree too large", offset=at)
        if count == 0:
            return []
        raw = fetch(rel + _DIR_SIZE, _ENTRY_SIZE * count, "resource entries past directory")
        return [struct.unpack_from("<II", raw, _ENTRY_SIZE * i) for i in range(count)]

    def key(field: int) -> ResourceKey:
        if not field & _HIGH_BIT:
            return field
        rel = field & _LOW_BITS
        (length,) = struct.unpack("<H", fetch(rel, _LEN_SIZE, "resource name past end of tree"))
        if length > MAX_RESOURCE_NAME:
            raise ParseError("resource name too long", offset=root.start + rel)
        if length == 0:
            return b""
        return bytes(fetch(rel + _LEN_SIZE, 2 * length, "resource name past end of tree"))

    def walk(rel: int, level: int, path: tuple[ResourceKey, ...]) -> None:
        for index, (field, target) in enumerate(table(rel, level)):
            is_dir = bool(target & _HIGH_BIT)
            if is_dir != (level < MAX_RESOURCE_DEPTH):
                at = root.start + rel + _DIR_SIZE + _ENTRY_SIZE * index
                raise ParseError("resource tree not three levels", offset=at)
            here = (*path, key(field))
            if is_dir:
                walk(target & _LOW_BITS, level + 1, here)
                continue
            raw = fetch(target, _DATA_SIZE, "resource data entry past end of tree")
            data_rva, size, code_page, _reserved = struct.unpack("<IIII", raw)
            type_key, name_key, lang_key = here
            entries.append(
                ResourceEntry(
                    type_key,
                    name_key,
                    lang_key,
                    data_rva,
                    size,
                    code_page,
                    Address(root.start + target),
                )
            )

    walk(0, 1, ())
    return ResourceSummary(Address(root.start), root.size, tuple(entries))


def find_resource(summary: ResourceSummary, type_id: int, name_id: int) -> ResourceEntry | None:
    """First leaf in walk order with ID keys ``type_id`` and ``name_id`` (first language wins)."""
    for entry in summary.entries:
        if (
            isinstance(entry.type, int)
            and isinstance(entry.name, int)
            and entry.type == type_id
            and entry.name == name_id
        ):
            return entry
    return None
