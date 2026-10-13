"""Synthetic resource trees and Inno Setup loader structures (see slice-6a spec, ## Tests)."""

from __future__ import annotations

import struct
import zlib
from collections.abc import Mapping

from tests.formats.pe_build import build_pe, dir_at

__all__ = [
    "MAGIC_515",
    "PI32",
    "block",
    "build_inno",
    "offset_table",
    "put",
    "rsrc",
    "version_field",
]

type Key = int | str
type Leaf = tuple[int, int]  # (data RVA relative to base_rva, size)
type Tree = Mapping[Key, Mapping[Key, Mapping[Key, Leaf]]]

MAGIC_515 = b"rDlPtS\xcd\xe6\xd7{\x0b*"
_NO_CRC = (b"rDlPtS02\x87eVx", b"rDlPtS04\x87eVx", b"rDlPtS05\x87eVx")


def _ordered[V](node: Mapping[Key, V]) -> list[tuple[Key, V]]:
    """Named entries first, then ID entries; insertion order kept within each group."""
    items = list(node.items())
    return [kv for kv in items if isinstance(kv[0], str)] + [
        kv for kv in items if isinstance(kv[0], int)
    ]


def rsrc(tree: Tree, base_rva: int = 0) -> bytes:
    """A resource tree: directories depth-first (pre-order), then strings, then data entries."""
    dirs: list[list[tuple[Key, int | Leaf]]] = []  # per directory: (key, child dir index | leaf)

    def collect(node: Mapping[Key, object], level: int) -> int:
        index = len(dirs)
        dirs.append([])
        for key, child in _ordered(node):
            if level < 3:
                assert isinstance(child, Mapping)
                dirs[index].append((key, collect(child, level + 1)))
            else:
                assert isinstance(child, tuple)
                dirs[index].append((key, child))
        return index

    collect(tree, 1)
    offsets: list[int] = []
    pos = 0
    for entries in dirs:
        offsets.append(pos)
        pos += 16 + 8 * len(entries)
    strings = bytearray()
    data = bytearray()
    names = [k for entries in dirs for k, _ in entries if isinstance(k, str)]
    string_at = pos
    data_at = pos + sum(2 + 2 * len(n) for n in names)
    out = bytearray()
    for entries in dirs:
        named = sum(isinstance(k, str) for k, _ in entries)
        out += struct.pack("<IIHHHH", 0, 0, 0, 0, named, len(entries) - named)
        for key, child in entries:
            if isinstance(key, str):
                field = 0x80000000 | (string_at + len(strings))
                strings += struct.pack("<H", len(key)) + key.encode("utf-16-le")
            else:
                field = key
            if isinstance(child, int):
                target = 0x80000000 | offsets[child]
            else:
                target = data_at + len(data)
                data += struct.pack("<IIII", base_rva + child[0], child[1], 0, 0)
            out += struct.pack("<II", field, target)
    return bytes(out + strings + data)


def put(data: bytes, off: int, fmt: str, *values: int) -> bytes:
    """``data`` with ``values`` packed as ``fmt`` at ``off``."""
    buf = bytearray(data)
    struct.pack_into(fmt, buf, off, *values)
    return bytes(buf)


def offset_table(magic: bytes, fields: tuple[int, ...], crc: int | None = None) -> bytes:
    """Magic + u32 fields + the table CRC32 (computed if None; omitted for pre-4.0.10 magics)."""
    raw = magic + struct.pack(f"<{len(fields)}I", *fields)
    if magic in _NO_CRC:
        return raw
    return raw + struct.pack("<I", zlib.crc32(raw) if crc is None else crc)


def version_field(text: bytes) -> bytes:
    """The 64-byte NUL-padded setup data version field."""
    return text.ljust(64, b"\0")


def block(stored: int, flag: int, crc: int | None = None) -> bytes:
    """A 9-byte block header (CRC32 over stored size + flag) and ``stored`` zero payload bytes."""
    body = struct.pack("<IB", stored, flag)
    return struct.pack("<I", zlib.crc32(body) if crc is None else crc) + body + bytes(stored)


def build_inno() -> bytes:
    """PI32: build_pe(32) + an RT_RCDATA 11111 offset table in .data + setup data overlay."""
    buf = bytearray(build_pe(32))
    struct.pack_into("<II", buf, dir_at(1, 32), 0, 0)
    struct.pack_into("<II", buf, dir_at(2, 32), 0x2000, 0x90)
    tree = rsrc({10: {11111: {0: (0x60, 44)}}}, 0x2000)
    buf[0x400 : 0x400 + len(tree)] = tree
    table = offset_table(MAGIC_515, (1, 0, 0x11, 0x22, 0x33, 0x600, 0x66A))
    buf[0x460 : 0x460 + len(table)] = table
    appended = (
        version_field(b"Inno Setup Setup Data (6.4.0.1)")
        + block(16, 1)
        + block(8, 1)
        + b"zlb\x1a"
        + bytes(4)
    )
    return bytes(buf) + appended


PI32 = build_inno()
