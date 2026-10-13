"""Synthetic resource trees and Inno Setup loader structures (see slice-6a spec, ## Tests)."""

from __future__ import annotations

import hashlib
import lzma
import struct
import zlib
from collections.abc import Mapping, Sequence

from retool.formats.domain.inno_setup import RecordSpec
from tests.formats.pe_build import build_pe, dir_at

__all__ = [
    "G7",
    "G7_BLOCK1",
    "G7_BLOCK2",
    "G7_BLOCKS",
    "G7_SHA256_1",
    "G7_SHA256_2",
    "G7_STREAM1",
    "G7_STREAM2",
    "ID_643",
    "MAGIC_515",
    "PI32",
    "block",
    "build_inno",
    "file_entry",
    "framed",
    "generic_record",
    "inno_ansi",
    "inno_string",
    "language_entry",
    "location_entry",
    "lzma1_block",
    "lzma1_blocks",
    "many_files_inno",
    "offset_table",
    "put",
    "raw_lzma1",
    "record",
    "rsrc",
    "setup_header",
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


_PI32_ID = b"Inno Setup Setup Data (6.4.0.1)"
_PI32_BLOCKS = block(16, 1) + block(8, 1)


def build_inno(setup_id: bytes = _PI32_ID, blocks: bytes = _PI32_BLOCKS) -> bytes:
    """build_pe(32) + an RT_RCDATA 11111 offset table in .data + setup data overlay.

    Defaults give PI32; the table's data offset is 0x600 + 64 + len(blocks).
    """
    buf = bytearray(build_pe(32))
    struct.pack_into("<II", buf, dir_at(1, 32), 0, 0)
    struct.pack_into("<II", buf, dir_at(2, 32), 0x2000, 0x90)
    tree = rsrc({10: {11111: {0: (0x60, 44)}}}, 0x2000)
    buf[0x400 : 0x400 + len(tree)] = tree
    data_offset = 0x600 + 64 + len(blocks)
    table = offset_table(MAGIC_515, (1, 0, 0x11, 0x22, 0x33, 0x600, data_offset))
    buf[0x460 : 0x460 + len(table)] = table
    appended = version_field(setup_id) + blocks + b"zlb\x1a" + bytes(4)
    return bytes(buf) + appended


PI32 = build_inno()


# Slice 6b: decoded setup data builders (spec ## CLI/JSON, Builders).


def inno_string(text: str) -> bytes:
    """A ``String``: i32 byte count + UTF-16LE."""
    raw = text.encode("utf-16-le", "surrogatepass")
    return struct.pack("<i", len(raw)) + raw


def inno_ansi(raw: bytes) -> bytes:
    """An ``AnsiString``: i32 byte count + raw bytes."""
    return struct.pack("<i", len(raw)) + raw


def record(strings: Sequence[str], ansi: Sequence[bytes], fixed: bytes) -> bytes:
    """Strings, then AnsiStrings, then the fixed bytes."""
    return b"".join(inno_string(t) for t in strings) + b"".join(inno_ansi(a) for a in ansi) + fixed


def generic_record(spec: RecordSpec, seed: int) -> bytes:
    """A ``spec`` record: every String "s<seed>", every AnsiString b"a", zero fixed bytes."""
    return record([f"s{seed}"] * spec.strings, [b"a"] * spec.ansi, bytes(spec.fixed))


def setup_header(
    counts: Sequence[int],
    *,
    app_name: str = "",
    app_version: str = "",
    app_publisher: str = "",
    compress: int = 3,
    options: bytes = bytes(6),
    fixed_size: int = 177,
) -> bytes:
    """TSetupHeader 6.4.3: 33 Strings ([0] name, [4] publisher, [9] version), 4 Ansi, fixed."""
    strings = [""] * 33
    strings[0], strings[4], strings[9] = app_name, app_publisher, app_version
    fixed = bytearray(fixed_size)
    struct.pack_into("<16i", fixed, 0, *counts)
    fixed[160] = compress
    fixed[171:177] = options
    return record(strings, [b""] * 4, bytes(fixed))


def language_entry() -> bytes:
    """TSetupLanguageEntry: "english" + 5 empty Strings, 4 empty Ansi, 21 zero bytes."""
    return record(["english"] + [""] * 5, [b""] * 4, bytes(21))


def file_entry(
    source: str, dest: str, location: int, *, options: int = 0, file_type: int = 0
) -> bytes:
    """TSetupFileEntry: source, dest + 8 empty Strings; PermissionsEntry -1."""
    fixed = bytearray(43)
    struct.pack_into("<i", fixed, 20, location)
    struct.pack_into("<hIB", fixed, 36, -1, options, file_type)
    return record([source, dest] + [""] * 8, [], bytes(fixed))


def location_entry(size: int, sha256: bytes, filetime: int, flags: int) -> bytes:
    """TSetupFileLocationEntry (85 B) with slices/offsets/versions zero."""
    out = bytearray(85)
    struct.pack_into("<Q", out, 20, size)
    out[36:68] = sha256
    struct.pack_into("<Q", out, 68, filetime)
    out[84] = flags
    return bytes(out)


def raw_lzma1(payload: bytes, dict_size: int = 1 << 16) -> bytes:
    """Raw LZMA1 (lc 3, lp 0, pb 2) as liblzma writes it (with an end marker)."""
    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": 3, "lp": 0, "pb": 2}]
    return lzma.compress(payload, format=lzma.FORMAT_RAW, filters=filters)


def framed(body: bytes) -> bytes:
    """``body`` as chunks of CRC32 u32 + up to 4096 bytes."""
    out = bytearray()
    for at in range(0, len(body), 4096):
        piece = body[at : at + 4096]
        out += struct.pack("<I", zlib.crc32(piece)) + piece
    return bytes(out)


def lzma1_block(index: int, stream: bytes, props: bytes = b"\x5d\x00\x00\x01\x00") -> bytes:
    """Block ``index`` (1 or 2): 9-byte header (flag 1) + framed props and stream."""
    assert index in (1, 2)
    body = framed(props + stream)
    head = struct.pack("<IB", len(body), 1)
    return struct.pack("<I", zlib.crc32(head)) + head + body


G7_BLOCK1 = (
    setup_header(
        (1, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0),
        app_name="Demo App",
        app_version="1.2.3",
        app_publisher="Retool Tests",
    )
    + language_entry()
    + file_entry("C:\\build\\app.exe", "{app}\\app.exe", 0)
    + file_entry("C:\\build\\readme.txt", "{app}\\readme.txt", 1)
    + struct.pack("<ii", 0, 0)
)
G7_BLOCK2 = location_entry(
    1024, hashlib.sha256(b"app").digest(), 132000000000000000, 0x12
) + location_entry(5, hashlib.sha256(b"hello").digest(), 0, 0x10)
G7_SHA256_1 = "2447b7f7484ddbb00d36ac6ceddb99a18d7acff27e057cf7b821a7feff5ab068"
G7_SHA256_2 = "9d514ff5a38dee1ed0d2394fc653be8cc55e2ce8de50f475f3fbbf52db2901d9"
# Pinned raw_lzma1 outputs (liblzma may differ across versions; regenerate per spec).
G7_STREAM1 = bytes.fromhex(
    "000800334767bfa55524c7f27430fab068044088b7b5567bc38797cea6d8284df94c2d82501c2da98fe11be4"
    "3cca634754dae977ab1d727ad86b013bea098d87f8c1262d676259f61b19031e9057583c304a65b15e396715"
    "96af8358cfdf5837b0a478ea7c8f21dd2914396f15075814d98b367ba44bd17d2473cdffd165b0a1af21c7dd"
    "c585772e91bfcc7a1d6a60233ffc6b91a6"
)
G7_STREAM2 = bytes.fromhex(
    "00006e024c98280344d919e03099067d4ac37c101baf0e0849564e0ab5a67526501c20c363d85c537d17bda2"
    "a2b6e89343def7c35d8f8296836f97878d6f00aa3ae956c6e3e131986475ec2631356ba18a4485ce4f644af2"
    "e664385c2a3555bace5cc820beffffd9058000"
)
G7_BLOCKS = lzma1_block(1, G7_STREAM1) + lzma1_block(2, G7_STREAM2)
G7 = build_inno(b"Inno Setup Setup Data (6.4.3)", G7_BLOCKS)

ID_643 = b"Inno Setup Setup Data (6.4.3)"


def lzma1_blocks(block1: bytes, block2: bytes) -> bytes:
    """Both header blocks from decoded payloads (encoded with ``raw_lzma1``)."""
    return lzma1_block(1, raw_lzma1(block1)) + lzma1_block(2, raw_lzma1(block2))


def many_files_inno(count: int = 1100) -> bytes:
    """t79/t80: ``count`` files named 129 x U+1F600 at location 0 (flags 0x18: encrypted).

    Options vary pseudo-randomly so the stream stays under the ratio tripwire.
    """
    name = "\U0001f600" * 129
    counts = [0] * 16
    counts[7], counts[8] = count, 1
    block1 = bytearray(setup_header(counts))
    for i in range(count):
        block1 += file_entry(name, name, 0, options=zlib.crc32(i.to_bytes(4, "little")))
    block1 += struct.pack("<ii", 0, 0)
    block2 = location_entry(7, bytes(32), 0, 0x18)
    return build_inno(ID_643, lzma1_blocks(bytes(block1), block2))
