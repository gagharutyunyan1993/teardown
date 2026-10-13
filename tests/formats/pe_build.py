"""Synthetic PE32/PE32+ fixtures built field by field (see slice-4 spec, ## Tests)."""

from __future__ import annotations

import struct

from tests.formats.elf_build import patch
from tests.formats.fakes import SparseSource

__all__ = [
    "P32",
    "P64",
    "PT32",
    "PT64",
    "REAL_CERT",
    "REAL_SIZE",
    "big_data",
    "build_pe",
    "build_pe_tables",
    "dir_at",
    "name",
    "p",
    "p32",
    "patch",
    "real_shape",
    "rva",
]


def _align_up(value: int, align: int) -> int:
    return (value + align - 1) // align * align


def build_pe(
    bits: int = 64, *, extra_sections: int = 0, opt_pad: int = 0, ndirs: int = 16
) -> bytes:
    is64 = bits == 64
    fixed = 112 if is64 else 96
    nsec = 2 + extra_sections
    opt = fixed + 8 * ndirs + opt_pad
    table = 0x58 + opt
    hdr = _align_up(table + 40 * nsec, 0x200)
    text_rva = _align_up(hdr, 0x1000)
    data_rva = text_rva + 0x1000
    size = hdr + 0x400
    buf = bytearray(size)
    struct.pack_into("<H", buf, 0, 0x5A4D)
    struct.pack_into("<I", buf, 0x3C, 0x40)
    buf[0x40:0x44] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        buf,
        0x44,
        0x8664 if is64 else 0x14C,
        nsec,
        0x5F000000,
        0,
        0,
        opt,
        0x22 if is64 else 0x102,
    )
    head = (0x20B if is64 else 0x10B, 14, 36, 0x200, 0x200, 0, text_rva, text_rva)
    tail = (0x1000, 0x200, 6, 1, 2, 3, 5, 4, 0, data_rva + 0x1000, hdr, 0xC0FFEE, 3)
    stack_heap = (0x100000, 0x1000, 0x80000, 0x2000, 0, ndirs)
    if is64:
        values = (*head, 0x140000000, *tail, 0x8160, *stack_heap)
        struct.pack_into("<HBB5IQ2I6H4I2H4Q2I", buf, 0x58, *values)
    else:
        values = (*head, data_rva, 0x400000, *tail, 0x8140, *stack_heap)
        struct.pack_into("<HBB9I6H4I2H6I", buf, 0x58, *values)
    if ndirs > 1:
        struct.pack_into("<II", buf, 0x58 + fixed + 8, data_rva, 0x28)
    sections = (
        (b".text", 0x10, text_rva, 0x200, hdr, 0x60000020),
        (b".data", 0x1000, data_rva, 0x200, hdr + 0x200, 0xC0000040),
    )
    for i, (name, vsize, vaddr, raw, ptr, chars) in enumerate(sections):
        struct.pack_into(
            "<8sIIIIIIHHI", buf, table + 40 * i, name, vsize, vaddr, raw, ptr, 0, 0, 0, 0, chars
        )
    buf[hdr : hdr + 16] = b"\x90" * 16
    buf[hdr + 0x200 : hdr + 0x208] = b"\x11" * 8
    return bytes(buf)


P64 = build_pe()
P32 = build_pe(32)

_WIDTH64 = {0x46: "<H", 0x54: "<H", 0x58: "<H", 0x70: "<Q"}
_WIDTH32 = {0x46: "<H", 0x54: "<H", 0x58: "<H"}


def p(*patches: tuple[int, int], data: bytes = P64) -> bytes:
    """P64 (or ``data`` with P64 layout) with each (offset, value) written at its field width."""
    for off, value in patches:
        data = patch(data, off, _WIDTH64.get(off, "<I"), value)
    return data


def p32(*patches: tuple[int, int]) -> bytes:
    """P32 with each (offset, value) written at its field width."""
    data = P32
    for off, value in patches:
        data = patch(data, off, _WIDTH32.get(off, "<I"), value)
    return data


def name(data: bytes, off: int, raw: bytes) -> bytes:
    """``data`` with the 8-byte section name at ``off`` replaced by ``raw`` (NUL-padded)."""
    return data[:off] + raw.ljust(8, b"\0") + data[off + 8 :]


def dir_at(index: int, bits: int = 64) -> int:
    """File offset of data directory entry ``index`` in ``build_pe(bits)`` (e_lfanew 0x40)."""
    return 0x58 + (112 if bits == 64 else 96) + 8 * index


def rva(offset: int) -> int:
    """RVA of a file offset inside .data of P64-shaped images (.data at file 0x400, RVA 0x2000)."""
    return offset + 0x1C00


def _thunks(values: list[int], bits: int) -> bytes:
    return b"".join(struct.pack("<Q" if bits == 64 else "<I", v) for v in values)


def build_pe_tables(bits: int = 64) -> bytes:
    """PT64 / PT32: build_pe(bits) + two import descriptors, a certificate and an overlay."""
    buf = bytearray(build_pe(bits))
    flag = 1 << (63 if bits == 64 else 31)
    struct.pack_into("<II", buf, dir_at(1, bits), 0x2000, 0x3C)
    struct.pack_into("<5I", buf, 0x400, 0x2040, 0, 0, 0x20C0, 0x2080)
    struct.pack_into("<5I", buf, 0x414, 0, 0, 0, 0x20D0, 0x20A0)
    buf[0x428:0x43C] = bytes(20)
    for at in (0x440, 0x480):
        thunks = _thunks([0x20E0, flag | 16, 0], bits)
        buf[at : at + len(thunks)] = thunks
    thunks = _thunks([0x20F0, 0], bits)
    buf[0x4A0 : 0x4A0 + len(thunks)] = thunks
    buf[0x4C0:0x4CD] = b"KERNEL32.dll\0"
    buf[0x4D0:0x4DB] = b"USER32.dll\0"
    buf[0x4E0:0x4EE] = struct.pack("<H", 0x123) + b"ExitProcess\0"
    buf[0x4F0:0x4FE] = struct.pack("<H", 2) + b"MessageBoxA\0"
    struct.pack_into("<II", buf, dir_at(4, bits), 0x20600, 0x10)
    overlay = (
        b"7z\xbc\xaf\x27\x1c"
        + bytes(65530)
        + bytes(range(256)) * 256
        + struct.pack("<IHH", 12, 0x200, 2)
        + b"\x30\x82\0\0"
        + bytes(4)
        + b"PK\x03\x04"
        + bytes(12)
    )
    return bytes(buf) + overlay


PT64 = build_pe_tables()
PT32 = build_pe_tables(32)


def big_data(raw: int) -> bytes:
    """P64 headers with .data grown to ``raw`` zero bytes at file 0x400 (VS = SizeOfRawData)."""
    data = P64[:0x400] + bytes(raw)
    return p((0x178, raw), (0x180, raw), data=data)


REAL_SIZE = 139821624
REAL_CERT = (139811888, 9736)


def real_shape() -> SparseSource:
    """The real sample's shape: PE32, 11 sections, raw end 0xd3e00, a 9736-byte certificate."""
    head = build_pe(32, extra_sections=9)
    head = patch(head, dir_at(1, 32), "<I", 0)
    head = patch(head, dir_at(1, 32) + 4, "<I", 0)
    head = patch(head, 0x168, "<I", 0xD3E00 - 0x600)
    head = patch(head, 0x170, "<I", 0xD3E00 - 0x600)
    head = patch(head, dir_at(4, 32), "<I", REAL_CERT[0])
    head = patch(head, dir_at(4, 32) + 4, "<I", REAL_CERT[1])
    tail = struct.pack("<IHH", 9729, 0x200, 2).ljust(REAL_CERT[1], b"\0")
    return SparseSource(REAL_SIZE, head=head, tail=tail)
