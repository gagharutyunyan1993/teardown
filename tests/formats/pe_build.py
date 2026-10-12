"""Synthetic PE32/PE32+ fixtures built field by field (see slice-4 spec, ## Tests)."""

from __future__ import annotations

import struct

from tests.formats.elf_build import patch

__all__ = ["P32", "P64", "build_pe", "name", "p", "p32", "patch"]


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
