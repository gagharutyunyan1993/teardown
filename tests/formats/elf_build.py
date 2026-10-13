"""Synthetic ELF fixtures built with ``struct`` (spec slice-3 field tables)."""

from __future__ import annotations

import struct

STRTAB = b"\0.text\0.bss\0.shstrtab\0"  # 22 bytes; names at 1, 7, 12
U64 = 2**64 - 1
U32 = 0xFFFFFFFF


def _align_up(value: int, align: int) -> int:
    return (value + align - 1) // align * align


def patch(data: bytes, off: int, fmt: str, value: int) -> bytes:
    buf = bytearray(data)
    struct.pack_into(fmt, buf, off, value)
    return bytes(buf)


def _ehdr(
    e: str,
    bits: int,
    *,
    machine: int,
    entry: int,
    phoff: int,
    shoff: int,
    flags: int,
    phentsize: int,
    phnum: int,
    shentsize: int,
    shnum: int,
    shstrndx: int,
) -> bytes:
    cls = 2 if bits == 64 else 1
    data = 1 if e == "<" else 2
    ident = bytes([0x7F, 0x45, 0x4C, 0x46, cls, data, 1, 0]) + bytes(8)
    if bits == 64:
        fmt, ehsize = e + "16sHHIQQQIHHHHHH", 64
    else:
        fmt, ehsize = e + "16sHHIIIIIHHHHHH", 52
    return struct.pack(
        fmt, ident, 2, machine, 1, entry, phoff, shoff, flags, ehsize, phentsize, phnum,
        shentsize, shnum, shstrndx,
    )  # fmt: skip


def _phdr(e: str, bits: int, ptype: int, flags: int, offset: int, vaddr: int, paddr: int,
          filesz: int, memsz: int, align: int) -> bytes:  # fmt: skip
    if bits == 64:
        return struct.pack(e + "IIQQQQQQ", ptype, flags, offset, vaddr, paddr, filesz, memsz, align)
    return struct.pack(e + "8I", ptype, offset, vaddr, paddr, filesz, memsz, flags, align)


def _shdr(e: str, bits: int, name: int, stype: int, flags: int, addr: int, offset: int,
          size: int, link: int, info: int, addralign: int, entsize: int) -> bytes:  # fmt: skip
    fmt = e + ("IIQQQQIIQQ" if bits == 64 else "10I")
    return struct.pack(fmt, name, stype, flags, addr, offset, size, link, info, addralign, entsize)


def build_elf(
    bits: int = 64, msb: bool = False, *, phent_pad: int = 0, shent_pad: int = 0
) -> bytes:
    """F64 = ``build_elf()``, F32 = ``build_elf(32, msb=True)``: two LOADs, four sections."""
    e = ">" if msb else "<"
    ehsize, pent, sent = (64, 56, 64) if bits == 64 else (52, 32, 40)
    phent, shent = pent + phent_pad, sent + shent_pad
    phoff = ehsize
    text = phoff + 2 * phent
    data = text + 16
    strtab = data + 8
    shoff = _align_up(strtab + len(STRTAB), 8 if bits == 64 else 4)
    size = shoff + 4 * shent
    base = 0x400000 if bits == 64 else 0x8000
    out = bytearray(size)
    out[0:ehsize] = _ehdr(
        e, bits, machine=62 if bits == 64 else 40, entry=base + text, phoff=phoff, shoff=shoff,
        flags=0, phentsize=phent, phnum=2, shentsize=shent, shnum=4, shstrndx=3,
    )  # fmt: skip
    data_vaddr = base + 0x1000 + data
    phdrs = (
        _phdr(e, bits, 1, 5, 0, base, base, data, data, 0x1000),
        _phdr(e, bits, 1, 6, data, data_vaddr, data_vaddr, 8, 0x100, 0x1000),
    )
    for i, raw in enumerate(phdrs):
        out[phoff + i * phent : phoff + i * phent + pent] = raw
    out[text : text + 16] = b"\x90" * 16
    out[data : data + 8] = b"\x11" * 8
    out[strtab : strtab + len(STRTAB)] = STRTAB
    shdrs = (
        _shdr(e, bits, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        _shdr(e, bits, 1, 1, 6, base + text, text, 0x10, 0, 0, 16, 0),
        _shdr(e, bits, 7, 8, 3, data_vaddr + 8, strtab, 0xF8, 0, 0, 8, 0),
        _shdr(e, bits, 12, 3, 0, 0, strtab, len(STRTAB), 0, 0, 1, 0),
    )
    for i, raw in enumerate(shdrs):
        out[shoff + i * shent : shoff + i * shent + sent] = raw
    return bytes(out)


def build_worst_elf() -> bytes:
    """ELF64 LSB at every cap: 512 phdrs, 3072 shdrs, 256-byte names, all-ones values."""
    e, phnum, shnum = "<", 512, 3072
    phoff = 64
    shoff = phoff + phnum * 56
    table_off = shoff + shnum * 64
    table = b"\0" + b"\x01" * 256 + b"\0"
    head = _ehdr(
        e, 64, machine=62, entry=U64, phoff=phoff, shoff=shoff, flags=U32, phentsize=56,
        phnum=phnum, shentsize=64, shnum=shnum, shstrndx=shnum - 1,
    )  # fmt: skip
    phdr = _phdr(e, 64, U32, U32, U64, U64, U64, 0, U64, U64)
    shdr = _shdr(e, 64, 1, 8, U64, U64, U64, U64, U32, U32, U64, U64)
    names = _shdr(e, 64, 1, 3, 0, 0, table_off, len(table), 0, 0, 0, 0)
    return head + phdr * phnum + shdr * (shnum - 1) + names + table


F64 = build_elf()
F32 = build_elf(32, msb=True)

_EHDR64 = {16: "H", 18: "H", 20: "I", 24: "Q", 32: "Q", 40: "Q", 48: "I"}
_PHDR64 = {0: "I", 4: "I"}  # every other phdr field is 8 bytes
_SHDR64 = {0: "I", 4: "I", 40: "I", 44: "I"}  # every other shdr field is 8 bytes


def _fmt64(off: int) -> str:
    """Field width of F64 at ``off`` (header, phdr table at 0x40, shdr table at 0xe0)."""
    if off < 64:
        return "<" + _EHDR64.get(off, "H")
    if 0x40 <= off < 0xB0:
        return "<" + _PHDR64.get((off - 0x40) % 56, "Q")
    if 0xE0 <= off < 0x1E0:
        return "<" + _SHDR64.get((off - 0xE0) % 64, "Q")
    raise AssertionError(f"no F64 field at 0x{off:x}")


def p(*patches: tuple[int, int]) -> bytes:
    data = F64
    for off, value in patches:
        data = patch(data, off, _fmt64(off), value)
    return data


def byte(data: bytes, off: int, value: int) -> bytes:
    return patch(data, off, "B", value)
