"""ELF structure (gABI ch4/ch5): value objects and a bounded parser over ``ByteSource``.

Every offset and length taken from the file is checked against the source size before a read;
table counts are capped. Malformed input raises ``ParseError`` with a static reason and the
offending offset; a short read raises ``InputChanged``. File bytes never enter a reason.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, replace
from enum import IntEnum
from typing import Final

from retool.formats.domain.model import InputChanged
from retool.formats.domain.ports import ByteSource
from retool.shared import Address, ByteRange, ParseError

MAX_PHNUM: Final = 512
MAX_SHNUM: Final = 3072
MAX_SHSTRTAB: Final = 1 << 20
MAX_SECTION_NAME: Final = 256

PT_NULL: Final = 0
PT_LOAD: Final = 1
SHT_NULL: Final = 0
SHT_STRTAB: Final = 3
SHT_NOBITS: Final = 8
PN_XNUM: Final = 0xFFFF
SHN_XINDEX: Final = 0xFFFF

_MAGIC: Final = b"\x7fELF"
_EI_NIDENT: Final = 16
_EV_CURRENT: Final = 1
_OFF_CLASS: Final = 4
_OFF_DATA: Final = 5
_OFF_VERSION: Final = 6
_OFF_E_VERSION: Final = 20
_OFF_SH_TYPE: Final = 4


class ElfClass(IntEnum):
    ELF32 = 1
    ELF64 = 2


class ElfData(IntEnum):
    LSB = 1
    MSB = 2


@dataclass(frozen=True, slots=True)
class _Layout:
    """Per-class struct formats (without byte order), struct sizes and field offsets."""

    ehdr: str
    phdr: str
    shdr: str
    ehsize: int
    phentsize: int
    shentsize: int
    off_ehsize: int
    off_phentsize: int
    off_phnum: int
    off_shentsize: int
    off_shnum: int
    off_shstrndx: int
    sh_size: int
    sh_link: int
    sh_info: int


_LAYOUT32: Final = _Layout(
    "16sHHIIIIIHHHHHH", "8I", "10I", 52, 32, 40, 40, 42, 44, 46, 48, 50, 20, 24, 28
)
_LAYOUT64: Final = _Layout(
    "16sHHIQQQIHHHHHH", "IIQQQQQQ", "IIQQQQIIQQ", 64, 56, 64, 52, 54, 56, 58, 60, 62, 32, 40, 44
)


@dataclass(frozen=True, slots=True)
class ElfHeader:
    """ELF header; ``e_phnum``, ``e_shnum`` and ``e_shstrndx`` are effective (escapes resolved)."""

    ei_class: ElfClass
    ei_data: ElfData
    ei_osabi: int
    ei_abiversion: int
    e_type: int
    e_machine: int
    e_entry: Address
    e_phoff: Address
    e_shoff: Address
    e_flags: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int

    @property
    def bits(self) -> int:
        return 32 if self.ei_class is ElfClass.ELF32 else 64


@dataclass(frozen=True, slots=True)
class ProgramHeader:
    p_type: int
    p_flags: int
    p_offset: Address
    p_vaddr: Address
    p_paddr: Address
    p_filesz: int
    p_memsz: int
    p_align: int


@dataclass(frozen=True, slots=True)
class SectionHeader:
    """Section header; ``name`` is b"" for no name or when the file has no name table."""

    sh_name: int
    name: bytes
    sh_type: int
    sh_flags: int
    sh_addr: Address
    sh_offset: Address
    sh_size: int
    sh_link: int
    sh_info: int
    sh_addralign: int
    sh_entsize: int


@dataclass(frozen=True, slots=True)
class ElfFile:
    """Immutable snapshot of a parsed ELF: header and both tables in file order."""

    header: ElfHeader
    program_headers: tuple[ProgramHeader, ...]
    section_headers: tuple[SectionHeader, ...]

    def __post_init__(self) -> None:
        phnum, shnum = self.header.e_phnum, self.header.e_shnum
        if not (
            len(self.program_headers) == phnum <= MAX_PHNUM
            and len(self.section_headers) == shnum <= MAX_SHNUM
        ):
            raise ParseError("ELF table counts inconsistent")


def display_name(raw: bytes) -> str:
    """Printable ASCII kept except backslash and double quote; every other byte as ``\\xNN``."""
    return "".join(
        chr(b) if 0x20 <= b <= 0x7E and b not in (0x22, 0x5C) else f"\\x{b:02x}" for b in raw
    )


def section_kind(sh_type: int) -> str:
    """Display label of a section type; never compared by code."""
    match sh_type:
        case 0:
            return "null"
        case 1:
            return "progbits"
        case 2:
            return "symtab"
        case 3:
            return "strtab"
        case 7:
            return "note"
        case 8:
            return "nobits"
        case 18:
            return "symtab_shndx"
        case _:
            return f"type-0x{sh_type:x}"


def _read(source: ByteSource, limit: int, offset: int, size: int) -> bytes:
    rng = ByteRange(offset, size).check_within(limit)
    data = source.read(rng.start, rng.size)
    if len(data) != size:
        raise InputChanged(offset=offset)
    return data


def _ints(fmt: str, buf: bytes) -> tuple[int, ...]:
    if len(buf) != struct.calcsize(fmt):
        raise ParseError("ELF struct size mismatch")
    # The ident field ("16s") is the only non-int field; it is dropped here.
    return tuple(v for v in struct.unpack_from(fmt, buf, 0) if isinstance(v, int))


def _program(fmt: str, is64: bool, buf: bytes) -> ProgramHeader:
    if is64:
        p_type, flags, offset, vaddr, paddr, filesz, memsz, align = _ints(fmt, buf)
    else:
        p_type, offset, vaddr, paddr, filesz, memsz, flags, align = _ints(fmt, buf)
    return ProgramHeader(
        p_type, flags, Address(offset), Address(vaddr), Address(paddr), filesz, memsz, align
    )


def _section(fmt: str, buf: bytes) -> SectionHeader:
    name, sh_type, flags, addr, offset, size, link, info, addralign, entsize = _ints(fmt, buf)
    return SectionHeader(
        name,
        b"",
        sh_type,
        flags,
        Address(addr),
        Address(offset),
        size,
        link,
        info,
        addralign,
        entsize,
    )


def _check_segment(ph: ProgramHeader, at: int, size: int, bits: int) -> None:
    if ph.p_type != PT_NULL and ph.p_filesz > 0 and ph.p_offset.value + ph.p_filesz > size:
        raise ParseError("segment file range exceeds file", offset=at)
    if ph.p_type == PT_LOAD and ph.p_filesz > ph.p_memsz:
        raise ParseError("PT_LOAD filesz exceeds memsz", offset=at)
    if ph.p_type == PT_LOAD and ph.p_vaddr.value + ph.p_memsz > 1 << bits:
        raise ParseError("PT_LOAD exceeds address space", offset=at)


def _check_section(sh: SectionHeader, at: int, size: int) -> None:
    if sh.sh_type not in (SHT_NULL, SHT_NOBITS) and sh.sh_offset.value + sh.sh_size > size:
        raise ParseError("section file range exceeds file", offset=at)


def _names(table: bytes, sections: list[SectionHeader], at: list[int]) -> list[SectionHeader]:
    out: list[SectionHeader] = []
    for sh, ent in zip(sections, at, strict=True):
        if sh.sh_name == 0:
            out.append(sh)
            continue
        if sh.sh_name >= len(table):
            raise ParseError("section name offset past string table", offset=ent)
        end = table.find(b"\0", sh.sh_name, min(len(table), sh.sh_name + MAX_SECTION_NAME + 1))
        if end < 0:
            raise ParseError(f"section name exceeds {MAX_SECTION_NAME} bytes", offset=ent)
        out.append(replace(sh, name=table[sh.sh_name : end]))
    return out


def _name_table(source: ByteSource, size: int, tab: SectionHeader, ent: int) -> bytes:
    if tab.sh_type != SHT_STRTAB:
        raise ParseError("section name table is not SHT_STRTAB", offset=ent + _OFF_SH_TYPE)
    if tab.sh_size > MAX_SHSTRTAB:
        raise ParseError(f"section name table exceeds {MAX_SHSTRTAB} bytes", offset=ent)
    if tab.sh_size == 0:
        return b""
    start = tab.sh_offset.value
    table = _read(source, size, start, tab.sh_size)
    if table[0] != 0:
        raise ParseError("section name table does not start with NUL", offset=start)
    if table[-1] != 0:
        raise ParseError("section name table does not end with NUL", offset=start + len(table) - 1)
    return table


def parse_elf(source: ByteSource) -> ElfFile:
    """Parse the ELF header, both tables and section names; checks run in the spec's order."""
    size = source.size
    if size < _EI_NIDENT:
        raise ParseError("ELF identification exceeds file", offset=0)
    ident = _read(source, size, 0, _EI_NIDENT)
    if ident[:4] != _MAGIC:
        raise ParseError("bad ELF magic", offset=0)
    if ident[_OFF_CLASS] not in (ElfClass.ELF32, ElfClass.ELF64):
        raise ParseError("invalid EI_CLASS", offset=_OFF_CLASS)
    if ident[_OFF_DATA] not in (ElfData.LSB, ElfData.MSB):
        raise ParseError("invalid EI_DATA", offset=_OFF_DATA)
    if ident[_OFF_VERSION] != _EV_CURRENT:
        raise ParseError("invalid EI_VERSION", offset=_OFF_VERSION)
    ei_class = ElfClass(ident[_OFF_CLASS])
    ei_data = ElfData(ident[_OFF_DATA])
    lay = _LAYOUT32 if ei_class is ElfClass.ELF32 else _LAYOUT64
    is64 = ei_class is ElfClass.ELF64
    bits = 64 if is64 else 32
    order = "<" if ei_data is ElfData.LSB else ">"
    if size < lay.ehsize:
        raise ParseError("ELF header exceeds file", offset=0)
    head = _read(source, size, 0, lay.ehsize)
    (
        e_type,
        e_machine,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = _ints(order + lay.ehdr, head)
    if e_version != _EV_CURRENT:
        raise ParseError("invalid e_version", offset=_OFF_E_VERSION)
    if e_ehsize < lay.ehsize:
        raise ParseError("e_ehsize smaller than ELF header", offset=lay.off_ehsize)

    shdr_fmt = order + lay.shdr
    sh0: SectionHeader | None = None
    shnum = 0
    if e_shoff == 0:
        if e_shnum != 0:
            raise ParseError("e_shnum set without e_shoff", offset=lay.off_shnum)
        if e_shstrndx != 0:
            raise ParseError("e_shstrndx set without e_shoff", offset=lay.off_shstrndx)
    else:
        if e_shentsize < lay.shentsize:
            raise ParseError("e_shentsize smaller than section header", offset=lay.off_shentsize)
        if e_shoff + e_shentsize > size:
            raise ParseError("section header table exceeds file", offset=e_shoff)
        sh0 = _section(shdr_fmt, _read(source, size, e_shoff, lay.shentsize))
        shnum, shnum_at = e_shnum, lay.off_shnum
        if e_shnum == 0:
            shnum, shnum_at = sh0.sh_size, e_shoff + lay.sh_size
            if shnum == 0:
                raise ParseError("section count is zero", offset=shnum_at)
        if shnum > MAX_SHNUM:
            raise ParseError(f"section count exceeds {MAX_SHNUM}", offset=shnum_at)
        if e_shoff + e_shentsize * shnum > size:
            raise ParseError("section header table exceeds file", offset=e_shoff)

    phnum, phnum_at = e_phnum, lay.off_phnum
    if e_phnum == PN_XNUM:
        if sh0 is None:
            raise ParseError("PN_XNUM without section header table", offset=lay.off_phnum)
        phnum, phnum_at = sh0.sh_info, e_shoff + lay.sh_info
    if phnum > MAX_PHNUM:
        raise ParseError(f"program header count exceeds {MAX_PHNUM}", offset=phnum_at)
    if e_phoff == 0 and phnum != 0:
        raise ParseError("e_phnum set without e_phoff", offset=lay.off_phnum)
    if phnum > 0:
        if e_phentsize < lay.phentsize:
            raise ParseError("e_phentsize smaller than program header", offset=lay.off_phentsize)
        if e_phoff + e_phentsize * phnum > size:
            raise ParseError("program header table exceeds file", offset=e_phoff)

    phdr_fmt = order + lay.phdr
    phdrs: list[ProgramHeader] = []
    for i in range(phnum):
        at = e_phoff + i * e_phentsize
        ph = _program(phdr_fmt, is64, _read(source, size, at, lay.phentsize))
        _check_segment(ph, at, size, bits)
        phdrs.append(ph)

    shdrs: list[SectionHeader] = []
    ents: list[int] = []
    if sh0 is not None:
        _check_section(sh0, e_shoff, size)
        shdrs.append(sh0)
        ents.append(e_shoff)
    for i in range(1, shnum):
        at = e_shoff + i * e_shentsize
        sh = _section(shdr_fmt, _read(source, size, at, lay.shentsize))
        _check_section(sh, at, size)
        shdrs.append(sh)
        ents.append(at)

    shstrndx, shstrndx_at = e_shstrndx, lay.off_shstrndx
    if sh0 is not None and e_shstrndx == SHN_XINDEX:
        shstrndx, shstrndx_at = sh0.sh_link, e_shoff + lay.sh_link
    if shstrndx != 0 and shstrndx >= shnum:
        raise ParseError("e_shstrndx out of range", offset=shstrndx_at)
    if shstrndx != 0:
        table = _name_table(source, size, shdrs[shstrndx], ents[shstrndx])
        shdrs = _names(table, shdrs, ents)

    header = ElfHeader(
        ei_class=ei_class,
        ei_data=ei_data,
        ei_osabi=ident[7],
        ei_abiversion=ident[8],
        e_type=e_type,
        e_machine=e_machine,
        e_entry=Address(e_entry),
        e_phoff=Address(e_phoff),
        e_shoff=Address(e_shoff),
        e_flags=e_flags,
        e_ehsize=e_ehsize,
        e_phentsize=e_phentsize,
        e_phnum=phnum,
        e_shentsize=e_shentsize,
        e_shnum=shnum,
        e_shstrndx=shstrndx,
    )
    return ElfFile(header, tuple(phdrs), tuple(shdrs))
