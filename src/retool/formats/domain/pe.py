"""PE/COFF image structure (Microsoft "PE Format"): value objects and a bounded parser.

Every offset and length taken from the file is checked against the source size before a read;
table counts are capped. Malformed input raises ``ParseError`` with a static reason and the
offending offset; a short read raises ``InputChanged``. File bytes never enter a reason.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

from retool.formats.domain.parsing import read_exact
from retool.formats.domain.ports import ByteSource
from retool.shared import Address, ParseError

MAX_SECTIONS: Final = 96
MAX_DIRS: Final = 16

PE32_MAGIC: Final = 0x10B
PE32PLUS_MAGIC: Final = 0x20B
ROM_MAGIC: Final = 0x107

SCN_CNT_CODE: Final = 0x20
SCN_CNT_INITIALIZED_DATA: Final = 0x40
SCN_CNT_UNINITIALIZED_DATA: Final = 0x80

_DOS_MAGIC: Final = 0x5A4D
_SIGNATURE: Final = b"PE\0\0"
_DOS_FMT: Final = "<H58xI"
_DOS_SIZE: Final = 64
_OFF_LFANEW: Final = 0x3C
_SIG_SIZE: Final = 4
_COFF_FMT: Final = "<HHIIIHH"
_COFF_SIZE: Final = 20
_OFF_NUMSEC: Final = 2
_OFF_SIZEOPT: Final = 16
_MAGIC_FMT: Final = "<H"
_MAGIC_SIZE: Final = 2
_DIR_FMT: Final = "<II"
_DIR_SIZE: Final = 8
_SEC_FMT: Final = "<8sIIIIIIHHI"
_SEC_SIZE: Final = 40
_NAME_SIZE: Final = 8


@dataclass(frozen=True, slots=True)
class _Layout:
    """Per-magic optional header struct format, fixed size and field offsets."""

    fmt: str
    size: int
    off_size_of_headers: int
    off_number_of_rva_and_sizes: int


_LAYOUT32: Final = _Layout("<HBB9I6H4I2H6I", 96, 60, 92)
_LAYOUT64: Final = _Layout("<HBB5IQ2I6H4I2H4Q2I", 112, 60, 108)


@dataclass(frozen=True, slots=True)
class DosHeader:
    e_magic: int
    e_lfanew: Address


@dataclass(frozen=True, slots=True)
class CoffHeader:
    machine: int
    number_of_sections: int
    time_date_stamp: int
    pointer_to_symbol_table: Address
    number_of_symbols: int
    size_of_optional_header: int
    characteristics: int


@dataclass(frozen=True, slots=True)
class OptionalHeader:
    """Optional header fields as stored; ``base_of_data`` is None for PE32+."""

    magic: int
    major_linker_version: int
    minor_linker_version: int
    size_of_code: int
    size_of_initialized_data: int
    size_of_uninitialized_data: int
    address_of_entry_point: int
    base_of_code: int
    base_of_data: int | None
    image_base: int
    section_alignment: int
    file_alignment: int
    major_os_version: int
    minor_os_version: int
    major_image_version: int
    minor_image_version: int
    major_subsystem_version: int
    minor_subsystem_version: int
    win32_version_value: int
    size_of_image: int
    size_of_headers: int
    checksum: int
    subsystem: int
    dll_characteristics: int
    size_of_stack_reserve: int
    size_of_stack_commit: int
    size_of_heap_reserve: int
    size_of_heap_commit: int
    loader_flags: int
    number_of_rva_and_sizes: int  # declared value, unclamped

    @property
    def bits(self) -> int:
        return 64 if self.magic == PE32PLUS_MAGIC else 32


@dataclass(frozen=True, slots=True)
class DataDirectory:
    """Raw directory entry; its index is its position in ``PeFile.directories``."""

    virtual_address: int
    size: int


@dataclass(frozen=True, slots=True)
class PeSection:
    """Section table entry; ``name`` is the bytes before the first NUL (at most 8)."""

    name: bytes
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: Address
    pointer_to_relocations: Address
    pointer_to_linenumbers: Address
    number_of_relocations: int
    number_of_linenumbers: int
    characteristics: int


@dataclass(frozen=True, slots=True)
class PeFile:
    """Immutable snapshot of a parsed PE: headers, data directories and sections in file order."""

    dos: DosHeader
    coff: CoffHeader
    optional: OptionalHeader
    directories: tuple[DataDirectory, ...]
    sections: tuple[PeSection, ...]

    def __post_init__(self) -> None:
        if not (
            len(self.sections) == self.coff.number_of_sections <= MAX_SECTIONS
            and len(self.directories) == min(self.optional.number_of_rva_and_sizes, MAX_DIRS)
        ):
            raise ParseError("PE table counts inconsistent")


def pe_section_kind(characteristics: int) -> str:
    """Display label from the content flags; code wins over data, data over bss."""
    if characteristics & SCN_CNT_CODE:
        return "code"
    if characteristics & SCN_CNT_INITIALIZED_DATA:
        return "data"
    if characteristics & SCN_CNT_UNINITIALIZED_DATA:
        return "bss"
    return "other"


def _ints(fmt: str, buf: bytes) -> tuple[int, ...]:
    if len(buf) != struct.calcsize(fmt):
        raise ParseError("PE struct size mismatch")
    return tuple(v for v in struct.unpack_from(fmt, buf, 0) if isinstance(v, int))


def _optional(magic: int, buf: bytes) -> OptionalHeader:
    if magic == PE32PLUS_MAGIC:
        head = _ints(_LAYOUT64.fmt, buf)
        base_of_data: int | None = None
        rest = head[8:]
    else:
        head = _ints(_LAYOUT32.fmt, buf)
        base_of_data = head[8]
        rest = head[9:]
    (
        image_base,
        section_alignment,
        file_alignment,
        major_os,
        minor_os,
        major_image,
        minor_image,
        major_subsystem,
        minor_subsystem,
        win32_version_value,
        size_of_image,
        size_of_headers,
        checksum,
        subsystem,
        dll_characteristics,
        stack_reserve,
        stack_commit,
        heap_reserve,
        heap_commit,
        loader_flags,
        number_of_rva_and_sizes,
    ) = rest
    return OptionalHeader(
        magic=head[0],
        major_linker_version=head[1],
        minor_linker_version=head[2],
        size_of_code=head[3],
        size_of_initialized_data=head[4],
        size_of_uninitialized_data=head[5],
        address_of_entry_point=head[6],
        base_of_code=head[7],
        base_of_data=base_of_data,
        image_base=image_base,
        section_alignment=section_alignment,
        file_alignment=file_alignment,
        major_os_version=major_os,
        minor_os_version=minor_os,
        major_image_version=major_image,
        minor_image_version=minor_image,
        major_subsystem_version=major_subsystem,
        minor_subsystem_version=minor_subsystem,
        win32_version_value=win32_version_value,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        checksum=checksum,
        subsystem=subsystem,
        dll_characteristics=dll_characteristics,
        size_of_stack_reserve=stack_reserve,
        size_of_stack_commit=stack_commit,
        size_of_heap_reserve=heap_reserve,
        size_of_heap_commit=heap_commit,
        loader_flags=loader_flags,
        number_of_rva_and_sizes=number_of_rva_and_sizes,
    )


def _section_name(raw: bytes) -> bytes:
    end = raw.find(b"\0")
    return raw if end < 0 else raw[:end]


def _section(buf: bytes) -> PeSection:
    ints = _ints(_SEC_FMT, buf)  # the name ("8s") is the only non-int field; dropped here
    vsize, vaddr, raw_size, raw_ptr, reloc_ptr, line_ptr, nreloc, nline, characteristics = ints
    return PeSection(
        _section_name(buf[:_NAME_SIZE]),
        vsize,
        vaddr,
        raw_size,
        Address(raw_ptr),
        Address(reloc_ptr),
        Address(line_ptr),
        nreloc,
        nline,
        characteristics,
    )


def _check_section(section: PeSection, at: int, size: int) -> None:
    raw_size = section.size_of_raw_data
    if raw_size > 0 and section.pointer_to_raw_data.value + raw_size > size:
        raise ParseError("section raw data exceeds file", offset=at)


def parse_pe(source: ByteSource) -> PeFile:
    """Parse the PE headers and section table of ``source``; raw section data is never read."""
    size = source.size
    if size < _DOS_SIZE:
        raise ParseError("DOS header exceeds file", offset=0)
    e_magic, lfanew = _ints(_DOS_FMT, read_exact(source, size, 0, _DOS_SIZE))
    if e_magic != _DOS_MAGIC:
        raise ParseError("bad DOS magic", offset=0)
    if lfanew < _DOS_SIZE:
        raise ParseError("e_lfanew inside DOS header", offset=_OFF_LFANEW)
    if lfanew + _SIG_SIZE > size:
        raise ParseError("PE signature exceeds file", offset=_OFF_LFANEW)
    if read_exact(source, size, lfanew, _SIG_SIZE) != _SIGNATURE:
        raise ParseError("bad PE signature", offset=lfanew)
    coff_at = lfanew + _SIG_SIZE
    if coff_at + _COFF_SIZE > size:
        raise ParseError("COFF header exceeds file", offset=coff_at)
    machine, nsec, stamp, symptr, nsym, sizeopt, chars = _ints(
        _COFF_FMT, read_exact(source, size, coff_at, _COFF_SIZE)
    )
    if nsec > MAX_SECTIONS:
        raise ParseError(f"section count exceeds {MAX_SECTIONS}", offset=coff_at + _OFF_NUMSEC)
    coff = CoffHeader(machine, nsec, stamp, Address(symptr), nsym, sizeopt, chars)
    opt_at = coff_at + _COFF_SIZE
    if opt_at + _MAGIC_SIZE > size:
        raise ParseError("optional header exceeds file", offset=opt_at)
    (magic,) = _ints(_MAGIC_FMT, read_exact(source, size, opt_at, _MAGIC_SIZE))
    if magic == ROM_MAGIC:
        raise ParseError("ROM optional header not supported", offset=opt_at)
    if magic not in (PE32_MAGIC, PE32PLUS_MAGIC):
        raise ParseError("invalid optional header magic", offset=opt_at)
    lay = _LAYOUT64 if magic == PE32PLUS_MAGIC else _LAYOUT32
    if sizeopt < lay.size:
        raise ParseError(
            "optional header smaller than its fixed part", offset=coff_at + _OFF_SIZEOPT
        )
    if opt_at + lay.size > size:
        raise ParseError("optional header exceeds file", offset=opt_at)
    optional = _optional(magic, read_exact(source, size, opt_at, lay.size))
    ndirs = min(optional.number_of_rva_and_sizes, MAX_DIRS)
    dirs_at = opt_at + lay.size
    if lay.size + _DIR_SIZE * ndirs > sizeopt:
        raise ParseError(
            "data directories exceed optional header",
            offset=opt_at + lay.off_number_of_rva_and_sizes,
        )
    if dirs_at + _DIR_SIZE * ndirs > size:
        raise ParseError("data directories exceed file", offset=dirs_at)
    directories: list[DataDirectory] = []
    if ndirs > 0:
        table = read_exact(source, size, dirs_at, _DIR_SIZE * ndirs)
        for i in range(ndirs):
            entry = table[i * _DIR_SIZE : (i + 1) * _DIR_SIZE]
            vaddr, dsize = _ints(_DIR_FMT, entry)
            directories.append(DataDirectory(vaddr, dsize))
    if optional.size_of_headers > size:
        raise ParseError("SizeOfHeaders exceeds file", offset=opt_at + lay.off_size_of_headers)
    table_at = opt_at + sizeopt
    sections: list[PeSection] = []
    if nsec > 0:
        if table_at + _SEC_SIZE * nsec > size:
            raise ParseError("section table exceeds file", offset=table_at)
        table = read_exact(source, size, table_at, _SEC_SIZE * nsec)
        for i in range(nsec):
            section = _section(table[i * _SEC_SIZE : (i + 1) * _SEC_SIZE])
            _check_section(section, table_at + i * _SEC_SIZE, size)
            sections.append(section)
    return PeFile(
        DosHeader(e_magic, Address(lfanew)), coff, optional, tuple(directories), tuple(sections)
    )
