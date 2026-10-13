"""PE/COFF image structure (Microsoft "PE Format"): value objects and a bounded parser.

Every offset and length taken from the file is checked against the source size before a read;
table counts are capped. Malformed input raises ``ParseError`` with a static reason and the
offending offset; a short read raises ``InputChanged``. File bytes never enter a reason.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from retool.formats.domain.parsing import read_exact
from retool.formats.domain.ports import ByteSource
from retool.shared import Address, ByteRange, ParseError

MAX_SECTIONS: Final = 96
MAX_DIRS: Final = 16
MAX_IMPORT_DLLS: Final = 256
MAX_IMPORT_FUNCS: Final = 512
MAX_IMPORT_NAME: Final = 256
IMPORT_DLL_NAME_BYTES: Final = 12288
MAX_IMPORT_FUNCS_TOTAL: Final = 16384
IMPORT_TOTAL_NAME_BYTES: Final = 262144
MAX_CERTS: Final = 16
SIGNATURE_WINDOW: Final = 64
MAX_SIGNATURE_MATCHES: Final = 16
# Worst-case bytes parse_imports reads: the descriptor table (20 x 257), per DLL its name
# window (257) and thunk array (8 x 513), and one hint/name window (2 + 256 + 1) per listed
# function: 20*(DLLS+1) + DLLS*((NAME+1) + 8*(FUNCS+1)) + FUNCS_TOTAL*(2+NAME+1) = 5,365,012.
MAX_IMPORT_READ_BYTES: Final = (
    20 * (MAX_IMPORT_DLLS + 1)
    + MAX_IMPORT_DLLS * ((MAX_IMPORT_NAME + 1) + 8 * (MAX_IMPORT_FUNCS + 1))
    + MAX_IMPORT_FUNCS_TOTAL * (2 + MAX_IMPORT_NAME + 1)
)

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
_U16_MAX: Final = 0xFFFF


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


class ThunkEnd(StrEnum):
    """Why the walk of one DLL's thunk array stopped."""

    NULL = "null"  # terminating zero thunk
    CAP = "cap"  # a per-DLL or global budget was reached
    DATA_END = "data_end"  # the file-backed run ended
    UNMAPPED = "unmapped"  # an RVA is not file-backed (or a bound/corrupt PE32+ thunk)


@dataclass(frozen=True, slots=True)
class ImportedFunction:
    """One import: by ``ordinal``, or by ``hint`` and ``name`` (bytes before the NUL)."""

    ordinal: int | None
    hint: int | None
    name: bytes | None
    name_truncated: bool = False

    def __post_init__(self) -> None:
        if self.ordinal is not None:
            ok = self.hint is None and self.name is None and 0 <= self.ordinal <= _U16_MAX
        else:
            ok = (
                self.hint is not None
                and self.name is not None
                and 0 <= self.hint <= _U16_MAX
                and len(self.name) <= MAX_IMPORT_NAME
            )
        if not ok or (self.name_truncated and self.name is None):
            raise ParseError("invalid imported function")


def function_name_bytes(functions: tuple[ImportedFunction, ...]) -> int:
    """Total name bytes of ``functions`` (ordinal imports count 0)."""
    return sum(len(f.name) for f in functions if f.name is not None)


@dataclass(frozen=True, slots=True)
class ImportedDll:
    """One import descriptor, its DLL name and the functions read from its thunk array."""

    descriptor_offset: Address
    ilt_rva: int
    time_date_stamp: int
    forwarder_chain: int
    name_rva: int
    iat_rva: int
    name: bytes | None
    name_truncated: bool
    functions: tuple[ImportedFunction, ...]
    end: ThunkEnd

    def __post_init__(self) -> None:
        if not (
            len(self.functions) <= MAX_IMPORT_FUNCS
            and function_name_bytes(self.functions) <= IMPORT_DLL_NAME_BYTES
            and (self.name is None or len(self.name) <= MAX_IMPORT_NAME)
            and not (self.name_truncated and self.name is None)
        ):
            raise ParseError("invalid imported DLL")


@dataclass(frozen=True, slots=True)
class CertificateEntry:
    """WIN_CERTIFICATE header; ``length`` includes the 8-byte header, contents are not read."""

    offset: Address
    length: int
    revision: int
    certificate_type: int

    def __post_init__(self) -> None:
        if self.length < 8:
            raise ParseError("certificate length below header size")


@dataclass(frozen=True, slots=True)
class SignatureMatch:
    """A fixed-byte magic of the signature table found at a file offset."""

    name: str
    offset: Address


@dataclass(frozen=True, slots=True)
class OverlayInfo:
    """File bytes past the image: payload, then the certificate table, then trailing bytes."""

    offset: Address
    size: int
    certificate: ByteRange | None
    payload_size: int
    trailing_size: int
    signatures: tuple[SignatureMatch, ...]

    def __post_init__(self) -> None:
        cert_size = self.certificate.size if self.certificate is not None else 0
        if not (
            self.size >= 1
            and self.payload_size >= 0
            and self.trailing_size >= 0
            and self.payload_size + cert_size + self.trailing_size == self.size
            and (self.certificate is not None or self.trailing_size == 0)
            and (
                self.certificate is None
                or self.certificate.start == self.offset.value + self.payload_size
            )
            and len(self.signatures) <= MAX_SIGNATURE_MATCHES
        ):
            raise ParseError("overlay sizes inconsistent")


@dataclass(frozen=True, slots=True)
class PeFile:
    """Immutable snapshot of a parsed PE: headers, data directories and sections in file order,
    plus the import, certificate and overlay tables attached after the headers are parsed."""

    dos: DosHeader
    coff: CoffHeader
    optional: OptionalHeader
    directories: tuple[DataDirectory, ...]
    sections: tuple[PeSection, ...]
    imports: tuple[ImportedDll, ...] = ()
    certificates: tuple[CertificateEntry, ...] = ()
    overlay: OverlayInfo | None = None

    def __post_init__(self) -> None:
        if not (
            len(self.sections) == self.coff.number_of_sections <= MAX_SECTIONS
            and len(self.directories) == min(self.optional.number_of_rva_and_sizes, MAX_DIRS)
            and len(self.imports) <= MAX_IMPORT_DLLS
            and len(self.certificates) <= MAX_CERTS
            and sum(len(d.functions) for d in self.imports) <= MAX_IMPORT_FUNCS_TOTAL
            and sum(function_name_bytes(d.functions) for d in self.imports)
            <= IMPORT_TOTAL_NAME_BYTES
        ):
            raise ParseError("PE table counts inconsistent")


def directory(pe: PeFile, index: int) -> DataDirectory | None:
    """Data directory ``index`` if present (VirtualAddress and Size both non-zero)."""
    if index >= len(pe.directories):
        return None
    entry = pe.directories[index]
    return entry if entry.virtual_address != 0 and entry.size != 0 else None


def directory_offset(pe: PeFile, index: int) -> int:
    """File offset of data directory entry ``index``."""
    fixed = _LAYOUT64.size if pe.optional.bits == 64 else _LAYOUT32.size
    return pe.dos.e_lfanew.value + _SIG_SIZE + _COFF_SIZE + fixed + _DIR_SIZE * index


def section_table_end(pe: PeFile) -> int:
    """File offset just past the section table."""
    table_at = pe.dos.e_lfanew.value + _SIG_SIZE + _COFF_SIZE + pe.coff.size_of_optional_header
    return table_at + _SEC_SIZE * pe.coff.number_of_sections


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
