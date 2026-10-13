"""Inno Setup 6.4.3 decoded setup data: setup header, entry lists and file locations.

Leaf module: imports only ``shared`` and stdlib. Layouts from issrc@is-6_4_3
``Projects/Src/Shared.Struct.pas`` (see the slice-6b spec, ## Binary layout). Decoded offsets
are relative to the decoded block start; they are plain ints, never ``Address`` and never a
``ParseError`` offset (ADR 0003), so errors carry them in the text only.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from retool.shared import ParseError

MAX_INNO_STRING: Final = 1 << 24
MAX_INNO_ENTRIES: Final = 1 << 16
MAX_INNO_ENTRIES_TOTAL: Final = 1 << 18
MAX_WIZARD_IMAGES: Final = 64
LOCATION_SIZE: Final = 85
COUNT_NAMES: Final[tuple[str, ...]] = (
    "language",
    "custom_message",
    "permission",
    "type",
    "component",
    "task",
    "dir",
    "file",
    "file_location",
    "icon",
    "ini",
    "registry",
    "install_delete",
    "uninstall_delete",
    "run",
    "uninstall_run",
)
# (name, offset, size) of the 177-byte fixed part of TSetupHeader 6.4.3.
HEADER_FIELDS: Final[tuple[tuple[str, int, int], ...]] = (
    ("counts", 0, 64),
    ("min_version", 64, 10),
    ("only_below_version", 74, 10),
    ("wizard_style", 84, 1),
    ("wizard_size_percent_x", 85, 4),
    ("wizard_size_percent_y", 89, 4),
    ("wizard_image_alpha_format", 93, 1),
    ("password_test", 94, 4),
    ("encryption_kdf_salt", 98, 16),
    ("encryption_kdf_iterations", 114, 4),
    ("encryption_base_nonce", 118, 24),
    ("extra_disk_space_required", 142, 8),
    ("slices_per_disk", 150, 4),
    ("uninstall_log_mode", 154, 1),
    ("dir_exists_warning", 155, 1),
    ("privileges_required", 156, 1),
    ("privileges_required_overrides_allowed", 157, 1),
    ("show_language_dialog", 158, 1),
    ("language_detection_method", 159, 1),
    ("compress_method", 160, 1),
    ("disable_dir_page", 161, 1),
    ("disable_program_group_page", 162, 1),
    ("uninstall_display_size", 163, 8),
    ("options", 171, 6),
)
LOCATION_FLAG_NAMES: Final[tuple[str, ...]] = (
    "version_info_valid",
    "timestamp_utc",
    "call_instruction_optimized",
    "chunk_encrypted",
    "chunk_compressed",
)

_APP_NAME: Final = 0
_APP_PUBLISHER: Final = 4
_APP_VERSION: Final = 9
_DLL_METHODS: Final = (1, 2)  # cmZip, cmBzip carry a decompressor DLL
_U8: Final = 0xFF
_U32: Final = 0xFFFFFFFF
_U64: Final = (1 << 64) - 1
_SHA256_SIZE: Final = 32


class Cursor:
    """Forward reader over decoded bytes; local to one parse call, never stored."""

    __slots__ = ("_data", "_label", "_limit", "_pos")

    def __init__(
        self, data: bytes, *, label: str, start: int = 0, limit: int | None = None
    ) -> None:
        end = len(data) if limit is None else limit
        if not 0 <= start <= end <= len(data):
            raise ParseError(f"inno {label} cursor bounds invalid at decoded offset 0x{start:x}")
        self._data = data
        self._label = label
        self._pos = start
        self._limit = end

    @property
    def pos(self) -> int:
        return self._pos

    @property
    def remaining(self) -> int:
        return self._limit - self._pos

    def _error(self, what: str, at: int) -> ParseError:
        return ParseError(f"inno {self._label} {what} at decoded offset 0x{at:x}")

    def read_fixed(self, size: int) -> bytes:
        if not 0 <= size <= self.remaining:
            raise self._error("record truncated", self._pos)
        start = self._pos
        self._pos += size
        return self._data[start : self._pos]

    def read_i32(self) -> int:
        value: int = struct.unpack("<i", self.read_fixed(4))[0]
        return value

    def _length(self, *, wide: bool) -> int:
        at = self._pos
        n = self.read_i32()
        if n < 0:
            raise self._error(f"string length {n} negative", at)
        if wide and n % 2:
            raise self._error(f"string length {n} odd", at)
        if n > MAX_INNO_STRING:
            raise self._error(f"string length {n} too large", at)
        if n > self.remaining:
            raise self._error(f"string length {n} past end", at)
        return n

    def read_string(self) -> bytes:
        """A ``String``: i32 byte count + UTF-16LE bytes (raw)."""
        return self.read_fixed(self._length(wide=True))

    def read_ansi(self) -> bytes:
        """An ``AnsiString``: i32 byte count + raw bytes."""
        return self.read_fixed(self._length(wide=False))


@dataclass(frozen=True, slots=True)
class RecordSpec:
    """A record: ``strings`` Strings, ``ansi`` AnsiStrings, ``fixed`` raw bytes; its count slot."""

    name: str
    count_index: int | None  # index into COUNT_NAMES; None = not a list
    strings: int
    ansi: int
    fixed: int

    def __post_init__(self) -> None:
        if not (
            self.name
            and (self.count_index is None or 0 <= self.count_index < len(COUNT_NAMES))
            and min(self.strings, self.ansi, self.fixed) >= 0
        ):
            raise ParseError("inno record spec inconsistent")

    @property
    def min_size(self) -> int:
        return 4 * (self.strings + self.ansi) + self.fixed


SETUP_HEADER_643: Final = RecordSpec("setup_header", None, 33, 4, 177)
LISTS_643: Final[tuple[RecordSpec, ...]] = (
    RecordSpec("language", 0, 6, 4, 21),
    RecordSpec("custom_message", 1, 2, 0, 4),
    RecordSpec("permission", 2, 0, 1, 0),
    RecordSpec("type", 3, 4, 0, 30),
    RecordSpec("component", 4, 5, 0, 42),
    RecordSpec("task", 5, 6, 0, 26),
    RecordSpec("dir", 6, 7, 0, 27),
    RecordSpec("file", 7, 10, 0, 43),
    RecordSpec("icon", 9, 13, 0, 48),
    RecordSpec("ini", 10, 10, 0, 21),
    RecordSpec("registry", 11, 9, 0, 29),
    RecordSpec("install_delete", 12, 7, 0, 21),
    RecordSpec("uninstall_delete", 13, 7, 0, 21),
    RecordSpec("run", 14, 13, 0, 27),
    RecordSpec("uninstall_run", 15, 13, 0, 27),
)
_FILE_COUNT: Final = COUNT_NAMES.index("file")
_LOCATION_COUNT: Final = COUNT_NAMES.index("file_location")


@dataclass(frozen=True, slots=True)
class Record:
    """One record read with a ``RecordSpec``; strings are raw bytes."""

    decoded_offset: int
    strings: tuple[bytes, ...]
    ansi: tuple[bytes, ...]
    fixed: bytes

    def __post_init__(self) -> None:
        if self.decoded_offset < 0:
            raise ParseError("inno record decoded offset negative")


def read_record(cur: Cursor, spec: RecordSpec) -> Record:
    """Read the Strings, then the AnsiStrings, then the fixed bytes of one ``spec`` record."""
    at = cur.pos
    strings = tuple(cur.read_string() for _ in range(spec.strings))
    ansi = tuple(cur.read_ansi() for _ in range(spec.ansi))
    return Record(at, strings, ansi, cur.read_fixed(spec.fixed))


class InnoCompressMethod(StrEnum):
    """TSetupCompressMethod; ids 0..4 in declaration order."""

    STORED = "stored"
    ZIP = "zip"
    BZIP = "bzip"
    LZMA = "lzma"
    LZMA2 = "lzma2"


class InnoFileType(StrEnum):
    """TSetupFileEntry.FileType; ids 0, 1."""

    USER_FILE = "user_file"
    UNINSTALL_EXE = "uninstall_exe"


def _utf16(raw: bytes) -> bool:
    return len(raw) % 2 == 0 and len(raw) <= MAX_INNO_STRING


def _field(name: str) -> tuple[int, int]:
    """(offset, size) of the ``HEADER_FIELDS`` row ``name``."""
    for row, offset, size in HEADER_FIELDS:
        if row == name:
            return offset, size
    raise KeyError(name)


@dataclass(frozen=True, slots=True)
class InnoHeader:
    """The kept part of TSetupHeader: three display strings, entry counts, compression, options."""

    app_name: bytes
    app_version: bytes
    app_publisher: bytes
    counts: tuple[int, ...]
    compress_method: int
    options: bytes

    def __post_init__(self) -> None:
        if not (
            _utf16(self.app_name)
            and _utf16(self.app_version)
            and _utf16(self.app_publisher)
            and len(self.counts) == len(COUNT_NAMES)
            and 0 <= self.compress_method <= _U8
            and len(self.options) == _field("options")[1]
        ):
            raise ParseError("inno setup header fields inconsistent")
        for name, count in zip(COUNT_NAMES, self.counts, strict=True):
            if not 0 <= count <= MAX_INNO_ENTRIES:
                raise ParseError(f"inno {name} count {count} out of range")
        total = sum(self.counts)
        if total > MAX_INNO_ENTRIES_TOTAL:
            raise ParseError(f"inno entry total {total} too large")

    @property
    def num_files(self) -> int:
        return self.counts[_FILE_COUNT]

    @property
    def num_locations(self) -> int:
        return self.counts[_LOCATION_COUNT]

    @property
    def compress_name(self) -> InnoCompressMethod | None:
        methods = tuple(InnoCompressMethod)
        return methods[self.compress_method] if self.compress_method < len(methods) else None


@dataclass(frozen=True, slots=True)
class InnoFileEntry:
    """The kept part of one TSetupFileEntry and its decoded offset in block 1."""

    decoded_offset: int
    source: bytes
    dest: bytes
    location: int
    options: int
    file_type: int

    def __post_init__(self) -> None:
        if not (
            self.decoded_offset >= 0
            and _utf16(self.source)
            and _utf16(self.dest)
            and -(1 << 31) <= self.location < (1 << 31)
            and 0 <= self.options <= _U32
            and 0 <= self.file_type <= _U8
        ):
            raise ParseError("inno file entry fields inconsistent")

    @property
    def file_type_name(self) -> InnoFileType | None:
        types = tuple(InnoFileType)
        return types[self.file_type] if self.file_type < len(types) else None


@dataclass(frozen=True, slots=True)
class InnoFileLocation:
    """The kept part of one TSetupFileLocationEntry (block 2)."""

    index: int
    original_size: int
    sha256: bytes
    filetime: int
    flags: int

    def __post_init__(self) -> None:
        if not (
            self.index >= 0
            and 0 <= self.original_size <= _U64
            and len(self.sha256) == _SHA256_SIZE
            and 0 <= self.filetime <= _U64
            and 0 <= self.flags <= _U8
        ):
            raise ParseError("inno file location fields inconsistent")

    def _bit(self, name: str) -> bool:
        return bool(self.flags >> LOCATION_FLAG_NAMES.index(name) & 1)

    @property
    def version_info_valid(self) -> bool:
        return self._bit("version_info_valid")

    @property
    def timestamp_utc(self) -> bool:
        return self._bit("timestamp_utc")

    @property
    def call_instruction_optimized(self) -> bool:
        return self._bit("call_instruction_optimized")

    @property
    def chunk_encrypted(self) -> bool:
        return self._bit("chunk_encrypted")

    @property
    def chunk_compressed(self) -> bool:
        return self._bit("chunk_compressed")


@dataclass(frozen=True, slots=True)
class InnoSetupBlock:
    """Block 1 parsed: the header and every file entry."""

    header: InnoHeader
    files: tuple[InnoFileEntry, ...]

    def __post_init__(self) -> None:
        if len(self.files) != self.header.num_files:
            raise ParseError("inno setup block file count inconsistent")


def _header(rec: Record) -> InnoHeader:
    counts_at, counts_size = _field("counts")
    method_at, _ = _field("compress_method")
    options_at, options_size = _field("options")
    counts = struct.unpack_from(f"<{counts_size // 4}i", rec.fixed, counts_at)
    return InnoHeader(
        rec.strings[_APP_NAME],
        rec.strings[_APP_VERSION],
        rec.strings[_APP_PUBLISHER],
        tuple(counts),
        rec.fixed[method_at],
        rec.fixed[options_at : options_at + options_size],
    )


def _file_entry(rec: Record) -> InnoFileEntry:
    location, options, file_type = struct.unpack_from("<i14xIB", rec.fixed, 20)
    return InnoFileEntry(
        rec.decoded_offset, rec.strings[0], rec.strings[1], location, options, file_type
    )


def _blob(cur: Cursor, what: str) -> None:
    size = cur.read_i32()
    if size < 0 or size > cur.remaining:
        raise ParseError(f"inno {what} size {size} invalid")
    cur.read_fixed(size)


def parse_setup_643(data: bytes) -> InnoSetupBlock:
    """Parse the whole decoded block 1; every byte must be accounted for (S9)."""
    cur = Cursor(data, label="block1")
    header = _header(read_record(cur, SETUP_HEADER_643))
    files: list[InnoFileEntry] = []
    for spec in LISTS_643:
        if spec.count_index is None:
            raise ParseError(f"inno record spec {spec.name} is not a list")
        count = header.counts[spec.count_index]
        if count * spec.min_size > cur.remaining:
            raise ParseError(f"inno {spec.name} list past end at decoded offset 0x{cur.pos:x}")
        for _ in range(count):
            rec = read_record(cur, spec)
            if spec.count_index == _FILE_COUNT:
                files.append(_file_entry(rec))
    for _ in range(2):  # wizard images, then small wizard images
        n = cur.read_i32()
        if not 0 <= n <= MAX_WIZARD_IMAGES:
            raise ParseError(f"inno wizard image count {n} out of range")
        for _ in range(n):
            _blob(cur, "wizard image")
    if header.compress_method in _DLL_METHODS:
        _blob(cur, "decompressor")
    if cur.remaining:
        raise ParseError(f"inno block1 has {cur.remaining} trailing bytes")
    return InnoSetupBlock(header, tuple(files))


def parse_locations_643(data: bytes, count: int) -> tuple[InnoFileLocation, ...]:
    """Parse decoded block 2: exactly ``count`` 85-byte file location entries."""
    if count < 0 or len(data) != count * LOCATION_SIZE:
        raise ParseError(f"inno block2 size {len(data)} is not {count} x {LOCATION_SIZE}")
    locations: list[InnoFileLocation] = []
    for i in range(count):
        at = i * LOCATION_SIZE
        size = int.from_bytes(data[at + 20 : at + 28], "little")
        filetime = int.from_bytes(data[at + 68 : at + 76], "little")
        sha = data[at + 36 : at + 36 + _SHA256_SIZE]
        locations.append(InnoFileLocation(i, size, sha, filetime, data[at + 84]))
    return tuple(locations)
