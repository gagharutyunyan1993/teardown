"""Domain services: pure functions over bytes. No I/O here."""

from __future__ import annotations

from retool.formats.domain.image import (
    Image,
    MappedSegment,
    MemoryMap,
    RawLoadSpec,
)
from retool.formats.domain.model import Format
from retool.shared import ByteRange, ParseError

MAGIC_WINDOW = 4  # every magic detect() knows is <= MAGIC_WINDOW bytes

_MACHO_MAGICS = frozenset(
    {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    }
)


def detect(data: bytes) -> Format:
    """Return the container format of ``data`` based on its first bytes.

    ``MZ`` only marks a PE candidate (DOS stub); ``\\xca\\xfe\\xba\\xbe`` is shared with
    Java class files. Disambiguation is the job of the per-format parsers.
    """
    head = data[:MAGIC_WINDOW]
    if head == b"\x7fELF":
        return Format.ELF
    if head[:2] == b"MZ":
        return Format.PE
    if head in _MACHO_MAGICS:
        return Format.MACHO
    return Format.UNKNOWN


def structured_format(head: bytes) -> Format | None:
    """Return the structured format ``head`` starts with, or None. Safe for any length."""
    found = detect(head)
    return None if found is Format.UNKNOWN else found


def build_raw_image(spec: RawLoadSpec, source_size: int) -> Image:
    """Validate ``spec`` against a source of ``source_size`` bytes and build the raw image.

    ADR 0001 checks 3 and 4 live here; the value objects enforce checks 5-8.
    """
    segments: list[MappedSegment] = []
    for index, req in enumerate(spec.segments):
        off = req.file_offset
        if not 0 <= off < source_size:
            raise ParseError("segment file offset outside source", offset=off if off >= 0 else None)
        length = source_size - off if req.file_length is None else req.file_length
        if length < 1:
            raise ParseError("empty segment", offset=off)
        file = ByteRange(off, length).check_within(source_size)
        mem_size = length if req.mem_size is None else req.mem_size
        segments.append(MappedSegment(file, req.start, mem_size, req.name or f"seg{index}"))
    return Image(spec.arch, MemoryMap(tuple(segments)), spec.entry, Format.RAW)
