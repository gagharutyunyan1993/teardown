"""Format-neutral parsing contract, its result, the error guard and shared read/name helpers."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from retool.formats.domain.facts import magic_finding
from retool.formats.domain.image import Image
from retool.formats.domain.model import Format, InputChanged
from retool.formats.domain.ports import ByteSource
from retool.shared import ArchitectureId, ByteRange, Finding, NotAnalysed, ParseError


@dataclass(frozen=True, slots=True)
class SectionSummary:
    """Display row of one section; ``kind`` is a label, never compared."""

    index: int
    name: str
    kind: str
    addr: int
    offset: int
    size: int

    def __post_init__(self) -> None:
        if self.index < 0 or self.size < 0:
            raise ParseError("section summary index and size must be non-negative")


@dataclass(frozen=True, slots=True)
class ParsedContainer:
    """What a format parser established: arch, optional image, sections, facts and gaps."""

    arch: ArchitectureId | None
    image: Image | None
    sections: tuple[SectionSummary, ...]
    findings: tuple[Finding, ...]
    not_analysed: tuple[NotAnalysed, ...]

    def __post_init__(self) -> None:
        if self.image is not None and self.image.arch != self.arch:
            raise ParseError("container arch differs from image arch")


class FormatParser(Protocol):
    """Never raises except InputChanged and source I/O errors (RetoolError); any other
    malformed structure becomes NotAnalysed; reasons are static text + numbers."""

    def parse(self, source: ByteSource, producer: str) -> ParsedContainer: ...


def guarded_parse(
    fmt: Format,
    build: Callable[[ByteSource, str], ParsedContainer],
    source: ByteSource,
    producer: str,
) -> ParsedContainer:
    """Run ``build``; a rejected structure keeps the magic finding and becomes one note."""
    try:
        return build(source, producer)
    except InputChanged:
        raise
    except ParseError as exc:
        return ParsedContainer(
            None,
            None,
            (),
            (magic_finding(fmt, producer),),
            (NotAnalysed(f"{fmt.value} structure rejected: {exc}"),),
        )


def read_exact(source: ByteSource, limit: int, offset: int, size: int) -> bytes:
    """Read exactly ``size`` bytes at ``offset`` after checking the range against ``limit``."""
    rng = ByteRange(offset, size).check_within(limit)
    data = source.read(rng.start, rng.size)
    if len(data) != size:
        raise InputChanged(offset=offset)
    return data


def display_name(raw: bytes) -> str:
    """Printable ASCII kept except backslash and double quote; every other byte as ``\\xNN``."""
    return "".join(
        chr(b) if 0x20 <= b <= 0x7E and b not in (0x22, 0x5C) else f"\\x{b:02x}" for b in raw
    )
