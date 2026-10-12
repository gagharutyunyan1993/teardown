"""Memory image of a loaded binary: segments mapped into address spaces (ADR 0001).

Value objects only; they hold no bytes. Zero-fill beyond a segment's file data is virtual.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import pairwise

from retool.formats.domain.model import Format
from retool.shared import AddressSpace, ArchitectureId, ByteRange, ParseError, SpaceAddress

MAX_SEGMENTS = 64
MAX_IMAGE_SIZE = 1 << 32  # (assumption) Ghidra MAX_BINARY_SIZE analogue
DEFAULT_SPACE = AddressSpace("ram", 64)
_SEGMENT_NAME = re.compile(r"[a-z0-9_.-]{1,32}")


@dataclass(frozen=True, slots=True)
class MappedSegment:
    """File bytes ``file`` mapped at ``start``; the ``mem_size - file.size`` tail reads as zero."""

    file: ByteRange
    start: SpaceAddress
    mem_size: int
    name: str

    def __post_init__(self) -> None:
        if _SEGMENT_NAME.fullmatch(self.name) is None:
            raise ParseError("invalid segment name")
        if self.mem_size < 1:
            raise ParseError("empty segment")
        if self.mem_size < self.file.size:
            raise ParseError("memory size smaller than file length")
        if self.start.offset.value + self.mem_size - 1 > self.start.space.max_offset:
            raise ParseError("segment exceeds address space")

    @property
    def end(self) -> int:
        """Exclusive end offset inside the segment's space."""
        return self.start.offset.value + self.mem_size

    def contains(self, addr: SpaceAddress) -> bool:
        return addr.space == self.start.space and (
            self.start.offset.value <= addr.offset.value < self.end
        )


@dataclass(frozen=True, slots=True)
class MemoryMap:
    """Non-overlapping segments: at most ``MAX_SEGMENTS`` and ``MAX_IMAGE_SIZE`` mapped bytes."""

    segments: tuple[MappedSegment, ...]

    def __post_init__(self) -> None:
        if not 1 <= len(self.segments) <= MAX_SEGMENTS:
            raise ParseError(f"segment count must be 1..{MAX_SEGMENTS}")
        widths: dict[str, int] = {}
        for seg in self.segments:
            space = seg.start.space
            if widths.setdefault(space.name, space.width_bits) != space.width_bits:
                raise ParseError("address space declared with two widths")
        if sum(seg.mem_size for seg in self.segments) > MAX_IMAGE_SIZE:
            raise ParseError(f"mapped size exceeds {MAX_IMAGE_SIZE} bytes")
        for name in widths:
            ordered = sorted(
                (s for s in self.segments if s.start.space.name == name),
                key=lambda s: s.start.offset.value,
            )
            for prev, cur in pairwise(ordered):
                if cur.start.offset.value < prev.end:
                    raise ParseError("segments overlap in space")

    def segment_at(self, addr: SpaceAddress) -> MappedSegment | None:
        for seg in self.segments:
            if seg.contains(addr):
                return seg
        return None

    def file_range_for(self, addr: SpaceAddress, size: int) -> ByteRange:
        """File bytes backing ``[addr, addr + size)``; the caller zero-pads the missing tail."""
        if size < 1:
            raise ParseError("read size must be at least 1")
        seg = self.segment_at(addr)
        if seg is None:
            raise ParseError("address not mapped")
        rel = addr.offset.value - seg.start.offset.value
        if rel + size > seg.mem_size:
            raise ParseError("read crosses segment end")
        return ByteRange(
            seg.file.start + min(rel, seg.file.size),
            max(0, min(size, seg.file.size - rel)),
        )


@dataclass(frozen=True, slots=True)
class Image:
    """A loaded binary: architecture, memory map, optional entry point, source format."""

    arch: ArchitectureId
    memory: MemoryMap
    entry: SpaceAddress | None
    format: Format

    def __post_init__(self) -> None:
        if self.entry is None:
            return
        space = self.entry.space
        for seg in self.memory.segments:
            other = seg.start.space
            if other.name == space.name and other.width_bits != space.width_bits:
                raise ParseError("address space declared with two widths")
        if self.memory.segment_at(self.entry) is None:
            raise ParseError("entry outside every segment")


@dataclass(frozen=True, slots=True)
class RawSegmentSpec:
    """Request for one raw segment. No validation here by design: bounds need the source size,
    so ``build_raw_image`` checks them.

    ``file_length`` None = to end of source; ``mem_size`` None = file length;
    ``name`` None = ``seg{index}``.
    """

    file_offset: int
    file_length: int | None
    start: SpaceAddress
    mem_size: int | None = None
    name: str | None = None


@dataclass(frozen=True, slots=True)
class RawLoadSpec:
    """Request to load a source as a raw image. Architecture and segment bases are mandatory."""

    arch: ArchitectureId
    segments: tuple[RawSegmentSpec, ...]
    entry: SpaceAddress | None = None

    def __post_init__(self) -> None:
        if not self.segments:
            raise ParseError("no segment declared")
        if len(self.segments) > MAX_SEGMENTS:
            raise ParseError(f"segment count exceeds {MAX_SEGMENTS}")
