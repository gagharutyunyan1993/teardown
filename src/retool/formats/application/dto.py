"""Data transfer objects crossing the application boundary."""

from __future__ import annotations

from dataclasses import dataclass

from retool.formats.domain.model import Format
from retool.shared import ArchitectureId, Finding, NotAnalysed, SpaceAddress


@dataclass(frozen=True, slots=True)
class FileInfo:
    size: int
    sha256: str
    format: Format
    stage: str
    stage_version: str
    findings: tuple[Finding, ...]
    not_analysed: tuple[NotAnalysed, ...]


@dataclass(frozen=True, slots=True)
class SegmentInfo:
    name: str
    start: SpaceAddress
    mem_size: int
    file_start: int
    file_size: int


@dataclass(frozen=True, slots=True)
class RawImageInfo:
    """Display fields of a raw load. ``shadowed_format`` is a magic the raw load ignored."""

    source_size: int
    format: Format
    arch: ArchitectureId
    entry: SpaceAddress | None
    segments: tuple[SegmentInfo, ...]
    shadowed_format: Format | None
    stage: str
    stage_version: str
    findings: tuple[Finding, ...]
    not_analysed: tuple[NotAnalysed, ...]
