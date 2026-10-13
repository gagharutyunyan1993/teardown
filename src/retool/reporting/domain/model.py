"""Read model of a report: display values only, no lookup, overlap or containment behaviour."""

from __future__ import annotations

import re
from dataclasses import dataclass

from retool.shared import ArchitectureId, Finding, NotAnalysed, ParseError, SpaceAddress

SCHEMA_VERSION = 1
MAX_STAGES = 16
MAX_FINDINGS = 4096
MAX_NOT_ANALYSED = 256  # report bounds (assumption)
MAX_IMAGE_SEGMENTS = (
    64  # reporting's own output bound: keeps raw_image to ~10 KiB of JSON (assumption)
)
_SEGMENT = re.compile(r"[a-z0-9_.-]{1,32}")  # plain ASCII output, no escapes needed (assumption)
_STAGE = re.compile(r"[a-z0-9_.:-]{1,64}")  # stage names are Finding producers (findings.py:15)
_VERSION = re.compile(r"[0-9a-z_.+-]{1,32}")  # (assumption)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_U64_MAX = (1 << 64) - 1


def _is_u64(value: int) -> bool:
    return type(value) is int and 0 <= value <= _U64_MAX


@dataclass(frozen=True, slots=True)
class InputDigest:
    """Size and SHA-256 of the whole input."""

    sha256: str
    size: int

    def __post_init__(self) -> None:
        if _SHA256.fullmatch(self.sha256) is None:
            raise ParseError("input sha256 must be 64 lowercase hex chars")
        if not _is_u64(self.size):
            raise ParseError("input size must be an int in 0..2**64-1")


@dataclass(frozen=True, slots=True)
class SegmentLayout:
    """One user-declared raw segment, as displayed."""

    name: str
    start: SpaceAddress
    mem_size: int
    file_start: int
    file_size: int

    def __post_init__(self) -> None:
        if _SEGMENT.fullmatch(self.name) is None:
            raise ParseError("segment name must be 1..32 chars of [a-z0-9_.-]")
        if not _is_u64(self.mem_size) or self.mem_size < 1:
            raise ParseError("segment mem_size must be an int in 1..2**64-1")
        if not _is_u64(self.file_start):
            raise ParseError("segment file_start must be an int in 0..2**64-1")
        if not _is_u64(self.file_size):
            raise ParseError("segment file_size must be an int in 0..2**64-1")


@dataclass(frozen=True, slots=True)
class RawImageLayout:
    """The user-declared raw image layout (ADR 0001); not a finding, no provenance."""

    arch: ArchitectureId
    entry: SpaceAddress | None
    segments: tuple[SegmentLayout, ...]

    def __post_init__(self) -> None:
        if not 1 <= len(self.segments) <= MAX_IMAGE_SEGMENTS:
            raise ParseError(f"raw image needs 1..{MAX_IMAGE_SEGMENTS} segments")


@dataclass(frozen=True, slots=True)
class StageOutput:
    """What one versioned analysis stage reported."""

    name: str
    version: str
    findings: tuple[Finding, ...] = ()
    not_analysed: tuple[NotAnalysed, ...] = ()
    raw_image: RawImageLayout | None = None

    def __post_init__(self) -> None:
        if _STAGE.fullmatch(self.name) is None:
            raise ParseError("invalid stage name")
        if _VERSION.fullmatch(self.version) is None:
            raise ParseError("invalid stage version")
        if any(f.producer != self.name for f in self.findings):
            raise ParseError("finding producer does not match stage")


@dataclass(frozen=True, slots=True)
class Report:
    """Aggregate root: the input digest and the stages run on it, in execution order."""

    input: InputDigest
    stages: tuple[StageOutput, ...]

    def __post_init__(self) -> None:
        if not 1 <= len(self.stages) <= MAX_STAGES:
            raise ParseError(f"stage count must be 1..{MAX_STAGES}")
        if len({s.name for s in self.stages}) != len(self.stages):
            raise ParseError("duplicate stage name")
        if sum(s.raw_image is not None for s in self.stages) > 1:
            raise ParseError("at most one stage may carry a raw image")
        if sum(len(s.findings) for s in self.stages) > MAX_FINDINGS:
            raise ParseError(f"finding count exceeds {MAX_FINDINGS}")
        if sum(len(s.not_analysed) for s in self.stages) > MAX_NOT_ANALYSED:
            raise ParseError(f"not-analysed count exceeds {MAX_NOT_ANALYSED}")

    @property
    def raw_image(self) -> RawImageLayout | None:
        """The single stage's raw image layout, else None."""
        for stage in self.stages:
            if stage.raw_image is not None:
                return stage.raw_image
        return None
