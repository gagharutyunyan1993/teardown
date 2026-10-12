"""Use cases of the formats context. Orchestrate domain services through ports."""

from __future__ import annotations

import hashlib
from typing import Final

from retool.formats.application.dto import FileInfo, RawImageInfo, SegmentInfo
from retool.formats.application.registry import parser_for
from retool.formats.domain.facts import format_facts
from retool.formats.domain.image import Image, RawLoadSpec
from retool.formats.domain.model import InputChanged
from retool.formats.domain.ports import ByteSource
from retool.formats.domain.services import MAGIC_WINDOW, build_raw_image, detect, structured_format

_CHUNK = 1 << 20
_HEAD = 4096


def _segment_infos(image: Image) -> tuple[SegmentInfo, ...]:
    return tuple(
        SegmentInfo(
            name=seg.name,
            start=seg.start,
            mem_size=seg.mem_size,
            file_start=seg.file.start,
            file_size=seg.file.size,
        )
        for seg in image.memory.segments
    )


class InspectFile:
    """Basic facts about a byte source: size, digest, container format."""

    STAGE: Final = "formats.inspect"
    STAGE_VERSION: Final = "3"  # bump when this use case's facts for the same input change

    def __init__(self, source: ByteSource) -> None:
        self._source = source

    def execute(self) -> FileInfo:
        size = self._source.size
        digest = hashlib.sha256()
        offset = 0
        while offset < size:
            chunk = self._source.read(offset, _CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            offset += len(chunk)
        if offset != size:
            raise InputChanged()
        head = self._source.read(0, _HEAD)
        fmt = detect(head)
        parser = parser_for(fmt)
        if parser is None:
            findings, not_analysed = format_facts(fmt, self.STAGE)
            return FileInfo(
                size=size,
                sha256=digest.hexdigest(),
                format=fmt,
                stage=self.STAGE,
                stage_version=self.STAGE_VERSION,
                findings=findings,
                not_analysed=not_analysed,
            )
        parsed = parser.parse(self._source, self.STAGE)
        image = parsed.image
        return FileInfo(
            size=size,
            sha256=digest.hexdigest(),
            format=fmt,
            stage=self.STAGE,
            stage_version=self.STAGE_VERSION,
            findings=parsed.findings,
            not_analysed=parsed.not_analysed,
            arch=parsed.arch,
            entry=None if image is None else image.entry,
            segments=() if image is None else _segment_infos(image),
            sections=parsed.sections,
        )


class LoadRawImage:
    """Load a byte source as a raw image. Explicit only; a structured magic only warns."""

    STAGE: Final = "formats.raw"
    STAGE_VERSION: Final = "1"  # bump when this use case's facts for the same input change

    def __init__(self, source: ByteSource) -> None:
        self._source = source

    def execute(self, spec: RawLoadSpec) -> RawImageInfo:
        size = self._source.size
        image = build_raw_image(spec, size)
        head = self._source.read(0, min(MAGIC_WINDOW, size))
        findings, not_analysed = format_facts(image.format, self.STAGE)
        return RawImageInfo(
            source_size=size,
            format=image.format,
            arch=image.arch,
            entry=image.entry,
            segments=_segment_infos(image),
            shadowed_format=structured_format(head),
            stage=self.STAGE,
            stage_version=self.STAGE_VERSION,
            findings=findings,
            not_analysed=not_analysed,
        )
