"""Use cases of the formats context. Orchestrate domain services through ports."""

from __future__ import annotations

import hashlib

from retool.formats.application.dto import FileInfo, RawImageInfo, SegmentInfo
from retool.formats.domain.image import RawLoadSpec
from retool.formats.domain.ports import ByteSource
from retool.formats.domain.services import build_raw_image, detect, structured_format

_CHUNK = 1 << 20
_HEAD = 4096
_MAGIC_WINDOW = 4  # == services._HEADER_LEN; every magic detect() knows is <= 4 bytes


class InspectFile:
    """Basic facts about a byte source: size, digest, container format."""

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
        head = self._source.read(0, _HEAD)
        return FileInfo(size=size, sha256=digest.hexdigest(), format=detect(head))


class LoadRawImage:
    """Load a byte source as a raw image. Explicit only; a structured magic only warns."""

    def __init__(self, source: ByteSource) -> None:
        self._source = source

    def execute(self, spec: RawLoadSpec) -> RawImageInfo:
        size = self._source.size
        image = build_raw_image(spec, size)
        head = self._source.read(0, min(_MAGIC_WINDOW, size))
        return RawImageInfo(
            source_size=size,
            format=image.format,
            arch=image.arch,
            entry=image.entry,
            segments=tuple(
                SegmentInfo(
                    name=seg.name,
                    start=seg.start,
                    mem_size=seg.mem_size,
                    file_start=seg.file.start,
                    file_size=seg.file.size,
                )
                for seg in image.memory.segments
            ),
            shadowed_format=structured_format(head),
        )
