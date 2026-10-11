"""Use cases of the formats context. Orchestrate domain services through ports."""

from __future__ import annotations

import hashlib

from retool.formats.application.dto import FileInfo
from retool.formats.domain.ports import ByteSource
from retool.formats.domain.services import detect

_CHUNK = 1 << 20
_HEAD = 4096


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
