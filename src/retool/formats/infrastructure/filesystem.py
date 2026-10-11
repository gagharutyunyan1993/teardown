"""Adapters backed by the local filesystem."""

from __future__ import annotations

from pathlib import Path


class FileByteSource:
    """ByteSource adapter over a regular file. Reads on demand; never maps the whole file."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._size = path.stat().st_size

    @property
    def size(self) -> int:
        return self._size

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0:
            return b""
        with self._path.open("rb") as fh:
            fh.seek(offset)
            return fh.read(size)
