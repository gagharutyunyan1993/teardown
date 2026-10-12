"""Adapters backed by the local filesystem."""

from __future__ import annotations

import stat
from pathlib import Path

from retool.shared import RetoolError


def _unreadable(exc: OSError) -> RetoolError:
    # The path is not echoed: it is user-supplied.
    return RetoolError(f"cannot read input: {exc.strerror or 'I/O error'}")


class FileByteSource:
    """ByteSource adapter over a regular file. Reads on demand; never maps the whole file."""

    def __init__(self, path: Path) -> None:
        self._path = path
        try:
            st = path.stat()
        except OSError as exc:
            raise _unreadable(exc) from exc
        if not stat.S_ISREG(st.st_mode):
            # FIFOs, devices and directories: size is meaningless and open() may block.
            raise RetoolError("cannot read input: not a regular file")
        self._size = st.st_size

    @property
    def size(self) -> int:
        return self._size

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset >= self._size:
            return b""
        size = min(size, self._size - offset)  # never preallocate a hostile size
        try:
            with self._path.open("rb") as fh:
                fh.seek(offset)
                return fh.read(size)
        except OSError as exc:
            raise _unreadable(exc) from exc
