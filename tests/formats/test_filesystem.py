import os
from pathlib import Path

import pytest

from retool.formats.infrastructure.filesystem import FileByteSource
from retool.shared import RetoolError


def test_missing_path_raises_retool_error(tmp_path: Path) -> None:
    with pytest.raises(RetoolError) as exc:
        FileByteSource(tmp_path / "missing")
    assert not isinstance(exc.value, OSError)
    assert str(exc.value).startswith("cannot read input:")
    assert "missing" not in str(exc.value)


def test_directory_raises_retool_error(tmp_path: Path) -> None:
    with pytest.raises(RetoolError, match="not a regular file") as exc:
        FileByteSource(tmp_path).read(0, 4)
    assert not isinstance(exc.value, OSError)


def test_fifo_raises_retool_error(tmp_path: Path) -> None:
    fifo = tmp_path / "f"
    os.mkfifo(fifo)
    with pytest.raises(RetoolError, match="not a regular file") as exc:
        FileByteSource(fifo)
    assert not isinstance(exc.value, OSError)


def test_read_clamps_to_file_size(tmp_path: Path) -> None:
    path = tmp_path / "a.bin"
    path.write_bytes(bytes(range(16)))
    source = FileByteSource(path)
    assert source.read(0, 1 << 40) == bytes(range(16))
    assert source.read(16, 4) == b""
