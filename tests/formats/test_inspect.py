import hashlib

from retool.formats import Format, InspectFile


class MemorySource:
    """In-memory ByteSource for tests; keeps the use case free of the filesystem."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    @property
    def size(self) -> int:
        return len(self._data)

    def read(self, offset: int, size: int) -> bytes:
        return self._data[offset : offset + size]


def test_inspect_reports_size_digest_and_format() -> None:
    data = b"\x7fELF" + b"\x00" * 60
    info = InspectFile(MemorySource(data)).execute()
    assert info.size == 64
    assert info.sha256 == hashlib.sha256(data).hexdigest()
    assert info.format is Format.ELF


def test_inspect_empty_source() -> None:
    info = InspectFile(MemorySource(b"")).execute()
    assert info.size == 0
    assert info.format is Format.UNKNOWN
