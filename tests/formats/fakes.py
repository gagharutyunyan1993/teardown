"""In-memory ByteSource fakes and spec builders for formats tests."""

from __future__ import annotations

from retool.formats import DEFAULT_SPACE, RawSegmentSpec
from retool.shared import Address, AddressSpace, ArchitectureId, SpaceAddress


class MemorySource:
    """ByteSource over an in-memory buffer; records every read."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self.calls: list[tuple[int, int]] = []

    @property
    def size(self) -> int:
        return len(self._data)

    def read(self, offset: int, size: int) -> bytes:
        self.calls.append((offset, size))
        return self._data[offset : offset + size]


class SparseSource:
    """ByteSource reporting ``size`` bytes without holding them: ``head`` then zeros."""

    def __init__(self, size: int, head: bytes = b"") -> None:
        self._size = size
        self._head = head
        self.calls: list[tuple[int, int]] = []

    @property
    def size(self) -> int:
        return self._size

    def read(self, offset: int, size: int) -> bytes:
        self.calls.append((offset, size))
        end = min(offset + size, self._size)
        if offset >= end:
            return b""
        head = self._head[offset:end]
        return head + bytes(end - offset - len(head))


def seg(
    off: int,
    length: int | None,
    start: SpaceAddress,
    mem_size: int | None = None,
    name: str | None = None,
) -> RawSegmentSpec:
    return RawSegmentSpec(off, length, start, mem_size, name)


def sa(space: AddressSpace, n: int) -> SpaceAddress:
    return SpaceAddress(space, Address(n))


ram = DEFAULT_SPACE
rom = AddressSpace("rom", 64)
bank1 = AddressSpace("bank1", 16)
arm = ArchitectureId("armv7")
