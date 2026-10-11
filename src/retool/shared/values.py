"""Value objects of the shared kernel. Immutable, validated on construction."""

from __future__ import annotations

from dataclasses import dataclass

from retool.shared.errors import ParseError


@dataclass(frozen=True, slots=True)
class Address:
    """A non-negative address or offset inside a binary."""

    value: int

    def __post_init__(self) -> None:
        if self.value < 0:
            raise ParseError(f"negative address {self.value}")

    def __int__(self) -> int:
        return self.value


@dataclass(frozen=True, slots=True)
class ByteRange:
    """A half-open range [start, start + size) inside a byte source."""

    start: int
    size: int

    def __post_init__(self) -> None:
        if self.start < 0 or self.size < 0:
            raise ParseError(f"invalid range start={self.start} size={self.size}")

    @property
    def end(self) -> int:
        return self.start + self.size

    def check_within(self, limit: int) -> ByteRange:
        """Return self if the range lies inside ``limit`` bytes, else raise ParseError."""
        if self.end > limit:
            raise ParseError(
                f"range [{self.start}, {self.end}) exceeds {limit} bytes", offset=self.start
            )
        return self
