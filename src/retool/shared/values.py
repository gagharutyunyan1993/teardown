"""Value objects of the shared kernel. Immutable, validated on construction."""

from __future__ import annotations

import re
from dataclasses import dataclass

from retool.shared.errors import ParseError

_ID = re.compile(r"[a-z0-9_.:-]{1,32}")  # ADR 0001 charset
_NAME = re.compile(r"[a-z0-9_.-]{1,32}")  # no ':'/'@' so CLI suffixes and str() stay unambiguous
_MAX_WIDTH_BITS = 64


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


@dataclass(frozen=True, slots=True)
class ArchitectureId:
    """Opaque processor architecture id, always declared, never inferred (ADR 0001)."""

    name: str

    def __post_init__(self) -> None:
        if _ID.fullmatch(self.name) is None:
            raise ParseError("invalid architecture id")

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True, slots=True)
class AddressSpace:
    """A named address space of a fixed width in bits (e.g. ``ram``, 64)."""

    name: str
    width_bits: int

    def __post_init__(self) -> None:
        if _NAME.fullmatch(self.name) is None:
            raise ParseError("invalid address space name")
        if not 1 <= self.width_bits <= _MAX_WIDTH_BITS:
            raise ParseError(f"address space width must be 1..{_MAX_WIDTH_BITS} bits")

    @property
    def max_offset(self) -> int:
        return (1 << self.width_bits) - 1


@dataclass(frozen=True, slots=True)
class SpaceAddress:
    """An address qualified by the address space it lives in."""

    space: AddressSpace
    offset: Address

    def __post_init__(self) -> None:
        if self.offset.value > self.space.max_offset:
            raise ParseError(f"address exceeds {self.space.width_bits}-bit space")

    def __str__(self) -> str:
        return f"{self.space.name}:0x{self.offset.value:x}"
