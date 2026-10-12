"""Domain model of the formats context."""

from __future__ import annotations

from enum import StrEnum

from retool.shared import ParseError


class Format(StrEnum):
    """Container format identified from magic bytes."""

    ELF = "elf"
    PE = "pe"
    MACHO = "macho"
    UNKNOWN = "unknown"
    RAW = "raw"
    """Set only by an explicit raw load; detect() never returns it."""


class InputChanged(ParseError):
    """The source returned fewer bytes than its size promised: the input changed while read.

    The only error a format parser lets escape; every other ``ParseError`` becomes a note.
    """

    def __init__(self, *, offset: int | None = None) -> None:
        super().__init__("input changed during read", offset=offset)
