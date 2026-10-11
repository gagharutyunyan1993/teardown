"""Domain model of the formats context."""

from __future__ import annotations

from enum import StrEnum


class Format(StrEnum):
    """Container format identified from magic bytes."""

    ELF = "elf"
    PE = "pe"
    MACHO = "macho"
    UNKNOWN = "unknown"
