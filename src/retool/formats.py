"""Executable-format detection by magic bytes.

Only the header is inspected. The input is untrusted: never trust lengths or
offsets read from it without bounds checks.
"""

from __future__ import annotations

from enum import StrEnum

_HEADER_LEN = 4


class Format(StrEnum):
    ELF = "elf"
    PE = "pe"
    MACHO = "macho"
    UNKNOWN = "unknown"


_MACHO_MAGICS = frozenset(
    {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    }
)


def detect(data: bytes) -> Format:
    """Return the executable format of ``data`` based on its first bytes."""
    head = data[:_HEADER_LEN]
    if head == b"\x7fELF":
        return Format.ELF
    if head[:2] == b"MZ":
        return Format.PE
    if head in _MACHO_MAGICS:
        return Format.MACHO
    return Format.UNKNOWN
