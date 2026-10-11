"""Domain services: pure functions over bytes. No I/O here."""

from __future__ import annotations

from retool.formats.domain.model import Format

_HEADER_LEN = 4

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
    """Return the container format of ``data`` based on its first bytes.

    ``MZ`` only marks a PE candidate (DOS stub); ``\\xca\\xfe\\xba\\xbe`` is shared with
    Java class files. Disambiguation is the job of the per-format parsers.
    """
    head = data[:_HEADER_LEN]
    if head == b"\x7fELF":
        return Format.ELF
    if head[:2] == b"MZ":
        return Format.PE
    if head in _MACHO_MAGICS:
        return Format.MACHO
    return Format.UNKNOWN
