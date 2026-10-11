"""Error hierarchy. Parsers raise ParseError; nothing else escapes a parser."""

from __future__ import annotations


class RetoolError(Exception):
    """Base class for every error raised by retool."""


class ParseError(RetoolError):
    """Malformed or hostile input. Carries the offset so reports can cite it."""

    def __init__(self, reason: str, *, offset: int | None = None) -> None:
        self.reason = reason
        self.offset = offset
        where = f" at offset 0x{offset:x}" if offset is not None else ""
        super().__init__(f"{reason}{where}")
