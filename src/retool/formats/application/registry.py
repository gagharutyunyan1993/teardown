"""Registry: selects the format parser strategy for a detected format."""

from __future__ import annotations

from retool.formats.domain.elf_parser import ElfParser
from retool.formats.domain.model import Format
from retool.formats.domain.parsing import FormatParser


def parser_for(fmt: Format) -> FormatParser | None:
    """The parser for ``fmt``, or None when this version has none."""
    match fmt:
        case Format.ELF:
            return ElfParser()
        case _:
            return None
