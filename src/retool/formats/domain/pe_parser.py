"""Strategy: the PE ``FormatParser``."""

from __future__ import annotations

from retool.formats.domain.model import Format
from retool.formats.domain.parsing import (
    ParsedContainer,
    SectionSummary,
    display_name,
    guarded_parse,
)
from retool.formats.domain.pe import parse_pe, pe_section_kind
from retool.formats.domain.pe_facts import pe_facts
from retool.formats.domain.pe_image import pe_arch, pe_image, section_mem_size
from retool.formats.domain.ports import ByteSource
from retool.shared import NotAnalysed, ParseError

_NO_MAP_NOTE = "pe memory image not built: no headers or sections to map"


def _build_pe(source: ByteSource, producer: str) -> ParsedContainer:
    pe = parse_pe(source)
    notes: list[NotAnalysed] = []
    try:
        image = pe_image(pe)
    except ParseError as exc:
        image = None
        notes.append(NotAnalysed(f"pe memory image not built: {exc}"))
    else:
        if image is None:
            notes.append(NotAnalysed(_NO_MAP_NOTE))
    findings, fact_notes = pe_facts(pe, image, producer)
    base = pe.optional.image_base
    sections = tuple(
        SectionSummary(
            index,
            display_name(s.name),
            pe_section_kind(s.characteristics),
            base + s.virtual_address,
            s.pointer_to_raw_data.value,
            section_mem_size(s),
        )
        for index, s in enumerate(pe.sections)
    )
    return ParsedContainer(pe_arch(pe.coff), image, sections, findings, (*notes, *fact_notes))


class PeParser:
    """Stateless PE strategy; satisfies ``FormatParser``."""

    def parse(self, source: ByteSource, producer: str) -> ParsedContainer:
        return guarded_parse(Format.PE, _build_pe, source, producer)
