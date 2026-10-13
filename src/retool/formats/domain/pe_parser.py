"""Strategy: the PE ``FormatParser``."""

from __future__ import annotations

from dataclasses import replace

from retool.formats.domain.model import Format, InputChanged
from retool.formats.domain.parsing import (
    ParsedContainer,
    SectionSummary,
    display_name,
    guarded_parse,
)
from retool.formats.domain.pe import (
    CertificateEntry,
    ImportedDll,
    OverlayInfo,
    PeFile,
    parse_pe,
    pe_section_kind,
)
from retool.formats.domain.pe_certificates import parse_certificates
from retool.formats.domain.pe_facts import pe_facts
from retool.formats.domain.pe_image import pe_arch, pe_image, section_mem_size
from retool.formats.domain.pe_imports import parse_imports
from retool.formats.domain.pe_overlay import overlay_info
from retool.formats.domain.ports import ByteSource
from retool.shared import NotAnalysed, ParseError

_NO_MAP_NOTE = "pe memory image not built: no headers or sections to map"


def _not_parsed(part: str, exc: ParseError) -> tuple[NotAnalysed, ...]:
    return (NotAnalysed(f"pe {part} not parsed: {exc}"),)


def attach_tables(source: ByteSource, pe: PeFile) -> tuple[PeFile, tuple[NotAnalysed, ...]]:
    """Attach imports, certificates and overlay to ``pe``, in that order.

    A ``ParseError`` in one part empties only that part and becomes one note; ``InputChanged``
    (a ``ParseError``) and source I/O errors propagate.
    """
    imports: tuple[ImportedDll, ...]
    certificates: tuple[CertificateEntry, ...]
    overlay: OverlayInfo | None
    try:
        imports, import_notes = parse_imports(source, pe)
    except InputChanged:
        raise
    except ParseError as exc:
        imports, import_notes = (), _not_parsed("imports", exc)
    try:
        certificates, certificate_notes = parse_certificates(source, pe)
    except InputChanged:
        raise
    except ParseError as exc:
        certificates, certificate_notes = (), _not_parsed("certificates", exc)
    overlay_notes: tuple[NotAnalysed, ...] = ()
    try:
        overlay = overlay_info(source, pe)
    except InputChanged:
        raise
    except ParseError as exc:  # defensive: overlay_info only reads within the file
        overlay, overlay_notes = None, _not_parsed("overlay", exc)
    attached = replace(pe, imports=imports, certificates=certificates, overlay=overlay)
    return attached, (*import_notes, *certificate_notes, *overlay_notes)


def _build_pe(source: ByteSource, producer: str) -> ParsedContainer:
    pe = parse_pe(source)
    pe, table_notes = attach_tables(source, pe)
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
    return ParsedContainer(
        pe_arch(pe.coff), image, sections, findings, (*notes, *table_notes, *fact_notes)
    )


class PeParser:
    """Stateless PE strategy; satisfies ``FormatParser``."""

    def parse(self, source: ByteSource, producer: str) -> ParsedContainer:
        return guarded_parse(Format.PE, _build_pe, source, producer)
