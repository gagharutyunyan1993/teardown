"""Strategy: the ELF ``FormatParser``."""

from __future__ import annotations

from retool.formats.domain.elf import display_name, parse_elf, section_kind
from retool.formats.domain.elf_image import elf_arch, elf_image
from retool.formats.domain.facts import elf_facts
from retool.formats.domain.model import Format
from retool.formats.domain.parsing import ParsedContainer, SectionSummary, guarded_parse
from retool.formats.domain.ports import ByteSource
from retool.shared import NotAnalysed, ParseError

_NO_LOAD_NOTE = "elf memory image not built: no PT_LOAD segment with p_memsz > 0"


def _build_elf(source: ByteSource, producer: str) -> ParsedContainer:
    elf = parse_elf(source)
    notes: list[NotAnalysed] = []
    try:
        image = elf_image(elf)
    except ParseError as exc:
        image = None
        notes.append(NotAnalysed(f"elf memory image not built: {exc}"))
    else:
        if image is None:
            notes.append(NotAnalysed(_NO_LOAD_NOTE))
    findings, fact_notes = elf_facts(elf, image, producer)
    sections = tuple(
        SectionSummary(
            index,
            display_name(sh.name),
            section_kind(sh.sh_type),
            sh.sh_addr.value,
            sh.sh_offset.value,
            sh.sh_size,
        )
        for index, sh in enumerate(elf.section_headers)
    )
    return ParsedContainer(elf_arch(elf.header), image, sections, findings, (*notes, *fact_notes))


class ElfParser:
    """Stateless ELF strategy; satisfies ``FormatParser``."""

    def parse(self, source: ByteSource, producer: str) -> ParsedContainer:
        return guarded_parse(Format.ELF, _build_elf, source, producer)
