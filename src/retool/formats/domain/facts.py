"""Domain service: the findings and not-analysed markers formats reports for a format."""

from __future__ import annotations

from retool.formats.domain.elf import ElfData, ElfFile, display_name
from retool.formats.domain.elf_image import elf_arch
from retool.formats.domain.image import Image
from retool.formats.domain.model import Format
from retool.shared import Finding, JsonValue, NotAnalysed, Provenance, Verification

ENTRY_OUTSIDE_NOTE = "elf entry point outside every PT_LOAD segment"
NOT_PARSED_NOTE = "elf symbols, dynamic section, relocations and notes not parsed in this version"


def magic_finding(fmt: Format, producer: str) -> Finding:
    """The fact that the input starts with ``fmt``'s magic."""
    return Finding(
        "input", {"magic": fmt.value}, Provenance.PARSED, Verification.unverified(), producer
    )


def format_facts(fmt: Format, producer: str) -> tuple[tuple[Finding, ...], tuple[NotAnalysed, ...]]:
    """Return what ``producer`` established about the input's container, and what it did not."""
    if fmt is Format.RAW:
        return (), (NotAnalysed("raw image content not analysed"),)
    if fmt is Format.UNKNOWN:
        # No known magic was read, so there is no fact to report.
        return (), (NotAnalysed("container structure not parsed: unknown format"),)
    reason = f"container structure not parsed: no {fmt.value} parser in this version"
    return (magic_finding(fmt, producer),), (NotAnalysed(reason),)


def _parsed(subject: str, value: JsonValue, producer: str) -> Finding:
    return Finding(subject, value, Provenance.PARSED, Verification.unverified(), producer)


def elf_facts(
    elf: ElfFile, image: Image | None, producer: str
) -> tuple[tuple[Finding, ...], tuple[NotAnalysed, ...]]:
    """Findings for the ELF header and both tables, and the markers of what was not analysed."""
    h = elf.header
    header: JsonValue = {
        "class": h.bits,
        "data": "lsb" if h.ei_data is ElfData.LSB else "msb",
        "osabi": h.ei_osabi,
        "abiversion": h.ei_abiversion,
        "type": h.e_type,
        "machine": h.e_machine,
        "arch": str(elf_arch(h)),
        "entry": h.e_entry.value,
        "flags": h.e_flags,
        "ehsize": h.e_ehsize,
        "phoff": h.e_phoff.value,
        "phentsize": h.e_phentsize,
        "phnum": h.e_phnum,
        "shoff": h.e_shoff.value,
        "shentsize": h.e_shentsize,
        "shnum": h.e_shnum,
        "shstrndx": h.e_shstrndx,
    }
    findings = [magic_finding(Format.ELF, producer), _parsed("elf.header", header, producer)]
    for index, ph in enumerate(elf.program_headers):
        phdr: JsonValue = {
            "index": index,
            "type": ph.p_type,
            "flags": ph.p_flags,
            "offset": ph.p_offset.value,
            "vaddr": ph.p_vaddr.value,
            "paddr": ph.p_paddr.value,
            "filesz": ph.p_filesz,
            "memsz": ph.p_memsz,
            "align": ph.p_align,
        }
        findings.append(_parsed("elf.phdr", phdr, producer))
    for index, sh in enumerate(elf.section_headers):
        shdr: JsonValue = {
            "index": index,
            "name": display_name(sh.name),
            "type": sh.sh_type,
            "flags": sh.sh_flags,
            "addr": sh.sh_addr.value,
            "offset": sh.sh_offset.value,
            "size": sh.sh_size,
            "link": sh.sh_link,
            "info": sh.sh_info,
            "addralign": sh.sh_addralign,
            "entsize": sh.sh_entsize,
        }
        findings.append(_parsed("elf.shdr", shdr, producer))
    notes: list[NotAnalysed] = []
    if image is not None and h.e_entry.value != 0 and image.entry is None:
        notes.append(NotAnalysed(ENTRY_OUTSIDE_NOTE))
    notes.append(NotAnalysed(NOT_PARSED_NOTE))
    return tuple(findings), tuple(notes)
