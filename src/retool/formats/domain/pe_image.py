"""Domain services: project a parsed PE onto the format-neutral ``Image`` (ADR 0001)."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from retool.formats.domain.image import DEFAULT_SPACE, Image, MappedSegment, MemoryMap
from retool.formats.domain.model import Format
from retool.formats.domain.pe import CoffHeader, PeFile, PeSection
from retool.shared import Address, AddressSpace, ArchitectureId, ByteRange, SpaceAddress

_RAM32: Final = AddressSpace("ram", 32)

# Provisional names, header-declared from Machine (PE Format, Machine Types); settled by F-ARCH.
_ARCH_NAMES: Final[Mapping[int, str]] = MappingProxyType(
    {
        0x14C: "x86",
        0x8664: "x86_64",
        0x1C0: "arm",
        0x1C4: "arm",
        0xAA64: "aarch64",
        0x200: "ia64",
        0x6232: "loongarch32",
        0x6264: "loongarch64",
    }
)


def pe_arch(coff: CoffHeader) -> ArchitectureId:
    """Architecture id declared by Machine; unknown machines keep their number (decimal)."""
    return ArchitectureId(_ARCH_NAMES.get(coff.machine, f"pe-machine-{coff.machine}"))


def section_mem_size(section: PeSection) -> int:
    """Memory extent of a section: VirtualSize, or SizeOfRawData when VirtualSize is 0."""
    return section.virtual_size if section.virtual_size != 0 else section.size_of_raw_data


def rva_to_file(pe: PeFile, rva: int) -> ByteRange | None:
    """File-backed run of bytes starting at ``rva``; None if ``rva`` has no file bytes.

    Mirrors ``_segment``: the first section in file order whose memory extent holds ``rva``
    wins; its zero-filled tail is not file-backed. Outside every section, ``rva`` below
    SizeOfHeaders maps to the headers at file offset ``rva``.
    """
    for section in pe.sections:
        mem = section_mem_size(section)
        if section.virtual_address <= rva < section.virtual_address + mem:
            delta = rva - section.virtual_address
            backed = min(section.size_of_raw_data, mem)
            if delta < backed:
                return ByteRange(section.pointer_to_raw_data.value + delta, backed - delta)
            return None
    headers = pe.optional.size_of_headers
    if 0 <= rva < headers:
        return ByteRange(rva, headers - rva)
    return None


def _segment(section: PeSection, index: int, space: AddressSpace, base: int) -> MappedSegment:
    mem = section_mem_size(section)
    length = min(section.size_of_raw_data, mem)
    file = ByteRange(section.pointer_to_raw_data.value, length) if length > 0 else ByteRange(0, 0)
    start = SpaceAddress(space, Address(base + section.virtual_address))
    return MappedSegment(file, start, mem, f"sec{index}")


def pe_image(pe: PeFile) -> Image | None:
    """Map the headers and every section with a non-zero memory extent; None if nothing maps.

    ``MemoryMap``/``MappedSegment``/``SpaceAddress`` invariants raise ``ParseError``.
    """
    opt = pe.optional
    space = _RAM32 if opt.bits == 32 else DEFAULT_SPACE
    base = opt.image_base
    segments: list[MappedSegment] = []
    if opt.size_of_headers > 0:
        segments.append(
            MappedSegment(
                ByteRange(0, opt.size_of_headers),
                SpaceAddress(space, Address(base)),
                opt.size_of_headers,
                "headers",
            )
        )
    segments.extend(
        _segment(section, index, space, base)
        for index, section in enumerate(pe.sections)
        if section_mem_size(section) > 0
    )
    if not segments:
        return None
    memory = MemoryMap(tuple(segments))
    entry = None
    rva = opt.address_of_entry_point
    if rva != 0 and base + rva <= space.max_offset:
        candidate = SpaceAddress(space, Address(base + rva))
        if memory.segment_at(candidate) is not None:
            entry = candidate
    return Image(pe_arch(pe.coff), memory, entry, Format.PE)
