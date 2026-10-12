"""Domain services: project a parsed ELF onto the format-neutral ``Image`` (ADR 0001)."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from retool.formats.domain.elf import PT_LOAD, ElfClass, ElfFile, ElfHeader
from retool.formats.domain.image import DEFAULT_SPACE, Image, MappedSegment, MemoryMap
from retool.formats.domain.model import Format
from retool.shared import AddressSpace, ArchitectureId, ByteRange, SpaceAddress

_RAM32: Final = AddressSpace("ram", 32)

# Provisional names, header-declared from e_machine (Linux elf-em.h); settled by F-ARCH.
_ARCH_NAMES: Final[Mapping[int, str]] = MappingProxyType(
    {
        3: "x86",
        8: "mips",
        20: "ppc",
        21: "ppc64",
        22: "s390",
        40: "arm",
        62: "x86_64",
        183: "aarch64",
        243: "riscv",
    }
)


def elf_arch(header: ElfHeader) -> ArchitectureId:
    """Architecture id declared by ``e_machine``; unknown machines keep their number."""
    return ArchitectureId(_ARCH_NAMES.get(header.e_machine, f"elf-em-{header.e_machine}"))


def elf_image(elf: ElfFile) -> Image | None:
    """Map every PT_LOAD with ``p_memsz > 0``; None if there is none.

    ``MemoryMap`` invariants (overlap, segment count, mapped size) raise ``ParseError``.
    """
    header = elf.header
    space = _RAM32 if header.ei_class is ElfClass.ELF32 else DEFAULT_SPACE
    segments = tuple(
        MappedSegment(
            ByteRange(ph.p_offset.value, ph.p_filesz),
            SpaceAddress(space, ph.p_vaddr),
            ph.p_memsz,
            f"phdr{index}",
        )
        for index, ph in enumerate(elf.program_headers)
        if ph.p_type == PT_LOAD and ph.p_memsz > 0
    )
    if not segments:
        return None
    memory = MemoryMap(segments)
    entry = None
    if header.e_entry.value != 0:
        candidate = SpaceAddress(space, header.e_entry)
        if memory.segment_at(candidate) is not None:
            entry = candidate
    return Image(elf_arch(header), memory, entry, Format.ELF)
