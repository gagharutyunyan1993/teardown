"""Inno Setup file list: each file entry joined with its block-2 location (if any)."""

from __future__ import annotations

from dataclasses import dataclass

from retool.formats.domain.inno_setup import InnoFileEntry, InnoFileLocation
from retool.shared import ParseError


@dataclass(frozen=True, slots=True)
class InnoFile:
    """A file entry and the location it names; ``None`` iff the entry's location is -1."""

    entry: InnoFileEntry
    location: InnoFileLocation | None

    def __post_init__(self) -> None:
        if (self.location is None) != (self.entry.location == -1) or (
            self.location is not None and self.location.index != self.entry.location
        ):
            raise ParseError("inno file location inconsistent")


def join_files(
    entries: tuple[InnoFileEntry, ...], locations: tuple[InnoFileLocation, ...]
) -> tuple[InnoFile, ...]:
    """Join entries to locations in entry order; entries may share a location."""
    n = len(locations)
    files: list[InnoFile] = []
    for i, entry in enumerate(entries):
        loc = entry.location
        if loc == -1:
            files.append(InnoFile(entry, None))
        elif 0 <= loc < n:
            files.append(InnoFile(entry, locations[loc]))
        else:
            raise ParseError(f"inno file {i} location {loc} out of range {n}")
    return tuple(files)
