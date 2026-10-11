"""Data transfer objects crossing the application boundary."""

from __future__ import annotations

from dataclasses import dataclass

from retool.formats.domain.model import Format


@dataclass(frozen=True, slots=True)
class FileInfo:
    size: int
    sha256: str
    format: Format
