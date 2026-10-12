"""Bounded context: executable container formats (identification, headers, sections).

Other contexts and the interface layer use only what is exported here.
"""

from retool.formats.application.dto import FileInfo, RawImageInfo, SegmentInfo
from retool.formats.application.use_cases import InspectFile, LoadRawImage
from retool.formats.domain.image import (
    DEFAULT_SPACE,
    Image,
    MappedSegment,
    MemoryMap,
    RawLoadSpec,
    RawSegmentSpec,
)
from retool.formats.domain.model import Format, InputChanged
from retool.formats.domain.parsing import SectionSummary
from retool.formats.domain.ports import ByteSource
from retool.formats.domain.services import detect

__all__ = [
    "DEFAULT_SPACE",
    "ByteSource",
    "FileInfo",
    "Format",
    "Image",
    "InputChanged",
    "InspectFile",
    "LoadRawImage",
    "MappedSegment",
    "MemoryMap",
    "RawImageInfo",
    "RawLoadSpec",
    "RawSegmentSpec",
    "SectionSummary",
    "SegmentInfo",
    "detect",
]
