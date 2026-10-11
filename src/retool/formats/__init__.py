"""Bounded context: executable container formats (identification, headers, sections).

Other contexts and the interface layer use only what is exported here.
"""

from retool.formats.application.dto import FileInfo
from retool.formats.application.use_cases import InspectFile
from retool.formats.domain.model import Format
from retool.formats.domain.ports import ByteSource
from retool.formats.domain.services import detect

__all__ = ["ByteSource", "FileInfo", "Format", "InspectFile", "detect"]
