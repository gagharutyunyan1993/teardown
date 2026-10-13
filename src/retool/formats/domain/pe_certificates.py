"""Domain service: WIN_CERTIFICATE headers of the PE Attribute Certificate Table (directory 4).

Directory 4's VirtualAddress is a file offset. Only the 8-byte headers are read; certificate
contents (PKCS#7) are not. Entries are contiguous and 8-byte aligned; the table Size must
equal the rounded sum of the entry lengths.
"""

from __future__ import annotations

import struct
from typing import Final

from retool.formats.domain.parsing import read_exact
from retool.formats.domain.pe import (
    MAX_CERTS,
    CertificateEntry,
    PeFile,
    directory,
    directory_offset,
)
from retool.formats.domain.ports import ByteSource
from retool.shared import Address, NotAnalysed, ParseError

_CERT_DIR: Final = 4
_HDR_FMT: Final = "<IHH"
_HDR_SIZE: Final = 8
_ALIGN_MASK: Final = 7
_TRUNCATED_NOTE: Final = f"pe certificates truncated at {MAX_CERTS} entries"


def _header(buf: bytes) -> tuple[int, ...]:
    if len(buf) != struct.calcsize(_HDR_FMT):
        raise ParseError("PE struct size mismatch")
    return tuple(v for v in struct.unpack_from(_HDR_FMT, buf, 0) if isinstance(v, int))


def parse_certificates(
    source: ByteSource, pe: PeFile
) -> tuple[tuple[CertificateEntry, ...], tuple[NotAnalysed, ...]]:
    """Certificate headers in table order, and a note if the entry cap was hit."""
    found = directory(pe, _CERT_DIR)
    if found is None:
        return (), ()
    size = source.size
    table_at = directory_offset(pe, _CERT_DIR)
    end = found.virtual_address + found.size
    if end > size:
        raise ParseError("certificate table exceeds file", offset=table_at)
    pos = found.virtual_address
    entries: list[CertificateEntry] = []
    while pos < end:
        if len(entries) == MAX_CERTS:
            return tuple(entries), (NotAnalysed(_TRUNCATED_NOTE),)
        if pos + _HDR_SIZE > end:
            raise ParseError("certificate header exceeds table", offset=pos)
        length, revision, certificate_type = _header(read_exact(source, size, pos, _HDR_SIZE))
        if length < _HDR_SIZE:
            raise ParseError("certificate length below header size", offset=pos)
        if pos + length > end:
            raise ParseError("certificate entry exceeds table", offset=pos)
        entries.append(CertificateEntry(Address(pos), length, revision, certificate_type))
        pos += (length + _ALIGN_MASK) & ~_ALIGN_MASK
    if pos != end:
        raise ParseError("certificate lengths do not sum to table size", offset=table_at)
    return tuple(entries), ()
