"""Domain services: the PE overlay (file bytes past the image) and anchored signature probes.

The overlay starts after the last section's raw data, SizeOfHeaders and the section table
(convention, unverified). At most three probes are read: the first ``SIGNATURE_WINDOW`` bytes
of the payload, the first ``SIGNATURE_WINDOW`` bytes after the certificate table, and each
file-anchored magic. Nothing else of the overlay is read.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from retool.formats.domain.parsing import read_exact
from retool.formats.domain.pe import (
    SIGNATURE_WINDOW,
    OverlayInfo,
    PeFile,
    SignatureMatch,
    directory,
    section_table_end,
)
from retool.formats.domain.ports import ByteSource
from retool.shared import Address, ByteRange, ParseError

_CERT_DIR: Final = 4
_MIN_MAGIC: Final = 3
_RULE_NAME: Final = re.compile(r"[a-z0-9-]{1,32}")


class SignatureAnchor(StrEnum):
    """Where a rule's offset is measured from: a probe window or the file start."""

    WINDOW = "window"
    FILE = "file"


@dataclass(frozen=True, slots=True)
class SignatureRule:
    """An exact fixed-byte ``magic`` at offset ``at`` of its anchor."""

    name: str
    anchor: SignatureAnchor
    at: int
    magic: bytes

    def __post_init__(self) -> None:
        if not (
            _RULE_NAME.fullmatch(self.name) is not None
            and len(self.magic) >= _MIN_MAGIC
            and self.at >= 0
            and self.at + len(self.magic) <= SIGNATURE_WINDOW
        ):
            raise ParseError("invalid signature rule")


_W: Final = SignatureAnchor.WINDOW

# Sources: spec slice 5, ## Signatures (relayed by the orchestrator 2026-10-13).
SIGNATURES: Final[tuple[SignatureRule, ...]] = (
    SignatureRule("7z", _W, 0, b"7z\xbc\xaf\x27\x1c"),  # 7-Zip 7zFormat.txt
    SignatureRule("zip-local", _W, 0, b"PK\x03\x04"),  # PKWARE APPNOTE 4.3.7
    SignatureRule("gzip", _W, 0, b"\x1f\x8b\x08"),  # RFC 1952 2.3.1, CM 8
    SignatureRule("nsis", _W, 4, b"\xef\xbe\xad\xdeNullsoftInst"),  # nsis fileform.h
    SignatureRule("inno-setup-data", _W, 0, b"Inno Setup Setup Data ("),  # innoextract version.cpp
    SignatureRule("inno-chunk", _W, 0, b"zlb\x1a"),  # innoextract chunk.cpp
    SignatureRule("inno-loader", SignatureAnchor.FILE, 0x30, b"Inno"),  # innoextract offsets.cpp
)


def match_window(window: bytes, offset: int) -> tuple[SignatureMatch, ...]:
    """WINDOW rules matching ``window`` (read at file ``offset``), in table order."""
    return tuple(
        SignatureMatch(rule.name, Address(offset))
        for rule in SIGNATURES
        if rule.anchor is SignatureAnchor.WINDOW
        and rule.at + len(rule.magic) <= len(window)
        and window[rule.at : rule.at + len(rule.magic)] == rule.magic
    )


def overlay_info(source: ByteSource, pe: PeFile) -> OverlayInfo | None:
    """The overlay's extent, its certificate sub-range and signature matches; None if empty."""
    size = source.size
    raw_end = max(
        (
            s.pointer_to_raw_data.value + s.size_of_raw_data
            for s in pe.sections
            if s.size_of_raw_data > 0
        ),
        default=0,
    )
    start = min(max(raw_end, pe.optional.size_of_headers, section_table_end(pe)), size)
    if start == size:
        return None
    found = directory(pe, _CERT_DIR)
    certificate = None
    if (
        found is not None
        and found.virtual_address >= start
        and found.virtual_address + found.size <= size
    ):
        certificate = ByteRange(found.virtual_address, found.size)
    payload_size = (certificate.start if certificate is not None else size) - start
    trailing_size = size - certificate.end if certificate is not None else 0
    matches: list[SignatureMatch] = []
    if payload_size > 0:
        window = read_exact(source, size, start, min(SIGNATURE_WINDOW, payload_size))
        matches.extend(match_window(window, start))
    if certificate is not None and trailing_size > 0:
        at = certificate.end
        window = read_exact(source, size, at, min(SIGNATURE_WINDOW, trailing_size))
        matches.extend(match_window(window, at))
    for rule in SIGNATURES:
        if (
            rule.anchor is SignatureAnchor.FILE
            and rule.at + len(rule.magic) <= size
            and read_exact(source, size, rule.at, len(rule.magic)) == rule.magic
        ):
            matches.append(SignatureMatch(rule.name, Address(rule.at)))
    return OverlayInfo(
        Address(start), size - start, certificate, payload_size, trailing_size, tuple(matches)
    )
