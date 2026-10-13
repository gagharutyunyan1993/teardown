from __future__ import annotations

import re
import struct

import pytest

from retool.formats.domain.model import InputChanged
from retool.formats.domain.pe import (
    SIGNATURE_WINDOW,
    CertificateEntry,
    OverlayInfo,
    SignatureMatch,
    parse_pe,
)
from retool.formats.domain.pe_overlay import (
    SIGNATURES,
    SignatureAnchor,
    SignatureRule,
    match_window,
    overlay_info,
)
from retool.formats.domain.pe_parser import PeParser, attach_tables
from retool.shared import Address, ByteRange, NotAnalysed, ParseError
from tests.formats.fakes import MemorySource, ShrinkingSource
from tests.formats.pe_build import P64, PT64, REAL_CERT, dir_at, p, patch, real_shape

PRODUCER = "formats.inspect"
DIR4 = dir_at(4)
CERT16 = struct.pack("<IHH", 16, 0x200, 2) + bytes(8)
WINDOW_RULES = [r for r in SIGNATURES if r.anchor is SignatureAnchor.WINDOW]


def _overlay(data: bytes) -> tuple[OverlayInfo | None, list[tuple[int, int]]]:
    """overlay_info and its reads (after parse_pe's)."""
    source = MemorySource(data)
    pe = parse_pe(source)
    before = len(source.calls)
    info = overlay_info(source, pe)
    return info, source.calls[before:]


def _dir4(data: bytes, va: int, size: int) -> bytes:
    return patch(patch(data, DIR4, "<I", va), DIR4 + 4, "<I", size)


def _with_window(raw: bytes) -> bytes:
    return P64 + raw.ljust(SIGNATURE_WINDOW, b"\0")


# 18: PT64


def test_pt64_overlay() -> None:
    info, _ = _overlay(PT64)
    assert info == OverlayInfo(
        Address(0x600),
        0x20020,
        ByteRange(0x20600, 16),
        0x20000,
        16,
        (SignatureMatch("7z", Address(0x600)), SignatureMatch("zip-local", Address(0x20610))),
    )


def test_pt64_overlay_reads() -> None:
    source = MemorySource(PT64)
    attach_tables(source, parse_pe(source))
    after = source.calls[source.calls.index((0x20600, 8)) + 1 :]
    assert after == [(0x600, 64), (0x20610, 16), (0x30, 4), (0x30, 12)]


# 19-21: extent and certificate sub-range (O1-O2)


def test_no_overlay() -> None:
    assert _overlay(P64) == (None, [])


def test_overlay_without_raw_data() -> None:
    info, _ = _overlay(p((0x158, 0), (0x180, 0)))
    assert info is not None
    assert (info.offset, info.size) == (Address(0x200), 0x400)


def test_overlay_starts_after_section_table() -> None:
    info, _ = _overlay(p((0x158, 0), (0x180, 0), (0x94, 0)))
    assert info is not None
    assert (info.offset, info.size) == (Address(0x198), 0x468)


def test_overlay_is_certificate_only() -> None:
    info, calls = _overlay(_dir4(P64 + CERT16, 0x600, 16))
    assert info is not None
    assert (info.size, info.payload_size, info.trailing_size) == (16, 0, 0)
    assert info.certificate == ByteRange(0x600, 16)
    assert calls == [(0x30, 4)]


def test_certificate_inside_image_not_in_overlay() -> None:
    data = _dir4(P64[:0x400] + CERT16 + P64[0x410:] + bytes(16), 0x400, 16)
    source = MemorySource(data)
    pe, notes = attach_tables(source, parse_pe(source))
    assert notes == ()
    assert pe.certificates == (CertificateEntry(Address(0x400), 16, 0x200, 2),)
    assert pe.overlay is not None
    assert pe.overlay.certificate is None
    assert pe.overlay.payload_size == pe.overlay.size == 16


def test_certificate_past_eof() -> None:
    source = MemorySource(_dir4(P64 + CERT16, 0x600, 0x20))
    pe, notes = attach_tables(source, parse_pe(source))
    assert pe.overlay is not None
    assert pe.overlay.certificate is None
    assert pe.overlay.payload_size == 16
    assert notes == (
        NotAnalysed("pe certificates not parsed: certificate table exceeds file at offset 0xe8"),
    )


def test_certificate_mid_overlay() -> None:
    trailing = b"7z\xbc\xaf\x27\x1c".ljust(100, b"\0")
    data = _dir4(P64 + bytes(0x100) + CERT16 + trailing, 0x700, 16)
    info, calls = _overlay(data)
    assert info is not None
    assert (info.payload_size, info.trailing_size) == (0x100, 100)
    assert info.signatures == (SignatureMatch("7z", Address(0x710)),)
    assert calls == [(0x600, 64), (0x710, 64), (0x30, 4)]


# 22-23: real shape, input changed


def test_real_shape() -> None:
    source = real_shape()
    pe, notes = attach_tables(source, parse_pe(source))
    assert notes == ()
    assert pe.overlay == OverlayInfo(
        Address(867840), 138953784, ByteRange(*REAL_CERT), 138944048, 0, ()
    )
    assert sorted(c for c in source.calls if c[0] >= 867840) == [
        (867840, 64),
        (139811888, 8),
    ]
    assert pe.certificates == (CertificateEntry(Address(139811888), 9729, 0x200, 2),)


@pytest.mark.parametrize(
    ("cut", "honest", "offset"),
    [(0x20600, 14, 0x20600), (0x610, 15, 0x600)],
    ids=["certificate-header", "overlay-probe"],
)
def test_input_changed_in_tables(cut: int, honest: int, offset: int) -> None:
    with pytest.raises(InputChanged) as err:
        PeParser().parse(ShrinkingSource(PT64, cut=cut, honest_reads=honest), PRODUCER)
    assert err.value.offset == offset


# 24-26: signature probes (O3-O4)


@pytest.mark.parametrize("rule", WINDOW_RULES, ids=[r.name for r in WINDOW_RULES])
def test_window_signature(rule: SignatureRule) -> None:
    info, _ = _overlay(_with_window(bytes(rule.at) + rule.magic))
    assert info is not None
    assert info.signatures == (SignatureMatch(rule.name, Address(0x600)),)


def test_window_without_signature() -> None:
    info, _ = _overlay(_with_window(b""))
    assert info is not None
    assert info.signatures == ()


def test_file_anchored_signature() -> None:
    info, _ = _overlay(_with_window(b"")[:0x30] + b"Inno" + _with_window(b"")[0x34:])
    assert info is not None
    assert info.signatures == (SignatureMatch("inno-loader", Address(0x30)),)


def test_file_anchored_signature_needs_overlay() -> None:
    assert _overlay(P64[:0x30] + b"Inno" + P64[0x34:]) == (None, [])


def test_short_window_no_match() -> None:
    info, calls = _overlay(P64 + b"7z\xbc")
    assert info is not None
    assert info.signatures == ()
    assert calls == [(0x600, 3), (0x30, 4)]


def test_no_trailing_probe_without_trailing_bytes() -> None:
    info, calls = _overlay(PT64[:-16])
    assert info is not None
    assert info.trailing_size == 0
    assert calls == [(0x600, 64), (0x30, 4)]


def test_match_window_reports_window_offset() -> None:
    window = bytes(4) + b"\xef\xbe\xad\xdeNullsoftInst"
    assert match_window(window, 0x1234) == (SignatureMatch("nsis", Address(0x1234)),)
    assert match_window(window[:-1], 0x1234) == ()


# 27: the table


def test_signature_table() -> None:
    names = [r.name for r in SIGNATURES]
    assert len(set(names)) == len(names)
    for rule in SIGNATURES:
        assert re.fullmatch(r"[a-z0-9-]{1,32}", rule.name)
        assert len(rule.magic) >= 3
        assert rule.at + len(rule.magic) <= SIGNATURE_WINDOW


@pytest.mark.parametrize(
    ("at", "magic"), [(0, b"PK"), (61, b"Inno")], ids=["two-bytes", "past-window"]
)
def test_signature_rule_invariants(at: int, magic: bytes) -> None:
    with pytest.raises(ParseError):
        SignatureRule("x", SignatureAnchor.WINDOW, at, magic)
