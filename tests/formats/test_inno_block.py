"""Slice 6b: Inno header block deframing and decoding, t55-t60."""

from __future__ import annotations

import hashlib
import random
import struct
import zlib

import pytest

from retool.formats.domain.decompress import MAX_STORED_BLOCK, DecodeError, DecodeFailure
from retool.formats.domain.inno import InnoBlockHeader, InnoCompression, parse_block_header
from retool.formats.domain.inno_block import block_chunks, decode_block
from retool.formats.domain.ports import ByteSource
from retool.shared import Address
from tests.formats.fakes import MemorySource, SparseSource
from tests.formats.inno_build import (
    G7_BLOCK1,
    G7_BLOCK2,
    G7_SHA256_1,
    G7_SHA256_2,
    G7_STREAM1,
    G7_STREAM2,
    framed,
    lzma1_block,
    raw_lzma1,
)

AT = 0x10
PROPS = b"\x5d\x00\x00\x01\x00"


def _source(block_bytes: bytes) -> tuple[MemorySource, InnoBlockHeader]:
    data = bytes(AT) + block_bytes
    header = parse_block_header(data[AT : AT + 9], AT, 1, (6, 4, 3, 0))
    return MemorySource(data), header


def _raw_block(body: bytes, stored: int | None = None) -> bytes:
    head = struct.pack("<IB", len(body) if stored is None else stored, 1)
    return struct.pack("<I", zlib.crc32(head)) + head + body


def _kind(source: ByteSource, header: InnoBlockHeader) -> DecodeError:
    with pytest.raises(DecodeError) as info:
        decode_block(source, header, cap=1 << 20)
    return info.value


def test_t55_chunk_reads() -> None:
    payload = bytes(range(256)) * 35 + bytes(32)  # 8,992 B -> stored 9,004
    source, header = _source(_raw_block(framed(payload)))
    assert b"".join(block_chunks(source, header)) == payload
    pos = AT + 9
    assert source.calls == [(pos, 4100), (pos + 4100, 4100), (pos + 8200, 804)]


def test_t56_chunk_crc() -> None:
    body = bytearray(framed(bytes(9000)))
    body[4100] ^= 1
    source, header = _source(_raw_block(bytes(body)))
    exc = _kind(source, header)
    assert exc.kind is DecodeFailure.CRC
    assert str(exc) == f"chunk 2 CRC mismatch at offset {AT:#x}"


LONG_STREAM = raw_lzma1(random.Random(1).randbytes(12_000))  # > 2 chunks, never ends early


@pytest.mark.parametrize("stored", [2 * 4100 + 4, 3])
def test_t57_chunk_header_truncated(stored: int) -> None:
    source, header = _source(_raw_block(framed(PROPS + LONG_STREAM)[:stored]))
    exc = _kind(source, header)
    assert (exc.kind, exc.reason) == (DecodeFailure.TRUNCATED, "chunk header truncated")


def test_t56_crc_after_output_records_decoded() -> None:
    body = bytearray(framed(PROPS + LONG_STREAM))
    body[4100] ^= 1  # chunk 2 CRC
    source, header = _source(_raw_block(bytes(body)))
    exc = _kind(source, header)
    assert (exc.kind, exc.reason) == (DecodeFailure.CRC, "chunk 2 CRC mismatch")
    assert exc.decoded > 0


def test_t57_body_past_end() -> None:
    source = MemorySource(bytes(64))
    header = InnoBlockHeader(1, Address(AT), 0, 64 - AT - 9 + 1, 1, InnoCompression.LZMA1, True)
    exc = _kind(source, header)
    assert (exc.kind, str(exc)) == (
        DecodeFailure.TRUNCATED,
        f"block body past end of file at offset {AT:#x}",
    )
    assert source.calls == []


def test_t58_props_truncated() -> None:
    source, header = _source(_raw_block(framed(PROPS[:3])))
    assert header.stored_size == 7
    exc = _kind(source, header)
    assert (exc.kind, exc.reason) == (DecodeFailure.TRUNCATED, "lzma1 properties truncated")


def test_t58_props_invalid() -> None:
    source, header = _source(lzma1_block(1, G7_STREAM1, props=b"\xe1\x00\x00\x01\x00"))
    exc = _kind(source, header)
    assert (exc.kind, exc.reason) == (DecodeFailure.BAD_PARAMS, "lzma1 properties 225 invalid")


def test_t59_stored_over_cap() -> None:
    stored = MAX_STORED_BLOCK + 1
    source = SparseSource(stored + 64)
    header = InnoBlockHeader(1, Address(AT), 0, stored, 1, InnoCompression.LZMA1, True)
    exc = _kind(source, header)
    assert (exc.kind, exc.reason) == (
        DecodeFailure.OVER_CAP,
        f"stored size {stored} exceeds 16777216 bytes",
    )
    assert source.calls == []


def test_t60_payload_hashes() -> None:
    assert hashlib.sha256(G7_BLOCK1).hexdigest() == G7_SHA256_1
    assert hashlib.sha256(G7_BLOCK2).hexdigest() == G7_SHA256_2
    assert len(G7_STREAM1) == 149


@pytest.mark.parametrize(("stream", "payload"), [(G7_STREAM1, G7_BLOCK1), (G7_STREAM2, G7_BLOCK2)])
def test_t60_pinned_streams_decode(stream: bytes, payload: bytes) -> None:
    source, header = _source(lzma1_block(1, stream))
    out = decode_block(source, header, cap=1 << 20)
    assert (out.data, out.consumed, out.trailing, out.ended) == (payload, len(stream), 0, True)


def test_t60_trailing_chunks_never_read() -> None:
    junk = 4096 - len(PROPS) - len(G7_STREAM1)  # unused data in chunk 1
    body = framed(PROPS + G7_STREAM1 + b"j" * junk + b"x" * 4096 + b"y" * 20)
    source, header = _source(_raw_block(body))
    out = decode_block(source, header, cap=1 << 20)
    assert out.data == G7_BLOCK1
    assert out.trailing == junk + 4100 + 24
    assert source.calls == [(AT + 9, 4100)]


@pytest.mark.parametrize(
    ("compression", "flag"), [(InnoCompression.ZLIB, 1), (InnoCompression.STORED, 0)]
)
def test_non_lzma1_block_unavailable(compression: InnoCompression, flag: int) -> None:
    source = MemorySource(bytes(64))
    header = InnoBlockHeader(1, Address(AT), 0, 8, flag, compression, True)
    exc = _kind(source, header)
    assert (exc.kind, str(exc)) == (
        DecodeFailure.UNAVAILABLE,
        f"block compression {compression} not decoded at offset {AT:#x}",
    )
    assert source.calls == []
