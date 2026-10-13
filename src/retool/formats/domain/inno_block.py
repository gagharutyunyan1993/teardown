"""Domain service: deframe an Inno Setup header block and decode it (ADR 0003).

A block body is chunks of CRC32 u32 + up to 4096 payload bytes (issrc ``Compression.Base.pas``
TCompressedBlockReader). The first 5 payload bytes are the LZMA1 properties; the rest is the
raw LZMA1 stream. Every read goes through ``read_exact``; chunks after the codec's end of
stream are neither read nor CRC-checked (as Setup) and count as trailing bytes.
"""

from __future__ import annotations

import struct
import zlib
from collections.abc import Iterator
from itertools import chain
from typing import Final

from retool.formats.domain.decompress import (
    MAX_STORED_BLOCK,
    Codec,
    Decoded,
    DecodeError,
    DecodeFailure,
    decompress,
    lzma1_params,
)
from retool.formats.domain.inno import BLOCK_HEADER_SIZE, InnoBlockHeader, InnoCompression
from retool.formats.domain.parsing import read_exact
from retool.formats.domain.ports import ByteSource

CHUNK_PAYLOAD: Final = 4096
_CRC_SIZE: Final = 4
_PROPS_SIZE: Final = 5


def block_chunks(source: ByteSource, block: InnoBlockHeader) -> Iterator[bytes]:
    """CRC-verified chunk payloads of ``block``'s body, read lazily one chunk at a time."""
    at = block.offset.value
    pos = at + BLOCK_HEADER_SIZE
    left = block.stored_size
    k = 0
    while left > 0:
        if left < _CRC_SIZE + 1:
            raise DecodeError(DecodeFailure.TRUNCATED, "chunk header truncated", offset=at)
        n = min(CHUNK_PAYLOAD, left - _CRC_SIZE)
        raw = read_exact(source, source.size, pos, _CRC_SIZE + n)
        k += 1
        (crc,) = struct.unpack_from("<I", raw)
        payload = raw[_CRC_SIZE:]
        if zlib.crc32(payload) != crc:
            raise DecodeError(DecodeFailure.CRC, f"chunk {k} CRC mismatch", offset=at)
        yield payload
        pos += _CRC_SIZE + n
        left -= _CRC_SIZE + n


def decode_block(
    source: ByteSource, block: InnoBlockHeader, *, cap: int, declared: int | None = None
) -> Decoded:
    """Decode an LZMA1 header block; ``trailing`` includes the stored bytes never read."""
    at = block.offset.value
    if block.compression is not InnoCompression.LZMA1:
        reason = f"block compression {block.compression} not decoded"
        raise DecodeError(DecodeFailure.UNAVAILABLE, reason, offset=at)
    stored = block.stored_size
    if stored > MAX_STORED_BLOCK:
        reason = f"stored size {stored} exceeds {MAX_STORED_BLOCK} bytes"
        raise DecodeError(DecodeFailure.OVER_CAP, reason, offset=at)
    if at + BLOCK_HEADER_SIZE + stored > source.size:
        raise DecodeError(DecodeFailure.TRUNCATED, "block body past end of file", offset=at)
    yielded = 0

    def counted() -> Iterator[bytes]:
        nonlocal yielded
        for payload in block_chunks(source, block):
            yielded += _CRC_SIZE + len(payload)
            yield payload

    chunks = counted()
    head = b""
    while len(head) < _PROPS_SIZE:
        piece = next(chunks, None)
        if piece is None:
            raise DecodeError(DecodeFailure.TRUNCATED, "lzma1 properties truncated", offset=at)
        head += piece
    params = lzma1_params(head[:_PROPS_SIZE], at)
    rest = chain((head[_PROPS_SIZE:],), chunks)
    out = decompress(Codec.LZMA1_RAW, params, rest, cap=cap, declared=declared, offset=at)
    return Decoded(out.data, out.consumed, out.trailing + (stored - yielded), out.ended)
