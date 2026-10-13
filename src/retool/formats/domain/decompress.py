"""Bounded streaming decompression of a container's own metadata blocks (ADR 0003).

Pure domain service over stdlib codecs. ``bz2``/``lzma`` are optional builds and are imported
lazily inside functions; ``zlib`` is always present. Output is bounded by ``cap`` (or the
declared size), a compression-ratio tripwire and a no-progress guard; codec failures become
``DecodeError`` with static text + numbers, never the stdlib message. Decoded bytes are never
decoded again (depth 1).
"""

from __future__ import annotations

import zlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from retool.shared import ParseError

MAX_STORED_BLOCK: Final = 1 << 24
MAX_DECODED_TOTAL: Final = 1 << 26
MAX_RATIO: Final = 1024
RATIO_FLOOR: Final = 1 << 20
STEP: Final = 1 << 16
LZMA_MAX_DICT: Final = 1 << 30
LZMA_MIN_DICT: Final = 4096
MAX_DECODE_DEPTH: Final = 1  # documentary: decoded bytes are never decoded again
MAX_STALLS: Final = 8  # consecutive no-progress decoder calls before CORRUPT

_PROPS_LIMIT: Final = 225  # lc/lp/pb byte: 9 * 5 * 5


class Codec(StrEnum):
    """A codec declared by container structure (never sniffed)."""

    ZLIB = "zlib"
    BZIP2 = "bzip2"
    LZMA1_RAW = "lzma1"
    LZMA2_RAW = "lzma2"


class DecodeFailure(StrEnum):
    """Why a decode stopped; closed set (ADR 0003)."""

    BAD_PARAMS = "bad_params"
    OVER_CAP = "over_cap"
    OVER_RATIO = "over_ratio"
    DECLARED_OVER_CAP = "declared_over_cap"
    SIZE_MISMATCH = "size_mismatch"
    TRUNCATED = "truncated"
    CORRUPT = "corrupt"
    CRC = "crc"
    UNAVAILABLE = "unavailable"


class DecodeError(ParseError):
    """A failed decode; ``offset`` is a file offset (the block header), never a decoded one."""

    def __init__(
        self, kind: DecodeFailure, reason: str, *, offset: int | None = None, decoded: int = 0
    ) -> None:
        super().__init__(reason, offset=offset)
        self.kind = kind
        self.decoded = decoded


@dataclass(frozen=True, slots=True)
class LzmaParams:
    """LZMA literal/position bits and dictionary size, validated before decoder construction."""

    lc: int
    lp: int
    pb: int
    dict_size: int

    def __post_init__(self) -> None:
        if not (
            self.lc >= 0
            and self.lp >= 0
            and self.lc + self.lp <= 4
            and 0 <= self.pb <= 4
            and 0 <= self.dict_size <= LZMA_MAX_DICT
        ):
            raise DecodeError(DecodeFailure.BAD_PARAMS, "lzma parameters invalid")


@dataclass(frozen=True, slots=True)
class Decoded:
    """Decoded output, input bytes consumed, input bytes left after the end, end marker seen."""

    data: bytes
    consumed: int
    trailing: int
    ended: bool

    def __post_init__(self) -> None:
        if self.consumed < 0 or self.trailing < 0:
            raise ParseError("decoded sizes must be non-negative")


def lzma1_params(props: bytes, offset: int) -> LzmaParams:
    """Decode the 5-byte LZMA1 properties (Misc byte + u32 LE dictionary size)."""
    if len(props) != 5:
        raise DecodeError(DecodeFailure.TRUNCATED, "lzma1 properties truncated", offset=offset)
    p = props[0]
    lc, lp, pb = p % 9, (p // 9) % 5, p // 45
    if p >= _PROPS_LIMIT or lc + lp > 4:
        raise DecodeError(DecodeFailure.BAD_PARAMS, f"lzma1 properties {p} invalid", offset=offset)
    dict_size = int.from_bytes(props[1:5], "little")
    if dict_size > LZMA_MAX_DICT:
        raise DecodeError(
            DecodeFailure.BAD_PARAMS,
            f"lzma1 dictionary {dict_size} exceeds {LZMA_MAX_DICT}",
            offset=offset,
        )
    return LzmaParams(lc, lp, pb, dict_size)


class _Decoder(Protocol):
    @property
    def eof(self) -> bool: ...
    @property
    def unused_data(self) -> bytes: ...
    def decompress(self, data: bytes, max_length: int, /) -> bytes: ...


@dataclass(frozen=True, slots=True)
class _Engine:
    """One decoder plus codec-specific views: pending input and whether it wants a new chunk."""

    decoder: _Decoder
    tail: Callable[[], bytes]
    hungry: Callable[[], bool]
    errors: tuple[type[Exception], ...]


def _zlib() -> _Engine:
    z = zlib.decompressobj(wbits=15)
    return _Engine(z, lambda: z.unconsumed_tail, lambda: not z.unconsumed_tail, ())


def _bz2() -> _Engine:
    import bz2  # optional build: lazy (ADR 0003)

    d = bz2.BZ2Decompressor()
    return _Engine(d, lambda: b"", lambda: d.needs_input, ())


def _lzma1(params: LzmaParams, limit: int) -> _Engine:
    import lzma  # optional build: lazy (ADR 0003)

    filters = [
        {
            "id": lzma.FILTER_LZMA1,
            "dict_size": max(LZMA_MIN_DICT, min(params.dict_size, limit)),
            "lc": params.lc,
            "lp": params.lp,
            "pb": params.pb,
        }
    ]
    try:
        d = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filters)
    except (lzma.LZMAError, ValueError, MemoryError):
        raise DecodeError(DecodeFailure.BAD_PARAMS, "decoder rejected parameters") from None
    return _Engine(d, lambda: b"", lambda: d.needs_input, (lzma.LZMAError,))


def _engine(codec: Codec, params: LzmaParams | None, limit: int) -> _Engine:
    try:
        if codec is Codec.ZLIB:
            return _zlib()
        if codec is Codec.BZIP2:
            return _bz2()
        if codec is Codec.LZMA1_RAW:
            if params is None:
                raise DecodeError(DecodeFailure.BAD_PARAMS, "lzma1 parameters missing")
            return _lzma1(params, limit)
    except ImportError:
        raise DecodeError(DecodeFailure.UNAVAILABLE, f"codec {codec} unavailable") from None
    raise DecodeError(DecodeFailure.UNAVAILABLE, f"codec {codec} not implemented")


def decompress(
    codec: Codec,
    params: LzmaParams | None,
    chunks: Iterable[bytes],
    *,
    cap: int,
    declared: int | None = None,
    offset: int | None = None,
) -> Decoded:
    """Decode ``chunks`` with ``codec`` producing at most ``cap`` (or exactly ``declared``) bytes.

    The next chunk is pulled only when the decoder needs input; after the end of stream no
    chunk is pulled. Iterator exceptions propagate; a ``DecodeError`` from the iterator is
    re-raised with the same kind, text and offset and ``decoded`` = output produced so far.
    """
    if cap < 0 or (declared is not None and declared < 0):
        raise ValueError("cap and declared must be non-negative")

    def fail(kind: DecodeFailure, reason: str, decoded: int = 0) -> DecodeError:
        return DecodeError(kind, reason, offset=offset, decoded=decoded)

    if declared is not None and declared > cap:
        raise fail(DecodeFailure.DECLARED_OVER_CAP, f"declared size {declared} exceeds {cap}")
    limit = cap if declared is None else declared
    try:
        engine = _engine(codec, params, limit)
    except DecodeError as exc:
        raise fail(exc.kind, exc.reason) from None
    dec = engine.decoder
    errors: tuple[type[Exception], ...] = (
        zlib.error,
        OSError,
        EOFError,
        ValueError,
        *engine.errors,
    )
    out = bytearray()
    fed = 0
    stalls = 0
    chunk_iter = iter(chunks)

    def consumed() -> int:
        return fed - len(engine.tail()) - len(dec.unused_data)

    def call(data: bytes) -> bytes:
        try:
            piece = dec.decompress(data, min(STEP, limit - len(out) + 1))
        except MemoryError:
            reason = f"decoder out of memory after {len(out)} output bytes"
            raise fail(DecodeFailure.CORRUPT, reason, len(out)) from None
        except errors:
            reason = f"stream corrupt after {len(out)} output bytes"
            raise fail(DecodeFailure.CORRUPT, reason, len(out)) from None
        out.extend(piece)
        if len(out) > limit:
            if declared is not None:
                reason = f"output exceeds declared {declared} bytes"
                raise fail(DecodeFailure.SIZE_MISMATCH, reason, len(out))
            raise fail(DecodeFailure.OVER_CAP, f"output exceeds {cap} bytes", len(out))
        if len(out) > RATIO_FLOOR and len(out) > MAX_RATIO * consumed():
            reason = f"output {len(out)} bytes exceeds ratio {MAX_RATIO}"
            raise fail(DecodeFailure.OVER_RATIO, reason, len(out))
        return piece

    while not dec.eof:
        new = False
        if engine.hungry():
            try:
                chunk = next(chunk_iter, None)
            except DecodeError as exc:  # framing failure: keep kind/text, record output so far
                raise DecodeError(
                    exc.kind, exc.reason, offset=exc.offset, decoded=len(out)
                ) from None
            if chunk is None:
                if codec is Codec.ZLIB:
                    while not dec.eof and call(b""):
                        pass
                break
            fed += len(chunk)
            new = len(chunk) > 0
            data = chunk
        else:
            data = engine.tail()
        if call(data) or new:
            stalls = 0
        else:
            stalls += 1
            if stalls > MAX_STALLS:
                raise fail(DecodeFailure.CORRUPT, "decoder made no progress", len(out))
    ended = dec.eof
    if not ended and codec in (Codec.ZLIB, Codec.BZIP2):
        reason = f"stream truncated after {len(out)} output bytes"
        raise fail(DecodeFailure.TRUNCATED, reason, len(out))
    if declared is not None and len(out) != declared:
        reason = f"output size {len(out)} differs from declared {declared}"
        raise fail(DecodeFailure.SIZE_MISMATCH, reason, len(out))
    return Decoded(bytes(out), consumed(), len(dec.unused_data) if ended else 0, ended)
