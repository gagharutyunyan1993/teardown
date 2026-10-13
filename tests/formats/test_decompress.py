"""Slice 6b: bounded decompression (ADR 0003), t40-t54."""

from __future__ import annotations

import ast
import bz2
import gzip
import lzma
import random
import sys
import zlib
from collections.abc import Iterable, Iterator
from pathlib import Path

import pytest

from retool.formats.domain import decompress as dmod
from retool.formats.domain.decompress import (
    MAX_DECODED_TOTAL,
    MAX_STALLS,
    RATIO_FLOOR,
    STEP,
    Codec,
    Decoded,
    DecodeError,
    DecodeFailure,
    LzmaParams,
    decompress,
    lzma1_params,
)
from retool.formats.domain.model import InputChanged
from tests.formats.inno_build import G7_BLOCK1, G7_STREAM1, raw_lzma1

P = LzmaParams(3, 0, 2, 1 << 16)
DOMAIN = Path(__file__).parents[2] / "src" / "retool" / "formats" / "domain"


def _lz(chunks: Iterable[bytes], *, cap: int = MAX_DECODED_TOTAL, **kw: int) -> Decoded:
    return decompress(Codec.LZMA1_RAW, P, chunks, cap=cap, **kw)


def _fails(kind: DecodeFailure, codec: Codec, data: bytes, **kw: int) -> DecodeError:
    params = P if codec is Codec.LZMA1_RAW else None
    cap = kw.pop("cap", MAX_DECODED_TOTAL)
    with pytest.raises(DecodeError) as info:
        decompress(codec, params, [data], cap=cap, **kw)
    assert info.value.kind is kind
    return info.value


# t40: round trip


@pytest.mark.parametrize("size", [len(G7_STREAM1), 7])
def test_t40_lzma1_round_trip(size: int) -> None:
    chunks = [G7_STREAM1[i : i + size] for i in range(0, len(G7_STREAM1), size)]
    out = _lz(chunks)
    assert out == Decoded(G7_BLOCK1, len(G7_STREAM1), 0, True)


# t41-t43: caps


def test_t41_over_cap() -> None:
    exc = _fails(DecodeFailure.OVER_CAP, Codec.LZMA1_RAW, raw_lzma1(bytes(200_000)), cap=100_000)
    assert exc.decoded == 100_001
    assert exc.reason == "output exceeds 100000 bytes"


def test_t42_over_ratio() -> None:
    _fails(DecodeFailure.OVER_RATIO, Codec.LZMA1_RAW, raw_lzma1(bytes(3 << 20)))


def test_t43_ratio_bound_is_strict() -> None:
    out = _lz([raw_lzma1(bytes(RATIO_FLOOR))])
    assert out.ended
    assert len(out.data) == RATIO_FLOOR


# t44: truncated


def test_t44_lzma1_truncated_is_unterminated() -> None:
    out = _lz([G7_STREAM1[:-6]])
    assert not out.ended
    assert len(out.data) == 739
    assert G7_BLOCK1.startswith(out.data)


@pytest.mark.parametrize(
    ("codec", "stream"),
    [(Codec.ZLIB, zlib.compress(G7_BLOCK1)[:-4]), (Codec.BZIP2, bz2.compress(G7_BLOCK1)[:-10])],
)
def test_t44_truncated(codec: Codec, stream: bytes) -> None:
    exc = _fails(DecodeFailure.TRUNCATED, codec, stream)
    assert exc.reason.startswith("stream truncated after ")


# t45: parameters


@pytest.mark.parametrize(
    "props",
    [b"\xe1\x00\x00\x01\x00", b"\x0d\x00\x00\x01\x00", b"\x5d\x01\x00\x00\x40"],
)
def test_t45_bad_props(props: bytes) -> None:
    with pytest.raises(DecodeError) as info:
        lzma1_params(props, 0x640)
    assert info.value.kind is DecodeFailure.BAD_PARAMS
    assert info.value.offset == 0x640


def test_t45_max_dict_accepted() -> None:
    assert lzma1_params(b"\x5d\x00\x00\x00\x40", 0) == LzmaParams(3, 0, 2, 1 << 30)


def test_t45_dict_zero_clamped() -> None:
    out = decompress(Codec.LZMA1_RAW, LzmaParams(3, 0, 2, 0), [G7_STREAM1], cap=1 << 20)
    assert out.data == G7_BLOCK1


def test_t45_bad_params_vo_and_missing() -> None:
    with pytest.raises(DecodeError) as info:
        LzmaParams(3, 0, 5, 1 << 16)
    assert info.value.kind is DecodeFailure.BAD_PARAMS
    with pytest.raises(DecodeError) as info:
        decompress(Codec.LZMA1_RAW, None, [G7_STREAM1], cap=1 << 20)
    assert info.value.kind is DecodeFailure.BAD_PARAMS


# t46: dictionary clamp

CLAMP_DATA = bytes(range(256)) * 1250
CLAMP_STREAM = raw_lzma1(CLAMP_DATA, dict_size=1 << 26)


def test_t46_dict_clamp(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[int] = []
    real = lzma.LZMADecompressor

    def spy(fmt: int, filters: list[dict[str, int]]) -> lzma.LZMADecompressor:
        seen.append(filters[0]["dict_size"])
        return real(fmt, filters=filters)

    monkeypatch.setattr(lzma, "LZMADecompressor", spy)
    out = decompress(
        Codec.LZMA1_RAW, LzmaParams(3, 0, 2, 1 << 26), [CLAMP_STREAM], cap=len(CLAMP_DATA)
    )
    assert out.data == CLAMP_DATA
    assert seen == [320_000]


# t47: zlib


class _ZlibSpy:
    def __init__(self, inner: zlib._Decompress, lengths: list[int]) -> None:
        self._inner = inner
        self._lengths = lengths

    @property
    def eof(self) -> bool:
        return self._inner.eof

    @property
    def unused_data(self) -> bytes:
        return self._inner.unused_data

    @property
    def unconsumed_tail(self) -> bytes:
        return self._inner.unconsumed_tail

    def decompress(self, data: bytes, max_length: int) -> bytes:
        self._lengths.append(max_length)
        return self._inner.decompress(data, max_length)


def test_t47_zlib_bounded_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    lengths: list[int] = []
    real = zlib.decompressobj
    monkeypatch.setattr(zlib, "decompressobj", lambda wbits: _ZlibSpy(real(wbits), lengths))
    data = b"ab" * (1 << 19)
    stream = zlib.compress(data)
    out = decompress(Codec.ZLIB, None, [stream], cap=MAX_DECODED_TOTAL)
    assert out == Decoded(data, len(stream), 0, True)
    assert len(lengths) >= (1 << 20) // STEP
    assert max(lengths) <= STEP


def test_t47_zlib_empty_stored_blocks() -> None:
    empty = b"\x00\x00\x00\xff\xff"
    stream = b"\x78\x01" + empty * 200_000 + b"\x01\x00\x00\xff\xff" + zlib.adler32(b"").to_bytes(4)
    out = decompress(Codec.ZLIB, None, [stream], cap=MAX_DECODED_TOTAL)
    assert out == Decoded(b"", len(stream), 0, True)
    assert 1_000_000 < out.consumed < 1_000_020


# t48: bz2


def test_t48_bz2_round_trip() -> None:
    assert decompress(Codec.BZIP2, None, [bz2.compress(G7_BLOCK1)], cap=1 << 20).data == G7_BLOCK1


def test_t48_bz2_trailing() -> None:
    stream = bz2.compress(G7_BLOCK1)
    out = decompress(Codec.BZIP2, None, [stream + b"junk"], cap=1 << 20)
    assert out == Decoded(G7_BLOCK1, len(stream), 4, True)


# t49: lazy optional codecs


@pytest.mark.parametrize(("module", "codec"), [("lzma", Codec.LZMA1_RAW), ("bz2", Codec.BZIP2)])
def test_t49_unavailable(monkeypatch: pytest.MonkeyPatch, module: str, codec: Codec) -> None:
    monkeypatch.setitem(sys.modules, module, None)
    exc = _fails(DecodeFailure.UNAVAILABLE, codec, b"x")
    assert exc.reason == f"codec {codec} unavailable"


def _module_level_imports(node: ast.AST) -> Iterator[str]:
    """Imported module names outside function bodies (try/if/class blocks included)."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            continue
        if isinstance(child, ast.Import):
            yield from (alias.name for alias in child.names)
        elif isinstance(child, ast.ImportFrom):
            yield child.module or ""
        yield from _module_level_imports(child)


def test_t49_no_module_level_optional_codec_import() -> None:
    for path in sorted(DOMAIN.glob("*.py")):
        names = {n.split(".")[0] for n in _module_level_imports(ast.parse(path.read_text()))}
        assert not names & {"lzma", "bz2"}, path.name


def test_t49_scan_sees_guarded_imports() -> None:
    tree = ast.parse(
        "try:\n    import lzma\nexcept ImportError:\n    pass\ndef f():\n    import bz2\n"
    )
    assert set(_module_level_imports(tree)) == {"lzma"}


# t50: declared size


def test_t50_declared_over_cap_never_pulls() -> None:
    pulled: list[int] = []

    def chunks() -> Iterator[bytes]:
        pulled.append(1)
        yield G7_STREAM1

    with pytest.raises(DecodeError) as info:
        _lz(chunks(), cap=5, declared=10)
    assert info.value.kind is DecodeFailure.DECLARED_OVER_CAP
    assert pulled == []


@pytest.mark.parametrize("size", [99, 101])
def test_t50_size_mismatch(size: int) -> None:
    _fails(DecodeFailure.SIZE_MISMATCH, Codec.LZMA1_RAW, raw_lzma1(bytes(size)), declared=100)


@pytest.mark.parametrize(("cap", "declared"), [(-1, None), (10, -1)])
def test_t50_negative_is_programming_error(cap: int, declared: int | None) -> None:
    with pytest.raises(ValueError, match="non-negative"):
        _lz([G7_STREAM1], cap=cap, **({} if declared is None else {"declared": declared}))


# t51: corrupt


def _raw_deflate(data: bytes) -> bytes:
    c = zlib.compressobj(wbits=-15)
    return c.compress(data) + c.flush()


@pytest.mark.parametrize(
    ("codec", "stream"),
    [
        (Codec.ZLIB, b"\x78\x9c\xff\xff"),
        (Codec.ZLIB, _raw_deflate(G7_BLOCK1)),
        (Codec.ZLIB, gzip.compress(G7_BLOCK1)),
    ],
)
def test_t51_corrupt(codec: Codec, stream: bytes) -> None:
    exc = _fails(DecodeFailure.CORRUPT, codec, stream)
    assert exc.reason.startswith("stream corrupt after ")


def test_t51_lzma_dict_too_small() -> None:
    # Deviation: the t46 data only has distance-256 matches, which a 4096-B dict decodes;
    # a 16 KiB pseudo-random block repeated needs a dict > 4096 (E4's failure mode).
    data = random.Random(0).randbytes(16384) * 20
    stream = raw_lzma1(data, dict_size=1 << 26)
    with pytest.raises(DecodeError) as info:
        decompress(Codec.LZMA1_RAW, LzmaParams(3, 0, 2, 4096), [stream], cap=1 << 20)
    assert info.value.kind is DecodeFailure.CORRUPT
    assert "Corrupt input data" not in str(info.value)


# t52: iterator errors propagate


def test_t52_input_changed_propagates() -> None:
    error = InputChanged(offset=5)

    def chunks() -> Iterator[bytes]:
        yield G7_STREAM1[:10]
        raise error

    with pytest.raises(InputChanged) as info:
        _lz(chunks())
    assert info.value is error


def test_t52_iterator_decode_error_keeps_kind_and_records_output() -> None:
    def chunks() -> Iterator[bytes]:
        yield G7_STREAM1[:100]
        raise DecodeError(DecodeFailure.CRC, "chunk 2 CRC mismatch", offset=0x640)

    with pytest.raises(DecodeError) as info:
        _lz(chunks())
    exc = info.value
    assert (exc.kind, str(exc)) == (DecodeFailure.CRC, "chunk 2 CRC mismatch at offset 0x640")
    assert 0 < exc.decoded < len(G7_BLOCK1)


def test_t53_lzma2_unavailable() -> None:
    exc = _fails(DecodeFailure.UNAVAILABLE, Codec.LZMA2_RAW, b"x")
    assert exc.reason == "codec lzma2 not implemented"


# t54: no-progress and memory guards


class _Fake:
    """A decoder that never progresses; optionally raises MemoryError on call ``boom``."""

    def __init__(self, calls: list[int], boom: int = 0) -> None:
        self._calls = calls
        self._boom = boom
        self.eof = False
        self.needs_input = False
        self.unused_data = b""

    def decompress(self, data: bytes, max_length: int) -> bytes:
        self._calls.append(max_length)
        if len(self._calls) == self._boom:
            raise MemoryError
        return b""


@pytest.mark.parametrize(("boom", "reason"), [(0, "made no progress"), (2, "out of memory")])
def test_t54_fake_decoder(monkeypatch: pytest.MonkeyPatch, boom: int, reason: str) -> None:
    calls: list[int] = []
    monkeypatch.setattr(lzma, "LZMADecompressor", lambda *a, **k: _Fake(calls, boom))
    exc = _fails(DecodeFailure.CORRUPT, Codec.LZMA1_RAW, b"x")
    assert reason in exc.reason
    assert len(calls) == (MAX_STALLS + 1 if boom == 0 else boom)


def test_t54_endless_empty_chunks() -> None:
    def chunks() -> Iterator[bytes]:
        yield G7_STREAM1[:50]
        while True:
            yield b""

    with pytest.raises(DecodeError) as info:
        _lz(chunks())
    assert info.value.kind is DecodeFailure.CORRUPT
    assert "made no progress" in info.value.reason


def test_module_caps_values() -> None:
    assert (dmod.MAX_STORED_BLOCK, dmod.MAX_DECODED_TOTAL, dmod.MAX_RATIO) == (
        1 << 24,
        1 << 26,
        1024,
    )
    assert (dmod.RATIO_FLOOR, dmod.STEP, dmod.LZMA_MAX_DICT, dmod.LZMA_MIN_DICT) == (
        1 << 20,
        1 << 16,
        1 << 30,
        4096,
    )
    assert (dmod.MAX_DECODE_DEPTH, dmod.MAX_STALLS) == (1, 8)
