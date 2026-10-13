# 0003. Container metadata blocks are decompressed by one pure, bounded stdlib streaming function in `formats/domain`

Date: 2026-10-13   Status: accepted   Deciders: judge (opus/xhigh) on proposals from analyst A (opus/high), analyst B (sonnet/high)

## Context
The Inno Setup slice (6a) parses loader structures and block headers up to the compressed body. The architect ruling of 2026-10-13 made "extracting, decompressing or mapping an embedded payload" a `/decide` question (src: `docs/architecture/ARCHITECTURE.md` §2, `formats` row). Decoding the header blocks is the next step toward setup metadata. Constraints:
- Inputs are hostile and parsers bound every length (src: `CLAUDE.md` §Safety). The domain imports only stdlib + `shared`, with no I/O and no third-party code; runtime `dependencies = []` (src: ARCH §3; `pyproject.toml`).
- A `FormatParser` never raises except `InputChanged`/I-O, and its reasons are static text + numbers (src: `formats/domain/parsing.py:47-49`). An escaping `ParseError` collapses the whole parse into one "structure rejected" note (src: `parsing.py:54-72`).
- Firmware/container splitting is deferred to a future ADR (src: `docs/decisions/0001-raw-image-loading.md` l.89-90).

## Evidence
- E1 zlib: in one-shot `decompress(data, wbits, bufsize)`, bufsize is only the initial buffer size. `Decompress.decompress(data, max_length)` honours `max_length` and leaves the rest in `unconsumed_tail`. In `Decompress.flush(length)`, length is only the initial size (src: docs.python.org/3.13/library/zlib.html, fetched 2026-10-13).
- E2 lzma: `LZMADecompressor(format, memlimit, filters)` needs `filters` with FORMAT_RAW. `decompress(data, max_length)` is bounded. dict_size is 4 KiB..1.5 GiB; lc+lp ≤ 4; pb ≤ 4 (src: docs.python.org/3.13/library/lzma.html, 2026-10-13).
- E3 bz2: `decompress(data, max_length)`, `needs_input`, `eof`; EOFError after the end of stream (src: docs.python.org/3.13/library/bz2.html, 2026-10-13).
- E4 Probes on Python 3.13.16 with synthetic data (researcher + judge, 2026-10-13):
  - memlimit with FORMAT_RAW raises ValueError. lc/lp/pb of 4/1/2, 3/0/5 or 8/0/2 raise an opaque LZMAError("Internal error") at construction.
  - A 320 000 B stream encoded with a 64 MiB dict decodes identically with the dict set to len(output). With a 4096 B dict it fails with LZMAError("Corrupt input data").
  - Truncated LZMA input gives no exception and eof False. zlib `max_length` is honoured.
  - 1 000 002 B of empty stored deflate blocks give 0 output bytes. Under `ulimit -v 800000`, a 1.5 GiB dict raises MemoryError at construction.
- E5 Setup reads both header blocks with `TCompressedBlockReader.Create(SetupFile, TLZMA1Decompressor)` (src: issrc@is-6_4_3 `Projects/Src/Setup.MainFunc.pas` l.2740, l.2875). LZMA1 props are a Misc byte + u32 LE dict, and the dict must be ≤ 1 GiB (`MaxDictionarySize = 1024 shl 20`). Decoding uses `LZMA_FINISH_ANY`, so no end mark is required. The LZMA2 prop must be < 40 (src: issrc@is-6_4_3 `Compression.LZMADecompressor.pas`).
- E6 Inno block framing (src: issrc@is-6_4_3 `Compression.Base.pas`, `TCompressedBlockReader`):
  - HdrCRC u32 covers {StoredSize u32, Compressed bool}. The reader rejects a header CRC mismatch and a pos+StoredSize past EOF.
  - The body is chunks of CRC32 u32 + ≤ 4096 B. At least 5 bytes must remain before each chunk, and every chunk CRC is checked.
  - The reader never checks that the whole body was consumed; its destructor seeks past unread input.
- E7 innoextract master:
  - `src/stream/block.cpp`: version ≥ 4.1.6 → LZMA1, otherwise boost `zlib_decompressor()`.
  - `src/stream/lzma.cpp` l.78-85: rejects `properties > 225`; pb=p/45, lp=(p%45)/9, lc=p%9; dict u32 LE; `lzma_raw_decoder` (fetched 2026-10-13).
- E8 ClamAV `etc/clamd.conf.sample` (main, 2026-10-13):
  - MaxFileSize 100M, which also applies to files inside containers. MaxScanSize 400M extracted per input. MaxRecursion 17, MaxFiles 10000, MaxScanTime 120000 ms.
  - MaxEmbeddedPE 40M is the largest file checked for an embedded PE.
  - `Heuristics.Limits.Exceeded*` is flagged only with AlertExceedsMax, which defaults to no.
- E9 CWE-409 "Improper Handling of Highly Compressed Data" (v4.20). E10 CERT IDS04-J: the compliant solution counts the bytes actually extracted against TOOBIG = 100 MB and TOOMANY = 1024, and does not trust declared sizes. E11 Python zipfile: bombs are a listed limitation; no mitigation is prescribed (docs 3.13).
- E12 Repo facts:
  - archcheck A1/A4 allow every `sys.stdlib_module_names` member in domain (src: `tools/archcheck.py:22,62`).
  - The per-stage pattern is `except InputChanged: raise` / `except ParseError` → note (src: `inno_loader.py:148-152`, `pe_parser.py:59-78`). `InputChanged` subclasses `ParseError` (`model.py:21`).
  - `inno.py` already imports `zlib`.
  - Provenance is origin {PARSED, DISASSEMBLED, INFERRED, LLM_SUGGESTED}, and the gate anchors on PARSED/DISASSEMBLED (ADR 0002 l.99-112).
  - Sample: block 1 is stored as 34 817 B and block 2 as 1 663 B, both LZMA1 (researcher).

Conflicts: E7 accepts p = 225, which means pb = 5. That is invalid per E2/E4, so the rule is p < 225.
- E5 proves only that an end mark is not *required*. Whether the compiler writes one is (assumption), so both outcomes are accepted.

## Options considered
1. **Pure domain function on stdlib codecs.** For: no dependency or port; the caps are domain rules (ARCH §4); passes A1/A4 (E12). Against: C decoders run in-process, with no clock or rlimit isolation.
2. **Port + `infrastructure/stdlib_codecs.py`.** For: a later subprocess with rlimits/timeout; a fake decoder. Against: there is no sandbox to put behind it; the loop and caps stay in domain anyway; one more port and adapter just for stdlib.
3. **One-shot `zlib.decompress`/`lzma.decompress`.** Rejected: output is unbounded (E1, E2).
4. **A new DECODED provenance tier.** Rejected: it needs a superseding ADR 0002 and would remove these facts from the gate anchors (E12).

## Independent opinions
- Analyst A recommended `codec.py`, a `DecodeError(ParseError)` caught per block, 64 MiB per block + 16 MiB stored, and decode status as facts.
- Analyst B recommended `decompress.py`, a returned `Decompressed | Failed` result, 16 MiB per header + 64 MiB per parse, chunk-iterator input, and `want_prefix`.

Both agree on: stdlib only, the bounded loop, the dict clamp, ratio 1024 above 1 MiB, PARSED, depth 1, and a port as the runner-up.

How each disagreement was settled:
- Failure channel: A. It matches the repo's raise-and-catch-per-stage convention (E12). Both channels meet the contract, and B's escape risk gets a required test.
- Caps: B's structure (per object + per input total, as in E8 and E10), with A's single-block allowance. The magnitudes are (assumption).
- Props bound: B (p < 225; E2, E4, E7).
- No end mark: A's rule plus B's condition that the structural parse succeeds (E5, E6).
- Input: B's chunk iterator (E6).
- `want_prefix`: deferred, because no consumer exists.
- Status facts: A's, which makes limit hits machine-readable (E8).

## Decision
**Module.** `src/retool/formats/domain/decompress.py` is a pure domain service:
`decompress(codec, params, chunks: Iterable[bytes], *, cap: int, declared: int | None = None) -> Decoded`.
- `Decoded(data, consumed, trailing, ended: bool)` is frozen.
- Failures raise `DecodeError(ParseError)` with `kind: DecodeFailure`, a closed StrEnum: BAD_PARAMS, OVER_CAP, OVER_RATIO, DECLARED_OVER_CAP, SIZE_MISMATCH, TRUNCATED, CORRUPT, CRC, UNAVAILABLE.
- The reason is static text + numbers. The offset is the block header's file offset, never a decoded offset. Stdlib exception text is never echoed.
- `bz2`/`lzma` are imported lazily, because they are optional builds; ImportError → UNAVAILABLE. No port, no adapter, `dependencies = []`.

**Codecs.** The codec comes from declared structure only, never from sniffing.
- Closed enum {ZLIB, BZIP2, LZMA1_RAW, LZMA2_RAW}. Only declared members are implemented; Inno headers need ZLIB (< 4.1.6) and LZMA1_RAW (E5, E7).
- ZLIB uses `decompressobj(wbits=15)`, with no 47/31 auto-detect and no FORMAT_AUTO. That this is a zlib-wrapped stream per the boost default is (assumption); wbits 15 also accepts smaller windows.
- LZMA1_RAW uses `LZMADecompressor(FORMAT_RAW, filters=[{FILTER_LZMA1, ...}])` with no memlimit (E4). Before construction:
  - require p < 225, lc+lp ≤ 4 and pb ≤ 4 (E2, E4);
  - reject a declared dict > 1 GiB (E5);
  - set dict = max(4096, min(declared, cap)). The decoder never needs more than the output so far (E4); a round-trip test pins this.
- LZMA2_RAW: prop < 40, with the same dict rule.

**Loop.**
- STEP = 64 KiB; `max_length = min(STEP, cap - len(out) + 1)`.
- len(out) > cap → OVER_CAP.
- len(out) > RATIO_FLOOR and > MAX_RATIO × consumed → OVER_RATIO. This is a tripwire, not the primary bound.
- zlib is re-fed `unconsumed_tail`. bz2/lzma are fed `b""` while `not needs_input`. The next chunk is pulled only when input is needed.
- On eof, `trailing = len(unused_data)`, and no second stream is started. Never a one-shot call or `flush()`.
- Only codec errors are mapped: zlib.error, LZMAError, OSError, EOFError, ValueError, and MemoryError at construction. Iterator errors, including `InputChanged`, propagate.
- With a declared size, cap = min(declared, cap). declared > cap fails before decoding (DECLARED_OVER_CAP); a different output length → SIZE_MISMATCH. A declared size is never trusted alone (E10).

**Completeness.**
- ZLIB/BZIP2 are complete only on eof; input exhausted earlier → TRUNCATED.
- LZMA1_RAW is complete as `ended` on eof, or as `unterminated` when all stored input is consumed, every chunk CRC is valid and the decoder needs input (E5).
- Facts come from decoded bytes only if the decode is complete **and** the fixed-layout parse of those bytes succeeds.

**Caps.** Domain `Final`s, all (assumption) until a corpus is measured:
- MAX_STORED_BLOCK = 16 MiB compressed, checked against `stored_size` before any body byte is read. It bounds work, because input can be consumed without output (E4).
- MAX_DECODED_TOTAL = 64 MiB per parse; each block's cap is the remaining budget.
- MAX_RATIO = 1024, RATIO_FLOOR = 1 MiB, MAX_DECODE_DEPTH = 1, LZMA_MAX_DICT = 1 GiB (E5).

Why these values: Setup sets no header limit (E6). The sample block is 34 817 B, so 16 MiB stored is about 480× that. 64 MiB total is below ClamAV's 100M per contained file and 400M per input (E8), and below CERT's 100 MB (E10).

**Inno.** `inno.py`/`inno_loader.py` deframe:
- a generator yields CRC-verified chunks of ≤ 4096 B through `read_exact`;
- fewer than 5 bytes before a chunk → TRUNCATED; a chunk CRC mismatch → CRC;
- the 5-byte props are parsed before construction.

The loader catches per block (`except InputChanged: raise`, then `except ParseError` → `NotAnalysed(str(exc))`) and keeps the block-header facts. Example reason: "inno block 1 not decoded: output exceeds 67108864 bytes".

Each attempted block also yields a PARSED finding `inno.block{n}.decode` with the value `ended`, `unterminated` or the failure kind, plus the decoded size. Calling a limit hit a "possible bomb" belongs to `analysis`.

**Provenance.**
- Facts from decoded bytes are PARSED: the decode is deterministic, CRC-checked and structural (ADR 0002).
- The subject names the block, the codec and the offset in decoded space, e.g. `inno.block1[lzma1]+0x120:setup_header.app_name`.
- Decoded offsets are never wrapped in `Address`.

**Boundary with ADR 0001.**
- Decoded bytes stay in memory for the owning parser only. They never become an `Image`, `MemoryMap`, `RawLoadSpec`, a file, or `detect()` input. Depth is 1: decoded bytes are never decoded again.
- Inno data chunks (file payloads), extraction and mapping stay with the deferred splitting ADR. That ADR reuses `decompress` and these caps, and adds count/depth limits (E8).

## Consequences
- Easier: setup metadata becomes reachable with no dependencies. There is one audited loop and set of limits for every codec. Limit hits are visible as notes and as facts.
- Harder: CPU is bounded only by caps, not by a clock, and C decoders run in-process. A legitimate header over 64 MiB gives an OVER_CAP note. Peak memory is about dict + output ≤ 2 × 64 MiB (assumption).
- Follow-ups:
  1. ARCH §2, `formats` row: replace "without decompression; extracting, decompressing or mapping an embedded payload is a `/decide` question" with "bounded in-memory decompression of a container's own metadata blocks per ADR 0003 (depth 1); extracting or mapping an embedded payload remains a `/decide` question (ADR 0001 deferred splitting ADR)".
  2. ARCH §3: `llm`/`mcp` "pending ADR 0003/0004" becomes the next free numbers, as ADR 0002 l.133 provides.
  3. Add this ADR to ARCH §7.
  4. Change the `inno.py` docstring "no payload byte is decompressed" to "header blocks are decompressed only via `decompress.py` (ADR 0003); file data never".
  5. Write a spec with tests: dict-clamp round-trip; empty-stored-block bound; over-cap; ratio; truncated; bad props; a decode failure keeps the block-header facts.
  6. Add a line to `.claude/memory/DECISIONS.md`.

## Dissent
- Both analysts' runner-up: a port + `infrastructure/stdlib_codecs.py`, for rlimits/timeout, fakes and third-party codecs. Rejected because stdlib is allowed in domain (E12), the caps and loop are domain rules either way, and no sandbox exists. The signature is port-shaped, so a later move is cheap.
- Analyst B: a returned result, so a forgotten catch cannot reach `guarded_parse` and drop all facts. Kept as the alternative. Mitigation: a mandatory test, and `guarded_parse` never crashes.
- Analyst B: a 16 MiB per-header cap. Rejected because no source supports the value and the total budget already bounds memory.

## Revisit when
- A decoder CVE, an incident, or a need for wall-clock limits → a port with a sandboxed adapter (superseding ADR).
- Measured legitimate headers approach 64 MiB decoded or 16 MiB stored, or exceed ratio 1024.
- The Inno compiler is shown to always (or never) write an LZMA1 end mark → tighten or drop `unterminated`.
- The splitting ADR needs file payloads, an `Image` from decoded bytes, or depth > 1.
- A non-stdlib codec is needed, or archcheck stops treating `zlib`/`bz2`/`lzma` as stdlib.
- A consumer needs to tell decoder-derived facts apart from raw-file facts.

## Sources
- Python 3.13 zlib, lzma, bz2 and zipfile docs (fetched 2026-10-13).
- issrc@is-6_4_3: `Compression.LZMADecompressor.pas`, `Compression.Base.pas`, `Setup.MainFunc.pas`.
- innoextract master: `src/stream/lzma.cpp`, `src/stream/block.cpp`.
- ClamAV main `etc/clamd.conf.sample`; CWE-409 v4.20; SEI CERT IDS04-J. Local probes on Python 3.13.16 (2026-10-13).
- Repo: ARCHITECTURE.md §2–§4, §7; `tools/archcheck.py`; `formats/domain/{parsing,inno,inno_loader,pe_parser,model}.py`; ADR 0001; ADR 0002.
