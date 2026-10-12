# Slice 1: shared kernel vocabulary + findings types + explicit raw image loading

Implements ADR 0001 (Decision, safety checks 1-10) and the `shared` part of ADR 0002 (findings types, control 11
contract). Repo facts verified at b271d51. `architect review required`: grows the kernel, adds a use case and
`retool.formats` exports, edits `.importlinter`. Revision 3 (review rounds 1-2 applied).

## Scope
In: `shared` gains `ArchitectureId`, `AddressSpace`, `SpaceAddress` (ADR 0001) and `Provenance`, `Verification`,
`Finding`, `NotAnalysed`, `JsonValue` (ADR 0002). `formats` gains `Format.RAW`, `MappedSegment`, `MemoryMap`, `Image`,
`RawSegmentSpec`, `RawLoadSpec`, `build_raw_image`, `LoadRawImage`, `RawImageInfo`, `SegmentInfo`. `retool info` gains
the raw flags, the UNKNOWN hint and unreadable input -> exit 1. `.importlinter` gains the assist ban.
Out: any `assist` code; firmware splitting; checksums; seg:off conversion; `FormatParser`/registry; JSON report;
reading mapped bytes beyond the magic probe; sha256 in raw output; width or memory-size syntax on the CLI.

## Architecture
| Module | Context / layer | Pattern | Implements |
|---|---|---|---|
| `shared/values.py` (+3 classes) | shared kernel | value objects, `__post_init__` raises `ParseError` (§4) | ADR 0001 Decision "shared gains three pure value objects" |
| `shared/findings.py` (new) | shared kernel | value objects + `StrEnum` | ADR 0002 "Findings types live in shared" |
| `shared/json_value.py` (new) | shared kernel | PEP 695 type alias | ADR 0002 "recursive JsonValue alias" |
| `formats/domain/model.py` | formats / domain | enum member | ADR 0001 "`Format` gains RAW, detect() never returns it" |
| `formats/domain/image.py` (new) | formats / domain | value objects (no identity); `MemoryMap` and `Image` validate cross-field invariants in `__post_init__`; `RawSegmentSpec`/`RawLoadSpec` are request objects | ADR 0001 `MappedSegment`, `MemoryMap`, `Image`, `RawLoadSpec`; checks 5-8 |
| `formats/domain/services.py` | formats / domain | pure domain service | `build_raw_image(spec, source_size) -> Image`; checks 3, 4 |
| `formats/application/{dto,use_cases}.py` | formats / application | DTO of display fields; use case `VerbNoun.execute()` | `LoadRawImage(source).execute(RawLoadSpec)`; checks 9, 10 |
| `formats/__init__.py` | formats public API | re-exports (no infrastructure, A3) | ADR 0001 "exported through retool.formats" |
| `formats/infrastructure/filesystem.py` | formats / infrastructure | adapter translates `OSError` to `RetoolError` at the boundary (§4 Adapters, Errors) | ARCHITECTURE.md §4 "only RetoolError subclasses cross a layer boundary" |
| `interface/cli/main.py` | interface | composition root; builds the request only (A7) | ADR 0001 CLI flags + UNKNOWN hint |
Ports: none new; `LoadRawImage` uses existing `ByteSource` (`formats/domain/ports.py:11-19`). No context boundary changes
beyond what ARCHITECTURE.md §2 rows (already amended) state. All new domain modules import only stdlib + `retool.shared` (A1).

## Interfaces
All modules start with `from __future__ import annotations`; every dataclass is `@dataclass(frozen=True, slots=True)`.
No validation error message echoes a rejected name or id (ids, space names, segment names); numbers are not echoed
when they come from the user unbounded (e.g. `SpaceAddress`: `address exceeds {width}-bit space`).
`shared/values.py` (append; `Address` and `ByteRange` unchanged, `values.py:10-45`):
```python
_ID = re.compile(r"[a-z0-9_.:-]{1,32}")        # ADR 0001 charset
_NAME = re.compile(r"[a-z0-9_.-]{1,32}")       # (assumption) no ':'/'@' so CLI suffixes and str() stay unambiguous
class ArchitectureId:   name: str              # _ID.fullmatch else ParseError; __str__ -> name
class AddressSpace:     name: str; width_bits: int     # no default; _NAME.fullmatch; 1 <= width_bits <= 64
    @property
    def max_offset(self) -> int: ...          # (1 << width_bits) - 1
class SpaceAddress:     space: AddressSpace; offset: Address  # offset.value <= space.max_offset; __str__ -> f"{space.name}:0x{offset.value:x}"
```
`shared/json_value.py`: `type JsonValue = str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]`
`shared/findings.py` (constants are not in `retool.shared.__all__`):
```python
MIN_LLM_CHECKS = 2; MAX_CHECKS = 16                     # (assumption) 16
_PRODUCER = re.compile(r"[a-z0-9_.:-]{1,64}")           # also used for check names
class Provenance(StrEnum): PARSED="parsed"; DISASSEMBLED="disassembled"; INFERRED="inferred"; LLM_SUGGESTED="llm_suggested"
class Verification:
    class Status(StrEnum): UNVERIFIED="unverified"; PASSED="passed"; REJECTED="rejected"   # (assumption) nested: exports = ADR names
    status: Verification.Status; checks: tuple[str, ...] = (); reason: str = ""
    # UNVERIFIED: checks == () and reason == "".
    # PASSED (assumption): 1 <= len(checks) <= MAX_CHECKS, each _PRODUCER.fullmatch, no duplicates, reason == "".
    # REJECTED (assumption): 1 <= len(reason) <= 256, reason.isprintable(), checks == (). Else ParseError.
    @classmethod
    def unverified(cls) -> Verification: ...
    @classmethod
    def passed(cls, checks: tuple[str, ...]) -> Verification: ...
    @classmethod
    def rejected(cls, reason: str) -> Verification: ...
class Finding:
    subject: str            # (assumption) stable key, e.g. "ram:0x8000000"; 1..256 chars, str.isprintable()
    value: JsonValue
    provenance: Provenance
    verification: Verification
    producer: str           # _PRODUCER.fullmatch, e.g. "formats.raw"
    # LLM_SUGGESTED with PASSED and len(checks) < MIN_LLM_CHECKS -> ParseError (ADR 0002 control 5, defence in depth)
class NotAnalysed:  reason: str   # (assumption) 1..256 chars, isprintable()
```
`shared/__init__.py` adds all eight ADR names to imports and `__all__`.
`formats/domain/model.py`: `RAW = "raw"`; docstring: "set only by an explicit raw load; detect() never returns it".
`formats/domain/image.py`:
```python
MAX_SEGMENTS = 64
MAX_IMAGE_SIZE = 1 << 32                      # (assumption) Ghidra MAX_BINARY_SIZE analogue
DEFAULT_SPACE = AddressSpace("ram", 64)       # ADR 0001 default space
_SEGMENT_NAME = re.compile(r"[a-z0-9_.-]{1,32}")   # (assumption)
class MappedSegment:  file: ByteRange; start: SpaceAddress; mem_size: int; name: str
    # mem_size >= 1 ("empty segment"); mem_size >= file.size; file.size == 0 allowed (BSS-only / unbacked region,
    # ELF PT_LOAD p_filesz == 0; ADR 0001 cites Binary Ninja "Unbacked Region"); length >= 1 is build_raw_image's rule;
    # start.offset.value + mem_size - 1 <= start.space.max_offset; _SEGMENT_NAME.fullmatch (not echoed)
    def contains(self, addr: SpaceAddress) -> bool: ...   # addr.space == start.space (name AND width) and start <= addr < start + mem_size
class MemoryMap:  segments: tuple[MappedSegment, ...]
    # 1 <= len <= MAX_SEGMENTS; one width per space name; sum(mem_size) <= MAX_IMAGE_SIZE; no overlap within a space
    def segment_at(self, addr: SpaceAddress) -> MappedSegment | None: ...
    def file_range_for(self, addr: SpaceAddress, size: int) -> ByteRange: ...
class Image:  arch: ArchitectureId; memory: MemoryMap; entry: SpaceAddress | None; format: Format
    # entry None, or segment_at(entry) is not None; a segment space with entry.space.name but another width -> "declared with two widths"
class RawSegmentSpec:  file_offset: int; file_length: int | None; start: SpaceAddress; mem_size: int | None = None; name: str | None = None
    # Request object: no __post_init__ by design (bounds need source_size; build_raw_image checks them).
    # (assumption) file_length None = to end of source; (assumption) mem_size None = file length; name None = f"seg{index}".
class RawLoadSpec:  arch: ArchitectureId; segments: tuple[RawSegmentSpec, ...]; entry: SpaceAddress | None = None
    # __post_init__: 1 <= len(segments) <= MAX_SEGMENTS
```
`file_range_for(addr, size)`: `size < 1` -> ParseError; `seg = segment_at(addr)` else ParseError("address not mapped");
`rel = addr.offset.value - seg.start.offset.value`; `rel + size > seg.mem_size` -> ParseError("read crosses segment end"); return
`ByteRange(seg.file.start + min(rel, seg.file.size), max(0, min(size, seg.file.size - rel)))`. The caller pads the
missing tail with zeros (zero-fill is virtual, check 9).
`formats/domain/services.py` (`detect` at `services.py:20-33` unchanged; it already slices `data[:4]` and compares, so
heads of 0-3 bytes are safe, `services.py:26-33`):
```python
def build_raw_image(spec: RawLoadSpec, source_size: int) -> Image: ...
def structured_format(head: bytes) -> Format | None: ...   # detect(head) unless UNKNOWN; any len(head) >= 0
```
`build_raw_image` per segment `i`: check 3; `length = source_size - off if file_length is None else file_length`;
check 4 (`length >= 1`, then `ByteRange(off, length).check_within(source_size)`); `MappedSegment(file, start,
length if mem_size is None else mem_size, name or f"seg{i}")`; then `MemoryMap(...)`, then
`Image(spec.arch, memory, spec.entry, Format.RAW)`.
`formats/application/dto.py` (display fields only; the DTO never carries `Image`):
```python
class SegmentInfo:   name: str; start: SpaceAddress; mem_size: int; file_start: int; file_size: int
class RawImageInfo:  source_size: int; format: Format; arch: ArchitectureId; entry: SpaceAddress | None
                     segments: tuple[SegmentInfo, ...]; shadowed_format: Format | None
```
`formats/application/use_cases.py`: `_MAGIC_WINDOW = 4` (== `_HEADER_LEN`, `services.py:7`; every magic in `detect` is <= 4 bytes)
```python
class LoadRawImage:
    def __init__(self, source: ByteSource) -> None: ...
    def execute(self, spec: RawLoadSpec) -> RawImageInfo: ...
    # size = source.size; image = build_raw_image(spec, size)   (no read on failure; success implies size >= 1)
    # head = source.read(0, min(_MAGIC_WINDOW, size)); shadowed = structured_format(head); never switches loader
    # map image -> RawImageInfo field by field (no rules)
```
`formats/__init__.py` adds: `DEFAULT_SPACE, Image, LoadRawImage, MappedSegment, MemoryMap, RawImageInfo, RawLoadSpec,
RawSegmentSpec, SegmentInfo` (`build_raw_image` stays internal; tests import it from the domain module).

## Files
Modify: `src/retool/shared/values.py` (45 lines; `Address` :10-21, `ByteRange` :24-45), `src/retool/shared/__init__.py`
(:3-6), `src/retool/formats/domain/model.py` (`Format` :8-14), `src/retool/formats/domain/services.py` (`detect(data: bytes)`
:20), `src/retool/formats/application/dto.py` (`FileInfo` :10-14), `src/retool/formats/application/use_cases.py`
(`InspectFile` :15-32, reads head 4096 at :31), `src/retool/formats/__init__.py` (:6-12), `src/retool/interface/cli/main.py`
(`_cmd_info` :14-20, single `info` subparser :27-28, returns 2 on unknown command :33), `.importlinter` (:24-31),
`src/retool/formats/infrastructure/filesystem.py` (`path.stat()` in `__init__` :13; `open`/`seek`/`read` in `read()` :19-24):
wrap each in `try`/`except OSError as exc` and `raise RetoolError(f"cannot read input: {exc.strerror or 'I/O error'}") from exc`
(existing base class; the kernel gains nothing; the path is not echoed),
`docs/architecture/ARCHITECTURE.md` §7: replace the line beginning "Contracts these ADRs require" (l.65) with exactly:
"Contracts these ADRs require in `.importlinter`. Slice 1 adds `retool.assist` to `shared-kernel-pure` and item 2 early, with `retool.formats` as the only source; item 2 gains `retool.disasm`/`.analysis`/`.reporting` in the change that creates each one (import-linter rejects a missing source module). The rest of item 1, and item 3, are added in the same change that creates `assist`:"
`tests/formats/test_detect.py` (parametrized `test_detect` :6-18), `tests/interface/test_cli.py` (`test_info` :8-16).
Create: `src/retool/shared/findings.py`, `src/retool/shared/json_value.py`, `src/retool/formats/domain/image.py`,
`tests/shared/test_space.py`, `tests/shared/test_findings.py`, `tests/formats/fakes.py`, `tests/formats/test_raw_image.py`,
`tests/formats/test_load_raw.py`, `tests/formats/test_filesystem.py`. Do not touch `tests/formats/test_inspect.py` (its inline `MemorySource` stays).
Context facts: `ParseError(reason, *, offset=None)` (`shared/errors.py:13`); `check_within` raises with
`offset=self.start` (`values.py:39-44`); `FileByteSource` stats the path in `__init__` (`filesystem.py:11-13`), so today a
missing path raises `OSError` there and a directory raises it on `open` in `read()` (`filesystem.py:22`); `ByteSource.read` may return fewer bytes at the end (`ports.py:17-18`).

## Safety checks
Every ParseError below carries `offset=None` unless a file offset is named. Reasons are substrings tests match on.
| # | ADR 0001 check | Raised in | Reason (substring) | offset |
|---|---|---|---|---|
| 1 | arch required, charset, never inferred | `ArchitectureId.__post_init__`; CLI `--raw` without `--arch` -> exit 2 | `invalid architecture id` (value not echoed) | None |
| 2 | base required, no default 0 | API: `RawSegmentSpec.start` has no default (omitting it is a `TypeError`); CLI: neither `--base` nor `--map` -> exit 2; ParseError only for zero segments in `RawLoadSpec.__post_init__` | `no segment declared` | None |
| 3 | 0 <= file offset < source size | `build_raw_image` | `segment file offset outside source` | file_offset |
| 4 | length >= 1, offset+length <= size | `build_raw_image`; `ByteRange.check_within`; `MappedSegment` (mem_size >= 1) | `empty segment` / `exceeds` | file_offset (None from `MappedSegment`) |
| 5 | mem_size >= length; start+mem_size-1 <= 2**w-1 | `MappedSegment.__post_init__` (and `SpaceAddress` for start) | `memory size smaller than file length` / `segment exceeds address space` / `address exceeds` | None |
| 6 | 1 <= count <= 64; total incl. zero-fill <= MAX_IMAGE_SIZE | `RawLoadSpec.__post_init__` (count, before any loop); `MemoryMap.__post_init__` (count, total) | `segment count` / `mapped size exceeds` | None |
| 7 | no overlap within a space | `MemoryMap.__post_init__` (sort per space; also one width per space name) | `segments overlap in space` / `declared with two widths` | None |
| 8 | entry inside a segment of its space | `Image.__post_init__` (space compared by name and width) | `entry outside every segment` / `declared with two widths` | None |
| 9 | bounded windows, never whole, virtual zero-fill | `LoadRawImage.execute` reads only `[0, min(4, size))`; `Image`/`MemoryMap`/DTO hold no bytes; `file_range_for` | (no error) | - |
| 10 | magic under `--raw` only warns | `LoadRawImage.execute` -> `RawImageInfo.shadowed_format`; CLI prints warning | (no error) | - |

## CLI
`retool info PATH [--raw --arch ID (--base ADDR [--offset N] [--length N] | --map OFF:ADDR:SIZE[@SPACE] ...) [--entry ADDR[@SPACE]]]`
- Integers: `int(text, 0)` (decimal or `0x`); `ValueError` (incl. Python's 4300-digit decimal limit) ->
  `argparse.ArgumentTypeError` -> exit 2. Sign/range checks are the domain's (negative values reach
  `Address`/`build_raw_image` and fail with exit 1). Verified on Python 3.13: `--offset -1` parses to -1;
  `--map -1:0:1` is an argparse "expected one argument" error (exit 2); `--map=-1:0:1` parses.
- `--map` (append): `body, _, space = text.rpartition("@")` when `@` present (empty space -> exit 2); `body.split(":")` must
  give exactly 3 integers -> `RawSegmentSpec(off, size, SpaceAddress(space_or_default, Address(addr)))`, `mem_size=None`,
  where `@SPACE` builds `AddressSpace(space, DEFAULT_SPACE.width_bits)` (assumption: `@SPACE` always creates a 64-bit space).
  `--entry` takes the same `ADDR[@SPACE]` suffix (assumption; ADR shows `--entry ADDR`).
- `--base` -> one `RawSegmentSpec(offset or 0, length, SpaceAddress(DEFAULT_SPACE, Address(base)))` (ADR: shorthand).
- Usage errors via the `info` subparser's `error()` (exit 2): `--raw` without `--arch`; `--raw` without `--base`/`--map`;
  `--base` with `--map` (assumption: mutually exclusive); `--offset`/`--length` without `--base`; any raw flag without `--raw`.
- Without `--raw`: unchanged output (`main.py:16-19`); if `format is Format.UNKNOWN`, also print to stderr exactly
  `unknown format; to load as a raw image use --raw --arch --base`; exit 0. Never falls back to raw.
- With `--raw`: `LoadRawImage(FileByteSource(path)).execute(spec)`; stdout lines `path:   {path}`, `size:   {n}`,
  `format: raw`, `arch:   {arch}`, `entry:  {"none" if info.entry is None else info.entry}`, then per `SegmentInfo`
  `segment {name}: {start} mem=0x{mem_size:x} file=0x{file_start:x}+0x{file_size:x}`. If `shadowed_format is not None`,
  stderr `warning: input starts with {fmt} magic; loaded as raw because --raw was given`. Exit 0.
- `RetoolError` from request building, `FileByteSource` (unreadable input, both paths of `info`) or the use case ->
  stderr `error: {exc}`, exit 1. main.py catches `RetoolError` only, never `OSError`. No `struct`/`ByteRange(` in main.py (A7).

## Tests
Fakes (`tests/formats/fakes.py`): `MemorySource(data)` and `SparseSource(size, head=b"")` (reports `size` without holding
it; returns `head` then zeros); both record `calls: list[tuple[int, int]]`. `seg(off, length, start, mem_size=None,
name=None)` builds `RawSegmentSpec`. `ram = DEFAULT_SPACE`, `rom = AddressSpace("rom", 64)`, `bank1 = AddressSpace("bank1", 16)`,
`arm = ArchitectureId("armv7")`, `sa(space, n) = SpaceAddress(space, Address(n))`.
`tests/shared/test_space.py`:
1. `test_arch_id_accepts` [`"armv7"`, `"pi32v2"`, `"x86_64"`, `"a"*32`] -> `str(id) == name`.
2. `test_arch_id_rejects` [`""`, `"a"*33`, `"ARM"`, `"arm v7"`, `"arm/../x"`, `"arm\n"`, `"arm%s"`, `"armж"`] -> ParseError, offset None, input not in `str(exc)` (check 1).
3. `test_space_width` 1 and 64 ok; [0, 65, -1] -> ParseError; `AddressSpace("x")` -> TypeError. `test_space_name_rejects` [`""`, `"ram:1"`, `"r@m"`, `"a"*33`, `"r\x1b[2J"`] -> ParseError, input not in `str(exc)`.
4. `test_space_address_bounds`: `sa(bank1, 0xFFFF)` ok, `0x10000` -> ParseError; `sa(ram, 2**64-1)` ok, `2**64` -> ParseError, `str(2**64)` not in message.
5. `test_space_address_str`: `sa(ram, 0x8000000)` -> `"ram:0x8000000"`.
`tests/shared/test_findings.py`:
6. `test_provenance_members` == {parsed, disassembled, inferred, llm_suggested}.
7. `test_verification_factories`: unverified(), passed(("a","b")), rejected("r") construct; statuses match.
8. `test_verification_rejects` [PASSED+(), PASSED+("a","a"), PASSED+("",), PASSED+("Bad Check",), PASSED+17 distinct names, PASSED+reason, REJECTED+"", REJECTED+"a"*257, REJECTED+"a\nb", REJECTED+checks, UNVERIFIED+checks, UNVERIFIED+reason] -> ParseError; PASSED+16 distinct ok.
9. `test_llm_passed_needs_two_checks`: LLM_SUGGESTED+passed(("x",)) -> ParseError; with ("x","y") ok; PARSED+passed(("x",)) ok.
10. `test_finding_rejects` subject [`""`, `"a"*257`, `"a\nb"`], producer [`"Bad Producer"`, `"a"*65`] -> ParseError.
11. `test_finding_json_value`: value `{"a": [1, 2.5, None, True, "x"]}` stored unchanged. `test_not_analysed`: [`""`, `"a"*257`, `"a\nb"`] -> ParseError; `"budget exceeded"` ok.
`tests/formats/test_raw_image.py` (domain, `build_raw_image(RawLoadSpec(arm, segs, entry), size)` unless noted):
12. `test_single_mapping` (happy): size 0x100, `seg(0, None, sa(ram, 0x8000000))` -> format RAW, one segment, file `ByteRange(0,0x100)`, mem 0x100, name `seg0`, entry None.
13. `test_base_with_offset_length`: `seg(0x10, 0x20, sa(ram, 0))`, size 0x100 -> file `ByteRange(0x10, 0x20)`.
14. `test_multi_mapping`: size 0x100; `seg(0,0x40,sa(ram,0))`, `seg(0x40,0x40,sa(ram,0x1000))`, `seg(0x80,0x80,sa(bank1,0x4000))` -> 3 segments; `segment_at(sa(ram,0x1010)).name == "seg1"`; `segment_at(sa(ram,0x800)) is None`; `segment_at(sa(bank1,0x4000)).name == "seg2"`.
15. `test_zero_fill_tail`: size 0x10, `seg(0, 0x10, sa(ram,0x2000), mem_size=0x100)` -> `file_range_for(sa(ram,0x2008), 0x10) == ByteRange(0x8, 0x8)`; `(sa(ram,0x2020), 0x10) == ByteRange(0x10, 0)`; `(sa(ram,0x20f8), 0x10)`, `(sa(ram,0x3000), 1)`, `(sa(ram,0x2000), 0)` -> ParseError.
16. `test_arch_without_disassembler`: `ArchitectureId("pi32v2")` loads; `image.arch.name == "pi32v2"`.
17. `test_check2_no_segment`: `RawLoadSpec(arm, ())` -> ParseError `no segment declared`; `RawSegmentSpec(0, None)` -> TypeError.
18. `test_check3_offset` [(off 0, size 0), (-1, 16), (16, 16), (2**64, 16)] with `seg(off, None, sa(ram,0))` -> ParseError, `exc.offset == off`; (15, 16) ok.
19. `test_check4_length` [(0, 0, 16) `empty segment`, (0, -5, 16), (8, 9, 16) offset 8, (0, 2**64, 16)] -> ParseError with offset == file offset; (8, 8, 16) ok. Direct `MappedSegment(ByteRange(0,0), sa(ram,0), 0, "s")` -> `empty segment`; `MappedSegment(ByteRange(0x10,0), sa(ram,0), 0x10, "bss")` ok (BSS-only).
20. `test_check5_mem_size` (size 0x100): `seg(0,0x10,sa(ram,0),mem_size=0x8)` -> `memory size smaller`; `seg(0,0x100,sa(bank1,0xFF00))` ok; same with `mem_size=0x101` -> `segment exceeds address space`; `seg(0,0x20,sa(ram,2**64-0x10))` -> `segment exceeds address space`; `seg(0,1,sa(ram,0),name="Bad\x1b")` -> ParseError, name not in message.
21. `test_check6_count`: 65 specs `seg(0,1,sa(ram,i))` -> ParseError `segment count` at `RawLoadSpec(...)`; size 64, `seg(i,1,sa(ram,i))` for i<64 ok; `MemoryMap(())` -> `segment count`; size 0x10: `seg(0,0x10,sa(ram,0),mem_size=MAX_IMAGE_SIZE+1)` -> `mapped size exceeds`, `mem_size=MAX_IMAGE_SIZE` ok; `seg(0,0x10,sa(ram,0),mem_size=MAX_IMAGE_SIZE//2+1)` + `seg(0,0x10,sa(rom,0),mem_size=MAX_IMAGE_SIZE//2+1)` -> `mapped size exceeds`.
22. `test_check7_overlap` (size 0x100): `seg(0,0x10,sa(ram,0))`+`seg(0x10,0x10,sa(ram,0xF))` -> `segments overlap`; +`seg(0x10,0x10,sa(ram,0x10))` ok (adjacent); +`seg(0x10,0x10,sa(bank1,0))` ok; `seg(0,0x10,sa(ram,0),mem_size=0x100)`+`seg(0x10,0x10,sa(ram,0x80))` -> overlap (zero-fill); `seg(0,0x10,sa(ram,0x100))`+`seg(0x10,0x10,sa(ram,0x108))` -> overlap (declared high-to-low); `seg(0,0x10,sa(AddressSpace("x",16),0))`+`seg(0x10,0x10,sa(AddressSpace("x",32),0x1000))` -> `declared with two widths`.
23. `test_check8_entry` (size 0x10, `seg(0,0x10,sa(ram,0x1000),mem_size=0x100)`): entry `sa(ram,0x1000)` ok; `sa(ram,0x10ff)` ok (zero-fill); `sa(ram,0x1100)` -> `entry outside every segment`; `sa(bank1,0x1000)` -> `entry outside`; `sa(AddressSpace("ram",32),0x1000)` -> `declared with two widths`; None ok.
24. `test_detect_never_returns_raw` (in `test_detect.py`): every 1- and 2-byte head, `b""`, and each magic of `services.py:9-17,27-31` (`b"\x7fELF"`, `b"MZ"`, `b"\xfe\xed\xfa\xce"`, `b"\xce\xfa\xed\xfe"`, `b"\xfe\xed\xfa\xcf"`, `b"\xcf\xfa\xed\xfe"`, `b"\xca\xfe\xba\xbe"`) alone and `+ b"\0"*60` -> `detect(h) is not Format.RAW`.
`tests/formats/test_load_raw.py` (application, fakes only):
25. `test_load_raw_happy`: `MemorySource(bytes(range(256)))`, `seg(0,None,sa(ram,0x8000000))` -> `source_size == 256`, `format is RAW`, one `SegmentInfo("seg0", sa(ram,0x8000000), 0x100, 0, 0x100)`, `entry is None`, `shadowed_format is None`.
26. `test_check9_bounded_reads`: `SparseSource(1 << 31)`, `seg(0,None,sa(ram,0))` -> ok, `calls == [(0, 4)]`; offset `1 << 31` -> ParseError, `calls == []`; `MemorySource(b"\0")` and `MemorySource(b"\x7fEL")` with `seg(0,None,sa(ram,0))` -> ok, `shadowed_format is None`, `calls == [(0, len(data))]`.
27. `test_check10_magic_under_raw`: [`b"\x7fELF"+b"\0"*60` -> ELF, `b"MZ"` (2-byte source; `detect` tests `head[:2]`, `services.py:29`) -> PE, `b"\xcf\xfa\xed\xfe"+b"\0"*60` -> MACHO, `b"\0"*64` -> None] -> `format is RAW`, `shadowed_format` as listed.
`tests/interface/test_cli.py` (tmp_path files; raw cases use `--raw --arch armv7` unless stated):
28. `test_info_unknown_hint`: `b"\0"*16` -> 0; stdout `format: unknown`; stderr contains the exact hint.
29. `test_info_raw_single`: `b"\0"*0x100`, `--base 0x8000000` -> 0; stdout has `format: raw`, `arch:   armv7`, `entry:  none`, `segment seg0: ram:0x8000000 mem=0x100 file=0x0+0x100`.
30. `test_info_raw_multi_map`: `b"\0"*0x100`, `--map 0:0x0:0x80 --map 0x80:0x4000:0x80@bank1 --entry 0x4000@bank1` -> 0; two segment lines; `entry:  bank1:0x4000`.
31. `test_info_raw_magic_warning`: ELF bytes, `--base 0` -> 0; stdout `format: raw`; stderr `warning: input starts with elf magic`.
32. `test_info_raw_usage_errors` [no `--arch`; no `--base`/`--map`; `--base`+`--map`; `--offset` with `--map`; `--arch` without `--raw`; `--map 1:2`; `--map a:b:c`; `--base zz`; `--map 0:0:1@`; `--base` + 4301 decimal digits; `--map -1:0:1`] -> `SystemExit` code 2.
33. `test_info_raw_domain_errors` (file `b"\0"*16`) [`--arch ARM --base 0`; `--base 0 --offset 0x100`; `--base 0 --offset -1`; `--base 0 --length 0`; `--map=-1:0:1`; `--base 0x1000 --entry 0x10`; `--base 0x` + `"f"*5000`] -> 1, stderr starts `error:`, no stderr line longer than 200 chars.
34. `test_info_missing_path` [with and without `--raw --arch armv7 --base 0`] on `tmp_path / "missing"` -> 1, stderr starts `error:`.
`tests/formats/test_filesystem.py` (infrastructure, tmp_path):
35. `test_missing_path_raises_retool_error`: `FileByteSource(tmp_path / "missing")` -> `RetoolError` (not `OSError`; `pytest.raises(RetoolError)` and `not isinstance(exc.value, OSError)`), message starts `cannot read input:`.
36. `test_directory_raises_retool_error`: `FileByteSource(tmp_path).read(0, 4)` -> `RetoolError`, not `OSError`.
Check -> test map: 1:2,32 · 2:17,32 · 3:18,33 · 4:19,33 · 5:20,4,33 · 6:21 · 7:22 · 8:23,33 · 9:15,26 · 10:27,31.

## Import-linter
Verified with import-linter 2.15 on a scratch copy of `.importlinter`: a missing **source** module fails the run
(`Module 'retool.disasm' does not exist.`, `importlinter/contracts/forbidden.py:103,220-225`, exit 1); a missing
**forbidden** module is skipped (`forbidden.py:107`), so `retool.assist` may be named before it exists (5 kept, 0 broken).
The assist ban is added deliberately early, with the `shared` findings types it protects. ARCHITECTURE.md §7 says these
contracts are "not yet present; added ... in the same change that creates `assist`"; this slice replaces that line
(text in `## Files`). The ARCHITECTURE.md §7 edit lands in the same commit as the `.importlinter` change.
1. In `shared-kernel-pure` (`.importlinter:24-31`) append `    retool.assist` to `forbidden_modules` (§7 item 1, shared part).
2. Append:
```ini

# ADR 0002 control 11: deterministic contexts never import the LLM context.
# Add retool.disasm / retool.analysis / retool.reporting to source_modules in the change that
# creates each one (import-linter 2.15 rejects a missing source module).
[importlinter:contract:no-assist-in-deterministic]
name = deterministic contexts do not import assist
type = forbidden
source_modules =
    retool.formats
forbidden_modules =
    retool.assist
```
§7 item 3 is out of scope here (no assist, no SDK). It belongs to the spec that creates assist, which verifies
include_external_packages as §7 requires. A4 covers this slice.

## Risks
- `JsonValue` (PEP 695 recursive) is an open check: scratch run of mypy 2.4.0 `--strict` accepted it and rejected
  `{"a": {1}}` and `{1: "x"}`. If `make typecheck` rejects it, fallback: `from typing import TypeAlias`;
  `JsonValue: TypeAlias = "str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]"  # noqa: UP040`
  (also verified under mypy 2.4.0; ruff UP040 flags it, so the noqa is required). mypy covers `src` only (`pyproject.toml:40-42`).
- `JsonValue` is static typing only: it admits NaN/inf floats and unbounded depth. Deferred: the JSON-report spec adds
  bounded runtime validation (depth, node count, finite floats, str keys).
- `Finding` with a list/dict `value` is unhashable (frozen dataclass `__hash__` raises TypeError): never put it in sets.
- No context constructs `Finding` yet; ADR 0002 revisit trigger ("only one context constructs Finding") applies after the next spec.
- Open (architect): `--base` vs `--map` mutually exclusive; `--entry ADDR@SPACE`; CLI spaces always 64-bit and no
  memory-size syntax, so zero-fill and narrow spaces are API-only in this slice; `Finding.subject: str` and
  `NotAnalysed` without a subject (ADR names only `reason`); `MAX_IMAGE_SIZE = 4 GiB`; `MAX_CHECKS = 16`; name charsets.

## Acceptance
1. `make check` passes (ruff, mypy --strict, import-linter 5 contracts kept, archcheck ok, pytest).
2. Tests 1-36 exist under the names above and pass; each ADR 0001 check appears in the check -> test map.
3. `grep -c "Format.RAW" src/retool/formats/domain/services.py` prints 1 (only in `build_raw_image`), and test 24 passes.
4. `src/retool/shared/__init__.py` `__all__` equals the 4 old names plus the 8 ADR names; no other shared additions.
5. `grep -rnE "struct\.|ByteRange\(" src/retool/interface` is empty; `grep -rn "import" src/retool/shared` shows no `retool.formats`/`retool.assist`.
6. `grep -nw "Image" src/retool/formats/application/dto.py` prints nothing (the DTO holds no `Image`).
7. `grep -n "except OSError" src/retool/interface/cli/main.py` prints nothing; `docs/architecture/ARCHITECTURE.md` §7 contains the new line verbatim.
8. No file under `src/retool/assist/`; `git diff --stat` lists only the files in `## Files`.
