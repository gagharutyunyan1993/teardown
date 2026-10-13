# Slice 6b: bounded decompression (ADR 0003) + Inno Setup 6.4.3 header and file list

## Scope
In: (A) `formats/domain/decompress.py` per ADR 0003. (B) Inno block deframing (CRC chunks) + LZMA1 props. (C) Block 1 of
**6.4.3 only**: setup header, every entry list read structurally (only File entries kept), wizard images, decompressor
DLL; block 2: file-location entries. (D) Findings `inno.block{n}.decode`, setup header, file entries (caps + truncation);
notes; JSON only; `STAGE_VERSION = "6"`; CLI code unchanged; schema_version unchanged (new subjects only).
Out (see ## Follow-ups): other Inno versions (one note), extraction or any file-data chunk byte, decryption, slices,
wizard image / icon / ini / registry / run / delete / type / component / task / dir / language / message content
(skipped only), stored (flag 0) or zlib header blocks (note), LZMA2 use. No change to `retool.formats.__all__`, `dto.py`,
`interface/`, `reporting/`, `shared/`, `.importlinter`, `PeFile` fields.
Encryption on: header blocks are read like any other (assumption: 6.4 encrypts file data chunks only; Setup reads both
blocks with a plain TCompressedBlockReader, E5); header and entries parse; data chunks are never touched; note N7 is
informational. If the assumption is wrong the LZMA decode fails → N4, no crash.

## Architecture
Conforms to ARCH §2 as amended by ADR 0003 (bounded in-memory decompression of a container's own metadata blocks,
depth 1), §3 (domain = stdlib + `shared`; `bz2`/`lzma` imported lazily inside functions; `zlib` top-level, as `inno.py`
already does), §4 (pure domain services; frozen VOs validated in `__post_init__` raising `ParseError`; capped counts;
`read_exact` before every file read). ADR 0002: facts via `parsed_finding`, provenance PARSED. Decoded bytes live only
inside one `inno_info` call; never an `Image`, `Address`, `ByteRange`, file, or `detect()` input. No new port, adapter
or context. **architect review required** (round 1: approved with A1-A5, applied): first decompression in the codebase;
aggregate `PeFile` grows through its child `InnoInfo` (+3 fields); new domain service `decompress`.
| Module | Context / layer | Pattern (ARCH §4) |
|---|---|---|
| `formats/domain/decompress.py` (new, leaf: stdlib + `shared`) | formats / domain | pure domain service `decompress`; VOs `LzmaParams`, `Decoded`; closed enums `Codec`, `DecodeFailure`; error `DecodeError(ParseError)`; caps |
| `formats/domain/inno_block.py` (new) | formats / domain | pure service: deframe a block from `ByteSource` (generator), parse props, call `decompress` |
| `formats/domain/inno_setup.py` (new, leaf: stdlib + `shared`) | formats / domain | `Cursor` (local, mutable, never stored); `Final` tuples `HEADER_FIELDS`, `LISTS_643`; VOs `RecordSpec`, `Record`, `InnoHeader`, `InnoFileEntry`, `InnoFileLocation`, `InnoSetupBlock`; enums `InnoCompressMethod`, `InnoFileType`; pure parsers |
| `formats/domain/inno_files.py` (new; imports `inno_setup`) | formats / domain | VO `InnoFile`; pure `join_files` |
| `formats/domain/inno.py` | formats / domain | + VO `InnoDecodeStatus`, `SUPPORTED_SETUP_VERSION`, `MAX_INNO_FILE_FINDINGS`; `InnoInfo` + `header`, `files`, `decode` (defaults); docstring rewritten (A3, below) |
| `formats/domain/inno_loader.py` | formats / domain | + private stage `_setup` after `_blocks`; new notes; INNO_NOT_PARSED_NOTE text |
| `formats/domain/inno_facts.py` | formats / domain | + `MAX_INNO_TEXT`; decode, header, file findings; private `_text` (UTF-16 → escaped str) |
| `formats/application/use_cases.py` | formats / application | `STAGE_VERSION = "6"`; nothing else |
| `tests/formats/inno_build.py` | tests | + builders below; `build_inno(setup_id=..., blocks=...)` (defaults = PI32) |
Import graph (acyclic): `decompress`, `inno_setup` leaves; `inno_files` → `inno_setup`; `inno` → `decompress`,
`inno_setup`, `inno_files`; `inno_block` → `inno`, `decompress`, `parsing`, `ports`; `inno_loader` → all of these.
`inno.py` docstring (A3, ADR 0003 follow-up 4), replacing the "Leaf module ... no payload byte is decompressed" text:
"Inno Setup loader structures, block headers and the decoded setup data VOs. Imports `shared`, stdlib, `decompress`,
`inno_setup`, `inno_files`. Header blocks are decompressed only via `decompress.py` (ADR 0003); file data never."
A1-A7 as slice 6a: no cross-context or third-party import, every dataclass `frozen=True, slots=True`, no `Any`, no
module-level list/dict/set (tables are `Final` tuples).

## Interfaces
```python
# decompress.py
MAX_STORED_BLOCK: Final = 1 << 24; MAX_DECODED_TOTAL: Final = 1 << 26; MAX_RATIO: Final = 1024
RATIO_FLOOR: Final = 1 << 20; STEP: Final = 1 << 16; LZMA_MAX_DICT: Final = 1 << 30; LZMA_MIN_DICT: Final = 4096
MAX_DECODE_DEPTH: Final = 1          # documentary: decoded bytes are never decoded again
MAX_STALLS: Final = 8                # consecutive no-progress decoder calls before CORRUPT
class Codec(StrEnum): ZLIB = "zlib"; BZIP2 = "bzip2"; LZMA1_RAW = "lzma1"; LZMA2_RAW = "lzma2"
class DecodeFailure(StrEnum): BAD_PARAMS = "bad_params"; OVER_CAP = "over_cap"; OVER_RATIO = "over_ratio"
    DECLARED_OVER_CAP = "declared_over_cap"; SIZE_MISMATCH = "size_mismatch"; TRUNCATED = "truncated"
    CORRUPT = "corrupt"; CRC = "crc"; UNAVAILABLE = "unavailable"
class DecodeError(ParseError):
    def __init__(self, kind: DecodeFailure, reason: str, *, offset: int | None = None, decoded: int = 0) -> None
    kind: DecodeFailure; decoded: int    # output bytes produced before the failure (0 for framing/params)
class LzmaParams: lc: int; lp: int; pb: int; dict_size: int
    # post_init: 0 <= lc, lp; lc + lp <= 4; 0 <= pb <= 4; 0 <= dict_size <= LZMA_MAX_DICT else DecodeError(BAD_PARAMS)
def lzma1_params(props: bytes, offset: int) -> LzmaParams    # 5 B: p = props[0] < 225; lc=p%9, lp=(p//9)%5, pb=p//45; dict u32 LE
class Decoded: data: bytes; consumed: int; trailing: int; ended: bool   # all ints >= 0; ended False only for LZMA*_RAW
def decompress(codec: Codec, params: LzmaParams | None, chunks: Iterable[bytes], *, cap: int,
               declared: int | None = None, offset: int | None = None) -> Decoded
# inno_block.py
def block_chunks(source: ByteSource, block: InnoBlockHeader) -> Iterator[bytes]   # CRC-verified chunk payloads
def decode_block(source: ByteSource, block: InnoBlockHeader, *, cap: int, declared: int | None = None) -> Decoded
# inno_setup.py
MAX_INNO_STRING: Final = 1 << 24; MAX_INNO_ENTRIES: Final = 1 << 16; MAX_INNO_ENTRIES_TOTAL: Final = 1 << 18
MAX_WIZARD_IMAGES: Final = 64; LOCATION_SIZE: Final = 85; COUNT_NAMES: Final[tuple[str, ...]]  # 16 names, ## Binary layout
HEADER_FIELDS: Final[tuple[tuple[str, int, int], ...]]   # (name, offset, size) rows of the 177-B fixed part
LOCATION_FLAG_NAMES: Final[tuple[str, ...]]               # bit i -> name, 5 entries
class Cursor:   # __slots__; label e.g. "block1"; 0 <= start <= limit <= len(data) else ParseError
    def __init__(self, data: bytes, *, label: str, start: int = 0, limit: int | None = None) -> None
    pos: int (property); remaining: int (property)
    def read_fixed(self, size: int) -> bytes; def read_i32(self) -> int
    def read_string(self) -> bytes   # raw UTF-16LE (S1-S4); def read_ansi(self) -> bytes  (S1, S2, S4)
class RecordSpec: name: str; count_index: int | None; strings: int; ansi: int; fixed: int   # frozen VO; ints >= 0
SETUP_HEADER_643: Final = RecordSpec("setup_header", None, 33, 4, 177)   # count_index None = not a list
LISTS_643: Final[tuple[RecordSpec, ...]]                 # 15 lists in stream order (## Binary layout)
class Record: decoded_offset: int; strings: tuple[bytes, ...]; ansi: tuple[bytes, ...]; fixed: bytes   # VO
def read_record(cur: Cursor, spec: RecordSpec) -> Record
class InnoCompressMethod(StrEnum): STORED; ZIP; BZIP; LZMA; LZMA2       # ids 0..4, values lowercase
class InnoFileType(StrEnum): USER_FILE = "user_file"; UNINSTALL_EXE = "uninstall_exe"   # ids 0, 1
class InnoHeader: app_name: bytes; app_version: bytes; app_publisher: bytes   # raw UTF-16LE, even, <= MAX_INNO_STRING
    counts: tuple[int, ...]; compress_method: int; options: bytes
    # post_init: len(counts) == 16, each 0..MAX_INNO_ENTRIES, sum <= MAX_INNO_ENTRIES_TOTAL; compress_method u8;
    #   len(options) == 6. Properties: num_files (counts[7]), num_locations (counts[8]),
    #   compress_name -> InnoCompressMethod | None (None for ids > 4; no error)
class InnoFileEntry: decoded_offset: int; source: bytes; dest: bytes; location: int; options: int; file_type: int
    # decoded_offset >= 0 (plain int, never Address, never ParseError(offset=)); location i32; options u32;
    #   file_type u8; property file_type_name -> InnoFileType | None (None for ids > 1; no error)
class InnoFileLocation: index: int; original_size: int; sha256: bytes; filetime: int; flags: int
    # index >= 0; size, filetime u64; len(sha256) == 32; flags u8 (any bits accepted);
    #   bool properties version_info_valid, timestamp_utc, call_instruction_optimized, chunk_encrypted, chunk_compressed
class InnoSetupBlock: header: InnoHeader; files: tuple[InnoFileEntry, ...]   # len(files) == header.num_files
def parse_setup_643(data: bytes) -> InnoSetupBlock                     # whole decoded block 1; exact end required
def parse_locations_643(data: bytes, count: int) -> tuple[InnoFileLocation, ...]   # len(data) == count * 85
# inno_files.py
class InnoFile: entry: InnoFileEntry; location: InnoFileLocation | None
    # post_init: (location is None) == (entry.location == -1); else location.index == entry.location
def join_files(entries: tuple[InnoFileEntry, ...], locations: tuple[InnoFileLocation, ...]) -> tuple[InnoFile, ...]
# inno.py
SUPPORTED_SETUP_VERSION: Final = (6, 4, 3, 0); MAX_INNO_FILE_FINDINGS: Final = 1024
class InnoDecodeStatus: index: int; codec: Codec; ended: bool; failure: DecodeFailure | None
    decoded_size: int; consumed: int | None; trailing: int | None
    # index in (1, 2); failure is not None -> not ended and consumed is None and trailing is None; else both ints
class InnoInfo: ... + header: InnoHeader | None = None; files: tuple[InnoFile, ...] = ()
    decode: tuple[InnoDecodeStatus, ...] = ()
    # + len(decode) <= len(blocks), decode[i].index == i + 1; header -> decode[0].failure is None;
    #   files -> header is not None and len(files) == header.num_files and len(decode) == 2
# inno_facts.py
MAX_INNO_TEXT: Final = 128            # chars per displayed string (S11)
```
`Cursor` (A2) does not use `ByteRange`, `check_within` or `read_exact` (those are for file offsets); it checks
`0 <= size <= remaining` itself and raises `ParseError(..., offset=None)` with "at decoded offset 0x.." in the text.
`join_files`: per entry in order: `-1` → `InnoFile(e, None)`; `0 <= loc < len(locations)` → `InnoFile(e, locations[loc])`
(entries may share a location); else `ParseError(f"inno file {i} location {loc} out of range {n}")`.

## Decompression
Loop (`decompress`), `limit = cap if declared is None else declared`:
1. `cap < 0` or `declared < 0` → ValueError (programming error). `declared > cap` → DECLARED_OVER_CAP before the
   iterator is touched.
2. Construct (lazy import; ImportError → UNAVAILABLE "codec <c> unavailable"): ZLIB `zlib.decompressobj(wbits=15)` (no
   auto-detect); BZIP2 `bz2.BZ2Decompressor()`; LZMA1_RAW requires `params` (None → BAD_PARAMS) →
   `lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{"id": FILTER_LZMA1, "dict_size": d, "lc", "lp", "pb"}])`, no
   memlimit, `d = max(LZMA_MIN_DICT, min(params.dict_size, limit))`; LZMA2_RAW → UNAVAILABLE "codec lzma2 not
   implemented" (no consumer). LZMAError/ValueError/MemoryError at construction → BAD_PARAMS "decoder rejected parameters".
3. Repeat until `eof`: hungry = (ZLIB: `not unconsumed_tail`; others: `needs_input`). Hungry → `next(chunks)`; exhausted →
   stop (ZLIB first drains: call with `b""` while a call returns output). Not hungry → feed `unconsumed_tail` (ZLIB) or
   `b""`. Every call is `decompress(data, min(STEP, limit - len(out) + 1))`; `fed` += len of each new chunk;
   `consumed = fed - len(unconsumed_tail) - len(unused_data)` (attributes absent for a codec count as 0).
4. After each call: `len(out) > limit` → SIZE_MISMATCH if declared else OVER_CAP "output exceeds <cap> bytes";
   `len(out) > RATIO_FLOOR and len(out) > MAX_RATIO * consumed` → OVER_RATIO (ADR wording: consumed, not fed).
   Stall: an iteration that produced no output and consumed no non-empty new chunk (endless `b""` chunks count)
   increments `stalls`, any other iteration resets it; `stalls > MAX_STALLS` → CORRUPT "decoder made no progress".
5. Codec errors on every call (`zlib.error`, `LZMAError`, `OSError`, `EOFError`, `ValueError`) → CORRUPT "stream corrupt
   after N output bytes"; `MemoryError` on any call → CORRUPT "decoder out of memory after N output bytes"; stdlib text
   never echoed. Iterator errors (`InputChanged`, `DecodeError` CRC/TRUNCATED) propagate as is.
6. End: eof → `ended=True`, `trailing = len(unused_data)`, no further chunk pulled, no second stream. Not eof: ZLIB/BZIP2 →
   TRUNCATED "stream truncated after N output bytes"; LZMA* → `ended=False` (input exhausted, decoder needs input:
   `unterminated`). `declared` and `len(out) != declared` → SIZE_MISMATCH. Never one-shot calls, never `flush()`.
   `DecodeError.decoded = len(out)` at the failure.
Inno (`decode_block`): `block.compression is LZMA1` required (else the loader never calls it).
`block.stored_size > MAX_STORED_BLOCK` → OVER_CAP "stored size N exceeds 16777216 bytes" before any body read;
`block.offset + 9 + stored_size > source.size` → TRUNCATED "block body past end of file" (offset = block header file
offset), before any body read. `block_chunks`: `pos = block.offset + 9`, `left = stored_size`; while `left > 0`: `left <
5` → TRUNCATED "chunk header truncated"; `n = min(4096, left - 4)`; one `read_exact(source, source.size, pos, 4 + n)`;
CRC32(payload) != u32 → CRC "chunk K CRC mismatch" (K 1-based); yield payload; advance. Props = first 5 joined bytes (may
span chunks; fewer → TRUNCATED "lzma1 properties truncated"), `lzma1_params` (BAD_PARAMS: "lzma1 properties N invalid",
"lzma1 dictionary N exceeds 1073741824"); the remaining bytes feed `decompress(LZMA1_RAW, ..., offset=block.offset.value)`.
After codec eof the remaining chunks are neither read nor CRC-checked (accepted, as Setup; R9): `decode_block` counts
stored bytes yielded (4 + payload per chunk) and returns `Decoded` with `trailing = unused_data + (stored_size − yielded)`.
Completeness: a block's facts exist only if decode returned (ended, or unterminated = all stored chunks read and
CRC-valid + decoder needs input) **and** its 6.4.3 parse succeeded, including the exact-end rule (S9).
Budget: block 1 `cap = MAX_DECODED_TOTAL`; block 2 `cap = MAX_DECODED_TOTAL - len(block1)`, `declared =
header.num_locations * 85`. `InnoDecodeStatus` per attempted block; finding `inno.block{n}.decode`.

## Binary layout
6.4.3 (src: `Projects/Src/Shared.Struct.pas`@is-6_4_3, fetched 2026-10-13, unless tagged). Decoded offsets are relative
to the decoded block start (after props). Little-endian. Enum = 1 byte, set = ceil(N/8) bytes (assumption, Delphi
default; acceptance M1 is the proof).
- String: `Len` i32 (byte count) + Len bytes UTF-16LE. AnsiString: `Len` i32 + Len raw bytes. A record = its N leading
  Strings, then its Ansi strings, then `fixed` raw bytes (`SizeOf(record) - 4 * (N + A)`) (src: SECompressedBlockRead).
- TSetupHeader: 33 Strings, 4 Ansi (src: SetupHeaderStrings/SetupHeaderAnsiStrings); kept: [0] AppName, [4]
  AppPublisher, [9] AppVersion. Fixed **177 B** = `HEADER_FIELDS` (offset size name): 0 64 counts (16 × i32, COUNT_NAMES
  order: language, custom_message, permission, type, component, task, dir, file, file_location, icon, ini, registry,
  install_delete, uninstall_delete, run, uninstall_run) · 64 10 min_version · 74 10 only_below_version (TSetupVersionData
  = WinVersion u32, NTVersion u32, NTServicePack u16) · 84 1 wizard_style · 85 4 wizard_size_percent_x · 89 4
  wizard_size_percent_y · 93 1 wizard_image_alpha_format · 94 4 password_test · 98 16 encryption_kdf_salt · 114 4
  encryption_kdf_iterations · 118 24 encryption_base_nonce (i64 + i32 + 3 × i32) · 142 8 extra_disk_space_required · 150
  4 slices_per_disk · 154 1 uninstall_log_mode · 155 1 dir_exists_warning · 156 1 privileges_required · 157 1
  privileges_required_overrides_allowed (set of 2) · 158 1 show_language_dialog · 159 1 language_detection_method · 160 1
  compress_method (cmStored, cmZip, cmBzip, cmLZMA, cmLZMA2) · 161 1 disable_dir_page · 162 1
  disable_program_group_page · 163 8 uninstall_display_size · 171 6 options (set of 44 TSetupHeaderOption). Sum 177.
  Options are kept raw (6 B); no bit is interpreted (the position of shEncryptionUsed is (assumption), not relied on).
- **Set-size decision: 6 B** for Options (ceil(44/8)). Not switchable at runtime. Proven by acceptance step M1 on the
  sample (no N5 ⇒ exact end of block 1 and NumFile == entries); a 179-byte layout fails t66.
- Lists after the header, in order (`LISTS_643`, strings/ansi; fixed B with its fields; all records packed, Integer 4,
  Smallint 2, Boolean 1, Integer64 8, VD = TSetupVersionData 10) (src: issrc@is-6_4_3 `Projects/Src/Shared.Struct.pas`,
  fetched 2026-10-13): language 6/4; 21 (LanguageID 4, 4 font sizes 16, RightToLeft 1) · custom_message 2/0; 4 ·
  permission 0/1; 0 (Permissions AnsiString) · type 4/0; 30 (2 × VD 20, Options set(1) 1, Typ enum 1, Size 8) · component
  5/0; 42 (ExtraDiskSpaceRequired 8, Level 4, Used 1, 2 × VD 20, Options set(5) 1, Size 8) · task 6/0; 26 (Level 4, Used
  1, 2 × VD 20, Options set(5) 1) · dir 7/0; 27 (Attribs 4, 2 × VD 20, PermissionsEntry 2, Options set(5) 1) · **file
  10/0; 43** · icon 13/0; 48 (TGUID 16, 2 × VD 20, IconIndex 4, ShowCmd 4, CloseOnExit enum 1, HotKey u16 2, Options
  set(6) 1; was 51, M1 round 1: 13 × 4 + 48 = 100 B matches the sample) · ini 10/0; 21 (2 × VD 20, Options set(5) 1) ·
  registry 9/0; 29 (2 × VD 20, RootKey HKEY 4 (assumption: 32-bit build), PermissionsEntry 2, Typ enum 1, Options set(12)
  2) · install_delete, uninstall_delete 7/0; 21 (2 × VD 20, DeleteType enum 1) · run, uninstall_run 13/0; 27 (2 × VD 20,
  ShowCmd 4, Wait enum 1, Options set(12) 2). Enum = 1 B and set packing remain (assumption) (proven on the sample by
  M1); file_location is block 2.
- Then wizard images twice: `N` i32 + N × (`size` i32 + size bytes) (assumption, R3). Then, only if compress_method ∈
  {1 ZIP, 2 BZIP}, the decompressor DLL: `size` i32 + size bytes (assumption). Then the block must end (S9).
- TSetupFileEntry: 10 Strings ([0] SourceFilename, [1] DestName kept); fixed 43 B: 0 MinVersion 10, 10 OnlyBelow 10, 20
  LocationEntry i32 (−1 = none), 24 Attribs i32, 28 ExternalSize i64, 36 PermissionsEntry i16, 38 Options (set of 32,
  4 B), 42 FileType u8.
- Block 2: `count × 85 B` TSetupFileLocationEntry: 0 FirstSlice i32, 4 LastSlice i32, 8 StartOffset i32, 12
  ChunkSuboffset i64, 20 OriginalSize i64, 28 ChunkCompressedSize i64, 36 SHA256Sum 32 B (size: assumption), 68
  SourceTimeStamp FILETIME u64, 76 FileVersionMS u32, 80 FileVersionLS u32, 84 Flags: inline `set of
  (floVersionInfoValid, floTimeStampInUTC, floCallInstructionOptimized, floChunkEncrypted, floChunkCompressed)`, 1 B,
  bit i = LOCATION_FLAG_NAMES[i] (version_info_valid, timestamp_utc, call_instruction_optimized, chunk_encrypted,
  chunk_compressed). Kept: index, 20, 36, 68, 84. Unknown bits 5-7 are kept raw, never an error (D1).

## Safety checks
Cursor errors are `ParseError` with `offset=None` and the decoded offset in the text (`at decoded offset 0x..`): decoded
offsets are never file offsets (ADR 0003). Messages are static text + numbers.
S1 every read: `size >= 0` and `size <= remaining` else "inno <label> record truncated at decoded offset 0x..".
S2 String/Ansi `Len < 0` → "string length N negative"; S3 String (not Ansi) `Len` odd → "string length N odd".
S4 `Len > MAX_INNO_STRING` → "string length N too large"; `Len > remaining` → "string length N past end".
S5 each count `0 <= c <= MAX_INNO_ENTRIES` else "inno <name> count N out of range"; sum of 16 counts <=
   MAX_INNO_ENTRIES_TOTAL else "inno entry total N too large"; before each list: `count * (4 * (strings + ansi) + fixed)
   <= remaining` else "inno <name> list past end" (rejects huge counts before looping).
S6 unknown ids never raise (D1): compress_method > 4 → `compress_name None` (no DLL expected); FileType > 1 →
   `file_type_name None`; location Flags bits 5-7 kept in `flags`.
S7 wizard image list `N` 0..MAX_WIZARD_IMAGES else "inno wizard image count N out of range"; `size` < 0 or > remaining →
   "inno wizard image size N invalid"; same rule for the DLL size ("inno decompressor size N invalid").
S8 LocationEntry: −1 or `0 <= loc < num_locations` (join); block 2 `len(data) == count * 85` else "inno block2 size N is
   not M x 85".
S9 after the last structure `remaining == 0` else "inno block1 has N trailing bytes".
S10 cursor never moves past `limit`; `Cursor` is created over the whole decoded bytes, one per block.
S11 text display (`inno_facts._text(raw) -> tuple[str, bool]`): `raw.decode("utf-16-le", "surrogatepass")`; cut to
   MAX_INNO_TEXT chars (flag truncated); keep a char iff `ch.isprintable()` and `ch not in '\\"'` and not a lone
   surrogate; else `\uXXXX` (≤ U+FFFF) or `\UXXXXXXXX`. Python length ≤ 1280 < MAX_JSON_STR.
S12 sha256 → lowercase hex (64). FILETIME: `filetime` int always; `timestamp` = None if 0 or `ft // 10 >
   265046774399999999` (µs from 1601-01-01 to 9999-12-31T23:59:59.999999; largest accepted ft 2650467743999999999,
   first rejected 2650467744000000000), else `(datetime(1601,1,1) + timedelta(microseconds=ft // 10)).isoformat()` +
   `"Z"` iff `timestamp_utc`.
S13 every `DecodeError`/`ParseError` from `_setup` becomes a note; `InputChanged` propagates; nothing reaches
   `guarded_parse` (t81).

## Caps
Decode: MAX_STORED_BLOCK 16 MiB, MAX_DECODED_TOTAL 64 MiB per parse, MAX_RATIO 1024 above RATIO_FLOOR 1 MiB, STEP 64 KiB,
MAX_STALLS 8, dict ≤ 1 GiB clamped to `max(4096, min(dict, limit))` (ADR 0003; magnitudes (assumption)). Parse:
MAX_INNO_STRING 16 MiB, MAX_INNO_ENTRIES 65536 per list, MAX_INNO_ENTRIES_TOTAL 262144, MAX_WIZARD_IMAGES 64 (assumption).
Findings: existing worst ≤ 3 + 96 + 256 + 16 + 1 + 16 + 1 (resource) + 6 (inno 6a) = 395; + 2 decode + 1 header +
MAX_INNO_FILE_FINDINGS 1024 = 1422 < MAX_FINDINGS 4096. Report chars (pretty, ensure_ascii): existing worst ≈ 2,972,647
(slice 5) + ≈ 31,000 (6a) ≈ 3.0 M. A displayed string ≤ 128 chars × 12 JSON chars (astral → surrogate pair) = 1,536;
file finding ≤ 2 × 1,536 + ≈ 1,000 (envelope + 14 keys) ≈ 4,100; × 1024 ≈ 4.2 M; header ≈ 6,000. Total ≈ 7.2 M <
MAX_REPORT_CHARS 8,388,608 (86 %); 2048 findings would exceed it, hence 1024 (brief suggested 2048). Per value: nodes < 40,
text < 6,000 < MAX_JSON_TEXT. Beyond the cap: findings for the first 1024 files, header `files_reported` 1024, note N6.

## CLI/JSON
Finding order after 6a's (`inno.loader`, `inno.version`, `inno.block` ×2, `inno.data`): `inno.block1.decode`,
`inno.block2.decode`, header, files. All PARSED, producer unchanged.
- `inno.block{n}.decode`: `{"codec": "lzma1", "status": "ended"|"unterminated"|<DecodeFailure value>,
  "decoded_size": int, "consumed": int|null, "trailing": int|null}`.
- Header, subject `inno.block1[lzma1]+0x0:setup_header` (ADR 0003 subject form): `{"app_name", "app_version",
  "app_publisher": str, "compress_method": str|null, "compress_method_id": int, "options_hex": str (12 hex),
  "counts": {16 COUNT_NAMES: int}, "files_total": int, "files_reported": int, "text_truncated": bool}`.
- File, subject `inno.block1[lzma1]+0x<decoded_offset hex>:file_entry`: `{"index", "dest", "source", "file_type":
  str|null, "file_type_id": int, "options": int, "location": int, "size": int|null, "sha256": str|null, "filetime":
  int|null, "timestamp": str|null, "flags": [known names]|null, "flags_raw": int|null, "text_truncated": bool}`
  (location −1 → the six location keys null).
Notes (static + numbers, in step order): N1 `inno version A.B.C.D unsupported: headers not parsed`; N2 `inno headers
not decoded: block headers incomplete` (< 2 blocks or a crc_ok False); N3 `inno block N compression <c> not decoded`
(stored/zlib); N4 `inno block N not decoded: <DecodeError>` (e.g. `... output exceeds 67108864 bytes at offset
0x640`); N5 `inno block N not parsed: <ParseError>`; N6 `inno file list truncated: K of N files reported`; N7 `inno file
data encrypted: K of N file locations` (informational); INNO_NOT_PARSED_NOTE becomes `inno data chunks, slices and
non-file entries not extracted or reported in this version` (still last).
`_setup` runs when `version` is set and ≥ BLOCKS_FROM: version ≠ SUPPORTED_SETUP_VERSION or not unicode → N1 stop; N2
stop; N3 stop → decode 1 (N4 stop) → parse 1 (N5 stop) → decode 2 (N4: header kept, files ()) → parse 2 + join (N5:
header kept, files ()) → N6 if `len(files) > MAX_INNO_FILE_FINDINGS` → N7 if any location `chunk_encrypted`.
Goldens: G1–G6 regenerated (stage version "6"; G6 = PI32 6.4.0.1 also gains N1 and the new INNO_NOT_PARSED_NOTE, no
decode). **G7** `tests/fixtures/reporting/pe32_inno_files.json`: `build_inno(setup_id=b"Inno Setup Setup Data (6.4.3)",
blocks=lzma1_block(1, G7_STREAM1) + lzma1_block(2, G7_STREAM2))`; table data_offset = 0x600 + 64 + len(blocks).
Builders (tests only): `inno_string(text)`, `inno_ansi(raw)`, `record(strings, ansi, fixed)`, `generic_record(spec,
seed)` (strings "s<seed>", ansi b"a", zero fixed), `setup_header(counts, *, app_name="", app_version="",
app_publisher="", compress=3, options=bytes(6), fixed_size=177)`, `language_entry()`, `file_entry(source, dest,
location, *, options=0, file_type=0)`, `location_entry(size, sha256, filetime, flags)`, `raw_lzma1(payload,
dict_size=1 << 16)` (`lzma.compress(FORMAT_RAW, [{FILTER_LZMA1, dict 64 KiB, lc 3, lp 0, pb 2}])`), `framed(body)`
(CRC32 + ≤ 4096 chunks), `lzma1_block(index, stream, props=b"\x5d\x00\x00\x01\x00")` (9-B header + framed).
G7_STREAM1/2 are hex constants generated once with `raw_lzma1` and pinned (liblzma output may differ across versions).
Regeneration recipe (only if the payload builders change): `raw_lzma1(payload).hex()` → replace the constants; update
G7_SHA256_1/2, the stream-1 size (149 B now) and regenerate the G7 golden; review the diff. G7 decoded layout (scratch
run, Python 3.13.16):
- Block 1 = 752 B, G7_SHA256_1 = 2447b7f7484ddbb00d36ac6ceddb99a18d7acff27e057cf7b821a7feff5ab068:
  [0, 375) header: strings [0] "Demo App" (Len 16), [4] "Retool Tests" (24), [9] "1.2.3" (10), 30 empty (Len 0); 4
  empty ansi; fixed 177 with counts (1,0,0,0,0,0,0,2,2,0,0,0,0,0,0,0), byte 160 = 3, rest 0.
  [375, 450) language: "english" + 5 empty strings, 4 empty ansi, 21 zero B.
  [450, 591) file 0: "C:\build\app.exe", "{app}\app.exe", 8 empty; fixed LocationEntry 0, PermissionsEntry −1, rest 0.
  [591, 744) file 1: "C:\build\readme.txt", "{app}\readme.txt", 8 empty; LocationEntry 1, PermissionsEntry −1.
  [744, 752) wizard image counts 0, 0 (compress 3 → no DLL).
- Block 2 = 170 B, G7_SHA256_2 = 9d514ff5a38dee1ed0d2394fc653be8cc55e2ce8de50f475f3fbbf52db2901d9: loc 0 = slices 0,0,
  start 0, suboffset 0, size 1024, chunk size 0, sha256(b"app") a172cedc…f333, filetime 132000000000000000, versions
  0, flags 0x12; loc 1 = size 5, sha256(b"hello") 2cf24dba…9824, filetime 0, flags 0x10.
- Expected: decode statuses `ended` (liblzma raw LZMA1 writes an end marker: scratch eof True, 149-B stream 1);
  file subjects `+0x1c2` and `+0x24f`; file 0 `timestamp` "2019-04-17T18:40:00Z", flags [timestamp_utc,
  chunk_compressed], flags_raw 18; file 1 `timestamp` null; no N6, no N7.

## Tests
Tests carry `t<NN>`. `tests/formats/test_decompress.py`:
- t40 LZMA1 round-trip of the G7 block-1 payload in 1 chunk and in 7-B chunks: data equal, ended, trailing 0, consumed ==
  len(stream). t41 200,000 zero B, cap 100,000 → OVER_CAP, `decoded == 100001`, reason "output exceeds 100000 bytes".
- t42 3 MiB zeros in one chunk, cap 64 MiB → OVER_RATIO; t43 exactly RATIO_FLOOR zeros → ended (bound is strict).
- t44 truncated: LZMA1 stream minus 6 B → ended False, data a prefix of payload (scratch: 739 of 752); zlib minus 4 B and
  bz2 minus 10 B → TRUNCATED. t45 bad props: p 225, p 13 (lc 4 + lp 1), dict 0x40000001 → BAD_PARAMS; dict 0x40000000
  accepted (`lzma1_params`); dict 0 → 4096 and decodes; `LzmaParams(pb=5)` and params None with LZMA1_RAW → BAD_PARAMS.
- t46 dict clamp: 320,000 B (`bytes(range(256)) * 1250`) encoded with dict 64 MiB, props declare 64 MiB, cap 320,000 →
  equal output; a spy on `lzma.LZMADecompressor` sees dict_size 320,000. t47 zlib: 1 MiB `b"ab"` stream in one chunk →
  equal; every call's max_length ≤ STEP (spy); 200,000 empty stored deflate blocks → ended, 0 B, consumed ≈ 1,000,007.
- t48 bz2: round-trip; stream + b"junk" → ended, trailing 4. t49 `monkeypatch.setitem(sys.modules, "lzma", None)` →
  UNAVAILABLE (same for bz2); an `ast` scan of every `formats/domain/*.py` finds no module-level `lzma`/`bz2` import.
- t50 declared 10 > cap 5 → DECLARED_OVER_CAP and the iterator spy was never advanced; output 99 or 101 vs declared 100
  → SIZE_MISMATCH; cap −1 or declared −1 → ValueError. t51 CORRUPT: `b"\x78\x9c\xff\xff"` zlib; t46 stream with props
  dict 4096 (E4); raw deflate and gzip under ZLIB; no stdlib text in messages ("Corrupt input data" absent).
- t52 iterator raising `InputChanged` / `DecodeError(CRC)` → the same exception propagates. t53 LZMA2_RAW → UNAVAILABLE.
- t54 fake `lzma.LZMADecompressor` (monkeypatched): `decompress` → b"", `needs_input` False, `eof` False → CORRUPT "made
  no progress" after exactly MAX_STALLS + 1 calls; a fake raising MemoryError on its 2nd call → CORRUPT "out of memory"; the real
  LZMA1 decoder fed a valid prefix then an endless iterator of `b""` chunks → CORRUPT "made no progress".
`tests/formats/test_inno_block.py` (`MemorySource`, `SparseSource` from `tests/formats/fakes.py`):
- t55 body of 9,000 B → reads (pos, 4100), (pos+4100, 4100), (pos+8200, 804); joined payload equal. t56 chunk 2 CRC
  flipped → CRC "chunk 2 CRC mismatch at offset 0x<block offset>". t57 stored = 2 × 4100 + 4 and stored = 3 →
  TRUNCATED; hand-built `InnoBlockHeader` with stored_size = remaining + 1 → TRUNCATED "block body past end of file",
  zero reads (via the loader 6a's "payload past end of file" note pre-empts it: no decode status, N2). t58 stored 7
  (3-B payload) → "lzma1 properties truncated"; props byte 0xE1 → BAD_PARAMS. t59 stored MAX_STORED_BLOCK + 1 →
  OVER_CAP, zero body reads. t60 sha256(builder payloads) == G7_SHA256_1/2; pinned streams decode to the payloads; a
  stream + 2 extra chunks after eof → `trailing` counts unused data + the unread stored bytes, those chunks never read.
`tests/formats/test_inno_setup.py`:
- t61 Cursor: read past limit, `start > limit`, `limit > len`, `read_i32` with 3 B left → ParseError with "decoded
  offset 0x.." and `offset is None`; `read_fixed(0)` → b"". t62 strings: Len −1, 7, past end, `MAX_INNO_STRING`
  monkeypatched to 8 with Len 10 → S2-S4; Len 0 → b""; ansi Len 3 accepted, ansi Len −1 → S2.
- t63 `parse_setup_643(G7 block 1)` → header fields, counts, 2 entries with decoded_offset 450, 591 and fields as layout.
- t64 `HEADER_FIELDS`: offsets contiguous from 0, `sum(sizes) == 177 == SETUP_HEADER_643.fixed`; rows for counts, 160
  compress_method and 171 options match ## Binary layout.
- t65 NumFile 65537, −1 → S5; five lists of 60,000 → total; NumFile 2 with one record → truncated / "list past end".
- t66 G7 block 1 + b"\0" → "inno block1 has 1 trailing bytes"; header built with `fixed_size=179` → ParseError (set-size
  sensitivity). t67 (D1) compress_method 5 → parses, `compress_name None`; file type 2 → `file_type_name None`;
  location flags 0xF2 → accepted, `flags == 0xF2`, known bools (timestamp_utc, chunk_compressed) true.
- t68 wizard count 65, size −1, size > remaining → S7; compress=1 with a 3-B DLL → exact end; DLL size −1 → S7;
  compress=1 without DLL → truncated. t69 `parse_locations_643(G7 block 2, 2)` fields; 169 B → S8.
- t85 every list: 2 `generic_record`s for each of the 15 `LISTS_643` specs (file records via `file_entry`); each of the
  two wizard image lists (after the 15 entry lists) holds N=2 images of sizes 3 and 0; compress=2 with a 5-B DLL → exact
  end; counts as built; file decoded_offsets equal the builder-recorded offsets.
`tests/formats/test_inno_files.py`: t71 G7 join; −1 → `location None`; loc 2 of 2 and −2 → "inno file 1 location 2 out
of range 2". t72 VO invariants of `InnoFileEntry`, `InnoFileLocation`, `InnoFile`, `InnoDecodeStatus`, `InnoInfo` (+3).
`tests/formats/test_inno_loader.py` / `test_inno_facts.py` (`build_inno(...)` variants):
- t73 PI32 → N1 "inno version 6.4.0.1 unsupported: headers not parsed", `decode == ()`, zero body reads.
- t74 G7 → statuses (ended, ended), header, 2 files; finding subjects and values exactly as ## CLI/JSON.
- t75 block 1 chunk CRC bad → status `crc`, N4, 6a block facts kept, block 2 not attempted. t76 block 1 payload + 1 B →
  status ended, N5 "inno block 1 not parsed: inno block1 has 1 trailing bytes", no header. t77 NumFileLocation 3 with a
  2-location block 2 → block 2 `size_mismatch`, header kept, files (). t78 `MAX_DECODED_TOTAL` monkeypatched to 852 →
  block 2 `declared_over_cap`. t79 1,100 files (all location 0) whose source and dest are 129 × U+1F600 → 1,024 file findings,
  `files_total` 1100, `files_reported` 1024, N6, `text_truncated` true; location flags 0x18 → N7 "1 of 1".
- t81 every t75-t78 parse keeps the PE findings; no "structure rejected" note. t82 6.4.3 with block 1 flag 0 → N3; with
  one block → N2.
- t86 `inno_loader.decode_block` monkeypatched to return `Decoded(payload_n, consumed=len(stream_n), trailing=0,
  ended=False)` for G7 → statuses `unterminated` ×2, consumed 149 for block 1, trailing 0, header + 2 files; returning
  G7 block 1[:739] unterminated → N5 (truncated at decoded offset), no header, block 2 not attempted.
- t70 `_text`: "a\u0001\"\\b" → `a\u0001\u0022\u005cb`; lone `b"\x00\xd8"` → `\ud800`; U+1F600 kept; U+E0001 → `\U000e0001`;
  129 chars → 128 + truncated; G7 file 0 `sha256`, `timestamp`; ft 2650467743999999999 → "9999-12-31T23:59:59.999999",
  ft 2650467744000000000 and 2**64 − 1 → null.
`tests/interface/test_cli.py`: t80 t79's file (source and dest both 129 × U+1F600, the real maximum) via `info --json`: max pretty size of an inno file finding ≤ 4,200 chars;
t83 G7 golden; G1-G6 goldens regenerated (review the diff: only stage version and G6 notes change).

## Evidence
- issrc@is-6_4_3 `Projects/Src/Shared.Struct.pas` (fetched 2026-10-13 by the orchestrator, D1-D3): header string
  counts 33/4, the 177-B fixed field list, file entry 10 Str + 43 B, location entry 85 B and its 5-member flag set.
  Via brief: `Shared.SetupEntFunc.pas` SECompressedBlockRead; `Setup.MainFunc.pas` read order and TLZMA1Decompressor for
  both blocks; `Compression.Base.pas` chunk framing; `Compression.LZMADecompressor.pas` dict ≤ 1 GiB, LZMA_FINISH_ANY.
- innoextract master: props p ≤ 225 split; lacks CloseApplicationsFilterExcludes. ADR 0003 (accepted 2026-10-13).
- Repo: `inno.py:175-222`, `inno_loader.py:134-208`, `inno_facts.py:60-69`, `parsing.py:54-88`, `shared/errors.py:10-17`
  (offset text), `shared/findings.py:91` (subject = printable text), `shared/json_value.py:11-14`,
  `reporting/domain/model.py:12`, `reporting/domain/services.py:10-22` (8 MiB, ensure_ascii), golden keys `findings`,
  `not_analysed[].reason` (`pe32_inno.json`), slice-5 worst case.
- Scratch runs 2026-10-13 (Python 3.13.16): G7 sizes/hashes, LZMA1 eof/props, 739-B cut, FILETIME bounds (above).

## Risks
- R1 set size 6 vs 8 and enum = 1 B (assumption): acceptance step M1 decides; if N5 appears for block 1, report
  `blocked` with the note text; no runtime fallback (a layout change is a spec change).
- R2 unterminated LZMA1 may decode a few garbage bytes past the last real symbol (assumption, rc state after flush);
  S9 / SIZE_MISMATCH would then reject a legitimate block. M1 reveals it; resolution is an ADR 0003 "revisit" item.
- R3 list record sizes are sourced from `Shared.Struct.pas`@is-6_4_3 (icon corrected 51 → 48, registry 31 → 29 in fix
  round 1); HKEY width and set packing stay (assumption). The wizard-image framing "N + sized blobs, twice" and the DLL
  framing are (assumption). M1 covers all but the DLL (sample is LZMA). R4 header counts unrelated to the file list are
  validated only by S5.
- R5 1024 / 128 caps truncate large installers and long names (flagged); corpus measurement → F-DECOMP-CORPUS.
- R6 `decompress` gains `offset` (keyword) beyond ADR 0003's literal signature, needed for the reason's file offset.
  The ratio tripwire uses `consumed` as the ADR says.
- R7 ADR names (`MAX_STORED_BLOCK`, `MAX_DECODED_TOTAL`) used instead of the brief's; ADR subject form instead of bare
  `inno.header`/`inno.file`. R8 MemoryError during decoding → CORRUPT (kind chosen here; ADR names construction only).
- R9 chunks after codec eof are neither read nor CRC-checked; their stored bytes count in `trailing` (as Setup, E6).
- R10 `MAX_STALLS = 8` no-progress guard is not named by ADR 0003 (a bound, not a policy); architect to confirm.

## Acceptance
1. `make check` passes; `uv run pytest -q --collect-only | tail -n 1` ≥ 735 tests (689 + one per t40–t86, t84 unused).
2. `grep -rnE "^(import|from) (lzma|bz2)\b" src/retool/formats/domain/` prints nothing (column-0 = module level; lazy
   imports are indented) and t49's ast scan passes.
3. `grep -cE "^[A-Z_0-9]+: Final" src/retool/formats/domain/decompress.py` ≥ 9 (one Final per line); the ## Caps values appear verbatim.
4. `git status --porcelain` lists only files named in ## Architecture, `tests/**`, the 6 regenerated goldens and the new
   G7 golden; no `samples/` path.
5. G7 golden matches; G1-G5 diffs are the stage version only; G6 also its notes. t64 passes (`HEADER_FIELDS` sum 177).
6. **M1 (manual, sample; replaces the former t84)**: run
   `uv run retool info --json <the sample path> | jq -e 'def h: (.findings[] | select(.subject | endswith(":setup_header")) | .value);
   def d(n): (.findings[] | select(.subject == "inno.block\(n).decode") | .value);
   ([.not_analysed[].reason | select(test("^inno block [12] not (decoded|parsed)"))] | length == 0)
   and (d(1).status | IN("ended", "unterminated")) and (d(2).status | IN("ended", "unterminated"))
   and (h.files_total == h.counts.file)
   and ([.findings[] | select(.subject | endswith(":file_entry"))] | length) == ([h.files_total, 1024] | min)
   and (d(2).decoded_size == h.counts.file_location * 85)'` → `true` (the implementer first confirms the `value`/`subject` key names against
   `tests/fixtures/reporting/pe32_inno.json`). No N5 for block 1 means S9 held: the block-1
   cursor ended exactly at the decoded end (proves the 6-B set). The implementer reports both statuses, decoded sizes,
   NumFile and NumFileLocation; the orchestrator records the result via `/remember`. Not runnable → status `partial`.
7. Every new dataclass `frozen=True, slots=True`; no `Any`; `make arch` green.

## Follow-ups
| ID | What |
|---|---|
| F-INNO-VERSIONS | table-driven RecordSpec/header layouts per version (5.5–6.6), innoextract parity |
| F-INNO-EXTRACT | file data chunks, slices, mapping — needs the splitting ADR (ADR 0001/0003) |
| F-INNO-ENCRYPT | 6.4 XChaCha20 chunk encryption: KDF fields, shEncryptionUsed bit position, header-block encryption check |
| F-DECOMP-CORPUS | measure header sizes/ratios/file counts on a corpus; revisit caps (ADR 0003 "revisit") |
| F-DECISIONS | DECISIONS.md line for ADR 0003 via `/remember` |
