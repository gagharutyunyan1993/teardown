# Slice 6a: PE resource lookup + Inno Setup loader structure (no decompression)

## Scope
In: (A) PE resource tree walk (dir 2) → `ResourceSummary` + `pe.resource` finding; lookup by type/name ID. (B) Inno loader
offset table (pointer at 0x30, resource RT_RCDATA 11111). (C) setup-data version field at header_offset. (D) headers of
block 1 and block 2 (CRC32, stored_size, compression flag) and the first data-chunk magic at data_offset. `inno.*`
findings, notes, JSON; `formats.inspect` stage "5"; schema_version stays 1 (new subjects only).
Policy (as slice 5): a `ParseError` in resources / inno drops only that part + one note `pe <part> not parsed: <exc>`;
`InputChanged` propagates. Inno sub-stages that fail after the table is parsed add a note and stop that chain only.
Out: decompression of any kind, header/entry parsing, slices, legacy (< 4.0.9) block layout, resource contents (see
## Follow-ups). No change to `retool.formats.__all__`, `dto.py`, `interface/`, `reporting/`, `shared/`, `.importlinter`.

## Architecture
Conforms to ARCH §2 (`formats`: container identification and structural parsing; Inno in scope, confirmed by the architect
round 1, no `/decide`), §3 (domain = stdlib + `shared`; bytes only via port `ByteSource`; `zlib.crc32` is stdlib), §4 (pure
domain services, frozen VOs validated in `__post_init__` raising `ParseError`, capped counts, `read_exact` before every
read, file offsets as `Address`; strategy `PeParser` keeps its shape), §5 (domain unit tests on `MemorySource` /
`SparseSource`, CLI goldens). ADR 0002: `formats` authors its findings via `parsed_finding`. No new port, no new context.
CRC32 checks verify checksum fields the container declares over spans it defines; they are not content predicates, and no
payload byte (block contents, chunk data) is read beyond the 4-byte chunk magic.
**architect review required** (aggregate `PeFile` gains `resources`, `inno`; round-1 items A1-A6 applied).
Leaf rule (pe.py is 501 lines at HEAD 3b75236): `pe_resources.py` and `inno.py` import only `parsing`, `ports`, `model`,
`shared`, stdlib, never `pe` / `pe_image`, so `pe.py` references their VOs without a cycle.
| Module | Context / layer | Pattern (ARCH §4) |
|---|---|---|
| `formats/domain/pe_resources.py` (new, leaf) | formats / domain | caps; VOs `ResourceEntry`, `ResourceSummary`; pure services `parse_resources`, `find_resource` |
| `formats/domain/inno.py` (new, leaf) | formats / domain | constants; private `_TableLayout` table; enums `InnoRoute`, `InnoCompression`; VOs `InnoOffsets`, `InnoVersion`, `InnoBlockHeader`, `InnoData`, `InnoInfo`; pure byte parsers |
| `formats/domain/inno_loader.py` (new) | formats / domain | pure service `inno_info` over `ByteSource` + `PeFile` (route, table, version, blocks, data) |
| `formats/domain/inno_facts.py` (new) | formats / domain | pure `inno_facts` → `inno.*` findings |
| `formats/domain/pe.py` | formats / domain | `PeFile` + `resources: ResourceSummary \| None = None`, `inno: InnoInfo \| None = None` (2 imports, 2 fields, no new VOs; `__post_init__` unchanged) |
| `formats/domain/pe_image.py` | formats / domain | + pure `rva_range` |
| `formats/domain/pe_parser.py` | formats / domain | `attach_tables` + parts 4 resources, 5 inno; private `_resources` |
| `formats/domain/pe_facts.py` | formats / domain | + `pe.resource`, appends `inno_facts`; NOT_PARSED_NOTE "resources" → "resource contents" |
| `formats/application/use_cases.py` | formats / application | `InspectFile.STAGE_VERSION = "5"`; nothing else |
| `tests/formats/inno_build.py` (new) | tests | builders below |
A1-A7: no cross-context or third-party import; every new dataclass `frozen=True, slots=True`; no `Any`; interface untouched.

## Interfaces
```python
# pe_resources.py
MAX_RESOURCE_ENTRIES: Final = 4096   # per directory table (named + id)
MAX_RESOURCE_TOTAL: Final = 16384    # directory entries walked across the whole tree
MAX_RESOURCE_DEPTH: Final = 3        # type -> name -> language; hard cap in the walk
MAX_RESOURCE_NAME: Final = 64        # UTF-16 code units in a named entry
ResourceKey = int | bytes            # ID (0..0x7FFFFFFF) or raw UTF-16LE name (even length <= 2*MAX_RESOURCE_NAME)
class ResourceEntry: type: ResourceKey; name: ResourceKey; lang: ResourceKey; data_rva: int; size: int
    code_page: int; entry_offset: Address      # file offset of the IMAGE_RESOURCE_DATA_ENTRY; u32 fields 0..2**32-1
class ResourceSummary: offset: Address; size: int; entries: tuple[ResourceEntry, ...]   # len <= MAX_RESOURCE_TOTAL
def parse_resources(source: ByteSource, root: ByteRange) -> ResourceSummary: ...
def find_resource(summary: ResourceSummary, type_id: int, name_id: int) -> ResourceEntry | None: ...
    # first entry in walk order with int keys type == type_id and name == name_id (first language wins)
# inno.py
class InnoRoute(StrEnum): POINTER = "pointer"; RESOURCE = "resource"
class InnoCompression(StrEnum): STORED = "stored"; ZLIB = "zlib"; LZMA1 = "lzma1"
Version = tuple[int, int, int, int]         # (major, minor, patch, build), each 0..255
@dataclass(frozen=True, slots=True)
class _TableLayout: loader_version: Version | None; size: int; has_revision: bool; has_exe_compressed: bool
    has_message: bool; has_crc: bool
    # post_init: size == 12 + 4 * (6 + has_revision + has_exe_compressed + has_message + has_crc); like pe._Layout
_LAYOUTS: Final[Mapping[bytes, _TableLayout]]   # MappingProxyType, rows of ## Binary layout; _NEWEST = the 5.1.5 row
class InnoOffsets: route: InnoRoute; table_offset: Address; table_size: int; loader_version: Version | None
    revision: int | None; exe_offset: Address; exe_compressed_size: int | None; exe_uncompressed_size: int
    exe_checksum: int; message_offset: Address | None; header_offset: Address; data_offset: Address
    crc_ok: bool | None
    # table_size == the _LAYOUTS row size for loader_version; revision None iff loader_version < 5.1.5 (None = newest); crc_ok None iff < 4.0.10;
    # exe_compressed_size / message_offset present iff the layout has them; ints are u32
class InnoVersion: raw: bytes; version: Version; unicode: bool; known: bool    # 1 <= len(raw) <= 64, no NUL in raw
class InnoBlockHeader: index: int; offset: Address; expected_crc: int; stored_size: int; flag: int
    compression: InnoCompression; crc_ok: bool  # index in (1, 2); flag in (0, 1); (flag == 0) == (compression is STORED)
class InnoData: offset: Address; magic_ok: bool
class InnoInfo: offsets: InnoOffsets; version: InnoVersion | None; blocks: tuple[InnoBlockHeader, ...]
    data: InnoData | None   # len(blocks) <= 2; blocks[i].index == i + 1; blocks only with version >= 4.0.9
def offset_table_size(magic: bytes) -> int: ...               # _LAYOUTS.get(magic, _NEWEST).size
def parse_offset_table(raw: bytes, route: InnoRoute, offset: int) -> InnoOffsets: ...  # raw = whole table
def is_legacy_stamp(head: bytes) -> bool: ...                 # 12 bytes
def parse_version_field(field: bytes) -> InnoVersion | None: ...   # 64 bytes; None = not recognised
def parse_block_header(raw: bytes, offset: int, index: int, version: Version) -> InnoBlockHeader: ...  # 9 bytes
# inno_loader.py
def inno_info(source: ByteSource, pe: PeFile) -> tuple[InnoInfo | None, tuple[NotAnalysed, ...]]: ...
# pe_image.py
def rva_range(pe: PeFile, rva: int, size: int) -> ByteRange | None: ...  # rva_to_file run if size <= run.size
# inno_facts.py
def inno_facts(info: InnoInfo, producer: str) -> tuple[Finding, ...]: ...
```
`_resources(source, pe)`: `d = directory(pe, 2)`; None → None; `run = rva_to_file(pe, d.virtual_address)`; None → raise
`ParseError("resource directory not file-backed", offset=directory_offset(pe, 2))`; else `parse_resources(source,
ByteRange(run.start, min(d.size, run.size)))`. `attach_tables` (each part contained as in slice 5, notes in part order):
imports, certificates, overlay, resources; `attached = replace(pe, imports=..., certificates=..., overlay=...,
resources=...)`; `inno, inno_notes = inno_info(source, attached)` (ParseError → `pe inno not parsed: ...`); return
`replace(attached, inno=inno)`. Neither replace can raise: `PeFile.__post_init__` checks only slice-5 caps and the new
children validate themselves (t18 pins the VO invariants).
`inno_info` (reads only through `read_exact`, limit `source.size`; notes in step order, INNO_NOT_PARSED_NOTE last):
1. POINTER: read 12 B at 0x30 `"<III"`. Magic 0x6F6E6E49 and u32[2] == u32[1] ^ 0xFFFFFFFF → table candidate at u32[1]:
   off + 12 > size, or off + offset_table_size(magic read there) > size → note `inno loader pointer target 0x.. past end
   of file` and fall through to 2 (the part is not dropped). Magic with a failing complement → note `inno loader pointer
   at 0x30 fails its complement check`, fall through. Both notes are kept whatever later steps find. Pointer first
   (src: innoextract loader/offsets.cpp load: exe file, then resource). Step-1 notes also survive an S8 raise in step 2.
2. RESOURCE: `e = find_resource(pe.resources, 10, 11111)` (if resources); `rng = rva_range(pe, e.data_rva, e.size)`;
   None → `ParseError("inno offset table resource not file-backed", offset=e.entry_offset)`; table at rng.start, limit
   rng.start + e.size.
3. No table: if `pe.overlay` has signature `inno-chunk` or `inno-setup-data` → note `inno-like overlay without a loader
   offset table`; return (None, notes so far). No route, no hint → (None, ()).
4. Table: 12 B magic, then the rest (S7-S8). Notes: unknown magic → `inno loader magic unknown at offset 0x..; read as the
   5.1.5 layout`; revision ≠ 1 → `inno loader revision N unexpected`; crc_ok False → `inno loader table CRC mismatch at
   offset 0x..` (table_offset).
5. Version at h = header_offset (one read: 64 B, or 12 B when 12 ≤ size − h < 64): h + 12 > size or h + 64 > size (after
   the legacy check) → `inno setup data header past end of file at offset 0x..`; `is_legacy_stamp` → `inno legacy setup
   data stamp not analysed at offset 0x..`; `parse_version_field` None → `inno setup data version not recognised at
   offset 0x..`. Any of these: no blocks.
6. Blocks (version ≥ 4.0.9 else note `inno blocks before 4.0.9 not analysed`): pos1 = h + 64; S10-S12 per block; block 2
   only if block 1 is reported with crc_ok; pos2 = pos1 + 9 + stored_size1.
7. Data (independent of 5-6): data_offset == 0 → `inno data in external slice files not analysed`; data_offset + 4 >
   size → `inno data chunk past end of file at offset 0x..`; else `InnoData(offset, read == b"zlb\x1a")`.
8. INNO_NOT_PARSED_NOTE = `inno setup headers, entries and data chunks not decompressed or parsed in this version` when
   InnoInfo is returned. Reads ≤ 7, bytes ≤ 12 + 44 + 64 + 18 + 4 = 142 (pointer fall-through adds ≤ 1 read of 12 B).

## Binary layout
All little-endian.
- Resource directory `"<IIHHHH"` (16): Characteristics, TimeDateStamp, Major, Minor, NumberOfNamedEntries (+12),
  NumberOfIdEntries (+14); then (named + id) entries `"<II"` (8): Name/ID (bit 31 → low 31 bits = string offset), Offset
  (bit 31 → low 31 bits = subdirectory offset, else data-entry offset). All offsets relative to the directory start
  (DataDir[2] RVA), not RVAs (src: PE .rsrc). Levels type → name → language; named entries precede ID entries; order may be
  violated → linear scan, table order kept (src: PE .rsrc). NAME_IS_STRING = DATA_IS_DIRECTORY = 0x80000000 (src: winnt.h).
- Data entry `"<IIII"` (16): OffsetToData (an RVA), Size, CodePage, Reserved (src: PE .rsrc). String `"<H"` Length in
  WCHARs (src: winnt.h IMAGE_RESOURCE_DIR_STRING_U) + 2·Length bytes UTF-16LE. RT_RCDATA = 10 (src: winuser.h).
- Lookup (src: innoextract exereader.cpp find_resource): type and name entries must be directories, language entry must be
  a data entry; first language entry is taken.
- Pointer at file 0x30 `"<III"`: 0x6F6E6E49 ("Inno"), offset, ~offset (src: innoextract loader/offsets.cpp).
- Offset table `"<12s"` magic + u32 fields (src: innoextract loader/offsets.cpp load_offsets_at). R revision, U unnamed,
  EO exe_offset, EC exe_compressed_size, EU exe_uncompressed_size, CK exe_checksum (Adler32 < 4.0.3, CRC32 after),
  MO message_offset (not CRC-covered), HO header_offset, DO data_offset, T table CRC32 over all preceding bytes:
| magic (12 B) | loader_version | fields | size |
|---|---|---|---|
| `rDlPtS02\x87eVx` | 1.2.10 | U EO EC EU CK MO HO DO | 44 |
| `rDlPtS04\x87eVx` | 4.0.0 | U EO EC EU CK HO DO | 40 |
| `rDlPtS05\x87eVx` | 4.0.3 | U EO EC EU CK HO DO | 40 |
| `rDlPtS06\x87eVx` | 4.0.10 | U EO EC EU CK HO DO T | 44 |
| `rDlPtS07\x87eVx` | 4.1.6 | U EO EU CK HO DO T | 40 |
| `rDlPtS\xcd\xe6\xd7{\x0b*` and `nS5W7dT\x83\xaa\x1b\x0fj` | 5.1.5 | R U EO EU CK HO DO T | 44 |
| any other | None (newest) | as 5.1.5 | 44 |
  CRC check: `zlib.crc32(raw[:size - 4]) == T` (no MO exists when T exists). Revision expected 1 (warning otherwise).
- Version field at HO (src: innoextract setup/version.cpp): 12 B; byte 0 == `i` and byte 11 == 0x1A → legacy stamp; else
  64 B NUL-padded. raw = bytes before the first NUL (all 64 if none); must contain `Inno Setup`; version = max over groups
  `rb"\((\d{1,3})\.(\d{1,3})\.(\d{1,3})[a-z]?(?:\.(\d{1,3}))?\)"` with every component ≤ 255 (build 0 if absent; 255 cap
  mirrors INNO_VERSION_EXT byte packing, assumption); none → not recognised. unicode = version ≥ 6.3.0 or `(u)`/`(U)` in
  raw. known = field == entry NUL-padded to 64 for an entry of `_KNOWN_FIELDS` (memcmp in the source): the Evidence subset
  `Inno Setup Setup Data (5.1.5)`, `(5.5.7) (u)`, `(6.0.0) (u)`, `(6.1.0) (u)`, `(6.3.0)`, `(6.4.0)`, `(6.4.0.1)`.
- Block header ≥ 4.0.9 `"<IIB"` (9) at pos: expected CRC32, stored_size, flag; CRC32 over bytes [pos+4, pos+9); flag ≠ 0
  → LZMA1 if version ≥ 4.1.6 else zlib; payload = stored_size bytes of sub-chunks (u32 CRC32 + ≤ 4096 B)
  (src: innoextract stream/block.cpp block_reader::get). Block 2 at pos1 + 9 + stored_size1 (assumption; Acceptance 7).
- Data chunk: 4 B `zlb\x1a` at data_offset + chunk offset; first chunk offset 0 (assumption)
  (src: innoextract stream/chunk.cpp, slice.cpp).

## Safety checks
Resources (each violation → `ParseError(reason, offset=file offset)` → whole resources part dropped + note):
- S1 Root: `root` comes from `rva_to_file` of the directory RVA; bound B = min(dir2.Size, backed run). The tree region is
  read once, `read_exact(source, root.end, root.start, min(B, MAX_RESOURCE_READ))`; every structure is a slice of that
  window with rel + n ≤ B checked first (reasons unchanged), then rel + n ≤ window ("resource structure past the read
  window").
- S2 Directory at rel: rel + 16 ≤ B; n = named + id; n > MAX_RESOURCE_ENTRIES → "resource directory too large"; rel + 16
  + 8n > B → "resource entries past directory" (rejected, never clamped); total += n right after the header is read,
  before its entries; total > MAX_RESOURCE_TOTAL → "resource tree too large" (offset = that directory).
- S3 Structure: level-1 and level-2 entries must have DATA_IS_DIRECTORY set, level-3 entries must not; else "resource
  tree not three levels". Hard cap: the walk never reads a directory at level > MAX_RESOURCE_DEPTH (raises "resource tree
  deeper than 3 levels"; unreachable while S3 holds, kept as the recursion bound).
- S4 Visited set of directory rel offsets (root included): a revisit → "resource directory revisited" (cycles, shared
  subtrees).
- S5 String at rel: rel + 2 ≤ B; Length > MAX_RESOURCE_NAME → "resource name too long"; rel + 2 + 2·Length ≤ B.
- S6 Data entry at rel: rel + 16 ≤ B. OffsetToData/Size are stored, resolved only via `rva_range` (S8). Read budget: one
  read of min(B, MAX_RESOURCE_READ) B; a capped packed tree needs ≤ 16 + 16384·(8 + 16 + 130) = 2,785,296 B.
Inno (S8 raises → `inno_info` returns (None, step-1 notes + `pe inno not parsed: ...`); S7, S9-S13 add the quoted note and stop their chain only):
- S7 Pointer read 0x30..0x3C lies in the DOS header `parse_pe` already required; target checks in step 1 (note, fall
  through), never a raise.
- S8 Resource route: `rva_range` None (unmapped, zero-filled tail, Size > backed run) → "inno offset table resource not
  file-backed", offset = e.entry_offset; table_size > e.size → "inno offset table larger than its resource", offset =
  e.entry_offset; table end > size (defensive) → "inno offset table past end of file", offset = table_offset.
- S9 Version: the 12-byte probe and the 64-byte field are bounds-checked against size before reading (step 5).
- S10 Block header: pos + 9 ≤ size else `inno block N header past end of file at offset 0x..`.
- S11 flag ∉ {0, 1} → `inno block N compression flag F unexpected at offset 0x..`; block not reported.
- S12 CRC32 of the 5 bytes ≠ expected → reported with crc_ok False + `inno block N header CRC mismatch at offset 0x..`,
  chain stops (payload not checked). Else pos + 9 + stored_size > size → `inno block N payload past end of file at
  offset 0x..`, not reported; == size accepted.
- S13 Data: data_offset + 4 ≤ size before reading. All arithmetic in Python ints (no wrap); no allocation from a
  file-supplied length except the bounded reads above (≤ 16 + 8·4096 per directory).

## Caps
MAX_RESOURCE_ENTRIES 4096 per table, MAX_RESOURCE_TOTAL 16384, MAX_RESOURCE_DEPTH 3, MAX_RESOURCE_NAME 64 units,
MAX_RESOURCE_READ 4 MiB (≥ the 2,785,296 B worst case of S6),
MAX_VERSION_FIELD 64, MAX_RESOURCE_TYPE_ROWS 64 (facts only) — all (assumption: real installers carry < 200 resources).
`pe.resource` worst case: 64 rows × (named type 64 units × ≤ 7 JSON chars + ~20) ≈ 30,000 chars < 65,536; nodes ≤ 64·5 +
8 < 4,096. `inno.version.raw` ≤ 64 × 5 = 320 chars. Findings +6 → ≤ 391 << MAX_FINDINGS 4096.

## CLI/JSON
Text: no code change; new notes print as `note:` lines. JSON values (encoder sorts keys), all `parsed_finding`; Address
fields render as `.value`:
- `pe.resource`: {"offset", "size", "leaves": len(entries), "types": [{"type": int | utf16_display, "count": leaves}] in
  first-seen order, ≤ 64 rows, "types_truncated": true only if more}. `utf16_display`: each LE unit 0x20-0x7E except `"`
  and `\` kept, else `\uXXXX` (lowercase hex).
- `inno.loader`: {"route", "table_offset", "version": "a.b.c" | null, "revision": int | null, "exe_offset",
  "exe_uncompressed_size", "exe_checksum", "header_offset", "data_offset", "crc_ok": bool | null}; "exe_compressed_size"
  and "message_offset" only when present.
- `inno.version`: {"raw": display_name(raw), "major", "minor", "patch", "build", "unicode", "known"}.
- `inno.block` × ≤ 2: {"index", "offset", "stored_size", "compressed": flag == 1, "compression", "crc_ok"}.
- `inno.data`: {"offset", "magic_ok"}.
Order: ... pe.overlay, pe.signature ×, pe.resource, inno.loader, inno.version, inno.block ×, inno.data.
Goldens (slice-3 transform). G1-G5: only `stages[formats.inspect].version` "4" → "5" and `stages[formats.inspect].sha256`
change, plus the NOT_PARSED_NOTE string in G4/G5. G6 `tests/fixtures/reporting/pe32_inno.json` (new), recipe `info PI32
--json`, PI32 below; findings (values from a scratch run of HEAD code on PI32, 2026-10-13; inno/resource values derived):
- input {"magic":"pe"}; pe.header {"arch":"x86","characteristics":258,"e_lfanew":64,"machine":332,"number_of_sections":2,
  "number_of_symbols":0,"pointer_to_symbol_table":0,"size_of_optional_header":224,"time_date_stamp":1593835520}
- pe.optional {"address_of_entry_point":4096,"base_of_code":4096,"base_of_data":8192,"checksum":12648430,
  "data_directories": 16 × {"index":i,"size":0,"virtual_address":0} except index 2 {"size":144,"virtual_address":8192},
  "dll_characteristics":33088,"file_alignment":512,"format":"pe32","image_base":4194304,"loader_flags":0,"magic":267,
  "major_image_version":2,"major_linker_version":14,"major_os_version":6,"major_subsystem_version":5,
  "minor_image_version":3,"minor_linker_version":36,"minor_os_version":1,"minor_subsystem_version":4,
  "number_of_rva_and_sizes":16,"section_alignment":4096,"size_of_code":512,"size_of_headers":512,"size_of_heap_commit":8192,
  "size_of_heap_reserve":524288,"size_of_image":12288,"size_of_initialized_data":512,"size_of_stack_commit":4096,
  "size_of_stack_reserve":1048576,"size_of_uninitialized_data":0,"subsystem":3,"win32_version_value":0}
- pe.section {"characteristics":1610612768,"index":0,"name":".text","number_of_linenumbers":0,"number_of_relocations":0,
  "pointer_to_linenumbers":0,"pointer_to_raw_data":512,"pointer_to_relocations":0,"size_of_raw_data":512,
  "virtual_address":4096,"virtual_size":16}; pe.section idem with "characteristics":3221225536,"index":1,"name":".data",
  "pointer_to_raw_data":1024,"virtual_address":8192,"virtual_size":4096
- pe.overlay {"certificate":null,"offset":1536,"payload_size":114,"size":114,"trailing_size":0}; pe.signature
  {"offset":1536,"signature":"inno-setup-data"}; pe.resource {"leaves":1,"offset":1024,"size":144,"types":[{"count":1,
  "type":10}]}
- inno.loader {"crc_ok":true,"data_offset":1642,"exe_checksum":51,"exe_offset":17,"exe_uncompressed_size":34,
  "header_offset":1536,"revision":1,"route":"resource","table_offset":1120,"version":"5.1.5"}; inno.version {"build":1,
  "known":true,"major":6,"minor":4,"patch":0,"raw":"Inno Setup Setup Data (6.4.0.1)","unicode":true}
- inno.block {"compressed":true,"compression":"lzma1","crc_ok":true,"index":1,"offset":1600,"stored_size":16}; inno.block
  {"compressed":true,"compression":"lzma1","crc_ok":true,"index":2,"offset":1625,"stored_size":8}; inno.data
  {"magic_ok":true,"offset":1642}. Notes: INNO_NOT_PARSED_NOTE, NOT_PARSED_NOTE.
Stage sha256: implementer computes from the recipe, reviewer recomputes.

## Tests
Builders (`tests/formats/inno_build.py`): `rsrc(tree, base_rva) -> bytes` (tree = {type: {name: {lang: (rva, size)}}},
keys int | str; str → named UTF-16LE; directories depth-first, then strings, then data entries); `offset_table(magic,
fields, crc=None)` (None → computed); `version_field(text)` (NUL-pad to 64); `block(stored, flag, crc=None)`.
PI32 = `build_inno()`. Base `build_pe(32)` (0x600 B): "MZ", e_lfanew 0x40; "PE\0\0" at 0x40; COFF at 0x44 (0x14C, 2
sections, SizeOfOptionalHeader 0xE0, 0x102); optional at 0x58 (PE32, SizeOfHeaders 0x200, 16 dirs, dir1 entry at 0xC0,
dir2 entry at 0xC8); section table 0x138..0x188: .text VS 0x10 RVA 0x1000 raw 0x200 @0x200; .data VS 0x1000 RVA 0x2000
raw 0x200 @0x400 (backed run at RVA 0x2000 = 0x200 ≥ 0x90); raw end 0x600 = overlay start. Patches: dir1 = (0, 0); dir2 =
(0x2000, 0x90); at 0x400 (overwrites .data's 8 × 0x11, rest zero): root `"<IIHHHH"` (0,0,0,0,0,1) + entry (10,
0x80000018); 0x418 dir (0,0,0,0,0,1) + entry (11111, 0x80000030); 0x430 dir + entry (0, 0x48); 0x448 data entry (0x2060,
44, 0, 0); 0x460 table `rDlPtS\xcd\xe6\xd7{\x0b*` + `"<7I"` (1, 0, 0x11, 0x22, 0x33, 0x600, 0x66A) + CRC 0x85b3797d.
Appended: 0x600 version_field(b"Inno Setup Setup Data (6.4.0.1)"); 0x640 block(16, 1) = 0950c5d1 10000000 01 + 16 zero
B; 0x659 block(8, 1) = 4a8c5581 08000000 01 + 8 zero B; 0x66A b"zlb\x1a" + 4 zero B. Size 0x672 = 1650. sha256: file
c0a6c7740939bb024cbcfd0009ea2d2d577f3a8b21c47b2f8b6ce730a7d42a4c; [0x400, 0x490) 70d92f832424c8317c70244bf94c4723fbc9170b
567d55d2163431beef317e70; [0x600, 0x672) 3482a1be4f79ddd1d81f19487e3170f03fe093616738b4655ee2921ab88c9e8e (scratch run,
matches the reviewer's). Tests carry `t<NN>` in the function name.
`test_pe_resources.py` (root = whole blob, `MemorySource`):
- t01 single leaf 10/11111/0 → one `ResourceEntry` with exact fields and entry_offset. t02 named type "MYTYPE" + ID type 3
  with 2 names → 3 entries in table order, named key = UTF-16LE bytes; zero-length name allowed.
- t03 find_resource: first language wins; absent → None; a named entry never matches an int.
- t04 level-3 entry with bit 31 (depth 4 / cycle to root) → "not three levels"; t05 name-level subdir → root rel 0 →
  "revisited"; t06 level-1 data entry → "not three levels".
- t07 counts 0xFFFF + 0xFFFF → "too large"; n = 3 with room for 2 → "entries past directory".
- t08 root 2 types × 4096 names, every name → its own distinct 1-entry language dir (shared data entry): totals 2, 4098,
  8194, 12290; the 4095th language dir under type 2 makes 16385 → exact reason "resource tree too large" at that dir.
- t09 string offset B - 1 → past end; Length 65 → "name too long"; t10 data entry at B - 8 → past end; dir2.Size 0x20
  with entries beyond → past end (via attach_tables note); PI32 reads in [0x400, 0x490) are exactly (0x400, 0x90),
  (0x460, 12), (0x46C, 32); a subdirectory at MAX_RESOURCE_READ + 0x10 → "past the read window", one read.
- t11 dir2 RVA unmapped → note `pe resources not parsed: resource directory not file-backed at offset 0x..`; inno
  pointer route still runs.
`test_inno.py` (pure byte parsers):
- t12 parametrize 7 magics: layout fields/sizes per table; crc_ok True for ≥ 4.0.10, None below; t13 T flipped → crc_ok
  False; t14 unknown magic → loader_version None, 5.1.5 fields; `_TableLayout` with a wrong size raises.
- t15 versions: `(6.4.0.1)` → (6,4,0,1) unicode known; `(5.5.7) (u)` known unicode; `(5.5.7) (U)` unicode, not known;
  `(9.9.9)` → (9,9,9,0) unicode (≥ 6.3.0) not known; `(5.1.0)` not unicode; two groups → max; component 256 ignored.
- t16 `i1.2.10--16\x1a` → `is_legacy_stamp` True; `My Setup Data (6.4.0)` → None; `Inno Setup Setup Data` → None;
  64 non-NUL bytes incl. 0xFF → raw is all 64 bytes.
- t17 block header: CRC ok/mismatch; flag 2 with valid CRC → ParseError; compression stored / zlib (4.0.9) / lzma1 (4.1.6).
- t18 VO invariants: revision vs loader_version, flag vs compression, len(blocks) ≤ 2, index order, raw with NUL,
  Address fields reject negatives.
`test_inno_loader.py` (via `parse_pe` + `attach_tables`; variants patch PI32):
- t19 PI32 → InnoInfo equal to the G6 values; inno part reads ≤ 7 and ≤ 142 B (`SparseSource.calls` delta).
- t20 pointer route: "Inno" + off + ~off at 0x30, 4.1.6 table (40 B) in the overlay → POINTER; t21 complement wrong, no
  resource → inno None + complement note; t22 both routes valid → POINTER wins.
- t23 complement wrong, resource present → parsed via RESOURCE, complement note present before table notes.
- t24 valid complement, target size - 8 (and size + 4) → past-end pointer note; with resource → parsed via RESOURCE;
  without → inno None, note only, no `pe inno not parsed` note.
- t25 pointer target 0x5000 past end + data RVA unmapped → (pointer note, `pe inno not parsed: ... not file-backed at
  offset 0x448`), pointer note first. Resource Size 43 → `pe inno not parsed: inno offset table larger than its resource at offset 0x448`; data RVA
  unmapped → "not file-backed at offset 0x448".
- t26 header_offset = size → past-end note, loader still reported; header_offset = size - 20 → past-end note, no
  version, exactly one 12 B read at h; data_offset 0 → external-slices note; data_offset = size - 4 accepted, size - 3
  → data past-end note; bad chunk bytes → magic_ok False.
- t27 legacy stamp at header_offset → legacy note; `(4.0.8)` → version reported, blocks note.
- t28 block 1: CRC mismatch → 1 block crc_ok False, note, no block 2; flag 2 with valid CRC → note `inno block 1
  compression flag 2 unexpected at offset 0x640`, blocks == (); header at size - 5 → header past-end note; stored_size
  = size - pos - 8 and 0xFFFFFFFF → payload past-end note, no blocks.
- t29 block 2: CRC mismatch → block 1 ok + block 2 crc_ok False + note; file cut at 0x660 → block 2 header past-end
  note; stored_size2 9 (CRC recomputed, file cut at 0x66A) → payload past-end note; stored_size2 8 with file cut at 0x66A
  (pos2 + 9 + stored == size) → accepted; stored_size1 15 (CRC recomputed) → block 2 read at 0x658 on garbage → crc_ok
  False, note `inno block 2 header CRC mismatch at offset 0x658`.
- t30 notes: table CRC flipped → exactly `inno loader table CRC mismatch at offset 0x460`; revision 2; unknown magic;
  overlay starting `zlb\x1a` without a table → "inno-like overlay" note only.
- t31 real shape: `real_shape()` head with dir2 → tree at .data + 0x10, 5.1.5 table HO 0xd3e00, DO 0xd3e40 (zeros) →
  RESOURCE, version not-recognised note, magic_ok False, no 0x30 magic, inno reads ≤ 7.
- t32 `ShrinkingSource` cut inside the resource tree read (0x400, cut 0x418) / inside the table magic (0x460, cut
  0x464) → `InputChanged` propagates.
`test_pe_facts.py`: t33 PI32 finding order and values; 65 ID types → 64 rows + types_truncated; named type → `\u` escapes.
`test_cli.py`: t34 G6 golden; G1-G5 regenerated; text `info PI32` shows the two notes.

## Evidence
Researchers 2026-10-13: (src: PE .rsrc) Microsoft PE format, .rsrc section; (src: winnt.h) IMAGE_RESOURCE_* constants
and DIR_STRING_U; (src: winuser.h) RT_RCDATA 10; (src: innoextract src/loader/exereader.cpp find_resource),
(src: innoextract src/loader/offsets.cpp load, load_from_exe_file, load_offsets_at), (src: innoextract
src/setup/version.cpp), (src: innoextract src/stream/block.cpp block_reader::get), (src: innoextract src/stream/chunk.cpp,
slice.cpp). Repo: HEAD 3b75236; pe.py 501 lines; `SIGNATURES` holds inno-setup-data, inno-chunk, inno-loader;
`rva_to_file` in pe_image.py; `SparseSource.calls` records reads; STAGE_VERSION "4"; PI32 scratch values above.

## Risks
- R1 Block 2 position pos1 + 9 + stored_size1 is inferred (assumption); its own CRC is the check (Acceptance 7).
- R2 Requiring resource Size ≥ table size is stricter than innoextract (which reads past); a short resource is noted.
- R3 Any resource-tree violation drops the whole tree, so a hostile file can hide route B; the note makes it visible.
- R4 `_KNOWN_FIELDS` is a 7-entry subset: real versions may show known false (F-INNO-VERSIONS).
- R5 dir2.Size smaller than the tree (packers) → resources note (assumption: rare in installers).
- R6 Pointer-first order mirrors innoextract; the brief listed resource first (both routes rarely coexist).
- R7 pe.py grows to ~505 lines (F-PE-TABLES).

## Acceptance
1. `make check` passes (lint, mypy --strict, arch, tests); t01-t34 present (`grep -c "def test_.*t[0-9][0-9]"`).
2. `grep -rnE "decompressobj|zlib\.decompress|import (lzma|bz2)" src/retool/formats` → no match.
3. G6 matches the recipe. In G1-G5 `git diff` shows only `stages[formats.inspect].version`, `.sha256` and (G4/G5) the
   NOT_PARSED_NOTE string; the implementer confirms G4/G5 gain no `pe.resource` / `inno.*` finding (P64/PT64 dir2 = (0,
   0), bytes 0x30..0x3C zero, overlay signatures only 7z / zip-local) and lists the diffed fields in its report.
4. `grep -n 'STAGE_VERSION: Final = "5"' src/retool/formats/application/use_cases.py` matches once.
5. `git diff --stat` touches no file under `src/retool/{shared,interface,reporting}`, `.importlinter`,
   `src/retool/formats/__init__.py`.
6. `wc -l src/retool/formats/domain/pe.py` ≤ 510; each new module ≤ 300 lines; `pe_resources.py` and `inno.py` contain
   no import of `retool.formats.domain.pe` / `pe_image` (grep).
7. Orchestrator only: `uv run retool info <sample> --json` shows `inno.loader` route "resource"; record which of
   exe_offset / header_offset / data_offset equals 0xd3e00 and `inno.block` 2 crc_ok. crc_ok false (or no block 2)
   falsifies the pos1 + 9 + stored_size1 assumption: the spec reopens before 6b.

## Follow-ups
- F-INNO-ENTRIES: bounded LZMA1/zlib decompression of block 1/2 and header/entry parsing — after a `/decide`.
- F-INNO-SLICES: multi-file installers (`idska32\x1a` slice headers, data_offset 0).
- F-INNO-VERSIONS: transcribe the full innoextract version table (known/unicode/ISX flags) with source dates.
- F-INNO-LEGACY: < 4.0.9 block layout and legacy `i1.2.10--16\x1a` stamps.
- F-RSRC-FULL: version info, manifest, icons, string tables; resource contents in findings.
- F-PE-TABLES: the next `PeFile` field moves the slice-5 VOs and caps into a leaf `pe_tables.py` first.
- F-EMBEDDED: a second embedded-container family must not add another `PeFile` field without a `/decide` on a generic
  embedded-container model.
