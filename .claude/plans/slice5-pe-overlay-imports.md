# Slice 5: PE imports, certificate headers, overlay facts (`formats`)

Goal: from hostile PE input, report (A) `pe.overlay` - file bytes past the last section's raw data: extent, certificate
sub-range (dir 4), payload and trailing sizes, plus bounded `pe.signature` matches at the overlay start, right after the
certificate table and at file offset 0x30; (B) `pe.import` - Import Directory walk: DLL name + functions (hint/name or
ordinal) under caps; (C) `pe.certificate` - WIN_CERTIFICATE headers (length, revision, type), no PKCS#7. Repo facts verified
at e8e1144 (466 tests). Revision 2 applies round 1 (architect A1-A8, reviewer R1-R9; orchestrator decisions, no `/decide`).
`architect review required`: aggregate `PeFile` gains children. No new context, port, DTO or public export.

## Scope
In: dir 1 import descriptors, ILT/IAT (PE32 u32, PE32+ u64), Hint/Name entries, DLL names; dir 4 WIN_CERTIFICATE headers;
overlay extent and anchored signature probes; findings, notes, JSON; `formats.inspect` stage version "4".
Policy: parts are contained: a `ParseError` in imports / certificates / overlay drops only that part + one note `pe <part>
not parsed: <reason> at offset 0x..`; everything else stays. `InputChanged` still fails the command (exit 1).
Out (follow-ups): F-DELAY delay-load imports (dir 13); F-BOUND bound imports (dir 11), bound-IAT decoding; F-EXPORT-DIR
exports; F-RSRC resources; F-PKCS7 certificate contents; F-INNO-RESOURCE Inno offset table (resource 11111, the 0x30 pointer);
F-OVERLAY-SCAN scanned or unverified signatures (ZIP EOCD/ZIP64 backwards, NSIS 512-aligned scan, CAB "MSCF" bytes, zlib
FCHECK predicate); F-PACKER packer verdicts in `analysis` (UPX, zlib heuristics) incl. F-ENTROPY (overlay entropy; advisory
for that spec: `analysis` receives the overlay range as a typed DTO field, never re-derives it); F-TEXT-FINDINGS text
rendering of findings via `reporting` (CLI text unchanged here).

## Architecture
Conforms to ARCH §2 (`formats`: "structural parsing of ... imports"; overlay extent, certificate headers and fixed-offset
container magics are "container identification and structural parsing"), §3 (domain = stdlib + `shared`; bytes only via port
`ByteSource`), §4 (pure domain services, frozen VOs validated in `__post_init__`, capped counts, `read_exact` =
`check_within` before every read, file offsets as `Address`, `ParseError` with offset; strategy `PeParser` keeps its shape),
§5 (domain unit tests on `MemorySource`/`SparseSource`, CLI goldens). ADR 0002: `formats` authors its findings; every
`pe.signature` is PARSED via `parsed_finding` (an exact fixed-byte magic at an anchored offset, like `magic_finding`).
A1-A7: no new cross-context or third-party import; every new dataclass frozen; no `Any`; interface untouched.
`rva_to_file` lives in `pe_image.py` next to `section_mem_size` and mirrors `_segment`'s mapping, but works on `PeFile`, not
`Image`: imports must not depend on `Image`, which is None under F-SEGCAP (> 63 sections) or section overlaps; a zero-filled
tail returns None by design (no file bytes). Test 4 checks agreement with `MemoryMap.file_range_for`.
| Module | Context / layer | Pattern (ARCH §4) |
|---|---|---|
| `formats/domain/pe.py` | formats / domain | + 9 caps; VOs `ImportedFunction`, `ImportedDll`, enum `ThunkEnd`, `CertificateEntry`, `SignatureMatch`, `OverlayInfo`; `PeFile` + `imports`, `certificates`, `overlay` (defaults, invariants); pure `directory`, `directory_offset`, `section_table_end`; `parse_pe` unchanged. VOs live here because `PeFile` references them and the new modules import `pe` (cycle otherwise); if pe.py exceeds ~500 lines, move them to a leaf `pe_tables.py` |
| `formats/domain/pe_image.py` | formats / domain | + pure `rva_to_file` |
| `formats/domain/pe_imports.py` (new) | formats / domain | pure service `parse_imports` over `ByteSource` |
| `formats/domain/pe_certificates.py` (new) | formats / domain | pure service `parse_certificates` over `ByteSource` |
| `formats/domain/pe_overlay.py` (new) | formats / domain | pure services `overlay_info`, `match_window`; VO `SignatureRule`, enum `SignatureAnchor`, immutable table `SIGNATURES` |
| `formats/domain/pe_parser.py` | formats / domain | strategy `PeParser`; + `attach_tables` (runs the three parts, contains their `ParseError`) |
| `formats/domain/pe_facts.py` | formats / domain | + findings `pe.import`, `pe.certificate`, `pe.overlay`, `pe.signature`; NOT_PARSED_NOTE reworded |
| `formats/application/use_cases.py` | formats / application | `InspectFile.STAGE_VERSION = "4"`; nothing else |
| `tests/formats/pe_build.py`, `tests/formats/fakes.py` | tests | builders below; `SparseSource` gains `tail` |
Unchanged: `retool.formats.__all__`, `dto.py`, `parsing.py`, `interface/`, `reporting/`, `shared/`, `.importlinter`.
Version policy (slice 2): facts for an `MZ` input change -> stage "4"; no report key/type/meaning change -> schema_version 1.

## Interfaces
```python
# domain/pe.py (all VOs @dataclass(frozen=True, slots=True); __post_init__ violations raise ParseError; one constant per line)
MAX_IMPORT_DLLS: Final = 256; MAX_IMPORT_FUNCS: Final = 512; MAX_IMPORT_NAME: Final = 256
IMPORT_DLL_NAME_BYTES: Final = 12288; MAX_IMPORT_FUNCS_TOTAL: Final = 16384; IMPORT_TOTAL_NAME_BYTES: Final = 262144
MAX_CERTS: Final = 16; SIGNATURE_WINDOW: Final = 64; MAX_SIGNATURE_MATCHES: Final = 16
class ThunkEnd(StrEnum): NULL = "null"; CAP = "cap"; DATA_END = "data_end"; UNMAPPED = "unmapped"
class ImportedFunction: ordinal: int | None; hint: int | None; name: bytes | None; name_truncated: bool = False
    # exactly one form: (ordinal) or (hint and name); ordinal, hint in 0..0xFFFF; len(name) <= MAX_IMPORT_NAME;
    # name_truncated only with a name
class ImportedDll: descriptor_offset: Address; ilt_rva: int; time_date_stamp: int; forwarder_chain: int; name_rva: int
    iat_rva: int; name: bytes | None; name_truncated: bool; functions: tuple[ImportedFunction, ...]; end: ThunkEnd
    # len(functions) <= MAX_IMPORT_FUNCS; function-name bytes <= IMPORT_DLL_NAME_BYTES; len(name) <= MAX_IMPORT_NAME
class CertificateEntry: offset: Address; length: int; revision: int; certificate_type: int     # length >= 8
class SignatureMatch: name: str; offset: Address
class OverlayInfo: offset: Address; size: int; certificate: ByteRange | None; payload_size: int; trailing_size: int
    signatures: tuple[SignatureMatch, ...]
    # size >= 1; payload_size + (certificate.size if certificate else 0) + trailing_size == size;
    # trailing_size == 0 without a certificate; len(signatures) <= MAX_SIGNATURE_MATCHES
class PeFile: <slice-4 fields>; imports: tuple[ImportedDll, ...] = (); certificates: tuple[CertificateEntry, ...] = ()
    overlay: OverlayInfo | None = None
    # post_init adds: len(imports) <= MAX_IMPORT_DLLS, len(certificates) <= MAX_CERTS, total functions <=
    # MAX_IMPORT_FUNCS_TOTAL, total function-name bytes <= IMPORT_TOTAL_NAME_BYTES, else "PE table counts inconsistent"
def directory(pe: PeFile, index: int) -> DataDirectory | None: ...  # None if index >= len(dirs) or VA == 0 or size == 0
def directory_offset(pe: PeFile, index: int) -> int: ...   # e_lfanew + 24 + (112 if bits == 64 else 96) + 8 * index
def section_table_end(pe: PeFile) -> int: ...  # e_lfanew + 24 + SizeOfOptionalHeader + 40 * NumberOfSections
# domain/pe_image.py
def rva_to_file(pe: PeFile, rva: int) -> ByteRange | None: ...    # file-backed run starting at rva (R1-R3)
# domain/pe_imports.py
def parse_imports(source: ByteSource, pe: PeFile) -> tuple[tuple[ImportedDll, ...], tuple[NotAnalysed, ...]]: ...
# domain/pe_certificates.py
def parse_certificates(source: ByteSource, pe: PeFile) -> tuple[tuple[CertificateEntry, ...], tuple[NotAnalysed, ...]]: ...
# domain/pe_overlay.py
class SignatureAnchor(StrEnum): WINDOW = "window"; FILE = "file"
class SignatureRule: name: str; anchor: SignatureAnchor; at: int; magic: bytes
    # name [a-z0-9-]{1,32}; len(magic) >= 3; at >= 0; at + len(magic) <= SIGNATURE_WINDOW
SIGNATURES: Final[tuple[SignatureRule, ...]]                       # ## Signatures, in output order
def match_window(window: bytes, offset: int) -> tuple[SignatureMatch, ...]: ...   # WINDOW rows in table order
def overlay_info(source: ByteSource, pe: PeFile) -> OverlayInfo | None: ...
# domain/pe_parser.py
def attach_tables(source: ByteSource, pe: PeFile) -> tuple[PeFile, tuple[NotAnalysed, ...]]: ...
```
`attach_tables`: imports, then certificates, then overlay (read order tested). Each call: `except InputChanged: raise` (it
subclasses `ParseError`), `except ParseError as exc`: part empty + note `f"pe {imports|certificates|overlay} not parsed:
{exc}"` (overlay: defensive only). Notes per part in that order (failure note or the part's own notes). Returns `replace(pe,
imports=..., certificates=..., overlay=...)`; that replace cannot fail: every part is built within the same caps that
`PeFile.__post_init__` checks (test 17 pins the invariants). `_build_pe`: `pe = parse_pe(source)`; `pe, table_notes =
attach_tables(source, pe)`; image as before; notes `(*image_notes, *table_notes, *fact_notes)`.
`pe_facts` order: magic, pe.header, pe.optional, pe.section x n, pe.import x (descriptor order), pe.certificate x (table
order), pe.overlay (if any), pe.signature x (`overlay.signatures` order), all via `parsed_finding`. Values in ## CLI.

## Binary layout
All little-endian; w = 8 (PE32+) | 4 (PE32).
- Import descriptor `"<5I"` (20): +0 ILT RVA (OriginalFirstThunk), +4 TimeDateStamp, +8 ForwarderChain, +12 Name RVA
  (ASCIIZ DLL name), +16 IAT RVA (FirstThunk); table ends at an all-zero entry; no max count (src: PE, Import Directory Table).
- Thunk `"<I"` | `"<Q"`: bit 31 | 63 = import by ordinal, ordinal = bits 15-0; name import: bits 30-0 = Hint/Name RVA;
  array ends at 0 (src: PE, Import Lookup Table); IAT identical until bound (src: PE, Import Address Table). Bits 30-16 |
  62-16 of an ordinal thunk: spec says must be 0, reader ignores them (assumption); PE32+ name-thunk bits 62-31: spec says
  must be 0, reader stops the DLL with UNMAPPED (I6).
- Hint/Name: `"<H"` hint, ASCIIZ name, optional pad to even (ignored) (src: PE, Hint/Name Table); no max length stated.
- Dir 4: VirtualAddress is a FILE OFFSET (src: PE, Attribute Certificate Table). WIN_CERTIFICATE `"<IHH"` (8): dwLength
  (incl. header), wRevision (0x0100, 0x0200), wCertificateType (1, 2 PKCS_SIGNED_DATA, 3 reserved, 4); payload; entries
  contiguous, next at offset + align8(dwLength); Size includes padding (src: PE, Attribute Certificate Table).
- Overlay: not defined by src; O1 (unverified). Dir entries: P64 dir1 @0xD0, dir4 @0xE8; P32 dir1 @0xC0, dir4 @0xD8.

## Safety checks
RVA translation. Decision: zero-filled tails and gaps are "not file-backed" (None); only an untranslatable descriptor table
rejects the imports part; elsewhere the element is dropped and the per-DLL walk stops with a reason.
R1 Sections in file order; the first with VA <= rva < VA + section_mem_size(s) wins (assumption). delta = rva - VA, backed =
   min(SizeOfRawData, mem): delta < backed -> ByteRange(PointerToRawData + delta, backed - delta); else None (src: PE,
   Section Table: zero padding past SizeOfRawData).
R2 No section matches and rva < SizeOfHeaders -> ByteRange(rva, SizeOfHeaders - rva) (headers at ImageBase, unverified as in
   slice 4); else None (gap, beyond image).
R3 Runs lie inside the file by P15/P17; every read still goes through `read_exact(source, source.size, off, n)`. Walks and
   name scans never cross the end of their run.
Imports (`parse_imports`; D = directory(pe, 1); budget counters are local ints threaded through private helpers - A5 forbids
mutable dataclasses):
I1 D None -> ((), ()), no read.
I2 rva_to_file(D.VA) None -> ParseError("import directory not in file", offset=directory_offset(pe, 1)).
I3 n = min(D.size // 20, run.size // 20, MAX_IMPORT_DLLS + 1); one read of 20n bytes (none if n == 0). Entry i all-zero ->
   stop; i == MAX_IMPORT_DLLS -> stop + note "pe imports truncated at 256 DLLs"; else one DLL. Reaching n without a null
   entry ends the walk silently (assumption, Risks R3).
I4 Names: DLL name run None -> name None (walk continues). Window = min(MAX_IMPORT_NAME + 1, run bytes) after any hint;
   first NUL at j -> bytes before it; no NUL -> first MAX_IMPORT_NAME bytes (fewer if the run ends), name_truncated True.
I5 Thunk array RVA = ILT if ILT != 0 else IAT (convention, unverified); 0 -> UNMAPPED; run None -> UNMAPPED; count =
   min(MAX_IMPORT_FUNCS + 1, run.size // w); one read of count * w bytes; count 0 -> DATA_END.
I6 Thunk k: 0 -> NULL; k == MAX_IMPORT_FUNCS -> CAP; functions listed so far (all DLLs) == MAX_IMPORT_FUNCS_TOTAL -> CAP;
   ordinal flag -> ordinal = v & 0xFFFF; PE32+ name thunk with v >> 31 != 0 -> UNMAPPED (bound VA or corrupt); hint/name
   run None -> UNMAPPED; run.size < 2 -> DATA_END; read min(2 + MAX_IMPORT_NAME + 1, run.size) bytes, hint `"<H"`, name per
   I4; DLL name bytes + len(name) > IMPORT_DLL_NAME_BYTES or global name bytes + len(name) > IMPORT_TOTAL_NAME_BYTES -> CAP
   (not listed); count exhausted -> DATA_END.
Certificates (`parse_certificates`; D = directory(pe, 4); A = directory_offset(pe, 4)):
C1 D None -> ((), ()).   C2 D.VA + D.size > size -> "certificate table exceeds file" @A.
C3 pos = D.VA, end = D.VA + D.size; loop while pos < end: len(entries) == MAX_CERTS -> note "pe certificates truncated at
   16 entries", stop (C7 skipped).
C4 pos + 8 > end -> "certificate header exceeds table" @pos.   C5 dwLength < 8 -> "certificate length below header size" @pos.
C6 pos + dwLength > end -> "certificate entry exceeds table" @pos; else entry, pos += (dwLength + 7) & ~7.
C7 after the loop pos != end -> "certificate lengths do not sum to table size" @A. Revision, type, start alignment: raw.
Overlay (`overlay_info`; size = source.size):
O1 raw_end = max(PointerToRawData + SizeOfRawData over sections with SizeOfRawData > 0, default 0); start = min(max(raw_end,
   SizeOfHeaders, section_table_end(pe)), size) (convention, unverified); start == size -> None, no read.
O2 cert = ByteRange(D4.VA, D4.size) if directory(pe, 4) and D4.VA >= start and D4.VA + D4.size <= size else None (independent
   of C2-C7). payload_size = (cert.start if cert else size) - start; trailing_size = size - cert.end if cert else 0.
O3 Probes: payload_size > 0 -> read min(64, payload_size) at start, `match_window`; trailing_size > 0 -> read min(64,
   trailing_size) at cert.end, `match_window`; then FILE rows in table order: at + len(magic) <= size -> read len(magic) at
   `at`, equal -> match at `at`. Nothing else is read: payload and trailing bytes past their first 64 never are. No probe
   without an overlay. Overlay reads <= 64 + 64 + 4 bytes whatever its size.
O4 `match_window`: a WINDOW row matches iff at + len(magic) <= len(window) and window[at:at+len(magic)] == magic; the reported
   offset is the window offset (structure start, e.g. NSIS firstheader).

## Signatures
Decision (orchestrator, round 1): an exact fixed-byte magic (>= 3 bytes) at an anchored offset is a structural fact, PARSED
like `magic_finding`; only rows with bytes from a cited source are admitted; unverified or predicate rules wait for
F-OVERLAY-SCAN / F-PACKER. All findings `Verification.unverified()`. Changing a row changes one table line and test 24's
parameters, never test structure. Sources: relayed by the orchestrator 2026-10-13 (researcher).
| name | anchor | at | magic | src |
|---|---|---|---|---|
| 7z | window | 0 | 37 7A BC AF 27 1C | (src: relayed by orchestrator 2026-10-13: ip7z/7zip DOC/7zFormat.txt) |
| zip-local | window | 0 | 50 4B 03 04 | (src: relayed by orchestrator 2026-10-13: PKWARE APPNOTE 4.3.7) |
| gzip | window | 0 | 1F 8B 08 | (src: relayed by orchestrator 2026-10-13: RFC 1952 §2.3.1, CM 8 deflate) |
| nsis | window | 4 | EF BE AD DE 4E 75 6C 6C 73 6F 66 74 49 6E 73 74 | (src: relayed by orchestrator 2026-10-13: nsis Source/exehead/fileform.h) |
| inno-setup-data | window | 0 | "Inno Setup Setup Data (" | (src: relayed by orchestrator 2026-10-13: innoextract version.cpp) |
| inno-chunk | window | 0 | 7A 6C 62 1A "zlb\x1a" | (src: relayed by orchestrator 2026-10-13: innoextract chunk.cpp) |
| inno-loader | file | 0x30 | 49 6E 6E 6F "Inno" (u32 0x6f6e6e49) | (src: relayed by orchestrator 2026-10-13: innoextract offsets.cpp) |
Omitted: CAB "MSCF" (bytes unverified) and zlib FCHECK predicate -> F-OVERLAY-SCAN / F-PACKER; UPX ("UPX!" + A1 D8 D0 D5,
found by search -> F-PACKER); ZIP central/EOCD/ZIP64 (backward scan) -> F-OVERLAY-SCAN; NSIS flags and Inno `~offset` checks
(16 / 4 fixed bytes suffice, assumption); NSIS 512-aligned probes (unverified); Inno offset-table magics -> F-INNO-RESOURCE.

## Caps
Limits: per finding value nodes 4096, text (strings + keys) 65536, string 4096 (shared/json_value.py); MAX_FINDINGS 4096
(reporting/domain/model.py:12); MAX_REPORT_CHARS 8 MiB pretty (reporting/domain/services.py:12). `display_name` <= 4 chars
per raw byte; JSON escapes its backslash -> <= 5.
- MAX_IMPORT_DLLS 256 (assumption: large real tables ~100). One `pe.import` finding per DLL, never one per function.
- MAX_IMPORT_FUNCS 512 per DLL; MAX_IMPORT_NAME 256 bytes for function and DLL names (longer decorated names truncated and
  flagged; assumption).
- IMPORT_DLL_NAME_BYTES 12288: worst `pe.import` text = 102 (keys) + 8 + 4*256 (dll) + 512*22 (function keys) + 4*12288 =
  61,550 < 65,536; nodes <= 12 + 512*4 = 2,060 < 4,096. Scratch run (2026-10-13, `check_json_value`): 55,054.
- MAX_IMPORT_FUNCS_TOTAL 16384, IMPORT_TOTAL_NAME_BYTES 262144 (global): without them 256 DLLs x ~115 KB pretty ~ 29 MB >
  8 MiB. Worst document (scratch run): 32 DLLs x 512 functions (10,922 with 24-byte \xff names = 262,128 name bytes, the rest
  ordinals) + 224 DLLs without functions, every DLL name 256 \xff bytes (imports 2,900,920 chars) + 96 sections named
  b"\xff"*8 + 16 notes of 256 chars = 2,972,647 chars = 35 % of MAX_REPORT_CHARS.
- Import read budget: each name thunk charges max(len(name), 3) to IMPORT_DLL_NAME_BYTES; parse_imports reads <= MAX_IMPORT_READ_BYTES = 20*257 + 256*(257 + 8*513) + 16384*259 = 5,365,012 B (test pins it).
- MAX_CERTS 16 (assumption; nested Authenticode signatures live inside one entry); reads <= 128 bytes.
- Findings <= 3 + 96 + 256 + 16 + 1 + 13 (2 windows x 6 rows + 1 file row) = 385 << 4096; MAX_SIGNATURE_MATCHES 16 >= 13.

## CLI
Text: no code change; new notes print as `note:` lines. NOT_PARSED_NOTE = "pe exports, relocations, resources, delay-load
and bound imports, certificate contents, debug data, CLR metadata and COFF symbols not parsed in this version";
`retool info P64` and `info PT64` print slice-4's `_P64_TEXT` lines with this note.
JSON finding values (encoder sorts keys):
- `pe.import`: {"index", "descriptor_offset", "dll": display_name | null, "dll_truncated": true (only if truncated),
  "ilt_rva", "time_date_stamp", "forwarder_chain", "name_rva", "iat_rva", "functions": [{"hint", "name",
  "name_truncated": true (only if truncated)} | {"ordinal"}], "end": ThunkEnd value}.
- `pe.certificate`: {"index", "offset", "length", "revision", "type"}.
- `pe.overlay`: {"offset", "size", "certificate": {"offset", "size"} | null, "payload_size", "trailing_size"}.
- `pe.signature`: {"signature", "offset"}, provenance parsed.
Goldens (slice-3 transform `json.dumps(json.loads(LINE), indent=2, sort_keys=True) + "\n"`). G1-G3 stage hashes from a
scratch run with STAGE_VERSION "4" (the same method reproduced HEAD's v3 hashes of G3 and G4): G1 `elf_magic.json`
a93c83ed238585e50632efb1a210c3dc53b9d5494585edbab985fc80a9beb0ac; G2 `raw_base.json` formats.inspect
e43d7d9e1b5e01c2929584639cf17a8823d67996c119349d51fc320b845fbfc7 (formats.raw unchanged 92cfbecf...); G3 `elf64_min.json`
80320b07a4a4bcdb752d34a93183910a63531100717c3c00897a71af6a77af11. Only "version" and these hashes change in G1-G3.
G4 `pe64_min.json`, recipe `info P64 --json`: version "4", new stage sha, new note text, and after the two `pe.section`
findings one `pe.import` {"index":0,"descriptor_offset":1024,"dll":"MZ","ilt_rva":286331153,"time_date_stamp":286331153,
"forwarder_chain":0,"name_rva":0,"iat_rva":0,"functions":[],"end":"unmapped"}. Deliberate: P64's .data starts with 8 x 0x11
and Name RVA 0 maps into the headers, so G4 pins hostile-descriptor handling; P64 is not changed.
G5 `pe64_tables.json` (new), recipe `info PT64 --json`; input size 132640, sha256
606bed2468d7857f728da6a180eec38c235db0a387e657bcae7dd1556b0c7900. Findings: G4's header/optional/sections with
data_directories[1] = (8192, 60), [4] = (132608, 16); then pe.import 0 {"descriptor_offset":1024,"dll":"KERNEL32.dll",
"ilt_rva":8256,"time_date_stamp":0,"forwarder_chain":0,"name_rva":8384,"iat_rva":8320,"functions":[{"hint":291,
"name":"ExitProcess"},{"ordinal":16}],"end":"null"}; pe.import 1 {"descriptor_offset":1044,"dll":"USER32.dll","ilt_rva":0,
"time_date_stamp":0,"forwarder_chain":0,"name_rva":8400,"iat_rva":8352,"functions":[{"hint":2,"name":"MessageBoxA"}],
"end":"null"}; pe.certificate {"index":0,"offset":132608,"length":12,"revision":512,"type":2}; pe.overlay {"offset":1536,
"size":131104,"certificate":{"offset":132608,"size":16},"payload_size":131072,"trailing_size":16}; pe.signature
{"signature":"7z","offset":1536}; pe.signature {"signature":"zip-local","offset":132624}. Notes: NOT_PARSED_NOTE only.
G4/G5 stage sha256: computed by the implementer from the recipe, recomputed by the reviewer (Acceptance 3).

## Tests
Builders (`tests/formats/pe_build.py`, `patch` from elf_build; in .data file offset = RVA - 0x1C00):
- `build_pe_tables(bits=64)` -> PT64 / PT32 (0x20620 B; PT32 sha256 264abcc9bd086492fddd7476b916179d1a3852f550ea476a8374e
  a8837d9ccad): build_pe(bits); dir1 = (0x2000, 0x3C); 0x400 desc0 (0x2040, 0, 0, 0x20C0, 0x2080); 0x414 desc1 (0, 0, 0,
  0x20D0, 0x20A0); 0x428 20 zero bytes; 0x440 and 0x480 thunks [0x20E0, ordinal flag | 16, 0] (width w); 0x4A0 [0x20F0, 0];
  0x4C0 b"KERNEL32.dll\0"; 0x4D0 b"USER32.dll\0"; 0x4E0 `<H` 0x123 + b"ExitProcess\0"; 0x4F0 `<H` 2 + b"MessageBoxA\0";
  append b"7z\xbc\xaf\x27\x1c" + 65530 zero bytes, bytes(range(256)) * 256, `<IHH` (12, 0x200, 2) + b"\x30\x82\0\0" + 4
  zero bytes, b"PK\x03\x04" + 12 zero bytes; dir4 = (0x20600, 0x10). (Payload bytes kept from revision 1; hashes unchanged.)
- `big_data(raw)` -> P64[:0x400] + bytes(raw) with sec1 VS (0x178) = SizeOfRawData (0x180) = raw; overlay none.
- `real_shape()` -> SparseSource(139821624, head=H, tail=T): H = build_pe(32, extra_sections=9) with dir1 = (0, 0), sec1
  SizeOfRawData (0x170) = VS (0x168) = 0xd3e00 - 0x600, dir4 = (139811888, 9736); T = `<IHH` (9729, 0x200, 2) padded to 9736.
- `fakes.py`: `SparseSource(size, head=b"", tail=b"")`; bytes in [size - len(tail), size) come from `tail`.
Big layouts (file offsets; RVA = offset + 0x1C00): L7 = big_data(0x5000): n descriptors at 0x400, name b"a.dll\0" at 0x5240,
IAT [0] at 0x5250, dir1 = (0x2000, 20(n+1)). L13 = big_data(0x2000): descriptors at 0x400, ILT at 0x800 (<= 514 thunks),
hint/name b"f" at 0x1900, 256-byte name entry at 0x1A00, DLL name b"a.dll\0" at 0x1C00. L39 = big_data(0x6C00) (file 0x7000):
256 descriptors + null at 0x400 (dir1 size 5140), ILT 512 + null at 0x1900, 512 hint/name entries (2 + 24 x b"\xff" + NUL)
at 0x2A00 + 0x20k, DLL name 300 x b"\xff" + NUL at 0x6A00.
`tests/formats/test_pe_imports.py`:
1. parse_imports(PT64) -> the two DLLs of G5 (descriptor_offset 0x400 / 0x414, DLL1 via IAT), notes (); PT32 -> equal DLLs.
2. Calls after parse_pe's 7 (PT64 and PT32): [(0x400,60),(0x4c0,257),(0x440,448),(0x4e0,259),(0x4d0,257),(0x4a0,352),
   (0x4f0,259)].
3. rva_to_file(PT64): 0x2000 -> (0x400,0x200); 0x21ff -> (0x5ff,1); 0x2200 -> None (tail); 0x1008 -> (0x208,8); 0x1010,
   0x1800 -> None (gap); 0 -> (0,0x200); 0x1ff -> (0x1ff,1); 0x200, 0xffffffff -> None; sec0 VS 0 -> 0x1100 -> (0x300,0x100);
   sec1 VA 0x1000 -> 0x1000 -> (0x200,0x10) (first wins).
4. Agreement (PT64, PT32): for every rva in [0, SizeOfImage): img = pe_image(pe), a = sa(ImageBase + rva); if
   img.memory.segment_at(a) is None then rva_to_file is None; else r = file_range_for(a, 1): rva_to_file is None iff
   r.size == 0, and when not None its start == r.start.
5. I1: build_pe(ndirs=1); dir1 VA 0; dir1 size 0 -> ((), ()), no read after parse_pe.
6. I2: dir1 VA 0x2400 and 0x1800 -> ParseError "import directory not in file" @0xd0; PeParser -> note "pe imports not
   parsed: import directory not in file at offset 0xd0"; certificate, overlay and signature findings still present.
7. I3: dir1 size 0x28 -> 2 DLLs; 0x14 -> 1; 0x13 -> 0, no descriptor read; dir1 VA 0x21F0 (run 16 B) -> 0, no read. L7: n =
   1000 -> 256 DLLs + note "pe imports truncated at 256 DLLs", descriptor read (0x400, 5140); 256 + null and 257 + null
   (dir1 size 20(n+1)) -> no note / note.
8. I4 DLL name, parametrized name RVA: 0x2400 (tail), 0x1800 (gap), 0xFFFFFFFF -> name None, functions still parsed; 0x100
   (headers, zeros) -> b"". Content: 300 x b"D" -> 256 bytes, name_truncated; 256 x b"D" + NUL -> not truncated;
   b'\xff\x01"\\' -> JSON "dll" == "\\xff\\x01\\x22\\x5c".
9. I5: desc1 IAT 0 (ILT 0) -> (), UNMAPPED; desc0 ILT 0x2400 -> (), UNMAPPED (IAT not consulted); desc1 IAT 0x21FC -> (),
   DATA_END.
10. I6 ordinals: PE32+ 0xC000000000FF0010 -> ordinal 16; PE32 0xFFFF0010 -> 16; PE32 0x800020E0 -> ordinal 0x20E0; PE32+
    0x800020E0 and 0x1000020E0 -> UNMAPPED.
11. I6 hint/name: RVA 0x2400, 0x1800 -> DLL0 (), UNMAPPED; 0x100 -> {hint 0, name b""}; 0x21FF -> DATA_END; 300 x b"B" ->
    256 bytes truncated; 14 non-NUL bytes up to the section end (RVA 0x21F0) -> 14 bytes, truncated.
12. I6: desc1 IAT 0x21F8 holding 0x20F0 -> [MessageBoxA], DATA_END.
13. L13 per-DLL cap: 513 non-zero thunks to "f" -> 512 functions, CAP, thunk read (0x800, 4104); 512 + 0 -> NULL.
14. L13 global count: 33 descriptors sharing a 512 + null ILT -> DLLs 0-31 have 512, DLL 32 (), CAP, its name still read.
15. L13 name budgets (thunks to the 256-byte entry): one DLL -> 48 functions, CAP; 23 DLLs -> 21 x 48, DLL 21 has 16, DLL 22
    (), CAP.
16. ShrinkingSource(PT64, cut=0x400, honest_reads=7) -> InputChanged @0x400 from parse_imports and PeParser().parse.
17. VOs: ImportedFunction with ordinal and name, with neither, ordinal 0x10000, hint -1, name 257 B, name_truncated without
    name -> ParseError; ImportedDll with 513 functions or 12289 name bytes -> ParseError; `replace(PeFile)` with 257 DLLs,
    16385 functions, 262145 name bytes or 17 certificates -> "PE table counts inconsistent"; OverlayInfo whose sizes do not
    sum, or trailing_size > 0 without a certificate -> ParseError.
`tests/formats/test_pe_overlay.py`:
18. overlay_info(PT64) == OverlayInfo(Address(0x600), 0x20020, ByteRange(0x20600, 16), 0x20000, 16, (SignatureMatch("7z",
    Address(0x600)), SignatureMatch("zip-local", Address(0x20610)))); calls after the certificate read (0x20600, 8):
    [(0x600,64),(0x20610,16),(0x30,4)].
19. O1: P64 -> None, no read; sections raw 0 (0x158, 0x180) -> offset 0x200, size 0x400; plus SizeOfHeaders 0 (0x94) ->
    offset 0x198 (section_table_end), size 0x468.
20. O2: P64 + 16-byte cert, dir4 (0x600, 16) -> size 16, payload 0, trailing 0, calls only (0x30, 4); dir4 (0x400, 16) with
    a valid entry in .data -> certificate None, payload = size; dir4 past EOF -> certificate None + cert note.
21. Mid-overlay cert: P64 + 0x100 payload + 16-byte cert + 100 trailing bytes (b"7z\xbc\xaf\x27\x1c" first) -> payload
    0x100, trailing 100, match ("7z", cert.end); probe (cert.end, 64), no other read of the trailing bytes.
22. real_shape: offset 867840, size 138953784, certificate (139811888, 9736), payload 138944048, trailing 0; reads at
    offsets >= 867840 are exactly (867840, 64) and (139811888, 8); certificates (Address(139811888), 9729, 0x200, 2).
23. ShrinkingSource(PT64, cut=0x20600, honest_reads=14) -> InputChanged @0x20600 (dir-4 header read);
    ShrinkingSource(PT64, cut=0x610, honest_reads=15) -> InputChanged @0x600 (overlay probe); both via PeParser().parse.
24. Parametrized over WINDOW rows: P64 + 64-byte overlay with rule.magic at rule.at -> exactly (SignatureMatch(rule.name,
    Address(0x600)),); P64 + 64 zero bytes -> ().
25. inno-loader: P64 + 64-byte overlay, b"Inno" at 0x30 -> (inno-loader, 0x30); same without overlay -> None, no probe.
26. Overlay b"7z\xbc" -> no match, probe (0x600, 3); PT64 without the PK tail -> trailing 0, no probe at cert.end.
27. SIGNATURES: unique names matching [a-z0-9-]{1,32}; every len(magic) >= 3; at + len(magic) <= 64; SignatureRule with a
    2-byte magic, or at 61 with a 4-byte magic -> ParseError.
`tests/formats/test_pe_certificates.py`:
28. PT64 -> (CertificateEntry(Address(0x20600), 12, 0x200, 2),), notes (); P64 -> ((), ()); dir4 (0x600, 0) and (0, 16) ->
    ((), ()), no read.
29. Rounding: entries dwLength 9 then 8 appended to P64, Size 24 -> offsets 0x600, 0x610; Size 17 -> C4 'certificate header exceeds table' @0x610; Size 12 -> C7 @0xe8.
30. C2 (VA + Size = size + 1; 0xFFFFFFFF/0xFFFFFFFF) @0xe8; C4 Size 4 @VA; C5 dwLength 7 and 0 @VA; C6 0xFFFFFFFF @VA; a
    failing second entry @its offset.
31. C3: 17 entries of 8 bytes (Size 136) -> 16 + note "pe certificates truncated at 16 entries"; 16 entries -> no note.
`tests/formats/test_pe_facts.py` (append):
32. PeParser(PT64) findings == G5 findings (own loader), every `pe.signature` provenance parsed; notes (NOT_PARSED_NOTE,).
33. PT64 + dir1 VA 0x1800 + cert dwLength 7 + AEP 0x5000 -> notes (imports note, "pe certificates not parsed: certificate
    length below header size at offset 0x20600", ENTRY_OUTSIDE_NOTE, NOT_PARSED_NOTE); overlay finding present.
34. "dll_truncated" / "name_truncated" keys present only when truncated; DLL name None -> "dll": null.
35. attach_tables(P64) -> G4's DLL; calls after parse_pe == [(0x400,40),(0,257)].
`tests/reporting/test_pe_budget.py` (append):
36. 3 + MAX_SECTIONS + MAX_IMPORT_DLLS + MAX_CERTS + 1 + MAX_SIGNATURE_MATCHES <= MAX_FINDINGS.
37. L39 -> render_json(FormatsFactSource(MemorySource(data)).collect()) succeeds; DLLs 0-20 have 512 functions, DLL 21 has
    170, 22-255 () CAP; 261 findings. 38. L39 with 512 ordinal thunks -> DLLs 0-31 have 512, 32-255 () CAP; renders.
39. One DLL of 48 truncated 256-byte b"\xff" names + 464 empty names + 256-byte b"\xff" DLL name -> its pe.import value
    passes `check_json_value`.
`test_cli.py`: 40. `info P64 --json` == G4 (comment: the "MZ" import is deliberate, see ## CLI). 41. `info PT64 --json` ==
G5. 42. `info PT64` lines[3:] == `_P64_TEXT`. 43. G1-G3 pass with their test code unchanged.
Existing-test edits (only these): "3" -> "4" at test_facts.py:38, test_pe_facts.py:193, test_elf_facts.py:123;
test_pe_facts.py:85-86 and :119 build the expected side from `attach_tables(source, parse_pe(source))[0]`;
test_pe_facts.py:125 `3 + 64` -> `3 + 64 + 1` (the 0x11 descriptor); test_pe_facts.py:128-134: notes gain "pe imports not
parsed: import directory not in file at offset 0xd0" between the two, findings 5 -> 6 (overlay [0x198, 0x600): no raw data,
SizeOfHeaders 0, start = section_table_end); test_pe_budget.py:20 99 -> 100; test_cli.py `_P64_TEXT` note line.

## Evidence
- Microsoft "PE Format", learn.microsoft.com (ms.date 2026-09-10), researcher 2026-10-13: Import Directory Table, Import
  Lookup Table, Hint/Name Table, Import Address Table, Attribute Certificate Table, Section Table; Delay-Load (out of scope).
- Relayed by the orchestrator 2026-10-13: innoextract offsets.cpp / version.cpp / chunk.cpp; ip7z/7zip DOC/7zFormat.txt;
  PKWARE APPNOTE 4.3.7; RFC 1952 §2.3.1; nsis fileform.h; upx header.S/conf.h (UPX omitted).
- Planner scratch runs 2026-10-13: G1-G3 v4 hashes, PT64/PT32 sha256, worst-case sizes, real-shape arithmetic.

## Risks
R1 Overlay start convention unverified; PointerToRawData rounding not modelled; COFF symbols/debug data count as overlay.
R2 Zero-filled-tail RVAs are UNMAPPED although a loader reads zeros there (NULL); a reporting difference only (decision).
R3 A descriptor table ending at Size or run end without a terminator is accepted silently; understated Sizes lose DLLs
(assumption; F-ANOM-PE could note it). R4 ILT 0 -> IAT is a convention; bound IAT + ILT 0 -> UNMAPPED (F-BOUND).
R5 Names over 256 B are truncated; global budgets hide functions in huge tables (flagged by `end: "cap"`).
R6 C7 is strict (Size must equal the rounded sum); non-conforming signers lose certificate facts behind a note; the overlay
still uses the dir-4 range (decision: strict, per src).
R7 Signature false positives ~2^-24 or less per probe (>= 3 fixed bytes at fixed offsets); all stay unverified.
R8 Only one 64-byte window at the payload start and one after the certificate; installers with offset-table-addressed data
are found via F-INNO-RESOURCE / F-OVERLAY-SCAN. R9 Stage bump changes G1-G3 hashes by design.
R10 Directory "present" = VA != 0 and Size != 0 (assumption); a loader may ignore Size for dir 1.

## Acceptance
1. `make check` passes; lint-imports contract count equals HEAD's with 0 broken; archcheck prints `archcheck: ok`.
2. Tests 1-43 exist and pass; existing-test edits limited to the list above (`git diff tests/formats tests/reporting
   tests/interface`).
3. `git diff tests/fixtures/reporting`: G1-G3 show only `"version": "4"` and the ## CLI hashes; G4 shows only version, stage
   sha, note text and the one `pe.import` finding; `pe64_tables.json` exists, `jq empty` passes, input sha256 606bed24...;
   all files < 64 KiB. G4/G5 stage sha256 are produced by the implementer from the recipes and recomputed by the reviewer
   (`uv run retool info <fixture> --json`); they are not given in this spec.
4. `git diff --quiet src/retool/interface src/retool/shared src/retool/reporting src/retool/formats/__init__.py
   src/retool/formats/application/dto.py src/retool/formats/domain/parsing.py` succeeds.
5. `grep -cE "^(MAX_IMPORT_DLLS|MAX_IMPORT_FUNCS|MAX_IMPORT_NAME|IMPORT_DLL_NAME_BYTES|MAX_IMPORT_FUNCS_TOTAL|IMPORT_TOTAL_
   NAME_BYTES|MAX_CERTS|SIGNATURE_WINDOW|MAX_SIGNATURE_MATCHES):" src/retool/formats/domain/pe.py` prints 9;
   `grep -rnE "entropy|shannon" src/retool` prints nothing.
6. `grep -rln "import struct" src/retool` prints exactly `elf.py`, `pe.py`, `pe_imports.py`, `pe_certificates.py` under
   `src/retool/formats/domain/`; `grep -rn "except ParseError" src/retool/formats/application` prints nothing;
   `grep -n "except InputChanged" src/retool/formats/domain/pe_parser.py` prints >= 1 line.
7. `grep -n 'STAGE_VERSION: Final = "4"' src/retool/formats/application/use_cases.py` prints 1 line; `git diff --stat`
   lists only paths named in ## Architecture, ## Tests and the golden files.
8. Manual (orchestrator, not a test): `info <real sample> --json` -> overlay offset 867840, certificate {139811888, 9736},
   payload_size 138944048, trailing_size 0; >= 1 pe.import; one pe.certificate.
