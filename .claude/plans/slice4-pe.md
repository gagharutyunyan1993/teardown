# Slice 4: PE structural parser (`formats`) -> `Image`, findings, `retool info` text + JSON

Goal: parse PE32/PE32+ from hostile input (DOS header -> `e_lfanew` -> `PE\0\0` -> COFF header -> optional header -> data
directories -> section table) into a `formats` domain model; project headers + sections onto `Image`; report everything as
`formats`-built findings; plus two slice-3 follow-ups (elf_facts split, F-EXPORT). Repo facts verified at 372f60c.
`architect review required`: second `FormatParser` strategy in the registry, public API growth (`InputChanged`), shared
helpers moved into `parsing.py`. No new context, port or aggregate; no `/decide`. Revision 2 applies round 1 (architect S1-S5,
reviewer 1-11).

## Scope
In: DOS header, signature, COFF file header, optional header (PE32, PE32+), data directory table (raw RVA/size only), section
table (8-byte names), headers + sections -> `Image`, findings, notes, `retool info` text, JSON via findings (schema_version 1).
Policy (as slice 3 R1): a malformed PE is reported, not failed: exit 0, magic finding kept, note `pe structure rejected: <reason>
at offset 0x..`. Only `InputChanged` fails the command (exit 1, `error:` on stderr, empty stdout).
Out (named follow-ups): F-PE-IMP imports/IAT/delay imports; F-PE-EXP exports; F-PE-REL base relocations; F-PE-RES resources;
F-PE-CERT certificates (dir 4 is a file offset); F-PE-CLR; F-PE-SYM COFF symbols + string-table names (`/NNN`); F-PE-DBG
debug/TLS/load config; F-ANOM-PE anomaly findings (alignment rules, SizeOfImage, header/section overlap in file, Win32Version/
LoaderFlags != 0, NumberOfSymbols != 0 in an image, section order); F-ARCH (shared with ELF); F-SEGCAP `/decide` on
MAX_SEGMENTS when an in-scope sample loses its image to the 64-segment cap.

## Architecture
Conforms to ARCH §2 (`formats`: "structural parsing of ELF, PE"), §3 (domain = stdlib + `shared` + own domain), §4 (strategy
`PeParser` behind `FormatParser`, factory `parser_for`, `check_within` before every read, capped counts, file offsets as
`Address`, `ParseError` with offset), §5 (domain unit tests, use-case test on `MemorySource`, CLI smoke). ADR 0001:74 (every
structured parser produces `Image`); ADR 0002 (`formats` authors its findings; reporting adapter only maps). archcheck A1-A7 hold:
no new cross-context or third-party import, domain dataclasses frozen, no `Any`, interface untouched.

| Module | Context / layer | Pattern (ARCH §4) |
|---|---|---|
| `formats/domain/pe.py` (new) | formats / domain | constants, private layouts, VOs `DosHeader`, `CoffHeader`, `OptionalHeader`, `DataDirectory`, `PeSection`, `PeFile`; pure `parse_pe` over port `ByteSource`; `pe_section_kind` |
| `formats/domain/pe_image.py` (new) | formats / domain | pure services `pe_arch`, `section_mem_size`, `pe_image` |
| `formats/domain/pe_facts.py` (new) | formats / domain | pure `pe_facts` |
| `formats/domain/pe_parser.py` (new) | formats / domain | strategy `PeParser` (reuses `guarded_parse`, `ParsedContainer`, `SectionSummary`) |
| `formats/domain/elf_facts.py` (new) | formats / domain | `elf_facts` + its two notes, moved verbatim from `facts.py` |
| `formats/domain/facts.py` | formats / domain | keeps `magic_finding`, `format_facts`; `_parsed` -> public `parsed_finding`; no ELF import left |
| `formats/domain/parsing.py` | formats / domain | + neutral helpers `read_exact` (body of elf.py:181-186) and `display_name` (from elf.py, body unchanged) |
| `formats/domain/elf.py` | formats / domain | deletes `_read` and `display_name`; imports `read_exact` from `parsing` |
| `formats/application/registry.py` | formats / application | factory: `case Format.PE: return PeParser()` |
| `formats/application/use_cases.py` | formats / application | `InspectFile.STAGE_VERSION = "3"`; nothing else |
| `formats/__init__.py`; `reporting/infrastructure/formats_facts.py` | public API; reporting / infrastructure | export `InputChanged`; adapter raises it (F-EXPORT) |
Unchanged: `interface/cli/main.py` (already prints `FileInfo` arch/entry/segments/sections/notes generically), `dto.py`,
`image.py`, `format_facts` code (generic; PE no longer reaches it because `parser_for(Format.PE)` is not None).
ADR 0001: trigger 5 does not fire (every PE section is expressible as `MappedSegment`); check 6 rejects > 63 mapped sections
by design (R1, F-SEGCAP). Slice-2 version policy: facts for an `MZ` input change -> stage version "3"; no JSON key/type/meaning
change -> schema_version stays 1.

## Interfaces
```python
# domain/parsing.py (additions)
def read_exact(source: ByteSource, limit: int, offset: int, size: int) -> bytes: ...
    # ByteRange(offset, size).check_within(limit); source.read; len != size -> InputChanged(offset=offset)
def display_name(raw: bytes) -> str: ...   # moved from elf.py unchanged
# domain/pe.py   (all VOs @dataclass(frozen=True, slots=True); ints are raw field values)
MAX_SECTIONS: Final = 96; MAX_DIRS: Final = 16
PE32_MAGIC: Final = 0x10B; PE32PLUS_MAGIC: Final = 0x20B; ROM_MAGIC: Final = 0x107
SCN_CNT_CODE: Final = 0x20; SCN_CNT_INITIALIZED_DATA: Final = 0x40; SCN_CNT_UNINITIALIZED_DATA: Final = 0x80
class DosHeader: e_magic: int; e_lfanew: Address
class CoffHeader: machine: int; number_of_sections: int; time_date_stamp: int; pointer_to_symbol_table: Address
    number_of_symbols: int; size_of_optional_header: int; characteristics: int
class OptionalHeader: magic: int; major_linker_version: int; minor_linker_version: int; size_of_code: int
    size_of_initialized_data: int; size_of_uninitialized_data: int; address_of_entry_point: int; base_of_code: int
    base_of_data: int | None   # None for PE32+
    image_base: int; section_alignment: int; file_alignment: int; major_os_version: int; minor_os_version: int
    major_image_version: int; minor_image_version: int; major_subsystem_version: int; minor_subsystem_version: int
    win32_version_value: int; size_of_image: int; size_of_headers: int; checksum: int; subsystem: int
    dll_characteristics: int; size_of_stack_reserve: int; size_of_stack_commit: int; size_of_heap_reserve: int
    size_of_heap_commit: int; loader_flags: int; number_of_rva_and_sizes: int     # declared value, unclamped
    @property
    def bits(self) -> int: ...          # 64 if magic == PE32PLUS_MAGIC else 32
class DataDirectory: virtual_address: int; size: int     # index = position in PeFile.directories
class PeSection: name: bytes; virtual_size: int; virtual_address: int; size_of_raw_data: int
    pointer_to_raw_data: Address; pointer_to_relocations: Address; pointer_to_linenumbers: Address
    number_of_relocations: int; number_of_linenumbers: int; characteristics: int   # name = bytes before first NUL, <= 8
class PeFile: dos: DosHeader; coff: CoffHeader; optional: OptionalHeader; directories: tuple[DataDirectory, ...]
    sections: tuple[PeSection, ...]
    # post_init: len(sections) == coff.number_of_sections <= MAX_SECTIONS and
    #   len(directories) == min(optional.number_of_rva_and_sizes, MAX_DIRS), else ParseError("PE table counts inconsistent")
def parse_pe(source: ByteSource) -> PeFile: ...         # ParseError (P1-P17) or InputChanged (P18)
def pe_section_kind(characteristics: int) -> str: ...   # 0x20 "code" > 0x40 "data" > 0x80 "bss" > else "other"
                                                        # (assumption: display-only precedence)
# domain/pe_image.py
def pe_arch(coff: CoffHeader) -> ArchitectureId: ...    # provisional: 0x14c x86, 0x8664 x86_64, 0x1c0 arm, 0x1c4 arm,
    # 0xaa64 aarch64, 0x200 ia64, 0x6232 loongarch32, 0x6264 loongarch64; else f"pe-machine-{machine}" (decimal)
def section_mem_size(section: PeSection) -> int: ...    # virtual_size, or size_of_raw_data if virtual_size == 0
def pe_image(pe: PeFile) -> Image | None: ...           # None if nothing maps; MemoryMap/SpaceAddress ParseError propagates
# domain/pe_facts.py
ENTRY_OUTSIDE_NOTE = "pe entry point outside every mapped section"
STRING_TABLE_NOTE = "pe section names referencing the COFF string table not resolved"
NOT_PARSED_NOTE = ("pe imports, exports, relocations, resources, certificates, debug data, CLR metadata and COFF symbols "
                   "not parsed in this version")
def pe_facts(pe: PeFile, image: Image | None, producer: str) -> tuple[tuple[Finding, ...], tuple[NotAnalysed, ...]]: ...
# domain/pe_parser.py
class PeParser:   # satisfies FormatParser; stateless; parse = guarded_parse(Format.PE, _build_pe, source, producer)
    def parse(self, source: ByteSource, producer: str) -> ParsedContainer: ...
# domain/facts.py
def parsed_finding(subject: str, value: JsonValue, producer: str) -> Finding: ...  # PARSED, unverified (ex-_parsed)
```
Types: RVAs are image-relative and sizes are counts, so they stay int (as does `image_base`); file offsets are `Address`.
`_build_pe` mirrors `_build_elf`: `parse_pe`; `pe_image` `ParseError` -> image None + `f"pe memory image not built: {exc}"`;
None -> `"pe memory image not built: no headers or sections to map"`; not_analysed = that note + `pe_facts` notes; arch =
`pe_arch(pe.coff)`; sections = `SectionSummary(i, display_name(s.name), pe_section_kind(s.characteristics),
optional.image_base + s.virtual_address, s.pointer_to_raw_data.value, section_mem_size(s))`. `addr` is the unbounded sum as
computed, never clamped, also when no image is built (CLI prints it in hex, e.g. `addr=0x10000000000000000`).
`pe_facts` findings, in order: `magic_finding(Format.PE)`; `"pe.header"` `{"e_lfanew", "machine", "arch": str(pe_arch),
"number_of_sections", "time_date_stamp", "pointer_to_symbol_table", "number_of_symbols", "size_of_optional_header",
"characteristics"}`; `"pe.optional"` = every `OptionalHeader` field under its own name (`base_of_data` only when not None) +
`"format": "pe32"|"pe32+"` + `"data_directories": [{"index", "virtual_address", "size"}, ...]`; one `"pe.section"` per section
`{"index", "name": display_name, "virtual_size", "virtual_address", "size_of_raw_data", "pointer_to_raw_data",
"pointer_to_relocations", "pointer_to_linenumbers", "number_of_relocations", "number_of_linenumbers", "characteristics"}`.
Notes in order: ENTRY_OUTSIDE (image exists, entry RVA != 0, image.entry None); STRING_TABLE (any name where
`re.fullmatch(rb"/[0-9]+", name)`, rendered literally); NOT_PARSED always.

## Binary layout
All little-endian (`"<"`), `unpack_from(buf, 0)` on exactly calcsize bytes (sizes checked in a scratch run). L = e_lfanew,
C = L+4, O = L+24, F = 96 (PE32) | 112 (PE32+), T = O + SizeOfOptionalHeader, E_i = T + 40*i.
- DOS `"<H58xI"` (64): e_magic @0 (0x5A4D "MZ"), e_lfanew @0x3c (u32; winnt.h LONG, unverified) (src: PE, MS-DOS Stub).
- Signature: 4 bytes at L == `b"PE\0\0"` (src: PE, Signature).
- COFF `"<HHIIIHH"` (20) at C: Machine @0, NumberOfSections @2, TimeDateStamp @4, PointerToSymbolTable @8, NumberOfSymbols
  @12, SizeOfOptionalHeader @16, Characteristics @18 (src: PE, COFF File Header).
- Magic `"<H"` at O, read and validated before the layout (src: PE, Optional Header).
- PE32 `"<HBB9I6H4I2H6I"` (96): Magic 0, LinkerMaj 2, LinkerMin 3, SizeOfCode 4, InitData 8, UninitData 12, AddressOfEntryPoint
  16, BaseOfCode 20, BaseOfData 24, ImageBase 28, SectionAlignment 32, FileAlignment 36, OS 40/42, Image 44/46, Subsystem ver
  48/50, Win32VersionValue 52, SizeOfImage 56, SizeOfHeaders 60, CheckSum 64, Subsystem 68, DllCharacteristics 70, StackRes 72,
  StackCommit 76, HeapRes 80, HeapCommit 84, LoaderFlags 88, NumberOfRvaAndSizes 92.
- PE32+ `"<HBB5IQ2I6H4I2H4Q2I"` (112): as PE32 to 20, no BaseOfData, ImageBase 24 (u64), 32..71 as PE32, StackRes 72, StackCommit
  80, HeapRes 88, HeapCommit 96 (u64 each), LoaderFlags 104, NumberOfRvaAndSizes 108 (src: PE, Optional Header fields).
- Directories `"<II"` (8) x n at O+F: (VirtualAddress, Size); n = min(NumberOfRvaAndSizes, 16) (src: PE, Data Directories).
- Section `"<8sIIIIIIHHI"` (40) at E_i: Name 0, VirtualSize 8, VirtualAddress 12, SizeOfRawData 16, PointerToRawData 20,
  PointerToRelocations 24, PointerToLinenumbers 28, NumberOfRelocations 32, NumberOfLinenumbers 34, Characteristics 36; table
  located via SizeOfOptionalHeader, not via the struct size (src: PE, Section Table).
Reads (tested order), all through `parsing.read_exact(source, source.size, off, n)`: (0,64), (L,4), (C,20), (O,2), (O,F),
(O+F, 8n) if n > 0, (T, 40*NumberOfSections) if > 0. Raw section data is never read.
Name: `raw[:raw.find(b"\0")]` if a NUL exists, else all 8 bytes; bytes after the first NUL are ignored (assumption).

## Safety checks
Each raises `ParseError(reason, offset=...)` in this order; each precedes the read it guards. Python ints never wrap.
1. size < 64: "DOS header exceeds file" @0.   2. e_magic != 0x5A4D: "bad DOS magic" @0.
3. L < 64: "e_lfanew inside DOS header" @0x3c (assumption: overlapping NT headers rejected; R4).
4. L + 4 > size: "PE signature exceeds file" @0x3c.   5. signature != `PE\0\0`: "bad PE signature" @L.
6. C + 20 > size: "COFF header exceeds file" @C.
7. NumberOfSections > 96: "section count exceeds 96" @C+2 (src: PE, COFF File Header: loader limit 96). 0 is accepted.
8. O + 2 > size: "optional header exceeds file" @O.
9. Magic == 0x107: "ROM optional header not supported" @O.  10. Magic not 0x10b/0x20b: "invalid optional header magic" @O.
11. SizeOfOptionalHeader < F: "optional header smaller than its fixed part" @C+16 (F from src: PE, Optional Header field
    tables; rejecting is parser-side, assumption).
12. O + F > size: "optional header exceeds file" @O.
13. F + 8n > SizeOfOptionalHeader: "data directories exceed optional header" @O+92|108 (src: PE, validate probes against
    SizeOfOptionalHeader). NumberOfRvaAndSizes > 16 is clamped to 16 first (assumption; no stated max; R8).
14. O + F + 8n > size: "data directories exceed file" @O+F.
15. SizeOfHeaders > size: "SizeOfHeaders exceeds file" @O+60 (assumption, as slice-3 S20).
16. NumberOfSections > 0 and T + 40*NumberOfSections > size: "section table exceeds file" @T (location: src: PE, Section
    Table; bound: assumption, parser-side). With NumberOfSections 0, T past EOF is unchecked and harmless (nothing is read).
17. SizeOfRawData > 0 and PointerToRawData + SizeOfRawData > size: "section raw data exceeds file" @E_i (assumption: not
    stated by src; declared range, not the mapped part; SizeOfRawData 0 exempt, so BSS-only sections with any pointer pass).
18. short read: `InputChanged(offset=read offset)`; propagates through `PeParser` and `InspectFile`.
Not enforced (reported raw, F-ANOM-PE): FileAlignment power of two / 512..64K, SectionAlignment >= FileAlignment, SA < page =>
FA == SA, ImageBase multiple of 64K, SizeOfImage, Win32VersionValue/LoaderFlags 0, section order/adjacency, section table
inside SizeOfHeaders, Machine vs Magic consistency, e_lfanew alignment. Rationale: no alignment value is used for mapping.
`pe_image` (all (assumption) beyond src: PE, Section Table/Section Data): space `AddressSpace("ram", 32)` for PE32,
`DEFAULT_SPACE` for PE32+. Segment "headers" = `MappedSegment(ByteRange(0, SizeOfHeaders), sa(image_base),
SizeOfHeaders, "headers")` if SizeOfHeaders > 0 (unverified loader behaviour). Section i with m = `section_mem_size` > 0 and
k = min(SizeOfRawData, m): `MappedSegment(ByteRange(PointerToRawData, k) if k > 0 else ByteRange(0, 0),
sa(image_base + VirtualAddress), m, f"sec{i}")` - VirtualSize is the memory extent, raw beyond it is truncated, the tail beyond
SizeOfRawData is zero (src: PE, Section Table); no rounding to SectionAlignment; VirtualSize 0 falls back to SizeOfRawData
(reported loader behaviour, unverified); m == 0 maps nothing. Overlap (incl. headers vs sections), > 64 segments, > 4 GiB,
start or end beyond the space -> `MemoryMap`/`MappedSegment`/`SpaceAddress` `ParseError` -> "pe memory image not built: ...".
Unsorted sections are fine (MemoryMap sorts). Entry = `sa(image_base + AddressOfEntryPoint)` only if the RVA != 0 (src: PE,
Optional Header: 0 = no entry point, e.g. DLL), the sum <= space.max_offset and `segment_at` finds it, else None.

## Caps
- MAX_SECTIONS 96 = loader limit (src: PE, COFF File Header). Findings <= 3 + 96 = 99 << MAX_FINDINGS 4096 (reporting/domain/
  model.py:12). Names <= 8 bytes -> display <= 32 chars; pe.optional value <= ~100 JSON nodes << MAX_JSON_NODES 4096.
  Worst case (96 sections) ~100 findings x < 1.5 kB < 0.2 MB << MAX_REPORT_CHARS 8 MiB (arithmetic; test 48 checks).
- MAX_DIRS 16 (src: PE, Data Directories: 16 defined entries); clamp per check 13.
- MAX_OPTHDR: no constant needed. SizeOfOptionalHeader is a u16 used only as an offset to T; the parser reads at most
  F + 8*16 = 240 bytes of the optional header; no allocation depends on an unchecked length.
- Section table read <= 96*40 = 3840 bytes. MemoryMap MAX_SEGMENTS 64 (ADR 0001 check 6) limits images to 63 mapped sections
  + headers; more -> "image not built" (R1, F-SEGCAP).

## CLI
No code change. `retool info P64` stdout after `sha256:` exactly: `format: pe` / `arch:   x86_64` / `entry:  ram:0x140001000` /
`segment headers: ram:0x140000000 mem=0x200 file=0x0+0x200` / `segment sec0: ram:0x140001000 mem=0x10 file=0x200+0x10` /
`segment sec1: ram:0x140002000 mem=0x1000 file=0x400+0x200` / `section 0 ".text" code addr=0x140001000 off=0x200 size=0x10` /
`section 1 ".data" data addr=0x140002000 off=0x400 size=0x1000` / `note:   ` + NOT_PARSED_NOTE.
JSON: subjects `pe.header`, `pe.optional`, `pe.section`; schema_version 1; `formats.inspect` version "3". Golden =
`json.dumps(json.loads(LINE), indent=2, sort_keys=True) + "\n"` (slice-3 transform). All lines below come from a scratch run
with the real `render_json`/`stage_sha256` (which first reproduced every HEAD golden's v2 stage hash).
G1-G3 regeneration (slice-3 acceptance 3 recipe): run `info` as for each golden (G1 `b"\x7fELF"+b"\0"*60`; G2 `b"\0"*0x100`
with `--raw --arch armv7 --base 0x8000000`; G3 F64) with `--json`, or apply the transform to HEAD's file with `"version":
"3"` and the new stage hash: G1 `elf_magic.json` 8415b1f5831bf67935fcf65a929c6da0ce3a51fae2cec3c9e97e6b2ca663ac5c; G2
`raw_base.json` formats.inspect 9debe8d1056c03b65c288b30d754254eb4b88e81dda71d754bcccb4f4181caf4 (formats.raw unchanged); G3
`elf64_min.json` 80a9aa7b59ccdf94c108bb5faabe699cd3315b691eb3f71703db70e8d747edbb. Nothing else in G1-G3 changes.
G4 `pe64_min.json` (new, `info P64 --json`, 5566 bytes after the transform):
{"findings":[{"producer":"formats.inspect","provenance":"parsed","subject":"input","value":{"magic":"pe"},"verification":{"checks":[],"reason":"","status":"unverified"}},{"producer":"formats.inspect","provenance":"parsed","subject":"pe.header","value":{"arch":"x86_64","characteristics":34,"e_lfanew":64,"machine":34404,"number_of_sections":2,"number_of_symbols":0,"pointer_to_symbol_table":0,"size_of_optional_header":240,"time_date_stamp":1593835520},"verification":{"checks":[],"reason":"","status":"unverified"}},{"producer":"formats.inspect","provenance":"parsed","subject":"pe.optional","value":{"address_of_entry_point":4096,"base_of_code":4096,"checksum":12648430,"data_directories":[{"index":0,"size":0,"virtual_address":0},{"index":1,"size":40,"virtual_address":8192},{"index":2,"size":0,"virtual_address":0},{"index":3,"size":0,"virtual_address":0},{"index":4,"size":0,"virtual_address":0},{"index":5,"size":0,"virtual_address":0},{"index":6,"size":0,"virtual_address":0},{"index":7,"size":0,"virtual_address":0},{"index":8,"size":0,"virtual_address":0},{"index":9,"size":0,"virtual_address":0},{"index":10,"size":0,"virtual_address":0},{"index":11,"size":0,"virtual_address":0},{"index":12,"size":0,"virtual_address":0},{"index":13,"size":0,"virtual_address":0},{"index":14,"size":0,"virtual_address":0},{"index":15,"size":0,"virtual_address":0}],"dll_characteristics":33120,"file_alignment":512,"format":"pe32+","image_base":5368709120,"loader_flags":0,"magic":523,"major_image_version":2,"major_linker_version":14,"major_os_version":6,"major_subsystem_version":5,"minor_image_version":3,"minor_linker_version":36,"minor_os_version":1,"minor_subsystem_version":4,"number_of_rva_and_sizes":16,"section_alignment":4096,"size_of_code":512,"size_of_headers":512,"size_of_heap_commit":8192,"size_of_heap_reserve":524288,"size_of_image":12288,"size_of_initialized_data":512,"size_of_stack_commit":4096,"size_of_stack_reserve":1048576,"size_of_uninitialized_data":0,"subsystem":3,"win32_version_value":0},"verification":{"checks":[],"reason":"","status":"unverified"}},{"producer":"formats.inspect","provenance":"parsed","subject":"pe.section","value":{"characteristics":1610612768,"index":0,"name":".text","number_of_linenumbers":0,"number_of_relocations":0,"pointer_to_linenumbers":0,"pointer_to_raw_data":512,"pointer_to_relocations":0,"size_of_raw_data":512,"virtual_address":4096,"virtual_size":16},"verification":{"checks":[],"reason":"","status":"unverified"}},{"producer":"formats.inspect","provenance":"parsed","subject":"pe.section","value":{"characteristics":3221225536,"index":1,"name":".data","number_of_linenumbers":0,"number_of_relocations":0,"pointer_to_linenumbers":0,"pointer_to_raw_data":1024,"pointer_to_relocations":0,"size_of_raw_data":512,"virtual_address":8192,"virtual_size":4096},"verification":{"checks":[],"reason":"","status":"unverified"}}],"input":{"sha256":"29ccce7fc9b09c2b18ddedf628de35f255d7cb0a38afa340c44247335c9d9f76","size":1536},"not_analysed":[{"reason":"pe imports, exports, relocations, resources, certificates, debug data, CLR metadata and COFF symbols not parsed in this version","stage":"formats.inspect"}],"raw_image":null,"schema_version":1,"stages":[{"name":"formats.inspect","sha256":"7fdf857f1f389f331c0b25235ee798244b9736cc3de62a2982f427d093befe3e","version":"3"}]}

## Tests
`tests/formats/pe_build.py`: `build_pe(bits=64, *, extra_sections=0, opt_pad=0, ndirs=16) -> bytes`, `patch` from elf_build.
NumberOfSections = 2 + extra_sections; NumberOfRvaAndSizes = ndirs; opt = F + 8*ndirs + opt_pad (0xF0|0xE0 by default);
T = 0x58 + opt; hdr = align_up(T + 40*(2+extra), 0x200); text_rva = align_up(hdr, 0x1000); data_rva = text_rva + 0x1000;
size = hdr + 0x400; opt_pad zero bytes sit between the directories and T; extra entries are all zero, after the two real ones;
dir 1 is written only if ndirs > 1. Every byte not listed is 0; [hdr,+16) = 0x90; [hdr+0x200,+8) = 0x11.
P64 = `build_pe()` (0x600 B, sha256 = G4 input), P32 = `build_pe(32)` (0x600 B, sha256 d891318f2e0cb7071a3534d14cf122cc3be027d
25c0d25a1ea551fdf2d16a2b0). Values P64|P32: e_magic 0x5A4D; e_lfanew 0x40; sig @0x40; COFF @0x44: Machine 0x8664|0x14c,
sections 2, TimeDateStamp 0x5F000000, PtrSym 0, NumSym 0, SizeOfOptionalHeader 0xF0|0xE0, Characteristics 0x22|0x102.
Optional @0x58: Magic 0x20b|0x10b, linker 14.36, OS 6.1, Image 2.3, Subsystem 5.4, same in P64 and P32; SizeOfCode 0x200, InitData 0x200, UninitData 0, AEP = BaseOfCode = text_rva
(0x1000), BaseOfData -|data_rva (0x2000), ImageBase 0x140000000|0x400000, SA 0x1000, FA 0x200,
Win32VersionValue 0, SizeOfImage data_rva+0x1000 (0x3000), SizeOfHeaders hdr (0x200), CheckSum 0xC0FFEE, Subsystem
3, DllCharacteristics 0x8160|0x8140, StackRes 0x100000, StackCommit 0x1000, HeapRes 0x80000, HeapCommit 0x2000, LoaderFlags
0, NumberOfRvaAndSizes 16. Dirs @0xC8|0xB8: all (0,0) except index 1 = (data_rva, 0x28). Sections @T (0x148|0x138): ".text"
VS 0x10, VA text_rva, raw 0x200, ptr hdr, ch 0x60000020; ".data" VS 0x1000, VA data_rva, raw 0x200, ptr hdr+0x200, ch
0xC0000040. P64 patch offsets: lfanew 0x3c; NumberOfSections 0x46; SizeOfOptionalHeader 0x54; Magic 0x58; AEP 0x68;
ImageBase 0x70 (<Q); FA 0x7c; SizeOfHeaders 0x94; NumberOfRvaAndSizes 0xc4; sec0 name 0x148, VS 0x150, VA 0x154, raw 0x158,
ptr 0x15c; sec1 0x170 (VS 0x178, VA 0x17c, raw 0x180, ptr 0x184). P32: ImageBase 0x74, NumberOfRvaAndSizes 0xb4, sec0 @0x138
(VS 0x140), sec1 @0x160 (VS 0x168). "-> Pn @x" = that check's reason and `.offset == x`.
`tests/formats/test_pe_parse.py`:
1. P64 parses: every field above, 16 dirs, names (b".text", b".data"), base_of_data None, bits 64.
2. P32 parses: magic 0x10b, base_of_data 0x2000, image_base 0x400000, bits 32, sections from 0x138.
3. `MemorySource(P64).calls` == [(0,64),(0x40,4),(0x44,20),(0x58,2),(0x58,112),(0xc8,128),(0x148,80)].
4. Truncations: b"", P64[:63] -> P1 @0; [:0x43] -> P4 @0x3c; [:0x57] -> P6 @0x44; [:0x59] -> P8 @0x58; [:0xc7] -> P12 @0x58;
   [:0x100] -> P14 @0xc8; [:0x1ff] -> P15 @0x94; [:0x5ff] -> P17 @0x170.
5. P2: e_magic 0x4D5A -> @0. P3: e_lfanew in (0, 4, 0x3c, 0x3f) -> @0x3c. P4: e_lfanew 0x5fd and 0xffffffff -> @0x3c.
   P5: signature b"PE\0\1" -> @0x40; e_lfanew 0x200 -> @0x200.
6. Sections: extra_sections=94 (96, 0x1600 B) parses with 96 entries; extra_sections=95 -> P7 @0x46; p(0x46,0) parses, ().
7. P9: magic 0x107 -> @0x58. P10: magic 0, 0x10c -> @0x58.
8. P11: SizeOfOptionalHeader 0x6f and 0 -> @0x54; P32 with 0x5f -> @0x54. P13: 0xef -> @0xc4.
9. NumberOfRvaAndSizes: p(0xc4,0) -> no dirs, no dir read, sections intact from 0x148; 17 and 0xffffffff -> 16 dirs, declared
   value kept.
10. `build_pe(ndirs=0)`: SizeOfOptionalHeader == F (0x70), calls end (0x58,112),(0xc8,80); sections parse at T = 0xc8.
11. `build_pe(opt_pad=8)`: SizeOfOptionalHeader 0xf8, table read at 0x150, same sections (> struct size honoured).
12. P15: SizeOfHeaders 0x601 -> @0x94. P16: p(0x94,0x100) on P64[:0x190] -> @0x148; SizeOfOptionalHeader 0xffff -> @0x10057;
    the same with p(0x46,0) parses (T past EOF unchecked, nothing read).
13. P17: sec1 raw 0x201 -> @0x170; sec0 ptr 0xffffffff -> @0x148; BSS-only sec0 raw 0 + ptr 0xffffffff parses.
14. P18: `ShrinkingSource(P64, cut=0x148)` -> `InputChanged` @0x148 from `parse_pe` and from `PeParser().parse`.
15. Names: b"abcdefgh" (no NUL) -> 8 bytes; b".a\0junk\0" -> b".a"; all zero -> b"". `PeFile` with 1 section and
    number_of_sections 2 -> "PE table counts inconsistent".
16. `pe_section_kind`: 0x20, 0x60000020 -> "code"; 0x40 -> "data"; 0x80 -> "bss"; 0, 0x02000000 -> "other".
17. Alignment accepted: FA 0x300 parses; SA 0x100 < FA 0x200 parses (values reported raw).
18. `read_exact`: (source, 8, 4, 8) -> ParseError @4; `ShrinkingSource` short read -> InputChanged @offset.
`tests/formats/test_pe_image.py` (`sa`, `ram` from fakes; ram32 = AddressSpace("ram", 32)):
19. P64 -> `Image(ArchitectureId("x86_64"), MemoryMap((MappedSegment(ByteRange(0,0x200), sa(ram,0x140000000), 0x200,
    "headers"), MappedSegment(ByteRange(0x200,0x10), sa(ram,0x140001000), 0x10, "sec0"), MappedSegment(ByteRange(0x400,0x200),
    sa(ram,0x140002000), 0x1000, "sec1"))), sa(ram,0x140001000), Format.PE)` (covers raw > VirtualSize truncation and zero tail).
20. P32 -> arch "x86", ram32, same layout at 0x400000/0x401000/0x402000, entry 0x401000.
21. `pe_arch` for the 8 mapped machines; 0xa641 -> "pe-machine-42561"; 0 -> "pe-machine-0".
22. VirtualSize 0: p(0x150,0) -> sec0 mem 0x200 file (0x200,0x200); plus p(0x158,0) -> sec0 skipped.
23. BSS-only p(0x158,0)+p(0x15c,0) -> sec0 = MappedSegment(ByteRange(0,0), sa(ram,0x140001000), 0x10, "sec0"); with
    p(0x15c,0xffffffff) instead -> the same `ByteRange(0, 0)` (normalised).
24. Overlap: sec1 VA 0x1008 -> "segments overlap in space"; sec0 VA 0x100 (inside headers) -> same.
25. Unsorted (two entries swapped in-test) accepted: sec0 @0x140002000, sec1 @0x140001000.
26. Overflow: P64 ImageBase 2**64-0x1000 -> "address exceeds 64-bit space"; P32 ImageBase 0xfffff000 -> "address exceeds 32-bit
    space"; P32 sec1 VS 0xffffffff (ImageBase 0x400000) -> "segment exceeds address space"; P64 ImageBase 2**64-0x3000 builds
    (sec1 ends at 2**64) and AEP 0xffffffff -> entry None, no exception.
27. Mapped size: P64 sec0 VS 0x80000000, sec1 VA 0x80001000 + VS 0x80000000 (no overlap) -> "mapped size exceeds 4294967296
    bytes".
28. Entry: AEP 0 -> None; AEP 0x5000 -> None; AEP 0x10 -> sa(ram,0x140000010) (inside headers).
29. Segment count, in-test PeFile = `replace(parse_pe(P64), coff=replace(pe.coff, number_of_sections=n), sections=secs)` (both
    replaced together, else post_init raises): secs = n entries name b"", VS 0x10, VA 0x1000*(k+1), size_of_raw_data 0,
    pointer_to_raw_data Address(0), other fields 0. n = 63 -> 64 segments; n = 64 -> "segment count must be 1..64".
30. No map: SizeOfHeaders 0 + both sections VS 0 and raw 0 -> None.
`tests/formats/test_pe_facts.py`:
31. `pe_facts(parse_pe(P64), pe_image(...), "formats.inspect")` == G4 findings and notes (own JSON loader, as test_elf_facts).
32. P32: pe.optional has "format" "pe32" and "base_of_data" 0x2000; P64's has no "base_of_data" key.
33. `PeParser` on the fixtures of 24, 26 (its first three only; the `ImageBase 2**64-0x3000` case builds and
    expects no note), 27, 29(n=64) -> first note starts "pe memory image not built: "; 30 -> "...no headers
    or sections to map"; findings intact. 34. AEP 0x5000 -> notes (ENTRY_OUTSIDE_NOTE, NOT_PARSED_NOTE).
35. `PeParser` on test 26's first fixture: image None, `sections[0].addr == 2**64` (unclamped, no raise).
36. sec1 name b"/4" -> name "/4" in finding and summary; notes contain STRING_TABLE_NOTE before NOT_PARSED_NOTE; b"/4a" and
    b"/" -> no STRING_TABLE_NOTE (fullmatch).
37. Hostile name b'\xff\x01"\\abcd' -> "\\xff\\x01\\x22\\x5cabcd" in finding and SectionSummary.
38. `PeParser` on the 0x107 fixture -> findings (magic_finding(PE),), notes ("pe structure rejected: ROM optional header not
    supported at offset 0x58",); arch None, image None, sections ().
39. `parser_for(Format.PE)` is a `PeParser`. 40. `InspectFile(MemorySource(P64))`: stage_version "3", arch "x86_64", entry
    sa(ram,0x140001000), 3 SegmentInfo ("headers", "sec0", "sec1"), sections[0] == SectionSummary(0, ".text", "code",
    0x140001000, 0x200, 0x10).
`tests/interface/test_cli.py` (append): 41. `info P64` exit 0, lines per `## CLI`. 42. `info P64 --json` == `pe64_min.json`.
43. `info` on the 0x107 fixture: exit 0, note line of test 38. 44. G1/G2/G3 golden tests pass with their code unchanged.
45. `info` on test 35's fixture: exit 0, stdout contains `section 0 ".text" code addr=0x10000000000000000`.
`tests/reporting/test_formats_facts.py`: 46. F-EXPORT (below). `retool.formats`: 47. `"InputChanged" in __all__`.
`tests/reporting/test_pe_budget.py`: 48. `MAX_SECTIONS + 3 <= MAX_FINDINGS`; `build_pe(extra_sections=94)` with all 96 names
patched to b"\xff"*8: `render_json(FormatsFactSource(MemorySource(...)).collect())` does not raise, 99 findings.

## Follow-ups applied
- One commit, in this order inside it: (1) split `elf_facts`, `ENTRY_OUTSIDE_NOTE`, `NOT_PARSED_NOTE` verbatim to
  `formats/domain/elf_facts.py` (using `parsed_finding`), so `facts.py` drops its `elf` import; (2) move `display_name` and
  `_read` (as `read_exact`) to `parsing.py`, delete both from `elf.py`, which imports `read_exact` from `parsing` (no cycle:
  `parsing` -> `facts` no longer reaches `elf`). Importers: `elf_parser.py`, `elf_facts.py`, `tests/formats/test_elf_facts.py:13`
  (elf_facts), `tests/formats/test_elf_parse.py:12` (display_name). `parsing.py` docstring -> "Format-neutral parsing
  contract, its result, the error guard and shared read/name helpers." No behaviour change; no test patches `_read` (grep
  of tests 2026-10-12: only test names contain `_read`).
- F-EXPORT: `retool/formats/__init__.py` imports `InputChanged` from `domain.model` and adds `"InputChanged"` to `__all__`;
  `reporting/infrastructure/formats_facts.py:30` `raise ParseError("input changed during read")` -> `raise InputChanged()`
  (import from `retool.formats`; drop the unused `ParseError` import). In `test_input_changed_during_read` only the
  `pytest.raises` target changes, to `InputChanged` imported from `retool.formats`.
- Existing test edits (only these): `test_facts.py:38` and `test_elf_facts.py:123` "2" -> "3"; `test_elf_facts.py:117`
  loop drops `Format.PE`; `test_facts.py:9` parametrization drops `Format.PE` (ELF, MACHO stay); the imports above; F-EXPORT.

## Import-linter
None. All new modules are inside `formats` layers already covered by `layers-formats`, `no-infra-in-core`,
`no-interface-from-contexts`, `no-assist-in-deterministic`; the reporting adapter keeps importing only `retool.formats`.
Expect the same `Contracts: N kept, 0 broken.` as at HEAD.

## Evidence
- Microsoft, "PE Format", https://learn.microsoft.com/en-us/windows/win32/debug/pe-format (live page, undated), fetched by the
  researcher 2026-10-12; the planner re-fetched it 2026-10-12 (HTTP 200, 281,747 B) but did not re-grep (turn limit).
  Cited as (src: PE, <section>): MS-DOS Stub, Signature, COFF File Header (96-section limit), Machine Types, Characteristics,
  Optional Header (magic first; field offsets; entry RVA 0 = none; SA >= FA; FA "should be" pow2 512..64K), Data Directories
  (16; check NumberOfRvaAndSizes and SizeOfOptionalHeader), Section Table (location; fields; VirtualSize/zero pad; "/NNN";
  images use no string table), Section Flags, Section Data.
- Unverified: `MZ` and `e_lfanew` as LONG (winnt.h); directory names 13-15; headers mapped at ImageBase; VirtualSize 0 ->
  SizeOfRawData fallback; loader behaviour for raw past EOF, overlaps, NumberOfRvaAndSizes > 16, e_lfanew < 0x40.
- Scratch runs (2026-10-12): calcsize of all six struct strings; P64/P32/extra fixtures; G1-G4 stage hashes and G4 line.

## Risks
R1 ADR 0001 trigger 5 does not fire (sections expressible); check 6 rejects > 63 mapped sections by design -> no image for
such PEs; F-SEGCAP tracks the `/decide` (accepted by the orchestrator, recorded in DECISIONS.md). R2 Mapping choices
(VirtualSize as extent without SectionAlignment rounding, raw truncated to it, VS 0 fallback, headers segment) are
(assumption); disasm may see "address not mapped" in the alignment slack. R3 Checks 15/17 reject truncated or carved PEs (as
slice-3 R2). R4 Check 3 rejects golfed PEs with e_lfanew < 0x40. R5 Windows' rounding of PointerToRawData down to
FileAlignment/512 is not modelled. R6 Arch names provisional (F-ARCH); ARM64EC/ARM64X unmapped. R7 SectionSummary.addr may
exceed 64 bits (display only). R8 Clamping NumberOfRvaAndSizes to 16 hides declared extra entries (value still reported).
R9 Stage bump changes G1-G3 hashes by design.
Open (orchestrator): O2 confirm check 3 (reject e_lfanew < 0x40) vs accepting overlap. O3 confirm alignment rules are
reported, not enforced. (O1 closed: accept, F-SEGCAP.)

## Acceptance
1. `make check` passes; lint-imports contract count equals HEAD's with 0 broken; archcheck prints `archcheck: ok`.
2. Tests 1-48 exist and pass; existing-test edits limited to `## Follow-ups applied` (`git diff tests/formats tests/reporting`).
3. `git diff tests/fixtures/reporting` for G1-G3 shows only `"version": "3"` and the formats.inspect `sha256` values in `## CLI`;
   `pe64_min.json` equals the G4 line under the transform (5566 bytes), passes `jq empty`; all four files < 64 KiB.
4. `grep -rln "import struct" src/retool` prints exactly `elf.py` and `pe.py` under `src/retool/formats/domain/`;
   `git diff --quiet src/retool/interface` succeeds.
5. `grep -nE "MAX_SECTIONS: Final = 96|MAX_DIRS: Final = 16" src/retool/formats/domain/pe.py` prints 2 lines;
   `grep -rn "def elf_facts" src/retool` prints only `elf_facts.py`; `grep -n "import" src/retool/formats/domain/facts.py`
   shows no `elf`; `grep -nE "domain\.elf" src/retool/formats/domain/pe*.py` prints nothing; `grep -rn "except ParseError"
   src/retool/formats/application` prints nothing.
6. `grep -rn "def _read" src/retool/formats` prints nothing; `grep -rn "def read_exact\|def display_name"
   src/retool/formats` prints only `parsing.py` lines; `grep -rnE "\b_read\(|elf\._read" tests` prints nothing.
7. `retool.formats.__all__` == HEAD list + `"InputChanged"`; `grep -rn 'ParseError("input changed' src/retool/reporting`
   prints nothing; `git diff --stat` lists only paths named in `## Architecture`, `## Tests` and `## Follow-ups applied`.
