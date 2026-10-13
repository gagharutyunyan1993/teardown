# Slice 3: ELF structural parser (`formats`) -> `Image`, findings, `retool info` text + JSON

Goal: parse ELF32/64 LSB/MSB headers, phdrs, shdrs and section names from hostile input; project PT_LOAD into `Image`; report
everything as `formats`-built findings. Closes ADR 0001 "Every structured parser must produce `Image`" (0001:74) and its deferral
"The `FormatParser` and registry signature is set by the first structured-parser spec" (0001:92). Repo facts verified at 4bc385f.
`architect review required`: first `FormatParser` Protocol and registry (ARCH §4), `FileInfo` and public API growth
(`SectionSummary`), ADR 0001 clause closure. There is no new context, outward port or aggregate, so no `/decide` is needed.
Revision 2 applies round 1 (architect A1-A7, reviewer R1-R12).

## Scope
In: ELF ident and header; PN_XNUM / e_shnum==0 / SHN_XINDEX escapes; phdr and shdr tables; `.shstrtab` names; PT_LOAD -> `Image`;
findings and not-analysed markers; `retool info` text lines; JSON via the existing findings (schema_version stays 1).
Policy (assumption, R1): a structurally malformed ELF is reported, not failed: exit 0, the magic finding stays, not_analysed
carries `elf structure rejected: <reason> at offset 0x..`. Only `InputChanged` ("input changed during read") fails the command:
exit 1, `error:` on stderr, empty stdout.
Out (named follow-ups): F-SYM `.symtab`/`.dynsym`; F-DYN; F-REL; F-NOTE; F-COMP SHF_COMPRESSED; F-DWARF; F-ANOM anomaly findings
(LOAD order, section overlap, alignment, PT_INTERP/PT_PHDR); F-ARCH arch-id vocabulary `/decide` when `disasm` starts; F-EXPORT
export `InputChanged` so `reporting/infrastructure/formats_facts.py:30` adopts it; PE/Mach-O parsers via the registry.

## Evidence
Fetched 2026-10-12 by the researcher; the planner re-checked every URL on 2026-10-12 (HTTP 200) and grepped EV_CURRENT, PN_XNUM
and the EM lines.
- gABI ch4.eheader https://www.sco.com/developers/gabi/latest/ch4.eheader.html: e_ident, Ehdr fields, e_version "must be
  EV_CURRENT" (1), e_phoff/e_shoff 0 = absent, e_ehsize, e_shnum==0 -> shdr0.sh_size, SHN_XINDEX -> shdr0.sh_link.
- gABI ch4.intro https://www.sco.com/developers/gabi/latest/ch4.intro.html: type sizes (Addr/Off 4|8, Half 2, Word 4, Xword 8).
- gABI ch4.sheader https://www.sco.com/developers/gabi/latest/ch4.sheader.html: Shdr Fig 4-8, sh_type values, reserved indexes,
  NOBITS "occupies no space in the file". ch4.strtab https://www.sco.com/developers/gabi/latest/ch4.strtab.html: first/last byte
  NUL, index 0 = no name, empty table, suffix references.
- gABI ch5.pheader https://www.sco.com/developers/gabi/latest/ch5.pheader.html: Phdr Fig 5-1, p_type values, LOAD filesz > memsz
  prohibited, LOADs ascending by p_vaddr. man7 elf(5) https://man7.org/linux/man-pages/man5/elf.5.html: PN_XNUM -> shdr0.sh_info
  (only source).
- Linux elf-em.h https://github.com/torvalds/linux/blob/master/include/uapi/linux/elf-em.h (master): EM_386 3, MIPS 8, PPC 20,
  PPC64 21, S390 22, ARM 40, X86_64 62, AARCH64 183, RISCV 243.
Inference: NOBITS offset/size may lie past EOF; entsize below the struct size cannot hold the fields. Not relied on (unverified):
sh_type 4/5/6/9/11, PF_*/SHF_* bits, GNU p_types; reported as raw ints only.

## Architecture
Conforms to ARCH §2 (`formats` row: "structural parsing of ELF"), §3 (domain imports stdlib + `shared` + own domain only), §4
(strategy behind `FormatParser`, registry in application, `check_within` before every read, capped counts, `Address` offsets,
`ParseError` with offset), §5 (test layering as in Tests); ADR 0002 (`formats` builds its findings; `reporting` src unchanged).

| Module | Context / layer | Pattern (ARCH §4) | Clause |
|---|---|---|---|
| `formats/domain/elf.py` (new) | formats / domain | VOs `ElfHeader`, `ProgramHeader`, `SectionHeader`, `ElfFile`; pure `parse_elf` over port `ByteSource`; `display_name`, `section_kind` | ARCH §4 untrusted input |
| `formats/domain/elf_image.py` (new) | formats / domain | pure services `elf_arch`, `elf_image` | ADR 0001:74 |
| `formats/domain/facts.py` | formats / domain | pure `magic_finding` (extracted, reused by `format_facts`), `elf_facts` | ADR 0002 l.101-104 |
| `formats/domain/parsing.py` (new) | formats / domain | strategy Protocol `FormatParser`; VOs `ParsedContainer`, `SectionSummary`; neutral guard `guarded_parse` | ARCH §4; ADR 0001:92 |
| `formats/domain/elf_parser.py` (new) | formats / domain | strategy `ElfParser` (one class per format) | ARCH §4 |
| `formats/domain/model.py` | formats / domain | error `InputChanged(ParseError)`, unexported | ARCH §4 errors |
| `formats/application/registry.py` (new) | formats / application | factory `parser_for(fmt)` | ARCH §4 registry |
| `formats/application/{dto,use_cases}.py` | formats / application | DTO fields; `InspectFile` orchestrates; private `_segment_infos` shared with `LoadRawImage` | ARCH §4 use cases |
| `formats/__init__.py`; `interface/cli/main.py` | public API; interface | + `SectionSummary`; prints `FileInfo` fields, no parsing (A7) | ARCH §2-3 |

- `FormatParser` now: ADR 0001:92 assigns its signature to this spec and ARCH §4 prescribes it; deferring would be a local
  exception. Minimal: one method, one registry function. `ElfFile` is a VO (immutable snapshot with invariants), not an aggregate.
- `Image` stays in the domain; `FileInfo` carries only `SpaceAddress` + `SegmentInfo` (A1). ADR 0001 triggers (0001:115-121) do
  not fire: zero-memsz LOADs map nothing (skipped); overlapping LOADs break the `MemoryMap` invariant -> "image not built" (Risk R6).
- Arch from `e_machine` is header-declared, not inferred (assumption; architect confirms vs ADR 0001 check 1). Names are
  provisional until F-ARCH; a rename bumps the `formats.inspect` STAGE_VERSION, not schema_version (A6).

## Interfaces
```python
# domain/model.py
class InputChanged(ParseError):  # fixed reason "input changed during read"
    def __init__(self, *, offset: int | None = None) -> None: ...
# domain/elf.py  (all @dataclass(frozen=True, slots=True); IntEnum codes)
class ElfClass(IntEnum): ELF32 = 1; ELF64 = 2
class ElfData(IntEnum): LSB = 1; MSB = 2
MAX_PHNUM: Final = 512; MAX_SHNUM: Final = 3072; MAX_SHSTRTAB: Final = 1 << 20; MAX_SECTION_NAME: Final = 256
PT_NULL, PT_LOAD = 0, 1; SHT_NULL, SHT_STRTAB, SHT_NOBITS = 0, 3, 8; PN_XNUM = SHN_XINDEX = 0xFFFF
class ElfHeader: ei_class: ElfClass; ei_data: ElfData; ei_osabi: int; ei_abiversion: int; e_type: int; e_machine: int
    e_entry: Address; e_phoff: Address; e_shoff: Address; e_flags: int; e_ehsize: int; e_phentsize: int
    e_phnum: int; e_shentsize: int; e_shnum: int; e_shstrndx: int   # counts/index AFTER escape resolution
    @property
    def bits(self) -> int: ...       # 32 | 64
class ProgramHeader: p_type: int; p_flags: int; p_offset: Address; p_vaddr: Address; p_paddr: Address
    p_filesz: int; p_memsz: int; p_align: int
class SectionHeader: sh_name: int; name: bytes; sh_type: int; sh_flags: int; sh_addr: Address; sh_offset: Address
    sh_size: int; sh_link: int; sh_info: int; sh_addralign: int; sh_entsize: int   # name b"" = none or no table
class ElfFile: header: ElfHeader; program_headers: tuple[ProgramHeader, ...]; section_headers: tuple[SectionHeader, ...]
    # post_init: len(phdrs) == e_phnum <= MAX_PHNUM, len(shdrs) == e_shnum <= MAX_SHNUM, else ParseError("ELF table counts inconsistent")
def parse_elf(source: ByteSource) -> ElfFile: ...    # ParseError (S1-S30) or InputChanged (S31)
def display_name(raw: bytes) -> str: ...  # 0x20..0x7e kept except '\\' and '"'; any other byte -> f"\\x{b:02x}"
def section_kind(sh_type: int) -> str: ... # 0 null 1 progbits 2 symtab 3 strtab 7 note 8 nobits 18 symtab_shndx; else f"type-0x{t:x}"
# domain/elf_image.py
def elf_arch(header: ElfHeader) -> ArchitectureId: ...  # provisional: 3 x86, 8 mips, 20 ppc, 21 ppc64, 22 s390, 40 arm,
                                                        # 62 x86_64, 183 aarch64, 243 riscv; else f"elf-em-{e_machine}"
def elf_image(elf: ElfFile) -> Image | None: ...      # None if no PT_LOAD has p_memsz > 0; MemoryMap errors propagate
# domain/facts.py
def magic_finding(fmt: Format, producer: str) -> Finding: ...  # Finding("input", {"magic": fmt.value}, PARSED, unverified, producer)
def elf_facts(elf: ElfFile, image: Image | None, producer: str) -> tuple[tuple[Finding, ...], tuple[NotAnalysed, ...]]: ...
# domain/parsing.py
class SectionSummary: index: int; name: str; kind: str; addr: int; offset: int; size: int
    # post_init: index >= 0 and size >= 0 else ParseError; kind is a display label, never compared
class ParsedContainer: arch: ArchitectureId | None; image: Image | None; sections: tuple[SectionSummary, ...]
    findings: tuple[Finding, ...]; not_analysed: tuple[NotAnalysed, ...]   # post_init: image is None or image.arch == arch
class FormatParser(Protocol):
    """Never raises except InputChanged; any other malformed structure becomes NotAnalysed; reasons are static text + numbers."""
    def parse(self, source: ByteSource, producer: str) -> ParsedContainer: ...
def guarded_parse(fmt: Format, build: Callable[[ByteSource, str], ParsedContainer], source: ByteSource,
                  producer: str) -> ParsedContainer: ...
    # InputChanged propagates; other ParseError -> ParsedContainer(None, None, (), (magic_finding(fmt, producer),),
    #   (NotAnalysed(f"{fmt.value} structure rejected: {exc}"),))
# domain/elf_parser.py
class ElfParser:  # satisfies FormatParser; stateless; parse = guarded_parse(Format.ELF, _build_elf, source, producer)
    def parse(self, source: ByteSource, producer: str) -> ParsedContainer: ...
# application/registry.py
def parser_for(fmt: Format) -> FormatParser | None: ...   # match: Format.ELF -> ElfParser(); everything else -> None
# application/dto.py: FileInfo gains, after not_analysed:
    arch: ArchitectureId | None = None; entry: SpaceAddress | None = None
    segments: tuple[SegmentInfo, ...] = (); sections: tuple[SectionSummary, ...] = ()
```
`_build_elf`: `parse_elf`, then `elf_image`; its `ParseError` -> image None + note `f"elf memory image not built: {exc}"`; a None
result -> note `"elf memory image not built: no PT_LOAD segment with p_memsz > 0"`. not_analysed = that note (if any) + `elf_facts`
notes; arch = `elf_arch`; sections = `SectionSummary(i, display_name(name), section_kind(sh_type), sh_addr, sh_offset, sh_size)`.
File bytes never enter a reason. `elf_facts` findings (PARSED, unverified), in order: `magic_finding`; `"elf.header"`
`{"class": bits, "data": "lsb"|"msb", "osabi", "abiversion", "type", "machine", "arch": str, "entry", "flags", "ehsize", "phoff",
"phentsize", "phnum", "shoff", "shentsize", "shnum", "shstrndx"}`; one `"elf.phdr"` per phdr `{"index", "type", "flags", "offset",
"vaddr", "paddr", "filesz", "memsz", "align"}`; one `"elf.shdr"` per shdr `{"index", "name", "type", "flags", "addr", "offset",
"size", "link", "info", "addralign", "entsize"}`; all numbers ints. Notes: `"elf entry point outside every PT_LOAD segment"` (image
exists, e_entry != 0, image.entry None), then always `"elf symbols, dynamic section, relocations and notes not parsed in this version"`.
`InspectFile`: `STAGE_VERSION = "2"`; `parser_for` None -> `format_facts` (unchanged); else copy arch, sections, `entry =
image.entry`, `segments = _segment_infos(image)` (None/() without image). `use_cases.py:39` raises `InputChanged()` (A2);
`LoadRawImage` builds its segments via `_segment_infos` (no behaviour change).

## Binary layout
After `e_ident`, byte order from EI_DATA: `E = "<"` (1) or `">"` (2). e_ident: [0:4] 7f 45 4c 46, [4] EI_CLASS 1/2, [5] EI_DATA
1/2, [6] EI_VERSION 1, [7] OSABI, [8] ABIVERSION. Ehdr off/size ELF32|ELF64: e_type 16/2|16/2, e_machine 18/2|18/2, e_version
20/4|20/4, e_entry 24/4|24/8, e_phoff 28/4|32/8, e_shoff 32/4|40/8, e_flags 36/4|48/4, e_ehsize 40/2|52/2, e_phentsize 42/2|54/2,
e_phnum 44/2|56/2, e_shentsize 46/2|58/2, e_shnum 48/2|60/2, e_shstrndx 50/2|62/2; total 52|64.
Phdr32 (32): type offset vaddr paddr filesz memsz flags align at 0..28 step 4. Phdr64 (56): type 0/4, flags 4/4, offset 8, vaddr
16, paddr 24, filesz 32, memsz 40, align 48 (each /8); flags position differs. Shdr off32|off64 (40|64): name 0|0 (4), type 4|4
(4), flags 8|8, addr 12|16, offset 16|24, size 20|32, link 24|40 (4), info 28|44 (4), addralign 32|48, entsize 36|56. Escapes in
shdr[0]: sh_size +20|32, sh_link +24|40, sh_info +28|44.
`struct` (`unpack_from(buf, 0)` on exactly calcsize bytes; 52/64/32/56/40/64 checked in a scratch run): `EHDR32 =
E+"16sHHIIIIIHHHHHH"`, `EHDR64 = E+"16sHHIQQQIHHHHHH"` (ident, type, machine, version, entry, phoff, shoff, flags, ehsize,
phentsize, phnum, shentsize, shnum, shstrndx); `PHDR32 = E+"8I"` (type, offset, vaddr, paddr, filesz, memsz, flags, align);
`PHDR64 = E+"IIQQQQQQ"` (type, flags, offset, vaddr, paddr, filesz, memsz, align); `SHDR32 = E+"10I"`, `SHDR64 = E+"IIQQQQIIQQ"`.
Reads: `_read(source, ByteRange(off, n))` = `check_within(source.size)` + `source.read`; `len != n` -> `InputChanged(offset=off)`.
Order (tested): ident (0,16); header (0,52|64); shdr[0] if e_shoff != 0; phdr i at e_phoff + i*e_phentsize (struct size,
stride = entsize); shdr i >= 1 at e_shoff + i*e_shentsize; the names table once. Python ints never wrap; sums compared unmasked.
Name scan: `table.find(b"\0", sh_name, min(size, sh_name + MAX_SECTION_NAME + 1))`: at most MAX_SECTION_NAME+1 bytes; the NUL
must sit at relative index <= 256.

## Safety checks
Each raises `ParseError(reason, offset=...)`, in this execution order. `{shdr0}` = e_shoff, `{ent}` = entry start.
1. size < 16: "ELF identification exceeds file" @0.  2. "bad ELF magic" @0.  3. EI_CLASS not 1/2: "invalid EI_CLASS" @4.
4. EI_DATA not 1/2: "invalid EI_DATA" @5.  5. EI_VERSION != 1: "invalid EI_VERSION" @6.  6. size < 52|64: "ELF header exceeds file" @0.
7. e_version != 1: "invalid e_version" @20 (src: ch4.eheader).
8. e_ehsize < 52|64: "e_ehsize smaller than ELF header" @40|52; larger accepted (assumption).
9. e_shoff == 0, e_shnum != 0: "e_shnum set without e_shoff" @48|60.
10. e_shoff == 0, e_shstrndx != 0: "e_shstrndx set without e_shoff" @50|62.
11. e_shoff != 0, e_shentsize < 40|64: "e_shentsize smaller than section header" @46|58.
12. (e_shoff, e_shentsize) outside file: "section header table exceeds file" @e_shoff; full table (e_shoff, e_shentsize*shnum)
    same reason/offset, after 14.
13. e_shnum == 0 with table: shnum = shdr0.sh_size; 0 -> "section count is zero" @{shdr0}+20|32.
14. shnum > MAX_SHNUM: "section count exceeds 3072" @48|60, or @{shdr0}+20|32 when escaped.
15. e_shoff == 0, e_phnum == PN_XNUM: "PN_XNUM without section header table" @44|56.
16. effective phnum (shdr0.sh_info under PN_XNUM) > MAX_PHNUM: "program header count exceeds 512" @44|56, or @{shdr0}+28|44.
17. e_phoff == 0, effective phnum != 0: "e_phnum set without e_phoff" @44|56.
18. e_phoff != 0, effective phnum > 0, e_phentsize < 32|56: "e_phentsize smaller than program header" @42|54.
19. (e_phoff, e_phentsize*phnum) outside file: "program header table exceeds file" @e_phoff. e_phoff inside the ELF header is
    accepted (assumption: read-only aliasing is harmless; gABI does not forbid it).
20. p_type != PT_NULL, p_filesz > 0, p_offset + p_filesz > size: "segment file range exceeds file" @{ent}; p_filesz 0 exempt (R11).
21. PT_LOAD, p_filesz > p_memsz: "PT_LOAD filesz exceeds memsz" @{ent} (src: ch5.pheader).
22. PT_LOAD, p_vaddr + p_memsz > 2**bits: "PT_LOAD exceeds address space" @{ent}.
23. sh_type not SHT_NULL/SHT_NOBITS, sh_offset + sh_size > size: "section file range exceeds file" @{ent} (NOBITS never; inference).
24. effective shstrndx (shdr0.sh_link under SHN_XINDEX) != 0 and >= shnum: "e_shstrndx out of range" @50|62, or @{shdr0}+24|40.
25. names table sh_type != SHT_STRTAB: "section name table is not SHT_STRTAB" @{ent}+4 (assumption).
26. names table sh_size > MAX_SHSTRTAB: "section name table exceeds 1048576 bytes" @{ent} (before the read).
27. size > 0, byte 0 != 0: "section name table does not start with NUL" @sh_offset (src: ch4.strtab).
28. size > 0, last byte != 0: "section name table does not end with NUL" @sh_offset+size-1 (src: ch4.strtab).
29. sh_name != 0 and sh_name >= table size (incl. empty table): "section name offset past string table" @{ent}.
30. no NUL inside the scan window: "section name exceeds 256 bytes" @{ent}.  31. short read: `InputChanged` @read offset; propagates.
Names: sh_name 0 -> b""; effective shstrndx 0 -> every name b"", sh_name unchecked; suffix sharing allowed (src: ch4.strtab).
Not enforced (F-ANOM): LOAD p_vaddr order (accepted, test 25), p_align, PT_INTERP/PT_PHDR count/order, section overlap,
sh_addralign, all-zero shdr[0], escaped counts < 0xff00, file overlap between LOADs, e_type (phdrs read for every type).
`elf_image`: space `AddressSpace("ram", 32)` for ELF32, `DEFAULT_SPACE` for ELF64; per PT_LOAD with p_memsz > 0, in phdr order,
`MappedSegment(ByteRange(p_offset, p_filesz), SpaceAddress(space, p_vaddr), p_memsz, f"phdr{i}")`. Pure BSS (p_filesz 0) is legal:
size-0 `ByteRange` is allowed (values.py:37, image.py:33-36); its offset is never read. entry = `SpaceAddress(space, e_entry)` if
e_entry != 0 and `segment_at` finds it, else None. `MemoryMap` enforces overlap, MAX_SEGMENTS 64, MAX_IMAGE_SIZE
(image.py:15-16, 57-74). Vaddrs are unrelocated (ET_DYN base 0, assumption).

## Caps
- MAX_PHNUM 512, MAX_SHNUM 3072: 2 + 512 + 3072 = 3586 findings <= MAX_FINDINGS 4096 (reporting/domain/model.py:12).
- MAX_SECTION_NAME 256: display name <= 1024 chars <= MAX_JSON_STR 4096 (json_value.py:13), <= 1280 JSON-escaped; each value <= 18
  nodes and ~1.2k text chars, far below MAX_JSON_NODES/MAX_JSON_TEXT (json_value.py:12,14).
- Worst-case `render_json` (scratch run, real reporting code; all ints 2**64-1, 3072 names of 256 x 0x01, 3 notes of 256 chars,
  plus a 64-segment raw stage): 6,262,134 chars = 74.7% of MAX_REPORT_CHARS 8,388,608 (reporting/domain/services.py:12). With
  1024-byte names the same run raises "report exceeds", hence 256.
- MAX_SHSTRTAB 1 MiB bounds the single table read; typical tables < 4 KiB (assumption).

## CLI
`retool info PATH` text, after `format:`: if arch is set, `arch:   {arch}` and `entry:  {entry or "none"}`; per `SegmentInfo`
`segment {name}: {start} mem=0x{mem_size:x} file=0x{file_start:x}+0x{file_size:x}` (one private helper, shared with `--raw`); per
section `section {index} "{name}" {kind} addr=0x{addr:x} off=0x{offset:x} size=0x{size:x}`; per not_analysed (every format)
`note:   {reason}`. `--raw` text output unchanged.
JSON: no new keys; finding `value` is already free-form, so schema_version stays 1 (bumped on key/type/meaning change,
slice2:131); `formats.inspect` version "2". Golden = `json.dumps(json.loads(LINE), indent=2, sort_keys=True) + "\n"` of each
line; a scratch run verified this equals `render_json` and diffed G1/G2 against HEAD.
G1 `elf_magic.json` (`b"\x7fELF"+b"\0"*60`):
{"findings":[{"producer":"formats.inspect","provenance":"parsed","subject":"input","value":{"magic":"elf"},"verification":{"checks":[],"reason":"","status":"unverified"}}],"input":{"sha256":"cc9d6fac1f314ccbd3003c6a0e788a426958609b1312422d8fed40a08ee0bb51","size":64},"not_analysed":[{"reason":"elf structure rejected: invalid EI_CLASS at offset 0x4","stage":"formats.inspect"}],"raw_image":null,"schema_version":1,"stages":[{"name":"formats.inspect","sha256":"bc3ac3a6b5bd8de11364562a1470100fa26c2d4f21f075adf7abc3fbe10ab223","version":"2"}]}
G2 `raw_base.json` (`b"\0"*0x100`, `--raw --arch armv7 --base 0x8000000`):
{"findings":[],"input":{"sha256":"5341e6b2646979a70e57653007a1f310169421ec9bdd9f1a5648f75ade005af1","size":256},"not_analysed":[{"reason":"container structure not parsed: unknown format","stage":"formats.inspect"},{"reason":"raw image content not analysed","stage":"formats.raw"}],"raw_image":{"arch":"armv7","entry":null,"segments":[{"file_size":256,"file_start":0,"mem_size":256,"name":"seg0","start":"ram:0x8000000"}]},"schema_version":1,"stages":[{"name":"formats.inspect","sha256":"16c9718f3e35e903fd79004090f89c0fed4ce1252b90188fbe9fde507f19f759","version":"2"},{"name":"formats.raw","sha256":"92cfbecff776298495722c94cefc74ad272b40ed48a21fee43af22719186c841","version":"1"}]}
G3 `elf64_min.json` (F64, `info PATH --json`; 4181 bytes):
{"findings":[{"producer":"formats.inspect","provenance":"parsed","subject":"input","value":{"magic":"elf"},"verification":{"checks":[],"reason":"","status":"unverified"}},{"producer":"formats.inspect","provenance":"parsed","subject":"elf.header","value":{"abiversion":0,"arch":"x86_64","class":64,"data":"lsb","ehsize":64,"entry":4194480,"flags":0,"machine":62,"osabi":0,"phentsize":56,"phnum":2,"phoff":64,"shentsize":64,"shnum":4,"shoff":224,"shstrndx":3,"type":2},"verification":{"checks":[],"reason":"","status":"unverified"}},{"producer":"formats.inspect","provenance":"parsed","subject":"elf.phdr","value":{"align":4096,"filesz":192,"flags":5,"index":0,"memsz":192,"offset":0,"paddr":4194304,"type":1,"vaddr":4194304},"verification":{"checks":[],"reason":"","status":"unverified"}},{"producer":"formats.inspect","provenance":"parsed","subject":"elf.phdr","value":{"align":4096,"filesz":8,"flags":6,"index":1,"memsz":256,"offset":192,"paddr":4198592,"type":1,"vaddr":4198592},"verification":{"checks":[],"reason":"","status":"unverified"}},{"producer":"formats.inspect","provenance":"parsed","subject":"elf.shdr","value":{"addr":0,"addralign":0,"entsize":0,"flags":0,"index":0,"info":0,"link":0,"name":"","offset":0,"size":0,"type":0},"verification":{"checks":[],"reason":"","status":"unverified"}},{"producer":"formats.inspect","provenance":"parsed","subject":"elf.shdr","value":{"addr":4194480,"addralign":16,"entsize":0,"flags":6,"index":1,"info":0,"link":0,"name":".text","offset":176,"size":16,"type":1},"verification":{"checks":[],"reason":"","status":"unverified"}},{"producer":"formats.inspect","provenance":"parsed","subject":"elf.shdr","value":{"addr":4198600,"addralign":8,"entsize":0,"flags":3,"index":2,"info":0,"link":0,"name":".bss","offset":200,"size":248,"type":8},"verification":{"checks":[],"reason":"","status":"unverified"}},{"producer":"formats.inspect","provenance":"parsed","subject":"elf.shdr","value":{"addr":0,"addralign":1,"entsize":0,"flags":0,"index":3,"info":0,"link":0,"name":".shstrtab","offset":200,"size":22,"type":3},"verification":{"checks":[],"reason":"","status":"unverified"}}],"input":{"sha256":"686ac4b860df9b644d62c1e8330252ef0317c8492b8d52f43bd515aebe50e050","size":480},"not_analysed":[{"reason":"elf symbols, dynamic section, relocations and notes not parsed in this version","stage":"formats.inspect"}],"raw_image":null,"schema_version":1,"stages":[{"name":"formats.inspect","sha256":"8eec66d5ba11a7fa8c9b8257569a7a901305dff289e6fdaee98cee80ad244bba","version":"2"}]}

## Files
Create: `src/retool/formats/domain/{elf,elf_image,parsing,elf_parser}.py`, `src/retool/formats/application/registry.py`,
`tests/formats/{elf_build,test_elf_parse,test_elf_image,test_elf_facts}.py`, `tests/reporting/test_elf_budget.py`,
`tests/fixtures/reporting/elf64_min.json`.
Modify: `src/retool/formats/domain/{model,facts}.py`, `src/retool/formats/application/{dto,use_cases}.py`,
`src/retool/formats/__init__.py`, `src/retool/interface/cli/main.py`; `tests/formats/fakes.py` (+`ShrinkingSource(data, cut,
honest_reads=0)`: size `len(data)`, first `honest_reads` reads serve `data`, later ones `data[:cut]`); `tests/formats/test_facts.py`
(only `test_inspect_file_stage_fields`: version "2", expected facts = G1's); `tests/interface/test_cli.py` (append);
`tests/fixtures/reporting/{elf_magic,raw_base}.json` (regenerate).

## Tests
`elf_build.py`: `build_elf(bits=64, msb=False, *, phent_pad=0, shent_pad=0) -> bytes`; `patch(data, off, fmt, value) -> bytes`
(`struct.pack_into` on a copy); `build_worst_elf() -> bytes`. Layout: phoff = E; text = phoff+2*(P+phent_pad); data = text+16;
strtab = data+8; shoff = align_up(strtab+22, 8|4); size = shoff+4*(S+shent_pad); base 0x400000|0x8000; entry = base+text. Every
byte not listed is 0; [text,+16) = 0x90, [data,+8) = 0x11, strtab = `b"\0.text\0.bss\0.shstrtab\0"` (22 B).
F64 = `build_elf()`, F32 = `build_elf(32, msb=True)`; values F64|F32 (computed in scratch, verify against fixture):
- Ehdr: ident `7f454c46 02|01 01|02 01 00` + 8 zero bytes; e_type 2; e_machine 62|40; e_version 1; e_entry 0x4000b0|0x8074;
  e_phoff 0x40|0x34; e_shoff 0xe0|0xa4; e_flags 0; e_ehsize 64|52; e_phentsize 56|32; e_phnum 2; e_shentsize 64|40; e_shnum 4;
  e_shstrndx 3; size 0x1e0|0x144.
- phdr0 @0x40|0x34: type 1, flags 5, offset 0, vaddr=paddr 0x400000|0x8000, filesz=memsz 0xc0|0x84, align 0x1000. phdr1
  @0x78|0x54: type 1, flags 6, offset 0xc0|0x84, vaddr=paddr 0x4010c0|0x9084, filesz 8, memsz 0x100, align 0x1000.
- shdr i @0xe0+64i|0xa4+40i; shdr0 all zero; shdr1 name 1, type 1, flags 6, addr 0x4000b0|0x8074, offset 0xb0|0x74, size 0x10,
  addralign 16; shdr2 name 7, type 8, flags 3, addr 0x4010c8|0x908c, offset 0xc8|0x8c, size 0xf8, addralign 8; shdr3 name 12,
  type 3, offset 0xc8|0x8c, size 0x16, addralign 1.
- `build_worst_elf` (ELF64 LSB, 225602 B): header as F64 but e_phnum 512, e_shnum 3072, e_shstrndx 3071, e_shoff 0x7040, e_entry
  2**64-1, e_flags 0xffffffff; every phdr type/flags 0xffffffff, filesz 0, rest 2**64-1; shdr 0..3070 name 1, type 8, link/info
  0xffffffff, rest 2**64-1; shdr3071 name 1, type 3, offset 0x37040, size 258, rest 0; table `b"\0"+b"\x01"*256+b"\0"`.
`p(off, v)` = patch of F64 at the field width (`<H/<I/<Q`); "-> @x" = ParseError with that check's reason and `.offset == x`.
`tests/formats/test_elf_parse.py`:
1. F64 parses: every header field as built, effective counts 2/4/3, names (b"", b".text", b".bss", b".shstrtab"), both phdrs.
2. F32 parses: bits 32, MSB, e_machine 40, every phdr/shdr field as built (PHDR32 flags at +24).
3. `MemorySource(F64).calls` == [(0,16),(0,64),(0xe0,64),(0x40,56),(0x78,56),(0x120,64),(0x160,64),(0x1a0,64),(0xc8,22)].
4. S1: b"", F64[:15] -> @0. S2: b"\x7fELG"+F64[4:] -> @0. S3: byte4 in {0,3} -> @4. S4: byte5 in {0,3} -> @5. S5: byte6 in
   {0,2} -> @6. S6: F64[:63], F32[:51] -> @0. S7: p(20,0) -> @20. S8: p(52,63) -> @52; F32 e_ehsize(40,">H")=51 -> @40;
   p(52,80) parses.
5. Precedence (R8, R10): p(40,0) -> @60 with S9's reason, not S10's; S10: p(40,0)+p(60,0) with shstrndx 3 and 0xffff -> @62;
   S15: p(40,0)+p(60,0)+p(62,0)+p(56,0xffff) -> @56, and adding p(32,0) still gives S15, not S17; S17: p(32,0) -> @56; S17 uses
   the effective count: p(32,0)+p(56,0xffff)+p(0x10c,2) -> @56, while p(32,0)+p(56,0xffff) parses with no phdrs.
6. S11: p(58,63) -> @58. S18: p(54,55) -> @54; F32 e_phentsize(42)=31 -> @42. S12: p(40,0x1c0) -> @0x1c0; p(40,0x120) (full
   table) -> @0x120. S13: p(60,0)+p(0x100,0) -> @0x100. S14: p(60,3073) -> @60; p(60,0)+p(0x100,3073) -> @0x100. S16: p(56,513)
   -> @56; p(56,0xffff)+p(0x10c,513) -> @0x10c. S19: p(32,0x1a8) -> @0x1a8; p(32,8) parses (phdr0 aliases the header, phdr1 is LOAD0).
7. S20: p(0x80,2**64-16)+p(0x98,32) -> @0x78; non-LOAD p(0x78,4)+p(0x80,0x1d0)+p(0x98,0x20) -> @0x78; exempt (R11) and parse:
   p(0x98,0)+p(0x80,2**64-1) and PT_NULL p(0x78,0)+p(0x80,2**64-1). S21: p(0x98,0x101) -> @0x78. S22: p(0x88,2**64-0x80) ->
   @0x78; F32 p_vaddr(0x5c,">I")=0xffffff80 -> @0x54; p(0x88,2**64-0x100) parses.
8. S23: p(0x138,2**64-8) -> @0x120; NOBITS p(0x178,2**64-1)+p(0x180,2**63) parses. S24: p(62,4) -> @62;
   p(62,0xffff)+p(0x108,4) -> @0x108. S25: p(0x1a4,1), p(0x1a4,8) -> @0x1a4. S26: SparseSource((1<<20)+0x200,
   head=p(0x1c0,(1<<20)+1)) -> @0x1a0, no read > 64 after the header. S27: byte 0xc8 = 0x41 -> @0xc8. S28: byte 0xdd = 0x41 ->
   @0xdd. S29: p(0x120,22) -> @0x120; empty table p(0x1c0,0) -> @0x120.
9. S30: F64+b"\0"+b"a"*257+b"\0" with p(0x1b8,0x1e0)+p(0x1c0,259) -> @0x120; with 256 "a" (size 258) name == b"a"*256; F64
   shdr3 (window clipped by the table end before the cap) -> b".shstrtab" (R4).
10. S31: ShrinkingSource(F64, cut=0x120) -> `InputChanged` @0x120 from `parse_elf` and from `ElfParser().parse`.
11. Escapes: p(56,0xffff)+p(0x10c,2) -> e_phnum 2; p(60,0)+p(0x100,4) -> e_shnum 4; p(62,0xffff)+p(0x108,3) -> names resolved.
12. e_shoff == 0 legal: p(40,0)+p(60,0)+p(62,0) -> no shdrs. p(62,0) -> every name b"".
13. Stride: `build_elf(phent_pad=8, shent_pad=16)` -> e_phentsize 64, e_shentsize 80, same names, p_types (1, 1).
14. Suffix sharing: p(0x120,15) -> b"strtab"; p(0x120,21) -> b"". `ElfFile` with 1 phdr, e_phnum 2 -> "ELF table counts inconsistent".
15. `display_name(b'a"\\\x01\xff ') == 'a\\x22\\x5c\\x01\\xff '`; `section_kind(8) == "nobits"`, `section_kind(0x6ffffff6) ==
    "type-0x6ffffff6"`; `SectionSummary` with index -1 or size -1 -> ParseError.
`tests/formats/test_elf_image.py` (`sa`, `ram` from fakes):
16. F64 -> `Image(ArchitectureId("x86_64"), MemoryMap((MappedSegment(ByteRange(0,0xc0), sa(ram,0x400000), 0xc0, "phdr0"),
    MappedSegment(ByteRange(0xc0,8), sa(ram,0x4010c0), 0x100, "phdr1"))), sa(ram,0x4000b0), Format.ELF)`.
17. F32 -> arch "arm", `AddressSpace("ram",32)`, segments (0,0x84)@0x8000 mem 0x84, (0x84,8)@0x9084 mem 0x100, entry 0x8074.
18. p(18,m) for m in (3,8,20,21,22,40,62,183,243) -> the provisional names; p(18,0xbeef) -> "elf-em-48879".
19. Pure BSS (R9): p(0x98,0) -> phdr1 = `MappedSegment(ByteRange(0xc0,0), sa(ram,0x4010c0), 0x100, "phdr1")`.
20. p(0x98,0)+p(0xa0,0) -> only "phdr0". 21. No LOAD p(0x40,4)+p(0x78,4) -> None. 22. p(0x88,0x400010) -> "segments overlap in space".
23. p(0xa0,2**33) -> "mapped size exceeds 4294967296 bytes"; in-test `ElfFile` with 65 LOADs -> "segment count must be 1..64".
24. p(24,0x500000) -> entry None; p(24,0) -> entry None.
25. Unsorted LOADs accepted (MemoryMap sorts per space, image.py:67-74): F64 with the two phdr entries swapped -> ("phdr0"
    @0x4010c0, "phdr1" @0x400000).
`tests/formats/test_elf_facts.py`:
26. `elf_facts(parse_elf(F64), elf_image(...), "formats.inspect")` == G3's findings and not_analysed.
27. `ElfParser` on the fixtures of 21/22/23 -> note starts "elf memory image not built: " (21: "...no PT_LOAD segment with
    p_memsz > 0"); findings intact. 28. `ElfParser` on p(24,0x500000) -> notes ("elf entry point outside every PT_LOAD segment",
    symbols note). 29. `ElfParser` on G1 bytes -> G1's findings and note.
30. `guarded_parse(Format.PE, raising_build, ...)` -> "pe structure rejected: ..."; `InputChanged` from build propagates.
31. `parser_for(Format.ELF)` is an `ElfParser`; PE/MACHO/UNKNOWN/RAW -> None.
32. `InspectFile(MemorySource(F64))`: stage_version "2", arch "x86_64", entry sa(ram,0x4000b0), segments ==
    (SegmentInfo("phdr0", sa(ram,0x400000), 0xc0, 0, 0xc0), SegmentInfo("phdr1", sa(ram,0x4010c0), 0x100, 0xc0, 8)),
    sections[2] == SectionSummary(2, ".bss", "nobits", 0x4010c8, 0xc8, 0xf8).
`tests/reporting/test_elf_budget.py` (A7, R6): 33. `MAX_PHNUM + MAX_SHNUM + 2 <= MAX_FINDINGS`. 34. `render_json(FormatsFactSource(
MemorySource(build_worst_elf())).collect())` does not raise, length <= MAX_REPORT_CHARS, 3586 findings.
`tests/interface/test_cli.py` (append):
35. `info F64` exit 0; stdout lines after `sha256:` exactly: `format: elf` / `arch:   x86_64` / `entry:  ram:0x4000b0` /
    `segment phdr0: ram:0x400000 mem=0xc0 file=0x0+0xc0` / `segment phdr1: ram:0x4010c0 mem=0x100 file=0xc0+0x8` /
    `section 0 "" null addr=0x0 off=0x0 size=0x0` / `section 1 ".text" progbits addr=0x4000b0 off=0xb0 size=0x10` /
    `section 2 ".bss" nobits addr=0x4010c8 off=0xc8 size=0xf8` / `section 3 ".shstrtab" strtab addr=0x0 off=0xc8 size=0x16` /
    `note:   elf symbols, dynamic section, relocations and notes not parsed in this version`.
36. `info` on G1 bytes: exit 0; stdout contains `note:   elf structure rejected: invalid EI_CLASS at offset 0x4`.
37. Monkeypatch `retool.interface.cli.main.FileByteSource` to `lambda p: ShrinkingSource(F64, 0x120, honest_reads=2)`; `info x`
    with and without `--json` -> exit 1, stdout "", stderr starts `error: input changed during read` (R5).
38. `info F64 --json` stdout == `elf64_min.json`, stderr "". `test_info_json_golden_elf` (G1) and `test_info_json_golden_raw`
    (G2) pass with their code unchanged.

## Import-linter
None: every new module is inside `formats` layers already covered by `layers-formats`, `no-infra-in-core`,
`no-interface-from-contexts`, `no-assist-in-deterministic`; `reporting` src untouched. Expect `Contracts: 8 kept, 0 broken.`

## Risks
R1 Policy (Scope): malformed ELF -> exit 0 + note, not `error:`; architect/user may reverse. R2 Checks 9/10/17/20/23 reject carved
or truncated files with dangling ranges; relax via notes in F-ANOM. R3 Names > 256 bytes (long C++ function sections), > 3072
sections or > 512 phdrs reject the structure; cores with > 64 LOADs or > 4 GiB mapped get no image. R4 Arch names are provisional
and carry no endianness (ARM BE) -> ADR 0001 trigger 2 when `disasm` starts (F-ARCH). R5 ELF32 uses `ram`/32, raw and ELF64
`ram`/64. R6 If real samples need overlapping PT_LOADs, ADR 0001 trigger 5 fires -> `/decide`. R7 Worst-case JSON 6.3 MB.
R8 The stage bump changes the G1/G2 hashes by design.

## Acceptance
1. `make check` passes; lint-imports prints `Contracts: 8 kept, 0 broken.`; archcheck prints `archcheck: ok`.
2. Tests 1-38 exist and pass; among existing tests only `test_inspect_file_stage_fields` has an edited body
   (`git diff tests/formats/test_facts.py`).
3. Regenerate `elf_magic.json`/`raw_base.json` by running `info` as in G1/G2 (or applying the `## CLI` transform to the G1/G2
   lines). `git diff tests/fixtures/reporting` shows only G1's not_analysed reason, `version` "2" and stage `sha256`, and G2's
   `stages[0]` `version` "2" and `sha256`. All three files equal the `## CLI` lines under the transform, pass `jq empty`, are
   < 64 KiB; they are read by `test_info_json_golden_elf`, `test_info_json_golden_raw` and test 38.
4. `grep -rln "import struct" src/retool` prints only `src/retool/formats/domain/elf.py`;
   `grep -nE "struct\.|ByteRange\(|json\." src/retool/interface/cli/main.py` prints nothing.
5. `grep -nE "MAX_PHNUM: Final = 512|MAX_SHNUM: Final = 3072|MAX_SHSTRTAB: Final = 1 << 20|MAX_SECTION_NAME: Final = 256"
   src/retool/formats/domain/elf.py` prints 4 lines; `grep -rn "except ParseError" src/retool/formats/application` prints nothing.
6. `retool.formats.__all__` == slice-2 list + `"SectionSummary"`; `InputChanged` not exported; `git diff --stat` lists only
   `## Files` paths.
