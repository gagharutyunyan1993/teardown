# 0001. Raw headerless images load only on explicit request inside `formats`; address-space and architecture vocabulary goes to `shared`

Date: 2026-10-12   Status: accepted   Deciders: judge (opus/xhigh) on proposals from analyst A (opus/high), analyst B (sonnet/high)

## Context
On 2026-10-12 the user put raw headerless firmware images (no ELF/PE/Mach-O header) in scope. Such files carry no
machine-readable base address, architecture or layout, so the user has to declare them. Inputs are hostile and never
executed. Every offset and length, whether it comes from the file or from the user, must be bounds-checked
(CLAUDE.md, ARCHITECTURE.md §4). Repo state at commit 1012f39: `formats` only identifies magic bytes. There is no
structured parser yet, no `FormatParser` Protocol, no registry, no architecture type and no content-based fallback.
The requirement digest also lists banked layouts (TI-84 bank:offset, x86 real mode), an architecture without a
disassembler (pi32v2) and multi-module containers (coreboot). This ADR covers loading only. It changes the
responsibility rows of `formats` and `shared` in ARCHITECTURE.md §2, so it goes through `/decide`.

## Evidence and sources
Repository (read 2026-10-12, commit 1012f39):
- `Format` = {ELF, PE, MACHO, UNKNOWN}, documented as "identified from magic bytes". `detect()` checks 4 bytes and returns UNKNOWN when nothing matches, with no fallback (src: src/retool/formats/domain/model.py, domain/services.py).
- The public API of `formats` exports only `ByteSource`, `FileInfo`, `Format`, `InspectFile` and `detect`. `ByteSource` is a formats domain port (src: src/retool/formats/__init__.py, domain/ports.py).
- `shared` contains `Address(value >= 0)`, `ByteRange(start, size).check_within(limit)`, `ParseError(reason, offset=)` and `RetoolError` (src: src/retool/shared/values.py, errors.py).
- archcheck A1: a `domain/` module may import only stdlib, `retool.shared` and its own context. A2: cross-context imports go only through `retool.<ctx>` (src: tools/archcheck.py:54-59).
- ARCHITECTURE.md §1 defines `shared` as "value objects and errors, pure, dependency-free". §3 says "application imports domain + shared", and only infrastructure and interface import other contexts. §4 places ports as capability Protocols in the consumer's `domain/ports.py`. The `disasm` row says "instruction decoding over byte ranges".
- import-linter forbids `retool.shared` from importing `formats` or `interface`. No contract limits what `shared` may contain, and layer contracts exist only for `formats` (src: .importlinter).

External sources (fetched 2026-10-12 unless dated otherwise):
- Ghidra `BinaryLoader` ("Raw Binary") `extends AbstractProgramLoader`. It has tier `UNTARGETED_LOADER`, priority 100, and one `LoadSpec(this, 0, lcs, false)` per language, so it never prefers or guesses an architecture. Its options are Base Address, File Offset, Length, Block Name and Overlay. It rejects offset < 0 or >= file length, length < 0 or > file length, offset+length > file length, and length > space max − base + 1 (also capped at `Memory.MAX_BINARY_SIZE`). It reports "Memory Conflict" on overlap unless overlay is set. A null base "later gets converted to 0" (src: github.com/NationalSecurityAgency/ghidra master, Ghidra/Features/Base/.../opinion/BinaryLoader.java).
- Ghidra `SegmentedAddressSpace` converts seg:off to flat and back through 5 overridable methods. The default is x86 real mode with `REALMODE_SIZE = 21`. The flat form exists "to produce an Address object that can be used by other analyses" (src: ghidra master, .../program/model/address/SegmentedAddressSpace.java).
- angr cle: `class Blob(Backend)`. `is_compatible()` returns False, so `_static_backend` never selects it from content. An explicit `backend` option is resolved before content detection runs. When nothing matches, the error says "Perhaps try the 'blob' loader?". `arch` is required (`CLEError` otherwise). `base_addr` and `entry_point` default to 0 with a warning. Mapping is given as `segments=[(file_offset, mem_addr, size)]` (src: github.com/angr/cle master, cle/backends/blob.py, cle/loader.py).
- radare2: `-a` "force asm.arch", `-b` "force asm.bits", `-B baddr`, `-m addr` "map file at given address", `-n` "just load the raw file" (src: radare2.1 man page, dated May 20, 2025).
- Binary Ninja: opening a format "without a loader" shows the Open-with-Options dialog, which asks for "base load address and default architecture". Segments have separate memory start/length and file offset/length, and a segment can be an "Unbacked Region". Container extraction is a separate Container Browser (src: docs.binary.ninja/guide/index.html).
- binwalk identifies and extracts embedded files and runs entropy analysis. It has no base or architecture model (src: github.com/ReFirmLabs/binwalk README.md, master).

Source treatment: the dossier described a "registry keyed by `Format`" and a "`FormatParser` Protocol". These are plans in ARCHITECTURE.md §4, not code (grep of src/ finds neither). The dossier's binwalk version (3.1.1) and the LIEF raw, r2 banks and cle overlap items were not verified and are not relied on. The dossier left out one fact: Ghidra also defaults the base to 0, the same as cle.

## Options considered
1. **New `firmware`/`raw` context owns raw loading.** For: firmware vocabulary stays isolated, and splitting/checksums will need a context anyway. Against: A1 keeps its domain from using `formats.ByteSource`, so the port, DTOs and error translation would be duplicated. Ghidra and cle treat raw as one more loader in the same family (`BinaryLoader extends AbstractProgramLoader`, `Blob(Backend)`).
2. **Strategy in `formats`, with `MemoryMap`, spaces and arch all in `shared` (analyst B).** For: one model for every consumer, so nothing moves later. Against: today no consumer outside `formats` needs the map aggregate (`disasm` works "over byte ranges"). Every context would inherit file-layout policy (overlap rules, zero-fill caps), and taking it out of `shared` later touches every context.
3. **Strategy in `formats` with `AddressSpace` and the map in `formats`, and only an arch id in `shared` (analyst A).** For: the smallest kernel. Against: space-qualified addresses must appear in `disasm` and `analysis` domain signatures (branch targets and xrefs in banked memory). A1 forbids those domains from importing `formats`, so each would have to model spaces again.
4. **Content fallback (UNKNOWN treated as raw).** Against: none of the surveyed tools does this. cle never picks Blob from content, Ghidra never prefers raw, and Binary Ninja asks the user.
5. **Give `Address` a space or width.** Against: every `Address` user changes. Composing `SpaceAddress(space, Address)` is just as expressive.
6. **A single base and a flat address.** Against: it cannot express the banked layouts in the digest.

## Independent opinions
- Analyst A recommended raw as an explicit loader in `formats`, with `Image`, `MemoryMap` and `AddressSpace` in `formats` and only `ArchitectureId` in `shared`, because a bigger kernel is speculative while every consumer is still only planned.
- Analyst B recommended raw as an explicit parser in `formats`, with `AddressSpace`, `SpaceAddress`, `MemoryMap` and `Architecture(name, bits, endian)` in `shared`, because `disasm` must not depend on `formats`.

Both agree on: `formats` as owner; selection only on explicit request; no fallback; `Address` unchanged; arch and base required; overlap rejected within a space; count caps; splitting and checksums sent to a later `/decide`.

What settled each disagreement:
- **Location of the space vocabulary → `shared` (B).** The types appear in the domain signatures of `formats` (where segments start), `disasm` (branch targets) and `analysis` (xrefs), and A1 lets those domains import only `shared`. Ghidra's space-qualified Address is likewise the type "used by other analyses".
- **Location of `MemoryMap` → `formats` public API (A).** No domain outside `formats` has to name the map:
  - `disasm` decodes byte ranges.
  - `analysis` reaches memory through a capability port in its own domain (§4). That port takes `SpaceAddress`, and an adapter in `analysis/infrastructure` implements it.
  - So A1 does not force the map into `shared`.
  - Moving the map from `formats` to `shared` touches only `formats` importers. The reverse move touches every context.
  - B's own flip conditions are false (import-linter does not limit `shared`, and `formats` exports no map). However, B's premise that `disasm` needs the map contradicts the `disasm` responsibility row.
- **Shape of the architecture type → opaque `ArchitectureId` (A).** radare2 treats bits as a disassembler setting (`asm.bits`). Both proposals put the width used for bounds checks on the address space. A `(bits, endian)` descriptor would force the user to state facts that `formats` never uses, even for an architecture retool cannot decode (pi32v2).
- **Segment shape → file range plus memory size ≥ file size (A).** Binary Ninja's "Unbacked Region" and its separate file and memory lengths show the gap. B's `Mapping(file, start)` cannot express zero-filled tails (BSS).
- **`Format.RAW` → added, but `detect()` never returns it (B).** cle exposes `"blob"` in the same backend namespace as "elf" and "pe", and Ghidra lists Raw Binary among its loaders.
- **Entry must lie inside a segment (B).** Adopted.

## Decision
Raw images belong to the `formats` context and load only when explicitly requested. `formats` gains a pure domain
service `build_raw_image(spec, source_size) -> Image` and an application use case `LoadRawImage(source).execute(RawLoadSpec)`.
`Format` gains a `RAW` member, which `detect()` never returns (pinned by a unit test). The CLI flags are
`--raw --arch ID --base ADDR [--offset N --length N] [--map OFF:ADDR:SIZE[@SPACE]] [--entry ADDR]`. `--raw` bypasses
detection. Without `--raw`, an UNKNOWN result prints "unknown format; to load as a raw image use --raw --arch --base"
and never falls back to raw. This rule follows cle (explicit backend before detection; Blob never content-selected) and
Ghidra (raw never preferred).

Where the types live, settled by A1 and by who must import them:
- `shared` gains three pure value objects: `ArchitectureId` (opaque; validated as `[a-z0-9_.:-]{1,32}`), `AddressSpace(name, width_bits 1..64)` and `SpaceAddress(space, offset: Address)`, which requires offset ≤ 2**width−1. `Address` and `ByteRange` stay unchanged.
- `formats/domain` gains `MappedSegment(file: ByteRange, start: SpaceAddress, mem_size, name)`, `MemoryMap` (a validated value object with `segment_at` and `file_range_for`), `Image(arch, memory, entry, format)` and `RawLoadSpec`. A single `--base` is shorthand for one segment. These are exported through `retool.formats`.
- These `formats/domain` modules import only stdlib and `shared`, so a later promotion to `shared` is a pure move.
- Every structured parser must produce `Image` when it is written. None exists yet, so this costs nothing now.
- The default space is `ram`, 64-bit wide, unless the user declares one (assumption: a wrong width only loosens the overflow check).

Mandatory safety checks. Each check raises `ParseError`, carrying the offset when it is a file offset, and each has a unit test for empty, boundary and overflow cases:
1. `arch` is required, validated against the charset and length, and never inferred. It never reaches a path, shell or format string.
2. `base` is required. This is deliberately stricter than Ghidra and cle, which default to 0 (assumption: a wrong silent base gives plausible-looking but wrong addresses).
3. 0 ≤ file offset < source size (as in Ghidra).
4. length ≥ 1 and offset + length ≤ source size, checked through `ByteRange.check_within(size)` (as in Ghidra).
5. mem_size ≥ file length, and start + mem_size − 1 ≤ 2**width − 1 (Ghidra's check against space max − base + 1).
6. 1 ≤ segment count ≤ `MAX_SEGMENTS` (64), and total mapped bytes including zero-fill ≤ `MAX_IMAGE_SIZE` (Ghidra `MAX_BINARY_SIZE` analogue).
7. Segments must not overlap within one space. A bank or overlay is its own named space (Ghidra "Memory Conflict" unless overlay).
8. If `entry` is given, it must lie inside a segment of its space.
9. Bytes are read through `ByteSource` in bounded windows. The image is never materialised whole, and zero-fill is virtual.
10. If a structured-format magic is found under `--raw`, retool only warns. It never switches loader (cle resolves an explicit backend first).

Deferred:
- Firmware container splitting (SYNTHESIS row 8) and checksum verification (row 18) go to **a future ADR (firmware container splitting and checksum detection; number assigned when scheduled)**, which decides whether a `firmware` context should exist. Its per-module output must feed `RawLoadSpec`/`LoadRawImage` through the `formats` public API.
- Converting seg:off to flat for real mode (Ghidra `SegmentedAddressSpace` as the reference) waits until such a sample is in scope. It will be a pure function in `formats`.
- The `FormatParser` and registry signature is set by the first structured-parser spec.

## Consequences
- Easier:
  - `disasm` and `analysis` can be specified against `SpaceAddress` and `ArchitectureId` without depending on `formats`.
  - pi32v2 images load even though retool has no decoder for them.
  - A hostile header cannot redirect a raw load.
- Harder:
  - `shared` grows by three types, which must stay value objects with validation only.
  - Each context that consumes memory needs its own port plus an adapter over `retool.formats`.
  - Users must always state arch and base.
- Follow-ups:
  - Update ARCHITECTURE.md §2 rows `formats` ("+ user-declared raw images, ADR 0001") and `shared` (the new types).
  - Add a pointer in `.claude/memory/DECISIONS.md`.
  - The planner writes the raw-loading spec; the architect must approve it because it changes the kernel and adds a use case.
  - When `disasm` and `analysis` are created, add import-linter layer contracts for them, mirroring `formats` (assumption).

## Dissent
- **B (strongest).** `MemoryMap` belongs in `shared` now, because moving it later is a cross-cutting change. Mitigation: the map modules import only stdlib and `shared`, so promotion is a file move plus a re-export, and the first trigger below covers it.
- **A.** `AddressSpace` should stay in `formats`. Overruled by A1, because consumer domains must name spaces.
- **A, runner-up.** A `firmware` context, kept open for a future ADR (firmware container splitting and checksum detection; number assigned when scheduled).
- **B, runner-up.** Plain B with a flat `Address`, rejected for banked layouts.

## Revisit when
- A spec for a context other than `formats` needs `MemoryMap` or `Image` in its domain or application signatures, rather than behind a port. Then promote them to `shared` with a superseding ADR.
- A `disasm` spec needs bits or endianness that its own decoder table, keyed by `ArchitectureId`, cannot supply.
- Bank mapping depends on execution state, so static named spaces stop being enough.
- The split output of a future ADR (firmware container splitting and checksum detection; number assigned when scheduled) does not fit `RawLoadSpec`.
- A structured parser's segments cannot be expressed as `MappedSegment`.
- Consumers start branching on `Format.RAW`.
