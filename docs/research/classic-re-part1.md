# Research digest — classic reverse engineering, part 1 (hardware, firmware, retro, decompilation)

Source: reading list supplied by the user on 2026-10-11; notes produced by the researcher worker on 2026-10-11.
Markers: `status: fetched|unreachable` — whether the page itself was read; `(src: url)` — fact taken from that page; `(assumption)` — not verified against a source. GitHub repositories were unreachable through the session proxy (HTTP 403); those notes rest on secondary coverage.
Context: retool (Python 3.12 toolkit for static analysis of ELF/PE/Mach-O, LLM-assisted workflows).

### 1. Full Reverse Engineering of the TI-84 Plus OS
- url: https://siraben.github.io/ti84p-re/ | date: 2026-06-08 (listed; page shows no date) | status: fetched
- what: mdBook wiki documenting TI-84 Plus OS 2.55MP (Z80) from a validated 1 MiB Flash image; separates direct ROM evidence, emulator observations, public hardware behaviour and unresolved inference.
- techniques/tools/formats: Z80 disassembly, banked Flash paging (4-slot), bcall mechanism, VAT, TI-BASIC token stream, OP1-OP6 float registers, MD5 accelerator, Flash image, emulator tracing
- relevance to retool:
  - Per-finding confidence flags (ROM-evidence / emulator / inferred) are a good schema for analysis reports.
  - Banked/paged address spaces need a "bank:offset" address model, not flat VA.
  - The wiki structure (one chapter per subsystem) is a template for LLM-written docs.
- key fact: the target is a 1 MiB Flash image that sees only 64 KiB at a time via paging and bcalls. (src: https://siraben.github.io/ti84p-re/)

### 2. New (Old) 3D Golf: PC-9801 and Virtual Boy to Mega Drive
- url: https://blog.gingerbeardman.com/2026/06/19/new-old-3d-golf-porting-pc-9801-and-virtual-boy-to-mega-drive/ | date: 2026-06-29 on page (edited; URL says 06-19) | status: fetched (only the header and tags were read; body not read)
- what: Porting two old Japanese 3D golf games to Mega Drive. Page tags: reverseengineering, pc98, megadrive, hack, gamedev. (src: same url)
- techniques/tools/formats: (assumption) 68000 disassembly, PC-98 and Virtual Boy course data extraction, conversion to Mega Drive format
- relevance to retool:
  - (assumption) Course/level data in proprietary formats on non-x86 targets; format converters.
  - Not an ELF/PE/Mach-O topic; low direct fit.
- key fact: the post is tagged reverseengineering and covers a 13-minute read about porting golf courses across three platforms. (src: same url)

### 3. IBM MCGA gate arrays
- url: https://github.com/schlae/IBM_MCGA | date: 2026-06-27 (listed) | status: unreachable (direct fetch 403); one WebSearch gave secondary info
- what: Reverse engineering of the two custom gate arrays in IBM's MCGA video chipset (PS/2 Model 25/30): the 72X8300 memory controller (Seiko SLA6430, 4,342 cells) and the 72X8205 video formatter (Seiko SLA6330, 3,312 cells). Schematic and layout are provided. A decapping error ruined the top metal layer on one die. (src: web search summary of the repo, unverified against the page)
- techniques/tools/formats: die decapping, microscope imaging, netlist extraction, KiCad schematics (KiCad claim from a single Chinese-language blog, weaker)
- relevance to retool:
  - Netlist recovery from images/layout is hardware RE and out of scope for ELF/PE/Mach-O static analysis.
  - Found undocumented test registers and genlock support (secondary source), so hidden features need hardware-level evidence.
- key fact: the work found hidden test registers and undocumented genlock support (secondary coverage only). (src: https://www.webpronews.com/ibms-forgotten-mcga-chipset-yields-secrets-decades-later/)

### 4. Decomp Academy
- url: https://decomp-academy.dev/ | date: 2026-06-28 (listed) | status: fetched
- what: Interactive curriculum teaching matching decompilation. You read the asm, write C, and the compiler checks the result byte-for-byte. Covers GameCube (263 exercises), GBA (251) and N64 (241). Starts with PowerPC registers and reading MWCC output, then arithmetic idioms (division by constants, multiply by shifts).
- techniques/tools/formats: matching decompilation, MWCC (Metrowerks) compiler, PowerPC asm, compiler idiom catalogue
- relevance to retool:
  - A catalogue of compiler idioms (division by constant, "modulo has no instruction") could feed pattern recognisers or LLM prompts.
  - Byte-exact compile-and-compare is an objective success check for LLM decompilation.
  - Not ELF/PE/Mach-O specific.
- key fact: the course has 263 GameCube exercises and grades answers by compiling and comparing bytes. (src: https://decomp-academy.dev/)

### 5. The art and engineering of Sega CD Silpheed (FMV format)
- url: https://fabiensanglard.net/silpheed/index.html | date: June 1, 2026 on page (the brief listed 2026-07-13) | status: fetched (full page)
- what: Sanglard says he reverse engineered the FMV format in about two weeks of spare time and "did not write a single line of code". He says he designed tools but cannot say he "wrote" them (he built a storyboard of all cutscenes and background videos with them). The page describes the resulting format. It does NOT describe how the AI framework was driven, what the agent did, which tools it built (beyond the storyboard), how codec hypotheses were validated, or any AI pitfalls. He says the AI framework write-up and open-sourcing come "next month" (src: https://fabiensanglard.net/silpheed/index.html).
- techniques/tools/formats: per-frame self-contained codec (no delta); 8x8 tiles of 4-bit pixels; 768-tile 32x28 tilemap; single-colour tiles stored once and referenced (frame 44: 456 of 896 tiles reuse 15 plain tiles, about 50% saved); two-colour tiles regenerated by the Mega-CD ASIC "font bit" registers ($FF804D colour pair, $FF804E 16-bit pattern, read back $FF8050-$FF8056), 234 of 440 remaining tiles, about 37% saved on the remainder, 206 raw; tilemap = 768-bit bitmap (0 = auto-increment index, 1 = read immediate), 96 + 556 bytes = 652 vs 960; palette-cycling of 4 reserved colours (gameplay limited to 12 colours).
- relevance to retool:
  - Format analysis was driven by hardware constraints (150 KiB/s, 15 fps, about 8 KiB per frame); a "byte budget" check is a quick plausibility test for codec hypotheses.
  - Hardware side effects (ASIC registers used as a decompressor) mean the format cannot be understood from data alone, so an analyser needs the target's I/O map.
  - A generated storyboard of all assets is a concrete agent-built artefact for checking decode correctness visually.
- key fact: Silpheed's frames are self-contained (no delta), with a bitmap tilemap and ASIC-assisted two-colour tiles; the author wrote no code himself. (src: https://fabiensanglard.net/silpheed/index.html)
- pitfalls named by the page: none about AI. Format-specific oddities only: Stage 1 and Stage 10 "fractal" textures defeat the tile tricks, so all tiles are raw and the rate drops to 7.5 fps.
- gap: the AI workflow detail is not on this page; it is promised in a separate post ("next month", i.e. July 2026), not located (unverified whether it exists).

### 6. Plants vs. Zombies PS2 decompilation fork (OptiJuegos/pvz-ps2)
- url: https://github.com/OptiJuegos/pvz-ps2 | date: 2026-07-24 (listed) | status: unreachable (403); one WebSearch gave secondary info
- what: A PS2 port built on a PvZ GOTY decompilation (a fork of Patoke's, via re-plants-vs-zombies), using SDL and OpenGL. Boots from a memory card and needs the original game data. Warns of slow loading and crashes. (src: https://zeli.app/en/story/49035740, secondary; the OptiJuegos to re-plants-vs-zombies link is unconfirmed)
- techniques/tools/formats: decompilation-based porting, SDL/OpenGL, replacing Windows-only code and audio libraries
- relevance to retool:
  - Decompiled source as a basis for porting, not an analysis technique.
  - Weak fit.
- key fact: the PS2 port is based on a GOTY decompilation and needs the user's original game data. (src: https://zeli.app/en/story/49035740)

### 7. libsm64
- url: https://github.com/libsm64/libsm64 | date: 2026-07-27 (listed) | status: unreachable (403); one WebSearch gave secondary info
- what: Packages SM64 decompilation movement and rendering code as a shared library with a single-header API and a sample in the test directory. It loads an official ROM at runtime for textures and animations. Bindings exist for Unity, Blender and Godot; one source also lists Rust and WASM. (src: https://www.drweb.de/libsm64-mario-64-als-programmbibliothek-fuer-eigene-engines/, https://zeli.app/en/story/49067352, secondary)
- techniques/tools/formats: decompilation reuse, runtime ROM asset extraction, C ABI
- relevance to retool:
  - The "do not ship copyrighted assets; extract from the user's file at runtime" pattern is relevant to retool's handling of samples.
  - Not an analysis technique.
- key fact: the library loads textures and animations from the user's ROM at runtime because the decompilation does not include them. (src: https://zeli.app/en/story/49067352)

### 8. Flume Water Monitor 915 MHz signal security
- url: https://waveformsecurity.com/blog/flume/ | date: Jul 28, 2026 on page (listed 07-30) | status: fetched (intro and modulation section read; cipher analysis not read)
- what: Captured the sensor-to-bridge link with a LimeSDR Mini. FCC filings show 50-channel hopping across 902.5-927 MHz. The signal is 2-FSK at 200 kbps with about 25-byte messages. Part of each message is whitened by the RFM69 chip, and CRC-16 (poly 0x1021) seed and XOR were found by exhaustive search. The encryption was defeated in a few weeks of part-time work, helped by Steve Crosby's earlier RE.
- techniques/tools/formats: SDR capture, FSK demodulation, RFM69 whitening (starts FF 87 B8 89), CRC-16 parameter brute force, FCC filing lookup
- relevance to retool:
  - CRC parameter search (poly known, init/xorout brute-forced) is a reusable helper for unknown-format checksums.
  - Weak fit for ELF/PE/Mach-O, but good for a "checksum detector" feature.
- key fact: CRC-16 used poly 0x1021 with seed and XOR options found by exhaustive search. (src: https://waveformsecurity.com/blog/flume/)

### 9. Can you reverse engineer an ASIC? (Jane Street)
- url: https://blog.janestreet.com/can-you-reverse-engineer-an-asic/ | date: Aug 05, 2026 | status: fetched
- what: A puzzle that gives the final mask of a designed chip as a GDS file (metal, routing and active layers) plus sample inputs and outputs. The task is to recover a netlist, work out the chip's purpose, then use it to find a hidden string. Nothing in the GDS is labelled, and the layout is arranged to hint at function.
- techniques/tools/formats: GDS layout, netlist extraction, Verilog/synthesis/place-and-route background, logic reconstruction
- relevance to retool:
  - GDS parsing is outside current scope; a GDS reader is a possible far-future context.
  - A staged challenge (warm-up with design, then real puzzle) is a model for test fixtures.
- key fact: the GDS contains every polygon on every layer but no labels, so the netlist must be recovered first. (src: https://blog.janestreet.com/can-you-reverse-engineer-an-asic/)

### 10. What happens when a GPU reads memory (RTX 4090)
- url: https://blog.doubleword.ai/what-happens-when-a-gpu-reads-memory | date: not on page (listed 2026-08-21) | status: fetched (intro only; measured numbers not read)
- what: Follows one SASS global-load instruction of a vector-add kernel through the hardware. NVIDIA does not document the path, so the author infers it from timing experiments (microbenchmarks) on an RTX 4090.
- techniques/tools/formats: SASS inspection, CUDA microbenchmarking, latency/timing experiments
- relevance to retool:
  - Black-box inference from timing is a technique for undocumented hardware, not for static file analysis.
  - Low relevance; SASS could be a future disassembly target (assumption).
- key fact: the data path is undocumented, so it is determined by running timing experiments on the hardware. (src: https://blog.doubleword.ai/what-happens-when-a-gpu-reads-memory)

### 11. Kodak DC50 driver for Apple II
- url: https://www.colino.net/wordpress/archives/2026/08/23/kodak-dc50-now-usable-on-the-apple-ii/ | date: 2026/08/23 | status: fetched
- what: Adds Kodak DC50 Zoom support to the Quicktake for Apple II program: download, thumbnails, settings, delete, 115200 bps serial. The KDC image format is RADC-compressed, so the Quicktake 150 decoder is reused. Resolution 756x504 is cropped to 640x480 for the 256x192 renderer.
- techniques/tools/formats: dcraw (RADC), libgphoto2 DC120 code, kdcpi Perl tool (buggy), official Kodak pta31.exe (Win 3.1), serial packet protocol, KDC/RADC
- relevance to retool:
  - Cross-checking several imperfect reference implementations (and noting where they disagree) matches the "sources disagree" rule.
  - Protocol and format reuse across sibling devices is a useful heuristic.
- key fact: the DC50 protocol differs from the DC120 in libgphoto2, so that code gave only part of the commands and packet format. (src: https://www.colino.net/wordpress/archives/2026/08/23/kodak-dc50-now-usable-on-the-apple-ii/)

### 12. Decompiling a Nintendo 64 game in 84 days
- url: https://blog.chrislewis.au/decompiling-a-nintendo-64-game-in-84-days/ | date: 26 Aug, 2026 | status: fetched
- what: Snowboard Kids reached 100% matching decompilation (2,145 functions) in 84 days, versus 596 days for Snowboard Kids 2, using LLM agents. Agents ran across 4 git worktrees. Agents reused libultra/libmus source and m2c, and recorded IDO compiler quirks in DECOMPILATION_LEARNINGS.md.
- techniques/tools/formats: matching decompilation, IDO compiler, m2c, decomp-permuter, N64Sym (library function ID), N64 Decomp Workbench (mismatch classification, pass replay), Nigel --shard, similarity search across worktrees
- relevance to retool:
  - Cheap deterministic pass before LLM spend: m2c over all functions matched only 17 of 1,830 (0.93%) but cost no tokens.
  - Per-task deadlines, a shared learnings file, and similarity search over matched functions as agent context.
  - Pitfall: agents re-decompiled library functions unless told to use the existing source.
- key fact: Snowboard Kids took 84 days against 596 for the sequel, and the author says AI is only part of the reason. (src: https://blog.chrislewis.au/decompiling-a-nintendo-64-game-in-84-days/)

### 13. Jane Street ASIC RE challenge solved (jestoph)
- url: https://jestoph.com/2026/09/04/jane-street-challenge.html | date: 2026-09-04 (URL) | status: fetched (intro only; solution steps not read)
- what: Overview of a month-long solve of the GDS challenge: a warm-up with more information, then the real puzzle. He started by poking at the files without research, and promises per-step posts and published code.
- techniques/tools/formats: GDS parsing, netlist recovery (assumption: details not read)
- relevance to retool:
  - Same as note 9; only the workflow of exploring unknown files with no tooling is shown in what was read.
  - Low direct relevance.
- key fact: the challenge had a warm-up with design information and a real puzzle with only the layout. (src: https://jestoph.com/2026/09/04/jane-street-challenge.html)

### 14. Reverse-Engineering LogiCola
- url: https://logicola.org/blog/the-new-logicola | date: Sep 8, 2026 | status: fetched (intro only; RE details not read)
- what: Product post about the new LogiCola design language, built from what the author found reverse engineering the 2008 original Windows app. The new version is cross-platform (Chromebooks, phones) and aims to preserve Professor Gensler's work.
- techniques/tools/formats: (assumption) analysis of a 2008 Windows binary and its UI/content; details not read
- relevance to retool:
  - Preservation and porting of legacy Windows software is a plausible PE use case.
  - Little technical content seen.
- key fact: the new version is based on findings from reverse engineering the 2008 original. (src: https://logicola.org/blog/the-new-logicola)
