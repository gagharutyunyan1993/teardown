# Research synthesis — what the 2026-06…10 reading list implies for retool

Date: 2026-10-11. Inputs: `ai-re-part1`, `ai-re-part2`, `classic-re-part1`, `classic-re-part2` (researcher notes, 2026-10-11) and `docs/architecture/ARCHITECTURE.md`.
Citations: `(digest §N)` = note N of that digest; project facts cite `ARCHITECTURE.md` / `CLAUDE.md`. Factual claims with neither are marked `(assumption)`.
Caveat: each digest's "relevance to retool" bullets are the researcher's inference, not source facts. "Why" lines, ranks and fit tags here are this synthesis's reasoning over the cited notes.
Fit tags: `core` = ELF/PE/Mach-O static analysis; `adjacent` = raw firmware, checksums, LLM workflow, reports; `out-of-scope` = hardware/GDS/SDR/web-API.

## Evidence base

| digest | notes | fetched, full | fetched, partial (abstract/intro/header) | unreachable |
|---|---|---|---|---|
| ai-re-part1 | 14 | 5 | 7 (§2, §4, §6, §8, §12, §13, §14) | 2 (§1, §11) |
| ai-re-part2 | 13 | 13 | 0 | 0 |
| classic-re-part1 | 14 | 6 | 5 (§2, §8, §10, §13, §14) | 3 (§3, §6, §7) |
| classic-re-part2 | 13 | 4 | 6 (§2, §5, §6, §7, §8, §9) | 3 (§4, §12, §13) |
| **total** | **54** | **28** | **18** | **8** |

- Count check: the digests hold 54 notes, not 55. Unreachable = 7 GitHub repos (ai-re-part1 §11; classic-re-part1 §3, §6, §7; classic-re-part2 §4, §12, §13) + 1 Telegram post (ai-re-part1 §1). "6 repos" matches the classic digests only.
- Two GitHub repos were fetched directly (ai-re-part2 §10, §11).

| topic (one bucket per note; classification by this synthesis) | n | notes |
|---|---|---|
| executable / decompiler RE | 18 | ai-re-part1 §2, §6, §9, §11; ai-re-part2 §1, §2, §4, §8, §9, §12, §13; classic-re-part1 §4, §6, §7, §12, §14; classic-re-part2 §4, §12 |
| firmware / ROM images | 8 | ai-re-part1 §3; ai-re-part2 §3, §11; classic-re-part1 §1; classic-re-part2 §2, §3, §9, §13 |
| hardware / silicon / RF / accelerators | 11 | ai-re-part1 §4; ai-re-part2 §6; classic-re-part1 §3, §8, §9, §10, §13; classic-re-part2 §1, §5, §6, §8 |
| device / network protocols | 6 | ai-re-part1 §1, §14; classic-re-part1 §11; classic-re-part2 §7, §10, §11 |
| web / API | 3 | ai-re-part1 §5, §8, §12 |
| other (code-to-spec, LLM self-report, JS source maps, NN reimpl., game/media data) | 8 | ai-re-part1 §7, §10, §13; ai-re-part2 §5, §7, §10; classic-re-part1 §2, §5 |

- Only 3 notes name an ELF/PE/Mach-O artefact: Mach-O kext (ai-re-part2 §1), PE32 module inside a BIOS image (ai-re-part1 §3), PS5 ELF/SELF (classic-re-part2 §12, unreachable); a 4th implies PE (2008 Windows app, classic-re-part1 §14; (assumption)). Decompilation work mostly targets console/retro formats (DOL/REL, N64, GameCube/GBA, 6502).
- 21 notes use an LLM/agent as the RE method (same classification); 2 of those give no method detail (ai-re-part1 §1; classic-re-part1 §5).
- Weak evidence: all 8 unreachable notes; header/title-only reads (ai-re-part1 §14; classic-re-part1 §2; classic-re-part2 §2); news coverage of others' work (ai-re-part2 §13). Medium: abstract-only papers (ai-re-part1 §2, §4, §6).
- Net: the list is strong evidence for **workflow** requirements (validation, provenance, LLM control) and weak evidence for **ELF/PE/Mach-O feature** requirements. Firmware and retro targets dominate the technical content.

## Recurring patterns

1. **Ground-truth loop over narration.** Results are accepted only after comparison with an independent reference: live hardware, runtime traces, debugger repro, emulator screenshots, real traffic (ai-re-part1 §3; ai-re-part2 §1, §3, §4, §9; classic-re-part2 §10).
   Why: retool never executes samples (CLAUDE.md), so it can only *consume* such evidence; its own outputs need a cheap check hook.
2. **Byte-exact verification by hash.** Success = rebuilt or reimplemented output equals the original byte-for-byte, often per stage (classic-re-part1 §4, §12; ai-re-part2 §10; ai-re-part1 §4; classic-re-part2 §4 weak).
   Why: file/section/function hashes are objective, cheap and purely static.
3. **Provenance / confidence tier per finding.** Direct evidence vs observation vs inference vs guess are kept apart (classic-re-part1 §1; ai-re-part1 §4, §6, §13; classic-re-part1 §11).
   Why: reports must say how each fact was obtained; LLM-suggested facts need their own tier.
4. **Cheap deterministic pass before LLM spend.** Split/identify/auto-decompile first; the LLM gets only the residue (classic-re-part1 §12; ai-re-part1 §3; ai-re-part2 §5).
   Why: retool's parsers *are* that pass; their output should be shaped as compact LLM context.
5. **LLM fixation and premature certainty.** Models latch onto a plausible wrong artefact or call a result "definitive" too early; experts steered many times (ai-re-part2 §1, §4; ai-re-part1 §3, §9).
   Why: tooling should make disproof cheap (e.g. "is this class referenced by anything?").
6. **Right-looking but structurally wrong output.** Metric gaming, playable-but-wrong ports, survivorship bias in benchmarks (ai-re-part1 §2, §6; ai-re-part2 §9).
   Why: gates need several independent checks including structural invariants, never one score.
7. **Container first, then per-module analysis.** Firmware is split into modules/partitions; module types need different backends (ai-re-part1 §3; ai-re-part2 §3; classic-re-part2 §3; classic-re-part2 §13 weak).
   Why: ELF/PE often sit *inside* firmware; `formats` identifies only top-level ELF/PE/Mach-O (ARCHITECTURE.md §2).
8. **Raw, headerless or banked images.** Flat flash/ROM dumps with a base address, uncommon ISA or bank paging (classic-re-part1 §1; ai-re-part1 §3; classic-re-part2 §9; classic-re-part2 §2, §13 weak).
   Why: header-driven parsing does not cover them, nor does a flat `Address` (`shared` kernel, ARCHITECTURE.md §2; flatness is (assumption)).
9. **Reference oracles, and references that disagree.** Compare with vendor code, sibling-device code or other decompilers; record disagreement (classic-re-part1 §11; ai-re-part1 §9; ai-re-part2 §1, §10; ai-re-part1 §14 weak).
   Why: tests can cross-check retool's parse against a second parser; reports need a "sources disagree" state.
10. **Security properties as a deliverable.** Integrity-only hash vs signature, signing certificate, keys on device, envelope encryption (ai-re-part2 §2, §3, §8; classic-re-part2 §3; classic-re-part1 §8).
    Why: a recurring user question that static parsing can partly answer.
11. **RE packaged as agent tools.** Ghidra MCP, ghidra-cli + SKILL.md, REA, MCP servers over RE results (ai-re-part1 §2, §3, §5, §8; ai-re-part2 §12; classic-re-part2 §11).
    Why: a coding agent is a likely consumer of retool output, next to a human.
12. **Read-only first, no side effects.** Protect data, call read-only selectors only, preview before commit, never flash without rollback (ai-re-part2 §1; ai-re-part1 §8, §10; classic-re-part2 §13 weak).
    Why: matches retool's stance; any future write/execute path needs an explicit gate.
13. **Durable agent memory and goal contracts.** Learnings files, goal templates, skills, per-task deadlines (classic-re-part1 §12; ai-re-part2 §3, §7, §9; ai-re-part1 §3).
    Why: retool's harness already works this way; the binary-analyst agent can adopt RE-specific templates.
14. **Legal/IP boundaries.** Ship no assets, load them from the user's file; ToS and C&D risk (ai-re-part2 §13; ai-re-part1 §5, §8; classic-re-part1 §6, §7 weak; classic-re-part2 §4 weak).
    Why: reports and fixtures should not embed sample bytes beyond what a finding needs (assumption: no such rule exists yet).

## Candidate capabilities

Ranked by evidence strength, then fit (core before adjacent), then smaller architecture impact.
Strength: **strong** = ≥2 fetched primary sources show the practice; **medium** = 1 fetched source, or abstract/partial reads; **weak** = unreachable, secondary or `(assumption)` only.
Strength rates the practice in the sources; that retool needs it is inference.

| # | capability | fit | supporting notes | strength | architecture impact |
|---|---|---|---|---|---|
| 1 | Byte-exact compare of two binaries: file hash, per-section/segment hash, first differing offset | fit: core | classic-re-part1 §4, §12; ai-re-part2 §10; classic-re-part2 §4 (weak) | strong | existing `formats` + new use case; placement is /decide Q6 |
| 2 | Security-properties summary: code-signature presence ((assumption): Mach-O `LC_CODE_SIGNATURE`, PE certificate table), appended-hash detection, embedded certs/keys | fit: core | ai-re-part2 §2, §3, §8; classic-re-part2 §3 | strong | existing `formats` (structures) + `analysis` (summary); new aggregate → architect |
| 3 | Mach-O kext/framework metadata: IOKit dispatch tables (selector, method, in/out sizes), Obj-C class/selector lists, "referenced by any image?" check | fit: core | ai-re-part2 §1, §4 | strong | existing `formats` + `analysis` xrefs; multi-binary input → architect |
| 4 | Compiler-idiom annotations (division by constant, multiply by shifts) | fit: core | classic-re-part1 §4, §12 | strong | existing `disasm`/`analysis` (planned) |
| 5 | Provenance-tiered findings (parsed / disassembled / inferred / LLM-suggested) incl. explicit "not analysed: reason" | fit: adjacent | classic-re-part1 §1; ai-re-part2 §2; ai-re-part1 §6, §13; classic-re-part2 §8 | strong | shared-kernel vs `reporting` type → architect + /decide Q2 |
| 6 | Agent tool surface: retool use cases callable by a coding agent (MCP or JSON CLI), read-only by default | fit: adjacent | ai-re-part1 §2, §3, §8; ai-re-part2 §12; classic-re-part2 §11 | strong | new `interface` adapter + dependency → architect + /decide Q3 |
| 7 | LLM-output gate: accept an LLM rename/rewrite only after a correctness check (structural similarity or recompile + byte compare) plus several independent metrics | fit: adjacent | ai-re-part1 §2, §9; ai-re-part2 §9; classic-re-part1 §4 | strong | new port (model client) or new context → architect + /decide Q8 |
| 8 | Firmware container splitting (BIOS modules, partitions, FAT/update packages) handing embedded ELF/PE to `formats` | fit: adjacent | ai-re-part1 §3; ai-re-part2 §3; classic-re-part2 §3; classic-re-part2 §13 (weak) | strong | new context → architect + /decide Q1 |
| 9 | Disassembly for uncommon ISAs (Z80, PowerPC, 16-bit real mode, 6502, pi32v2) | fit: adjacent | classic-re-part1 §1, §4; ai-re-part1 §3; classic-re-part2 §9; classic-re-part2 §13 (weak) | strong | `disasm` backend dependency → /decide (ISA list from Q1) |
| 10 | Read-only import of external evidence (runtime traces, dumps, captures) to cross-check static findings | fit: adjacent | ai-re-part1 §3; ai-re-part2 §4; classic-re-part2 §10 | strong (practice); need is (assumption) | new port + input types → architect + /decide Q5 |
| 11 | RE session templates for the binary-analyst agent: goal contract, learnings file, read-only phase, per-task deadline | fit: adjacent | ai-re-part2 §3; classic-re-part1 §12; ai-re-part1 §3 | strong | harness only (`.claude/`), no context change |
| 12 | Xref / call-site map for security-relevant functions (signature verify, crypto, licence checks) | fit: core | ai-re-part2 §2; ai-re-part2 §8 | medium (§8 shows the target, not the method) | existing `analysis` (planned xrefs) |
| 13 | Library-function identification + similarity to already-analysed functions | fit: core | classic-re-part1 §12 | medium | `analysis` + new port for signature data → architect + /decide Q7 |
| 14 | Corpus mode: identify and validate every file under a directory, list parse failures | fit: core | ai-re-part2 §5 | medium | `interface` command over existing `formats`; no context change |
| 15 | x87 / special-case-heavy instructions covered by edge-case tests | fit: core | classic-re-part2 §1, §5 | medium (silicon sources; relevance inferred) | existing `disasm` (planned) |
| 16 | JSON report with input hash and per-stage hashes for reproducibility | fit: adjacent | ai-re-part2 §10; ai-re-part1 §4; classic-re-part2 §2 (weak) | medium | existing `reporting` (planned: text, JSON) |
| 17 | Raw image loader: base address, arch hint, bank:offset addressing | fit: adjacent | classic-re-part1 §1; ai-re-part1 §3; classic-re-part2 §9; classic-re-part2 §2, §13 (weak) | medium (explicit "raw mode" ask is in weak notes) | changes `shared.Address` + new `Format` → architect + /decide Q1 |
| 18 | Checksum/CRC detection and parameter search (poly/init/xorout; appended MD5) | fit: adjacent | classic-re-part1 §8; ai-re-part2 §3; ai-re-part1 §1 (weak) | medium | new domain service, context undecided → /decide Q1 |
| 19 | LLM evaluation harness: DWARF-derived ground truth with alignment-confidence tiers, paired across optimisation levels | fit: adjacent | ai-re-part1 §6; classic-re-part1 §12 | medium (paper read as abstract) | DWARF in `formats`; product vs `tools/` → /decide Q8 |
| 20 | Hard caps for CFG/graph construction against adversarial layouts | fit: core | ai-re-part1 §11 (weak) | weak | existing rule (`MAX_*` constants, ARCHITECTURE.md §4) in `analysis` |
| 21 | ELF dialects (PS4/PS5 SELF, NID imports) and Apple boot objects | fit: core | classic-re-part2 §12 (weak), §8 | weak | new parser strategies in existing `formats` |

## LLM-assisted workflow: lessons

| pitfall | control | sources |
|---|---|---|
| Agents game a single metric; output equivalent but less readable | correctness gate + several independent metrics | ai-re-part1 §2 |
| Tool-coverage steering alone gives inconsistent results | add an explicit validation phase | ai-re-part1 §2 |
| "Definitive" declared too early (twice), model wants to quit | per-claim evidence tier; human pushback; external lookup | ai-re-part2 §1 |
| Fixation on a plausible-but-wrong artefact, carried until context overflow | cheap static disproof (reference check); human debugger repro; fresh context | ai-re-part2 §4 |
| Autonomy overstated ("2 prompts"); 20+ expert corrections needed | budget expert steering; record corrections as learnings | ai-re-part1 §3, §9 |
| Agents re-decompile library code | library ID first; point the agent at existing source | classic-re-part1 §12 |
| Structurally wrong, surface-plausible result (tile-hop vs per-frame animation) | closed loop against reference behaviour; check structure, not looks | ai-re-part2 §9 |
| Model self-reports are unreliable | label observation / inference / guess; check against primary docs | ai-re-part1 §13 |
| Build-target mismatch (arm64e vs arm64) | mechanical architecture check on produced artefacts | ai-re-part2 §1 |
| Survivorship bias across optimisation levels | paired comparisons; confidence-tiered ground truth | ai-re-part1 §6 |
| LLM-derived spec not yet validated | test against real data/traffic before implementing | classic-re-part2 §10 |
| Tokens spent on easy cases | deterministic pass first (m2c: 17/1,830 at zero tokens); shared learnings; deadlines; parallel worktrees | classic-re-part1 §12 |
| Side effects on real systems | read-only selectors, data-protection phase, preview-before-commit, no flashing | ai-re-part2 §1; ai-re-part1 §8; classic-re-part2 §13 (weak) |
| Closed agents upload workspace + git history; config-borne injection | local-only tools, no uploads, config snapshot at startup, tools grouped by safety class | ai-re-part2 §7, §8 |
| Capability claims without method or reproduction | treat as weak until reproduced | classic-re-part1 §5; classic-re-part2 §12 (weak); ai-re-part2 §13 |

## Explicitly out of scope (for now)

- `fit: out-of-scope` Silicon/die/microcode RE, netlists (classic-re-part1 §3, §9, §13; classic-re-part2 §1, §5) — no file format; needs imaging.
- `fit: out-of-scope` GDS layout reader (classic-re-part1 §9, §13) — chip-design format, not an executable.
- `fit: out-of-scope` SDR/RF demodulation (classic-re-part1 §8) — signal processing; only its CRC search survives as #18.
- `fit: out-of-scope` Web/API RE, browser interception, MITM (ai-re-part1 §5, §8, §12) — live network + ToS risk; no network for samples (CLAUDE.md).
- `fit: out-of-scope` Live protocol discovery: DNS spoofing, IoT handshakes, captures (ai-re-part1 §1; classic-re-part2 §7, §10, §11) — needs live devices; capture *import* is Q5.
- `fit: out-of-scope` Executing samples: emulators, debuggers, vendor codecs in containers, RAM injection (ai-re-part1 §14; ai-re-part2 §4, §9, §11) — contradicts "never executed" (CLAUDE.md); only Q4 could change it.
- `fit: out-of-scope` GPU/accelerator black-box microbenchmarks (ai-re-part1 §4; classic-re-part1 §10; ai-re-part2 §6) — runtime measurement of hardware.
- `fit: out-of-scope` Porting, relinking, recompiling, bit-exact reimplementation (classic-re-part2 §12; ai-re-part2 §10, §13; classic-re-part1 §6, §7) — produces new software; IP risk.
- `fit: out-of-scope` Media/codec decoders, game-data converters, device image formats (classic-re-part1 §2, §5, §11) — per-format, no ELF/PE/Mach-O link.
- `fit: out-of-scope` Non-binary "RE": code-to-spec, LLM self-interviews, JS source maps (ai-re-part1 §10, §13; ai-re-part2 §7) — different input class.
- `fit: out-of-scope` Flashing or custom updaters (ai-re-part2 §3; classic-re-part2 §13 (weak)) — irreversible side effects.

## Open questions for /decide

1. **Firmware/raw images:** new bounded context (container split, raw loader, checksums; rows 8, 17, 18) or out of product? Settled by: the user's actual input mix (ELF/PE/Mach-O vs firmware/raw) and the ISA list it implies; whether any target needs bank:offset addressing.
2. **Findings model:** provenance/confidence type in `shared` kernel or owned by `reporting`? Settled by: whether ≥2 contexts must construct findings, per the first two feature specs.
3. **Agent tool surface:** MCP adapter in `interface`, or JSON CLI only? Settled by: the user's primary consumer (human vs agent) and a dated primary-source check of the MCP Python SDK licence and release cadence (assumption: such an SDK exists).
4. **Execution policy:** may retool ever run a vendor oracle or emulator in a sandbox? Settled by: the user's explicit safety stance; current rule is never (CLAUDE.md), so default stays "no".
5. **External evidence import:** should retool ingest traces/dumps/captures read-only to cross-check findings (row 10)? Settled by: one concrete user workflow that needs it and its file formats.
6. **Binary compare placement (row 1):** `formats` use case (hashes/sections only), `analysis` (function level), or a new `verification` context? Settled by: whether v1 needs function boundaries or only section bytes.
7. **Library-ID data (row 13):** bundled signatures, user-supplied, or none? Settled by: availability and licence of a signature corpus for the user's toolchains (primary source, dated).
8. **LLM in product vs harness (rows 7, 19):** must any retool command call a model? Settled by: the user's answer; if no, gates and evaluation live in the harness/`tools/`, not in a context.

## Suggested next steps

1. Researcher: re-fetch the 7 unreachable GitHub notes via the `gh` CLI (assumption: it reaches GitHub through the proxy) and update their status; this re-grades rows 1, 8, 9, 17, 20, 21 and pattern 14.
2. Orchestrator: ask the user Q1/Q8 (input mix; LLM in product or not). Rows 7, 8, 9, 17, 18, 19 depend on the answer.
3. `/decide` Q2, then planner spec for provenance-tiered findings + JSON rendering in `reporting` (rows 5, 16).
4. Planner spec: `retool compare <a> <b>` — file and per-section hashes, first differing offset (row 1), after Q6.
5. Planner spec: code-signature presence/summary for Mach-O and PE in `formats` (first slice of row 2).
6. Harness task: RE goal-contract + learnings-file template for the binary-analyst agent (row 11), under `.claude/rules/harness.md`.
