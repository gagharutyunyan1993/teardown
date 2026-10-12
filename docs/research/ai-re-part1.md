# Research digest — AI-assisted reverse engineering, part 1 (2026-06 … 2026-08)

Source: reading list supplied by the user on 2026-10-11; notes produced by the researcher worker on 2026-10-11.
Markers: `status: fetched|unreachable` — whether the page itself was read; `(src: url)` — fact taken from that page; `(assumption)` — not verified against a source.
Context: retool (Python 3.12 toolkit for static analysis of ELF/PE/Mach-O, LLM-assisted workflows).

### 1. LLM-Assisted RE of Proprietary IoT Protocol (Midea/MDV)
- url: https://t.me/neuraldeep/2168 | date: 2026-06-04 (from brief) | status: unreachable (unverified)
- what: Fetch returned only the Telegram embed shell (HTTP 200, no post text). One WebSearch found no mirror. (assumption) LLM agent reverses a Midea/MDV appliance wire protocol from captures.
- techniques/tools/formats: (assumption) UART/serial captures, frame/checksum inference, LLM agent loop
- relevance to retool:
  - (assumption) a protocol/frame-structure inference helper (field boundaries, checksum detection) for non-ELF blobs
- key fact: Page body not retrievable; nothing verified. (src: https://t.me/neuraldeep/2168)

### 2. LLM Agent-Assisted RE with Quantitative Readability Metrics
- url: https://arxiv.org/abs/2606.06838 | date: 2026-06-05 (v1) | status: fetched (abstract only)
- what: Authors Archibald and Thijssen use LLM agents to improve readability of decompiled C. Three phases: Ghidra-MCP steering, structural-similarity validation alone, then the QRS framework.
- techniques/tools/formats: Ghidra MCP, decompiler output cleanup, Quantitative Readability Score (structural-similarity gate + Lexical Surprisal, Structural Simplicity, Idiomatic Quality)
- relevance to retool:
  - Gate any LLM rewrite with a correctness check (structural similarity) plus separate readability metrics.
  - Pitfall: agents game a single metric and yield equivalent but less readable code; use several independent metrics.
  - Full-tool-coverage steering alone gave inconsistent results.
- key fact: Metric-only validation made agents "optimize for metrics in unintended ways"; QRS combines a similarity gate with 3 sub-metrics. (src: https://arxiv.org/abs/2606.06838)

### 3. AI-Assisted Firmware RE for Coreboot (ThinkPad x61)
- url: https://blog.aheymans.xyz/post/thinkpad_x61/ | date: 2026-06-04 (post date on page; brief says 06-09) | status: fetched
- what: Claude Opus 4.6 helped port the GM965/ICH8 ThinkPad x61 to coreboot from a Phoenix BIOS image. Author split the image with bios_extract and gave the agent ghidra-cli plus a SKILL.md and a radare2 skill.
- techniques/tools/formats: Phoenix BIOS modules, bios_extract, ghidra-cli, radare2 (16-bit real mode), PE32 raminit (Intel MRC-like), SerialICE traces, inteltool, acpidump/iasl, ectool, flashprog (ch341a, Intel descriptor)
- relevance to retool:
  - Firmware container splitting should come first, then per-module analysis (16-bit real-mode glue vs PE32 module).
  - Different backends suit different code: Ghidra decompiler for C-origin PE32, radare2 for real mode.
  - Pitfall: the "2 prompts, done" claim is retracted by the author. Over 20 manual steering corrections were needed from expert knowledge, and known-good runtime dumps/traces were the reference.
- key fact: The author calls his own "vibe RE" section "a complete lie"; the model needed heavy hand-holding. (src: https://blog.aheymans.xyz/post/thinkpad_x61/)

### 4. Rigel: RE of Metal 4.1 Tensor Path on Apple M4 Max
- url: https://arxiv.org/abs/2606.12765 | date: 2026-06-11 | status: fetched (abstract only)
- what: Black-box microbenchmark characterization of Metal Performance Primitives matmul2d on one M4 Max. A checksum-gated, provenance-tracked harness recovers 11 undocumented facts.
- techniques/tools/formats: microbenchmarks, per-rail power attribution, throughput triangulation, cooperative_tensor fragment layout reconstruction
- relevance to retool:
  - Provenance-tracked, reproducible findings (per-cell CSVs, checksums) is a model for retool reports.
  - Not a static-binary-analysis paper, so low direct relevance. (assumption)
- key fact: Metal 4.1 fp8 matmul2d is emulated, running at 0.94x fp16 throughput, and runs entirely on GPU shader cores. (src: https://arxiv.org/abs/2606.12765)

### 5. Show HN: Reverse-engineering web apps into agent tools
- url: https://news.ycombinator.com/item?id=48847834 | date: ~2026-07-09 | status: fetched
- what: A browser agent inside an authenticated web app watches the app's own API calls and auto-generates agent tools, described as a self-updating MCP server. HN comments (40) debate ToS and legal risk.
- techniques/tools/formats: in-page API observation, auto-generated MCP tools, auth/header/cookie handling
- relevance to retool:
  - Low relevance to binary analysis.
  - Pitfall: legal/ToS risk of using extracted tokens. The vendor's reply says they work only with the app owner's consent.
  - Observed manual pain: header and cookie handling.
- key fact: Commenters report manual DevTools RE is tedious mainly because of header/cookie handling and API drift. (src: https://news.ycombinator.com/item?id=48847834)

### 6. REFORGE: LLM benchmark on decompiled function naming
- url: https://arxiv.org/abs/2607.07738 | date: 2026-07-07 (v1), v2 2026-07-24 | status: fetched (abstract only)
- what: Provenance-tracked pipeline builds function-level ground truth: C source, compile, DWARF and syntactic extraction, alignment, decompile. Alignment uncertainty is modeled as an eight-gate confidence funnel with three tiers. Seven LLMs were tested on function naming.
- techniques/tools/formats: DWARF, decompilation, binary-to-source alignment, confidence stratification, benchmarking
- relevance to retool:
  - Use DWARF-derived ground truth with explicit alignment-confidence tiers to evaluate any LLM naming feature.
  - Pitfall: unpaired comparisons across optimization levels suffer survivorship bias.
- key fact: High-confidence ground-truth yield drops from 87.2% to 65.9% across optimization levels. (src: https://arxiv.org/abs/2607.07738)

### 7. Simon Willison: Reverse-engineering is cheap now
- url: https://simonwillison.net/2026/Jul/20/cheap-reverse-engineering/ | date: 2026-07-20 | status: fetched
- what: Short note on anecdotes of people using coding agents to reverse-engineer and automate home devices. The argument is economic: cheaper code lowers the ROI barrier and the maintenance fear.
- techniques/tools/formats: coding agents, undocumented device APIs
- relevance to retool:
  - Throwaway or regenerable RE scripts are acceptable. Design for cheap re-runs rather than long-lived hand-maintained parsers.
- key fact: Agents reduce the cost of trying and failing, so maintaining or discarding fragile undocumented-API code "carries way less psychological baggage." (src: https://simonwillison.net/2026/Jul/20/cheap-reverse-engineering/)

### 8. Reverse-engineering Yandex Lavka into an MCP ordering server
- url: https://habr.com/ru/articles/1062042/ | date: 2026-07-22 | status: fetched (first part read)
- what: Unofficial MCP server for ordering from Yandex Lavka. The author inspected logged-in Chrome Network traffic plus a fetch interceptor, recovered the /api/v1/providers/* endpoints, and copied request bodies from live traffic.
- techniques/tools/formats: Chrome DevTools Network, fetch interceptor, MCP tools (search_products, add_to_cart, checkout_preview), Python
- relevance to retool:
  - Low relevance to binary parsing.
  - Pitfalls: private web API needs CSRF token and extra headers (401 even with cookies); the author warns of ToS and API-change risk and that checkout has real side effects.
  - Pattern: expose RE results as MCP tools with a preview-before-commit step.
- key fact: POST requests returned 401 despite valid session cookies until X-CSRF-Token and X-Lavka-Web-City were added. (src: https://habr.com/ru/articles/1062042/)

### 9. Kuna: Decompiler Development in the Age of Coding Agents
- url: https://noelo.org/blog/kuna-release/ | date: 2026-07-30 | status: fetched
- what: Experimental decompiler, a Rust port of Ghidra reworked toward angr's pipeline, written almost entirely by an LLM. It improves through autonomous refinement against IDA, Ghidra and angr outputs on structuring metrics.
- techniques/tools/formats: Ghidra, angr, IDA Pro 9.2, control-flow structuring metrics, LLM refinement loop, Rust
- relevance to retool:
  - Metric-driven agent loops against reference decompilers need good benchmark metrics first.
  - The author stresses human scientific insight is required; it is not automatic research.
  - Gaps remain: types, optimizations, recompilability, variable identification.
- key fact: Perfect structuring on 44.4% of functions vs IDA's 45.7%. (src: https://noelo.org/blog/kuna-release/)

### 10. Agent-Based Specification RE (SDD on existing projects)
- url: https://habr.com/ru/articles/1064628/ | date: 2026-07-30 | status: fetched
- what: "Reverse engineering" here means code-to-spec, not binary RE. The author used a Spec Kit brownfield extension so an agent writes specs retroactively from an existing multi-subsystem codebase, with a read-only scan first and human review.
- techniques/tools/formats: Spec Kit (constitution, specify, plan, tasks), markdown prompt commands, agent-written specs
- relevance to retool:
  - Off-topic for binary analysis (assumption).
  - Process idea: start with a read-only scan and have the human review the output.
- key fact: Spec Kit commands are markdown prompts, so the extension source can be read before install. (src: https://habr.com/ru/articles/1064628/)

### 11. REpsych: Encoding Images into Control Flow Graphs
- url: https://github.com/xoreaxeaxeax/repsych | date: 2026-08-07 (brief) | status: unreachable (direct fetch 403; search found the Battelle/REpsych mirror, not fetched)
- what: Per the search summary only: a toolset that turns an image into a working program whose CFG renders that image, one basic block per pixel, in v1 and v2 variants. Works with IDA, semi-reliably with Hopper, BinNavi and radare2.
- techniques/tools/formats: CFG layout, basic blocks, 24 BPP bitmaps, DEF CON talk
- relevance to retool:
  - A hostile-input test case: huge or adversarial CFGs (one block per pixel) for graph-size limits in CFG builders.
  - CFG renderers differ in layout behavior.
- key fact: Each pixel becomes a basic block, so inputs of about 100x100 or less are recommended. (src: https://github.com/Battelle/REpsych, via search summary, page not read)

### 12. Reverse Engineering GitHub Copilot's Network Traffic
- url: https://www.lighthousenewsletter.com/p/i-put-github-copilot-behind-a-mitm | date: 2026-08-04 (on page; brief says 08-11) | status: fetched (paywalled, intro and setup only)
- what: The author put VS Code and Copilot behind mitmproxy, watching traffic first and reading source second. The fetched part covers Electron's network architecture and the CA-trust MITM setup. Findings are behind the paywall.
- techniques/tools/formats: mitmproxy, TLS MITM via local CA, Electron/Chromium vs Node networking, VS Code extension host
- relevance to retool:
  - Dynamic traffic observation to decide which questions to ask is a sensible first step before source reading.
  - Low relevance to static ELF/PE/Mach-O.
- key fact: Which network path a request takes (Chromium stack vs Node http/fetch) determines whether it can be intercepted. (src: https://www.lighthousenewsletter.com/p/i-put-github-copilot-behind-a-mitm)

### 13. Inside DeepSeek: RE an AI Assistant by Interviewing Itself
- url: https://manish.sh/writings/models/inside-deepseek-reverse-engineering-an-ai-assistant-by-interviewing-itself | date: published 2026-07-21 (brief 08-11) | status: fetched (intro and TL;DR only)
- what: Interviews a chat model about itself, then audits its claims against public arXiv papers. No weights or prompts were leaked.
- techniques/tools/formats: self-report interview, claim auditing against papers (MoE, MLA)
- relevance to retool:
  - Not binary RE; low relevance.
  - Pitfall: a model's self-description is unreliable. Label observation, inference and guess separately in LLM outputs.
- key fact: Architecture numbers should come from papers, not from the chat. The model hedged on facts V3 documents plainly. (src: https://manish.sh/writings/models/inside-deepseek-reverse-engineering-an-ai-assistant-by-interviewing-itself)

### 14. Claude Code reverse-engineered macOS support for HP LaserJet 1008a
- url: https://cdn.kuber.studio/chat/hp-laser-1008a-driver | date: 2026-08-17 session (brief 08-18) | status: fetched (header only; transcript body not read)
- what: A rendered Claude Code (Opus 4.8) transcript of about a 4-hour session. Per the header: reverse-engineered the SPL3 raster language and ran HP's real codec in a Linux container. Details were not read.
- techniques/tools/formats: SPL3 printer raster language, Linux container for vendor codec, native macOS printing
- relevance to retool:
  - Run vendor binaries only in an isolated container, as the page does. retool's rule that samples are never executed conflicts with that approach, so it would need an explicit sandbox policy.
  - Format-RE of an undocumented stream via a vendor oracle (compare output of the real codec with a re-implementation).
- key fact: The vendor's own codec was used as a reference oracle in a Linux container. (src: https://cdn.kuber.studio/chat/hp-laser-1008a-driver)
