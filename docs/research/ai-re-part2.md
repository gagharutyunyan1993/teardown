# Research digest — AI-assisted reverse engineering, part 2 (2026-08 … 2026-10)

Source: reading list supplied by the user on 2026-10-11; notes produced by the researcher worker on 2026-10-11.
Markers: `status: fetched|unreachable` — whether the page itself was read; `(src: url)` — fact taken from that page; `(assumption)` — not verified against a source.
Context: retool (Python 3.12 toolkit for static analysis of ELF/PE/Mach-O, LLM-assisted workflows). Notes 2 and 3 are deliberately summary-level (no step-by-step bypass detail).

### 1. Claude vibe-codes a macOS driver and companion app for an orphaned Drobo 5D
- url: https://fetzu.ch/blog/20260819_claudevsdrobo/ | date: 2026-08-19 (page title "Raiders of the Lost Array") | status: fetched
- what: The author gave Claude Opus 5 the last 5 Drobo driver and Dashboard releases plus the release-note PDFs. Claude worked in phases: protect data, validate protocol, decode payloads, CLI, live driver. It wrote C probe tools (droboprobe, droboesa) and then a DriverKit extension (DroboDext) and ReDrobo.app. (src: url)
- techniques/tools/formats: kext symbol-table and IOUserClient dispatch-table extraction, IOKit/SCSITaskUserClient, DriverKit dext, entitlement brute-force by binary search, protocol reversal of Drobo "ESA" mode pages (1308-byte struct), comparing a working Mac against a non-working one
- relevance to retool:
  - Dispatch-table and selector extraction from a Mach-O kext (selector, method name, in/out sizes) is a concrete Mach-O/IOKit analysis feature.
  - Cross-validate decoded payloads against a live reference (screenshots, a second machine). Only call read-only selectors.
  - Pitfall: the model concluded "definitive" wrongly twice and wanted to quit; human insistence plus web search resolved it. Also arch mismatch: dext built as arm64e instead of arm64.
- key fact: Claude extracted the kext user-client dispatch table (selector 2 = sGetESAModePage, 3 = sSetESAModePage, 1308-byte struct) and used only the read selector to obtain the protocol payloads. (src: https://fetzu.ch/blog/20260819_claudevsdrobo/)

### 2. Qwen 3.8 27B reverse-engineering job vs frontier model
- url: https://www.xda-developers.com/qwen-3-8-27b-reverse-engineering-job-frontier-model/ | date: 2026-08-22 | status: fetched
- what: Author ran a local open-weights model (Qwen 3.8 27B, 17GB VRAM, Pi harness, standard Bash tools only) to audit a commercial app's license-verification scheme; the model worked almost entirely by static analysis and produced a full written report.
- techniques/tools/formats: local LLM via Pi harness, static analysis of arm64 disassembly, code-signing/certificate inspection, Ghidra-class manual RE as comparison, offline signature/RSA license schemes
- relevance to retool:
  - Static-only RE (disassemble, map security functions to call sites) is a viable LLM workflow — no execution needed, fits retool's "inputs are hostile, never run samples" stance.
  - Model checked the signing certificate to detect a false ownership claim — provenance/authenticity checks are worth surfacing in a toolkit.
  - A running report of every step (how the scheme works, where it is weak) is a good output artifact pattern.
- key fact: The model recognized a jailbreak attempt, verified the signing certificate to catch a false ownership claim, then performed a static audit documenting the offline license scheme (signature check, hardware-serial machine binding, embedded revocation list, signed update path) in ~30 minutes. (src: https://www.xda-developers.com/qwen-3-8-27b-reverse-engineering-job-frontier-model/)

### 3. Everything I own, owned — Claude Opus RE of consumer firmware
- url: https://schlarp.com/posts/everything-i-own-owned/ | date: 2026-08-23 | status: fetched
- what: Over two weeks the author did agent-driven RE of five peripherals, giving Claude Opus 5 firmware + update tools and a fixed goal template, letting it churn and validate against live hardware; ~13 hours churn, 98 prompts total. Findings shared with vendors.
- techniques/tools/formats: agentic RE (Claude Code sessions), firmware + vendor update-utility capture, static+dynamic analysis, USB Video Class / vendor-class command channels, ThreadX RTOS (Ambarella SoC), FAT firmware images, MD5 integrity hashes, LED pattern tables
- relevance to retool:
  - Reusable prompt template as a documented "goal contract": reverse the update format/protocol, implement an own updater, enumerate protocol surfaces, determine security properties (checksums, signatures, secure boot), find hidden/debug functionality.
  - Peripherals are good iterative targets because they have a host data link + update mechanism; retool could model "firmware update format" as a first-class parse target.
  - Pitfall catalog for firmware: no anti-tamper, integrity-only (appended hash) with no signature — worth flagging in a security-properties report.
- key fact: The Insta360 webcam runs a ThreadX RTOS on an Ambarella SoC hosting small vision models, and its firmware is protected only by an appended MD5 integrity hash with effectively no anti-tamper. (src: https://schlarp.com/posts/everything-i-own-owned/)

### 4. What's really inside the ANE, or why you can't trust RE to an AI
- url: https://habr.com/ru/articles/1076240/ | date: 2026-08-30 | status: fetched
- what: Critique (Russian) of an AI-paired ANE RE project; author re-did the work in Rust (objc2) against AppleNeuralEngine.framework, used LLDB breakpoints on Obj-C exceptions, and showed the AI had latched onto a dead/unused private class and propagated the mistake through its context.
- techniques/tools/formats: Apple Neural Engine (ANE), AppleNeuralEngine.framework private classes, MIL files, CoreML, Rust + objc2 FFI, LLDB, Obj-C runtime messaging (compile/load), cargo test
- relevance to retool:
  - Concrete LLM-RE pitfall: a model fixates on a plausible-but-wrong artifact (_ANEInMemoryModel "holy grail") and carries the error until context overflows — argues for human-verifiable, cross-validated findings.
  - Reproducing a bug/crash (compiler fails after ~119–127 compiles) and stepping with a debugger is how the human disproved the AI's claim; retool should support ground-truth validation, not just LLM narration.
- key fact: The AI-led write-up treated the unused private class _ANEInMemoryModel as the key "in-memory path", but it is referenced nowhere in the system and the approach crashed after ~119 compilations. (src: https://habr.com/ru/articles/1076240/)

### 5. Inside Apple Neural Engine, part 2: running a model (Qwen without GPU/CPU)
- url: https://habr.com/ru/articles/1078762/ | date: 2026-09-05 | status: fetched
- what: Part 2 (Russian) of human ANE RE: instead of reversing the compiler binary, the author mined the macOS filesystem for ~163 real .mil example files to learn valid MIL constructs, filtered them with a Rust MIL-compile wrapper, and worked toward running Qwen purely on ANE.
- techniques/tools/formats: MIL (CoreML Model Intermediate Language), `find /System/Library -name '*.mil'`, FlexibleShapeInformation (DefaultShapes/RangeDims/EnumeratedShapes) for dynamic shapes, new data types (pixel_buffer, tensor_buffer, state<T>), multi-function kernels, Rust compile harness
- relevance to retool:
  - Harvesting valid real-world samples shipped with the OS as a spec/corpus beats reversing an opaque compiler — a corpus-mining workflow retool could offer.
  - Automating validation (feed each candidate file through a compile/run wrapper) to separate valid from invalid inputs mirrors a parser fuzz/validate loop.
- key fact: The author found ~163 valid CoreML MIL example files under /System/Library and discovered the entry function need not be named "main" and multiple functions can share one file to cut compile overhead. (src: https://habr.com/ru/articles/1078762/)

### 6. Retrospectively Reverse-Engineering Apple's Neural Engine
- url: https://eiln.github.io/posts/ane.html | date: 2026-08-10 (page; the brief said 09-12) | status: fetched
- what: Eileen Yoon revisits her M1 ANE Linux driver work to map the full internal architecture — compute cores, datapath, scheduler, memory, execution model — framing ANE as a CNN-era dataflow accelerator that transformers broke.
- techniques/tools/formats: Apple Neural Engine (A11/M1), hardware driver RE, die-shot analysis, MAC arrays (256 MACs/core x16 cores), dataflow/datapath analysis, CNN vs transformer workload reasoning
- relevance to retool:
  - Architecture-mapping as the goal (not just "make it run") — document compute/datapath/scheduler/memory/execution model; a template for structured hardware-RE reports.
  - Historical/design-intent reasoning: silicon choices reveal assumptions about workloads — useful framing for annotating RE findings.
- key fact: The M1 ANE has 16 compute cores each built around a 256-wide MAC array feeding an accumulator and activation stage, architected for predictable CNN reuse patterns that autoregressive transformers violate. (src: https://eiln.github.io/posts/ane.html)

### 7. Reverse-Engineering Claude Code Architecture from Source Maps
- url: https://claude-code-from-source.com/ | date: 2026-09-18 | status: fetched
- what: An 18-chapter book reconstructing Claude Code's internals by reading the source maps shipped with its npm package, distilling architecture and transferable patterns (agent loop, tool pipeline, multi-agent orchestration, memory, performance, security).
- techniques/tools/formats: JavaScript source-map RE of a shipped npm package, async-generator agent loop, 14-step tool-execution pipeline, prompt-cache prefix sharing, file-based memory with LLM recall, two-phase skill loading, lifecycle hooks
- relevance to retool:
  - RE target = shipped source maps/minified JS; a reminder that "binary" RE extends to bundled JS artifacts.
  - Documented agent-architecture patterns (speculative execution, partitioning tools by safety classification, config snapshots frozen at startup to resist injection) directly inform retool's own hexagonal + hook harness.
- key fact: The book reconstructs a 14-step tool-execution pipeline and multi-agent orchestration (sub-agents sharing byte-identical prompt-cache prefixes, claimed ~95% cost cut) purely from the source maps that shipped on npm. (src: https://claude-code-from-source.com/)

### 8. ZCode agent silently uploads workspaces and git history
- url: https://tokenstead.ai/guides/zcode-silent-git-history-upload | date: 2026-09-18 | status: fetched
- what: Reports a RE walkthrough (by "ferstar") of Z.ai's closed-source ZCode desktop app showing that, while logged in, it packages the entire workspace including full .git history, encrypts it with envelope encryption, and uploads to Aliyun OSS.
- techniques/tools/formats: desktop-app RE, envelope encryption (symmetric payload key wrapped with RSA-OAEP), server-delivered public key, local plaintext packaging manifest, Aliyun OSS upload pipeline, .git/objects, .git/lfs, reflogs
- relevance to retool:
  - Threat-model note for LLM harnesses: closed agents may exfiltrate the whole repo lineage (deleted secrets, unpushed branch names, internal hostnames in .git/config) — reinforces retool's "no uploading files/hashes without being asked".
  - Spotting envelope encryption where only the server holds the private key is a concrete "data cannot be decrypted by the user" red flag to detect.
- key fact: ZCode built a 313MB encrypted archive from a 42,411-file workspace where .git (lfs+objects+logs) was ~86.6% of the payload, wrapped with an RSA-OAEP key whose private half lives only in Z.ai's cloud. (src: https://tokenstead.ai/guides/zcode-silent-git-history-upload)

### 9. Analyzing Frontier Model Progress with Prince of Persia (Apple II → C#)
- url: https://blog.priyan.in/2026/09/analyzing-frontier-model-progress-with.html | date: 2026-09-25 | status: fetched
- what: Author handed Jordan Mechner's published Apple II 6502 assembly source to successive frontier models to port to C#, never editing code himself; tracked how each model (Opus 4.6, Codex, Opus 5) handled parsing level files and reproducing animation/movement.
- techniques/tools/formats: 6502 assembly source porting, C#/Raylib, level-file format parsing (rooms, tiles, gates, guards), DOSBox-control + Windows-control Claude Code skills (launch, send keys, screenshot), visual comparison against reference binary
- relevance to retool:
  - Porting/decompilation benchmark across model generations — a methodology for evaluating LLM RE capability over time.
  - Skills that drive an emulator (send keys, screenshot, compare to ground truth) create a closed validation loop — a reusable pattern for retool's LLM-assisted workflows.
  - Pitfall: wrong architectural assumption (tile-hop vs per-frame animation) produced a playable-looking but wrong port — structure matters more than surface fidelity.
- key fact: Early models correctly parsed the original level files (rooms, tiles, gates, guard positions) but got movement wrong because they modeled tile-by-tile hopping instead of the game's per-frame hand-drawn animation. (src: https://blog.priyan.in/2026/09/analyzing-frontier-model-progress-with.html)

### 10. OpenDLSS-NR: bit-exact Vulkan reimplementation of DLSS 5 neural rendering
- url: https://github.com/maanHimself/OpenDLSS-NR | date: 2026 (no explicit date on page) (assumption) | status: fetched
- what: MIT-licensed Vulkan reimplementation of NVIDIA's DLSS 5 Neural Rendering network, claimed bit-exact against the original (build 310.8.0); ships no NVIDIA weights, validated against recorded captures of the original at every block boundary.
- techniques/tools/formats: Vulkan (VK_KHR_cooperative_matrix, VK_NV_cooperative_matrix2, VK_EXT_shader_float8), FP8 (E4M3) activations + FP16 accumulate on tensor cores, PTX kernels (mma.sync, cp.async, split-K GEMM), GLSL reference path, Filament demo, WebGPU browser port, JSON manifests with SHA-256 stage hashes
- relevance to retool:
  - Bit-exact parity testing against captured intermediate tensors (all 75 block boundaries), not just final output — a gold standard for validating a reverse-engineered implementation.
  - Second independent implementation (WebGPU, no tensor cores/FP8) matching the same captures shows exactness is "in the specification, not the hardware" — a cross-validation design worth borrowing.
- key fact: The reimplemented U-net (71 shifted-window transformer blocks + global ViT, ~141 MiB weights) matches the original byte-for-byte at all 75 block boundaries, verified by two independent backends (Vulkan FP8 and WebGPU). (src: https://github.com/maanHimself/OpenDLSS-NR)

### 11. Reverse-Engineering a Nokia 110 4G to run a native AI agent
- url: https://github.com/anupray95/AI-Agent-on-a-NOKIA | date: 2026 (no explicit date on page) (assumption) | status: fetched
- what: Prototype native chat agent on a Nokia 110 4G feature phone; author reversed the firmware/boot process and ran custom code in RAM via the Calculator app's entry point (no flashing), repurposing its UI into a chat client that calls the DeepSeek API and invokes phone functions.
- techniques/tools/formats: feature-phone firmware RE, boot-process analysis, code injection into RAM via Calculator app entry point, firmware response-callback tracing, DeepSeek chat API with tool calls, 48MB memory constraints (compressed payloads, reused buffers), OpenAI Codex assist
- relevance to retool:
  - Running code in RAM through an existing app entry point (no firmware flash) is a low-risk dynamic-RE technique for constrained devices.
  - Tracing firmware response callbacks to route data back — a general method for understanding undocumented device APIs; pitfall shown: writing the wrong style field caused restarts, found by firmware tracing.
- key fact: The agent runs natively by loading custom code into the phone's RAM through the Calculator app's entry point (lost on power-off), fitting within 48MB via a simplified agent and compressed payloads. (src: https://github.com/anupray95/AI-Agent-on-a-NOKIA)

### 12. REA: Reverse Engineering Tool for Coding Agents
- url: https://rea.tools/ | date: 2026-10-10 (batch date; page gives no explicit date) (assumption) | status: fetched
- what: REA is tooling that gives a coding agent the ability to inspect a program and explain how it works; installed into an existing agent via `npx rea-agents@latest setup`, with setup guide, showcases, and analysis guides on the site.
- techniques/tools/formats: coding-agent integration (npx rea-agents), program inspection/analysis, "understand → change → rebuild" RE framing, Node.js-based agent plugin
- relevance to retool:
  - Direct competitor/reference: packages RE capabilities as agent tools — informs retool's own LLM-assisted workflow and CLI surface.
  - Framing RE goals as understand/change/rebuild a feature is a clean user-facing taxonomy.
- key fact: REA installs into an existing coding agent via `npx rea-agents@latest setup` and gives the agent tools to inspect a program and explain what it does, aimed at understanding, changing, or rebuilding a feature. (src: https://rea.tools/)

### 13. Classic games decompiled overnight with Claude Opus 5.5
- url: https://kotaku.com/we-might-be-cooked-as-these-vibe-coded-web-browser-ports-of-halo-the-simpsons-hit-and-run-and-gta-vice-city-seem-to-work-perfectly-2000743300 | date: 2026-10-09 | status: fetched
- what: News piece reporting that Claude Opus 5.5's strong decompilation ability led to hundreds of AI-decompiled web-browser ports/emulators of PS2/PS3-era games (Halo CE, GTA Vice City, Simpsons Hit & Run, etc.) appearing within weeks, many running well in-browser.
- techniques/tools/formats: AI-assisted decompilation (Claude Opus 5.5), source reconstruction/recompilation, web-browser (WASM/JS) ports/emulators, overnight agentic runs
- relevance to retool:
  - Signals that overnight agentic decompilation of large binaries is now practical — raises the bar for what retool's static-analysis + LLM workflows are expected to handle.
  - Legal/IP pitfall: decompiled game ports invite C&D; retool's docs should note licensing/IP boundaries for RE outputs.
- key fact: The article attributes a wave of fast, playable in-browser ports of PS2/PS3-era games to Claude Opus 5.5 being able to decompile and reconstruct source "overnight" rather than over months. (src: https://kotaku.com/we-might-be-cooked-as-these-vibe-coded-web-browser-ports-of-halo-the-simpsons-hit-and-run-and-gta-vice-city-seem-to-work-perfectly-2000743300)
