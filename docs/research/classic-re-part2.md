# Research digest — classic reverse engineering, part 2 (hardware, firmware, retro, decompilation)

Source: reading list supplied by the user on 2026-10-11; notes produced by the researcher worker on 2026-10-11.
Markers: `status: fetched|unreachable` — whether the page itself was read; `(src: url)` — fact taken from that page; `(assumption)` — not verified against a source. GitHub repositories were unreachable through the session proxy (HTTP 403); those notes rest on secondary coverage.
Context: retool (Python 3.12 toolkit for static analysis of ELF/PE/Mach-O, LLM-assisted workflows).

### 1. Intel 8087 FSCALE microcode
- url: https://www.righto.com/2026/09/8087-microcode-reverse-engineering-fscale.html | date: 2026-09-12 | status: fetched
- what: Ken Shirriff and the Opcode Collective decapped an 8087 and imaged the die. They read the 1648-entry microcode ROM and traced FSCALE: over 140 micro-instructions, 3 levels of subroutine calls, many special cases. (src: url)
- techniques/tools/formats: die photography/microscopy, microcode ROM extraction, datapath analysis (16-bit exponent path, 64-bit significand path, shifter, adder), 80-bit extended floats, register tags (valid/special/zero/empty)
- relevance to retool:
  - Microcode/ISA-level formats are out of scope for ELF/PE/Mach-O, but the 80-bit x87 float and tag semantics matter for any x87 disassembly or emulation.
  - Shows that a "trivial" instruction can have a huge special-case surface (zero/inf/NaN/denormal), so tests should cover these.
- key fact: FSCALE takes 140+ micro-instructions and also reveals a hidden 8087 feature. (src: url)

### 2. PS2 MechaCon (CXP102064) dumped
- url: https://www.tomshardware.com/video-games/playstation/26-year-old-sony-ps2-security-chip-broken-wide-open-after-four-years-of-effort-reverse-engineering-enthusiast-successfully-unlocks-cxp102064-mechacon-chip | date: 2026-09-16 | status: fetched (page body was not extractable; only title was usable)
- what: Title says the chip was chemically decapped and reverse-engineered over about 4 years. Body supplied via one WebSearch of secondary coverage: modder DiscoStarslayer with collaborator Libby made a rough optical dump after decapping. Libby then found a software weakness that bypassed read protection and gave a clean dump. (src: https://www.techspot.com/news/113876-someone-finally-cracked-playstation-2-security-chip-26.html, https://overclock3d.net/?p=314372)
- techniques/tools/formats: chemical decapping, optical ROM readout, read-protection bypass, firmware hashes/metadata
- relevance to retool:
  - Firmware blobs from such dumps are raw, headerless and architecture-specific. A raw-binary mode (base address, arch hint) is needed beyond ELF/PE/Mach-O.
  - Firmware dumps from different sources should be compared by hash.
- key fact: results cover the original chip only; later PS2 revisions use a different controller architecture. (src: https://www.remio.ai/post/sony-ps2-mechacon-hack-opens-a-security-chip-that-resisted-researchers-for-26-ye, via search snippet, not opened)

### 3. Flock Safety camera teardown
- url: https://www.wired.com/story/hackers-flock-camera-data-shows-how-system-works/ | date: 2026-09-16 | status: fetched
- what: Hackers (stegan0gram) removed a Flock camera and copied its storage. WIRED and 404 Media analysed the Android system, about 20 Flock apps, the logs and the ML models. They ran the models on test images and recovered an encryption key stored on the device. (src: url)
- techniques/tools/formats: flash/storage imaging, Android partitions (some unencrypted: "vendor", "media"), extracting on-device ML models and running them, log analysis, key recovery
- relevance to retool:
  - Handle extracted Android/embedded images with multiple partitions, some encrypted.
  - Log and string mining is productive. Logs showed about 21 days, about 50,200 vehicles and 1.6M images.
  - Pitfall: vendor claims such as "on-device encryption" must be verified against the key found on the device.
- key fact: the recovered on-device key unlocked videos, while the most sensitive storage stayed encrypted. (src: url)

### 4. Resident Evil 4 GameCube decompilation
- url: https://github.com/adonis-singh/re4 | date: 2026-09-20 | status: unreachable (GitHub returned HTTP 403 from the proxy); secondary info via 1 WebSearch
- what: Aggregator summaries (zeli.app/story/49778022) say it reconstructs the G4BE08 debug build (Nov 25 2004 prototype) as about 555k lines of C/C++ with no assembly. Building reproduces main.dol and all 114 REL overlays, verified by SHA-1. Figures are 1083 objects and 15,641 functions. No game assets are shipped. Not verified against the repo.
- techniques/tools/formats: matching decompilation, DOL and REL (relocatable overlay) formats, SHA-1 verification, the decomp-toolkit method (src: https://git.axiodl.com/encounter/decomp-toolkit)
- relevance to retool:
  - Byte-match verification (hash of rebuilt output vs original) is a good workflow check.
  - DOL and REL are PowerPC GameCube formats, which would be a new format context.
- key fact: build reproduces main.dol and 114 RELs by SHA-1 (src: https://zeli.app/story/49778022, aggregator, unverified against repo).
- other sources disagree: cornfordandcross.com and 1023jack.com describe the project vaguely, one dating it March 2024 and one AI-assisted. Not relied on.

### 5. Intel 8087 tangent (FPTAN)
- url: https://www.righto.com/2026/09/8087-tangent-cordic.html | date: 2026-09-26 | status: fetched (intro and CORDIC section read)
- what: Shirriff explains how FPTAN combines CORDIC (shift/add plus a constant ROM) with polynomial approximation. This gives about 90 us per tangent against 13,000 us on the 8086. The explanation comes from die imaging plus microcode. (src: url)
- techniques/tools/formats: die imaging, microcode ROM, constant ROM, CORDIC, 80-bit datapath, 16-bit CORDIC status shift register
- relevance to retool:
  - Recognising CORDIC/polynomial tables in firmware (constant tables) is a possible heuristic.
  - Otherwise low relevance to static ELF/PE/Mach-O analysis.
- key fact: the 8087 ROM holds 1648 micro-instructions, and FPTAN is a hybrid of CORDIC and polynomial approximation. (src: url)

### 6. FLIP fluid simulation on flip-dot display
- url: https://mitxela.com/projects/flipflip | date: 2026-09-24 (page date; the brief says 09-27) | status: fetched (only the intro was read)
- what: mitxela built a FLIP (Fluid Implicit Particle) simulation on electromechanical flip-dot panels for EMF2026. Panels are 13x28, dated 2007, mostly Hanover, from a donated pile. He covers custom decoder boards, KiCad PCBs, power and a joystick. (src: url)
- techniques/tools/formats: KiCad, hardware driver boards, FLIP simulation
- relevance to retool: essentially none (hardware and graphics build, not binary analysis). Only pattern: reverse-engineering the panel drive electronics from unlabelled legacy hardware.
- key fact: dots are non-volatile (two permanent magnets plus two polarisable cores) and the panel is 13x28. (src: url)

### 7. Hijacking PS5 RTMP stream via DNS spoofing
- url: https://yashgarg.dev/posts/hijacking-ps5-rtmp-stream/ | date: 2026-09-28 (updated 09-29) | status: fetched (about the first 60%)
- what: DNS logs (dnsmasq) showed which hostname the PS5 resolves for Twitch broadcast. Spoofing contribute.live-video.net redirects plain RTMP to nginx-rtmp on a Mac, avoiding RTMPS cert validation. A YouTube attempt failed because the PS5 polls the YouTube API for liveness and stopped after about 60s. (src: url)
- techniques/tools/formats: dnsmasq, nginx-rtmp, DNS log observation, RTMP vs RTMPS, certificate-pinning constraints
- relevance to retool:
  - Black-box protocol discovery by observing DNS/network behaviour is a workflow retool could document or support.
  - The sample-network rule in CLAUDE.md applies here: such captures would be done by a human outside retool.
- key fact: ingest.twitch.tv:443 is only a discovery endpoint; the real plain-RTMP endpoint is aps30.contribute.live-video.net (via ingest.global-contribute.live-video.net). (src: url)

### 8. Booting Linux on Apple M4
- url: https://yuka.dev/blog-2026-10-02-linux-m4.html | date: 2026-10-02 | status: fetched (first ~40 lines)
- what: First boot of Linux on an M4 Mac mini via m1n1 as a custom boot object, with a serial console. M4 mandates SPTM (Secure Page Table Monitor), so the usual m1n1-hypervisor MMIO tracing is blocked. m1n1 crashed because GXF is locked in raw boot mode and RVBAR is not writable. (src: url)
- techniques/tools/formats: m1n1, Asahi Linux, serial console, MMIO tracing via hypervisor, GXF, RVBAR, SPTM
- relevance to retool:
  - Apple Silicon-specific Mach-O/boot objects (kernelcache, m1n1 payloads) are a possible future format.
  - Lesson: a hardening feature (SPTM) can invalidate a whole analysis workflow, so tools must report which capabilities are unavailable.
- key fact: M4 is the first Apple Silicon generation to mandate SPTM. (src: url)

### 9. River Raid rebuilt in JS from ROM
- url: https://plicerin.github.io/riverraid-rom-port/ | date: 2026-10-05 (brief date, page undated) | status: fetched (play page only)
- what: A browser game port of the Atari 2600 River Raid. The page is player-facing and explains the game: the 4096-byte cartridge builds each 32-line river block from a 16-bit RNG seeded with $A814. The page excerpt does not describe the reverse-engineering method. (src: url)
- techniques/tools/formats: Atari 2600 4 KB ROM, 6502-family code, LFSR/PRNG, 1-button 8-direction joystick
- relevance to retool: procedural generation in tiny ROMs. Recovering PRNG seeds and generator logic is the kind of finding a RE assistant could surface. Method details unknown (assumption: ROM disassembly then JS port).
- key fact: the river is never stored; it is generated from a 16-bit RNG seeded with $A814 each game. (src: url)

### 10. Resurrecting iChat A/V on early OS X
- url: https://blog.pipetogrep.org/2026/09/11/resurrecting-ichat-audio-and-video-conferencing/ | date: 2026-09-11 (updated 2026-10-08) | status: fetched
- what: tcpdump plus iChat's debug flag (`-errorLogLevel 7`) showed iChat fetching snatmap.txt over HTTP, now redirected to HTTPS, which Leopard's old TLS cannot do. An LLM, fed network captures and iChat's framework, produced a spec for the SNATMAP protocol, and the author wrote a Python UDP server from it. Fix is an /etc/hosts entry for configuration.apple.com. (src: url)
- techniques/tools/formats: tcpdump, app debug logging, LLM-assisted protocol reverse engineering, SNATMAP over UDP/5678, XMPP, RTP
- relevance to retool:
  - Direct precedent for LLM-assisted workflows: captures plus binary to a protocol spec, then an implementation.
  - Wire format as a spec to extract: 16-byte request and response with type, nonce, IP and port (see key fact).
  - Pitfall: legacy TLS breaks the discovery step, and the LLM-derived spec needs real-traffic validation.
- key fact: SNATMAP is UDP/5678 with 16-byte packets: type ("1" request, "2" response), nonce, external or local IP, port. (src: url)

### 11. Tapo library adds TPAP
- url: https://mihai.dinculescu.dev/posts/tapo-speaks-tpap/ | date: 2026-10-06 | status: fetched
- what: A Rust/Python library for TP-Link Tapo devices added TPAP (v0.11.1), the protocol devices speak when "Third-Party Compatibility" is off. KLAP is used when it is on. Older protocol for cameras is AES SSL. Firmware 1.4.0 changed plug behaviour. The post also covers H200/H500 hubs, schedules/timers and an MCP server. (src: url)
- techniques/tools/formats: KLAP, TPAP, AES SSL, auth handshake analysis, Rust/Python, MCP
- relevance to retool:
  - IoT protocol churn after firmware updates (403 after update) is a typical RE target. Version-pinned protocol specs would help.
  - TPAP is described as stronger than KLAP because a recorded login cannot be used for offline password guessing (src: url, summarised from the intro; the cryptographic details of TPAP were not read).
- key fact: firmware 1.4.0+ plugs return 403 to KLAP clients unless the compatibility switch is on, which forced TPAP support. (src: url)

### 12. AnyPS5 binary porting tool
- url: https://github.com/boykopovar/AnyPS5 | date: 2026-10-07 | status: unreachable (GitHub 403 via proxy); secondary info via 1 WebSearch
- what: Per press coverage (pasqualepillitteri.it, pcgameshardware.de, korben.info), AnyPS5 converts PS5 executables into native Windows/Linux programs without an emulator. Parts: a relinker, reimplemented PS5 system libraries, and a shader recompiler targeting Vulkan 1.1. Users supply their own ELF/module files from a modified PS5. Status v0.1 with Sept 28 releases and GPL-2.0. Not verified against the repo.
- techniques/tools/formats: PS5 ELF/SELF modules, relinking, HLE of system libs, shader recompilation, Vulkan
- relevance to retool:
  - PS5/PS4 ELF variants (SELF, module/NID imports) are ELF dialects that retool's ELF parser would meet.
  - Unverified claims need caution: only one game is reported as working and the 60 fps figure is the authors' own.
- key fact: reported 1,166 PS5 GPU shader instructions implemented, covering recognition, not guaranteed correctness. (src: https://www.pcgameshardware.de/Playstation-5-Konsolen-265878/News/AnyPS5-PC-Portierung-erreicht-Meilenstein-1556302/, via search snippet, not opened)

### 13. M-Vave FM-1 synth firmware RE
- url: https://github.com/AL-255/FM-1-RE | date: 2026-10-07 | status: unreachable (GitHub 403 via proxy); secondary info via 1 WebSearch
- what: Per aggregator zeli.app/story/49994065: JieLi AC791N/WL82 SoC with a pi32v2 CPU and a Dexed/msfa-derived 6-operator FM engine. Execute-in-place flash at 0x02000000. The main branch covers OTA protocol, bootloader analysis and decompilation of the Windows updater. Custom firmware lives on branch `with-custom-firmware`. Ghidra is not named in the snippets seen. Not verified against the repo.
- techniques/tools/formats: Ghidra (per the brief's title, not confirmed), pi32v2 (uncommon CPU), OTA update protocol, bootloader analysis, XIP flash
- relevance to retool:
  - Uncommon-ISA firmware needs raw-image loading with a base address and custom CPU support.
  - Safety pitfall: single-bank flash layout with no verified recovery or rollback, so tools must not suggest flashing.
- key fact: update protocol has no demonstrated recovery, rollback or safe interrupted-write behaviour. (src: https://zeli.app/story/49994065, aggregator)
