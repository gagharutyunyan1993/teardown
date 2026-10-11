---
paths:
  - "src/**"
  - ".claude/plans/**"
  - "docs/architecture/**"
---
# Architecture rules (summary of docs/architecture/ARCHITECTURE.md; the doc wins)
- Code lives in a bounded context `src/retool/<ctx>/{domain,application,infrastructure}/`; `shared` = kernel, `interface` = composition root + CLI. New context ⇒ `/decide`.
- Dependencies point inward: interface → application → domain; infrastructure implements `domain/ports.py` Protocols and is wired in interface only. `make arch` fails otherwise.
- domain: stdlib + `retool.shared` only; frozen dataclasses; pure functions; no I/O; no third-party.
- application: one use case per class (`execute()`), DTOs out, orchestration only, no business rules.
- infrastructure: one adapter per technology; translate failures to `RetoolError`; no domain logic.
- Cross-context access only via `retool.<ctx>` public API (`__init__` exports); never deep imports; never infrastructure in exports.
- Ports named by capability (`ByteSource`), adapters by technology (`FileByteSource`). Parsers: strategy per format behind a Protocol, selected by a registry in application.
- No `Any`, no bare `# type: ignore`, no module-level mutable state, no inheritance for reuse.
- Every spec names context/layer/pattern per module in a `## Architecture` section; the architect approves it when a boundary or port changes.
