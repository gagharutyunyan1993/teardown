# Decisions (architecture / process; one line each, `YYYY-MM-DD what — why`)
- 2026-10-10 Python 3.12+, uv, ruff, mypy --strict, pytest — fastest path for RE tooling; stack swappable via Makefile only.
- 2026-10-10 All checks via `make` targets — hooks/skills never call tools directly.
- 2026-10-10 samples/ is read-only, never executed; static analysis only inside the agent.
- 2026-10-11 Fable is orchestrator only: no Edit/Write/Bash; work goes to opus/sonnet/haiku workers via contract prompts with explicit model+effort — enforced by agent setting + pre-agent/subagent-stop hooks
- 2026-10-11 Non-trivial decisions via /decide: researcher dossier with dated primary sources, two blind analysts on different models, judge (opus xhigh) writes ADR in docs/decisions/ — enforced by hooks
- 2026-10-11 Architecture: hexagonal + DDD by bounded context (docs/architecture/ARCHITECTURE.md); make arch (import-linter + tools/archcheck.py) in make check; architect worker approves specs/diffs touching conte
- 2026-10-12 user confirmed 2026-10-12 that raw headerless firmware images, base address plus arch hint, are in scope for retool, and that LLM calls are part of the product, not only the dev harness; both need /de
- 2026-10-12 raw images load only on explicit request inside formats via LoadRawImage and Format.RAW, never detected, no fallback; ArchitectureId, AddressSpace, SpaceAddress go to shared; MemoryMap, MappedSegment,
- 2026-10-12 LLM calls live in a new assist context behind SuggestionSource, EvidenceSource and AuditLog ports; v1 is single-shot structured output with no tools; Provenance, Verification, Finding, NotAnalysed go 
