# retool architecture (accepted plan)

Status: accepted 2026-10-11. Changes only through `/decide` and a superseding ADR; `make arch` enforces what is mechanical.
Amended 2026-10-12 by ADR 0001 and ADR 0002 (index in §7).

## 1. Style
Hexagonal (ports & adapters) with DDD tactical patterns, organised by bounded context. Dependencies point inward:
`interface` → `application` → `domain`; `infrastructure` implements `domain` ports and is wired only in `interface` (composition root).
`shared` is the shared kernel: value objects and errors, pure, dependency-free.

## 2. Bounded contexts (src/retool/<context>/)
| Context | Responsibility | Status |
|---|---|---|
| `formats` | container identification and structural parsing of ELF, PE, Mach-O (headers, sections, segments, symbols, imports); user-declared raw images loaded only on explicit request (`Format.RAW`, never returned by `detect()`; use case `LoadRawImage`; no content fallback) (ADR 0001). Public API also exports `MemoryMap`, `MappedSegment`, `Image`; their promotion to `shared` is an ADR 0001 revisit trigger, not a default | started |
| `disasm` | instruction decoding over byte ranges, architecture-agnostic API | planned |
| `analysis` | higher-level facts built from formats + disasm: strings, xrefs, function discovery, packer heuristics | planned |
| `reporting` | rendering analysis results (text, JSON) | planned |
| `assist` | owns every outbound model call (ADR 0002): v1 single-shot structured output, no tools; egress policy, budgets, audit; a pure gate (>= 2 independent checks) before a suggestion is trusted. Ports: `SuggestionSource`, `EvidenceSource`, `AuditLog`. `formats`, `disasm`, `analysis`, `reporting` never import `assist` | planned |
| `shared` | kernel: `Address`, `ByteRange`, `ParseError`; address/architecture vocabulary `ArchitectureId`, `AddressSpace`, `SpaceAddress` (ADR 0001); findings `Provenance`, `Verification`, `Finding`, `NotAnalysed` and the `JsonValue` alias (ADR 0002). Value objects with validation only | started |
| `interface` | composition root + delivery (CLI); no logic | started |

A new context, or a change to a context's responsibility, is a `/decide` question. Contexts talk through their public `__init__` exports only; no deep imports across contexts (`retool.formats.domain.x` from `analysis` is a violation).

## 3. Layers inside a context
```
<context>/
  domain/        entities, value objects, aggregates, domain services (pure functions), ports (Protocols), domain events
  application/   use cases (one class per use case, `execute()`), DTOs, application services; depends on domain only
  infrastructure/ adapters implementing domain ports (filesystem, external tools, caches); may import third-party libs
  __init__.py    the context's public API: re-exports from application + domain model; nothing from infrastructure
```
Rules: domain imports only `shared` and stdlib (no I/O, no third-party); application imports domain + shared; infrastructure imports anything; interface imports contexts' public API and infrastructure adapters to wire them.
Cross-context reads that feed another context's port are infrastructure adapters over the public API, never interface code: `assist/infrastructure` may import `retool.formats` / `retool.analysis` public APIs (`retool_evidence.py`, ADR 0002); `interface` stays logic-free (it wires, it does not map DTOs).
Runtime `dependencies = []`. A third-party library enters only as an optional extra with its own ADR: `llm` (provider SDK, confined to `retool.assist.infrastructure`) pending ADR 0003, `mcp` (`interface/mcp`) pending ADR 0004.

## 4. Tactical patterns (how, not just what)
- **Value objects**: `@dataclass(frozen=True, slots=True)`, validated in `__post_init__`, raise `ParseError`. Equality by value.
- **Entities / aggregates**: frozen dataclasses with an identity field; an aggregate root exposes invariants as methods; children are not mutated from outside.
- **Ports**: `typing.Protocol` in `domain/ports.py`; named by capability (`ByteSource`, `SymbolResolver`), never by technology.
- **Adapters**: one class per technology in `infrastructure/<tech>.py`; no domain logic inside; failures are translated into `RetoolError` subclasses at the boundary.
- **Use cases**: `class VerbNoun: __init__(ports...) ; execute(request) -> dto`; no business rules in use cases, they orchestrate domain services.
- **Domain services**: pure functions over domain types; where a parser is a pipeline, use the *strategy* pattern (one parser class per format behind a `FormatParser` Protocol) and a *registry/factory* in application to select it by `Format`.
- **Untrusted input**: parsers consume a `ByteSource` through `ByteRange.check_within(size)` before every read; counts are capped (`MAX_SECTIONS` style constants in the domain module); all offsets are `Address`.
- **Errors**: only `RetoolError` subclasses cross a layer boundary; `ParseError` carries the offset.
- **No**: god modules, singletons, module-level mutable state, inheritance for code reuse (prefer composition), `Any`, `# type: ignore` without an issue reference, stringly-typed enums.

## 5. Testing strategy
- domain: unit tests, pure, parametrized edge cases (empty, truncated, overflowing counts).
- application: use-case tests with in-memory fakes of ports (`tests/<context>/fakes.py`), never real files.
- infrastructure: adapter tests with `tmp_path`.
- interface: a thin smoke test per command.
- architecture: `make arch` (import-linter contracts + `tools/archcheck.py`) runs inside `make check`; contracts required by ADR 0001/0002 are listed in §7.

## 6. Change procedure
1. New feature → planner writes the spec naming the context, layer and pattern for each new module, with a `## Architecture` section (the architect reviews it when a context boundary or a port changes).
2. Implementer follows the spec; `make check` must pass, including `make arch`.
3. Reviewer checks pattern conformance as finding category 0 (before safety).
4. Anything that would break a rule here is a `/decide` question, not a local exception.

## 7. Decisions
Accepted ADRs that amend this plan (the ADR wins where wording differs):
- `docs/decisions/0001-raw-image-loading.md` — raw images in `formats`, explicit only; space/architecture vocabulary in `shared`; `MemoryMap`/`Image` stay in `formats` public API.
- `docs/decisions/0002-llm-assist-context.md` — new `assist` context; single-shot, no tools in v1; findings types in `shared`; SDK confined to `assist/infrastructure`.

Contracts these ADRs require in `.importlinter` (not yet present; added by an implementer in the same change that creates `assist`):
1. `assist` added to the four existing contracts: a `layers-assist` contract mirroring `layers-formats`; `retool.assist.domain`/`.application` in `no-infra-in-core` (forbidding `retool.assist.infrastructure`); `retool.assist` in `shared-kernel-pure` forbidden modules; `retool.assist` in `no-interface-from-contexts` sources.
2. New `forbidden` contract: `retool.formats`, `retool.disasm`, `retool.analysis`, `retool.reporting` must not import `retool.assist`.
3. New `forbidden` contract: the provider SDK is importable only from `retool.assist.infrastructure` (assumption per ADR 0002: needs `include_external_packages`; verify in the spec).
4. When `disasm`/`analysis` are created, layer contracts mirroring `formats` (ADR 0001 follow-up).
