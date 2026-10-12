# 0002. LLM calls live in a new `assist` context: single-shot structured output, no tools in v1, gated before any finding is trusted

Date: 2026-10-12   Status: accepted   Deciders: judge (opus/xhigh) on proposals from analyst A (opus/high), analyst B (sonnet/high)

## Context
On 2026-10-12 the user decided that LLM calls are part of the product, not only the dev harness (src: `.claude/memory/DECISIONS.md`, 2026-10-12 entry). No existing context mentions LLMs, and adding a context is a `/decide` question (src: `docs/architecture/ARCHITECTURE.md` §2, accepted 2026-10-11). Binding constraints:
- Inputs are hostile; samples are never executed or edited; no network access for samples; no uploading of hashes or files to third parties without being asked; secrets never enter the repo, prompts or logs (src: `CLAUDE.md` §Safety).
- Ports are `Protocol`s in `domain/ports.py`, named by capability and never by technology; one adapter per technology; only `RetoolError` subclasses cross layers; no `Any`, singletons or module-level mutable state (src: ARCHITECTURE.md §4).
- Runtime `dependencies = []` (src: `pyproject.toml`); every new dependency needs its own ADR (brief facts, 2026-10-12).
- Open research questions touched here: Q2 (where the findings model lives), Q3 (agent surface), Q8 (LLM gate) (src: `docs/research/SYNTHESIS.md`, 2026-10-11).

## Evidence (Sources)
Repo, read 2026-10-12:
- E1 `tools/archcheck.py`: A2 flags only *deep* cross-context imports, so code in any layer, infrastructure included, may import another context's public `retool.<ctx>` (l.52-55). ARCHITECTURE.md §3: infrastructure "imports anything", application "imports domain + shared". A4 bans third-party imports only in domain/application (l.62-63). A6 bans the word `Any` on every non-comment line of every `src/` file, infrastructure included (l.76-78). `interface` is not a context, so A2/A4 skip it (l.45-46).
- E2 `.importlinter`: contracts are written by hand per context (`layers-formats`, `no-infra-in-core`, `shared-kernel-pure`, `no-interface-from-contexts`); `forbidden` contracts already express "X must not import Y" (l.14-42).
- E3 SYNTHESIS row 5: four provenance tiers (parsed / disassembled / inferred / LLM-suggested) plus explicit "not analysed: reason". Row 7: accept LLM output only after a correctness check plus several independent metrics. Row 16: JSON report with input and per-stage hashes. Row 19: eval harness. Q2 is settled by whether ≥2 contexts construct findings; Q3 by who the primary consumer is.

Digest lessons (researcher notes, 2026-10-11, primary URLs inside):
- E4 Agents gamed metric-only validation, and "full-tool-coverage steering alone gave inconsistent results" (ai-re-part1 §2, arXiv 2606.06838, 2026-06-05).
- E5 The "2 prompts" claim was retracted: the work took >20 expert corrections, with known-good traces as the reference (ai-re-part1 §3, 2026-06-04). The agent there was given ghidra-cli plus a SKILL.md.
- E6 DWARF ground truth with three confidence tiers; high-confidence yield fell from 87.2% to 65.9% across optimisation levels (ai-re-part1 §6, arXiv 2607.07738 v2, 2026-07-24). Metrics come first and human insight is still required (ai-re-part1 §9, 2026-07-30).
- E7 The model wrongly called a result "definitive" twice (ai-re-part2 §1, 2026-08-19). A model fixated on an unused class and carried the error through its context; a static "referenced nowhere" check disproved it (ai-re-part2 §4, 2026-08-30). A model's self-description is unreliable (ai-re-part1 §13).
- E8 A local 27B model with Bash tools ran a static-only audit inside an external harness (ai-re-part2 §2, 2026-08-22). REA provides tools for an existing agent (§12). Claude Code groups tools by safety class (§7). A closed agent silently uploaded a whole workspace (§8, 2026-09-18).
- E9 Run the cheap deterministic pass first; the LLM gets only the residue (classic-re-part1 §12, 2026-08-26).

External, opened 2026-10-12:
- E10 Client tools run in your application: Claude stops with `tool_use`, and "your code executes the operation and sends back a `tool_result`". Server tools (web_search, web_fetch, code_execution, tool_search) run on Anthropic's infrastructure (src: https://docs.claude.com/en/docs/agents-and-tools/tool-use/overview).
- E11 Structured outputs use `output_config.format` with `json_schema`, and "beta headers are no longer required". `messages.parse()` accepts a Pydantic model. The JSON schema is cached for up to 24 h, separately from message content (src: https://docs.claude.com/en/docs/build-with-claude/structured-outputs).
- E12 MCP spec: "there SHOULD always be a human in the loop with the ability to deny tool invocations". Annotations are untrusted unless they come from trusted servers. Servers MUST validate all tool inputs and implement access controls (src: https://modelcontextprotocol.io/specification/latest/server/tools).
- E13 `anthropic` 1.13.0: released 2026-10-09, MIT, classifier "Typed". Deps: anyio, docstring-parser, httpx2, jiter, pydantic>=1.10,<3, sniffio, typing-extensions (src: https://pypi.org/pypi/anthropic/1.13.0/json).
- E14 `mcp` 2.3.0: released 2026-10-02, Production/Stable, MIT. Deps include starlette, sse-starlette, uvicorn, pyjwt[crypto], jsonschema, opentelemetry-api, python-multipart, pydantic>=2.12 (src: https://pypi.org/pypi/mcp/2.3.0/json).

Stale or conflicting sources: E11 supersedes the dossier's "structured outputs GA unverified". The dossier's dependency lists were incomplete and are corrected by E13/E14. The Binary Ninja MCP, Sidekick, GhidraMCP and REA approval-flow facts were not re-opened, and nothing here relies on them.

## Options considered (Alternatives considered)
1. A: `assist` context, a generic one-turn `LanguageModel` port, and an in-product bounded tool loop over read-only client-side tools.
   - For: the model fetches the context it needs (E8 shows tool-driven static audits work).
   - Against: every tool result is a further upload whose content the model picks at run time (E10), so it cannot be previewed or consented to specifically. No human can deny an invocation (E12). Unattended steering failed repeatedly (E4, E5, E7).
2. B: `assist` context, a capability-named `SuggestionSource` port, single-shot structured output, no tools in v1.
   - For: the payload is fixed before the call and can be shown in a dry run; model output is inert data that gets gated.
   - Against: the model sees only what the deterministic context builder chose, and its quality against a loop is unmeasured.
3. A port inside `analysis` (A's runner-up).
   - For: no new context.
   - Against: puts egress, keys and nondeterminism into a deterministic context, and the SDK import can no longer be confined by contract (E2).
4. Interface-only, where an external agent makes every call (B's runner-up, the REA model, E8).
   - For: no key and no egress inside retool.
   - Against: contradicts the user's 2026-10-12 decision, and the gate cannot be enforced on output retool never sees. Its surface is delivered anyway by steps 1-2 of the order below.

## Independent opinions and Dissent
- Analyst A recommended `assist` with a bounded read-only tool loop, so the model can investigate (xrefs, `is_referenced`) instead of receiving a fixed context.
- Analyst B recommended `assist` with single-shot structured output and no tools, because egress must stay previewable and server tools run remotely.

Both agree on, and this ADR adopts: a new `assist` context; the provider SDK only in assist infrastructure, as optional extra `llm`; a pure domain gate needing ≥2 independent checks; LLM output entering as LLM_SUGGESTED; budgets; an audit log; the key read only at wiring; the JSON CLI before MCP; MCP stdio-only and read-only, decided in its own ADR.

| point | A | B | settled by |
|---|---|---|---|
| in-product tool loop | bounded read-only client tools | none in v1 | E10 + CLAUDE.md "without being asked" + E12 + E4/E5/E7: **B** |
| port | `LanguageModel.complete` (generic turn) | `SuggestionSource` | ARCH §4 capability naming; without a loop no generic turn is needed: **B** |
| provenance | 6 tiers incl. LLM_CORROBORATED, NOT_ANALYSED | 4 tiers + orthogonal `Verification` + `NotAnalysed` | E3 row 5 (origin ≠ gate outcome): **B** |
| reading other contexts | assist infra adapter over public API | CLI maps DTOs | E1 (allowed) + interface "no logic" (ARCH §1-2): **A** |
| surface order | JSON CLI, then MCP | findings/JSON, CLI, assist, adapter, MCP last | user decision + Q3 open + E5 (agent used a CLI) + E14 weight: **B** |
| no-GA fallback | strict tools | `messages.parse` | E11 (no beta header needed): **B**; no tools even as a fallback |
| eval before enabling | C9 | not stated | E4, E6, E9: **A**'s control adopted |
| dry-run manifest, data minimisation | not stated | yes | CLAUDE.md §Safety: **B**'s control adopted |

Dissent recorded:
- A holds that a fixed context starves the model of callee names and xrefs. Accepted as unmeasured; it is a revisit trigger.
- A holds that read-only tools bound the worst case to a wrong suggestion. Rejected: read-only tool results are still uploads (E10), and sample-controlled strings can steer which ones the model requests (assumption: prompt injection via sample strings is feasible).
- B's argument that "server tools run remotely" is true (E10) but did not decide anything, because A also excluded server tools.

## Decision
Create the bounded context `assist`, which owns every outbound model call. v1 is **single-shot structured output with no tools** (B). From A it takes the anti-corruption adapter placement and the eval gate.

Deciding evidence:
- A client tool's result goes back to the API (E10), so in A's loop the model decides at run time what derived sample content leaves the machine. That loop could be steered by sample-controlled strings, which makes the "not without being asked" rule impossible to preview.
- Nobody can deny individual invocations (E12).
- It repeats the unattended-steering failures in E4, E5 and E7.

Multi-step investigation is served instead by the read-only JSON CLI/MCP surface used from an external agent, whose host keeps a human in the loop (E5, E8, E12). The "referenced anywhere?" check that disproved fixation (E7) becomes a mandatory gate check, not an optional tool.

- **Context and ports.** `assist/domain/ports.py` defines three ports, which accept and return frozen dataclasses only; no SDK type crosses them:
  - `SuggestionSource`: one request with a pre-built, minimised payload in, candidates out.
  - `EvidenceSource`: read-only fact queries.
  - `AuditLog`.

  Domain:
  - `Suggestion` aggregate, `EgressPolicy` + `PayloadManifest`, `Budget`.
  - Pure gate functions plus `AcceptancePolicy`.

  Application:
  - `ProposeFunctionNames`, `ExplainFunction`, `GateSuggestion`, `PreviewEgress` (dry run).

  Infrastructure:
  - `offline.py`: null source, the default wiring.
  - `retool_evidence.py`: imports only `retool.formats` / `retool.analysis` public APIs (E1).
  - `jsonl_audit.py`.
  - The provider adapter (ADR 0003).
- **Findings types live in `shared`.**
  - `Provenance` {PARSED, DISASSEMBLED, INFERRED, LLM_SUGGESTED}.
  - `Verification` {UNVERIFIED, PASSED(checks), REJECTED(reason)}.
  - `Finding` (subject, value, provenance, verification, producer) and `NotAnalysed(reason)`.
  - A recursive `JsonValue` alias for JSON boundaries under A6 (E1). Assumption: mypy --strict accepts a PEP 695 recursive alias; verify in the spec.

  This settles Q2 for findings: `assist` and the deterministic contexts both construct findings (≥2).
- **Mandatory controls.**
  1. Remote calls are off by default. Each invocation needs an explicit opt-in flag plus a configured key. `--dry-run` prints the `PayloadManifest` and sends nothing.
  2. Data minimisation is enforced in the domain `EgressPolicy`: only derived facts for one subject go out (capped disassembly text, referenced strings, symbol/import names), with per-field and total caps. Never raw bytes, hashes, paths or file names.
  3. No `tools` parameter at all, client or server. Output uses `output_config.format`. Schemas are static, versioned in the repo, and never contain sample-derived values, because the schema cache is separate from message content (E11).
  4. Injection posture: sample text is delimited data. Model output is never executed, used as a path or command, or fed into another request. Every field is re-validated by domain value objects, and syntactic validity does not count as a gate check.
  5. Gate and provenance:
     - Everything the model returns enters as LLM_SUGGESTED/UNVERIFIED, and its provenance never changes.
     - PASSED needs ≥2 independent pure checks, at least one of them against PARSED/DISASSEMBLED facts: address is a known function start, target is referenced, no collision with a parsed symbol.
     - Model-reported confidence never affects verification (E7).
     - Output that cannot be gated (explanations) stays UNVERIFIED. Code-rewrite suggestions are out of v1.
  6. One request per subject, with no history carried between subjects (E7). Budgets cover calls per run, tokens per call and a wall-clock deadline. Exceeding a budget raises `BudgetExceeded`, and the remainder is reported as `NotAnalysed`.
  7. The key is read once at the composition root, never logged, never put in prompts, and stripped from errors. SDK failures become `ModelUnavailable(RetoolError)`.
  8. A local audit record per call: model id, prompt and schema version, request sha256, token counts, manifest, gate verdicts. It never holds the key or raw bytes. The JSON report records model id and prompt version next to the stage hashes (E3 row 16).
  9. Inputs are never written. Persisting accepted suggestions is a later spec, and never goes into the input.
  10. LLM commands stay experimental and out of default pipelines until the eval harness (E3 row 19), run on synthetic/DWARF fixtures and not on samples, shows lift on ≥2 independent metrics (E4, E6).
  11. `make arch` contracts, added in the same change as `assist`:
      - `assist` is added to all four existing contracts.
      - formats/disasm/analysis/reporting must not import `retool.assist`.
      - The provider SDK may be imported only from `retool.assist.infrastructure`. Assumption: this needs import-linter's `include_external_packages`.
- **Surface order.**
  1. Shared findings plus the JSON report.
  2. A read-only, bounded, versioned JSON CLI (hex addresses, pagination, `not_analysed`). It already serves external agents, with no dependency (E5, E8).
  3. `assist` domain, ports, gate, egress, fakes and the offline adapter.
  4. The provider adapter, then the eval harness.
  5. MCP last: stdio only, static `tools/list`, read-only, no open/save/close.
- **Dependencies.** Runtime `dependencies = []` stays.
  - ADR 0003 chooses the provider adapter: `anthropic>=1.13,<2` as optional extra `llm` (E13), or a stdlib `urllib` adapter. It also checks A6 and mypy --strict against the SDK.
  - ADR 0004 covers `mcp>=2.3,<3` as optional extra `mcp` in `interface/mcp` (E14). It is written only once step 5 is due.
  - Use the next free numbers if 0003/0004 are taken. The current pydantic ranges of the two extras overlap (E13, E14).

## Consequences
- Easier: formats/disasm/analysis/reporting stay free of network access, keys and nondeterminism. Application tests use fakes and the offline adapter, so CI makes no network calls. Every byte of egress is previewable and audited. Swapping providers touches one adapter.
- Harder: the context builder must choose up front what the model sees, which risks under-informing it. `shared` grows (architect review). Every context now needs hand-written import-linter entries. Two specs and ADR 0003 come before the first real call.
- Follow-ups: planner spec for shared findings + JSON report (architect review); spec for the read-only JSON CLI; spec for `assist` core; ADR 0003; eval-harness spec. The orchestrator records this ADR in `.claude/memory/DECISIONS.md`.

## Revisit when (Revisit triggers)
- The eval harness shows single-shot naming below its threshold, and a measured tool-loop variant beats it. That requires a new threat-model ADR, with per-call approval or a local-only model.
- A local-only model adapter (no egress) becomes the default. The egress argument against a loop then weakens.
- No ≥2-check gate can be built for a suggestion kind without execution or recompilation. That kind then stays UNVERIFIED or moves to interface-only.
- After the first two specs, only one context constructs `Finding`. Move it out of `shared` (Q2).
- The user names an agent as the primary consumer (Q3). MCP then moves ahead of the provider adapter.
- `anthropic` 2.x is released, structured outputs change status or deprecate `output_config`, the extras' pydantic ranges conflict, or import-linter cannot confine the SDK import.
