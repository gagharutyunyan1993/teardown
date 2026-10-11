---
name: decide
description: Run the evidence-based decision protocol for a non-trivial question (library choice, architecture, format-handling strategy, security trade-off) — research, two independent analysts, a judge, an ADR. Use before any decision that is hard to reverse; never decide such things by instinct.
argument-hint: <decision question in one sentence>
---
Existing ADRs:

!`ls docs/decisions/ | grep -E '^[0-9]{4}-' || echo "(none yet)"`

Question: `$ARGUMENTS`

Run the protocol from `.claude/agents/orchestrator.md` §5, in this order, each step a contract prompt:
1. `researcher` (sonnet, medium; opus/high if the topic is deep): evidence dossier — facts from primary sources with dates/versions, current best practice, deprecations, known pitfalls, repo constraints (ask `explorer` first if repo facts matter). The dossier is relayed verbatim to the next steps.
2. Two `analyst`s IN PARALLEL with the same dossier under `## Evidence` and the same question: one on `opus` (high), one on `sonnet` (high). Add a third (opus, xhigh) only if the first two disagree on the recommendation. Never show one analyst another's output.
3. `judge` (opus, xhigh) with all proposals verbatim under `## Proposals` and the dossier under `## Evidence`. If it returns `status: blocked`, send its question to `researcher`, then continue the SAME judge with SendMessage so it keeps its table.
4. On an `adr:` path: `/remember decision <one line> (adr: <path>)`. Report to the user: the decision, the main dissent, the revisit triggers. Five lines max.
