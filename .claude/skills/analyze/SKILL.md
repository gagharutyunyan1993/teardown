---
name: analyze
description: Deep static analysis of a sample via the binary-analyst worker; the report lands in analysis/ and only a short summary returns to the orchestrator. Use after /triage when more detail is needed.
argument-hint: <path-to-sample> [question]
---
Delegate to `binary-analyst` with model `opus`, effort `high`, using the contract prompt:
- Goal: answer the question about `$ARGUMENTS` (if no question is given: what is this file, what does it do, how is it built).
- Done when: `analysis/<sha256-prefix>.md` exists with the sections from the agent file; the summary answers the question or states what could not be determined.
- Context: path from `$ARGUMENTS`; any facts already known from /triage (paste the 5 most relevant lines, not the whole report).
- Constraints: static only; every tool bounded; never execute.
- Report: path + 10-line summary.
Relay the summary to the user in Russian, at most 10 lines.
