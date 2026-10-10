---
name: analyze
description: Deep static analysis of a sample in a forked context via the binary-analyst agent; the report lands in analysis/ and only a short summary returns. Use after /triage when more detail is needed.
argument-hint: <path-to-sample> [question]
context: fork
agent: binary-analyst
---
Analyse `$ARGUMENTS`. Follow your procedure; write the report to `analysis/`; reply with the 10-line summary only.
