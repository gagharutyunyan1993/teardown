---
name: remember
description: Record a durable decision or learning in .claude/memory (one line, dated). Use the moment a design decision is made or a non-obvious gotcha is found.
argument-hint: decision|learning <one-line text>
allowed-tools: Edit, Read
---
Append one line to the right file, newest last, format `- YYYY-MM-DD text — why` (today: !`date +%F`):
- `decision ...` → `.claude/memory/DECISIONS.md`
- `learning ...` → `.claude/memory/LEARNINGS.md`

Input: `$ARGUMENTS`

Tighten the wording to one line (under 160 chars). If the file already has an equivalent line, update it instead of duplicating. Reply with the line written, nothing else.
