---
name: remember
description: Record a durable decision or learning in .claude/memory (one line, dated). Use the moment a design decision is made or a non-obvious gotcha is found. Avoid quotes and pipes in the text.
argument-hint: decision|learning <one-line text>
---
!`bash "${CLAUDE_SKILL_DIR}/scripts/remember.sh" $ARGUMENTS`

Reply with the line written, nothing else.
