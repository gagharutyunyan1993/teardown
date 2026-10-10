---
name: harness-check
description: Validate the Claude Code harness — settings JSON, hook syntax and executability, and pipe-tests of every guard with synthetic payloads. Run after any change under .claude/.
allowed-tools: Bash(bash *check.sh*)
---
Harness self-test:

!`bash "${CLAUDE_SKILL_DIR}/scripts/check.sh" 2>&1 | tail -60`

If any line starts with FAIL, fix the hook or the expectation (whichever is wrong) and run `/harness-check` again. Reply with the pass/fail counts only.
