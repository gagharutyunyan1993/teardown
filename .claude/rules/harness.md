---
paths:
  - ".claude/**"
  - "CLAUDE.md"
  - "Makefile"
---
# Editing the harness
- Hooks read one JSON object on stdin and source `.claude/hooks/lib.sh` (`deny`, `ask`, `post_context`, `jqi`).
- After changing a hook or settings, run `/harness-check`: it validates JSON, syntax-checks scripts and pipe-tests every guard with synthetic payloads. Add a case there for every new rule.
- Orchestration is enforced by three things: `agent: orchestrator` in settings (tool restriction on the main thread), `pre-agent-guard.sh` (contract prompt + model/effort), `subagent-stop-check.sh` (REPORT block). Change one, re-test all.
- Permission rules are matched per subcommand (split on `|`, `&&`, `;`). Anything needing context (pipes, paths) belongs in a hook, not a rule.
- Keep CLAUDE.md under 80 lines and rules under 20 lines each; they are loaded every session.
- Settings edits take effect after `/hooks` is opened once or the session restarts.
