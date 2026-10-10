# retool

Reverse-engineering toolkit in Python. Early stage.

```sh
uv sync            # deps
make check         # ruff + mypy --strict + pytest
uv run retool info <file>
```

Working with Claude Code: the harness in `.claude/` (hooks, agents, skills, rules) is documented in `CLAUDE.md`.
Useful slash commands: `/triage <sample>`, `/analyze <sample>`, `/check`, `/commit`, `/remember`, `/harness-check`.
