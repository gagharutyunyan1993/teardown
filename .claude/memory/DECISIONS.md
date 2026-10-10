# Decisions (architecture / process; one line each, `YYYY-MM-DD what — why`)
- 2026-10-10 Python 3.12+, uv, ruff, mypy --strict, pytest — fastest path for RE tooling; stack swappable via Makefile only.
- 2026-10-10 All checks via `make` targets — hooks/skills never call tools directly.
- 2026-10-10 samples/ is read-only, never executed; static analysis only inside the agent.
