---
name: check
description: Run the full quality gate (ruff, mypy --strict, pytest) and show only the tail. Use when you need the result mid-task; the Stop hook runs it automatically at the end.
allowed-tools: Bash(make *)
---
Result of `make check`:

!`make check 2>&1 | grep -vE 'UV_NATIVE_TLS|^uv run' | tail -40`

If anything failed: fix the code (not the test, unless the test is wrong and you say why), then stop. Do not re-run the whole suite; the Stop hook will.
