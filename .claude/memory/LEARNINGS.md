# Learnings (gotchas, environment facts; one line each)
- Cloud container: uv/ruff/mypy/pytest preinstalled; no capstone/lief/pyelftools yet — add with `uv add` when needed.
- Cloud container has no `xxd`; use `hexdump -C -n N` / `od -A x -t x1z`.
- Bash permission rules split on `|`/`&&`; a hook (not a rule) is what catches `curl | sh`.
- 2026-10-11 Container has no direct DNS (CLAUDE_CODE_PROXY_RESOLVES_HOSTS=true): built-in WebFetch may fail with ENOTFOUND even when the network policy allows the host; curl via HTTPS_PROXY works — researchers use .claude/skills/fetch/scripts/fetch.sh
