# Learnings (gotchas, environment facts; one line each)
- Cloud container: uv/ruff/mypy/pytest preinstalled; no capstone/lief/pyelftools yet — add with `uv add` when needed.
- Cloud container has no `xxd`; use `hexdump -C -n N` / `od -A x -t x1z`.
- Bash permission rules split on `|`/`&&`; a hook (not a rule) is what catches `curl | sh`.
- 2026-10-11 Cloud env network policy blocked learn.microsoft.com for WebFetch (DNS ENOTFOUND); researcher must mark facts (unverified) until the host is allowed in environment settings
