# Learnings (gotchas, environment facts; one line each)
- Cloud container: uv/ruff/mypy/pytest preinstalled; no capstone/lief/pyelftools yet — add with `uv add` when needed.
- Cloud container has no `xxd`; use `hexdump -C -n N` / `od -A x -t x1z`.
- Bash permission rules split on `|`/`&&`; a hook (not a rule) is what catches `curl | sh`.
- 2026-10-11 Container has no direct DNS (CLAUDE_CODE_PROXY_RESOLVES_HOSTS=true): built-in WebFetch may fail with ENOTFOUND even when the network policy allows the host; curl via HTTPS_PROXY works — researchers use .claude/skills/fetch/scripts/fetch.sh
- 2026-10-11 A running subagent keeps the tool list it was spawned with; after editing an agent file spawn a new instance, SendMessage will not pick up new tools
- 2026-10-11 A narrow grep pattern in a fetch brief makes the researcher report facts as unverified that the page does contain; on status partial widen the pattern before concluding the source lacks it
- 2026-10-12 researcher workers hit the 15-turn limit on dossiers with 10+ fetches; brief them with max 8 fetches and tell them to write after the budget, or split the dossier in two
