#!/usr/bin/env bash
# SessionStart: make the env usable (venv on PATH, deps synced) and print a
# ten-line situational brief. Plain stdout becomes model context, so keep it short.
set -u
. "$(dirname "$0")/lib.sh"
cd "$ROOT" || exit 0
SRC="$(jqi '.source // "startup"')"

if [ "$SRC" = "compact" ]; then
  echo "## Resumed after compaction"
  [ -f "$STATE/snapshot.md" ] && cat "$STATE/snapshot.md"
  echo "Rules in CLAUDE.md still apply. Continue the task; do not re-explore what the snapshot already states."
  exit 0
fi

# Environment: venv on PATH for every later Bash call.
if [ ! -x .venv/bin/python ] && command -v uv >/dev/null; then
  uv sync --quiet >"$STATE/setup.log" 2>&1 || echo "note: uv sync failed, see .claude/state/setup.log"
fi
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  {
    echo "export PATH=\"$ROOT/.venv/bin:\$PATH\""
    echo "export VIRTUAL_ENV=\"$ROOT/.venv\""
    echo "export PYTHONDONTWRITEBYTECODE=1"
  } >> "$CLAUDE_ENV_FILE"
fi

DIRTY="$(git status --porcelain 2>/dev/null | wc -l)"
echo "## Session brief"
echo "branch: $(git branch --show-current 2>/dev/null)  dirty files: $DIRTY  last: $(git log -1 --format='%h %s' 2>/dev/null)"
[ "$DIRTY" -gt 0 ] && git status --short | head -10 | sed 's/^/  /'
[ -f "$STATE/snapshot.md" ] && [ "$SRC" = "resume" ] && { echo "previous snapshot:"; sed 's/^/  /' "$STATE/snapshot.md" | head -12; }
exit 0
