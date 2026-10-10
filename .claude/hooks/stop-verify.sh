#!/usr/bin/env bash
# Stop: if code changed since the last verified state, run `make check` once and
# block the stop with a compact failure report. Cheap no-op when nothing changed.
set -u
. "$(dirname "$0")/lib.sh"

[ "$(jqi '.stop_hook_active // false')" = "true" ] && exit 0
cd "$ROOT" || exit 0
[ -f Makefile ] && [ -d .venv ] || exit 0

WATCH="src tests pyproject.toml Makefile"
# Fingerprint = HEAD + working-tree diff + untracked files with mtimes.
FP="$( { git rev-parse HEAD 2>/dev/null; git diff HEAD -- $WATCH 2>/dev/null; \
        git ls-files --others --exclude-standard -- $WATCH 2>/dev/null | xargs -r stat -c '%n %Y'; } | sha256sum | cut -c1-16)"
[ -f "$STATE/verified.fp" ] && [ "$(cat "$STATE/verified.fp")" = "$FP" ] && exit 0

LOG="$STATE/check.log"
if make check >"$LOG" 2>&1; then
  printf '%s' "$FP" > "$STATE/verified.fp"
  exit 0
fi

{
  echo "make check failed. Fix before finishing (log: .claude/state/check.log):"
  grep -Ev '^(uv run|warning: The .UV_NATIVE_TLS|make: \*\*\*)' "$LOG" | grep -E 'error|Error|FAILED|failed|E   |assert|-->|\.py:[0-9]+' | head -30
} >&2
exit 2
