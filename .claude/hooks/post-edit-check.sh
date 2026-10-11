#!/usr/bin/env bash
# PostToolUse(Write|Edit): format + lint only the touched file. Silent on success;
# on problems, inject a short note so the model fixes it now instead of at Stop.
set -u
. "$(dirname "$0")/lib.sh"

F="$(jqi '.tool_input.file_path // empty')"
[ -n "$F" ] && [ -f "$F" ] || exit 0
case "$F" in "$ROOT"/*) ;; *) exit 0 ;; esac   # only project files
REL="$(relpath "$F")"
cd "$ROOT" || exit 0

run_ruff() {
  if [ -x .venv/bin/ruff ]; then .venv/bin/ruff "$@"; elif command -v ruff >/dev/null; then ruff "$@"; else return 0; fi
}

case "$REL" in
  *.py)
    run_ruff format -q "$F" >/dev/null 2>&1 || true
    run_ruff check -q --fix "$F" >/dev/null 2>&1 || true
    OUT="$(run_ruff check --output-format concise "$F" 2>&1 | grep -v '^All checks passed' | head -15)"
    [ -n "$OUT" ] && post_context "ruff ($REL):"$'\n'"$OUT"
    ;;
  .claude/hooks/*.sh|.claude/skills/*/scripts/*.sh|.claude/*.sh)
    chmod +x "$F" 2>/dev/null || true
    OUT="$(bash -n "$F" 2>&1 | head -5)"
    [ -n "$OUT" ] && post_context "bash syntax ($REL):"$'\n'"$OUT"
    ;;
  *.json)
    OUT="$(jq empty "$F" 2>&1 | head -3)"
    [ -n "$OUT" ] && post_context "invalid JSON ($REL): $OUT"
    ;;
esac
exit 0
