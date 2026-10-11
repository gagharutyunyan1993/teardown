#!/usr/bin/env bash
# Append a dated one-liner to DECISIONS.md or LEARNINGS.md. Usage: remember.sh decision|learning text...
set -u
ROOT="${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
KIND="${1:-}"; shift || true
TEXT="$*"
case "$KIND" in
  decision|d) F="$ROOT/.claude/memory/DECISIONS.md" ;;
  learning|l) F="$ROOT/.claude/memory/LEARNINGS.md" ;;
  *) echo "usage: /remember decision|learning <text>"; exit 1 ;;
esac
[ -n "$TEXT" ] || { echo "empty text"; exit 1; }
TEXT="$(printf '%s' "$TEXT" | tr -s ' ' | cut -c1-200)"
LINE="- $(date +%F) $TEXT"
if grep -qF -- "$TEXT" "$F"; then echo "already recorded: $TEXT"; exit 0; fi
printf '%s\n' "$LINE" >> "$F"
echo "$(basename "$F"): $LINE"
