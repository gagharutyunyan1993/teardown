#!/usr/bin/env bash
# PreToolUse(Read): keep binaries, generated files and huge files out of the context.
set -u
. "$(dirname "$0")/lib.sh"

F="$(jqi '.tool_input.file_path // empty')"
[ -z "$F" ] && exit 0
[ -f "$F" ] || exit 0
REL="$(relpath "$F")"
HAS_RANGE="$(jqi 'if (.tool_input.offset // .tool_input.limit) then "1" else "" end')"

case "$REL" in
  uv.lock|*.lock|package-lock.json|*.min.js|*.min.css)
    deny "Generated file. Grep it for the specific entry instead of reading it." ;;
  .venv/*|.git/*|*/__pycache__/*|*.pyc|.mypy_cache/*|.ruff_cache/*|.pytest_cache/*)
    deny "Tool cache / VCS internals. Nothing useful here." ;;
esac

MIME="$(file -b --mime-type "$F" 2>/dev/null || echo unknown)"
SIZE="$(stat -c %s "$F" 2>/dev/null || echo 0)"

case "$MIME" in
  image/*|application/pdf) exit 0 ;;        # the Read tool renders these
  text/*|application/json|application/xml|application/toml|application/x-yaml|inode/x-empty) ;;
  *)
    case "$REL" in samples/*) hint="use /triage $REL" ;; *) hint="use file, hexdump -C -n 256, strings | head" ;; esac
    deny "Binary ($MIME). Reading it dumps garbage into context; $hint." ;;
esac

if [ "$SIZE" -gt 1048576 ]; then
  deny "File is $((SIZE / 1024)) KiB. Grep it, or Read with offset/limit."
fi
if [ -z "$HAS_RANGE" ]; then
  LINES="$(wc -l < "$F")"
  if [ "$LINES" -gt 1200 ]; then
    deny "File has $LINES lines. Grep for the symbol first, then Read with offset/limit around it."
  fi
fi
exit 0
