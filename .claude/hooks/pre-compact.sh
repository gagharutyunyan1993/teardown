#!/usr/bin/env bash
# PreCompact: snapshot working state so the post-compact session can resume precisely.
set -u
. "$(dirname "$0")/lib.sh"
cd "$ROOT" || exit 0
{
  echo "snapshot: $(date -u +%FT%TZ) trigger=$(jqi '.trigger // "?"')"
  echo "branch: $(git branch --show-current 2>/dev/null)"
  echo "last commit: $(git log -1 --format='%h %s' 2>/dev/null)"
  echo "uncommitted:"
  git status --short 2>/dev/null | head -30 | sed 's/^/  /'
  echo "diff stat:"
  git diff --stat HEAD 2>/dev/null | tail -8 | sed 's/^/  /'
} > "$STATE/snapshot.md"
exit 0
