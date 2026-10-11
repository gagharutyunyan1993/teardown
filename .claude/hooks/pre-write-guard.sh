#!/usr/bin/env bash
# PreToolUse(Write|Edit): protect untrusted inputs, generated files and VCS internals.
set -u
. "$(dirname "$0")/lib.sh"

F="$(jqi '.tool_input.file_path // empty')"
[ -z "$F" ] && exit 0
REL="$(relpath "$F")"

case "$REL" in
  samples/*)
    case "$REL" in samples/README.md|samples/.gitkeep) exit 0 ;; esac
    deny "samples/ holds untrusted inputs; never write or modify them from the agent. Test fixtures go to tests/fixtures/." ;;
  uv.lock) deny "Generated: run 'uv lock' / 'uv add' instead of editing uv.lock." ;;
  .git/*|.venv/*|*/__pycache__/*) deny "Do not write into VCS/tool internals." ;;
  .env|.env.*|*.pem|*.key) deny "Secrets are never written by the agent." ;;
esac
exit 0
