#!/usr/bin/env bash
# Shared helpers for hooks. Source with: . "$(dirname "$0")/lib.sh"
# Every hook reads one JSON object on stdin into $INPUT.

INPUT="$(cat)"
ROOT="${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
STATE="$ROOT/.claude/state"
mkdir -p "$STATE"

jqi() { printf '%s' "$INPUT" | jq -r "$@"; }

# PreToolUse decisions. Reason is shown to the model, keep it one line and actionable.
deny()  { jq -cn --arg r "$1" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'; exit 0; }
ask()   { jq -cn --arg r "$1" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"ask",permissionDecisionReason:$r}}'; exit 0; }

# PostToolUse: inject a short note into the model context.
post_context() { jq -cn --arg c "$1" '{hookSpecificOutput:{hookEventName:"PostToolUse",additionalContext:$c}}'; }

# Path relative to project root (or unchanged if outside).
relpath() { local p="$1"; printf '%s' "${p#"$ROOT"/}"; }
