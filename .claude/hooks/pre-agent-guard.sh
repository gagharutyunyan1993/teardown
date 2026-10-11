#!/usr/bin/env bash
# PreToolUse(Agent): the orchestrator may only delegate with a complete contract prompt,
# to a known worker, with an explicit model and effort. Sloppy briefs are rejected here.
set -u
. "$(dirname "$0")/lib.sh"

TYPE="$(jqi '.tool_input.subagent_type // empty')"
MODEL="$(jqi '.tool_input.model // empty')"
EFFORT="$(jqi '.tool_input.effort // empty')"
PROMPT="$(jqi '.tool_input.prompt // empty')"
ALLOWED=" planner implementer reviewer researcher explorer binary-analyst test-runner claude-code-guide "

[ -z "$TYPE" ] && deny "Name the worker: subagent_type must be one of:$ALLOWED(see .claude/agents/orchestrator.md §1)."
case "$ALLOWED" in *" $TYPE "*) ;; *) deny "Unknown worker '$TYPE'. Use one of:$ALLOWED" ;; esac
[ "$MODEL" = "fable" ] && deny "Workers never run on fable. Pick opus/sonnet/haiku per the routing table."
[ -z "$MODEL" ] && deny "Set model explicitly (opus|sonnet|haiku) per the routing table in orchestrator.md §1."
[ -z "$EFFORT" ] && deny "Set effort explicitly (low|medium|high|xhigh) per the routing table in orchestrator.md §1."
case "$TYPE" in
  explorer|test-runner) [ "$MODEL" = "haiku" ] || deny "$TYPE runs on haiku (cheap lookups); do not spend $MODEL on it." ;;
esac

MISSING=""
for h in "## Goal" "## Done when" "## Context" "## Report"; do
  printf '%s' "$PROMPT" | grep -qF "$h" || MISSING="$MISSING '$h'"
done
[ -n "$MISSING" ] && deny "Contract prompt incomplete, missing:$MISSING. Use the template in orchestrator.md §2 (Role/Goal/Done when/Context/Constraints/Steps/Report)."
printf '%s' "$PROMPT" | grep -qE '^\s*- ' || deny "'## Done when' needs at least one bulleted, verifiable criterion."

LEN=${#PROMPT}
[ "$LEN" -gt 15000 ] && deny "Prompt is $LEN chars. Over 15k is a sign of pasted dumps; reference files/spec paths instead."
[ "$LEN" -lt 300 ] && deny "Prompt is only $LEN chars; a worker cannot act on it without rediscovering context. Fill Context and Done when."
exit 0
