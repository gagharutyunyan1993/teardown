#!/usr/bin/env bash
# PreToolUse(Agent): the orchestrator may only delegate with a complete contract prompt,
# to a known worker, with an explicit model and effort. Sloppy briefs are rejected here.
set -u
. "$(dirname "$0")/lib.sh"

TYPE="$(jqi '.tool_input.subagent_type // empty')"
MODEL="$(jqi '.tool_input.model // empty')"
EFFORT="$(jqi '.tool_input.effort // empty')"
PROMPT="$(jqi '.tool_input.prompt // empty')"
ALLOWED=" planner architect implementer reviewer researcher analyst judge explorer binary-analyst test-runner claude-code-guide "

[ -z "$TYPE" ] && deny "Name the worker: subagent_type must be one of:$ALLOWED(see .claude/agents/orchestrator.md §1)."
case "$ALLOWED" in *" $TYPE "*) ;; *) deny "Unknown worker '$TYPE'. Use one of:$ALLOWED" ;; esac
[ "$MODEL" = "fable" ] && deny "Workers never run on fable. Pick opus/sonnet/haiku per the routing table."
[ -z "$MODEL" ] && deny "Set model explicitly (opus|sonnet|haiku) per the routing table in orchestrator.md §1."
[ -z "$EFFORT" ] && deny "Set effort explicitly (low|medium|high|xhigh) per the routing table in orchestrator.md §1."
case "$TYPE" in
  explorer|test-runner) [ "$MODEL" = "haiku" ] || deny "$TYPE runs on haiku (cheap lookups); do not spend $MODEL on it." ;;
  judge) [ "$MODEL" = "opus" ] && [ "$EFFORT" = "xhigh" ] || deny "judge runs on opus at xhigh: it is the one place where depth is bought on purpose." ;;
  analyst) [ "$MODEL" != "haiku" ] || deny "analyst needs opus or sonnet; haiku cannot carry an evidence-based argument." ;;
  architect) [ "$MODEL" = "opus" ] || deny "architect runs on opus; boundary judgement is not a place to save." ;;
esac
# A planner brief must point at the accepted architecture so specs are placed correctly.
if [ "$TYPE" = "planner" ] || [ "$TYPE" = "architect" ]; then
  printf '%s' "$PROMPT" | grep -qF "ARCHITECTURE.md" || deny "Reference docs/architecture/ARCHITECTURE.md in the brief (Context) so the $TYPE works against the accepted plan."
fi

MISSING=""
for h in "## Goal" "## Done when" "## Context" "## Report"; do
  printf '%s' "$PROMPT" | grep -qF "$h" || MISSING="$MISSING '$h'"
done
[ -n "$MISSING" ] && deny "Contract prompt incomplete, missing:$MISSING. Use the template in orchestrator.md §2 (Role/Goal/Done when/Context/Constraints/Steps/Report)."
printf '%s' "$PROMPT" | grep -qE '^\s*- ' || deny "'## Done when' needs at least one bulleted, verifiable criterion."

case "$TYPE" in
  analyst) printf '%s' "$PROMPT" | grep -qF "## Evidence" || deny "An analyst brief needs '## Evidence' (the researcher's dossier, verbatim). No dossier, no analysts."
           printf '%s' "$PROMPT" | grep -qiE "not seen|independent" || deny "State in the brief that the analyst works independently and has not seen other proposals." ;;
  judge)   printf '%s' "$PROMPT" | grep -qF "## Proposals" || deny "A judge brief needs '## Proposals' with every analyst's output verbatim."
           printf '%s' "$PROMPT" | grep -qF "## Evidence" || deny "A judge brief needs '## Evidence' (the same dossier the analysts saw)."
           [ "$(printf '%s' "$PROMPT" | grep -c '## Recommendation')" -ge 2 ] || deny "The judge needs at least two independent proposals (two '## Recommendation' sections) before it can decide." ;;
esac

LEN=${#PROMPT}
[ "$LEN" -gt 15000 ] && deny "Prompt is $LEN chars. Over 15k is a sign of pasted dumps; reference files/spec paths instead."
[ "$LEN" -lt 300 ] && deny "Prompt is only $LEN chars; a worker cannot act on it without rediscovering context. Fill Context and Done when."
exit 0
