#!/usr/bin/env bash
# SubagentStop: a worker may not finish without the REPORT block, and an implementer
# may not claim "done" without a green make check. The reason goes back to the worker.
set -u
. "$(dirname "$0")/lib.sh"

[ "$(jqi '.stop_hook_active // false')" = "true" ] && exit 0
TYPE="$(jqi '.agent_type // empty')"
MSG="$(jqi '.last_assistant_message // empty')"
case "$TYPE" in planner|implementer|reviewer|researcher|analyst|judge|binary-analyst) ;; *) exit 0 ;; esac

fail() { printf '%s\n' "$1" >&2; exit 2; }
printf '%s' "$MSG" | grep -qE '^\s*REPORT\s*$' || fail "Finish with the REPORT block (status/changed/verified/deviations/open/confidence), see your agent file."
STATUS="$(printf '%s' "$MSG" | grep -oiE '^\s*status:\s*(done|partial|blocked)' | tail -1 | awk '{print tolower($2)}')"
[ -n "$STATUS" ] || fail "REPORT needs 'status: done | partial | blocked'."
printf '%s' "$MSG" | grep -qiE '^\s*verified:\s*\S' || fail "REPORT needs a non-empty 'verified:' line stating what you actually ran or read."
printf '%s' "$MSG" | grep -qiE '^\s*confidence:\s*(high|medium|low)' || fail "REPORT needs 'confidence: high | medium | low'."

if [ "$TYPE" = "implementer" ] && [ "$STATUS" = "done" ]; then
  printf '%s' "$MSG" | grep -qiE '^\s*verified:.*make check:\s*pass' \
    || fail "status: done requires 'verified: make check: pass'. Run make check; if it is red, report status: partial with the failure."
fi
if [ "$TYPE" = "analyst" ]; then
  printf '%s' "$MSG" | grep -qF "## Recommendation" || fail "Analyst output needs a '## Recommendation' section (one option, one sentence)."
  [ "$(printf '%s' "$MSG" | grep -c '(src:')" -ge 2 ] || fail "Back your claims: at least two '(src: <url or path>, <date/version>)' markers, or label claims '(assumption)' and lower confidence."
  printf '%s' "$MSG" | grep -qiE '^\s*would change my mind if:\s*\S' || fail "State 'would change my mind if: <specific evidence>'."
fi
if [ "$TYPE" = "researcher" ]; then
  [ "$(printf '%s' "$MSG" | grep -cE '\(src:|\(unverified\)')" -ge 1 ] || fail "Mark every fact '(src: <url>, <date/version>)' or '(unverified)'."
fi
if [ "$TYPE" = "judge" ]; then
  printf '%s' "$MSG" | grep -qiE '^\s*verdict:\s*\S' || fail "Judge REPORT needs 'verdict: <chosen option>'."
  printf '%s' "$MSG" | grep -qiE '^\s*adr:\s*\S' || fail "Judge REPORT needs 'adr: <docs/decisions/NNNN-slug.md or none>'."
  printf '%s' "$MSG" | grep -qiE '^\s*unresolved:\s*\S' || fail "Judge REPORT needs 'unresolved: <list or none>'."
  if [ "$STATUS" = "done" ]; then
    ADR="$(printf '%s' "$MSG" | grep -oiE '^\s*adr:\s*\S+' | tail -1 | awk '{print $2}')"
    [ -f "$ROOT/$ADR" ] || fail "status: done requires the ADR file to exist at the 'adr:' path ($ADR not found)."
  fi
fi
if [ "$TYPE" = "reviewer" ]; then
  printf '%s' "$MSG" | grep -qiE '^\s*verdict:\s*(ship|fix first)' || fail "Reviewer REPORT needs 'verdict: ship | fix first'."
fi
exit 0
