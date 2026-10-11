#!/usr/bin/env bash
# Status line: model | branch±dirty | context used %. Shows token pressure at a glance.
IN="$(cat)"
j() { printf '%s' "$IN" | jq -r "$1" 2>/dev/null; }
MODEL="$(j '.model.display_name // .model.id // "?"')"
DIR="$(j '.workspace.current_dir // .cwd // "."')"
BR="$(git -C "$DIR" branch --show-current 2>/dev/null)"
DIRTY="$(git -C "$DIR" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
CTX="$(j '.context_window.used_percentage // empty')"
[ -n "$CTX" ] && CTX="ctx ${CTX%.*}%" || CTX="ctx ?"
COST="$(j '.cost.total_cost_usd // empty')"
[ -n "$COST" ] && COST=" | \$$(printf '%.2f' "$COST")"
printf 'retool | %s | %s±%s | %s%s' "$MODEL" "${BR:-detached}" "$DIRTY" "$CTX" "$COST"
