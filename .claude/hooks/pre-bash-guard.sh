#!/usr/bin/env bash
# PreToolUse(Bash): block destructive commands, execution of untrusted samples,
# and token-wasting dumps. Grey-zone commands fall through to "ask".
set -u
. "$(dirname "$0")/lib.sh"

CMD="$(jqi '.tool_input.command // empty')"
[ -z "$CMD" ] && exit 0

E='[[:space:]]'

# --- destructive -----------------------------------------------------------
if printf '%s' "$CMD" | grep -Eq "rm$E+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|-r$E+-f|-f$E+-r)$E+(/|~|\\\$HOME|\\.git|\\*|\\.)($E|$)"; then
  deny "rm -rf on a root/home/.git/wildcard target is blocked. Delete specific paths."
fi
if printf '%s' "$CMD" | grep -Eq "git$E+push$E+.*(--force($E|$)|$E-f($E|$))"; then
  deny "Force push is blocked. Use --force-with-lease only if the user asked for it."
fi
if printf '%s' "$CMD" | grep -Eq "(curl|wget)[^|]*\\|$E*(sudo$E+)?(ba|z|da|k)?sh($E|$)"; then
  deny "Piping a download into a shell is blocked. Download to a file, inspect, then run."
fi
if printf '%s' "$CMD" | grep -Eq "git$E+(reset$E+--hard|clean$E+-[a-zA-Z]*f|checkout$E+(--$E+)?\\.($E|$)|restore$E+\\.($E|$)|branch$E+-D)"; then
  ask "This discards work or deletes a branch. Confirm with the user."
fi

# --- untrusted samples must never execute -----------------------------------
# Direct execution: samples/x or ./samples/x in command position.
# Interpreters/tracers: only when the sample is the script/target itself (first non-option arg),
# so 'bash triage.sh samples/x' and 'python -m retool samples/x' stay allowed.
if printf '%s' "$CMD" | grep -Eq "(^|[;&|([:space:]])(\\./|$ROOT/)?samples/[^[:space:];&|]+"; then
  # Allowed when the sample is an argument of an analysis tool, not the command itself.
  if printf '%s' "$CMD" | grep -Eq "(^|[;&|(]$E*)(\\./|$ROOT/)?samples/"; then
    deny "Never execute files from samples/. Analyse statically (file, readelf, objdump, strings | head) or use /triage."
  fi
fi
if printf '%s' "$CMD" | grep -Eq "chmod$E+[^;&|]*samples/"; then
  deny "Do not make samples executable."
fi
if printf '%s' "$CMD" | grep -Eq "(^|[;&|([:space:]])(python[0-9.]*|bash|sh|zsh|perl|ruby|node|wine|wine64|qemu-[a-z0-9-]+|ld\\.so|ld-linux[^ ]*|strace|ltrace|gdb|lldb|rr)$E+(-[^[:space:]]+$E+)*[\"']?(\\./|$ROOT/)?samples/"; then
  deny "Running or tracing a sample is blocked (untrusted code). Static analysis only; dynamic analysis needs an isolated VM the user sets up."
fi

# --- token guards -----------------------------------------------------------
# Hex/strings dumps without a limit or a pipe flood the context.
if printf '%s' "$CMD" | grep -Eq "(^|[;&([:space:]])(xxd|hexdump|od|strings)$E" && ! printf '%s' "$CMD" | grep -Eq "\\||$E-(l|n|s|c|N)$E*[0-9]"; then
  deny "Bound the output: add '| head -n 64', or -n/-l/-N <count>. Full dumps waste context."
fi
if printf '%s' "$CMD" | grep -Eq "(^|[;&([:space:]])cat$E+[^|;&]*samples/" && ! printf '%s' "$CMD" | grep -q '|'; then
  deny "Do not cat samples. Use 'file', 'hexdump -C -n 256', 'strings | head', or /triage."
fi
if printf '%s' "$CMD" | grep -Eq "(^|[;&([:space:]])(objdump|readelf)$E+[^|;&]*(-d|-D|-s|--disassemble|-x|-a|--all)($E|$)" && ! printf '%s' "$CMD" | grep -Eq "\\|$E*(head|grep|sed|awk|tail|wc|less|cut|sort|uniq)"; then
  deny "Full disassembly/dump floods the context. Pipe through head/grep, or target a symbol/section (-j .text --start-address=...)."
fi
if printf '%s' "$CMD" | grep -Eq "(^|[;&([:space:]])(pytest|uv$E+run$E+pytest)($E|$)" && printf '%s' "$CMD" | grep -Eq "(^|$E)-(v|vv|vvv|s)($E|$)"; then
  deny "Run tests quietly: 'make test' or 'pytest -q -x'. Verbose test output wastes context."
fi

exit 0
