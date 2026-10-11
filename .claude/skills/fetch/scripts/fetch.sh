#!/usr/bin/env bash
# Fetch a documentation page through the session proxy and print readable text.
# Usage: fetch.sh <url> [max-lines] [grep-pattern]
# Why: the built-in WebFetch resolves DNS itself and fails in proxy-only containers;
# curl honours HTTPS_PROXY and the CA bundle. Output is bounded to protect the context.
set -u
URL="${1:-}"; MAX="${2:-200}"; PAT="${3:-}"
[ -n "$URL" ] || { echo "usage: fetch.sh <url> [max-lines] [grep-pattern]"; exit 1; }
case "$URL" in https://*) ;; *) echo "only https:// URLs"; exit 1 ;; esac
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
CODE="$(curl -sSL --max-time 40 --max-filesize 5000000 -A 'retool-researcher/1.0' -o "$TMP" -w '%{http_code}' "$URL" 2>"$TMP.err")" || { echo "fetch failed: $(head -c 300 "$TMP.err")"; rm -f "$TMP.err"; exit 1; }
rm -f "$TMP.err"
echo "## $URL  (HTTP $CODE, fetched $(date -u +%F), $(stat -c %s "$TMP") bytes)"
python3 -I - "$TMP" "$MAX" "$PAT" <<'PY'
import html, re, sys
raw = open(sys.argv[1], "rb").read().decode("utf-8", "replace")
limit = int(sys.argv[2]); pat = sys.argv[3]
if "<html" in raw[:4000].lower() or "<body" in raw.lower():
    raw = re.sub(r"(?is)<(script|style|nav|header|footer|svg|noscript).*?</\1>", " ", raw)
    # Table rows become one line: "cell | cell | cell" (MS docs wrap cells in <p> with newlines).
    def row(m: re.Match[str]) -> str:
        cells = re.findall(r"(?is)<t[dh][^>]*>(.*?)</t[dh]>", m.group(1))
        cells = [re.sub(r"\s+", " ", re.sub(r"(?s)<[^>]+>", " ", c)).strip() for c in cells]
        return "\n" + " | ".join(c for c in cells if c) + "\n"
    raw = re.sub(r"(?is)<tr[^>]*>(.*?)</tr>", row, raw)
    raw = re.sub(r"(?i)<br\s*/?>|</(p|div|li|h[1-6]|pre|section|article)>", "\n", raw)
    raw = re.sub(r"(?s)<[^>]+>", " ", raw)
    raw = html.unescape(raw)
lines = [re.sub(r"[ \t]+", " ", l).strip() for l in raw.splitlines()]
lines = [l for l in lines if l]
if pat:
    rx = re.compile(pat, re.I)
    keep = []
    for i, l in enumerate(lines):
        if rx.search(l):
            keep.extend(lines[max(0, i - 2): i + 6])
    lines = list(dict.fromkeys(keep))
print("\n".join(lines[:limit]))
if len(lines) > limit:
    print(f"... ({len(lines) - limit} more lines; narrow with a grep-pattern or raise max-lines)")
PY
