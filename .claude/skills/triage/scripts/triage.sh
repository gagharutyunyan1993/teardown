#!/usr/bin/env bash
# Bounded static triage. Never executes the target. Output capped to ~120 lines.
set -u
F="${1:-}"
[ -n "$F" ] && [ -f "$F" ] || { echo "usage: triage.sh <file>  (file not found: '$F')"; exit 1; }

SIZE=$(stat -c %s "$F")
echo "## file"
echo "path:   $F"
echo "size:   $SIZE bytes"
echo "sha256: $(sha256sum "$F" | cut -d' ' -f1)"
echo "md5:    $(md5sum "$F" | cut -d' ' -f1)"
echo "type:   $(file -b "$F" | cut -c1-200)"
echo "mime:   $(file -b --mime-type "$F")"

echo "## entropy (8-bit Shannon; >7.2 suggests packed/encrypted)"
python3 -I - "$F" <<'PY'
import math, sys
from collections import Counter
data = open(sys.argv[1], "rb").read(4 * 1024 * 1024)
n = len(data)
if n:
    c = Counter(data)
    h = -sum((v / n) * math.log2(v / n) for v in c.values())
    print(f"overall: {h:.3f} (first {n} bytes)")
    blk = 65536
    hi = [(i, -sum((v/len(b))*math.log2(v/len(b)) for v in Counter(b).values()))
          for i in range(0, n, blk) for b in [data[i:i+blk]]]
    hot = [f"0x{i:x}:{e:.2f}" for i, e in hi if e > 7.2][:8]
    print("high-entropy 64K blocks:", " ".join(hot) if hot else "none")
PY

MAGIC=$(od -An -tx1 -N4 "$F" | tr -d ' \n')
case "$MAGIC" in
  7f454c46)
    echo "## ELF header"; readelf -h -W "$F" 2>&1 | grep -E 'Class|Data|Type|Machine|Entry|Flags' | sed 's/^ *//'
    echo "## sections"; readelf -S -W "$F" 2>&1 | grep -E '^\s*\[' | sed 's/\[ *\([0-9]*\)\]/[\1]/' | awk '{printf "%-20s %-12s size=%s\n", $2, $3, $6}' | head -40
    echo "## program headers"; readelf -l -W "$F" 2>&1 | grep -E '^\s+(LOAD|INTERP|DYNAMIC|GNU_STACK|GNU_RELRO)' | head -12
    echo "## dynamic"; readelf -d -W "$F" 2>&1 | grep -E 'NEEDED|SONAME|RPATH|RUNPATH|FLAGS|INIT|FINI' | sed 's/^ *//' | head -20
    echo "## imports (undefined dynamic symbols)"; nm -D -u "$F" 2>/dev/null | awk '{print $NF}' | sort -u | head -50 | tr '\n' ' '; echo
    echo "## exports (defined dynamic symbols)"; nm -D --defined-only "$F" 2>/dev/null | awk '{print $NF}' | head -30 | tr '\n' ' '; echo
    echo "## interp"; readelf -p .interp "$F" 2>/dev/null | grep -oE '/[^ ]+' | head -1 ;;
  4d5a*)
    echo "## PE (no PE parser installed; add pefile/lief with uv add when needed)"
    python3 -I - "$F" <<'PY'
import struct, sys
d = open(sys.argv[1], "rb").read(4096)
if len(d) >= 0x40:
    e = struct.unpack_from("<I", d, 0x3C)[0]
    if e + 24 <= len(d) and d[e:e+4] == b"PE\0\0":
        m, ns, ts, _, _, oh, ch = struct.unpack_from("<HHIIIHH", d, e + 4)
        print(f"machine=0x{m:04x} sections={ns} timestamp={ts} opt_hdr={oh} chars=0x{ch:04x}")
        if e + 24 + 2 <= len(d):
            magic = struct.unpack_from("<H", d, e + 24)[0]
            print("format:", {0x10B: "PE32", 0x20B: "PE32+"}.get(magic, hex(magic)))
    else:
        print("e_lfanew out of the first 4K or no PE signature")
PY
    ;;
  cafebabe|feedface|feedfacf|cefaedfe|cffaedfe) echo "## Mach-O (use otool/llvm-objdump if available)"; which otool llvm-objdump 2>/dev/null ;;
  *) echo "## unknown magic: $MAGIC"; echo "## head"; od -A x -t x1z -N 128 "$F" ;;
esac

echo "## strings (printable >= 8, first 40 unique, longest first)"
strings -n 8 "$F" 2>/dev/null | awk '!seen[$0]++' | awk '{ print length, $0 }' | sort -rn | cut -d' ' -f2- | head -40 | cut -c1-120
echo "## suspicious string hits"
strings -n 6 "$F" 2>/dev/null | grep -iE 'http://|https://|\.onion|cmd\.exe|powershell|/bin/sh|ptrace|LD_PRELOAD|VirtualAlloc|WriteProcessMemory|CreateRemoteThread|IsDebuggerPresent|UPX|\.dll$|\.so(\.[0-9]+)*$' | sort -u | head -25
exit 0
