---
paths:
  - "samples/**"
---
# samples/ is hostile input
- Never execute, trace, `chmod`, modify, delete or `cat` anything here. Hooks enforce this; do not work around them.
- First look: `/triage samples/<file>`. Deeper work: delegate to the `binary-analyst` agent so the dump stays out of the main context.
- Bounded tools only: `file`, `readelf -h/-S/-d`, `objdump -h`, `hexdump -C -n N -s OFF`, `strings -n 8 | head -N`, `nm -D | head`.
- Refer to a sample by its sha256 prefix in notes and reports, not by content.
