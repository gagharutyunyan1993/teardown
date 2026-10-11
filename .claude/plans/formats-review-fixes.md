# formats.py review fixes (from reviewer, 2026-10-11)

## Goal
Make `retool.formats.detect` accept `bytes | memoryview` and cover the review's missing test cases.

## Non-goals
PE/Mach-O header validation (belongs to the future per-format parsers).

## Public interface
`def detect(data: bytes | memoryview) -> Format` — unchanged name/return.

## Files
- modify `src/retool/formats.py`
- modify `tests/test_formats.py`

## Notes
1. `head = bytes(data[:_HEADER_LEN])` so memoryview input compares equal to bytes literals (copies at most 4 bytes).
2. Docstring: note that `MZ` marks a PE *candidate* (DOS stub) and `\xca\xfe\xba\xbe` is ambiguous with Java class files; disambiguation is the parsers' job.

## Test cases (add to the parametrize list)
1. `b"MZ"` → PE
2. `b"M"` → UNKNOWN
3. `b"\xfe\xed\xfa\xce"`, `b"\xce\xfa\xed\xfe"`, `b"\xfe\xed\xfa\xcf"` → MACHO
4. `b"\xcf\xfa\xed"` → UNKNOWN
5. `memoryview(b"\x7fELF\x02")` → ELF; `bytearray(b"MZ\x90")` → PE

## Acceptance criteria
- `make check` green; all cases above present and passing.
- No other behaviour change.
