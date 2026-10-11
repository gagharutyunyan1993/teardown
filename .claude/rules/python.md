---
paths:
  - "src/**/*.py"
  - "tests/**/*.py"
---
# Python rules
- Full type hints; `mypy --strict` must pass. `from __future__ import annotations` at the top of every module.
- Parsing untrusted bytes: take `bytes | memoryview`, check `offset + size <= len(data)` before every `struct.unpack_from`; reject absurd counts (cap table sizes); never allocate based on an unchecked length field.
- Errors: raise `retool.shared.ParseError(reason, offset=...)`; bounds via `retool.shared.ByteRange(...).check_within(size)`. No bare `except`.
- No `print` in library code; the CLI layer prints. Use `logging` for diagnostics.
- Small pure functions over classes with state. Dataclasses (`frozen=True, slots=True`) for parsed structures.
- Tests: one behaviour per test, parametrize edge cases (empty, truncated, overflowing lengths). Build fixtures with `struct.pack`, do not commit real binaries.
- Do not add dependencies for something `struct` can do in 20 lines.
