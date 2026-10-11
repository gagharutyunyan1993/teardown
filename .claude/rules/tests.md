---
paths:
  - "tests/**"
---
# Test rules
- Run with `make test` or `uv run pytest -q -x tests/<file>.py`. Never `-v`/`-s`.
- Fixtures under `tests/fixtures/` stay under 64 KiB and are synthetic (built by a script in `tests/fixtures/build.py`), never copied from `samples/`.
- A failing test is reported by the Stop hook; fix the code, not the assertion, unless the test is wrong and you say why.
