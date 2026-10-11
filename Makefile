# Single entry point for every check. Hooks and skills call these targets,
# so swapping the stack means editing this file only.
.PHONY: setup fmt lint typecheck arch test check

UV ?= uv

setup:
	$(UV) sync --quiet

fmt:
	$(UV) run ruff format src tests

lint:
	$(UV) run ruff check src tests

typecheck:
	$(UV) run mypy

arch:
	$(UV) run lint-imports --no-cache 2>&1 | grep -E "KEPT|BROKEN|Contracts:|^-|Error|Traceback" || exit 1; $(UV) run lint-imports --no-cache >/dev/null
	$(UV) run python tools/archcheck.py

test:
	$(UV) run pytest

check: lint typecheck arch test
