# Single entry point for every check. Hooks and skills call these targets,
# so swapping the stack means editing this file only.
.PHONY: setup fmt lint typecheck test check

UV ?= uv

setup:
	$(UV) sync --quiet

fmt:
	$(UV) run ruff format src tests

lint:
	$(UV) run ruff check src tests

typecheck:
	$(UV) run mypy

test:
	$(UV) run pytest

check: lint typecheck test
