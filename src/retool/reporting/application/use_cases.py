"""Use cases of the reporting context. Orchestration only."""

from __future__ import annotations

from retool.reporting.domain.ports import FactSource
from retool.reporting.domain.services import render_json


class RenderJsonReport:
    """Collect the facts and render them as the versioned JSON report."""

    def __init__(self, facts: FactSource) -> None:
        self._facts = facts

    def execute(self) -> str:
        return render_json(self._facts.collect())
