"""Ports: capabilities the reporting core needs from the outside world."""

from __future__ import annotations

from typing import Protocol

from retool.reporting.domain.model import Report


class FactSource(Protocol):
    """Supplies the facts to report, already assembled into a Report."""

    def collect(self) -> Report: ...
