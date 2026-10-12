"""Domain service: the findings and not-analysed markers formats reports for a format."""

from __future__ import annotations

from retool.formats.domain.model import Format
from retool.shared import Finding, NotAnalysed, Provenance, Verification


def format_facts(fmt: Format, producer: str) -> tuple[tuple[Finding, ...], tuple[NotAnalysed, ...]]:
    """Return what ``producer`` established about the input's container, and what it did not."""
    if fmt is Format.RAW:
        return (), (NotAnalysed("raw image content not analysed"),)
    if fmt is Format.UNKNOWN:
        # No known magic was read, so there is no fact to report.
        return (), (NotAnalysed("container structure not parsed: unknown format"),)
    finding = Finding(
        "input", {"magic": fmt.value}, Provenance.PARSED, Verification.unverified(), producer
    )
    reason = f"container structure not parsed: no {fmt.value} parser in this version"
    return (finding,), (NotAnalysed(reason),)
