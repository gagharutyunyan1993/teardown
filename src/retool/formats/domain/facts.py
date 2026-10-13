"""Domain service: the findings and not-analysed markers formats reports for a format."""

from __future__ import annotations

from retool.formats.domain.model import Format
from retool.shared import Finding, JsonValue, NotAnalysed, Provenance, Verification


def magic_finding(fmt: Format, producer: str) -> Finding:
    """The fact that the input starts with ``fmt``'s magic."""
    return Finding(
        "input", {"magic": fmt.value}, Provenance.PARSED, Verification.unverified(), producer
    )


def format_facts(fmt: Format, producer: str) -> tuple[tuple[Finding, ...], tuple[NotAnalysed, ...]]:
    """Return what ``producer`` established about the input's container, and what it did not."""
    if fmt is Format.RAW:
        return (), (NotAnalysed("raw image content not analysed"),)
    if fmt is Format.UNKNOWN:
        # No known magic was read, so there is no fact to report.
        return (), (NotAnalysed("container structure not parsed: unknown format"),)
    reason = f"container structure not parsed: no {fmt.value} parser in this version"
    return (magic_finding(fmt, producer),), (NotAnalysed(reason),)


def parsed_finding(subject: str, value: JsonValue, producer: str) -> Finding:
    """A PARSED, unverified finding about ``subject``."""
    return Finding(subject, value, Provenance.PARSED, Verification.unverified(), producer)
