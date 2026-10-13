"""Findings vocabulary shared by every context that reports facts (ADR 0002)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from retool.shared.errors import ParseError
from retool.shared.json_value import JsonValue, check_json_value

MIN_LLM_CHECKS = 2
MAX_CHECKS = 16
_MAX_TEXT = 256
_PRODUCER = re.compile(r"[a-z0-9_.:-]{1,64}")  # also used for check names


def _is_text(value: str) -> bool:
    return 1 <= len(value) <= _MAX_TEXT and value.isprintable()


class Provenance(StrEnum):
    """Where a finding came from."""

    PARSED = "parsed"
    DISASSEMBLED = "disassembled"
    INFERRED = "inferred"
    LLM_SUGGESTED = "llm_suggested"


@dataclass(frozen=True, slots=True)
class Verification:
    """Outcome of deterministic checks applied to a finding."""

    class Status(StrEnum):
        UNVERIFIED = "unverified"
        PASSED = "passed"
        REJECTED = "rejected"

    status: Verification.Status
    checks: tuple[str, ...] = ()
    reason: str = ""

    def __post_init__(self) -> None:
        if self.status is Verification.Status.UNVERIFIED:
            if self.checks or self.reason:
                raise ParseError("unverified status carries no checks or reason")
        elif self.status is Verification.Status.PASSED:
            if not 1 <= len(self.checks) <= MAX_CHECKS:
                raise ParseError(f"passed status needs 1..{MAX_CHECKS} checks")
            if any(_PRODUCER.fullmatch(c) is None for c in self.checks):
                raise ParseError("invalid check name")
            if len(set(self.checks)) != len(self.checks):
                raise ParseError("duplicate check name")
            if self.reason:
                raise ParseError("passed status carries no reason")
        elif self.status is Verification.Status.REJECTED:
            if not _is_text(self.reason):
                raise ParseError(
                    f"rejected status needs a printable reason of 1..{_MAX_TEXT} chars"
                )
            if self.checks:
                raise ParseError("rejected status carries no checks")
        else:
            raise ParseError("invalid verification status")

    @classmethod
    def unverified(cls) -> Verification:
        return cls(Verification.Status.UNVERIFIED)

    @classmethod
    def passed(cls, checks: tuple[str, ...]) -> Verification:
        return cls(Verification.Status.PASSED, checks=checks)

    @classmethod
    def rejected(cls, reason: str) -> Verification:
        return cls(Verification.Status.REJECTED, reason=reason)


@dataclass(frozen=True, slots=True)
class Finding:
    """One fact about a subject, with its provenance and verification state."""

    subject: str
    value: JsonValue
    provenance: Provenance
    verification: Verification
    producer: str

    def __post_init__(self) -> None:
        if not _is_text(self.subject):
            raise ParseError(f"finding subject must be 1..{_MAX_TEXT} printable chars")
        if _PRODUCER.fullmatch(self.producer) is None:
            raise ParseError("invalid producer name")
        check_json_value(self.value)
        if (
            self.provenance is Provenance.LLM_SUGGESTED
            and self.verification.status is Verification.Status.PASSED
            and len(self.verification.checks) < MIN_LLM_CHECKS
        ):
            raise ParseError(f"llm-suggested finding needs at least {MIN_LLM_CHECKS} checks")


@dataclass(frozen=True, slots=True)
class NotAnalysed:
    """An explicit marker that something was not analysed, and why."""

    reason: str

    def __post_init__(self) -> None:
        if not _is_text(self.reason):
            raise ParseError(f"not-analysed reason must be 1..{_MAX_TEXT} printable chars")
