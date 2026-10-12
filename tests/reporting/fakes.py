"""Builders and fakes for reporting tests."""

from __future__ import annotations

from retool.reporting import InputDigest, RawImageLayout, Report, StageOutput
from retool.shared import Finding, JsonValue, NotAnalysed, Provenance, Verification

PARSED = Provenance.PARSED


def fnd(
    value: JsonValue,
    producer: str = "s",
    provenance: Provenance = PARSED,
    verification: Verification | None = None,
) -> Finding:
    return Finding("input", value, provenance, verification or Verification.unverified(), producer)


def stage(
    name: str = "s",
    version: str = "1",
    findings: tuple[Finding, ...] = (),
    not_analysed: tuple[NotAnalysed, ...] = (),
    raw_image: RawImageLayout | None = None,
) -> StageOutput:
    return StageOutput(name, version, findings, not_analysed, raw_image)


digest = InputDigest("0" * 64, 0)


class FakeFacts:
    """FactSource returning a fixed report (or raising a fixed error); counts calls."""

    def __init__(self, report_or_exc: Report | Exception) -> None:
        self._result = report_or_exc
        self.calls = 0

    def collect(self) -> Report:
        self.calls += 1
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


class GrowingSource:
    """ByteSource that grows by 16 bytes once it has been read: a TOCTOU stand-in."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._grown = False
        self.calls: list[tuple[int, int]] = []

    @property
    def size(self) -> int:
        return len(self._data) + (16 if self._grown else 0)

    def read(self, offset: int, size: int) -> bytes:
        self._grown = True
        self.calls.append((offset, size))
        end = min(offset + size, self.size)
        return bytes(max(0, end - offset))
