"""Domain services: the versioned JSON encoding of a report. Pure; no I/O."""

from __future__ import annotations

import hashlib
import json

from retool.reporting.domain.model import SCHEMA_VERSION, RawImageLayout, Report, StageOutput
from retool.shared import Finding, JsonValue, NotAnalysed, ParseError, check_json_value

# 8 MiB of JSON text per encoding, trailing newline excluded; ASCII so chars == bytes (assumption)
MAX_REPORT_CHARS = 1 << 23


def _encode(document: JsonValue, encoder: json.JSONEncoder) -> str:
    """Stream ``document`` through ``encoder``, failing as soon as the cap is passed."""
    parts: list[str] = []
    total = 0
    for chunk in encoder.iterencode(document):
        total += len(chunk)
        if total > MAX_REPORT_CHARS:
            raise ParseError(f"report exceeds {MAX_REPORT_CHARS} chars")
        parts.append(chunk)
    return "".join(parts)


def _canonical() -> json.JSONEncoder:
    return json.JSONEncoder(
        sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
    )


def _pretty() -> json.JSONEncoder:
    return json.JSONEncoder(sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2)


def _finding(finding: Finding) -> JsonValue:
    checks: list[JsonValue] = [*finding.verification.checks]
    verification: dict[str, JsonValue] = {
        "status": finding.verification.status.value,
        "checks": checks,
        "reason": finding.verification.reason,
    }
    return {
        "subject": finding.subject,
        "value": finding.value,
        "provenance": finding.provenance.value,
        "verification": verification,
        "producer": finding.producer,
    }


def _not_analysed(marker: NotAnalysed, stage: StageOutput) -> JsonValue:
    return {"reason": marker.reason, "stage": stage.name}


def _raw_image(layout: RawImageLayout | None) -> JsonValue:
    if layout is None:
        return None
    segments: list[JsonValue] = [
        {
            "name": s.name,
            "start": str(s.start),
            "mem_size": s.mem_size,
            "file_start": s.file_start,
            "file_size": s.file_size,
        }
        for s in layout.segments
    ]
    return {
        "arch": str(layout.arch),
        "entry": None if layout.entry is None else str(layout.entry),
        "segments": segments,
    }


def stage_sha256(stage: StageOutput) -> str:
    """SHA-256 of the canonical encoding of one stage's report fragments.

    Re-validates every finding value first: list/dict values stay mutable after construction.
    """
    for finding in stage.findings:
        check_json_value(finding.value)
    findings: list[JsonValue] = [_finding(f) for f in stage.findings]
    not_analysed: list[JsonValue] = [_not_analysed(n, stage) for n in stage.not_analysed]
    document: dict[str, JsonValue] = {
        "name": stage.name,
        "version": stage.version,
        "findings": findings,
        "not_analysed": not_analysed,
        "raw_image": _raw_image(stage.raw_image),
    }
    text = _encode(document, _canonical())
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def render_json(report: Report) -> str:
    """Render ``report`` as one schema-versioned JSON document plus a trailing newline."""
    hashes = [stage_sha256(stage) for stage in report.stages]
    stages: list[JsonValue] = [
        {"name": stage.name, "version": stage.version, "sha256": digest}
        for stage, digest in zip(report.stages, hashes, strict=True)
    ]
    findings: list[JsonValue] = [_finding(f) for s in report.stages for f in s.findings]
    not_analysed: list[JsonValue] = [
        _not_analysed(n, s) for s in report.stages for n in s.not_analysed
    ]
    document: dict[str, JsonValue] = {
        "schema_version": SCHEMA_VERSION,
        "input": {"sha256": report.input.sha256, "size": report.input.size},
        "stages": stages,
        "findings": findings,
        "not_analysed": not_analysed,
        "raw_image": _raw_image(report.raw_image),
    }
    return _encode(document, _pretty()) + "\n"
