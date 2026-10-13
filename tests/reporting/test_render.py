import hashlib
import json
import re

import pytest

from retool.reporting import SCHEMA_VERSION, Report, render_json, stage_sha256
from retool.reporting.domain import services
from retool.shared import NotAnalysed, ParseError, Provenance, Verification
from tests.reporting.fakes import digest, fnd, stage

_KEYS = {"schema_version", "input", "stages", "findings", "not_analysed", "raw_image"}


def _canonical_hash(fragment: dict[str, object]) -> str:
    text = json.dumps(
        fragment, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
    )
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def test_schema_keys_and_version() -> None:
    doc = json.loads(render_json(Report(digest, (stage(),))))
    assert set(doc) == _KEYS
    assert doc["schema_version"] == SCHEMA_VERSION == 1


def test_render_provenance_and_verification() -> None:
    findings = (
        fnd(1, provenance=Provenance.PARSED),
        fnd(2, provenance=Provenance.DISASSEMBLED, verification=Verification.passed(("a",))),
        fnd(3, provenance=Provenance.INFERRED, verification=Verification.rejected("r")),
        fnd(4, provenance=Provenance.LLM_SUGGESTED),
    )
    doc = json.loads(render_json(Report(digest, (stage(findings=findings),))))
    assert [f["provenance"] for f in doc["findings"]] == [
        "parsed",
        "disassembled",
        "inferred",
        "llm_suggested",
    ]
    unverified = {"checks": [], "reason": "", "status": "unverified"}
    assert [f["verification"] for f in doc["findings"]] == [
        unverified,
        {"checks": ["a"], "reason": "", "status": "passed"},
        {"checks": [], "reason": "r", "status": "rejected"},
        unverified,
    ]


def test_render_deterministic() -> None:
    report = Report(digest, (stage(findings=(fnd({"b": 1, "a": 2}),)),))
    assert render_json(report) == render_json(report)
    swapped = Report(digest, (stage(findings=(fnd({"a": 2, "b": 1}),)),))
    assert render_json(report) == render_json(swapped)
    assert stage_sha256(report.stages[0]) == stage_sha256(swapped.stages[0])


def test_render_escapes_to_ascii() -> None:
    value = "\x1b[2J\x7f‮ ж"
    text = render_json(Report(digest, (stage(findings=(fnd(value),)),)))
    assert text.isascii()
    assert re.search(r"[\x00-\x09\x0b-\x1f\x7f]", text) is None
    for escaped in ("\\u001b", "\\u007f", "\\u202e"):
        assert escaped in text
    assert json.loads(text)["findings"][0]["value"] == value


def test_render_single_document() -> None:
    text = render_json(Report(digest, (stage(not_analysed=(NotAnalysed("r"),)),)))
    assert text.endswith("}\n")
    assert "\n\n" not in text
    json.loads(text)


def test_stage_sha256_canonical() -> None:
    def report(second_value: int, version: str = "1") -> Report:
        return Report(
            digest,
            (
                stage("a", findings=(fnd({"k": [1, None]}, "a"),)),
                stage(
                    "b",
                    version,
                    findings=(fnd(second_value, "b"),),
                    not_analysed=(NotAnalysed("r"),),
                ),
            ),
        )

    doc = json.loads(render_json(report(1)))
    for i, entry in enumerate(doc["stages"]):
        fragment = {
            "name": entry["name"],
            "version": entry["version"],
            "findings": [f for f in doc["findings"] if f["producer"] == entry["name"]],
            "not_analysed": [n for n in doc["not_analysed"] if n["stage"] == entry["name"]],
            "raw_image": None,
        }
        assert _canonical_hash(fragment) == entry["sha256"]
        assert stage_sha256(report(1).stages[i]) == entry["sha256"]

    changed = json.loads(render_json(report(2)))
    assert changed["stages"][0]["sha256"] == doc["stages"][0]["sha256"]
    assert changed["stages"][1]["sha256"] != doc["stages"][1]["sha256"]
    assert stage_sha256(stage(version="2")) != stage_sha256(stage())


def test_render_revalidates_mutated_value() -> None:
    f = fnd({"a": []})
    assert isinstance(f.value, dict)
    inner = f.value["a"]
    assert isinstance(inner, list)
    inner.append(float("nan"))
    report = Report(digest, (stage(findings=(f,)),))
    with pytest.raises(ParseError, match="not finite"):
        render_json(report)
    with pytest.raises(ParseError, match="not finite"):
        stage_sha256(report.stages[0])


def test_output_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    big = tuple(fnd(["\x01" * 4096] * 16) for _ in range(4096))
    with pytest.raises(ParseError, match="report exceeds"):
        stage_sha256(stage(findings=big))
    with pytest.raises(ParseError, match="report exceeds"):
        render_json(Report(digest, (stage(findings=big),)))

    small = Report(digest, (stage(findings=(fnd(1),)),))
    text = render_json(small)
    monkeypatch.setattr(services, "MAX_REPORT_CHARS", len(text) - 1)
    assert render_json(small) == text
    monkeypatch.setattr(services, "MAX_REPORT_CHARS", len(text) - 2)
    with pytest.raises(ParseError, match="report exceeds"):
        render_json(small)


def test_render_bool_value() -> None:
    text = render_json(Report(digest, (stage(findings=(fnd(True),)),)))
    assert '"value": true' in text
    assert json.loads(text)["findings"][0]["value"] is True
