import pytest

from retool.shared import Finding, NotAnalysed, ParseError, Provenance, Verification

Status = Verification.Status
_17 = tuple(f"c{i}" for i in range(17))


def test_provenance_members() -> None:
    assert {p.value for p in Provenance} == {"parsed", "disassembled", "inferred", "llm_suggested"}


def test_verification_factories() -> None:
    assert Verification.unverified().status is Status.UNVERIFIED
    assert Verification.passed(("a", "b")).status is Status.PASSED
    assert Verification.rejected("r").status is Status.REJECTED


@pytest.mark.parametrize(
    ("status", "checks", "reason", "error"),
    [
        (Status.PASSED, (), "", "needs 1..16 checks"),
        (Status.PASSED, ("a", "a"), "", "duplicate check name"),
        (Status.PASSED, ("",), "", "invalid check name"),
        (Status.PASSED, ("Bad Check",), "", "invalid check name"),
        (Status.PASSED, _17, "", "needs 1..16 checks"),
        (Status.PASSED, ("a",), "r", "passed status carries no reason"),
        (Status.REJECTED, (), "", "needs a printable reason"),
        (Status.REJECTED, (), "a" * 257, "needs a printable reason"),
        (Status.REJECTED, (), "a\nb", "needs a printable reason"),
        (Status.REJECTED, ("a",), "r", "rejected status carries no checks"),
        (Status.UNVERIFIED, ("a",), "", "unverified status carries no checks"),
        (Status.UNVERIFIED, (), "r", "unverified status carries no checks"),
    ],
)
def test_verification_rejects(
    status: Verification.Status, checks: tuple[str, ...], reason: str, error: str
) -> None:
    with pytest.raises(ParseError, match=error):
        Verification(status, checks, reason)


def test_verification_accepts_max_checks() -> None:
    assert len(Verification.passed(_17[:16]).checks) == 16


def _finding(
    provenance: Provenance = Provenance.PARSED,
    verification: Verification | None = None,
    subject: str = "ram:0x8000000",
    producer: str = "formats.raw",
) -> Finding:
    return Finding(subject, 1, provenance, verification or Verification.unverified(), producer)


def test_llm_passed_needs_two_checks() -> None:
    with pytest.raises(ParseError, match="needs at least 2 checks"):
        _finding(Provenance.LLM_SUGGESTED, Verification.passed(("x",)))
    _finding(Provenance.LLM_SUGGESTED, Verification.passed(("x", "y")))
    _finding(Provenance.PARSED, Verification.passed(("x",)))


@pytest.mark.parametrize(
    ("subject", "producer", "error"),
    [
        ("", "formats.raw", "finding subject must be"),
        ("a" * 257, "formats.raw", "finding subject must be"),
        ("a\nb", "formats.raw", "finding subject must be"),
        ("s", "Bad Producer", "invalid producer name"),
        ("s", "a" * 65, "invalid producer name"),
    ],
)
def test_finding_rejects(subject: str, producer: str, error: str) -> None:
    with pytest.raises(ParseError, match=error):
        _finding(subject=subject, producer=producer)


def test_finding_json_value() -> None:
    value = {"a": [1, 2.5, None, True, "x"]}
    finding = Finding("s", value, Provenance.INFERRED, Verification.unverified(), "p")
    assert finding.value == {"a": [1, 2.5, None, True, "x"]}


@pytest.mark.parametrize("reason", ["", "a" * 257, "a\nb"])
def test_not_analysed(reason: str) -> None:
    with pytest.raises(ParseError, match="not-analysed reason must be"):
        NotAnalysed(reason)
    assert NotAnalysed("budget exceeded").reason == "budget exceeded"


def _deep(depth: int) -> list[object]:
    value: list[object] = []
    for _ in range(depth - 1):
        value = [value]
    return value


@pytest.mark.parametrize(
    ("value", "reason"),
    [(float("nan"), "not finite"), (_deep(33), "too deep"), ({1: 2}, "key not a string")],
)
def test_finding_validates_value(value: object, reason: str) -> None:
    with pytest.raises(ParseError, match=reason):
        Finding("s", value, Provenance.PARSED, Verification.unverified(), "p")
