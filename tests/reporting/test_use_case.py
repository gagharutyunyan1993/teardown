import pytest

from retool.reporting import RenderJsonReport, Report, render_json
from retool.shared import ParseError
from tests.reporting.fakes import FakeFacts, digest, stage


def test_render_json_report() -> None:
    report = Report(digest, (stage(),))
    facts = FakeFacts(report)
    assert RenderJsonReport(facts).execute() == render_json(report)
    assert facts.calls == 1


def test_render_json_report_propagates() -> None:
    error = ParseError("x")
    with pytest.raises(ParseError) as exc:
        RenderJsonReport(FakeFacts(error)).execute()
    assert exc.value is error
