import pytest

from retool.reporting import InputDigest, RawImageLayout, Report, SegmentLayout
from retool.shared import NotAnalysed, ParseError
from tests.formats.fakes import arm, ram, sa
from tests.reporting.fakes import digest, fnd, stage


def _segment(
    name: str = "seg0", mem_size: int = 1, file_start: int = 0, file_size: int = 0
) -> SegmentLayout:
    return SegmentLayout(name, sa(ram, 0), mem_size, file_start, file_size)


def _layout(count: int = 1) -> RawImageLayout:
    return RawImageLayout(arm, None, tuple(_segment(f"seg{i}") for i in range(count)))


def test_input_digest() -> None:
    assert InputDigest("a" * 64, 0).size == 0
    for sha, size in [
        ("", 0),
        ("A" * 64, 0),
        ("g" * 64, 0),
        ("a" * 63, 0),
        ("a" * 64, -1),
        ("a" * 64, 10**5000),
        ("a" * 64, True),
    ]:
        with pytest.raises(ParseError):
            InputDigest(sha, size)


@pytest.mark.parametrize(
    ("name", "version"),
    [("", "1"), ("Bad Name", "1"), ("a" * 65, "1"), ("s", ""), ("s", "1 0"), ("s", "a" * 33)],
)
def test_stage_output_rejects(name: str, version: str) -> None:
    with pytest.raises(ParseError):
        stage(name, version)


def test_stage_output_rejects_foreign_producer() -> None:
    with pytest.raises(ParseError, match="producer does not match stage"):
        stage("s", findings=(fnd(1, "other"),))


def test_report_limits() -> None:
    def names(n: int) -> tuple[str, ...]:
        return tuple(f"s{i}" for i in range(n))

    rejected = [
        (),
        tuple(stage(n) for n in names(17)),
        (stage("a"), stage("a")),
        (stage("a", raw_image=_layout()), stage("b", raw_image=_layout())),
        (
            stage("a", findings=tuple(fnd(i, "a") for i in range(2048))),
            stage("b", findings=tuple(fnd(i, "b") for i in range(2049))),
        ),
        (stage(not_analysed=(NotAnalysed("r"),) * 257),),
    ]
    reasons = [
        "stage count",
        "stage count",
        "duplicate stage",
        "raw image",
        "finding count",
        "not-analysed count",
    ]
    for stages, reason in zip(rejected, reasons, strict=True):
        with pytest.raises(ParseError, match=reason):
            Report(digest, stages)

    assert len(Report(digest, tuple(stage(n) for n in names(16))).stages) == 16
    Report(digest, (stage(findings=tuple(fnd(i) for i in range(4096))),))
    Report(digest, (stage(not_analysed=(NotAnalysed("r"),) * 256),))
    layout = _layout()
    assert Report(digest, (stage("a"), stage("b", raw_image=layout))).raw_image is layout
    assert Report(digest, (stage("a"),)).raw_image is None


def test_raw_image_layout_rejects() -> None:
    for count in (0, 65):
        with pytest.raises(ParseError, match="segments"):
            _layout(count)
    assert len(_layout(64).segments) == 64
    with pytest.raises(ParseError) as exc:
        _segment("Bad\x1b")
    assert "Bad" not in str(exc.value)
    for kwargs in (
        {"mem_size": 0},
        {"file_start": -1},
        {"file_size": -1},
        {"mem_size": 10**5000},
        {"file_start": 10**5000},
        {"file_size": 10**5000},
        {"mem_size": True},
        {"file_start": True},
        {"file_size": True},
    ):
        with pytest.raises(ParseError):
            _segment(**kwargs)
