import pytest

import retool.formats
from retool.formats import InputChanged, InspectFile, LoadRawImage, RawLoadSpec
from retool.reporting import InputDigest, RawImageLayout, SegmentLayout, StageOutput
from retool.reporting.infrastructure.formats_facts import FormatsFactSource
from retool.shared import ParseError
from tests.formats.fakes import MemorySource, SparseSource, arm, bank1, ram, sa, seg
from tests.reporting.fakes import GrowingSource


def test_maps_inspect_dto() -> None:
    data = b"\x7fELF" + b"\0" * 60
    info = InspectFile(MemorySource(data)).execute()
    report = FormatsFactSource(MemorySource(data)).collect()
    assert report.input == InputDigest(info.sha256, info.size)
    assert report.stages == (
        StageOutput(info.stage, info.stage_version, info.findings, info.not_analysed),
    )
    assert report.raw_image is None


def test_maps_raw_dto() -> None:
    data = b"\0" * 0x100
    spec = RawLoadSpec(
        arm,
        (seg(0, 0x80, sa(ram, 0)), seg(0x80, 0x80, sa(bank1, 0x4000))),
        sa(bank1, 0x4000),
    )
    report = FormatsFactSource(MemorySource(data), spec).collect()
    assert tuple(s.name for s in report.stages) == (InspectFile.STAGE, LoadRawImage.STAGE)
    assert report.raw_image == RawImageLayout(
        arm,
        sa(bank1, 0x4000),
        (
            SegmentLayout("seg0", sa(ram, 0), 0x80, 0, 0x80),
            SegmentLayout("seg1", sa(bank1, 0x4000), 0x80, 0x80, 0x80),
        ),
    )
    raw_info = LoadRawImage(MemorySource(data)).execute(spec)
    raw_stage = report.stages[1]
    assert raw_stage.version == raw_info.stage_version
    assert raw_stage.findings == raw_info.findings
    assert raw_stage.not_analysed == raw_info.not_analysed


def test_raw_spec_error_before_hashing() -> None:
    past = SparseSource(1 << 31)
    spec = RawLoadSpec(arm, (seg(1 << 31, None, sa(ram, 0)),))
    with pytest.raises(ParseError):
        FormatsFactSource(past, spec).collect()
    assert past.calls == []


def test_input_changed_during_read() -> None:
    spec = RawLoadSpec(arm, (seg(0, None, sa(ram, 0)),))
    with pytest.raises(InputChanged, match="input changed during read"):
        FormatsFactSource(GrowingSource(b"\0" * 16), spec).collect()


def test_formats_exports_input_changed() -> None:
    assert "InputChanged" in retool.formats.__all__
