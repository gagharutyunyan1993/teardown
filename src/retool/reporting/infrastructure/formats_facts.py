"""Anti-corruption adapter: formats DTOs -> reporting read model. Maps only; authors no facts."""

from __future__ import annotations

from retool.formats import ByteSource, InspectFile, LoadRawImage, RawLoadSpec
from retool.reporting.domain.model import (
    InputDigest,
    RawImageLayout,
    Report,
    SegmentLayout,
    StageOutput,
)
from retool.shared import ParseError


class FormatsFactSource:
    """FactSource over the formats use cases for one byte source."""

    def __init__(self, source: ByteSource, raw: RawLoadSpec | None = None) -> None:
        self._source = source
        self._raw = raw

    def collect(self) -> Report:
        # The raw load runs first so spec errors fail before the whole input is hashed.
        raw_info = None if self._raw is None else LoadRawImage(self._source).execute(self._raw)
        info = InspectFile(self._source).execute()
        stages = [StageOutput(info.stage, info.stage_version, info.findings, info.not_analysed)]
        if raw_info is not None:
            if raw_info.source_size != info.size:
                raise ParseError("input changed during read")
            layout = RawImageLayout(
                raw_info.arch,
                raw_info.entry,
                tuple(
                    SegmentLayout(s.name, s.start, s.mem_size, s.file_start, s.file_size)
                    for s in raw_info.segments
                ),
            )
            stages.append(
                StageOutput(
                    raw_info.stage,
                    raw_info.stage_version,
                    raw_info.findings,
                    raw_info.not_analysed,
                    layout,
                )
            )
        return Report(InputDigest(info.sha256, info.size), tuple(stages))
