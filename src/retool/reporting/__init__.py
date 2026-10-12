"""Bounded context: rendering analysis results (text, JSON).

Other contexts and the interface layer use only what is exported here.
"""

from retool.reporting.application.use_cases import RenderJsonReport
from retool.reporting.domain.model import (
    SCHEMA_VERSION,
    InputDigest,
    RawImageLayout,
    Report,
    SegmentLayout,
    StageOutput,
)
from retool.reporting.domain.ports import FactSource
from retool.reporting.domain.services import render_json, stage_sha256

__all__ = [
    "SCHEMA_VERSION",
    "FactSource",
    "InputDigest",
    "RawImageLayout",
    "RenderJsonReport",
    "Report",
    "SegmentLayout",
    "StageOutput",
    "render_json",
    "stage_sha256",
]
