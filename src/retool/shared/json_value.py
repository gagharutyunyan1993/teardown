"""Recursive JSON value alias (ADR 0002). Static typing only; no runtime validation."""

from __future__ import annotations

type JsonValue = str | int | float | bool | list[JsonValue] | dict[str, JsonValue] | None
