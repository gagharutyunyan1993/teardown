"""Recursive JSON value alias (ADR 0002) and its bounded runtime validator."""

from __future__ import annotations

import math

from retool.shared.errors import ParseError

type JsonValue = str | int | float | bool | list[JsonValue] | dict[str, JsonValue] | None

MAX_JSON_DEPTH = 32  # a top-level container is depth 1; depth > 32 rejected (assumption)
MAX_JSON_NODES = 4096  # values incl. containers, excl. keys (assumption)
MAX_JSON_STR = 4096  # chars per string or key (assumption)
MAX_JSON_TEXT = 1 << 16  # total chars over all strings + keys of one value (assumption)
JSON_INT_MIN, JSON_INT_MAX = -(1 << 63), (1 << 64) - 1  # (assumption) 64-bit addresses fit


def _check_text(text: str, budget: int) -> int:
    """Validate one string or key; return the text budget used so far including it."""
    if len(text) > MAX_JSON_STR:
        raise ParseError(f"json string too long (max {MAX_JSON_STR} chars)")
    budget += len(text)
    if budget > MAX_JSON_TEXT:
        raise ParseError(f"json text budget exceeded (max {MAX_JSON_TEXT} chars)")
    if not text.isascii():
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            raise ParseError("json string not valid unicode") from None
    return budget


def check_json_value(value: object) -> None:
    """Raise ParseError unless ``value`` is a bounded, finite, exactly-typed JSON value.

    Walks iteratively with an explicit stack; the node cap is checked before a container's
    children are pushed, so wide or cyclic values fail in O(MAX_JSON_NODES).
    """
    nodes = 1
    text = 0
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if item is None or type(item) is bool:
            continue
        if type(item) is int:
            if not JSON_INT_MIN <= item <= JSON_INT_MAX:
                raise ParseError("json int out of range")
        elif type(item) is float:
            if not math.isfinite(item):
                raise ParseError("json float not finite")
        elif type(item) is str:
            text = _check_text(item, text)
        elif type(item) is list or type(item) is dict:
            if depth > MAX_JSON_DEPTH:
                raise ParseError(f"json value too deep (max {MAX_JSON_DEPTH})")
            if nodes + len(item) > MAX_JSON_NODES:
                raise ParseError(f"json value has too many nodes (max {MAX_JSON_NODES})")
            nodes += len(item)
            if type(item) is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise ParseError("json key not a string")
                    text = _check_text(key, text)
                    stack.append((child, depth + 1))
            else:
                stack.extend((child, depth + 1) for child in item)
        else:
            raise ParseError("json value has unsupported type")
