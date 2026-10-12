from enum import IntEnum, StrEnum

import pytest

from retool.shared import ParseError, check_json_value
from retool.shared.json_value import JSON_INT_MAX, JSON_INT_MIN


class _Color(StrEnum):
    RED = "red"


class _Level(IntEnum):
    ONE = 1


class _Float(float):
    pass


def _nested_lists(depth: int) -> object:
    value: object = []
    for _ in range(depth - 1):
        value = [value]
    return value


def _nested_dicts(depth: int) -> object:
    value: object = {"k": 0}
    for _ in range(depth - 1):
        value = {"k": value}
    return value


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        0,
        JSON_INT_MIN,
        JSON_INT_MAX,
        1.5,
        -0.0,
        "",
        "ж",
        "\x1b[2J",
        {"a": [1, 2.5, None, True, "x"]},
        _nested_lists(32),
        _nested_dicts(32),
        list(range(4095)),
        ["a" * 4096] * 16,
    ],
)
def test_check_json_value_accepts(value: object) -> None:
    assert check_json_value(value) is None


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        (float("nan"), "not finite"),
        (float("inf"), "not finite"),
        (float("-inf"), "not finite"),
        ({1: "x"}, "key not a string"),
        ({_Color.RED: 0}, "key not a string"),
        (_Level.ONE, "unsupported type"),
        (_Float(1.5), "unsupported type"),
        ((1,), "unsupported type"),
        (b"x", "unsupported type"),
        ({"a"}, "unsupported type"),
        (_Color.RED, "unsupported type"),
        (JSON_INT_MAX + 1, "int out of range"),
        (JSON_INT_MIN - 1, "int out of range"),
        ("a" * 4097, "string too long"),
        ({"k" * 4097: 0}, "string too long"),
        ("\ud800", "not valid unicode"),
        ({"\ud800": 0}, "not valid unicode"),
        (_nested_lists(33), "too deep"),
        (_nested_dicts(33), "too deep"),
        (list(range(4096)), "too many nodes"),
        (["a" * 4096] * 16 + ["b"], "text budget exceeded"),
        ({c * 4096: 0 for c in "abcdefghijklmnopq"}, "text budget exceeded"),
    ],
)
def test_check_json_value_rejects(value: object, reason: str) -> None:
    with pytest.raises(ParseError, match=reason) as exc:
        check_json_value(value)
    assert exc.value.offset is None
    assert "a" * 100 not in str(exc.value)


def test_check_json_value_cycles_and_width() -> None:
    a: list[object] = []
    a.append(a)
    d: dict[str, object] = {}
    d["k"] = d
    for cyclic in (a, d):
        with pytest.raises(ParseError, match="too deep"):
            check_json_value(cyclic)
    b: list[object] = []
    b.extend([b] * 1000)
    for wide in (b, {str(i): 0 for i in range(100_000)}, [0] * 10_000_000):
        with pytest.raises(ParseError, match="too many nodes"):
            check_json_value(wide)


def test_check_json_value_bool_is_not_int() -> None:
    # bool is an int subclass; it must pass as a bool, not through the int range check.
    assert check_json_value([True, False, {"b": True}]) is None
