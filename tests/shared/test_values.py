import pytest

from retool.shared import Address, ByteRange, ParseError


def test_address_rejects_negative() -> None:
    with pytest.raises(ParseError):
        Address(-1)


def test_byte_range_within_limit() -> None:
    assert ByteRange(4, 8).check_within(12).end == 12


@pytest.mark.parametrize(("start", "size", "limit"), [(4, 9, 12), (0, 1, 0), (12, 1, 12)])
def test_byte_range_overflow(start: int, size: int, limit: int) -> None:
    with pytest.raises(ParseError) as exc:
        ByteRange(start, size).check_within(limit)
    assert exc.value.offset == start


def test_byte_range_rejects_negative() -> None:
    with pytest.raises(ParseError):
        ByteRange(-1, 1)
