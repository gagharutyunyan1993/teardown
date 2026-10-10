import pytest

from retool.formats import Format, detect


@pytest.mark.parametrize(
    ("head", "expected"),
    [
        (b"\x7fELF\x02\x01\x01", Format.ELF),
        (b"MZ\x90\x00", Format.PE),
        (b"\xcf\xfa\xed\xfe", Format.MACHO),
        (b"\xca\xfe\xba\xbe", Format.MACHO),
        (b"hello", Format.UNKNOWN),
        (b"", Format.UNKNOWN),
        (b"\x7fEL", Format.UNKNOWN),
    ],
)
def test_detect(head: bytes, expected: Format) -> None:
    assert detect(head) is expected
