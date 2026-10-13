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


_MAGICS = [
    b"\x7fELF",
    b"MZ",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
]
_HEADS = (
    [b""]
    + [bytes([a]) for a in range(256)]
    + [bytes([a, b]) for a in range(256) for b in range(256)]
    + _MAGICS
    + [m + b"\0" * 60 for m in _MAGICS]
)


def test_detect_never_returns_raw() -> None:
    for head in _HEADS:
        assert detect(head) is not Format.RAW


def test_magic_window_public() -> None:
    from retool.formats.domain.services import MAGIC_WINDOW

    assert MAGIC_WINDOW == 4
    assert detect(b"\x7fELF"[:MAGIC_WINDOW]) is Format.ELF
