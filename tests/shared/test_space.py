import pytest

from retool.shared import Address, AddressSpace, ArchitectureId, ParseError, SpaceAddress

ram = AddressSpace("ram", 64)
bank1 = AddressSpace("bank1", 16)


def sa(space: AddressSpace, n: int) -> SpaceAddress:
    return SpaceAddress(space, Address(n))


@pytest.mark.parametrize("name", ["armv7", "pi32v2", "x86_64", "a" * 32])
def test_arch_id_accepts(name: str) -> None:
    assert str(ArchitectureId(name)) == name


@pytest.mark.parametrize(
    "name", ["", "a" * 33, "ARM", "arm v7", "arm/../x", "arm\n", "arm%s", "armж"]
)
def test_arch_id_rejects(name: str) -> None:
    with pytest.raises(ParseError, match="invalid architecture id") as exc:
        ArchitectureId(name)
    assert exc.value.offset is None
    if name:
        assert name not in str(exc.value)


def test_space_width() -> None:
    assert AddressSpace("x", 1).max_offset == 1
    assert AddressSpace("x", 64).max_offset == 2**64 - 1
    for width in (0, 65, -1):
        with pytest.raises(ParseError):
            AddressSpace("x", width)
    with pytest.raises(TypeError):
        AddressSpace("x")  # type: ignore[call-arg]  # width has no default by design


@pytest.mark.parametrize("name", ["", "ram:1", "r@m", "a" * 33, "r\x1b[2J"])
def test_space_name_rejects(name: str) -> None:
    with pytest.raises(ParseError) as exc:
        AddressSpace(name, 64)
    if name:
        assert name not in str(exc.value)


def test_space_address_bounds() -> None:
    assert sa(bank1, 0xFFFF).offset.value == 0xFFFF
    with pytest.raises(ParseError, match="address exceeds"):
        sa(bank1, 0x10000)
    assert sa(ram, 2**64 - 1).offset.value == 2**64 - 1
    with pytest.raises(ParseError, match="address exceeds") as exc:
        sa(ram, 2**64)
    assert str(2**64) not in str(exc.value)


def test_space_address_str() -> None:
    assert str(sa(ram, 0x8000000)) == "ram:0x8000000"
