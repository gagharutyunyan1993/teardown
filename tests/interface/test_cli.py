from pathlib import Path

import pytest

from retool.interface.cli.main import main


def test_info(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"\x7fELF" + b"\x00" * 60)

    assert main(["info", str(sample)]) == 0

    out = capsys.readouterr().out
    assert "format: elf" in out
    assert "size:   64" in out


_HINT = "unknown format; to load as a raw image use --raw --arch --base"
_RAW = ["--raw", "--arch", "armv7"]


def _file(tmp_path: Path, data: bytes) -> str:
    sample = tmp_path / "a.bin"
    sample.write_bytes(data)
    return str(sample)


def test_info_unknown_hint(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["info", _file(tmp_path, b"\0" * 16)]) == 0
    captured = capsys.readouterr()
    assert "format: unknown" in captured.out
    assert _HINT in captured.err


def test_info_raw_single(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _file(tmp_path, b"\0" * 0x100)
    assert main(["info", path, *_RAW, "--base", "0x8000000"]) == 0
    out = capsys.readouterr().out
    assert "format: raw" in out
    assert "arch:   armv7" in out
    assert "entry:  none" in out
    assert "segment seg0: ram:0x8000000 mem=0x100 file=0x0+0x100" in out


def test_info_raw_multi_map(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _file(tmp_path, b"\0" * 0x100)
    argv = ["--map", "0:0x0:0x80", "--map", "0x80:0x4000:0x80@bank1", "--entry", "0x4000@bank1"]
    assert main(["info", path, *_RAW, *argv]) == 0
    out = capsys.readouterr().out
    assert "segment seg0: ram:0x0 mem=0x80 file=0x0+0x80" in out
    assert "segment seg1: bank1:0x4000 mem=0x80 file=0x80+0x80" in out
    assert "entry:  bank1:0x4000" in out


def test_info_raw_magic_warning(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _file(tmp_path, b"\x7fELF" + b"\0" * 60)
    assert main(["info", path, *_RAW, "--base", "0"]) == 0
    captured = capsys.readouterr()
    assert "format: raw" in captured.out
    assert "warning: input starts with elf magic" in captured.err


_HUGE = "0x" + "f" * 5000
_MAX64 = "0xffffffffffffffff"


@pytest.mark.parametrize(
    ("flags", "hostile"),
    [
        (["--raw", "--base", "0"], None),
        ([*_RAW], None),
        ([*_RAW, "--base", "0", "--map", "0:0:1"], None),
        ([*_RAW, "--map", "0:0:1", "--offset", "0"], None),
        (["--arch", "armv7"], None),
        ([*_RAW, "--map", "1:2"], "1:2"),
        ([*_RAW, "--map", "a:b:c"], "a:b:c"),
        ([*_RAW, "--base", "zz"], "zz"),
        ([*_RAW, "--map", "0:0:1@"], None),
        ([*_RAW, "--base", "1" * 4301], "1" * 4301),
        ([*_RAW, "--map", "-1:0:1"], None),
        ([*_RAW, "--base", _HUGE], _HUGE),
        ([*_RAW, "--base", "0", "--offset", _HUGE], _HUGE),
        ([*_RAW, "--base", "0", "--length", _HUGE], _HUGE),
        ([*_RAW, "--map", f"{_HUGE}:0:1"], _HUGE),
        ([*_RAW, "--map", f"0:{_HUGE}:1"], _HUGE),
        ([*_RAW, "--map", f"0:0:{_HUGE}"], _HUGE),
        ([*_RAW, "--base", "0", "--entry", _HUGE], _HUGE),
        ([*_RAW, f"--base=-{_HUGE}"], _HUGE),
        ([*_RAW, "--base", "0", f"--offset=-{_HUGE}"], _HUGE),
        ([*_RAW, "--base", "0", f"--entry=-{_HUGE}"], _HUGE),
        ([*_RAW, "--base", "0x10000000000000000"], "0x10000000000000000"),
    ],
)
def test_info_raw_usage_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], flags: list[str], hostile: str | None
) -> None:
    path = _file(tmp_path, b"\0" * 16)
    with pytest.raises(SystemExit) as exc:
        main(["info", path, *flags])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert all(len(line) <= 200 for line in err.splitlines())
    if hostile is not None:
        assert hostile not in err


@pytest.mark.parametrize(
    "flags",
    [
        ["--raw", "--arch", "ARM", "--base", "0"],
        [*_RAW, "--base", "0", "--offset", "0x100"],
        [*_RAW, "--base", "0", "--offset", "-1"],
        [*_RAW, "--base", "0", "--length", "0"],
        [*_RAW, "--map=-1:0:1"],
        [*_RAW, "--base", "0x1000", "--entry", "0x10"],
        [*_RAW, "--map", "0:0xffffffffffffffff:2"],
        [*_RAW, "--base", _MAX64, "--length", "2"],
        [*_RAW, "--base", "0", "--offset", _MAX64],
        [*_RAW, "--base", "0", f"--offset=-{_MAX64}"],
        [*_RAW, "--base", "0", "--length", _MAX64],
        [*_RAW, "--base", "0", f"--length=-{_MAX64}"],
        [*_RAW, "--map", f"{_MAX64}:0:1"],
        [*_RAW, "--map", f"0:0:{_MAX64}"],
        [*_RAW, f"--map=-{_MAX64}:0:1"],
        [*_RAW, "--base", "0", "--entry", _MAX64],
        [*_RAW, f"--base=-{_MAX64}"],
        [*_RAW, "--base", "0", f"--entry=-{_MAX64}"],
    ],
)
def test_info_raw_domain_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], flags: list[str]
) -> None:
    path = _file(tmp_path, b"\0" * 16)
    assert main(["info", path, *flags]) == 1
    err = capsys.readouterr().err
    assert err.startswith("error:")
    assert all(len(line) <= 200 for line in err.splitlines())


def test_info_raw_segment_exceeds_space(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _file(tmp_path, b"\0" * 16)
    assert main(["info", path, *_RAW, "--map", "0:0xffffffffffffffff:2"]) == 1
    assert "segment exceeds address space" in capsys.readouterr().err


@pytest.mark.parametrize("flags", [[], [*_RAW, "--base", "0"]])
def test_info_missing_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], flags: list[str]
) -> None:
    assert main(["info", str(tmp_path / "missing"), *flags]) == 1
    assert capsys.readouterr().err.startswith("error:")
