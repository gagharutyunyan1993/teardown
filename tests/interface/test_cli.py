import json
from pathlib import Path

import pytest

from retool.formats import InspectFile
from retool.interface.cli import main as cli_main
from retool.interface.cli.main import main
from tests.formats.elf_build import build_elf
from tests.formats.fakes import MemorySource, ShrinkingSource
from tests.formats.inno_build import PI32
from tests.formats.pe_build import P64, PT64
from tests.formats.pe_build import p as pe_patch


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


FIXTURES = Path(__file__).parent.parent / "fixtures" / "reporting"
_ELF = b"\x7fELF" + b"\0" * 60


def test_info_json_golden_elf(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["info", _file(tmp_path, _ELF), "--json"]) == 0
    out, err = capsys.readouterr()
    assert out.encode("ascii") == (FIXTURES / "elf_magic.json").read_bytes()
    assert err == ""


def test_info_json_golden_raw(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _file(tmp_path, b"\0" * 0x100)
    assert main(["info", path, "--json", *_RAW, "--base", "0x8000000"]) == 0
    out, err = capsys.readouterr()
    assert out.encode("ascii") == (FIXTURES / "raw_base.json").read_bytes()
    assert err == ""


def test_info_json_raw_multi_map_entry(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _file(tmp_path, b"\0" * 0x100)
    maps = ["--map", "0:0x0:0x80", "--map", "0x80:0x4000:0x80@bank1", "--entry", "0x4000@bank1"]
    assert main(["info", path, "--json", *_RAW, *maps]) == 0
    out = capsys.readouterr().out
    assert '"entry": "bank1:0x4000"' in out
    assert '"start": "bank1:0x4000"' in out
    assert json.loads(out)["raw_image"]["segments"] == [
        {"file_size": 128, "file_start": 0, "mem_size": 128, "name": "seg0", "start": "ram:0x0"},
        {
            "file_size": 128,
            "file_start": 128,
            "mem_size": 128,
            "name": "seg1",
            "start": "bank1:0x4000",
        },
    ]


def test_info_json_deterministic_no_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    outs = []
    for name in ("secret-a.bin", "secret-b.bin"):
        sample = tmp_path / name
        sample.write_bytes(_ELF)
        assert main(["info", str(sample), "--json"]) == 0
        outs.append(capsys.readouterr().out)
    assert outs[0] == outs[1]
    assert "secret" not in outs[0]
    assert str(tmp_path) not in outs[0]


@pytest.mark.parametrize(
    ("data", "flags"),
    [(_ELF, []), (b"\0" * 16, []), (_ELF, [*_RAW, "--base", "0"])],
)
def test_info_json_stdout_is_one_document(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], data: bytes, flags: list[str]
) -> None:
    assert main(["info", _file(tmp_path, data), "--json", *flags]) == 0
    out, err = capsys.readouterr()
    assert out == json.dumps(json.loads(out), indent=2, sort_keys=True) + "\n"
    assert err == ""


@pytest.mark.parametrize(
    "flags",
    [
        ["--arch", "armv7"],
        ["--raw", "--base", "0"],
        ["--raw", "--arch", "armv7"],
        ["--base", "0"],
    ],
)
def test_info_json_usage_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], flags: list[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["info", _file(tmp_path, _ELF), "--json", *flags])
    assert exc.value.code == 2
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("missing", [False, True])
def test_info_json_errors_exit_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], missing: bool
) -> None:
    if missing:
        argv = ["info", str(tmp_path / "missing"), "--json"]
    else:
        path = _file(tmp_path, b"\0" * 16)
        argv = ["info", path, "--json", *_RAW, "--base", "0", "--offset", "0x100"]
    assert main(argv) == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("error:")


_F64 = build_elf()
_F64_TEXT = [
    "format: elf",
    "arch:   x86_64",
    "entry:  ram:0x4000b0",
    "segment phdr0: ram:0x400000 mem=0xc0 file=0x0+0xc0",
    "segment phdr1: ram:0x4010c0 mem=0x100 file=0xc0+0x8",
    'section 0 "" null addr=0x0 off=0x0 size=0x0',
    'section 1 ".text" progbits addr=0x4000b0 off=0xb0 size=0x10',
    'section 2 ".bss" nobits addr=0x4010c8 off=0xc8 size=0xf8',
    'section 3 ".shstrtab" strtab addr=0x0 off=0xc8 size=0x16',
    "note:   elf symbols, dynamic section, relocations and notes not parsed in this version",
]


def test_info_elf_text(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["info", _file(tmp_path, _F64)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[2].startswith("sha256: ")
    assert lines[3:] == _F64_TEXT


def test_info_elf_rejected_structure_note(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["info", _file(tmp_path, _ELF)]) == 0
    out = capsys.readouterr().out
    assert "note:   elf structure rejected: invalid EI_CLASS at offset 0x4" in out


def _reads_before_parse() -> int:
    """Reads InspectFile makes before the ELF parser's first (ident) read, from a call trace."""
    trace = MemorySource(_F64)
    InspectFile(trace).execute()
    return trace.calls.index((0, 16))


@pytest.mark.parametrize("flags", [[], ["--json"]])
def test_info_elf_input_changed_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], flags: list[str]
) -> None:
    honest = _reads_before_parse()
    monkeypatch.setattr(
        cli_main, "FileByteSource", lambda path: ShrinkingSource(_F64, 0x120, honest_reads=honest)
    )
    assert main(["info", "x", *flags]) == 1
    out, err = capsys.readouterr()
    assert out == ""
    # The hash pass and the magic read are served in full; the parser's read of shdr1 is short.
    assert err.startswith("error: input changed during read at offset 0x120")


def test_info_json_golden_elf64(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["info", _file(tmp_path, _F64), "--json"]) == 0
    out, err = capsys.readouterr()
    assert out.encode("ascii") == (FIXTURES / "elf64_min.json").read_bytes()
    assert err == ""


_P64_TEXT = [
    "format: pe",
    "arch:   x86_64",
    "entry:  ram:0x140001000",
    "segment headers: ram:0x140000000 mem=0x200 file=0x0+0x200",
    "segment sec0: ram:0x140001000 mem=0x10 file=0x200+0x10",
    "segment sec1: ram:0x140002000 mem=0x1000 file=0x400+0x200",
    'section 0 ".text" code addr=0x140001000 off=0x200 size=0x10',
    'section 1 ".data" data addr=0x140002000 off=0x400 size=0x1000',
    "note:   pe exports, relocations, resource contents, delay-load and bound imports, "
    "certificate contents, debug data, CLR metadata and COFF symbols not parsed in this version",
]


def test_info_pe_text(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["info", _file(tmp_path, P64)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[2].startswith("sha256: ")
    assert lines[3:] == _P64_TEXT


def test_info_json_golden_pe64(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # The "MZ" pe.import is deliberate: P64's .data starts with 8 x 0x11 and Name RVA 0 maps
    # into the headers, so this golden pins hostile-descriptor handling (slice-5 spec, ## CLI).
    assert main(["info", _file(tmp_path, P64), "--json"]) == 0
    out, err = capsys.readouterr()
    assert out.encode("ascii") == (FIXTURES / "pe64_min.json").read_bytes()
    assert err == ""


def test_info_json_golden_pe64_tables(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["info", _file(tmp_path, PT64), "--json"]) == 0
    out, err = capsys.readouterr()
    assert out.encode("ascii") == (FIXTURES / "pe64_tables.json").read_bytes()
    assert err == ""


def test_info_pe_tables_text(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["info", _file(tmp_path, PT64)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[3:] == _P64_TEXT


def test_info_pe_rejected_structure_note(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["info", _file(tmp_path, pe_patch((0x58, 0x107)))]) == 0
    out = capsys.readouterr().out
    assert "note:   pe structure rejected: ROM optional header not supported at offset 0x58" in out


def test_info_pe_section_address_unclamped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["info", _file(tmp_path, pe_patch((0x70, 2**64 - 0x1000)))]) == 0
    out = capsys.readouterr().out
    assert 'section 0 ".text" code addr=0x10000000000000000' in out


def test_info_json_golden_pe32_inno_t34(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["info", _file(tmp_path, PI32), "--json"]) == 0
    out, err = capsys.readouterr()
    assert out.encode("ascii") == (FIXTURES / "pe32_inno.json").read_bytes()
    assert err == ""


def test_info_pe32_inno_text_notes_t34(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["info", _file(tmp_path, PI32)]) == 0
    notes = [line for line in capsys.readouterr().out.splitlines() if line.startswith("note:")]
    assert notes == [
        "note:   inno setup headers, entries and data chunks not decompressed or parsed "
        "in this version",
        _P64_TEXT[-1],
    ]
