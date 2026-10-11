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
