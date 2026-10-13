"""Slice 6b: decoded Inno findings, text display and file-list caps, t70, t74, t79."""

from __future__ import annotations

import hashlib

import pytest

from retool.formats.domain.inno import MAX_INNO_FILE_FINDINGS
from retool.formats.domain.inno_facts import _text, _timestamp, inno_facts
from retool.formats.domain.inno_loader import inno_info
from retool.formats.domain.inno_setup import InnoFileLocation
from retool.formats.domain.pe import parse_pe
from retool.formats.domain.pe_parser import attach_tables
from retool.shared import JsonValue, NotAnalysed
from tests.formats.fakes import MemorySource
from tests.formats.inno_build import G7, many_files_inno


def _info(data: bytes) -> tuple[list[tuple[str, JsonValue]], tuple[NotAnalysed, ...]]:
    source = MemorySource(data)
    pe, _ = attach_tables(source, parse_pe(source))
    info, notes = inno_info(source, pe)
    assert info is not None
    return [(f.subject, f.value) for f in inno_facts(info, "formats.inspect")], notes


# t70: text display, sha256, timestamps


@pytest.mark.parametrize(
    ("text", "shown"),
    [
        ('a\u0001"\\b', "a\\u0001\\u0022\\u005cb"),
        ("\U0001f600", "\U0001f600"),
        ("\U000e0001", "\\U000e0001"),
    ],
)
def test_t70_text(text: str, shown: str) -> None:
    assert _text(text.encode("utf-16-le")) == (shown, False)


def test_t70_lone_surrogate() -> None:
    assert _text(b"\x00\xd8") == ("\\ud800", False)


def test_t70_truncated() -> None:
    assert _text(("x" * 129).encode("utf-16-le")) == ("x" * 128, True)
    assert _text(("x" * 128).encode("utf-16-le")) == ("x" * 128, False)


@pytest.mark.parametrize(
    ("filetime", "flags", "stamp"),
    [
        (132000000000000000, 0x02, "2019-04-17T18:40:00Z"),
        (132000000000000000, 0x00, "2019-04-17T18:40:00"),
        (2650467743999999999, 0x00, "9999-12-31T23:59:59.999999"),
        (2650467744000000000, 0x02, None),
        (2**64 - 1, 0x02, None),
        (0, 0x02, None),
    ],
)
def test_t70_timestamp(filetime: int, flags: int, stamp: str | None) -> None:
    assert _timestamp(InnoFileLocation(0, 0, bytes(32), filetime, flags)) == stamp


# t74: G7 findings exactly as ## CLI/JSON

COUNT_KEYS = (
    "language",
    "custom_message",
    "permission",
    "type",
    "component",
    "task",
    "dir",
    "file",
    "file_location",
    "icon",
    "ini",
    "registry",
    "install_delete",
    "uninstall_delete",
    "run",
    "uninstall_run",
)
COUNTS: dict[str, JsonValue] = dict.fromkeys(COUNT_KEYS, 0)
G7_HEADER: JsonValue = {
    "app_name": "Demo App",
    "app_version": "1.2.3",
    "app_publisher": "Retool Tests",
    "compress_method": "lzma",
    "compress_method_id": 3,
    "options_hex": "000000000000",
    "counts": COUNTS | {"language": 1, "file": 2, "file_location": 2},
    "files_total": 2,
    "files_reported": 2,
    "text_truncated": False,
}
G7_FILES: list[JsonValue] = [
    {
        "index": 0,
        "dest": "{app}\\u005capp.exe",
        "source": "C:\\u005cbuild\\u005capp.exe",
        "file_type": "user_file",
        "file_type_id": 0,
        "options": 0,
        "location": 0,
        "size": 1024,
        "sha256": hashlib.sha256(b"app").hexdigest(),
        "filetime": 132000000000000000,
        "timestamp": "2019-04-17T18:40:00Z",
        "flags": ["timestamp_utc", "chunk_compressed"],
        "flags_raw": 18,
        "text_truncated": False,
    },
    {
        "index": 1,
        "dest": "{app}\\u005creadme.txt",
        "source": "C:\\u005cbuild\\u005creadme.txt",
        "file_type": "user_file",
        "file_type_id": 0,
        "options": 0,
        "location": 1,
        "size": 5,
        "sha256": hashlib.sha256(b"hello").hexdigest(),
        "filetime": 0,
        "timestamp": None,
        "flags": ["chunk_compressed"],
        "flags_raw": 16,
        "text_truncated": False,
    },
]


def test_t74_g7_findings() -> None:
    findings, _ = _info(G7)
    assert [s for s, _ in findings] == [
        "inno.loader",
        "inno.version",
        "inno.block",
        "inno.block",
        "inno.data",
        "inno.block1.decode",
        "inno.block2.decode",
        "inno.block1[lzma1]+0x0:setup_header",
        "inno.block1[lzma1]+0x1c2:file_entry",
        "inno.block1[lzma1]+0x24f:file_entry",
    ]
    values = [v for _, v in findings[5:]]
    assert values[:2] == [
        {"codec": "lzma1", "status": "ended", "decoded_size": 752, "consumed": 149, "trailing": 0},
        {"codec": "lzma1", "status": "ended", "decoded_size": 170, "consumed": 107, "trailing": 0},
    ]
    assert values[2] == G7_HEADER
    assert values[3:] == G7_FILES


def test_t74_no_location_keys_null() -> None:
    from retool.formats.domain.inno_facts import _file
    from retool.formats.domain.inno_files import InnoFile
    from retool.formats.domain.inno_setup import InnoFileEntry

    value = _file(3, InnoFile(InnoFileEntry(9, b"", b"", -1, 0, 1), None))
    assert isinstance(value, dict)
    keys = ("size", "sha256", "filetime", "timestamp", "flags", "flags_raw")
    assert [value[k] for k in keys] == [None] * 6
    assert value["file_type"] == "uninstall_exe"


# t79: file finding cap, N6, N7


def test_t79_many_files() -> None:
    findings, notes = _info(many_files_inno())
    files = [v for s, v in findings if s.endswith(":file_entry")]
    assert len(files) == MAX_INNO_FILE_FINDINGS
    (header,) = [v for s, v in findings if s.endswith(":setup_header")]
    assert isinstance(header, dict)
    assert (header["files_total"], header["files_reported"]) == (1100, 1024)
    first = files[0]
    assert isinstance(first, dict)
    assert first["text_truncated"] is True
    assert first["dest"] == "\U0001f600" * 128
    assert notes[:2] == (
        NotAnalysed("inno file list truncated: 1024 of 1100 files reported"),
        NotAnalysed("inno file data encrypted: 1 of 1 file locations"),
    )
