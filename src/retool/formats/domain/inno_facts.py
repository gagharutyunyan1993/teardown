"""Domain service: the ``inno.*`` findings formats reports for parsed Inno loader structures."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Final

from retool.formats.domain.facts import parsed_finding
from retool.formats.domain.inno import (
    MAX_INNO_FILE_FINDINGS,
    InnoBlockHeader,
    InnoDecodeStatus,
    InnoInfo,
    InnoOffsets,
    InnoVersion,
)
from retool.formats.domain.inno_files import InnoFile
from retool.formats.domain.inno_setup import (
    COUNT_NAMES,
    LOCATION_FLAG_NAMES,
    InnoFileLocation,
    InnoHeader,
)
from retool.formats.domain.parsing import display_name
from retool.shared import Finding, JsonValue

MAX_INNO_TEXT: Final = 128  # chars per displayed string (S11)
_MAX_FILETIME_US: Final = 265046774399999999  # 1601-01-01 .. 9999-12-31T23:59:59.999999
_FILETIME_EPOCH: Final = datetime(1601, 1, 1)
_SUBJECT: Final = "inno.block1[lzma1]+0x"  # ADR 0003 decoded-space subject form


def _char(ch: str) -> str:
    code = ord(ch)
    if ch.isprintable() and ch not in '\\"' and not 0xD800 <= code <= 0xDFFF:
        return ch
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"


def _text(raw: bytes) -> tuple[str, bool]:
    """UTF-16LE text cut to MAX_INNO_TEXT chars, unprintable chars escaped; and truncated?"""
    text = raw.decode("utf-16-le", "surrogatepass")
    return "".join(_char(ch) for ch in text[:MAX_INNO_TEXT]), len(text) > MAX_INNO_TEXT


def _timestamp(location: InnoFileLocation) -> str | None:
    us = location.filetime // 10
    if location.filetime == 0 or us > _MAX_FILETIME_US:
        return None
    stamp = (_FILETIME_EPOCH + timedelta(microseconds=us)).isoformat()
    return stamp + "Z" if location.timestamp_utc else stamp


def _loader(o: InnoOffsets) -> JsonValue:
    v = o.loader_version
    value: dict[str, JsonValue] = {
        "route": str(o.route),
        "table_offset": o.table_offset.value,
        "version": f"{v[0]}.{v[1]}.{v[2]}" if v is not None else None,
        "revision": o.revision,
        "exe_offset": o.exe_offset.value,
    }
    if o.exe_compressed_size is not None:
        value["exe_compressed_size"] = o.exe_compressed_size
    value |= {
        "exe_uncompressed_size": o.exe_uncompressed_size,
        "exe_checksum": o.exe_checksum,
    }
    if o.message_offset is not None:
        value["message_offset"] = o.message_offset.value
    value |= {
        "header_offset": o.header_offset.value,
        "data_offset": o.data_offset.value,
        "crc_ok": o.crc_ok,
    }
    return value


def _version(v: InnoVersion) -> JsonValue:
    major, minor, patch, build = v.version
    return {
        "raw": display_name(v.raw),
        "major": major,
        "minor": minor,
        "patch": patch,
        "build": build,
        "unicode": v.unicode,
        "known": v.known,
    }


def _block(b: InnoBlockHeader) -> JsonValue:
    return {
        "index": b.index,
        "offset": b.offset.value,
        "stored_size": b.stored_size,
        "compressed": b.flag == 1,
        "compression": str(b.compression),
        "crc_ok": b.crc_ok,
    }


def _decode(d: InnoDecodeStatus) -> JsonValue:
    status = "ended" if d.ended else "unterminated"
    if d.failure is not None:
        status = str(d.failure)
    return {
        "codec": str(d.codec),
        "status": status,
        "decoded_size": d.decoded_size,
        "consumed": d.consumed,
        "trailing": d.trailing,
    }


def _header(h: InnoHeader, files: int) -> JsonValue:
    name, version, publisher = (_text(raw) for raw in (h.app_name, h.app_version, h.app_publisher))
    method = h.compress_name
    counts: dict[str, JsonValue] = dict(zip(COUNT_NAMES, h.counts, strict=True))
    return {
        "app_name": name[0],
        "app_version": version[0],
        "app_publisher": publisher[0],
        "compress_method": str(method) if method is not None else None,
        "compress_method_id": h.compress_method,
        "options_hex": h.options.hex(),
        "counts": counts,
        "files_total": h.num_files,
        "files_reported": min(files, MAX_INNO_FILE_FINDINGS),
        "text_truncated": name[1] or version[1] or publisher[1],
    }


def _file(index: int, f: InnoFile) -> JsonValue:
    e, loc = f.entry, f.location
    dest, dest_cut = _text(e.dest)
    source, source_cut = _text(e.source)
    kind = e.file_type_name
    value: dict[str, JsonValue] = {
        "index": index,
        "dest": dest,
        "source": source,
        "file_type": str(kind) if kind is not None else None,
        "file_type_id": e.file_type,
        "options": e.options,
        "location": e.location,
    }
    flags: list[JsonValue] | None = None
    if loc is not None:
        flags = [n for i, n in enumerate(LOCATION_FLAG_NAMES) if loc.flags >> i & 1]
    value |= {
        "size": loc.original_size if loc is not None else None,
        "sha256": loc.sha256.hex() if loc is not None else None,
        "filetime": loc.filetime if loc is not None else None,
        "timestamp": _timestamp(loc) if loc is not None else None,
        "flags": flags,
        "flags_raw": loc.flags if loc is not None else None,
        "text_truncated": dest_cut or source_cut,
    }
    return value


def inno_facts(info: InnoInfo, producer: str) -> tuple[Finding, ...]:
    """Findings for the loader table, version, block headers, first chunk, then decoded data."""
    findings = [parsed_finding("inno.loader", _loader(info.offsets), producer)]
    if info.version is not None:
        findings.append(parsed_finding("inno.version", _version(info.version), producer))
    findings.extend(parsed_finding("inno.block", _block(b), producer) for b in info.blocks)
    if info.data is not None:
        value: JsonValue = {"offset": info.data.offset.value, "magic_ok": info.data.magic_ok}
        findings.append(parsed_finding("inno.data", value, producer))
    findings.extend(
        parsed_finding(f"inno.block{d.index}.decode", _decode(d), producer) for d in info.decode
    )
    if info.header is not None:
        value = _header(info.header, len(info.files))
        findings.append(parsed_finding(f"{_SUBJECT}0:setup_header", value, producer))
    findings.extend(
        parsed_finding(f"{_SUBJECT}{f.entry.decoded_offset:x}:file_entry", _file(i, f), producer)
        for i, f in enumerate(info.files[:MAX_INNO_FILE_FINDINGS])
    )
    return tuple(findings)
