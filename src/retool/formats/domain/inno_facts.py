"""Domain service: the ``inno.*`` findings formats reports for parsed Inno loader structures."""

from __future__ import annotations

from retool.formats.domain.facts import parsed_finding
from retool.formats.domain.inno import InnoBlockHeader, InnoInfo, InnoOffsets, InnoVersion
from retool.formats.domain.parsing import display_name
from retool.shared import Finding, JsonValue


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


def inno_facts(info: InnoInfo, producer: str) -> tuple[Finding, ...]:
    """Findings for the loader table, version field, block headers and first chunk, in order."""
    findings = [parsed_finding("inno.loader", _loader(info.offsets), producer)]
    if info.version is not None:
        findings.append(parsed_finding("inno.version", _version(info.version), producer))
    findings.extend(parsed_finding("inno.block", _block(b), producer) for b in info.blocks)
    if info.data is not None:
        value: JsonValue = {"offset": info.data.offset.value, "magic_ok": info.data.magic_ok}
        findings.append(parsed_finding("inno.data", value, producer))
    return tuple(findings)
