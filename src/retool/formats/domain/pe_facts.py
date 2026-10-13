"""Domain service: the findings and not-analysed markers formats reports for a PE."""

from __future__ import annotations

import re
from typing import Final

from retool.formats.domain.facts import magic_finding, parsed_finding
from retool.formats.domain.image import Image
from retool.formats.domain.model import Format
from retool.formats.domain.parsing import display_name
from retool.formats.domain.pe import ImportedDll, ImportedFunction, OverlayInfo, PeFile
from retool.formats.domain.pe_image import pe_arch
from retool.shared import Finding, JsonValue, NotAnalysed

ENTRY_OUTSIDE_NOTE = "pe entry point outside every mapped section"
STRING_TABLE_NOTE = "pe section names referencing the COFF string table not resolved"
NOT_PARSED_NOTE = (
    "pe exports, relocations, resources, delay-load and bound imports, certificate contents, "
    "debug data, CLR metadata and COFF symbols not parsed in this version"
)

_STRING_TABLE_NAME: Final = re.compile(rb"/[0-9]+")


def _header(pe: PeFile) -> JsonValue:
    c = pe.coff
    return {
        "e_lfanew": pe.dos.e_lfanew.value,
        "machine": c.machine,
        "arch": str(pe_arch(c)),
        "number_of_sections": c.number_of_sections,
        "time_date_stamp": c.time_date_stamp,
        "pointer_to_symbol_table": c.pointer_to_symbol_table.value,
        "number_of_symbols": c.number_of_symbols,
        "size_of_optional_header": c.size_of_optional_header,
        "characteristics": c.characteristics,
    }


def _optional(pe: PeFile) -> JsonValue:
    o = pe.optional
    value: dict[str, JsonValue] = {
        "magic": o.magic,
        "format": "pe32+" if o.bits == 64 else "pe32",
        "major_linker_version": o.major_linker_version,
        "minor_linker_version": o.minor_linker_version,
        "size_of_code": o.size_of_code,
        "size_of_initialized_data": o.size_of_initialized_data,
        "size_of_uninitialized_data": o.size_of_uninitialized_data,
        "address_of_entry_point": o.address_of_entry_point,
        "base_of_code": o.base_of_code,
    }
    if o.base_of_data is not None:
        value["base_of_data"] = o.base_of_data
    value |= {
        "image_base": o.image_base,
        "section_alignment": o.section_alignment,
        "file_alignment": o.file_alignment,
        "major_os_version": o.major_os_version,
        "minor_os_version": o.minor_os_version,
        "major_image_version": o.major_image_version,
        "minor_image_version": o.minor_image_version,
        "major_subsystem_version": o.major_subsystem_version,
        "minor_subsystem_version": o.minor_subsystem_version,
        "win32_version_value": o.win32_version_value,
        "size_of_image": o.size_of_image,
        "size_of_headers": o.size_of_headers,
        "checksum": o.checksum,
        "subsystem": o.subsystem,
        "dll_characteristics": o.dll_characteristics,
        "size_of_stack_reserve": o.size_of_stack_reserve,
        "size_of_stack_commit": o.size_of_stack_commit,
        "size_of_heap_reserve": o.size_of_heap_reserve,
        "size_of_heap_commit": o.size_of_heap_commit,
        "loader_flags": o.loader_flags,
        "number_of_rva_and_sizes": o.number_of_rva_and_sizes,
        "data_directories": [
            {"index": index, "virtual_address": d.virtual_address, "size": d.size}
            for index, d in enumerate(pe.directories)
        ],
    }
    return value


def _function(f: ImportedFunction) -> JsonValue:
    if f.name is None:
        return {"ordinal": f.ordinal}
    value: dict[str, JsonValue] = {"hint": f.hint, "name": display_name(f.name)}
    if f.name_truncated:
        value["name_truncated"] = True
    return value


def _import(index: int, dll: ImportedDll) -> JsonValue:
    value: dict[str, JsonValue] = {
        "index": index,
        "descriptor_offset": dll.descriptor_offset.value,
        "dll": display_name(dll.name) if dll.name is not None else None,
    }
    if dll.name_truncated:
        value["dll_truncated"] = True
    value |= {
        "ilt_rva": dll.ilt_rva,
        "time_date_stamp": dll.time_date_stamp,
        "forwarder_chain": dll.forwarder_chain,
        "name_rva": dll.name_rva,
        "iat_rva": dll.iat_rva,
        "functions": [_function(f) for f in dll.functions],
        "end": dll.end.value,
    }
    return value


def _overlay(overlay: OverlayInfo) -> JsonValue:
    cert = overlay.certificate
    return {
        "offset": overlay.offset.value,
        "size": overlay.size,
        "certificate": {"offset": cert.start, "size": cert.size} if cert is not None else None,
        "payload_size": overlay.payload_size,
        "trailing_size": overlay.trailing_size,
    }


def pe_facts(
    pe: PeFile, image: Image | None, producer: str
) -> tuple[tuple[Finding, ...], tuple[NotAnalysed, ...]]:
    """Findings for the PE headers, sections and attached tables, and what was not analysed."""
    findings = [
        magic_finding(Format.PE, producer),
        parsed_finding("pe.header", _header(pe), producer),
        parsed_finding("pe.optional", _optional(pe), producer),
    ]
    for index, s in enumerate(pe.sections):
        section: JsonValue = {
            "index": index,
            "name": display_name(s.name),
            "virtual_size": s.virtual_size,
            "virtual_address": s.virtual_address,
            "size_of_raw_data": s.size_of_raw_data,
            "pointer_to_raw_data": s.pointer_to_raw_data.value,
            "pointer_to_relocations": s.pointer_to_relocations.value,
            "pointer_to_linenumbers": s.pointer_to_linenumbers.value,
            "number_of_relocations": s.number_of_relocations,
            "number_of_linenumbers": s.number_of_linenumbers,
            "characteristics": s.characteristics,
        }
        findings.append(parsed_finding("pe.section", section, producer))
    findings.extend(
        parsed_finding("pe.import", _import(index, dll), producer)
        for index, dll in enumerate(pe.imports)
    )
    for index, cert in enumerate(pe.certificates):
        value: JsonValue = {
            "index": index,
            "offset": cert.offset.value,
            "length": cert.length,
            "revision": cert.revision,
            "type": cert.certificate_type,
        }
        findings.append(parsed_finding("pe.certificate", value, producer))
    if pe.overlay is not None:
        findings.append(parsed_finding("pe.overlay", _overlay(pe.overlay), producer))
        findings.extend(
            parsed_finding(
                "pe.signature", {"signature": m.name, "offset": m.offset.value}, producer
            )
            for m in pe.overlay.signatures
        )
    notes: list[NotAnalysed] = []
    if image is not None and pe.optional.address_of_entry_point != 0 and image.entry is None:
        notes.append(NotAnalysed(ENTRY_OUTSIDE_NOTE))
    if any(_STRING_TABLE_NAME.fullmatch(s.name) for s in pe.sections):
        notes.append(NotAnalysed(STRING_TABLE_NOTE))
    notes.append(NotAnalysed(NOT_PARSED_NOTE))
    return tuple(findings), tuple(notes)
