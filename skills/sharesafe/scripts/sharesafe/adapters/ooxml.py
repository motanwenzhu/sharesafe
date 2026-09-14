"""OOXML package inspection without launching an office application."""

from __future__ import annotations

import io
from pathlib import PurePosixPath
import re
import zipfile
from typing import TYPE_CHECKING
import xml.etree.ElementTree as ET

from .archive import _bounded_read, _is_symlink, _unsafe_member_name
from .text import scan_text
from ..detectors import sanitize_display_path
from ..ooxml_xml import (
    declares_digital_signature,
    declares_embedded_object,
    declares_macros,
    local_name as _local,
    parse_xml as _parse_xml,
)
from ..zip_safety import preflight_zip

if TYPE_CHECKING:
    from ..engine import Scanner
    from ..models import Artifact, ReportBuilder


_CORE_FIELDS = {
    "creator": ("person_name", "identity_metadata", "Document author metadata is present", "medium"),
    "lastModifiedBy": ("person_name", "identity_metadata", "Last-modified-by metadata is present", "medium"),
    "title": ("document_metadata", "document_metadata", "Document title metadata is present", "low"),
    "subject": ("document_metadata", "document_metadata", "Document subject metadata is present", "low"),
    "description": ("document_metadata", "document_metadata", "Document description metadata is present", "medium"),
    "keywords": ("document_metadata", "document_metadata", "Document keyword metadata is present", "low"),
    "category": ("document_metadata", "document_metadata", "Document category metadata is present", "low"),
    "identifier": ("document_metadata", "document_metadata", "Document identifier metadata is present", "medium"),
    "created": ("timestamp", "timestamp_metadata", "Document creation timestamp is present", "low"),
    "modified": ("timestamp", "timestamp_metadata", "Document modification timestamp is present", "low"),
    "lastPrinted": ("timestamp", "timestamp_metadata", "Document last-printed timestamp is present", "medium"),
    "revision": ("revision", "document_metadata", "Document revision metadata is present", "low"),
    "contentStatus": ("document_metadata", "document_metadata", "Document content-status metadata is present", "low"),
    "language": ("document_metadata", "document_metadata", "Document language metadata is present", "low"),
    "version": ("document_metadata", "document_metadata", "Document version metadata is present", "low"),
}
_OLE_COMPOUND_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _is_embedded_part_name(name: str) -> bool:
    return any(part.casefold() in {"embeddings", "activex"} for part in PurePosixPath(name).parts)


def _xml_search_text(root: ET.Element, limit: int) -> str:
    # Joining adjacent runs without separators detects values split across OOXML runs.
    body_parts: list[str] = []
    attribute_parts: list[str] = []
    length = 0
    for value in root.itertext():
        if not value:
            continue
        length += len(value)
        if length > limit:
            raise ValueError("expanded XML text exceeds the configured limit")
        body_parts.append(value)
    for element in root.iter():
        for value in element.attrib.values():
            text = str(value)
            length += len(text) + 1
            if length > limit:
                raise ValueError("expanded XML attributes exceed the configured limit")
            attribute_parts.append(text)
    body = "".join(body_parts)
    attributes = "\n".join(attribute_parts)
    return f"{body}\n{attributes}" if attributes else body


def _has_truthy_attribute(element: ET.Element, name: str) -> bool:
    value = element.attrib.get(name)
    return value is not None and value.casefold() in {"1", "true", "on", "yes"}


def scan_ooxml(
    scanner: "Scanner",
    data: bytes,
    display_path: str,
    sniff_path: str,
    artifact: "Artifact",
    builder: "ReportBuilder",
    *,
    depth: int,
) -> None:
    limits = scanner.config.limits
    artifact.set_coverage("metadata", "complete")
    artifact.set_coverage("text", "complete")
    artifact.set_coverage("hidden_content", "complete")
    artifact.set_coverage("embedded_objects", "complete")
    if depth >= limits.max_archive_depth:
        builder.add_gap(artifact, "structure", "archive_depth_limit", "Nested OOXML depth reached the configured maximum.")
        return

    preflight = preflight_zip(data, limits.max_archive_entries)
    if preflight.status == "entry_limit":
        builder.add_gap(
            artifact,
            "structure",
            "archive_entry_limit",
            "OOXML package has too many parts; no parts were materialized.",
        )
        return
    if preflight.status == "malformed":
        builder.add_gap(artifact, "structure", "malformed_ooxml", "OOXML ZIP central directory could not be validated.")
        return

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except (zipfile.BadZipFile, OSError, ValueError):
        builder.add_gap(artifact, "structure", "malformed_ooxml", "OOXML ZIP package could not be parsed.")
        return

    extension = PurePosixPath(sniff_path.casefold()).suffix
    expected_main_part = {
        ".docx": "word/document.xml", ".docm": "word/document.xml",
        ".xlsx": "xl/workbook.xml", ".xlsm": "xl/workbook.xml",
        ".pptx": "ppt/presentation.xml", ".pptm": "ppt/presentation.xml",
    }.get(extension)

    with archive:
        comment_bytes = 0

        def scan_comment(payload: bytes, part: str) -> None:
            nonlocal comment_bytes
            if comment_bytes + len(payload) > limits.max_text_bytes:
                builder.add_gap(
                    artifact,
                    "text",
                    "ooxml_comment_text_limit",
                    "Office package comment text exceeds the configured cumulative scan limit.",
                )
                return
            comment_bytes += len(payload)
            scan_text(payload, artifact, builder, evidence_key=scanner.evidence_key, part=part)

        if archive.comment:
            builder.add_finding(
                artifact,
                rule_id="SS-OOXML-PACKAGE-COMMENT",
                category="identity_metadata",
                severity="medium",
                confidence=1.0,
                title="Office package contains a ZIP comment",
                location={"kind": "ooxml_package"},
                remediation_supported=True,
                remediation_action="remove_document_properties_from_copy",
            )
            scan_comment(archive.comment, "OOXML/package-comment")
        names = {info.filename.replace("\\", "/").casefold() for info in infos}
        if (
            expected_main_part is None
            or "[content_types].xml" not in names
            or expected_main_part not in names
        ):
            builder.add_gap(artifact, "structure", "ooxml_type_mismatch", "Package lacks the main part implied by its extension.")

        if len(infos) > limits.max_archive_entries:
            builder.add_gap(artifact, "structure", "archive_entry_limit", "OOXML package has too many parts; remaining parts were not read.")
            infos = infos[: limits.max_archive_entries]

        expanded = 0
        macro_found = extension in {".docm", ".xlsm", ".pptm"}
        signature_found = False
        comment_parts: list[str] = []
        note_parts: list[str] = []
        custom_xml_found = False
        embedded_object_found = False
        opaque_embedded_found = False
        names_seen: dict[str, int] = {}

        for index, info in enumerate(infos):
            raw_name = info.filename
            name = raw_name.replace("\\", "/")
            safe_name = sanitize_display_path(name)
            lower = name.casefold()
            if _is_embedded_part_name(name):
                embedded_object_found = True
            names_seen[lower] = names_seen.get(lower, 0) + 1
            occurrence = names_seen[lower]
            if lower.endswith((".xml", ".rels")):
                scanner.scan_container_name(name, artifact, builder)
            if _unsafe_member_name(raw_name):
                builder.add_finding(
                    artifact,
                    rule_id="SS-ARCHIVE-PATH-TRAVERSAL",
                    category="archive_structure",
                    severity="critical",
                    confidence=1.0,
                    title="OOXML package part uses an unsafe path",
                    location={"kind": "ooxml_part", "index": index},
                    remediation_action="rebuild_document_package",
                )
                builder.add_gap(artifact, "structure", "unsafe_part_name", "Unsafe OOXML part was not opened.")
                continue
            if occurrence > 1:
                builder.add_finding(
                    artifact,
                    rule_id="SS-OOXML-DUPLICATE-PART",
                    category="archive_structure",
                    severity="high",
                    confidence=1.0,
                    title="Office package contains duplicate or case-colliding part names",
                    location={"kind": "ooxml_part", "index": index, "occurrence": occurrence},
                    remediation_action="rebuild_document_package_without_duplicate_parts",
                )
                builder.add_gap(
                    artifact,
                    "structure",
                    "duplicate_ooxml_part",
                    "Duplicate part names make package interpretation ambiguous.",
                )
            if info.is_dir():
                scanner.scan_virtual_directory(f"{display_path}!/{name}", builder)
                continue
            if _is_symlink(info):
                builder.add_finding(
                    artifact,
                    rule_id="SS-OOXML-SYMLINK-PART",
                    category="filesystem_boundary",
                    severity="high",
                    confidence=1.0,
                    title="Office package contains a symbolic-link part",
                    location={"kind": "ooxml_part", "index": index},
                    remediation_action="rebuild_document_package_without_links",
                )
                builder.add_gap(artifact, "structure", "ooxml_link_not_followed", "OOXML symbolic-link payload was not scanned.")
                continue
            if info.comment:
                builder.add_finding(
                    artifact,
                    rule_id="SS-OOXML-PART-COMMENT",
                    category="identity_metadata",
                    severity="medium",
                    confidence=1.0,
                    title="Office package part contains a ZIP comment",
                    location={"kind": "ooxml_part", "part": safe_name},
                    remediation_supported=True,
                    remediation_action="remove_document_properties_from_copy",
                )
                scan_comment(info.comment, f"OOXML/comment/{safe_name}")
            if info.flag_bits & 0x1:
                builder.add_finding(
                    artifact,
                    rule_id="SS-OOXML-ENCRYPTED-PART",
                    category="coverage",
                    severity="high",
                    confidence=1.0,
                    title="Office package contains an encrypted part",
                    location={"kind": "ooxml_part", "index": index},
                    remediation_action="provide_an_unencrypted_review_copy",
                )
                builder.add_gap(artifact, "structure", "encrypted_member", "Encrypted OOXML part could not be inspected.")
                continue
            if info.file_size > limits.max_archive_member_bytes:
                builder.add_gap(artifact, "structure", "archive_member_size_limit", "OOXML part exceeds the configured size limit.")
                continue
            ratio = info.file_size / max(1, info.compress_size)
            if info.file_size > 1024 * 1024 and ratio > limits.max_compression_ratio:
                builder.add_gap(artifact, "structure", "compression_ratio_limit", "OOXML part exceeds the configured compression-ratio limit.")
                continue
            if expanded + info.file_size > limits.max_expanded_bytes or not scanner.claim_archive_bytes(info.file_size):
                builder.add_gap(artifact, "structure", "expanded_byte_limit", "OOXML package expansion budget was exhausted.")
                break
            try:
                with archive.open(info, "r") as handle:
                    part_data = _bounded_read(handle, min(limits.max_archive_member_bytes, info.file_size))
            except (OSError, RuntimeError, zipfile.BadZipFile, EOFError):
                builder.add_gap(artifact, "structure", "part_read_error", "OOXML package part could not be decompressed.")
                continue
            if len(part_data) != info.file_size:
                builder.add_gap(artifact, "structure", "part_size_mismatch", "OOXML part did not match its declared size.")
                continue
            expanded += len(part_data)

            if "vbaproject.bin" in lower or lower.endswith("/vbadata.xml"):
                macro_found = True
            if lower.startswith("_xmlsignatures/"):
                signature_found = True
            if lower.startswith("customxml/") and not lower.endswith(".rels"):
                custom_xml_found = True
            if re.search(r"(?:^|/)(?:comments|threadedcomments)[^/]*\.xml$", lower) or "/comments/" in lower:
                comment_parts.append(name)
            if lower.startswith("ppt/notesslides/") and lower.endswith(".xml"):
                note_parts.append(name)
            is_xml = lower.endswith((".xml", ".rels"))
            if is_xml:
                if len(part_data) > limits.max_xml_bytes:
                    builder.add_gap(artifact, "text", "xml_size_limit", "OOXML XML part exceeds the configured text limit.")
                    continue
                try:
                    root = _parse_xml(part_data)
                except (ET.ParseError, ValueError):
                    builder.add_gap(artifact, "structure", "xml_parse_error", "An OOXML XML part could not be parsed safely.")
                    scan_text(
                        part_data,
                        artifact,
                        builder,
                        evidence_key=scanner.evidence_key,
                        part=f"OOXML/unparsed/{safe_name}",
                    )
                    continue
                if declares_macros(root):
                    macro_found = True
                if declares_embedded_object(root):
                    embedded_object_found = True
                    opaque_embedded_found = True
                if (lower == "[content_types].xml" or lower.endswith(".rels")) and declares_digital_signature(root):
                    signature_found = True
                if lower.endswith(".rels"):
                    _scan_relationships(root, safe_name, artifact, builder)
                _inspect_xml_structure(root, lower, safe_name, artifact, builder)
                try:
                    searchable = _xml_search_text(root, limits.max_text_bytes)
                except ValueError:
                    builder.add_gap(artifact, "text", "expanded_xml_text_limit", "Expanded OOXML text exceeds the configured limit.")
                    continue
                if searchable:
                    scan_text(
                        searchable.encode("utf-8"), artifact, builder,
                        evidence_key=scanner.evidence_key, part=safe_name,
                    )
            else:
                if part_data.startswith(_OLE_COMPOUND_MAGIC):
                    embedded_object_found = True
                    opaque_embedded_found = True
                virtual_path = f"{display_path}!/{name}"
                scanner.scan_bytes(part_data, virtual_path, builder, depth=depth + 1)

        if macro_found:
            builder.add_finding(
                artifact,
                rule_id="SS-OOXML-MACRO",
                category="active_content",
                severity="high",
                confidence=1.0,
                title="Macro-enabled Office content is present",
                location={"kind": "ooxml_package"},
                remediation_action="review_and_remove_macros_with_a_trusted_office_tool",
            )
            builder.add_gap(artifact, "embedded_objects", "macro_not_analyzed", "VBA behavior and strings were not analyzed.")
        if signature_found:
            builder.add_finding(
                artifact,
                rule_id="SS-OOXML-DIGITAL-SIGNATURE",
                category="integrity_control",
                severity="high",
                confidence=1.0,
                title="Document contains a digital signature that sanitization would invalidate",
                location={"kind": "ooxml_package"},
                remediation_action="preserve_original_and_make_an_unsigned_review_copy",
            )
        if comment_parts:
            builder.add_finding(
                artifact,
                rule_id="SS-OOXML-COMMENTS",
                category="hidden_content",
                severity="high",
                confidence=1.0,
                title="Office comments or threaded comments are present",
                location={"kind": "ooxml_package", "part_count": len(comment_parts)},
                remediation_action="review_and_remove_comments_in_the_source_application",
            )
        if note_parts:
            builder.add_finding(
                artifact,
                rule_id="SS-OOXML-SPEAKER-NOTES",
                category="hidden_content",
                severity="high",
                confidence=1.0,
                title="PowerPoint speaker notes are present",
                location={"kind": "ooxml_package", "part_count": len(note_parts)},
                remediation_action="review_and_remove_speaker_notes",
            )
        if custom_xml_found:
            builder.add_finding(
                artifact,
                rule_id="SS-OOXML-CUSTOM-XML",
                category="hidden_content",
                severity="medium",
                confidence=1.0,
                title="Custom XML data is embedded in the Office package",
                location={"kind": "ooxml_package"},
                remediation_action="review_custom_xml_before_sharing",
            )
        if embedded_object_found:
            builder.add_finding(
                artifact,
                rule_id="SS-OOXML-EMBEDDED-OBJECT",
                category="hidden_content",
                severity="high",
                confidence=1.0,
                title="Office document contains an embedded object or active control",
                location={"kind": "ooxml_package"},
                remediation_action="review_and_remove_embedded_objects_in_the_source_application",
            )
            builder.add_gap(
                artifact,
                "embedded_objects",
                "embedded_object_not_analyzed" if opaque_embedded_found else "embedded_active_content_not_analyzed",
                "Embedded object behavior and complete internal semantics were not analyzed.",
            )

def _scan_relationships(
    root: ET.Element,
    part_name: str,
    artifact: "Artifact",
    builder: "ReportBuilder",
) -> None:
    external = [
        element
        for element in root.iter()
        if _local(element.tag) == "Relationship"
        and element.attrib.get("TargetMode", "").casefold() == "external"
    ]
    if external:
        builder.add_finding(
            artifact,
            rule_id="SS-OOXML-EXTERNAL-RELATIONSHIP",
            category="external_reference",
            severity="high",
            confidence=1.0,
            title="Office document contains external relationships",
            location={"kind": "ooxml_part", "part": part_name, "count": len(external)},
            remediation_action="review_and_break_external_links",
        )


def _inspect_xml_structure(
    root: ET.Element,
    lower_name: str,
    part_name: str,
    artifact: "Artifact",
    builder: "ReportBuilder",
) -> None:
    if lower_name == "docprops/core.xml":
        for child in root:
            local = _local(child.tag)
            value = "".join(child.itertext()).strip()
            if value and local in _CORE_FIELDS:
                value_class, category, title, severity = _CORE_FIELDS[local]
                builder.add_finding(
                    artifact,
                    rule_id=f"SS-OOXML-CORE-{re.sub(r'(?<!^)(?=[A-Z])', '-', local).upper()}",
                    category=category,
                    severity=severity,
                    confidence=1.0,
                    title=title,
                    location={"kind": "ooxml_part", "part": part_name, "field": local},
                    evidence={"mode": "omitted", "value_class": value_class},
                    remediation_supported=True,
                    remediation_action="remove_document_properties_from_copy",
                )
    elif lower_name == "docprops/app.xml":
        for child in root:
            local = _local(child.tag)
            value = "".join(child.itertext()).strip()
            if not value:
                continue
            if local in {"Manager", "Company"}:
                builder.add_finding(
                    artifact,
                    rule_id=f"SS-OOXML-APP-{local.upper()}",
                    category="identity_metadata",
                    severity="medium",
                    confidence=1.0,
                    title=f"Office {local.casefold()} metadata is present",
                    location={"kind": "ooxml_part", "part": part_name, "field": local},
                    evidence={"mode": "omitted", "value_class": "organization_or_person"},
                    remediation_supported=True,
                    remediation_action="remove_document_properties_from_copy",
                )
            elif local == "HyperlinkBase":
                builder.add_finding(
                    artifact,
                    rule_id="SS-OOXML-APP-HYPERLINK-BASE",
                    category="path_disclosure",
                    severity="medium",
                    confidence=1.0,
                    title="Office hyperlink-base metadata is present",
                    location={"kind": "ooxml_part", "part": part_name, "field": local},
                    evidence={"mode": "omitted", "value_class": "path_or_url"},
                    remediation_supported=True,
                    remediation_action="remove_document_properties_from_copy",
                )
            elif local in {"Application", "AppVersion", "Template"}:
                builder.add_finding(
                    artifact,
                    rule_id=f"SS-OOXML-APP-{local.upper()}",
                    category="software_metadata",
                    severity="low",
                    confidence=1.0,
                    title=f"Office {local.casefold()} metadata is present",
                    location={"kind": "ooxml_part", "part": part_name, "field": local},
                    evidence={"mode": "omitted", "value_class": "software_or_template"},
                    remediation_supported=True,
                    remediation_action="remove_document_properties_from_copy",
                )
    elif lower_name == "docprops/custom.xml":
        properties = [element for element in root.iter() if _local(element.tag) == "property"]
        if properties:
            builder.add_finding(
                artifact,
                rule_id="SS-OOXML-CUSTOM-PROPERTIES",
                category="identity_metadata",
                severity="medium",
                confidence=1.0,
                title="Custom Office document properties are present",
                location={"kind": "ooxml_part", "part": part_name, "count": len(properties)},
                remediation_supported=True,
                remediation_action="remove_custom_document_properties_from_copy",
            )

    if lower_name.startswith("word/"):
        revisions = sum(1 for element in root.iter() if _local(element.tag) in {"ins", "del", "moveFrom", "moveTo"})
        if revisions:
            builder.add_finding(
                artifact,
                rule_id="SS-OOXML-TRACKED-CHANGES",
                category="hidden_content",
                severity="high",
                confidence=1.0,
                title="Word tracked changes are present",
                location={"kind": "ooxml_part", "part": part_name, "count": revisions},
                remediation_action="accept_or_reject_changes_after_manual_review",
            )

    if lower_name.startswith("xl/worksheets/"):
        hidden_rows = sum(1 for element in root.iter() if _local(element.tag) in {"row", "col"} and _has_truthy_attribute(element, "hidden"))
        if hidden_rows:
            builder.add_finding(
                artifact,
                rule_id="SS-OOXML-HIDDEN-ROWS-COLUMNS",
                category="hidden_content",
                severity="high",
                confidence=1.0,
                title="Excel worksheet contains hidden rows or columns",
                location={"kind": "ooxml_part", "part": part_name, "count": hidden_rows},
                remediation_action="review_and_unhide_or_remove_hidden_cells",
            )
    if lower_name == "xl/workbook.xml":
        hidden_sheets = [
            element for element in root.iter()
            if _local(element.tag) == "sheet" and element.attrib.get("state", "visible").casefold() != "visible"
        ]
        if hidden_sheets:
            builder.add_finding(
                artifact,
                rule_id="SS-OOXML-HIDDEN-SHEET",
                category="hidden_content",
                severity="high",
                confidence=1.0,
                title="Excel workbook contains hidden or very-hidden sheets",
                location={"kind": "ooxml_part", "part": part_name, "count": len(hidden_sheets)},
                remediation_action="review_and_remove_or_unhide_sheets",
            )
    if lower_name == "ppt/presentation.xml":
        hidden_slides = [
            element for element in root.iter()
            if _local(element.tag) == "sldId" and element.attrib.get("show", "1").casefold() in {"0", "false", "off"}
        ]
        if hidden_slides:
            builder.add_finding(
                artifact,
                rule_id="SS-OOXML-HIDDEN-SLIDE",
                category="hidden_content",
                severity="high",
                confidence=1.0,
                title="PowerPoint presentation contains hidden slides",
                location={"kind": "ooxml_part", "part": part_name, "count": len(hidden_slides)},
                remediation_action="review_and_remove_or_unhide_slides",
            )

    if "externallinks/" in lower_name or lower_name.endswith("connections.xml"):
        builder.add_finding(
            artifact,
            rule_id="SS-OOXML-EXTERNAL-DATA",
            category="external_reference",
            severity="high",
            confidence=1.0,
            title="Office document contains external data-link definitions",
            location={"kind": "ooxml_part", "part": part_name},
            remediation_action="review_and_remove_external_data_connections",
        )
