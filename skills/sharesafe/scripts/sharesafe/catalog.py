"""Stable public capability and rule catalog.

The summary groups remain the compact default CLI view.  ``RULE_DETAILS`` is
the exact, versioned inventory used by policy tooling and ``rules --detail``;
wildcard entries are deliberately forbidden there.
"""

from __future__ import annotations

from typing import Any

from .detectors import RULESET_VERSION


RULE_GROUPS: tuple[dict[str, object], ...] = (
    {"prefix": "pii.*", "category": "pii", "description": "High-confidence email, mainland China mobile, resident ID, and Luhn-valid card patterns."},
    {"prefix": "secret.*", "category": "secret", "description": "Private keys, selected provider tokens, JWTs, and credential assignments."},
    {"prefix": "privacy.*", "category": "path_disclosure", "description": "Absolute user-home paths that may reveal account names."},
    {"prefix": "unicode.*", "category": "unicode_control", "description": "Bidirectional and zero-width controls that can hide or reshape evidence."},
    {"prefix": "SS-GEN-*", "category": "filesystem", "description": "Sensitive filenames, links, VCS history, executables, and type mismatches."},
    {"prefix": "SS-ARCHIVE-*", "category": "archive", "description": "ZIP traversal, encryption, links, duplicate names, comments, and entry metadata."},
    {"prefix": "SS-OOXML-*", "category": "office", "description": "Office properties, comments, revisions, notes, hidden content, links, macros, signatures, and embeddings."},
    {"prefix": "SS-PDF-*", "category": "pdf", "description": "PDF metadata, attachments, actions, forms, annotations, encryption, and redaction markers."},
    {"prefix": "SS-IMAGE-*", "category": "image", "description": "EXIF/GPS/XMP/IPTC/comments, device data, and textual image chunks."},
)


FORMATS: tuple[dict[str, object], ...] = (
    {"format": "text/code/config", "extensions": ["txt", "md", "csv", "json", "yaml", "xml", "env", "source code"], "scan": "complete for decoded bytes", "sanitize": "copied unchanged"},
    {"format": "OOXML", "extensions": ["docx", "xlsx", "pptx"], "scan": "properties, XML text, hidden content, links, embedded objects", "sanitize": "metadata-only copy; comments and body content remain"},
    {"format": "macro OOXML", "extensions": ["docm", "xlsm", "pptm"], "scan": "structure and visible XML; VBA unanalyzed", "sanitize": "copied unchanged; transform skipped and verification incomplete"},
    {"format": "ZIP", "extensions": ["zip", "jar", "epub", "whl"], "scan": "bounded recursive inventory", "sanitize": "copied unchanged; transform unsupported and verification incomplete"},
    {"format": "PDF", "extensions": ["pdf"], "scan": "basic structure; optional pypdf text", "sanitize": "detection-only; bytes are not rewritten"},
    {"format": "PNG", "extensions": ["png"], "scan": "chunks plus optional Pillow tags; no OCR", "sanitize": "allowlisted metadata chunks removed when orientation permits"},
    {"format": "JPEG", "extensions": ["jpg", "jpeg"], "scan": "segments plus optional Pillow EXIF; no OCR", "sanitize": "metadata segments removed when orientation is neutral"},
    {"format": "TIFF/WebP", "extensions": ["tif", "tiff", "webp"], "scan": "optional Pillow metadata; no OCR", "sanitize": "copied unchanged"},
    {"format": "other binary", "extensions": [], "scan": "unsupported gap", "sanitize": "copied unchanged; verification incomplete"},
)


def _rule(
    rule_id: str,
    category: str,
    severity: str,
    confidence: float,
    representations: tuple[str, ...],
    formats: tuple[str, ...],
    validator: str,
    *,
    automatic_remediation: bool = False,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "category": category,
        "default_severity": severity,
        "confidence": confidence,
        "representations": list(representations),
        "formats": list(formats),
        "validator": validator,
        "automatic_remediation": automatic_remediation,
    }


_TEXT_REPRESENTATIONS = ("decoded_text", "filename", "archive_member_name")
_TEXT_FORMATS = ("text", "code", "config", "archive_text", "ooxml_xml", "pdf_text", "image_metadata")


RULE_DETAILS: tuple[dict[str, Any], ...] = (
    _rule("pii.email", "pii", "high", 0.98, _TEXT_REPRESENTATIONS, _TEXT_FORMATS, "bounded_regex"),
    _rule("pii.cn_mobile", "pii", "high", 0.98, _TEXT_REPRESENTATIONS, _TEXT_FORMATS, "mainland_mobile_validator"),
    _rule("pii.cn_resident_id", "pii", "critical", 0.99, _TEXT_REPRESENTATIONS, _TEXT_FORMATS, "date_and_checksum"),
    _rule("pii.bank_card", "pii", "critical", 0.98, _TEXT_REPRESENTATIONS, _TEXT_FORMATS, "luhn_checksum"),
    _rule("secret.pem_private_key", "secret", "critical", 1.0, _TEXT_REPRESENTATIONS, _TEXT_FORMATS, "paired_pem_markers"),
    _rule("secret.aws_access_key_id", "secret", "critical", 0.99, _TEXT_REPRESENTATIONS, _TEXT_FORMATS, "provider_shape"),
    _rule("secret.aws_secret_access_key", "secret", "critical", 0.99, _TEXT_REPRESENTATIONS, _TEXT_FORMATS, "assignment_context"),
    _rule("secret.github_token", "secret", "critical", 0.99, _TEXT_REPRESENTATIONS, _TEXT_FORMATS, "provider_shape"),
    _rule("secret.openai_api_key", "secret", "critical", 0.99, _TEXT_REPRESENTATIONS, _TEXT_FORMATS, "provider_shape"),
    _rule("secret.slack_token", "secret", "critical", 0.99, _TEXT_REPRESENTATIONS, _TEXT_FORMATS, "provider_shape"),
    _rule("secret.google_api_key", "secret", "critical", 0.99, _TEXT_REPRESENTATIONS, _TEXT_FORMATS, "provider_shape"),
    _rule("secret.jwt", "secret", "high", 0.95, _TEXT_REPRESENTATIONS, _TEXT_FORMATS, "base64url_json_structure"),
    _rule("secret.credential_assignment", "secret", "high", 0.72, _TEXT_REPRESENTATIONS, _TEXT_FORMATS, "assignment_context_and_placeholder_filter"),
    _rule("privacy.windows_user_path", "path_disclosure", "medium", 0.95, _TEXT_REPRESENTATIONS, _TEXT_FORMATS, "windows_home_path_shape"),
    _rule("privacy.unix_user_path", "path_disclosure", "medium", 0.95, _TEXT_REPRESENTATIONS, _TEXT_FORMATS, "unix_home_path_shape"),
    _rule("unicode.bidi_control", "unicode_control", "high", 0.98, _TEXT_REPRESENTATIONS, _TEXT_FORMATS, "unicode_codepoint_set"),
    _rule("unicode.zero_width", "unicode_control", "medium", 0.75, _TEXT_REPRESENTATIONS, _TEXT_FORMATS, "unicode_codepoint_set"),
    _rule("SS-GEN-SYMLINK", "filesystem_boundary", "high", 1.0, ("filesystem_entry",), ("filesystem",), "lstat_or_reparse_attribute"),
    _rule("SS-GEN-VCS-METADATA", "repository_history", "high", 1.0, ("filesystem_entry",), ("filesystem",), "exact_sensitive_directory_name"),
    _rule("SS-GEN-TYPE-MISMATCH", "deceptive_file", "high", 0.98, ("magic_bytes", "extension"), ("binary",), "magic_extension_consistency"),
    _rule("SS-GEN-SENSITIVE-FILENAME", "sensitive_file", "high", 0.95, ("filename",), ("filesystem", "archive"), "sensitive_name_pattern"),
    _rule("SS-GEN-PII-FILENAME", "identity_in_filename", "high", 0.98, ("filename",), ("filesystem", "archive"), "text_detector_in_name"),
    _rule("SS-GEN-EXECUTABLE", "active_content", "high", 1.0, ("magic_bytes", "extension"), ("binary",), "executable_magic_or_extension"),
    _rule("SS-ARCHIVE-COMMENT", "identity_metadata", "low", 0.9, ("zip_comment",), ("zip",), "presence"),
    _rule("SS-ARCHIVE-PATH-TRAVERSAL", "archive_structure", "critical", 1.0, ("archive_member_name",), ("zip", "ooxml"), "normalized_relative_path"),
    _rule("SS-ARCHIVE-DUPLICATE-NAME", "archive_structure", "medium", 1.0, ("archive_member_name",), ("zip",), "casefolded_name_uniqueness"),
    _rule("SS-ARCHIVE-SYMLINK", "filesystem_boundary", "high", 1.0, ("zip_external_attributes",), ("zip",), "unix_mode_bits"),
    _rule("SS-ARCHIVE-ENCRYPTED", "coverage", "high", 1.0, ("zip_flags",), ("zip",), "encryption_flag"),
    _rule("SS-ARCHIVE-ENTRY-METADATA", "timestamp_metadata", "low", 0.95, ("zip_entry_metadata",), ("zip",), "non_normalized_metadata"),
    _rule("SS-OOXML-PACKAGE-COMMENT", "identity_metadata", "medium", 1.0, ("zip_comment",), ("ooxml",), "presence", automatic_remediation=True),
    _rule("SS-OOXML-DUPLICATE-PART", "archive_structure", "high", 1.0, ("ooxml_part_name",), ("ooxml",), "casefolded_name_uniqueness"),
    _rule("SS-OOXML-SYMLINK-PART", "filesystem_boundary", "high", 1.0, ("zip_external_attributes",), ("ooxml",), "unix_mode_bits"),
    _rule("SS-OOXML-PART-COMMENT", "identity_metadata", "medium", 1.0, ("zip_entry_comment",), ("ooxml",), "presence", automatic_remediation=True),
    _rule("SS-OOXML-ENCRYPTED-PART", "coverage", "high", 1.0, ("zip_flags",), ("ooxml",), "encryption_flag"),
    _rule("SS-OOXML-MACRO", "active_content", "high", 1.0, ("package_structure", "content_types"), ("ooxml",), "macro_declaration_or_part"),
    _rule("SS-OOXML-DIGITAL-SIGNATURE", "integrity_control", "high", 1.0, ("package_structure", "relationships"), ("ooxml",), "signature_declaration_or_part"),
    _rule("SS-OOXML-COMMENTS", "hidden_content", "high", 1.0, ("package_part_name",), ("ooxml",), "comment_part_presence"),
    _rule("SS-OOXML-SPEAKER-NOTES", "hidden_content", "high", 1.0, ("package_part_name",), ("pptx", "pptm"), "notes_part_presence"),
    _rule("SS-OOXML-CUSTOM-XML", "hidden_content", "medium", 1.0, ("package_part_name",), ("ooxml",), "custom_xml_part_presence"),
    _rule("SS-OOXML-EMBEDDED-OBJECT", "hidden_content", "high", 1.0, ("package_structure",), ("ooxml",), "embedding_or_activex_declaration"),
    _rule("SS-OOXML-EXTERNAL-RELATIONSHIP", "external_reference", "high", 1.0, ("relationship",), ("ooxml",), "external_target_mode"),
    _rule("SS-OOXML-CUSTOM-PROPERTIES", "identity_metadata", "medium", 1.0, ("custom_properties",), ("ooxml",), "part_presence", automatic_remediation=True),
    _rule("SS-OOXML-TRACKED-CHANGES", "hidden_content", "high", 1.0, ("xml_element",), ("docx", "docm"), "tracked_change_element"),
    _rule("SS-OOXML-HIDDEN-ROWS-COLUMNS", "hidden_content", "high", 1.0, ("xml_attribute",), ("xlsx", "xlsm"), "hidden_attribute"),
    _rule("SS-OOXML-HIDDEN-SHEET", "hidden_content", "high", 1.0, ("xml_attribute",), ("xlsx", "xlsm"), "sheet_state"),
    _rule("SS-OOXML-HIDDEN-SLIDE", "hidden_content", "high", 1.0, ("xml_attribute",), ("pptx", "pptm"), "hidden_attribute"),
    _rule("SS-OOXML-EXTERNAL-DATA", "external_reference", "high", 1.0, ("xml_element",), ("xlsx", "xlsm"), "external_data_element"),
    *tuple(
        _rule(
            f"SS-OOXML-CORE-{rule_suffix}", category, severity, 1.0,
            ("core_properties",), ("ooxml",), "non_empty_property", automatic_remediation=True,
        )
        for rule_suffix, category, severity in (
            ("CREATOR", "identity_metadata", "medium"),
            ("LAST-MODIFIED-BY", "identity_metadata", "medium"),
            ("TITLE", "document_metadata", "low"),
            ("SUBJECT", "document_metadata", "low"),
            ("DESCRIPTION", "document_metadata", "medium"),
            ("KEYWORDS", "document_metadata", "low"),
            ("CATEGORY", "document_metadata", "low"),
            ("IDENTIFIER", "document_metadata", "medium"),
            ("CREATED", "timestamp_metadata", "low"),
            ("MODIFIED", "timestamp_metadata", "low"),
            ("LAST-PRINTED", "timestamp_metadata", "medium"),
            ("REVISION", "document_metadata", "low"),
            ("CONTENT-STATUS", "document_metadata", "low"),
            ("LANGUAGE", "document_metadata", "low"),
            ("VERSION", "document_metadata", "low"),
        )
    ),
    *tuple(
        _rule(
            f"SS-OOXML-APP-{rule_suffix}", category, severity, 1.0,
            ("extended_properties",), ("ooxml",), "non_empty_property", automatic_remediation=True,
        )
        for rule_suffix, category, severity in (
            ("MANAGER", "identity_metadata", "medium"),
            ("COMPANY", "identity_metadata", "medium"),
            ("HYPERLINK-BASE", "path_disclosure", "medium"),
            ("APPLICATION", "software_metadata", "low"),
            ("APPVERSION", "software_metadata", "low"),
            ("TEMPLATE", "software_metadata", "low"),
        )
    ),
    *tuple(
        _rule(
            f"SS-IMAGE-PNG-{suffix}", "image_metadata", severity, 1.0,
            ("png_chunk",), ("png",), "chunk_presence", automatic_remediation=True,
        )
        for suffix, severity in (("EXIF", "medium"), ("TEXT", "medium"), ("ZTXT", "medium"), ("ITXT", "medium"), ("TIME", "low"))
    ),
    *tuple(
        _rule(
            f"SS-IMAGE-JPEG-{suffix}", "image_metadata", "medium", 1.0,
            ("jpeg_segment",), ("jpeg",), "segment_signature", automatic_remediation=True,
        )
        for suffix in ("EXIF", "XMP", "IPTC", "COMMENT")
    ),
    _rule("SS-IMAGE-GPS", "location_metadata", "critical", 1.0, ("decoded_image_metadata",), ("image",), "gps_tag_presence", automatic_remediation=True),
    _rule("SS-IMAGE-IDENTITY-METADATA", "identity_metadata", "high", 1.0, ("decoded_image_metadata",), ("image",), "identity_tag_presence", automatic_remediation=True),
    _rule("SS-IMAGE-DEVICE-METADATA", "device_metadata", "medium", 1.0, ("decoded_image_metadata",), ("image",), "device_tag_presence", automatic_remediation=True),
    *tuple(
        _rule(
            f"SS-PDF-METADATA-{field}", "identity_metadata", "medium" if field in {"AUTHOR", "CREATOR"} else "low", 0.9,
            ("pdf_dictionary",), ("pdf",), "dictionary_key_presence",
        )
        for field in ("AUTHOR", "CREATOR", "PRODUCER", "TITLE", "SUBJECT", "KEYWORDS")
    ),
    _rule("SS-PDF-XMP", "identity_metadata", "medium", 0.95, ("pdf_metadata_stream",), ("pdf",), "xmp_marker"),
    _rule("SS-PDF-ATTACHMENT", "embedded_content", "high", 0.9, ("pdf_object",), ("pdf",), "dictionary_key_presence"),
    _rule("SS-PDF-FILE-SPEC", "embedded_content", "medium", 0.9, ("pdf_object",), ("pdf",), "dictionary_key_presence"),
    _rule("SS-PDF-JAVASCRIPT", "active_content", "high", 0.9, ("pdf_object",), ("pdf",), "dictionary_key_presence"),
    _rule("SS-PDF-OPEN-ACTION", "active_content", "high", 0.9, ("pdf_object",), ("pdf",), "dictionary_key_presence"),
    _rule("SS-PDF-FORM", "hidden_content", "medium", 0.9, ("pdf_object",), ("pdf",), "dictionary_key_presence"),
    _rule("SS-PDF-ANNOTATION", "hidden_content", "medium", 0.9, ("pdf_object",), ("pdf",), "dictionary_key_presence"),
    _rule("SS-PDF-REDACTION-ANNOTATION", "redaction_risk", "high", 0.95, ("pdf_annotation",), ("pdf",), "redact_subtype"),
    _rule("SS-PDF-ENCRYPTED", "coverage", "high", 1.0, ("pdf_trailer",), ("pdf",), "encryption_dictionary"),
)


def exact_rule_catalog() -> list[dict[str, Any]]:
    """Return defensive copies ordered by exact rule identifier."""

    return [
        {
            **item,
            "representations": list(item["representations"]),
            "formats": list(item["formats"]),
        }
        for item in sorted(RULE_DETAILS, key=lambda item: item["rule_id"])
    ]


__all__ = ["FORMATS", "RULESET_VERSION", "RULE_DETAILS", "RULE_GROUPS", "exact_rule_catalog"]
