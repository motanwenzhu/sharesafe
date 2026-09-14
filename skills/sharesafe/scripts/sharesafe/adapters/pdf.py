"""Conservative PDF structure and optional text inspection."""

from __future__ import annotations

import io
import re
from typing import TYPE_CHECKING

from .text import scan_text

if TYPE_CHECKING:
    from ..engine import Scanner
    from ..models import Artifact, ReportBuilder


_METADATA_FIELDS = (b"/Author", b"/Creator", b"/Producer", b"/Title", b"/Subject", b"/Keywords")
_STRUCTURAL_RULES: tuple[tuple[bytes, str, str, str, str], ...] = (
    (b"/EmbeddedFiles", "SS-PDF-ATTACHMENT", "embedded_content", "high", "PDF contains embedded files"),
    (b"/Filespec", "SS-PDF-FILE-SPEC", "embedded_content", "medium", "PDF contains file-specification objects"),
    (b"/JavaScript", "SS-PDF-JAVASCRIPT", "active_content", "high", "PDF contains JavaScript"),
    (b"/OpenAction", "SS-PDF-OPEN-ACTION", "active_content", "high", "PDF contains an automatic open action"),
    (b"/AcroForm", "SS-PDF-FORM", "hidden_content", "medium", "PDF contains an interactive form"),
    (b"/Annots", "SS-PDF-ANNOTATION", "hidden_content", "medium", "PDF contains annotations or comments"),
)


def _pdf_token_present(data: bytes, token: bytes) -> bool:
    return re.search(re.escape(token) + rb"(?=[\s/<\[(])", data) is not None


def scan_pdf(
    scanner: "Scanner",
    data: bytes,
    artifact: "Artifact",
    builder: "ReportBuilder",
) -> None:
    artifact.set_coverage("metadata", "partial")
    artifact.set_coverage("text", "partial")
    artifact.set_coverage("hidden_content", "partial")
    artifact.set_coverage("embedded_objects", "partial")
    artifact.set_coverage("ocr", "not_applicable")

    for field in _METADATA_FIELDS:
        if _pdf_token_present(data, field):
            name = field[1:].decode("ascii")
            builder.add_finding(
                artifact,
                rule_id=f"SS-PDF-METADATA-{name.upper()}",
                category="identity_metadata",
                severity="medium" if name in {"Author", "Creator"} else "low",
                confidence=0.9,
                title=f"PDF {name.casefold()} metadata field is present",
                location={"kind": "pdf_dictionary", "field": name},
                evidence={"mode": "omitted", "value_class": "pdf_metadata"},
                remediation_supported=False,
                remediation_action="use_specialized_pdf_tool_on_a_copy",
            )
    if b"<x:xmpmeta" in data.lower() or b"<?xpacket" in data.lower():
        builder.add_finding(
            artifact,
            rule_id="SS-PDF-XMP",
            category="identity_metadata",
            severity="medium",
            confidence=0.95,
            title="PDF contains XMP metadata",
            location={"kind": "pdf_metadata", "field": "XMP"},
            remediation_supported=False,
            remediation_action="use_specialized_pdf_tool_on_a_copy",
        )

    for token, rule_id, category, severity, title in _STRUCTURAL_RULES:
        if _pdf_token_present(data, token):
            builder.add_finding(
                artifact,
                rule_id=rule_id,
                category=category,
                severity=severity,
                confidence=0.9,
                title=title,
                location={"kind": "pdf_structure"},
                remediation_action="review_pdf_structure_with_a_specialized_tool",
            )
    if re.search(rb"/Subtype\s*/Redact\b", data):
        builder.add_finding(
            artifact,
            rule_id="SS-PDF-REDACTION-ANNOTATION",
            category="redaction_risk",
            severity="high",
            confidence=0.95,
            title="PDF contains redaction annotations; confirm redactions were applied",
            location={"kind": "pdf_structure"},
            remediation_action="apply_and_verify_redactions_with_a_specialized_pdf_tool",
        )
    builder.add_gap(
        artifact,
        "structure",
        "pdf_deep_validation_partial",
        "Incremental revisions and every possible attachment or action are not exhaustively validated in v0.1.",
    )
    if _pdf_token_present(data, b"/Encrypt"):
        builder.add_finding(
            artifact,
            rule_id="SS-PDF-ENCRYPTED",
            category="coverage",
            severity="high",
            confidence=1.0,
            title="Encrypted PDF content cannot be fully inspected",
            location={"kind": "pdf_trailer"},
            remediation_action="provide_an_unencrypted_review_copy",
        )
        builder.add_gap(artifact, "content", "encrypted_pdf", "Encrypted PDF was not decrypted or text-scanned.")
        return

    _scan_with_pypdf(scanner, data, artifact, builder)


def _scan_with_pypdf(
    scanner: "Scanner",
    data: bytes,
    artifact: "Artifact",
    builder: "ReportBuilder",
) -> None:
    if not scanner.config.optional_tools:
        builder.add_dependency("pypdf", False, None, "pdf_text_and_structure")
        builder.add_gap(artifact, "text", "optional_dependency_disabled", "pypdf is disabled; PDF text was not extracted.")
        return
    try:
        import pypdf
        from pypdf import PdfReader
    except ImportError:
        builder.add_dependency("pypdf", False, None, "pdf_text_and_structure")
        builder.add_gap(artifact, "text", "optional_dependency_missing", "Install the pdf extra to extract and inspect PDF text.")
        return

    builder.add_dependency("pypdf", True, getattr(pypdf, "__version__", None), "pdf_text_and_structure")
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
    except Exception as exc:  # pypdf exposes parser-specific exceptions across versions.
        builder.add_gap(artifact, "structure", "pdf_parser_error", f"pypdf could not parse this PDF ({exc.__class__.__name__}).")
        return
    if reader.is_encrypted:
        builder.add_gap(artifact, "content", "encrypted_pdf", "pypdf reports that the PDF is encrypted.")
        return
    if len(reader.pages) > scanner.config.limits.max_pdf_pages:
        builder.add_gap(artifact, "text", "pdf_page_limit", "PDF has more pages than the configured maximum.")
        pages = list(reader.pages[: scanner.config.limits.max_pdf_pages])
    else:
        pages = list(reader.pages)

    empty_image_pages = 0
    for index, page in enumerate(pages, start=1):
        try:
            text = page.extract_text() or ""
        except Exception as exc:
            builder.add_gap(artifact, "text", "pdf_text_error", f"A PDF page could not be extracted ({exc.__class__.__name__}).")
            continue
        if text:
            scan_text(
                text.encode("utf-8"), artifact, builder,
                evidence_key=scanner.evidence_key, part=f"PDF/page-{index}",
            )
        else:
            try:
                resources = page.get("/Resources") or {}
                if resources.get("/XObject"):
                    empty_image_pages += 1
            except Exception:
                builder.add_gap(artifact, "structure", "pdf_resource_error", "PDF page resources could not be inspected.")
    if empty_image_pages:
        artifact.set_coverage("ocr", "unsupported")
        builder.add_gap(
            artifact,
            "ocr",
            "ocr_not_available",
            "One or more image-only PDF pages were not checked with OCR.",
        )
    else:
        artifact.set_coverage("ocr", "not_applicable")

    artifact.set_coverage("metadata", "complete")
    artifact.set_coverage("text", "complete")
    artifact.set_coverage("hidden_content", "complete")
    artifact.set_coverage("embedded_objects", "complete")
