"""Stable public capability catalog."""

from __future__ import annotations


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
    {"format": "PDF", "extensions": ["pdf"], "scan": "basic structure; optional pypdf text", "sanitize": "not rewritten in v0.1"},
    {"format": "PNG", "extensions": ["png"], "scan": "chunks plus optional Pillow tags; no OCR", "sanitize": "allowlisted metadata chunks removed when orientation permits"},
    {"format": "JPEG", "extensions": ["jpg", "jpeg"], "scan": "segments plus optional Pillow EXIF; no OCR", "sanitize": "metadata segments removed when orientation is neutral"},
    {"format": "TIFF/WebP", "extensions": ["tif", "tiff", "webp"], "scan": "optional Pillow metadata; no OCR", "sanitize": "copied unchanged"},
    {"format": "other binary", "extensions": [], "scan": "unsupported gap", "sanitize": "copied unchanged; verification incomplete"},
)
