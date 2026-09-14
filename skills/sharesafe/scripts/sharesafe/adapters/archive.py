"""Safe, bounded ZIP inventory and recursive scanning."""

from __future__ import annotations

import io
from pathlib import PurePosixPath
import re
import stat
import zipfile
from typing import TYPE_CHECKING

from .text import scan_text
from ..zip_safety import preflight_zip

if TYPE_CHECKING:
    from ..engine import Scanner
    from ..models import Artifact, ReportBuilder


_DRIVE_PATH = re.compile(r"^[A-Za-z]:[/\\]")


def _unsafe_member_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    if not normalized or "\x00" in normalized or normalized.startswith("/") or _DRIVE_PATH.match(name):
        return True
    return any(part == ".." for part in PurePosixPath(normalized).parts)


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def _bounded_read(handle: zipfile.ZipExtFile, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining > 0:
        chunk = handle.read(min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def scan_zip(
    scanner: "Scanner",
    data: bytes,
    display_path: str,
    artifact: "Artifact",
    builder: "ReportBuilder",
    *,
    depth: int,
) -> None:
    limits = scanner.config.limits
    artifact.set_coverage("metadata", "complete")
    artifact.set_coverage("embedded_objects", "complete")
    if depth >= limits.max_archive_depth:
        builder.add_gap(
            artifact,
            "embedded_objects",
            "archive_depth_limit",
            "Nested archive depth reached the configured maximum.",
        )
        return

    preflight = preflight_zip(data, limits.max_archive_entries)
    if preflight.status == "entry_limit":
        builder.add_gap(
            artifact,
            "embedded_objects",
            "archive_entry_limit",
            "Archive has more entries than the configured maximum; no entries were materialized.",
        )
        return
    if preflight.status == "malformed":
        builder.add_gap(artifact, "embedded_objects", "malformed_archive", "ZIP central directory could not be validated.")
        return

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except (zipfile.BadZipFile, OSError, ValueError):
        builder.add_gap(artifact, "embedded_objects", "malformed_archive", "ZIP central directory could not be parsed.")
        return

    with archive:
        comment_bytes = 0

        def scan_comment(payload: bytes, part: str) -> None:
            nonlocal comment_bytes
            if comment_bytes + len(payload) > limits.max_text_bytes:
                builder.add_gap(
                    artifact,
                    "text",
                    "archive_comment_text_limit",
                    "Archive comment text exceeds the configured cumulative scan limit.",
                )
                return
            comment_bytes += len(payload)
            scan_text(payload, artifact, builder, evidence_key=scanner.evidence_key, part=part)

        if archive.comment:
            builder.add_finding(
                artifact,
                rule_id="SS-ARCHIVE-COMMENT",
                category="identity_metadata",
                severity="low",
                confidence=0.9,
                title="ZIP archive comment is present",
                location={"kind": "archive_metadata"},
                remediation_action="remove_archive_comment",
            )
            scan_comment(archive.comment, "ZIP/archive-comment")

        if len(infos) > limits.max_archive_entries:
            builder.add_gap(
                artifact,
                "embedded_objects",
                "archive_entry_limit",
                "Archive has more entries than the configured maximum; remaining entries were not read.",
            )
            infos = infos[: limits.max_archive_entries]

        names_seen: dict[str, int] = {}
        expanded = 0
        timestamp_metadata = False

        for index, info in enumerate(infos):
            raw_name = info.filename
            canonical_name = raw_name.replace("\\", "/")
            names_seen[canonical_name] = names_seen.get(canonical_name, 0) + 1
            occurrence = names_seen[canonical_name]

            if info.date_time not in {(1980, 1, 1, 0, 0, 0), (2000, 1, 1, 0, 0, 0)} or info.extra or info.comment:
                timestamp_metadata = True
            if info.comment:
                scan_comment(info.comment, f"ZIP/member-comment/{index}")

            if _unsafe_member_name(raw_name):
                builder.add_finding(
                    artifact,
                    rule_id="SS-ARCHIVE-PATH-TRAVERSAL",
                    category="archive_structure",
                    severity="critical",
                    confidence=1.0,
                    title="Archive member uses an unsafe path",
                    location={"kind": "archive_member", "index": index},
                    remediation_action="rebuild_archive_with_safe_relative_names",
                )
                builder.add_gap(artifact, "embedded_objects", "unsafe_member_name", "Unsafe archive member was not opened.")
                continue

            if occurrence > 1:
                builder.add_finding(
                    artifact,
                    rule_id="SS-ARCHIVE-DUPLICATE-NAME",
                    category="archive_structure",
                    severity="medium",
                    confidence=1.0,
                    title="Archive contains duplicate member names",
                    location={"kind": "archive_member", "occurrence": occurrence},
                    remediation_action="rebuild_archive_without_duplicate_names",
                )

            if info.is_dir():
                scanner.scan_virtual_directory(f"{display_path}!/{canonical_name}", builder)
                continue
            if _is_symlink(info):
                builder.add_finding(
                    artifact,
                    rule_id="SS-ARCHIVE-SYMLINK",
                    category="filesystem_boundary",
                    severity="high",
                    confidence=1.0,
                    title="Archive contains a symbolic-link entry",
                    location={"kind": "archive_member", "index": index},
                    remediation_action="remove_or_materialize_link_after_manual_review",
                )
                builder.add_gap(artifact, "embedded_objects", "archive_link_not_followed", "Archive symlink payload was not scanned.")
                continue
            if info.flag_bits & 0x1:
                builder.add_finding(
                    artifact,
                    rule_id="SS-ARCHIVE-ENCRYPTED",
                    category="coverage",
                    severity="high",
                    confidence=1.0,
                    title="Encrypted archive member cannot be inspected",
                    location={"kind": "archive_member", "index": index},
                    remediation_action="provide_an_unencrypted_review_copy",
                )
                builder.add_gap(artifact, "embedded_objects", "encrypted_member", "Encrypted member content was not scanned.")
                continue
            if info.file_size > limits.max_archive_member_bytes:
                builder.add_gap(
                    artifact,
                    "embedded_objects",
                    "archive_member_size_limit",
                    "Archive member exceeds the configured expanded-size limit.",
                )
                continue
            ratio = info.file_size / max(1, info.compress_size)
            if info.file_size > 1024 * 1024 and ratio > limits.max_compression_ratio:
                builder.add_gap(
                    artifact,
                    "embedded_objects",
                    "compression_ratio_limit",
                    "Archive member exceeds the configured compression-ratio limit.",
                )
                continue
            if expanded + info.file_size > limits.max_expanded_bytes or not scanner.claim_archive_bytes(info.file_size):
                builder.add_gap(
                    artifact,
                    "embedded_objects",
                    "expanded_byte_limit",
                    "Archive expansion budget was exhausted; remaining content was not scanned.",
                )
                break

            try:
                with archive.open(info, "r") as handle:
                    member_data = _bounded_read(handle, min(limits.max_archive_member_bytes, info.file_size))
            except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile, EOFError):
                builder.add_gap(artifact, "embedded_objects", "archive_member_read_error", "Archive member could not be decompressed.")
                continue

            if len(member_data) > limits.max_archive_member_bytes or len(member_data) != info.file_size:
                builder.add_gap(
                    artifact,
                    "embedded_objects",
                    "archive_member_size_mismatch",
                    "Archive member size did not match its bounded declaration.",
                )
                continue
            expanded += len(member_data)
            suffix = f" [duplicate {occurrence}]" if occurrence > 1 else ""
            virtual_path = f"{display_path}!/{canonical_name}{suffix}"
            scanner.scan_bytes(member_data, virtual_path, builder, depth=depth + 1)

        if timestamp_metadata:
            builder.add_finding(
                artifact,
                rule_id="SS-ARCHIVE-ENTRY-METADATA",
                category="timestamp_metadata",
                severity="low",
                confidence=0.95,
                title="Archive entries retain timestamps or auxiliary metadata",
                location={"kind": "archive_metadata"},
                remediation_action="rebuild_archive_with_normalized_entry_metadata",
            )
