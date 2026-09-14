"""Bounded, local-only scan orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import stat
from typing import Iterable

from .adapters.text import scan_text
from .detectors import detect_text, hit_to_dict, sanitize_display_path, temporary_hmac_key
from .limits import Limits
from .models import Artifact, ReportBuilder
from .redaction import (
    content_hmac_token,
    contextual_relative_path,
    user_home_container_context,
)
from .sniff import MediaInfo, sniff, suspicious_extension


SENSITIVE_FILE_NAMES = {
    ".env", ".npmrc", ".pypirc", ".netrc", "credentials", "credentials.json",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "secrets.yml", "secrets.yaml",
    "service-account.json", "key.pem", "private.pem",
}
VCS_DIRECTORIES = {".git", ".hg", ".svn"}


@dataclass(frozen=True, slots=True)
class ScanConfig:
    limits: Limits = field(default_factory=Limits)
    report_mode: str = "shareable"
    optional_tools: bool = True
    logical_paths: bool = False


class Scanner:
    def __init__(
        self,
        config: ScanConfig | None = None,
        *,
        evidence_key: bytes | None = None,
        root_directory_context: str | None = None,
    ) -> None:
        self.config = config or ScanConfig()
        self.evidence_key = evidence_key or temporary_hmac_key()
        self.root_directory_context = root_directory_context
        self._files_seen = 0
        self._filesystem_bytes = 0
        self._filesystem_entries_seen = 0
        self._archive_expanded_bytes = 0
        self._filesystem_limit_exhausted = False

    def scan(self, paths: Iterable[str | os.PathLike[str]]) -> ReportBuilder:
        self._files_seen = 0
        self._filesystem_bytes = 0
        self._filesystem_entries_seen = 0
        self._archive_expanded_bytes = 0
        self._filesystem_limit_exhausted = False
        requested = [Path(path) for path in paths]
        if not requested:
            raise ValueError("at least one path is required")
        builder = ReportBuilder(limits=self.config.limits, report_mode=self.config.report_mode)
        multiple = len(requested) > 1

        for path in requested:
            try:
                absolute = path.absolute()
                status = absolute.lstat()
            except OSError as exc:
                builder.add_error("path_unavailable", f"A requested path is unavailable ({exc.__class__.__name__}).")
                continue

            raw_label = path.name or "root"
            if stat.S_ISDIR(status.st_mode):
                root_label, root_scan_path = self._root_directory_name(path, absolute)
            else:
                root_label, root_scan_path = raw_label, raw_label
            label = "artifact" if self.config.logical_paths else root_label
            if multiple and not self.config.logical_paths:
                label = root_label
            if self._is_link_or_reparse(absolute, status):
                self._record_link(absolute, sanitize_display_path(label), builder)
            elif stat.S_ISDIR(status.st_mode):
                if absolute.name.casefold() in VCS_DIRECTORIES:
                    self._record_vcs_directory(sanitize_display_path(label), builder)
                else:
                    directory_context = (
                        self.root_directory_context
                        if not multiple and self.root_directory_context is not None
                        else user_home_container_context(absolute.name)
                    )
                    self._record_directory(label, root_scan_path, builder, count_toward_limit=False)
                    self._walk_directory(
                        absolute,
                        "" if not multiple else label,
                        builder,
                        filesystem_depth=0,
                        root_call=True,
                        scan_context_prefix=directory_context,
                    )
            elif stat.S_ISREG(status.st_mode):
                self._scan_file(absolute, label, builder, depth=0)
            else:
                artifact = builder.add_artifact(
                    path=sanitize_display_path(label), content_token=None, size=getattr(status, "st_size", None),
                    media_type="application/octet-stream", status="partial",
                )
                builder.add_gap(artifact, "content", "special_file", "Special filesystem objects are not opened.")
        return builder

    @staticmethod
    def _root_directory_name(requested: Path, absolute: Path) -> tuple[str, str]:
        """Retain an ordinary basename without exposing a selected home username."""

        name = requested.name or absolute.name or "root"
        parent = absolute.parent.name
        folded_parent = parent.casefold()
        if folded_parent in {"users", "home", "documents and settings"}:
            scan_path = (
                f"C:/Documents and Settings/{name}"
                if folded_parent == "documents and settings"
                else f"/{parent}/{name}"
            )
            return "<user>", scan_path
        if name.casefold() == "root" and absolute.parent == Path(absolute.anchor):
            return "<user>", "/root/private"
        return sanitize_display_path(name), name

    @staticmethod
    def _is_link_or_reparse(path: Path, status: os.stat_result) -> bool:
        if stat.S_ISLNK(status.st_mode):
            return True
        attributes = getattr(status, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return bool(attributes & reparse)

    def _record_link(self, path: Path, display_path: str, builder: ReportBuilder) -> None:
        artifact = builder.add_artifact(
            path=display_path, content_token=None, size=None, media_type="inode/symlink", status="partial",
        )
        builder.add_finding(
            artifact,
            rule_id="SS-GEN-SYMLINK",
            category="filesystem_boundary",
            severity="high",
            confidence=1.0,
            title="Symbolic link or reparse point is not followed",
            remediation_action="replace_link_with_reviewed_regular_file_or_remove",
        )
        builder.add_gap(artifact, "content", "link_not_followed", "Link targets are outside the trusted scan boundary.")

    def _record_vcs_directory(self, display_path: str, builder: ReportBuilder) -> None:
        artifact = builder.add_artifact(
            path=sanitize_display_path(display_path), content_token=None, size=None, media_type="inode/directory",
        )
        builder.add_finding(
            artifact,
            rule_id="SS-GEN-VCS-METADATA",
            category="repository_history",
            severity="high",
            confidence=1.0,
            title="Version-control metadata is included in the share boundary",
            remediation_supported=False,
            remediation_action="omit_version_control_metadata_from_share_copy",
        )
        builder.add_gap(
            artifact,
            "content",
            "vcs_history_not_scanned",
            "Repository history was intentionally not traversed; remove it from the share boundary.",
        )

    def _record_directory(
        self,
        display_path: str,
        scan_path: str,
        builder: ReportBuilder,
        *,
        count_toward_limit: bool,
    ) -> Artifact:
        if count_toward_limit:
            self._files_seen += 1
        partial = count_toward_limit and self._files_seen > self.config.limits.max_files
        artifact = builder.add_artifact(
            path=sanitize_display_path(display_path),
            content_token=None,
            size=None,
            media_type="inode/directory",
            status="partial" if partial else "scanned",
        )
        self._scan_filename(scan_path, artifact, builder)
        if partial:
            self._filesystem_limit_exhausted = True
            builder.add_gap(
                artifact,
                "content",
                "file_count_limit",
                "Scan boundary contains more filesystem entries than the configured maximum.",
            )
        return artifact

    def scan_virtual_directory(
        self,
        display_path: str,
        builder: ReportBuilder,
    ) -> Artifact:
        """Add an already-bounded container directory to the report inventory."""

        raw_path = display_path.replace("\\", "/").rstrip("/")
        return self._record_directory(raw_path, raw_path, builder, count_toward_limit=False)

    def _walk_directory(
        self,
        root: Path,
        prefix: str,
        builder: ReportBuilder,
        *,
        filesystem_depth: int,
        root_call: bool = False,
        scan_context_prefix: str | None = None,
    ) -> None:
        if filesystem_depth > self.config.limits.max_directory_depth:
            artifact = builder.add_artifact(
                path=sanitize_display_path(prefix or root.name), content_token=None, size=None,
                media_type="inode/directory", status="partial",
            )
            builder.add_gap(artifact, "content", "directory_depth_limit", "Directory nesting exceeds the configured maximum.")
            return
        try:
            entries = []
            with os.scandir(root) as iterator:
                for entry in iterator:
                    self._filesystem_entries_seen += 1
                    if self._filesystem_entries_seen > self.config.limits.max_files:
                        self._filesystem_limit_exhausted = True
                        builder.add_gap(
                            None,
                            "content",
                            "file_count_limit",
                            "Scan boundary contains more filesystem entries than the configured maximum.",
                        )
                        return
                    entries.append(entry)
            entries.sort(key=lambda entry: entry.name.casefold())
        except OSError as exc:
            builder.add_error("directory_unreadable", f"A directory could not be enumerated ({exc.__class__.__name__}).")
            return

        if not entries and not root_call:
            raw_relative = prefix or root.name
            display, scan_path = contextual_relative_path(raw_relative, scan_context_prefix)
            self._record_directory(display, scan_path, builder, count_toward_limit=True)
            return

        for entry in entries:
            if self._filesystem_limit_exhausted:
                break
            raw_relative = f"{prefix}/{entry.name}" if prefix else entry.name
            display, scan_path = contextual_relative_path(raw_relative, scan_context_prefix)
            try:
                status = entry.stat(follow_symlinks=False)
                entry_path = Path(entry.path)
                if self._is_link_or_reparse(entry_path, status):
                    self._record_link(entry_path, display, builder)
                    continue
                if stat.S_ISDIR(status.st_mode):
                    if entry.name.casefold() in VCS_DIRECTORIES:
                        self._record_vcs_directory(display, builder)
                        continue
                    self._walk_directory(
                        entry_path, raw_relative.replace("\\", "/"), builder,
                        filesystem_depth=filesystem_depth + 1,
                        scan_context_prefix=scan_context_prefix,
                    )
                elif stat.S_ISREG(status.st_mode):
                    self._scan_file(
                        entry_path,
                        display,
                        builder,
                        depth=0,
                        filename_scan_path=scan_path,
                    )
                else:
                    artifact = builder.add_artifact(
                        path=display, content_token=None, size=status.st_size,
                        media_type="application/octet-stream", status="partial",
                    )
                    builder.add_gap(artifact, "content", "special_file", "Special filesystem objects are not opened.")
            except OSError as exc:
                builder.add_error("entry_unreadable", f"A directory entry could not be inspected ({exc.__class__.__name__}).")

    def _scan_file(
        self,
        path: Path,
        display_path: str,
        builder: ReportBuilder,
        *,
        depth: int,
        filename_scan_path: str | None = None,
    ) -> Artifact:
        try:
            before = path.stat(follow_symlinks=False)
            self._files_seen += 1
            self._filesystem_bytes += before.st_size
            if self._files_seen > self.config.limits.max_files:
                self._filesystem_limit_exhausted = True
                artifact = builder.add_artifact(
                    path=sanitize_display_path(display_path), content_token=None, size=before.st_size,
                    media_type="application/octet-stream", status="partial",
                )
                builder.add_gap(artifact, "content", "file_count_limit", "Scan boundary contains more files than the configured maximum.")
                return artifact
            if self._filesystem_bytes > self.config.limits.max_total_file_bytes:
                self._filesystem_limit_exhausted = True
                artifact = builder.add_artifact(
                    path=sanitize_display_path(display_path), content_token=None, size=before.st_size,
                    media_type="application/octet-stream", status="partial",
                )
                builder.add_gap(artifact, "content", "total_file_byte_limit", "Scan boundary exceeds the configured total-byte budget.")
                return artifact
            if before.st_size > self.config.limits.max_file_bytes:
                artifact = builder.add_artifact(
                    path=sanitize_display_path(display_path), content_token=None, size=before.st_size,
                    media_type="application/octet-stream", status="partial",
                )
                builder.add_gap(
                    artifact, "content", "file_size_limit",
                    "File exceeds the configured byte limit and was not read.",
                )
                return artifact
            with path.open("rb") as handle:
                opened = os.fstat(handle.fileno())
                data = handle.read(self.config.limits.max_file_bytes + 1)
            after = path.stat(follow_symlinks=False)
        except OSError as exc:
            artifact = builder.add_artifact(
                path=sanitize_display_path(display_path), content_token=None, size=None,
                media_type="application/octet-stream", status="partial",
            )
            builder.add_gap(artifact, "content", "read_error", f"File could not be read ({exc.__class__.__name__}).")
            return artifact

        if len(data) > self.config.limits.max_file_bytes:
            artifact = builder.add_artifact(
                path=sanitize_display_path(display_path), content_token=None, size=before.st_size,
                media_type="application/octet-stream", status="partial",
            )
            builder.add_gap(artifact, "content", "file_size_limit", "File grew beyond the byte limit while reading.")
            return artifact

        artifact = self.scan_bytes(
            data,
            display_path,
            builder,
            depth=depth,
            sniff_path=path.name,
            filename_scan_path=(
                filename_scan_path
                if filename_scan_path is not None
                else (path.name if self.config.logical_paths else display_path)
            ),
        )
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_opened = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_opened or identity_opened != identity_after:
            builder.add_gap(artifact, "content", "file_changed_during_scan", "File identity or metadata changed while it was being scanned.")
        return artifact

    def claim_archive_bytes(self, size: int) -> bool:
        """Reserve global decompression budget across all nesting levels."""

        if size < 0 or self._archive_expanded_bytes + size > self.config.limits.max_expanded_bytes:
            return False
        self._archive_expanded_bytes += size
        return True

    def scan_bytes(
        self,
        data: bytes,
        display_path: str,
        builder: ReportBuilder,
        *,
        depth: int,
        sniff_path: str | None = None,
        filename_scan_path: str | None = None,
    ) -> Artifact:
        raw_display_path = display_path.replace("\\", "/")
        display_path = sanitize_display_path(raw_display_path)
        raw_sniff_path = (sniff_path or raw_display_path).replace("\\", "/")
        media = sniff(data, raw_sniff_path)
        token = content_hmac_token(data, self.evidence_key)
        artifact = builder.add_artifact(
            path=display_path,
            content_token=token,
            size=len(data),
            media_type=media.media_type,
        )
        self._scan_filename(filename_scan_path or raw_display_path, artifact, builder)
        if suspicious_extension(raw_sniff_path, media):
            builder.add_finding(
                artifact,
                rule_id="SS-GEN-TYPE-MISMATCH",
                category="deceptive_file",
                severity="high",
                confidence=0.98,
                title="File extension does not match detected content",
                remediation_action="verify_the_file_type_and_source",
            )
        self._dispatch(data, display_path, raw_sniff_path, media, artifact, builder, depth)
        return artifact

    def scan_container_name(
        self,
        raw_name: str,
        artifact: Artifact,
        builder: ReportBuilder,
    ) -> None:
        """Run filename detectors for a container entry already represented by its parent."""

        normalized = raw_name.replace("\\", "/")
        self._scan_filename(
            normalized,
            artifact,
            builder,
            location={"kind": "container_part_name", "part": sanitize_display_path(normalized)},
        )

    def _scan_filename(
        self,
        raw_display_path: str,
        artifact: Artifact,
        builder: ReportBuilder,
        *,
        location: dict[str, object] | None = None,
    ) -> None:
        finding_location = location or {"kind": "filename"}
        name = raw_display_path.rsplit("/", 1)[-1].casefold()
        if name in SENSITIVE_FILE_NAMES or name.startswith(".env.") or name.endswith((".pem", ".key", ".p12", ".pfx")):
            builder.add_finding(
                artifact,
                rule_id="SS-GEN-SENSITIVE-FILENAME",
                category="sensitive_file",
                severity="high",
                confidence=0.95,
                title="Filename commonly indicates credentials or private key material",
                location=finding_location,
                remediation_supported=False,
                remediation_action="omit_file_from_share_copy",
            )

        for hit in detect_text(raw_display_path):
            if hit.category == "pii":
                builder.add_finding(
                    artifact,
                    rule_id="SS-GEN-PII-FILENAME",
                    category="identity_in_filename",
                    severity="high",
                    confidence=hit.confidence,
                    title="Filename appears to contain personal information",
                    location=finding_location,
                    evidence=hit_to_dict(hit, raw_display_path, self.evidence_key),
                    remediation_action="rename_file_in_share_copy",
                )
            else:
                builder.add_finding(
                    artifact,
                    rule_id=hit.rule_id,
                    category=hit.category,
                    severity=hit.severity,
                    confidence=hit.confidence,
                    title=f"{hit.title} in filename",
                    location=finding_location,
                    evidence=hit_to_dict(hit, raw_display_path, self.evidence_key),
                    remediation_action="rename_file_in_share_copy",
                )

    def _dispatch(
        self,
        data: bytes,
        display_path: str,
        sniff_path: str,
        media: MediaInfo,
        artifact: Artifact,
        builder: ReportBuilder,
        depth: int,
    ) -> None:
        if media.kind == "text":
            if len(data) > self.config.limits.max_text_bytes:
                builder.add_gap(artifact, "text", "text_size_limit", "Text exceeds the configured scan limit.")
            else:
                scan_text(data, artifact, builder, evidence_key=self.evidence_key)
            return

        if media.kind == "ooxml":
            from .adapters.ooxml import scan_ooxml
            scan_ooxml(self, data, display_path, sniff_path, artifact, builder, depth=depth)
            return
        if media.kind == "zip":
            from .adapters.archive import scan_zip
            scan_zip(self, data, display_path, artifact, builder, depth=depth)
            return
        if media.kind == "pdf":
            from .adapters.pdf import scan_pdf
            scan_pdf(self, data, artifact, builder)
            return
        if media.kind in {"png", "jpeg", "tiff", "webp"}:
            from .adapters.image import scan_image
            scan_image(self, data, media.kind, artifact, builder)
            return

        artifact.set_coverage("metadata", "unsupported")
        artifact.set_coverage("text", "unsupported")
        if media.kind == "executable":
            builder.add_finding(
                artifact,
                rule_id="SS-GEN-EXECUTABLE",
                category="active_content",
                severity="high",
                confidence=1.0,
                title="Executable content is present in the share boundary",
                remediation_action="remove_unless_explicitly_intended",
            )
        builder.add_gap(artifact, "content", "unsupported_format", "This binary format has no complete v0.1 parser.")
