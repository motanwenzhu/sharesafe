"""Fail-closed creation of metadata-reduced copies."""

from __future__ import annotations

import errno
import io
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import struct
import tempfile
from typing import Any, Mapping
from urllib.parse import unquote, urlsplit
import zipfile
import xml.etree.ElementTree as ET
import zlib

from .detectors import sanitize_display_path
from .limits import Limits
from .ooxml_xml import (
    declares_digital_signature,
    declares_embedded_object,
    declares_macros,
    local_name,
    parse_xml,
)
from .path_safety import same_or_within, uses_windows_alternate_stream
from .receipts import SanitizationActions, new_sanitization_actions
from .redaction import contextual_relative_path, user_home_container_context
from .safe_io import (
    FileIdentityChangedError,
    prepare_verified_parent,
    open_verified_binary,
    verify_directory_unchanged,
    verify_open_file_unchanged,
)
from .sniff import sniff
from .zip_safety import preflight_zip


NORMALIZED_TIME = 946684800  # 2000-01-01T00:00:00Z
NORMALIZED_ZIP_TIME = (2000, 1, 1, 0, 0, 0)
_OLE_COMPOUND_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


class UnsafeSanitizeRequest(ValueError):
    """Raised before any destination is committed."""


def create_sanitized_copy(
    source: Path,
    destination: Path,
    limits: Limits,
    *,
    evidence_key: bytes | None = None,
    before_report: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    source = source.absolute()
    destination = destination.absolute()
    if uses_windows_alternate_stream(source) or uses_windows_alternate_stream(destination):
        raise UnsafeSanitizeRequest("Windows alternate data stream paths are not supported")
    if not source.exists():
        raise UnsafeSanitizeRequest("source does not exist")
    if destination.exists() or destination.is_symlink():
        raise UnsafeSanitizeRequest("destination already exists; ShareSafe never overwrites")
    if os.path.normcase(str(source)) == os.path.normcase(str(destination)):
        raise UnsafeSanitizeRequest("source and destination must differ")
    if source.is_dir() and _is_within(destination, source):
        raise UnsafeSanitizeRequest("destination cannot be inside the source directory")
    _preflight_source(source, limits)

    try:
        parent_snapshot = prepare_verified_parent(destination)
    except FileIdentityChangedError as exc:
        raise UnsafeSanitizeRequest("destination parent is unsafe or changed") from exc
    stage_root = Path(
        tempfile.mkdtemp(prefix=".sharesafe-stage-", dir=parent_snapshot.path)
    )
    actions = new_sanitization_actions(
        evidence_key=evidence_key,
        before_report=before_report,
    )
    try:
        if source.is_dir():
            staged_payload = stage_root / "payload"
            staged_payload.mkdir()
            _copy_directory(source, staged_payload, limits, actions)
            _normalize_tree(staged_payload)
        elif source.is_file():
            staged_payload = stage_root / "payload"
            _transform_file(source, staged_payload, "artifact", limits, actions)
            _normalize_path(staged_payload, directory=False)
        else:
            raise UnsafeSanitizeRequest("only regular files and directories are supported")
        if not verify_directory_unchanged(parent_snapshot):
            raise UnsafeSanitizeRequest("destination parent changed before commit")
        commit_mode = _commit_no_overwrite(staged_payload, destination)
        if not verify_directory_unchanged(parent_snapshot):
            raise UnsafeSanitizeRequest("destination parent changed during commit")
        actions.append({
            "path": "<new-copy>",
            "action": "commit_without_overwrite",
            "status": "applied",
            "mode": commit_mode,
        })
        actions.append({
            "path": "<scan-boundary>",
            "action": "normalize_access_and_modification_times",
            "status": "applied",
        })
        actions.append({
            "path": "<new-copy>",
            "action": "verify_destination_parent_identity",
            "status": "applied",
            "mode": "path_checkpoint_not_handle_anchored",
        })
    except Exception:
        if destination.exists():
            # os.replace is the commit point. Never erase a committed result silently.
            raise
        raise
    finally:
        # Do not resolve a private staging name through a directory path that
        # no longer identifies the parent we created it in.  Leaving a private
        # orphan is safer than recursively deleting through a swapped parent.
        if verify_directory_unchanged(parent_snapshot):
            shutil.rmtree(stage_root, ignore_errors=True)
    return actions


def _is_within(path: Path, parent: Path) -> bool:
    return same_or_within(path, parent)


def _commit_no_overwrite(staged: Path, destination: Path) -> str:
    """Publish a staged path without ever replacing an existing destination."""

    if staged.is_file():
        try:
            os.link(staged, destination, follow_symlinks=False)
            return "atomic_hardlink"
        except FileExistsError as exc:
            raise UnsafeSanitizeRequest("destination appeared during sanitization; nothing was overwritten") from exc
        except (NotImplementedError, OSError) as exc:
            if isinstance(exc, OSError) and exc.errno == errno.EEXIST:
                raise UnsafeSanitizeRequest("destination appeared during sanitization; nothing was overwritten") from exc
            return _copy_staged_file_exclusive(staged, destination)

    if os.name == "nt":
        try:
            os.rename(staged, destination)
            return "atomic_rename_no_replace"
        except FileExistsError as exc:
            raise UnsafeSanitizeRequest("destination appeared during sanitization; nothing was overwritten") from exc

    # POSIX rename may replace an empty directory. Reserve the exact name with
    # mkdir(O_EXCL semantics), keep it private while populating, and remove it
    # on failure. This favors the never-overwrite guarantee over atomic
    # visibility of a multi-file tree.
    try:
        destination.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise UnsafeSanitizeRequest("destination appeared during sanitization; nothing was overwritten") from exc
    try:
        for child in staged.iterdir():
            os.rename(child, destination / child.name)
        staged.rmdir()
        _normalize_path(destination, directory=True)
        return "reserved_directory_commit"
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def _copy_staged_file_exclusive(staged: Path, destination: Path) -> str:
    descriptor: int | None = None
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with staged.open("rb") as source_handle, os.fdopen(descriptor, "wb") as destination_handle:
            descriptor = None
            shutil.copyfileobj(source_handle, destination_handle, length=1024 * 1024)
            destination_handle.flush()
            os.fsync(destination_handle.fileno())
        _normalize_path(destination, directory=False)
        return "exclusive_reserved_copy"
    except FileExistsError as exc:
        raise UnsafeSanitizeRequest("destination appeared during sanitization; nothing was overwritten") from exc
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        try:
            destination.unlink()
        except OSError:
            pass
        raise


def _is_link_or_reparse(path: Path) -> bool:
    status = path.lstat()
    if stat.S_ISLNK(status.st_mode):
        return True
    attributes = getattr(status, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _preflight_source(source: Path, limits: Limits) -> None:
    if _is_link_or_reparse(source):
        raise UnsafeSanitizeRequest("source is a symbolic link or reparse point")
    if source.is_file():
        if source.stat(follow_symlinks=False).st_size > limits.max_total_file_bytes:
            raise UnsafeSanitizeRequest("source exceeds the sanitization byte budget")
        return
    files = 0
    total = 0
    for directory, dir_names, file_names in os.walk(source, followlinks=False):
        base = Path(directory)
        try:
            depth = len(base.relative_to(source).parts)
        except ValueError as exc:
            raise UnsafeSanitizeRequest("source traversal escaped its root") from exc
        if depth > limits.max_directory_depth:
            raise UnsafeSanitizeRequest("source exceeds the sanitization directory-depth limit")
        for name in [*dir_names, *file_names]:
            candidate = base / name
            if _is_link_or_reparse(candidate):
                raise UnsafeSanitizeRequest("source tree contains a symbolic link or reparse point")
        for name in file_names:
            candidate = base / name
            status = candidate.stat(follow_symlinks=False)
            if not stat.S_ISREG(status.st_mode):
                raise UnsafeSanitizeRequest("source tree contains a non-regular file")
            files += 1
            total += status.st_size
            if files > limits.max_files:
                raise UnsafeSanitizeRequest("source exceeds the sanitization file-count limit")
            if total > limits.max_total_file_bytes:
                raise UnsafeSanitizeRequest("source exceeds the sanitization byte budget")


def _copy_directory(
    source: Path,
    destination: Path,
    limits: Limits,
    actions: SanitizationActions,
) -> None:
    scan_context = user_home_container_context(source.name)
    for directory, dir_names, file_names in os.walk(source, followlinks=False):
        if _is_link_or_reparse(Path(directory)):
            raise UnsafeSanitizeRequest("source tree changed to a link during sanitization")
        dir_names.sort(key=str.casefold)
        file_names.sort(key=str.casefold)
        for name in dir_names:
            if _is_link_or_reparse(Path(directory) / name):
                raise UnsafeSanitizeRequest("source tree changed to a link during sanitization")
        relative = Path(directory).relative_to(source)
        output_dir = destination / relative
        output_dir.mkdir(parents=True, exist_ok=True)
        for name in file_names:
            input_file = Path(directory) / name
            output_file = output_dir / name
            display, _ = contextual_relative_path((relative / name).as_posix(), scan_context)
            _transform_file(input_file, output_file, display, limits, actions)


def _transform_file(
    source: Path,
    destination: Path,
    display_path: str,
    limits: Limits,
    actions: SanitizationActions,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    before = source.stat(follow_symlinks=False)
    if _is_link_or_reparse(source) or not stat.S_ISREG(before.st_mode):
        raise UnsafeSanitizeRequest("source entry changed or is no longer a regular file")
    size = before.st_size
    safe_path = sanitize_display_path(display_path)
    if size > limits.max_file_bytes:
        _stable_stream_copy(source, destination, limits.max_total_file_bytes)
        _apply_safe_file_mode(source, destination)
        actions.append({
            "path": safe_path,
            "action": "copy_without_metadata_transform",
            "status": "skipped",
            "reason": "file_size_limit",
        })
        return
    data = _stable_read(source, limits.max_file_bytes)
    # Type selection uses the actual basename; ``display_path`` may be the
    # logical label "artifact" during before/after comparisons.
    media = sniff(data, source.name)
    output = data
    action = "copy_unchanged"
    status = "not_needed"
    reason: str | None = None

    if media.kind == "ooxml":
        output, status, reason = _sanitize_ooxml(data, source.name, limits)
        action = "remove_ooxml_metadata"
    elif (
        PurePosixPath(source.name.casefold()).suffix in {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}
        and data.startswith(_OLE_COMPOUND_MAGIC)
    ):
        action = "remove_ooxml_metadata"
        status = "skipped"
        reason = "encrypted_or_compound_ooxml_container"
    elif media.kind == "png":
        output, removed, reason = _sanitize_png(data)
        action = "strip_png_metadata"
        status = "partial" if removed and reason else ("applied" if removed else ("skipped" if reason else "not_needed"))
    elif media.kind == "jpeg":
        try:
            output, removed, reason = _sanitize_jpeg(data)
        except ValueError:
            output, removed, reason = data, 0, "invalid_jpeg_structure"
        action = "strip_jpeg_metadata"
        status = "partial" if removed and reason else ("applied" if removed else ("skipped" if reason else "not_needed"))
    elif media.kind == "pdf":
        action = "use_specialized_pdf_tool_on_a_copy"
        status = "unsupported"
        reason = "v0.1_does_not_rewrite_pdf"
    elif media.kind == "zip":
        action = "sanitize_archive_members"
        status = "unsupported"
        reason = "v0.1_does_not_rewrite_plain_zip"

    if action in {"remove_ooxml_metadata", "strip_png_metadata", "strip_jpeg_metadata"}:
        actions.add_transform_receipt(
            relative_path=safe_path,
            action_kind=action,
            media_type_before=media.media_type,
            media_type_after=sniff(output, source.name).media_type,
            transform_input=data,
            expected_after=output,
            status=status,
            reason=reason,
            limits=limits,
        )

    with destination.open("xb") as handle:
        handle.write(output)
        handle.flush()
        os.fsync(handle.fileno())
    _apply_safe_file_mode(source, destination)
    record: dict[str, Any] = {"path": safe_path, "action": action, "status": status}
    if reason:
        record["reason"] = reason
    actions.append(record)


def _sanitize_png(data: bytes) -> tuple[bytes, int, str | None]:
    from .adapters.image import _PNGChunkLimitError, _png_chunks

    removable = {"eXIf", "tEXt", "zTXt", "iTXt", "tIME"}
    chunks: list[tuple[str, bytes]] = []
    removed = 0
    retained_orientation = False
    try:
        for kind, payload in _png_chunks(data):
            remove = kind in removable
            if kind == "eXIf":
                orientation, parsed = _exif_orientation(payload)
                if not parsed or orientation not in {None, 1}:
                    remove = False
                    retained_orientation = True
            if remove:
                removed += 1
            else:
                chunks.append((kind, payload))
    except _PNGChunkLimitError:
        return data, 0, "png_chunk_limit"
    except ValueError:
        return data, 0, "invalid_png_structure"
    if not removed:
        reason = "exif_orientation_requires_lossless_normalization" if retained_orientation else None
        return data, 0, reason
    output = bytearray(b"\x89PNG\r\n\x1a\n")
    for kind, payload in chunks:
        kind_bytes = kind.encode("ascii")
        output.extend(struct.pack(">I", len(payload)))
        output.extend(kind_bytes)
        output.extend(payload)
        output.extend(struct.pack(">I", zlib.crc32(kind_bytes + payload) & 0xFFFFFFFF))
    reason = "exif_orientation_requires_lossless_normalization" if retained_orientation else None
    return bytes(output), removed, reason


def _exif_orientation(payload: bytes) -> tuple[int | None, bool]:
    # JPEG APP1 prefixes TIFF bytes with Exif\0\0; PNG eXIf stores the TIFF
    # stream directly.
    tiff = payload[6:] if payload.startswith(b"Exif\x00\x00") else payload
    if len(tiff) < 8:
        return None, False
    if tiff[:2] == b"II":
        endian = "<"
    elif tiff[:2] == b"MM":
        endian = ">"
    else:
        return None, False
    try:
        if struct.unpack(endian + "H", tiff[2:4])[0] != 42:
            return None, False
        offset = struct.unpack(endian + "I", tiff[4:8])[0]
        orientations: list[int] = []
        seen_offsets: set[int] = set()
        # Real-world EXIF normally has at most IFD0 and a thumbnail IFD.  A
        # small hard cap also prevents a hostile chain of overlapping IFDs
        # from turning this safety check into unbounded work.
        for _ in range(64):
            if offset == 0:
                non_neutral = next((value for value in orientations if value != 1), None)
                return (non_neutral if non_neutral is not None else (1 if orientations else None)), True
            if offset < 8 or offset % 2 or offset in seen_offsets or offset + 2 > len(tiff):
                return None, False
            seen_offsets.add(offset)
            count = struct.unpack(endian + "H", tiff[offset : offset + 2])[0]
            cursor = offset + 2
            table_end = cursor + count * 12
            if table_end + 4 > len(tiff):
                return None, False
            orientation_in_ifd = False
            for _entry in range(count):
                tag, kind, item_count = struct.unpack(endian + "HHI", tiff[cursor : cursor + 8])
                if tag == 0x0112:
                    # TIFF/EXIF Orientation is exactly one SHORT.  Treat a
                    # duplicate or a differently typed value as malformed;
                    # interpreting it as "absent" could strip an orientation
                    # that another decoder still honors.
                    if kind != 3 or item_count != 1 or orientation_in_ifd:
                        return None, False
                    orientation_in_ifd = True
                    orientations.append(struct.unpack(endian + "H", tiff[cursor + 8 : cursor + 10])[0])
                cursor += 12
            offset = struct.unpack(endian + "I", tiff[table_end : table_end + 4])[0]
        return None, False
    except struct.error:
        return None, False


def _sanitize_jpeg(data: bytes) -> tuple[bytes, int, str | None]:
    from .adapters.image import _is_jpeg_xmp, _jpeg_segment_records

    removal_spans: list[tuple[int, int]] = []
    removed = 0
    kept_unparsed_exif = False
    for marker, payload, start, end in _jpeg_segment_records(data):
        remove = marker in {0xED, 0xFE}
        is_exif = payload.startswith(b"Exif\x00\x00")
        is_xmp = _is_jpeg_xmp(payload)
        if marker == 0xE1 and (is_exif or is_xmp):
            remove = True
            if is_exif:
                orientation, parsed = _exif_orientation(payload)
                if not parsed or orientation not in {None, 1}:
                    remove = False
                    kept_unparsed_exif = True
        if remove:
            removed += 1
            removal_spans.append((start, end))

    reason = "exif_orientation_requires_lossless_normalization" if kept_unparsed_exif else None
    if not removal_spans:
        return data, 0, reason
    output = bytearray()
    cursor = 0
    for start, end in removal_spans:
        output.extend(data[cursor:start])
        cursor = end
    output.extend(data[cursor:])
    return bytes(output), removed, reason


def _sanitize_ooxml(data: bytes, display_path: str, limits: Limits) -> tuple[bytes, str, str | None]:
    from .adapters.archive import _bounded_read, _is_symlink, _unsafe_member_name

    preflight = preflight_zip(data, limits.max_archive_entries)
    if preflight.status == "entry_limit":
        return data, "skipped", "package_resource_limit"
    if preflight.status == "malformed":
        return data, "skipped", "malformed_ooxml"
    try:
        source = zipfile.ZipFile(io.BytesIO(data))
        infos = source.infolist()
    except (zipfile.BadZipFile, OSError):
        return data, "skipped", "malformed_ooxml"
    extension = PurePosixPath(display_path.casefold()).suffix
    names = {info.filename.replace("\\", "/").casefold() for info in infos}
    normalized_names = [info.filename.replace("\\", "/").casefold() for info in infos]
    if (
        len(set(normalized_names)) != len(normalized_names)
        or any(_unsafe_member_name(info.filename) or _is_symlink(info) or info.flag_bits & 0x1 for info in infos)
    ):
        source.close()
        return data, "skipped", "unsafe_or_ambiguous_package_structure"
    expected_main_part = {
        ".docx": "word/document.xml", ".docm": "word/document.xml",
        ".xlsx": "xl/workbook.xml", ".xlsm": "xl/workbook.xml",
        ".pptx": "ppt/presentation.xml", ".pptm": "ppt/presentation.xml",
    }.get(extension)
    if (
        expected_main_part is None
        or "[content_types].xml" not in names
        or expected_main_part not in names
    ):
        source.close()
        return data, "skipped", "ooxml_type_mismatch"
    if extension in {".docm", ".xlsm", ".pptm"} or any(
        "vbaproject.bin" in name or name.endswith("/vbadata.xml") for name in names
    ):
        source.close()
        return data, "skipped", "macro_enabled_document"
    if any(
        any(part in {"embeddings", "activex"} for part in PurePosixPath(name).parts)
        for name in names
    ):
        source.close()
        return data, "skipped", "embedded_object_not_supported"
    if len(infos) > limits.max_archive_entries or sum(info.file_size for info in infos) > limits.max_expanded_bytes:
        source.close()
        return data, "skipped", "package_resource_limit"
    if any(
        info.file_size > limits.max_archive_member_bytes
        or (
            info.file_size > 1024 * 1024
            and info.file_size / max(1, info.compress_size) > limits.max_compression_ratio
        )
        for info in infos
        if not info.is_dir()
    ):
        source.close()
        return data, "skipped", "package_resource_limit"

    signature_found = any(name.startswith("_xmlsignatures/") for name in names)
    try:
        # Validate every XML-bearing package part before rebuilding any ZIP
        # metadata.  Even parts that ShareSafe deliberately leaves untouched
        # must not let a malformed/DTD-bearing package be promoted to an
        # applied transform.
        for info in infos:
            if info.is_dir():
                continue
            lower = info.filename.replace("\\", "/").casefold()
            is_xml = lower.endswith(".xml") or lower.endswith(".rels")
            if not is_xml:
                with source.open(info, "r") as handle:
                    if handle.read(len(_OLE_COMPOUND_MAGIC)) == _OLE_COMPOUND_MAGIC:
                        source.close()
                        return data, "skipped", "embedded_object_not_supported"
                continue
            if info.file_size > limits.max_xml_bytes:
                source.close()
                return data, "skipped", "xml_part_size_limit"
            with source.open(info, "r") as handle:
                payload = _bounded_read(handle, info.file_size)
            if len(payload) != info.file_size:
                source.close()
                return data, "skipped", "package_part_size_mismatch"
            root = parse_xml(payload)
            if declares_macros(root):
                source.close()
                return data, "skipped", "macro_enabled_document"
            if declares_embedded_object(root):
                source.close()
                return data, "skipped", "embedded_object_not_supported"
            if (lower == "[content_types].xml" or lower.endswith(".rels")) and declares_digital_signature(root):
                signature_found = True
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile, EOFError, ET.ParseError, ValueError):
        source.close()
        return data, "skipped", "package_rewrite_error"
    if signature_found:
        source.close()
        return data, "skipped", "digitally_signed_document"

    remove_parts = {"docprops/custom.xml"}
    changed = bool(source.comment)
    output_buffer = io.BytesIO()
    expanded = 0
    try:
        with source, zipfile.ZipFile(output_buffer, "w", allowZip64=True) as target:
            target.comment = b""
            for info in infos:
                name = info.filename.replace("\\", "/")
                lower = name.casefold()
                if lower in remove_parts:
                    changed = True
                    continue
                if info.flag_bits & 0x1 or info.file_size > limits.max_archive_member_bytes:
                    return data, "skipped", "unreadable_or_oversize_package_part"
                remaining = limits.max_expanded_bytes - expanded
                if remaining < 0:
                    return data, "skipped", "package_resource_limit"
                with source.open(info, "r") as handle:
                    payload = _bounded_read(
                        handle,
                        min(limits.max_archive_member_bytes, info.file_size, remaining),
                    )
                if len(payload) != info.file_size:
                    return data, "skipped", "package_part_size_mismatch"
                expanded += len(payload)
                if lower.endswith(".xml") and len(payload) > limits.max_xml_bytes:
                    return data, "skipped", "xml_part_size_limit"
                if lower == "docprops/core.xml":
                    payload, part_changed = _clean_properties_xml(payload, "core")
                    changed = changed or part_changed
                elif lower == "docprops/app.xml":
                    payload, part_changed = _clean_properties_xml(payload, "app")
                    changed = changed or part_changed
                elif lower == "[content_types].xml":
                    payload, part_changed = _remove_custom_property_reference(payload, content_types=True)
                    changed = changed or part_changed
                elif lower.endswith(".rels"):
                    payload, part_changed = _remove_custom_property_reference(
                        payload,
                        content_types=False,
                        relationship_part=name,
                    )
                    changed = changed or part_changed
                normalized = zipfile.ZipInfo(filename=name, date_time=NORMALIZED_ZIP_TIME)
                normalized.compress_type = info.compress_type if info.compress_type in {
                    zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA,
                } else zipfile.ZIP_DEFLATED
                normalized.create_system = 3
                normalized_mode = 0o700 if info.is_dir() else 0o600
                normalized.external_attr = (normalized_mode & 0xFFFF) << 16
                if info.is_dir():
                    normalized.external_attr |= 0x10
                normalized.flag_bits = info.flag_bits & ~0x1
                target.writestr(normalized, payload)
                if (
                    info.date_time != NORMALIZED_ZIP_TIME
                    or info.extra
                    or info.comment
                    or info.create_system != normalized.create_system
                    or info.external_attr != normalized.external_attr
                ):
                    changed = True
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile, ET.ParseError, ValueError):
        return data, "skipped", "package_rewrite_error"
    return (output_buffer.getvalue() if changed else data), ("applied" if changed else "not_needed"), None


def _clean_properties_xml(data: bytes, kind: str) -> tuple[bytes, bool]:
    root = parse_xml(data)
    core_remove = {
        "creator", "lastModifiedBy", "title", "subject", "description", "keywords", "category",
        "identifier", "created", "modified", "lastPrinted", "revision", "contentStatus", "language", "version",
    }
    app_remove = {"Manager", "Company", "Template", "HyperlinkBase", "Application", "AppVersion"}
    remove = core_remove if kind == "core" else app_remove
    changed = False
    for child in list(root):
        local = local_name(child.tag)
        if local in remove and ("".join(child.itertext()).strip() or child.attrib):
            _remove_child_preserving_tail(root, child)
            changed = True
    if not changed:
        return data, False
    return ET.tostring(root, encoding="utf-8", xml_declaration=True), True


def _relationship_source_parts(relationship_part: str) -> tuple[str, ...] | None:
    """Return the source part path for an OPC Relationships part.

    ``_rels/.rels`` belongs to the package root.  A part-level relationship
    such as ``word/_rels/document.xml.rels`` belongs to
    ``word/document.xml``.
    """

    normalized = relationship_part.replace("\\", "/").strip("/")
    parts = tuple(part for part in normalized.split("/") if part)
    if tuple(part.casefold() for part in parts) == ("_rels", ".rels"):
        return ()
    if (
        len(parts) >= 2
        and parts[-2].casefold() == "_rels"
        and parts[-1].casefold().endswith(".rels")
        and len(parts[-1]) > len(".rels")
    ):
        return (*parts[:-2], parts[-1][:-len(".rels")])
    return None


def _resolve_internal_relationship_target(relationship_part: str, target: str) -> str | None:
    """Resolve an internal OPC relationship target to a package-root path."""

    try:
        parsed = urlsplit(target)
    except ValueError:
        return None
    if parsed.scheme or parsed.netloc or not parsed.path:
        return None
    path = unquote(parsed.path)
    if "\x00" in path or "\\" in path:
        return None
    source_parts = _relationship_source_parts(relationship_part)
    if source_parts is None:
        return None
    resolved = [] if path.startswith("/") else list(source_parts[:-1] if source_parts else ())
    for part in path.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not resolved:
                return None
            resolved.pop()
            continue
        resolved.append(part)
    return "/".join(resolved)


def _remove_custom_property_reference(
    data: bytes,
    *,
    content_types: bool,
    relationship_part: str | None = None,
) -> tuple[bytes, bool]:
    root = parse_xml(data)
    changed = False
    for child in list(root):
        attributes = {key.rsplit("}", 1)[-1]: value for key, value in child.attrib.items()}
        if content_types:
            part = attributes.get("PartName", "")
            should_remove = (
                local_name(child.tag) == "Override"
                and part.startswith("/")
                and (
                    _resolve_internal_relationship_target("_rels/.rels", part) or ""
                ).casefold() == "docprops/custom.xml"
            )
        else:
            target_mode = attributes.get("TargetMode", "").strip().casefold()
            resolved = (
                _resolve_internal_relationship_target(relationship_part, attributes.get("Target", ""))
                if relationship_part is not None and target_mode != "external"
                else None
            )
            should_remove = (
                local_name(child.tag) == "Relationship"
                and resolved is not None
                and resolved.casefold() == "docprops/custom.xml"
            )
        if should_remove:
            _remove_child_preserving_tail(root, child)
            changed = True
    if not changed:
        return data, False
    return ET.tostring(root, encoding="utf-8", xml_declaration=True), True


def _remove_child_preserving_tail(root: ET.Element, child: ET.Element) -> None:
    """Remove an element without silently deleting its following text."""

    children = list(root)
    position = children.index(child)
    tail = child.tail
    root.remove(child)
    if not tail:
        return
    remaining = list(root)
    if position > 0 and position - 1 < len(remaining):
        previous = remaining[position - 1]
        previous.tail = (previous.tail or "") + tail
    else:
        root.text = (root.text or "") + tail


def _normalize_tree(root: Path) -> None:
    for directory, dir_names, file_names in os.walk(root, topdown=False):
        for name in file_names:
            _normalize_path(Path(directory) / name, directory=False)
        for name in dir_names:
            _normalize_path(Path(directory) / name, directory=True)
    _normalize_path(root, directory=True)


def _apply_safe_file_mode(source: Path, destination: Path) -> None:
    try:
        source_mode = source.stat(follow_symlinks=False).st_mode
        os.chmod(destination, 0o755 if source_mode & 0o111 else 0o644)
    except OSError:
        pass


def _stable_read(source: Path, limit: int) -> bytes:
    before = source.stat(follow_symlinks=False)
    try:
        handle, opened = open_verified_binary(source, expected=before)
    except FileIdentityChangedError as exc:
        raise UnsafeSanitizeRequest("source changed before it could be read") from exc
    with handle:
        data = handle.read(limit + 1)
        unchanged = verify_open_file_unchanged(handle, source, opened=opened)
    if not unchanged:
        raise UnsafeSanitizeRequest("source changed while it was being read")
    if len(data) > limit or len(data) != opened.st_size:
        raise UnsafeSanitizeRequest("source exceeded its bounded size while being read")
    return data


def _stable_stream_copy(source: Path, destination: Path, limit: int) -> None:
    before = source.stat(follow_symlinks=False)
    copied = 0
    try:
        input_handle, opened = open_verified_binary(source, expected=before)
    except FileIdentityChangedError as exc:
        raise UnsafeSanitizeRequest("source changed before it could be copied") from exc
    with input_handle, destination.open("xb") as output_handle:
        while True:
            chunk = input_handle.read(1024 * 1024)
            if not chunk:
                break
            copied += len(chunk)
            if copied > limit:
                raise UnsafeSanitizeRequest("source exceeded the sanitization byte budget while copying")
            output_handle.write(chunk)
        output_handle.flush()
        os.fsync(output_handle.fileno())
        unchanged = verify_open_file_unchanged(input_handle, source, opened=opened)
    if not unchanged or copied != opened.st_size:
        raise UnsafeSanitizeRequest("source changed while it was being copied")


def _normalize_path(path: Path, *, directory: bool) -> None:
    if directory:
        try:
            os.chmod(path, 0o755)
        except OSError:
            pass
    try:
        os.utime(path, (NORMALIZED_TIME, NORMALIZED_TIME), follow_symlinks=False)
    except NotImplementedError:
        # Windows may not expose follow_symlinks for utime. Staged outputs are
        # link-free by construction, so the plain call is equivalent here.
        try:
            os.utime(path, (NORMALIZED_TIME, NORMALIZED_TIME))
        except OSError:
            pass
    except OSError:
        pass
