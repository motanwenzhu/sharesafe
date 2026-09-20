"""Verified construction of a new, explicitly approved share boundary.

This module executes only the allow-listed actions carried by a validated
``PreparePlan``.  It never edits the source tree, never overwrites an output,
and never treats a successful copy as sufficient evidence: source bindings,
the staged tree, the committed tree, and a final privacy scan are all checked.

Persisted plans and approvals are local control artifacts.  The result emitted
by this module is deliberately masked and omits plan/source/output digests.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import shutil
import stat
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .detectors import sanitize_display_path, temporary_hmac_key
from .engine import ScanConfig, Scanner
from .limits import Limits
from .models import stable_id
from .path_safety import same_or_within, uses_windows_alternate_stream
from .prepare_io import PrepareIOError, create_private_temporary_directory
from .prepare_plan import (
    PrepareAction,
    PrepareApproval,
    PreparePlan,
    PreparePlanError,
    create_prepare_plan,
    prepare_approval_from_mapping,
    prepare_plan_from_mapping,
)
from .receipts import bind_and_validate_receipt, new_sanitization_actions
from .redaction import content_hmac_token
from .report_hygiene import json_within_byte_limit, validate_masked_payload
from .safe_io import (
    DirectorySnapshot,
    FileIdentityChangedError,
    open_verified_binary,
    prepare_verified_parent,
    snapshot_verified_directory,
    verify_directory_unchanged,
    verify_open_file_unchanged,
)
from .sanitize import (
    NORMALIZED_TIME,
    _sanitize_jpeg,
    _sanitize_ooxml,
    _sanitize_png,
)
from .sniff import sniff

PREPARE_RESULT_SCHEMA = "sharesafe.prepare-result/v1"
_TRANSFORM_RECEIPT_ACTION = {
    "strip_ooxml_metadata": "remove_ooxml_metadata",
    "strip_png_metadata": "strip_png_metadata",
    "strip_jpeg_metadata": "strip_jpeg_metadata",
}
_INCLUDE_ACTIONS = {
    "copy_unchanged",
    "rename_in_bundle",
    "strip_ooxml_metadata",
    "strip_png_metadata",
    "strip_jpeg_metadata",
}
_RESULT_SIZE_ISSUE = {
    "code": "prepare_result_size_limit",
    "action_id": None,
    "path": "<new-bundle>",
}
_RESULT_SIZE_GAP_DETAIL = (
    "Prepare result details were omitted at the configured report byte limit."
)


class PrepareWorkflowError(ValueError):
    """Stable, non-sensitive failure from a prepare operation."""

    def __init__(
        self,
        code: str,
        *,
        exit_code: int = 3,
        output_may_exist: bool = False,
    ) -> None:
        self.code = code
        self.exit_code = exit_code
        self.output_may_exist = output_may_exist
        super().__init__(code.replace("_", " "))


@dataclass(frozen=True, slots=True)
class PrepareExecutionResult:
    payload: dict[str, Any]
    exit_code: int


@dataclass(frozen=True, slots=True)
class _ExpectedOutput:
    action_id: str
    target_path: str
    action: str
    media_type: str
    size: int
    digest: str
    content_token: str


def _display_path(value: str, limits: Limits) -> str:
    return sanitize_display_path(
        value,
        max_name_bytes=limits.max_name_bytes,
        max_display_path_chars=limits.max_display_path_chars,
    )


def _is_reparse(status_value: os.stat_result) -> bool:
    attributes = getattr(status_value, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _validated_plan(plan: PreparePlan | Mapping[str, Any]) -> PreparePlan:
    try:
        if isinstance(plan, PreparePlan):
            return prepare_plan_from_mapping(plan.to_dict())
        if isinstance(plan, Mapping):
            return prepare_plan_from_mapping(plan)
    except PreparePlanError as exc:
        raise PrepareWorkflowError(exc.code) from exc
    raise PrepareWorkflowError("invalid_plan_type")


def _validated_approval(
    approval: PrepareApproval | Mapping[str, Any],
    *,
    plan: PreparePlan,
) -> PrepareApproval:
    try:
        if isinstance(approval, PrepareApproval):
            return prepare_approval_from_mapping(approval.to_dict(), plan=plan)
        if isinstance(approval, Mapping):
            return prepare_approval_from_mapping(approval, plan=plan)
    except PreparePlanError as exc:
        raise PrepareWorkflowError(exc.code) from exc
    raise PrepareWorkflowError("invalid_approval_type")


def _plan_decisions(plan: PreparePlan) -> list[dict[str, object]]:
    return [
        {
            "source_path": action.source_path,
            "target_path": action.target_path,
            "action": action.action,
            "reason_code": action.reason_code,
        }
        for action in plan.actions
    ]


def assert_source_matches_plan(
    source: str | os.PathLike[str],
    plan: PreparePlan | Mapping[str, Any],
    *,
    limits: Limits | None = None,
) -> PreparePlan:
    """Re-enumerate and re-hash ``source`` against the exact validated plan."""

    validated = _validated_plan(plan)
    try:
        regenerated = create_prepare_plan(
            source,
            _plan_decisions(validated),
            limits=limits,
        )
    except PreparePlanError as exc:
        raise PrepareWorkflowError("source_drift") from exc
    if not hmac.compare_digest(regenerated.plan_digest, validated.plan_digest):
        raise PrepareWorkflowError("source_drift")
    return validated


def _check_output_boundary(source: Path, output: Path) -> DirectorySnapshot:
    source = source.absolute()
    output = output.absolute()
    if uses_windows_alternate_stream(source) or uses_windows_alternate_stream(output):
        raise PrepareWorkflowError("unsafe_path")
    if output.exists() or output.is_symlink():
        raise PrepareWorkflowError("output_exists")
    try:
        overlaps = same_or_within(output, source) or same_or_within(source, output)
    except ValueError as exc:
        raise PrepareWorkflowError("unsafe_path") from exc
    if overlaps:
        raise PrepareWorkflowError("overlapping_boundaries")
    try:
        return prepare_verified_parent(output)
    except FileIdentityChangedError as exc:
        raise PrepareWorkflowError("unsafe_output_parent") from exc


def _plain_status(path: Path, *, code: str) -> os.stat_result:
    try:
        status_value = path.lstat()
    except OSError as exc:
        raise PrepareWorkflowError(code) from exc
    if _is_reparse(status_value) or stat.S_ISLNK(status_value.st_mode):
        raise PrepareWorkflowError(code)
    return status_value


def _source_item_path(source: Path, action: PrepareAction) -> Path:
    source = source.absolute()
    root_status = _plain_status(source, code="source_drift")
    if stat.S_ISREG(root_status.st_mode):
        if action.source_path != source.name:
            raise PrepareWorkflowError("source_drift")
        return source
    if not stat.S_ISDIR(root_status.st_mode):
        raise PrepareWorkflowError("source_drift")
    cursor = source
    parts = action.source_path.split("/")
    for index, part in enumerate(parts):
        cursor = cursor / part
        status_value = _plain_status(cursor, code="source_drift")
        if index < len(parts) - 1 and not stat.S_ISDIR(status_value.st_mode):
            raise PrepareWorkflowError("source_drift")
    return cursor


def _read_bound_source(
    source: Path,
    action: PrepareAction,
    *,
    limits: Limits,
) -> bytes:
    path = _source_item_path(source, action)
    status_value = _plain_status(path, code="source_drift")
    if (
        not stat.S_ISREG(status_value.st_mode)
        or getattr(status_value, "st_nlink", 1) != 1
        or status_value.st_size != action.source_binding.size
        or status_value.st_size > limits.max_file_bytes
    ):
        raise PrepareWorkflowError("source_drift")
    try:
        handle, opened = open_verified_binary(path, expected=status_value)
        with handle:
            data = handle.read(limits.max_file_bytes + 1)
            unchanged = verify_open_file_unchanged(handle, path, opened=opened)
    except (FileIdentityChangedError, OSError) as exc:
        raise PrepareWorkflowError("source_drift") from exc
    if (
        not unchanged
        or len(data) != opened.st_size
        or len(data) > limits.max_file_bytes
    ):
        raise PrepareWorkflowError("source_drift")
    digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
    if not hmac.compare_digest(digest, action.source_binding.digest):
        raise PrepareWorkflowError("source_drift")
    if sniff(data[:8192], action.source_path).media_type != action.media_type:
        raise PrepareWorkflowError("source_drift")
    # Recheck the entire relative chain after the descriptor-bound read.  This
    # is still a checkpoint, not directory-handle anchoring; doctor and docs
    # disclose that residual race explicitly.
    _source_item_path(source, action)
    return data


def _validated_transform(
    action: PrepareAction,
    data: bytes,
    *,
    limits: Limits,
) -> bytes:
    if action.action == "strip_ooxml_metadata":
        output, status_value, reason = _sanitize_ooxml(
            data,
            action.source_path,
            limits,
        )
        applied = status_value == "applied" and reason is None
    elif action.action == "strip_png_metadata":
        output, removed, reason = _sanitize_png(data)
        applied = removed > 0 and reason is None
    elif action.action == "strip_jpeg_metadata":
        try:
            output, removed, reason = _sanitize_jpeg(data)
        except ValueError as exc:
            raise PrepareWorkflowError(
                "transform_not_applied",
                exit_code=2,
            ) from exc
        applied = removed > 0 and reason is None
    else:
        raise PrepareWorkflowError("unsupported_action")

    if not applied or output == data:
        raise PrepareWorkflowError("transform_not_applied", exit_code=2)
    media_after = sniff(
        output[:8192], action.target_path or action.source_path
    ).media_type
    if media_after != action.media_type:
        raise PrepareWorkflowError("transform_media_changed", exit_code=2)

    carrier = new_sanitization_actions()
    receipt_action = _TRANSFORM_RECEIPT_ACTION[action.action]
    carrier.add_transform_receipt(
        relative_path=action.target_path or action.source_path,
        action_kind=receipt_action,
        media_type_before=action.media_type,
        media_type_after=media_after,
        transform_input=data,
        expected_after=output,
        status="applied",
        reason=None,
        limits=limits,
    )
    receipts = carrier.receipts
    if len(receipts) != 1:
        raise PrepareWorkflowError("transform_receipt_invalid", exit_code=2)
    failure = bind_and_validate_receipt(
        receipts[0],
        before_artifact={"media_type": action.media_type},
        after_artifact={"media_type": media_after},
    )
    if failure is not None:
        raise PrepareWorkflowError(failure, exit_code=2)
    return output


def _expected_output_bytes(
    source: Path,
    action: PrepareAction,
    *,
    limits: Limits,
) -> bytes | None:
    data = _read_bound_source(source, action, limits=limits)
    if action.action == "omit_from_boundary":
        return None
    if action.action in {"copy_unchanged", "rename_in_bundle"}:
        return data
    if action.action in _TRANSFORM_RECEIPT_ACTION:
        return _validated_transform(action, data, limits=limits)
    raise PrepareWorkflowError("plan_not_executable")


def _target_path(root: Path, relative: str) -> Path:
    # ``prepare_plan_from_mapping`` already established a portable path with no
    # empty/dot/backslash/absolute components.
    return root.joinpath(*relative.split("/"))


def _write_private_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor: int | None = None
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(path, 0o600, follow_symlinks=False)
        except (NotImplementedError, OSError):
            pass
        try:
            os.utime(
                path,
                (NORMALIZED_TIME, NORMALIZED_TIME),
                follow_symlinks=False,
            )
        except (NotImplementedError, OSError):
            pass
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        # Do not unlink through a path after an exceptional write: another
        # actor may have replaced the name.  Verified staging cleanup (or an
        # incomplete-commit marker) owns recovery at a safer level.
        raise


def _normalize_private_directories(root: Path) -> None:
    for directory, dir_names, _ in os.walk(root, topdown=False, followlinks=False):
        for name in dir_names:
            candidate = Path(directory) / name
            try:
                os.chmod(candidate, 0o700, follow_symlinks=False)
                os.utime(
                    candidate,
                    (NORMALIZED_TIME, NORMALIZED_TIME),
                    follow_symlinks=False,
                )
            except (NotImplementedError, OSError):
                pass
    try:
        os.chmod(root, 0o700, follow_symlinks=False)
        os.utime(root, (NORMALIZED_TIME, NORMALIZED_TIME), follow_symlinks=False)
    except (NotImplementedError, OSError):
        pass


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _copy_staged_file_exclusive(staged: Path, destination: Path) -> None:
    """Copy one staged regular file through an O_EXCL destination handle."""

    source_status = _plain_status(staged, code="staging_changed")
    if not stat.S_ISREG(source_status.st_mode):
        raise PrepareWorkflowError("staging_changed", exit_code=4)
    try:
        destination_parent = snapshot_verified_directory(destination.parent)
        source_handle, opened = open_verified_binary(staged, expected=source_status)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOINHERIT", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(destination, flags, 0o600)
        with source_handle, os.fdopen(descriptor, "wb") as destination_handle:
            while True:
                chunk = source_handle.read(1024 * 1024)
                if not chunk:
                    break
                destination_handle.write(chunk)
            destination_handle.flush()
            os.fsync(destination_handle.fileno())
            source_unchanged = verify_open_file_unchanged(
                source_handle,
                staged,
                opened=opened,
            )
    except FileExistsError as exc:
        raise PrepareWorkflowError(
            "commit_target_appeared",
            exit_code=4,
            output_may_exist=True,
        ) from exc
    except PrepareWorkflowError:
        raise
    except (FileIdentityChangedError, OSError) as exc:
        raise PrepareWorkflowError(
            "commit_failed",
            exit_code=4,
            output_may_exist=True,
        ) from exc
    if not source_unchanged or not verify_directory_unchanged(destination_parent):
        raise PrepareWorkflowError(
            "commit_path_changed",
            exit_code=4,
            output_may_exist=True,
        )


def _materialize_staged_tree_exclusive(staged: Path, output: Path) -> None:
    """Populate a reserved output tree without any replacing rename."""

    directories: list[str] = []
    files: list[tuple[str, Path]] = []
    for directory, dir_names, file_names in os.walk(staged, followlinks=False):
        base = Path(directory)
        base_status = _plain_status(base, code="staging_changed")
        if not stat.S_ISDIR(base_status.st_mode):
            raise PrepareWorkflowError("staging_changed", exit_code=4)
        dir_names.sort(key=str.casefold)
        file_names.sort(key=str.casefold)
        for name in dir_names:
            child = base / name
            child_status = _plain_status(child, code="staging_changed")
            if not stat.S_ISDIR(child_status.st_mode):
                raise PrepareWorkflowError("staging_changed", exit_code=4)
            directories.append(child.relative_to(staged).as_posix())
        for name in file_names:
            child = base / name
            child_status = _plain_status(child, code="staging_changed")
            if not stat.S_ISREG(child_status.st_mode):
                raise PrepareWorkflowError("staging_changed", exit_code=4)
            files.append((child.relative_to(staged).as_posix(), child))

    directories.sort(key=lambda item: (item.count("/"), item.casefold(), item))
    for relative in directories:
        target = _target_path(output, relative)
        try:
            target.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise PrepareWorkflowError(
                "commit_target_appeared",
                exit_code=4,
                output_may_exist=True,
            ) from exc
        except OSError as exc:
            raise PrepareWorkflowError(
                "commit_failed",
                exit_code=4,
                output_may_exist=True,
            ) from exc
        try:
            snapshot_verified_directory(target)
        except FileIdentityChangedError as exc:
            raise PrepareWorkflowError(
                "commit_path_changed",
                exit_code=4,
                output_may_exist=True,
            ) from exc

    for relative, staged_file in sorted(files, key=lambda item: item[0].casefold()):
        _copy_staged_file_exclusive(staged_file, _target_path(output, relative))


def _commit_directory_no_overwrite(
    staged: Path,
    output: Path,
    *,
    parent_snapshot: DirectorySnapshot,
) -> str:
    """Reserve and populate ``output`` without replacing an existing path."""

    if not verify_directory_unchanged(parent_snapshot):
        raise PrepareWorkflowError("output_parent_changed")
    try:
        output.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise PrepareWorkflowError("output_exists") from exc
    except OSError as exc:
        raise PrepareWorkflowError("commit_failed", exit_code=4) from exc

    marker = output / f".sharesafe-incomplete-{secrets.token_hex(12)}"
    try:
        output_snapshot = snapshot_verified_directory(output)
        _write_private_file(marker, b"ShareSafe incomplete commit marker\n")
        if not verify_directory_unchanged(
            parent_snapshot
        ) or not verify_directory_unchanged(output_snapshot):
            raise PrepareWorkflowError(
                "output_parent_changed",
                exit_code=4,
                output_may_exist=True,
            )
        _materialize_staged_tree_exclusive(staged, output)
        marker.unlink()
        _fsync_directory(output)
        _fsync_directory(parent_snapshot.path)
        if not verify_directory_unchanged(
            parent_snapshot
        ) or not verify_directory_unchanged(output_snapshot):
            raise PrepareWorkflowError(
                "output_parent_changed",
                exit_code=4,
                output_may_exist=True,
            )
        return "exclusive_reserved_copy_tree"
    except PrepareWorkflowError:
        raise
    except Exception as exc:
        # Once the exclusive destination name is reserved, do not recursively
        # remove through a path an attacker may have swapped.  The marker (when
        # reachable) makes the incomplete state explicit.
        raise PrepareWorkflowError(
            "commit_failed",
            exit_code=4,
            output_may_exist=True,
        ) from exc


def _build_staged_tree(
    source: Path,
    staged: Path,
    plan: PreparePlan,
    *,
    limits: Limits,
    evidence_key: bytes,
) -> tuple[dict[str, _ExpectedOutput], list[dict[str, Any]]]:
    expected: dict[str, _ExpectedOutput] = {}
    records: list[dict[str, Any]] = []
    for action in plan.actions:
        output = _expected_output_bytes(source, action, limits=limits)
        if output is None:
            records.append(
                {
                    "action_id": action.action_id,
                    "source_path": _display_path(action.source_path, limits),
                    "target_path": None,
                    "action": action.action,
                    "status": "applied",
                    "relation": "absent_from_output",
                }
            )
            continue
        if action.target_path is None:
            raise PrepareWorkflowError("action_contract_mismatch")
        target = _target_path(staged, action.target_path)
        _write_private_file(target, output)
        digest = f"sha256:{hashlib.sha256(output).hexdigest()}"
        expected[action.target_path] = _ExpectedOutput(
            action_id=action.action_id,
            target_path=action.target_path,
            action=action.action,
            media_type=action.media_type,
            size=len(output),
            digest=digest,
            content_token=content_hmac_token(output, evidence_key),
        )
        records.append(
            {
                "action_id": action.action_id,
                "source_path": _display_path(action.source_path, limits),
                "target_path": _display_path(action.target_path, limits),
                "action": action.action,
                "status": "applied",
                "relation": (
                    "metadata_reduced_format_preserved"
                    if action.action in _TRANSFORM_RECEIPT_ACTION
                    else "byte_identical"
                ),
            }
        )
    _normalize_private_directories(staged)
    return expected, records


def _expected_from_source(
    source: Path,
    plan: PreparePlan,
    *,
    limits: Limits,
    evidence_key: bytes,
) -> tuple[dict[str, _ExpectedOutput], list[dict[str, Any]]]:
    expected: dict[str, _ExpectedOutput] = {}
    records: list[dict[str, Any]] = []
    for action in plan.actions:
        output = _expected_output_bytes(source, action, limits=limits)
        if output is None:
            records.append(
                {
                    "action_id": action.action_id,
                    "source_path": _display_path(action.source_path, limits),
                    "target_path": None,
                    "action": action.action,
                    "status": "verified",
                    "relation": "absent_from_output",
                }
            )
            continue
        if action.target_path is None:
            raise PrepareWorkflowError("action_contract_mismatch")
        expected[action.target_path] = _ExpectedOutput(
            action_id=action.action_id,
            target_path=action.target_path,
            action=action.action,
            media_type=action.media_type,
            size=len(output),
            digest=f"sha256:{hashlib.sha256(output).hexdigest()}",
            content_token=content_hmac_token(output, evidence_key),
        )
        records.append(
            {
                "action_id": action.action_id,
                "source_path": _display_path(action.source_path, limits),
                "target_path": _display_path(action.target_path, limits),
                "action": action.action,
                "status": "verified",
                "relation": (
                    "metadata_reduced_format_preserved"
                    if action.action in _TRANSFORM_RECEIPT_ACTION
                    else "byte_identical"
                ),
            }
        )
    return expected, records


def _observed_output_files(
    output: Path,
    *,
    limits: Limits,
) -> tuple[dict[str, Path], set[str]]:
    try:
        output_snapshot = snapshot_verified_directory(output)
    except FileIdentityChangedError as exc:
        raise PrepareWorkflowError("output_invalid", exit_code=2) from exc
    observed: dict[str, Path] = {}
    observed_directories: set[str] = set()
    total = 0
    count = 0
    for directory, dir_names, file_names in os.walk(output, followlinks=False):
        base = Path(directory)
        base_status = _plain_status(base, code="output_invalid")
        if not stat.S_ISDIR(base_status.st_mode):
            raise PrepareWorkflowError("output_invalid", exit_code=2)
        try:
            depth = len(base.relative_to(output).parts)
        except ValueError as exc:
            raise PrepareWorkflowError("output_invalid", exit_code=2) from exc
        if depth > limits.max_directory_depth:
            raise PrepareWorkflowError("output_limit", exit_code=2)
        if depth:
            observed_directories.add(base.relative_to(output).as_posix())
            count += 1
            if count > limits.max_files:
                raise PrepareWorkflowError("output_limit", exit_code=2)
        dir_names.sort(key=str.casefold)
        file_names.sort(key=str.casefold)
        for name in dir_names:
            child = base / name
            child_status = _plain_status(child, code="output_invalid")
            if not stat.S_ISDIR(child_status.st_mode):
                raise PrepareWorkflowError("output_invalid", exit_code=2)
        for name in file_names:
            child = base / name
            child_status = _plain_status(child, code="output_invalid")
            if (
                not stat.S_ISREG(child_status.st_mode)
                or getattr(child_status, "st_nlink", 1) != 1
            ):
                raise PrepareWorkflowError("output_invalid", exit_code=2)
            count += 1
            total += child_status.st_size
            if (
                count > limits.max_files
                or child_status.st_size > limits.max_file_bytes
                or total > limits.max_total_file_bytes
            ):
                raise PrepareWorkflowError("output_limit", exit_code=2)
            relative = child.relative_to(output).as_posix()
            observed[relative] = child
    if not verify_directory_unchanged(output_snapshot):
        raise PrepareWorkflowError("output_changed_during_verify", exit_code=2)
    return observed, observed_directories


def _verify_output_tree(
    output: Path,
    expected: Mapping[str, _ExpectedOutput],
    *,
    limits: Limits,
) -> tuple[list[dict[str, Any]], int]:
    issues: list[dict[str, Any]] = []
    try:
        observed, observed_directories = _observed_output_files(output, limits=limits)
    except PrepareWorkflowError as exc:
        return [
            {
                "code": exc.code,
                "action_id": None,
                "path": "<new-bundle>",
            }
        ], 0

    expected_directories: set[str] = set()
    for path in expected:
        parts = path.split("/")
        expected_directories.update(
            "/".join(parts[:depth]) for depth in range(1, len(parts))
        )
    for path in sorted(observed_directories - expected_directories, key=str.casefold):
        issues.append(
            {
                "code": "unexpected_output_directory",
                "action_id": None,
                "path": _display_path(path, limits),
            }
        )
    for path in sorted(expected_directories - observed_directories, key=str.casefold):
        issues.append(
            {
                "code": "expected_output_directory_missing",
                "action_id": None,
                "path": _display_path(path, limits),
            }
        )

    for path in sorted(set(observed) - set(expected), key=str.casefold):
        issues.append(
            {
                "code": "unexpected_output_file",
                "action_id": None,
                "path": _display_path(path, limits),
            }
        )
    for path in sorted(set(expected) - set(observed), key=str.casefold):
        item = expected[path]
        issues.append(
            {
                "code": "expected_output_missing",
                "action_id": item.action_id,
                "path": _display_path(path, limits),
            }
        )

    for path in sorted(set(expected) & set(observed), key=str.casefold):
        item = expected[path]
        candidate = observed[path]
        try:
            status_value = candidate.lstat()
            handle, opened = open_verified_binary(candidate, expected=status_value)
            digest = hashlib.sha256()
            prefix = bytearray()
            size = 0
            with handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    digest.update(chunk)
                    if len(prefix) < 8192:
                        prefix.extend(chunk[: 8192 - len(prefix)])
                unchanged = verify_open_file_unchanged(handle, candidate, opened=opened)
            actual_digest = f"sha256:{digest.hexdigest()}"
            media_type = sniff(bytes(prefix), path).media_type
            matches = (
                unchanged
                and size == item.size
                and hmac.compare_digest(actual_digest, item.digest)
                and media_type == item.media_type
            )
        except (FileIdentityChangedError, OSError):
            matches = False
        if not matches:
            issues.append(
                {
                    "code": "output_relation_mismatch",
                    "action_id": item.action_id,
                    "path": _display_path(path, limits),
                }
            )
    return issues, len(observed)


def _scan_output(
    output: Path,
    *,
    limits: Limits,
    optional_tools: bool,
    evidence_key: bytes,
):
    scanner = Scanner(
        ScanConfig(
            limits=limits,
            optional_tools=optional_tools,
            logical_paths=True,
        ),
        evidence_key=evidence_key,
    )
    builder = scanner.scan([output])
    return builder, builder.to_dict()


def _scan_snapshot_issues(
    report: Mapping[str, Any],
    expected: Mapping[str, _ExpectedOutput],
    *,
    limits: Limits,
) -> list[dict[str, Any]]:
    """Bind the final scanner's exact file reads to expected output bytes."""

    expected_signatures = Counter(
        (
            _display_path(item.target_path, limits),
            item.media_type,
            item.size,
            item.content_token,
        )
        for item in expected.values()
    )
    observed_signatures: Counter[tuple[object, object, object, object]] = Counter()
    artifacts = report.get("artifacts", [])
    if isinstance(artifacts, list):
        for artifact in artifacts:
            if not isinstance(artifact, Mapping):
                continue
            token = artifact.get("content_token")
            if not isinstance(token, str):
                continue
            observed_signatures[
                (
                    artifact.get("path"),
                    artifact.get("media_type"),
                    artifact.get("size"),
                    token,
                )
            ] += 1
    if observed_signatures == expected_signatures:
        return []
    return [
        {
            "code": "final_scan_snapshot_mismatch",
            "action_id": None,
            "path": "<new-bundle>",
        }
    ]


def _merge_issues(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[object, object, object]] = set()
    for group in groups:
        for issue in group:
            key = (issue.get("code"), issue.get("action_id"), issue.get("path"))
            if key not in seen:
                seen.add(key)
                merged.append(issue)
    return merged


def _minimal_final_scan_for_result(
    final_scan: Mapping[str, Any],
    *,
    max_report_bytes: int,
) -> dict[str, Any]:
    """Preserve a valid explicit coverage gap when scan detail cannot fit."""

    run = final_scan["run"]
    gap = {
        "id": stable_id(
            "g",
            None,
            "reporting",
            "prepare_result_size_limit",
            _RESULT_SIZE_GAP_DETAIL,
        ),
        "artifact_id": None,
        "capability": "reporting",
        "reason": "prepare_result_size_limit",
        "detail": _RESULT_SIZE_GAP_DETAIL,
    }
    return {
        "schema": "sharesafe.report/v1",
        "tool": dict(final_scan["tool"]),
        "run": {
            "id": run["id"],
            "started_at": run["started_at"],
            "offline": True,
            "report_mode": run["report_mode"],
            "limits": {"max_report_bytes": max_report_bytes},
        },
        "summary": {
            "verdict": "incomplete",
            "artifacts_total": 0,
            "artifacts_complete": 0,
            "artifacts_partial": 0,
            "findings": {
                "info": 0,
                "low": 0,
                "medium": 0,
                "high": 0,
                "critical": 0,
            },
            "gaps": 1,
            "errors": 0,
        },
        "artifacts": [],
        "findings": [],
        "gaps": [gap],
        "errors": [],
        "dependencies": [],
    }


def _raw_result_payload(
    *,
    operation: str,
    tool_version: str,
    plan: PreparePlan,
    action_records: list[dict[str, Any]],
    action_records_total: int,
    issues: list[dict[str, Any]],
    issues_total: int,
    observed_count: int,
    final_scan: dict[str, Any],
    final_scan_detail: str,
    commit_state: str,
    commit_mode: str | None,
    max_report_bytes: int,
    truncated: bool,
) -> dict[str, Any]:
    action_counts = dict(sorted(Counter(item.action for item in plan.actions).items()))
    exact = not issues and not truncated
    scan_verdict = final_scan.get("summary", {}).get("verdict")
    ready = exact and scan_verdict == "no_findings"
    actions_reported = len(action_records)
    issues_reported = len(issues)
    return {
        "schema": PREPARE_RESULT_SCHEMA,
        "tool": {"name": "sharesafe", "version": tool_version},
        "operation": operation,
        "source": "<selected-source>",
        "output": "<new-bundle>",
        "plan_summary": {
            "action_count": len(plan.actions),
            "action_counts": action_counts,
            "action_results_reported": actions_reported,
            "action_results_omitted": action_records_total - actions_reported,
        },
        "actions": action_records,
        "commit": {"state": commit_state, "mode": commit_mode},
        "verification": {
            "outcome": "verified" if exact else "incomplete",
            "source_snapshot": "matched",
            "expected_files": sum(
                1 for item in plan.actions if item.action in _INCLUDE_ACTIONS
            ),
            "observed_files": observed_count,
            "issue_count": issues_total,
            "issues_reported": issues_reported,
            "issues_omitted": issues_total - issues_reported,
            "issues": issues,
        },
        "final_scan": final_scan,
        "reporting": {
            "detail": "truncated" if truncated else "complete",
            "final_scan_detail": final_scan_detail,
            "max_bytes": max_report_bytes,
        },
        "ready_for_review": ready,
        "statement": (
            "The complete prepare result exceeded the configured report byte limit; omitted details and the output require review before sharing."
            if truncated
            else "The approved output relations were verified and no findings were observed within completed coverage; this is not a sharing guarantee."
            if ready
            else "Exact output relations, residual findings, or coverage gaps require review before sharing."
        ),
    }


def _largest_fitting_prefix(
    records: list[dict[str, Any]],
    *,
    minimum: int,
    build,
    max_bytes: int,
) -> int:
    low = minimum
    high = len(records)
    while low < high:
        middle = (low + high + 1) // 2
        if json_within_byte_limit(build(records[:middle]), max_bytes):
            low = middle
        else:
            high = middle - 1
    return low


def _result_payload(
    *,
    operation: str,
    tool_version: str,
    plan: PreparePlan,
    action_records: list[dict[str, Any]],
    issues: list[dict[str, Any]],
    observed_count: int,
    final_scan: dict[str, Any],
    commit_state: str,
    commit_mode: str | None,
    limits: Limits,
) -> dict[str, Any]:
    """Return a complete bounded result, degrading explicitly when necessary."""

    def build(
        selected_actions: list[dict[str, Any]],
        selected_issues: list[dict[str, Any]],
        selected_scan: dict[str, Any],
        *,
        scan_detail: str,
        truncated: bool,
        issue_total: int,
    ) -> dict[str, Any]:
        return _raw_result_payload(
            operation=operation,
            tool_version=tool_version,
            plan=plan,
            action_records=selected_actions,
            action_records_total=len(action_records),
            issues=selected_issues,
            issues_total=issue_total,
            observed_count=observed_count,
            final_scan=selected_scan,
            final_scan_detail=scan_detail,
            commit_state=commit_state,
            commit_mode=commit_mode,
            max_report_bytes=limits.max_report_bytes,
            truncated=truncated,
        )

    payload = build(
        action_records,
        issues,
        final_scan,
        scan_detail="complete",
        truncated=False,
        issue_total=len(issues),
    )
    if json_within_byte_limit(payload, limits.max_report_bytes):
        validate_masked_payload(payload, limits=limits)
        return payload

    bounded_issues = _merge_issues([dict(_RESULT_SIZE_ISSUE)], issues)
    issue_total = len(bounded_issues)
    scan_options = (
        (final_scan, "complete"),
        (
            _minimal_final_scan_for_result(
                final_scan,
                max_report_bytes=limits.max_report_bytes,
            ),
            "summarized",
        ),
    )
    selected_scan: dict[str, Any] | None = None
    selected_scan_detail = "summarized"
    for candidate_scan, candidate_detail in scan_options:
        candidate = build(
            [],
            bounded_issues[:1],
            candidate_scan,
            scan_detail=candidate_detail,
            truncated=True,
            issue_total=issue_total,
        )
        if json_within_byte_limit(candidate, limits.max_report_bytes):
            selected_scan = candidate_scan
            selected_scan_detail = candidate_detail
            break
    if selected_scan is None:
        raise PrepareWorkflowError(
            "prepare_result_control_budget",
            exit_code=2,
            output_may_exist=commit_state == "committed",
        )

    def with_issues(selected: list[dict[str, Any]]) -> dict[str, Any]:
        return build(
            [],
            selected,
            selected_scan,
            scan_detail=selected_scan_detail,
            truncated=True,
            issue_total=issue_total,
        )

    issue_prefix = _largest_fitting_prefix(
        bounded_issues,
        minimum=1,
        build=with_issues,
        max_bytes=limits.max_report_bytes,
    )
    selected_issues = bounded_issues[:issue_prefix]

    def with_actions(selected: list[dict[str, Any]]) -> dict[str, Any]:
        return build(
            selected,
            selected_issues,
            selected_scan,
            scan_detail=selected_scan_detail,
            truncated=True,
            issue_total=issue_total,
        )

    action_prefix = _largest_fitting_prefix(
        action_records,
        minimum=0,
        build=with_actions,
        max_bytes=limits.max_report_bytes,
    )
    payload = with_actions(action_records[:action_prefix])
    validate_masked_payload(payload, limits=limits)
    if not json_within_byte_limit(payload, limits.max_report_bytes):
        raise PrepareWorkflowError(
            "prepare_result_control_budget",
            exit_code=2,
            output_may_exist=commit_state == "committed",
        )
    return payload


def _exit_code(
    *,
    issues: list[dict[str, Any]],
    builder,
    fail_on: str,
    result_incomplete: bool = False,
) -> int:
    scan_code = builder.exit_code(fail_on)
    if issues or result_incomplete or scan_code == 2:
        return 2
    return scan_code


def apply_prepare_plan(
    source: str | os.PathLike[str],
    output: str | os.PathLike[str],
    plan: PreparePlan | Mapping[str, Any],
    approval: PrepareApproval | Mapping[str, Any],
    *,
    limits: Limits | None = None,
    optional_tools: bool = True,
    fail_on: str = "high",
    tool_version: str = "0.0.0",
) -> PrepareExecutionResult:
    """Apply an approved plan into one new directory and verify it."""

    effective_limits = limits or Limits()
    validated = assert_source_matches_plan(source, plan, limits=effective_limits)
    if not validated.executable:
        raise PrepareWorkflowError("plan_not_executable")
    _validated_approval(approval, plan=validated)
    source_path = Path(source).absolute()
    output_path = Path(output).absolute()
    parent_snapshot = _check_output_boundary(source_path, output_path)
    # Build outside the destination parent so replacing that parent cannot
    # redirect pre-commit payload writes into an attacker-selected directory.
    try:
        stage_snapshot = create_private_temporary_directory(
            prefix=".sharesafe-prepare-"
        )
    except PrepareIOError as exc:
        raise PrepareWorkflowError("private_staging_unavailable", exit_code=4) from exc
    stage_root = stage_snapshot.path
    staged_payload = stage_root / "payload"
    staged_payload.mkdir(mode=0o700)
    committed = False
    commit_mode: str | None = None
    evidence_key = temporary_hmac_key()
    try:
        expected, action_records = _build_staged_tree(
            source_path,
            staged_payload,
            validated,
            limits=effective_limits,
            evidence_key=evidence_key,
        )
        # A second full inventory checkpoint catches additions, removals, and
        # replacements that happened while individual actions were built.
        assert_source_matches_plan(source_path, validated, limits=effective_limits)
        staged_issues, staged_count = _verify_output_tree(
            staged_payload,
            expected,
            limits=effective_limits,
        )
        if staged_issues or staged_count != len(expected):
            raise PrepareWorkflowError("staging_verification_failed", exit_code=2)
        commit_mode = _commit_directory_no_overwrite(
            staged_payload,
            output_path,
            parent_snapshot=parent_snapshot,
        )
        committed = True
        pre_scan_issues, observed_count = _verify_output_tree(
            output_path,
            expected,
            limits=effective_limits,
        )
        builder, final_scan = _scan_output(
            output_path,
            limits=effective_limits,
            optional_tools=optional_tools,
            evidence_key=evidence_key,
        )
        binding_issues = _scan_snapshot_issues(
            final_scan,
            expected,
            limits=effective_limits,
        )
        post_scan_issues, post_scan_count = _verify_output_tree(
            output_path,
            expected,
            limits=effective_limits,
        )
        issues = _merge_issues(pre_scan_issues, binding_issues, post_scan_issues)
        observed_count = post_scan_count
        payload = _result_payload(
            operation="apply",
            tool_version=tool_version,
            plan=validated,
            action_records=action_records,
            issues=issues,
            observed_count=observed_count,
            final_scan=final_scan,
            commit_state="committed",
            commit_mode=commit_mode,
            limits=effective_limits,
        )
        return PrepareExecutionResult(
            payload=payload,
            exit_code=_exit_code(
                issues=issues,
                builder=builder,
                fail_on=fail_on,
                result_incomplete=payload["reporting"]["detail"] != "complete",
            ),
        )
    except PrepareWorkflowError:
        raise
    except (OSError, ValueError) as exc:
        raise PrepareWorkflowError(
            "apply_failed",
            exit_code=4,
            output_may_exist=committed or output_path.exists(),
        ) from exc
    finally:
        # Never recurse through a replaced output parent.  A private orphan is
        # safer than deleting an attacker-selected path.
        if verify_directory_unchanged(stage_snapshot):
            shutil.rmtree(stage_root, ignore_errors=True)


def verify_prepare_output(
    source: str | os.PathLike[str],
    output: str | os.PathLike[str],
    plan: PreparePlan | Mapping[str, Any],
    *,
    limits: Limits | None = None,
    optional_tools: bool = True,
    fail_on: str = "high",
    tool_version: str = "0.0.0",
) -> PrepareExecutionResult:
    """Recompute expected bytes from the bound source and verify an output."""

    effective_limits = limits or Limits()
    validated = assert_source_matches_plan(source, plan, limits=effective_limits)
    if not validated.executable:
        raise PrepareWorkflowError("plan_not_executable")
    source_path = Path(source).absolute()
    output_path = Path(output).absolute()
    if uses_windows_alternate_stream(output_path):
        raise PrepareWorkflowError("unsafe_path")
    try:
        overlaps = same_or_within(output_path, source_path) or same_or_within(
            source_path,
            output_path,
        )
    except ValueError as exc:
        raise PrepareWorkflowError("unsafe_path") from exc
    if overlaps:
        raise PrepareWorkflowError("overlapping_boundaries")
    evidence_key = temporary_hmac_key()
    expected, action_records = _expected_from_source(
        source_path,
        validated,
        limits=effective_limits,
        evidence_key=evidence_key,
    )
    assert_source_matches_plan(source_path, validated, limits=effective_limits)
    pre_scan_issues, observed_count = _verify_output_tree(
        output_path,
        expected,
        limits=effective_limits,
    )
    builder, final_scan = _scan_output(
        output_path,
        limits=effective_limits,
        optional_tools=optional_tools,
        evidence_key=evidence_key,
    )
    binding_issues = _scan_snapshot_issues(
        final_scan,
        expected,
        limits=effective_limits,
    )
    post_scan_issues, post_scan_count = _verify_output_tree(
        output_path,
        expected,
        limits=effective_limits,
    )
    issues = _merge_issues(pre_scan_issues, binding_issues, post_scan_issues)
    observed_count = post_scan_count
    payload = _result_payload(
        operation="verify",
        tool_version=tool_version,
        plan=validated,
        action_records=action_records,
        issues=issues,
        observed_count=observed_count,
        final_scan=final_scan,
        commit_state="not_applicable",
        commit_mode=None,
        limits=effective_limits,
    )
    return PrepareExecutionResult(
        payload=payload,
        exit_code=_exit_code(
            issues=issues,
            builder=builder,
            fail_on=fail_on,
            result_incomplete=payload["reporting"]["detail"] != "complete",
        ),
    )


def prepare_inspection(
    plan: PreparePlan | Mapping[str, Any],
) -> dict[str, Any]:
    """Return a masked review view without source bindings or plan digests."""

    validated = _validated_plan(plan)
    counts = dict(sorted(Counter(item.action for item in validated.actions).items()))
    return {
        "schema": "sharesafe.prepare-inspection/v1",
        "classification": "local_masked",
        "executable": validated.executable,
        "item_count": validated.item_count,
        "action_counts": counts,
        "actions": [
            {
                "action_id": item.action_id,
                "source_path": sanitize_display_path(item.source_path),
                "target_path": (
                    sanitize_display_path(item.target_path)
                    if item.target_path is not None
                    else None
                ),
                "action": item.action,
                "reason_code": item.reason_code,
                "media_type": item.media_type,
                "expected_relation": item.expected_relation,
                "known_losses": list(item.known_losses),
            }
            for item in validated.actions
        ],
    }


__all__ = [
    "PREPARE_RESULT_SCHEMA",
    "PrepareExecutionResult",
    "PrepareWorkflowError",
    "apply_prepare_plan",
    "assert_source_matches_plan",
    "prepare_inspection",
    "verify_prepare_output",
]
