"""Strict local-control plans and approvals for ShareSafe prepare operations.

The objects in this module are deliberately *not* shareable reports.  A plan
contains stable SHA-256 bindings for every source file so a later apply step can
fail closed when the selected source tree has drifted.  An approval binds the
exact canonical plan and the complete set of action identifiers; neither object
grants permission to upload data or to alter the source tree.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .limits import Limits
from .safe_io import (
    FileIdentityChangedError,
    file_identity,
    open_verified_binary,
    verify_open_file_unchanged,
)
from .sniff import sniff

PLAN_SCHEMA = "sharesafe.prepare-plan/v1"
APPROVAL_SCHEMA = "sharesafe.prepare-approval/v1"
LOCAL_CLASSIFICATION = "local_only_do_not_share"
SOURCE_BOUNDARY = "<selected-source>"
DESTINATION_BOUNDARY = "<new-bundle>"

_MAX_ACTIONS = 999_999
_MAX_PORTABLE_PATH_BYTES = 4096
_ACTION_ID_RE = re.compile(r"^prepare-action-[0-9]{6}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REASON_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_WINDOWS_RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    "clock$",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}
_INVALID_WINDOWS_CHARS = frozenset('<>:"\\|?*')

_ACTION_FIELDS = {
    "action_id",
    "source_path",
    "target_path",
    "action",
    "reason_code",
    "media_type",
    "source_binding",
    "approval_required",
    "expected_relation",
    "known_losses",
}
_PLAN_FIELDS = {
    "schema",
    "classification",
    "source_boundary",
    "destination_boundary",
    "item_count",
    "actions",
    "plan_digest",
}
_APPROVAL_FIELDS = {
    "schema",
    "classification",
    "status",
    "plan_digest",
    "approved_action_ids",
    "approval_digest",
}
_DECISION_FIELDS = {"source_path", "target_path", "action", "reason_code"}
_BINDING_FIELDS = {"algorithm", "digest", "size"}


@dataclass(frozen=True, slots=True)
class _ActionContract:
    approval_required: bool
    expected_relation: str
    known_losses: tuple[str, ...]
    target_mode: str
    media_types: frozenset[str] | None = None
    executable: bool = True


_ACTION_CONTRACTS: dict[str, _ActionContract] = {
    "copy_unchanged": _ActionContract(True, "byte_identical", (), "same"),
    "strip_ooxml_metadata": _ActionContract(
        True,
        "metadata_reduced_format_preserved",
        ("document_metadata_removed",),
        "same",
        frozenset(
            {
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            }
        ),
    ),
    "strip_png_metadata": _ActionContract(
        True,
        "metadata_reduced_format_preserved",
        ("image_metadata_removed",),
        "same",
        frozenset({"image/png"}),
    ),
    "strip_jpeg_metadata": _ActionContract(
        True,
        "metadata_reduced_format_preserved",
        ("image_metadata_removed",),
        "same",
        frozenset({"image/jpeg"}),
    ),
    "omit_from_boundary": _ActionContract(
        True,
        "absent_from_output",
        ("file_omitted",),
        "none",
    ),
    "rename_in_bundle": _ActionContract(
        True,
        "byte_identical",
        ("bundle_path_changed",),
        "different",
    ),
    "manual_or_external_required": _ActionContract(
        False,
        "not_applicable",
        (),
        "none",
        executable=False,
    ),
    "block": _ActionContract(
        False,
        "not_applicable",
        (),
        "none",
        executable=False,
    ),
}


class PreparePlanError(ValueError):
    """Stable, non-sensitive failure raised for invalid control artifacts."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code.replace("_", " "))


@dataclass(frozen=True, slots=True)
class SourceBinding:
    algorithm: str
    digest: str
    size: int

    def to_dict(self) -> dict[str, object]:
        return {"algorithm": self.algorithm, "digest": self.digest, "size": self.size}


@dataclass(frozen=True, slots=True)
class PrepareAction:
    action_id: str
    source_path: str
    target_path: str | None
    action: str
    reason_code: str
    media_type: str
    source_binding: SourceBinding
    approval_required: bool
    expected_relation: str
    known_losses: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "action_id": self.action_id,
            "source_path": self.source_path,
            "target_path": self.target_path,
            "action": self.action,
            "reason_code": self.reason_code,
            "media_type": self.media_type,
            "source_binding": self.source_binding.to_dict(),
            "approval_required": self.approval_required,
            "expected_relation": self.expected_relation,
            "known_losses": list(self.known_losses),
        }


@dataclass(frozen=True, slots=True)
class PreparePlan:
    schema: str
    classification: str
    source_boundary: str
    destination_boundary: str
    item_count: int
    actions: tuple[PrepareAction, ...]
    plan_digest: str

    @property
    def executable(self) -> bool:
        return all(_ACTION_CONTRACTS[item.action].executable for item in self.actions)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "classification": self.classification,
            "source_boundary": self.source_boundary,
            "destination_boundary": self.destination_boundary,
            "item_count": self.item_count,
            "actions": [item.to_dict() for item in self.actions],
            "plan_digest": self.plan_digest,
        }


@dataclass(frozen=True, slots=True)
class PrepareApproval:
    schema: str
    classification: str
    status: str
    plan_digest: str
    approved_action_ids: tuple[str, ...]
    approval_digest: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "classification": self.classification,
            "status": self.status,
            "plan_digest": self.plan_digest,
            "approved_action_ids": list(self.approved_action_ids),
            "approval_digest": self.approval_digest,
        }


@dataclass(frozen=True, slots=True)
class _InventoryItem:
    path: Path
    status: os.stat_result
    binding: SourceBinding
    media_type: str


def _canonical_json_without(payload: Mapping[str, Any], field: str) -> bytes:
    if not isinstance(payload, Mapping):
        raise TypeError("digest payload must be a mapping")
    value = {key: item for key, item in payload.items() if key != field}
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise PreparePlanError("noncanonical_payload") from exc
    return encoded


def canonical_plan_digest(payload: Mapping[str, Any]) -> str:
    """Return the SHA-256 of canonical UTF-8 JSON excluding ``plan_digest``."""

    return f"sha256:{hashlib.sha256(_canonical_json_without(payload, 'plan_digest')).hexdigest()}"


def canonical_approval_digest(payload: Mapping[str, Any]) -> str:
    """Return the SHA-256 of canonical UTF-8 JSON excluding ``approval_digest``."""

    return f"sha256:{hashlib.sha256(_canonical_json_without(payload, 'approval_digest')).hexdigest()}"


def _is_reparse(status_value: os.stat_result) -> bool:
    attributes = getattr(status_value, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _absolute_without_link_resolution(path: Path) -> Path:
    try:
        return Path(os.path.abspath(os.fspath(path)))
    except (OSError, TypeError, ValueError) as exc:
        raise PreparePlanError("invalid_source_boundary") from exc


def _assert_no_link_in_chain(path: Path) -> None:
    """Reject symlink/reparse components without resolving through them."""

    absolute = _absolute_without_link_resolution(path)
    anchor = Path(absolute.anchor)
    cursor = anchor
    parts = absolute.parts[1:] if absolute.anchor else absolute.parts
    for part in parts:
        cursor = cursor / part
        try:
            status_value = cursor.lstat()
        except FileNotFoundError as exc:
            raise PreparePlanError("source_not_found") from exc
        except OSError as exc:
            raise PreparePlanError("source_unreadable") from exc
        if stat.S_ISLNK(status_value.st_mode) or _is_reparse(status_value):
            raise PreparePlanError("unsafe_source_link")


def _portable_path_parts(value: str, *, limits: Limits) -> tuple[str, ...]:
    if not isinstance(value, str) or not value:
        raise PreparePlanError("invalid_relative_path")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise PreparePlanError("invalid_relative_path") from exc
    if (
        len(encoded) > _MAX_PORTABLE_PATH_BYTES
        or value.startswith(("/", "\\"))
        or _WINDOWS_DRIVE_RE.match(value)
        or "\\" in value
    ):
        raise PreparePlanError("invalid_relative_path")
    parts = value.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise PreparePlanError("invalid_relative_path")
    for part in parts:
        try:
            part_size = len(part.encode("utf-8", "strict"))
        except UnicodeEncodeError as exc:
            raise PreparePlanError("invalid_relative_path") from exc
        if (
            part_size > min(255, limits.max_name_bytes)
            or part.endswith((" ", "."))
            or any(character in _INVALID_WINDOWS_CHARS for character in part)
            or any(ord(character) < 32 or ord(character) == 127 for character in part)
            or part.split(".", 1)[0].casefold() in _WINDOWS_RESERVED
        ):
            raise PreparePlanError("invalid_relative_path")
    return tuple(parts)


def _portable_key_parts(value: str, *, limits: Limits) -> tuple[str, ...]:
    return tuple(
        unicodedata.normalize("NFC", part).casefold()
        for part in _portable_path_parts(value, limits=limits)
    )


def _portable_sort_key(
    value: str, *, limits: Limits
) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    parts = _portable_path_parts(value, limits=limits)
    normalized = tuple(unicodedata.normalize("NFC", part) for part in parts)
    return tuple(part.casefold() for part in normalized), normalized, value


def _validate_portable_file_tree(paths: Iterable[str], *, limits: Limits) -> None:
    """Reject file collisions and inconsistent spellings of parent folders."""

    file_keys: set[tuple[str, ...]] = set()
    parent_spellings: dict[tuple[str, ...], tuple[str, ...]] = {}
    for value in paths:
        parts = _portable_path_parts(value, limits=limits)
        normalized = tuple(unicodedata.normalize("NFC", part) for part in parts)
        key = tuple(part.casefold() for part in normalized)
        if key in file_keys:
            raise PreparePlanError("portable_path_collision")
        for depth in range(1, len(parts)):
            parent_key = key[:depth]
            spelling = normalized[:depth]
            existing = parent_spellings.get(parent_key)
            if existing is not None and existing != spelling:
                raise PreparePlanError("portable_path_collision")
            parent_spellings[parent_key] = spelling
        file_keys.add(key)
    for key in file_keys:
        if any(key[:depth] in file_keys for depth in range(1, len(key))):
            raise PreparePlanError("portable_path_collision")


def _validate_source_target_separation(
    actions: Iterable[PrepareAction],
    *,
    limits: Limits,
) -> None:
    """Keep omitted and renamed-away source names absent from the bundle.

    A different source item may not be targeted at a path that this plan says
    is omitted or renamed away.  Without this invariant, verification could
    observe the old name and could not prove the intended absence/rename
    relation even though target paths remained unique.
    """

    materialized = {
        _portable_key_parts(action.target_path, limits=limits)
        for action in actions
        if action.target_path is not None
    }
    for action in actions:
        source_key = _portable_key_parts(action.source_path, limits=limits)
        if action.action in {"omit_from_boundary", "rename_in_bundle"}:
            for target_key in materialized:
                if target_key[: len(source_key)] == source_key:
                    raise PreparePlanError("source_target_alias_collision")


def _discover_source(
    source: Path,
    *,
    limits: Limits,
) -> tuple[dict[str, tuple[Path, os.stat_result]], dict[str, os.stat_result]]:
    """Enumerate regular files and directory identities without following links."""

    try:
        root_status = source.lstat()
    except FileNotFoundError as exc:
        raise PreparePlanError("source_not_found") from exc
    except OSError as exc:
        raise PreparePlanError("source_unreadable") from exc
    if stat.S_ISLNK(root_status.st_mode) or _is_reparse(root_status):
        raise PreparePlanError("unsafe_source_link")

    files: dict[str, tuple[Path, os.stat_result]] = {}
    directories: dict[str, os.stat_result] = {}
    total_bytes = 0

    def add_file(relative: str, path: Path, status_value: os.stat_result) -> None:
        nonlocal total_bytes
        _portable_path_parts(relative, limits=limits)
        if getattr(status_value, "st_nlink", 1) != 1:
            raise PreparePlanError("unsafe_source_hardlink")
        if status_value.st_size < 0 or status_value.st_size > limits.max_file_bytes:
            raise PreparePlanError("source_file_limit")
        total_bytes += status_value.st_size
        if total_bytes > limits.max_total_file_bytes:
            raise PreparePlanError("source_total_size_limit")
        if len(files) >= min(limits.max_files, _MAX_ACTIONS):
            raise PreparePlanError("source_file_count_limit")
        files[relative] = (path, status_value)

    if stat.S_ISREG(root_status.st_mode):
        add_file(source.name, source, root_status)
        return files, directories
    if not stat.S_ISDIR(root_status.st_mode):
        raise PreparePlanError("unsupported_source_entry")

    directories[""] = root_status

    def walk(directory: Path, relative_parts: tuple[str, ...]) -> None:
        if len(relative_parts) > limits.max_directory_depth:
            raise PreparePlanError("source_directory_depth_limit")
        try:
            with os.scandir(directory) as iterator:
                entries = list(iterator)
        except OSError as exc:
            raise PreparePlanError("source_unreadable") from exc
        entries.sort(
            key=lambda entry: (
                unicodedata.normalize("NFC", entry.name).casefold(),
                unicodedata.normalize("NFC", entry.name),
                entry.name,
            )
        )
        for entry in entries:
            child_parts = (*relative_parts, entry.name)
            relative = "/".join(child_parts)
            _portable_path_parts(relative, limits=limits)
            child = directory / entry.name
            try:
                # ``DirEntry.stat(follow_symlinks=False)`` can expose zeroed
                # identity/link fields on some Windows filesystems.  A direct
                # lstat gives the same no-follow semantics with usable values
                # for the later descriptor comparison.
                child_status = child.lstat()
            except OSError as exc:
                raise PreparePlanError("source_changed") from exc
            if stat.S_ISLNK(child_status.st_mode) or _is_reparse(child_status):
                raise PreparePlanError("unsafe_source_link")
            if stat.S_ISDIR(child_status.st_mode):
                directories[relative] = child_status
                walk(child, child_parts)
            elif stat.S_ISREG(child_status.st_mode):
                add_file(relative, child, child_status)
            else:
                raise PreparePlanError("unsupported_source_entry")

    walk(source, ())
    _validate_portable_file_tree(files, limits=limits)
    return files, directories


def _hash_inventory_item(
    relative: str,
    path: Path,
    expected: os.stat_result,
) -> _InventoryItem:
    digest = hashlib.sha256()
    prefix = bytearray()
    size = 0
    try:
        handle, opened = open_verified_binary(path, expected=expected)
        try:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
                if len(prefix) < 8192:
                    prefix.extend(chunk[: 8192 - len(prefix)])
            if size != opened.st_size or not verify_open_file_unchanged(
                handle,
                path,
                opened=opened,
            ):
                raise PreparePlanError("source_changed")
        finally:
            handle.close()
    except FileIdentityChangedError as exc:
        raise PreparePlanError("source_changed") from exc
    except PreparePlanError:
        raise
    except OSError as exc:
        raise PreparePlanError("source_unreadable") from exc
    media_type = sniff(bytes(prefix), relative).media_type
    return _InventoryItem(
        path=path,
        status=expected,
        binding=SourceBinding("sha256", f"sha256:{digest.hexdigest()}", size),
        media_type=media_type,
    )


def _verify_discovery_unchanged(
    before_files: Mapping[str, tuple[Path, os.stat_result]],
    before_directories: Mapping[str, os.stat_result],
    after_files: Mapping[str, tuple[Path, os.stat_result]],
    after_directories: Mapping[str, os.stat_result],
) -> None:
    if (
        before_files.keys() != after_files.keys()
        or before_directories.keys() != after_directories.keys()
    ):
        raise PreparePlanError("source_changed")
    for relative in before_files:
        if file_identity(before_files[relative][1]) != file_identity(
            after_files[relative][1]
        ):
            raise PreparePlanError("source_changed")
    for relative in before_directories:
        if file_identity(before_directories[relative]) != file_identity(
            after_directories[relative]
        ):
            raise PreparePlanError("source_changed")


def _inventory(source: Path, *, limits: Limits) -> dict[str, _InventoryItem]:
    source = _absolute_without_link_resolution(source)
    _assert_no_link_in_chain(source)
    discovered, directories = _discover_source(source, limits=limits)
    inventory = {
        relative: _hash_inventory_item(relative, path, status_value)
        for relative, (path, status_value) in discovered.items()
    }
    discovered_after, directories_after = _discover_source(source, limits=limits)
    _verify_discovery_unchanged(
        discovered,
        directories,
        discovered_after,
        directories_after,
    )
    _assert_no_link_in_chain(source)
    return inventory


def _exact_fields(value: Mapping[str, Any], expected: set[str], *, prefix: str) -> None:
    if not isinstance(value, Mapping):
        raise PreparePlanError(f"invalid_{prefix}_type")
    actual = set(value.keys())
    if any(not isinstance(key, str) for key in actual):
        raise PreparePlanError(f"unknown_{prefix}_field")
    if actual - expected:
        raise PreparePlanError(f"unknown_{prefix}_field")
    if expected - actual:
        raise PreparePlanError(f"missing_{prefix}_field")


def _strict_string(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise PreparePlanError(code)
    return value


def _strict_nonnegative_int(value: Any, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PreparePlanError(code)
    return value


def _validate_reason(value: str) -> None:
    if len(value) > 64 or _REASON_RE.fullmatch(value) is None:
        raise PreparePlanError("invalid_reason_code")


def _contract_for(action: str) -> _ActionContract:
    try:
        return _ACTION_CONTRACTS[action]
    except KeyError as exc:
        raise PreparePlanError("unsupported_action") from exc


def _validate_target_contract(
    action: str,
    source_path: str,
    target_path: str | None,
    *,
    limits: Limits,
) -> None:
    contract = _contract_for(action)
    if contract.target_mode == "none":
        if target_path is not None:
            raise PreparePlanError("action_target_mismatch")
        return
    if target_path is None:
        raise PreparePlanError("action_target_mismatch")
    _portable_path_parts(target_path, limits=limits)
    if contract.target_mode == "same" and target_path != source_path:
        raise PreparePlanError("action_target_mismatch")
    if contract.target_mode == "different" and (
        target_path == source_path
        or _portable_key_parts(target_path, limits=limits)
        == _portable_key_parts(source_path, limits=limits)
    ):
        raise PreparePlanError("action_target_mismatch")


def _validate_action_contract(
    action: PrepareAction, *, limits: Limits, parsing: bool
) -> None:
    contract = _contract_for(action.action)
    try:
        _validate_target_contract(
            action.action,
            action.source_path,
            action.target_path,
            limits=limits,
        )
    except PreparePlanError as exc:
        if parsing and exc.code == "action_target_mismatch":
            raise PreparePlanError("action_contract_mismatch") from exc
        raise
    if (
        contract.media_types is not None
        and action.media_type not in contract.media_types
    ):
        raise PreparePlanError(
            "action_contract_mismatch" if parsing else "action_media_mismatch"
        )
    if (
        action.approval_required is not contract.approval_required
        or action.expected_relation != contract.expected_relation
        or action.known_losses != contract.known_losses
    ):
        raise PreparePlanError("action_contract_mismatch")


def create_prepare_plan(
    source: str | os.PathLike[str],
    decisions: Iterable[Mapping[str, Any]],
    *,
    limits: Limits | None = None,
) -> PreparePlan:
    """Create a deterministic, complete, local-only plan for ``source``."""

    effective_limits = limits or Limits()
    try:
        decision_values = list(decisions)
    except TypeError as exc:
        raise PreparePlanError("invalid_decisions_type") from exc
    if len(decision_values) > _MAX_ACTIONS:
        raise PreparePlanError("source_file_count_limit")

    decisions_by_source: dict[str, Mapping[str, Any]] = {}
    for decision in decision_values:
        _exact_fields(decision, _DECISION_FIELDS, prefix="decision")
        source_path = _strict_string(decision["source_path"], "invalid_relative_path")
        _portable_path_parts(source_path, limits=effective_limits)
        if source_path in decisions_by_source:
            raise PreparePlanError("duplicate_source_action")
        decisions_by_source[source_path] = decision

    # Reject malformed control input before spending time reading source bytes.
    # The source is still authoritative for completeness and media contracts.
    inventory = _inventory(Path(source), limits=effective_limits)
    if not inventory:
        raise PreparePlanError("source_inventory_empty")
    unknown = decisions_by_source.keys() - inventory.keys()
    if unknown:
        raise PreparePlanError("action_source_unknown")
    missing = inventory.keys() - decisions_by_source.keys()
    if missing:
        raise PreparePlanError("inventory_action_missing")

    ordered_sources = sorted(
        inventory,
        key=lambda value: _portable_sort_key(value, limits=effective_limits),
    )
    actions: list[PrepareAction] = []
    for index, source_path in enumerate(ordered_sources, 1):
        decision = decisions_by_source[source_path]
        action_name = _strict_string(decision["action"], "unsupported_action")
        contract = _contract_for(action_name)
        target_value = decision["target_path"]
        if target_value is not None and not isinstance(target_value, str):
            raise PreparePlanError("invalid_relative_path")
        target_path = target_value
        reason_code = _strict_string(decision["reason_code"], "invalid_reason_code")
        _validate_reason(reason_code)
        item = inventory[source_path]
        action = PrepareAction(
            action_id=f"prepare-action-{index:06d}",
            source_path=source_path,
            target_path=target_path,
            action=action_name,
            reason_code=reason_code,
            media_type=item.media_type,
            source_binding=item.binding,
            approval_required=contract.approval_required,
            expected_relation=contract.expected_relation,
            known_losses=contract.known_losses,
        )
        _validate_action_contract(action, limits=effective_limits, parsing=False)
        actions.append(action)

    _validate_portable_file_tree(
        (action.target_path for action in actions if action.target_path is not None),
        limits=effective_limits,
    )
    _validate_source_target_separation(actions, limits=effective_limits)
    payload: dict[str, object] = {
        "schema": PLAN_SCHEMA,
        "classification": LOCAL_CLASSIFICATION,
        "source_boundary": SOURCE_BOUNDARY,
        "destination_boundary": DESTINATION_BOUNDARY,
        "item_count": len(actions),
        "actions": [action.to_dict() for action in actions],
    }
    payload["plan_digest"] = canonical_plan_digest(payload)
    return _plan_from_validated_parts(payload, tuple(actions))


def _parse_binding(value: Any) -> SourceBinding:
    _exact_fields(value, _BINDING_FIELDS, prefix="source_binding")
    algorithm = _strict_string(value["algorithm"], "invalid_source_binding")
    digest = _strict_string(value["digest"], "invalid_source_binding")
    size = _strict_nonnegative_int(value["size"], "invalid_source_binding")
    if algorithm != "sha256" or _DIGEST_RE.fullmatch(digest) is None:
        raise PreparePlanError("invalid_source_binding")
    return SourceBinding(algorithm, digest, size)


def _parse_action(value: Any, *, limits: Limits) -> PrepareAction:
    _exact_fields(value, _ACTION_FIELDS, prefix="action")
    action_id = _strict_string(value["action_id"], "invalid_action_id")
    if _ACTION_ID_RE.fullmatch(action_id) is None:
        raise PreparePlanError("invalid_action_id")
    source_path = _strict_string(value["source_path"], "invalid_relative_path")
    _portable_path_parts(source_path, limits=limits)
    target_value = value["target_path"]
    if target_value is not None and not isinstance(target_value, str):
        raise PreparePlanError("invalid_relative_path")
    if isinstance(target_value, str):
        _portable_path_parts(target_value, limits=limits)
    action_name = _strict_string(value["action"], "unsupported_action")
    _contract_for(action_name)
    reason_code = _strict_string(value["reason_code"], "invalid_reason_code")
    _validate_reason(reason_code)
    media_type = _strict_string(value["media_type"], "invalid_media_type")
    if (
        not media_type
        or len(media_type) > 255
        or any(ord(char) < 32 for char in media_type)
    ):
        raise PreparePlanError("invalid_media_type")
    approval_required = value["approval_required"]
    if not isinstance(approval_required, bool):
        raise PreparePlanError("action_contract_mismatch")
    expected_relation = _strict_string(
        value["expected_relation"], "action_contract_mismatch"
    )
    known_losses_value = value["known_losses"]
    if not isinstance(known_losses_value, list) or not all(
        isinstance(item, str) for item in known_losses_value
    ):
        raise PreparePlanError("action_contract_mismatch")
    return PrepareAction(
        action_id=action_id,
        source_path=source_path,
        target_path=target_value,
        action=action_name,
        reason_code=reason_code,
        media_type=media_type,
        source_binding=_parse_binding(value["source_binding"]),
        approval_required=approval_required,
        expected_relation=expected_relation,
        known_losses=tuple(known_losses_value),
    )


def _plan_from_validated_parts(
    payload: Mapping[str, Any],
    actions: tuple[PrepareAction, ...],
) -> PreparePlan:
    return PreparePlan(
        schema=str(payload["schema"]),
        classification=str(payload["classification"]),
        source_boundary=str(payload["source_boundary"]),
        destination_boundary=str(payload["destination_boundary"]),
        item_count=int(payload["item_count"]),
        actions=actions,
        plan_digest=str(payload["plan_digest"]),
    )


def prepare_plan_from_mapping(
    value: Mapping[str, Any],
    *,
    limits: Limits | None = None,
) -> PreparePlan:
    """Parse and fully validate a persisted prepare plan."""

    effective_limits = limits or Limits()
    _exact_fields(value, _PLAN_FIELDS, prefix="plan")
    if (
        value["schema"] != PLAN_SCHEMA
        or value["classification"] != LOCAL_CLASSIFICATION
        or value["source_boundary"] != SOURCE_BOUNDARY
        or value["destination_boundary"] != DESTINATION_BOUNDARY
    ):
        raise PreparePlanError("invalid_plan_contract")
    item_count = _strict_nonnegative_int(value["item_count"], "invalid_item_count")
    actions_value = value["actions"]
    if not isinstance(actions_value, list) or len(actions_value) > _MAX_ACTIONS:
        raise PreparePlanError("invalid_actions_type")
    if item_count < 1 or item_count != len(actions_value):
        raise PreparePlanError("item_count_mismatch")
    digest = _strict_string(value["plan_digest"], "invalid_plan_digest")
    if _DIGEST_RE.fullmatch(digest) is None:
        raise PreparePlanError("invalid_plan_digest")
    actions = tuple(
        _parse_action(item, limits=effective_limits) for item in actions_value
    )
    expected_digest = canonical_plan_digest(value)
    if not hmac.compare_digest(digest, expected_digest):
        raise PreparePlanError("plan_digest_mismatch")

    expected_ids = [
        f"prepare-action-{index:06d}" for index in range(1, len(actions) + 1)
    ]
    if [action.action_id for action in actions] != expected_ids:
        raise PreparePlanError("action_id_sequence_mismatch")
    expected_order = sorted(
        (action.source_path for action in actions),
        key=lambda path: _portable_sort_key(path, limits=effective_limits),
    )
    if [action.source_path for action in actions] != expected_order:
        raise PreparePlanError("action_order_mismatch")
    _validate_portable_file_tree(
        (action.source_path for action in actions),
        limits=effective_limits,
    )
    _validate_portable_file_tree(
        (action.target_path for action in actions if action.target_path is not None),
        limits=effective_limits,
    )
    _validate_source_target_separation(actions, limits=effective_limits)
    for action in actions:
        _validate_action_contract(action, limits=effective_limits, parsing=True)
    return _plan_from_validated_parts(value, actions)


def _validated_plan(plan: PreparePlan | Mapping[str, Any]) -> PreparePlan:
    if isinstance(plan, PreparePlan):
        return prepare_plan_from_mapping(plan.to_dict())
    if isinstance(plan, Mapping):
        return prepare_plan_from_mapping(plan)
    raise PreparePlanError("invalid_plan_type")


def create_prepare_approval(
    plan: PreparePlan | Mapping[str, Any],
    approved_action_ids: Iterable[str],
) -> PrepareApproval:
    """Approve every action in one executable plan, without executing it."""

    validated_plan = _validated_plan(plan)
    if not validated_plan.executable:
        raise PreparePlanError("plan_not_executable")
    try:
        approved = list(approved_action_ids)
    except TypeError as exc:
        raise PreparePlanError("invalid_approval_actions_type") from exc
    if not all(
        isinstance(item, str) and _ACTION_ID_RE.fullmatch(item) for item in approved
    ):
        raise PreparePlanError("invalid_approval_action_id")
    if len(set(approved)) != len(approved):
        raise PreparePlanError("duplicate_approval_action")
    known = {action.action_id for action in validated_plan.actions}
    supplied = set(approved)
    if supplied - known:
        raise PreparePlanError("approval_action_unknown")
    if known - supplied:
        raise PreparePlanError("approval_incomplete")
    ordered = tuple(sorted(approved))
    payload: dict[str, object] = {
        "schema": APPROVAL_SCHEMA,
        "classification": LOCAL_CLASSIFICATION,
        "status": "approved_for_apply",
        "plan_digest": validated_plan.plan_digest,
        "approved_action_ids": list(ordered),
    }
    payload["approval_digest"] = canonical_approval_digest(payload)
    return PrepareApproval(
        schema=APPROVAL_SCHEMA,
        classification=LOCAL_CLASSIFICATION,
        status="approved_for_apply",
        plan_digest=validated_plan.plan_digest,
        approved_action_ids=ordered,
        approval_digest=str(payload["approval_digest"]),
    )


def prepare_approval_from_mapping(
    value: Mapping[str, Any],
    *,
    plan: PreparePlan | Mapping[str, Any] | None,
) -> PrepareApproval:
    """Parse an approval and bind it to the exact validated plan."""

    _exact_fields(value, _APPROVAL_FIELDS, prefix="approval")
    if (
        value["schema"] != APPROVAL_SCHEMA
        or value["classification"] != LOCAL_CLASSIFICATION
        or value["status"] != "approved_for_apply"
    ):
        raise PreparePlanError("invalid_approval_contract")
    plan_digest = _strict_string(value["plan_digest"], "invalid_plan_digest")
    approval_digest = _strict_string(
        value["approval_digest"], "invalid_approval_digest"
    )
    if (
        _DIGEST_RE.fullmatch(plan_digest) is None
        or _DIGEST_RE.fullmatch(approval_digest) is None
    ):
        raise PreparePlanError("invalid_approval_digest")
    approved_value = value["approved_action_ids"]
    if not isinstance(approved_value, list) or not all(
        isinstance(item, str) and _ACTION_ID_RE.fullmatch(item)
        for item in approved_value
    ):
        raise PreparePlanError("invalid_approval_actions_type")
    expected_digest = canonical_approval_digest(value)
    if not hmac.compare_digest(approval_digest, expected_digest):
        raise PreparePlanError("approval_digest_mismatch")
    if plan is None:
        raise PreparePlanError("approval_plan_required")
    validated_plan = _validated_plan(plan)
    if not hmac.compare_digest(plan_digest, validated_plan.plan_digest):
        raise PreparePlanError("approval_plan_mismatch")
    if not validated_plan.executable:
        raise PreparePlanError("plan_not_executable")
    if len(set(approved_value)) != len(approved_value):
        raise PreparePlanError("duplicate_approval_action")
    known = {action.action_id for action in validated_plan.actions}
    supplied = set(approved_value)
    if supplied - known:
        raise PreparePlanError("approval_action_unknown")
    if known - supplied:
        raise PreparePlanError("approval_incomplete")
    if approved_value != sorted(approved_value):
        raise PreparePlanError("approval_action_order_mismatch")
    return PrepareApproval(
        schema=APPROVAL_SCHEMA,
        classification=LOCAL_CLASSIFICATION,
        status="approved_for_apply",
        plan_digest=plan_digest,
        approved_action_ids=tuple(approved_value),
        approval_digest=approval_digest,
    )


__all__ = [
    "APPROVAL_SCHEMA",
    "LOCAL_CLASSIFICATION",
    "PLAN_SCHEMA",
    "PrepareAction",
    "PrepareApproval",
    "PreparePlan",
    "PreparePlanError",
    "SourceBinding",
    "canonical_approval_digest",
    "canonical_plan_digest",
    "create_prepare_approval",
    "create_prepare_plan",
    "prepare_approval_from_mapping",
    "prepare_plan_from_mapping",
]
