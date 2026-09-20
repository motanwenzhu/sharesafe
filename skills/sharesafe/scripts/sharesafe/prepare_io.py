"""Private, fail-closed I/O for local ShareSafe prepare control artifacts.

Prepare plans contain source-relative names and stable SHA-256 bindings.  They
are intentionally outside the masked-report boundary and must never be passed
to :mod:`sharesafe.reporting`.  This module validates their semantic contract,
writes a private same-directory staging inode, and publishes that complete
inode with exclusive hard-link creation so a destination is never overwritten
or observed as a partial JSON document.

Parent directory checks are path-based identity checkpoints.  They detect
replacement at the documented checkpoints but are not directory-handle
anchoring; the distinction is included in every successful write result.
"""

from __future__ import annotations

import ctypes
import errno
import json
import math
import os
import secrets
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Literal

from .limits import MAX_LIMIT_VALUE, Limits
from .path_safety import uses_windows_alternate_stream
from .prepare_plan import (
    LOCAL_CLASSIFICATION,
    PrepareApproval,
    PreparePlan,
    PreparePlanError,
    prepare_approval_from_mapping,
    prepare_plan_from_mapping,
)
from .safe_io import (
    DirectorySnapshot,
    FileIdentityChangedError,
    file_identity,
    open_verified_binary,
    prepare_verified_parent,
    snapshot_verified_directory,
    verify_directory_unchanged,
    verify_open_file_unchanged,
)

MAX_CONTROL_ARTIFACT_BYTES = 32 * 1024 * 1024

_BOM = b"\xef\xbb\xbf"
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_STAGING_PREFIX = ".sharesafe-control-"
_STAGING_SUFFIX = ".tmp"
_STAGING_ATTEMPTS = 128

_ERROR_MESSAGES = {
    "invalid_control_limit": "The local control artifact byte limit is invalid.",
    "control_path_rejected": "The local control artifact path is not supported.",
    "control_unavailable": "The local control artifact could not be read safely.",
    "control_not_regular": "The local control artifact must be a regular non-link file.",
    "control_too_large": "The local control artifact exceeds the configured byte limit.",
    "control_changed_during_read": "The local control artifact changed while it was being read.",
    "control_bom_rejected": "The local control artifact must be UTF-8 without a BOM.",
    "invalid_control_json": "The local control artifact is not strict UTF-8 JSON.",
    "control_object_required": "The local control artifact must be a JSON object.",
    "prepare_plan_invalid": "The local prepare plan failed semantic validation.",
    "prepare_approval_invalid": "The local prepare approval failed semantic validation.",
    "control_destination_exists": "The local control destination already exists; nothing was overwritten.",
    "control_parent_unsafe": "The local control destination parent could not be verified.",
    "control_parent_changed": "The local control destination parent changed during output.",
    "private_permissions_unavailable": "Owner-only local control permissions could not be established and verified.",
    "atomic_publish_unavailable": "Exclusive atomic publication is unavailable for this destination.",
    "control_write_failed": "The local control artifact could not be written safely.",
}


class PrepareIOError(ValueError):
    """Stable, path-free failure at a local control artifact boundary."""

    def __init__(self, code: str) -> None:
        if code not in _ERROR_MESSAGES:
            code = "control_write_failed"
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


class _PrivatePermissionError(OSError):
    """Internal signal used when private permissions cannot be proven."""


@dataclass(frozen=True, slots=True)
class LocalControlWriteResult:
    """Non-sensitive assurance receipt for a completed local-only write."""

    artifact_kind: Literal["plan", "approval"]
    classification: str
    bytes_written: int
    owner_only_verified: bool
    permission_control: Literal[
        "posix_owner_mode_0600", "windows_protected_current_user_dacl"
    ]
    atomic_publish: Literal["same_directory_hardlink_create_new"]
    parent_directory_identity_checkpoints: bool
    parent_directory_handle_anchoring: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_kind": self.artifact_kind,
            "classification": self.classification,
            "bytes_written": self.bytes_written,
            "owner_only_verified": self.owner_only_verified,
            "permission_control": self.permission_control,
            "atomic_publish": self.atomic_publish,
            "parent_directory_identity_checkpoints": (
                self.parent_directory_identity_checkpoints
            ),
            "parent_directory_handle_anchoring": (
                self.parent_directory_handle_anchoring
            ),
        }


def load_prepare_plan_file(
    path: str | os.PathLike[str],
    *,
    max_bytes: int = MAX_CONTROL_ARTIFACT_BYTES,
    limits: Limits | None = None,
) -> PreparePlan:
    """Read and semantically validate one explicitly selected local plan."""

    mapping = load_local_control_mapping(path, max_bytes=max_bytes)
    try:
        return prepare_plan_from_mapping(mapping, limits=limits)
    except (PreparePlanError, TypeError, ValueError, RecursionError):
        raise PrepareIOError("prepare_plan_invalid") from None


def load_prepare_approval_file(
    path: str | os.PathLike[str],
    *,
    plan: PreparePlan | Mapping[str, Any],
    max_bytes: int = MAX_CONTROL_ARTIFACT_BYTES,
) -> PrepareApproval:
    """Read an approval and bind it to the exact supplied validated plan."""

    mapping = load_local_control_mapping(path, max_bytes=max_bytes)
    try:
        return prepare_approval_from_mapping(mapping, plan=plan)
    except (PreparePlanError, TypeError, ValueError, RecursionError):
        raise PrepareIOError("prepare_approval_invalid") from None


def write_prepare_plan_file(
    path: str | os.PathLike[str],
    plan: PreparePlan | Mapping[str, Any],
    *,
    max_bytes: int = MAX_CONTROL_ARTIFACT_BYTES,
    limits: Limits | None = None,
) -> LocalControlWriteResult:
    """Validate and exclusively publish one private local prepare plan."""

    try:
        validated = prepare_plan_from_mapping(
            plan.to_dict() if isinstance(plan, PreparePlan) else plan,
            limits=limits,
        )
    except (PreparePlanError, TypeError, ValueError, RecursionError):
        raise PrepareIOError("prepare_plan_invalid") from None
    rendered = _render_control_json(validated.to_dict(), max_bytes=max_bytes)
    return _write_private_atomic(path, rendered, artifact_kind="plan")


def write_prepare_approval_file(
    path: str | os.PathLike[str],
    approval: PrepareApproval | Mapping[str, Any],
    *,
    plan: PreparePlan | Mapping[str, Any],
    max_bytes: int = MAX_CONTROL_ARTIFACT_BYTES,
) -> LocalControlWriteResult:
    """Validate and exclusively publish an approval for exactly ``plan``."""

    try:
        validated = prepare_approval_from_mapping(
            approval.to_dict() if isinstance(approval, PrepareApproval) else approval,
            plan=plan,
        )
    except (PreparePlanError, TypeError, ValueError, RecursionError):
        raise PrepareIOError("prepare_approval_invalid") from None
    rendered = _render_control_json(validated.to_dict(), max_bytes=max_bytes)
    return _write_private_atomic(path, rendered, artifact_kind="approval")


def load_local_control_mapping(
    path: str | os.PathLike[str],
    *,
    max_bytes: int = MAX_CONTROL_ARTIFACT_BYTES,
) -> dict[str, Any]:
    """Load one bounded strict-JSON object from the local control boundary.

    This function performs only safe I/O and strict JSON parsing.  Callers must
    still pass the returned mapping to their exact schema/semantic parser.
    """

    limit = _positive_limit(max_bytes)
    try:
        selected = Path(path).absolute()
    except (OSError, TypeError, ValueError):
        raise PrepareIOError("control_path_rejected") from None
    if uses_windows_alternate_stream(selected):
        raise PrepareIOError("control_path_rejected")

    data = _read_control_bytes(selected, limit)
    if data.startswith(_BOM):
        raise PrepareIOError("control_bom_rejected")
    try:
        decoded = data.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
            parse_float=_strict_json_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise PrepareIOError("invalid_control_json") from None
    if type(value) is not dict:
        raise PrepareIOError("control_object_required")
    try:
        _assert_unicode_scalars(value)
    except ValueError:
        raise PrepareIOError("invalid_control_json") from None
    return value


def _read_control_bytes(path: Path, max_bytes: int) -> bytes:
    try:
        parent_snapshot = snapshot_verified_directory(path.parent)
    except FileIdentityChangedError:
        raise PrepareIOError("control_not_regular") from None
    except (OSError, TypeError, ValueError):
        raise PrepareIOError("control_unavailable") from None
    try:
        before = path.lstat()
        attributes = getattr(before, "st_file_attributes", 0)
        if not stat.S_ISREG(before.st_mode) or attributes & _REPARSE_ATTRIBUTE:
            raise PrepareIOError("control_not_regular")
        if before.st_size > max_bytes:
            raise PrepareIOError("control_too_large")
        handle, opened = open_verified_binary(path, expected=before)
        with handle:
            data = handle.read(max_bytes + 1)
            unchanged = verify_open_file_unchanged(handle, path, opened=opened)
        parent_unchanged = verify_directory_unchanged(parent_snapshot)
    except PrepareIOError:
        raise
    except FileIdentityChangedError:
        raise PrepareIOError("control_changed_during_read") from None
    except (OSError, TypeError, ValueError):
        raise PrepareIOError("control_unavailable") from None

    if not unchanged or not parent_unchanged:
        raise PrepareIOError("control_changed_during_read")
    if len(data) > max_bytes:
        raise PrepareIOError("control_too_large")
    return data


def _render_control_json(payload: Mapping[str, Any], *, max_bytes: int) -> bytes:
    limit = _positive_limit(max_bytes)
    try:
        rendered = (
            json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise PrepareIOError("invalid_control_json") from None
    if len(rendered) > limit:
        raise PrepareIOError("control_too_large")
    return rendered


def _write_private_atomic(
    path: str | os.PathLike[str],
    data: bytes,
    *,
    artifact_kind: Literal["plan", "approval"],
) -> LocalControlWriteResult:
    try:
        target = Path(path).absolute()
    except (OSError, TypeError, ValueError):
        raise PrepareIOError("control_path_rejected") from None
    if uses_windows_alternate_stream(target):
        raise PrepareIOError("control_path_rejected")
    try:
        if target.exists() or target.is_symlink():
            raise PrepareIOError("control_destination_exists")
        parent_snapshot = prepare_verified_parent(target)
    except PrepareIOError:
        raise
    except (FileIdentityChangedError, OSError, ValueError):
        raise PrepareIOError("control_parent_unsafe") from None

    _assert_parent_unchanged(parent_snapshot)
    temporary: Path | None = None
    opened_identity: tuple[int, ...] | None = None
    published = False
    permission_control: str | None = None
    try:
        descriptor, temporary = _open_private_staging(parent_snapshot.path)
        with os.fdopen(descriptor, "w+b", closefd=True) as handle:
            permission_control = _verify_private_open_file(handle)
            opened = os.fstat(handle.fileno())
            opened_identity = file_identity(opened)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise _PrivatePermissionError

            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            if file_identity(os.fstat(handle.fileno()))[:3] != opened_identity[:3]:
                raise _PrivatePermissionError
            opened_identity = file_identity(os.fstat(handle.fileno()))
            permission_control = _verify_private_open_file(handle)

            _assert_parent_unchanged(parent_snapshot)
            try:
                os.link(temporary, target, follow_symlinks=False)
            except FileExistsError:
                raise PrepareIOError("control_destination_exists") from None
            except OSError as exc:
                if exc.errno == errno.EEXIST:
                    raise PrepareIOError("control_destination_exists") from None
                raise PrepareIOError("atomic_publish_unavailable") from None
            published = True

            _assert_parent_unchanged(parent_snapshot)
            _assert_published_identity(target, handle, require_links=2)
            opened_identity = file_identity(os.fstat(handle.fileno()))
            permission_control = _verify_private_open_file(handle)

            if not _safe_unlink_if_owned(temporary, opened_identity, parent_snapshot):
                raise PrepareIOError("control_write_failed")
            temporary = None
            opened_identity = file_identity(os.fstat(handle.fileno()))
            _assert_parent_unchanged(parent_snapshot)
            _assert_published_identity(target, handle, require_links=1)
            permission_control = _verify_private_open_file(handle)
    except PrepareIOError:
        _cleanup_failed_write(
            target,
            temporary,
            opened_identity,
            parent_snapshot,
            published=published,
        )
        raise
    except _PrivatePermissionError:
        _cleanup_failed_write(
            target,
            temporary,
            opened_identity,
            parent_snapshot,
            published=published,
        )
        raise PrepareIOError("private_permissions_unavailable") from None
    except (FileIdentityChangedError, OSError, TypeError, ValueError):
        _cleanup_failed_write(
            target,
            temporary,
            opened_identity,
            parent_snapshot,
            published=published,
        )
        raise PrepareIOError("control_write_failed") from None

    if permission_control not in {
        "posix_owner_mode_0600",
        "windows_protected_current_user_dacl",
    }:
        raise PrepareIOError("private_permissions_unavailable")
    return LocalControlWriteResult(
        artifact_kind=artifact_kind,
        classification=LOCAL_CLASSIFICATION,
        bytes_written=len(data),
        owner_only_verified=True,
        permission_control=permission_control,  # type: ignore[arg-type]
        atomic_publish="same_directory_hardlink_create_new",
        parent_directory_identity_checkpoints=True,
        parent_directory_handle_anchoring=False,
    )


def _positive_limit(value: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > MAX_LIMIT_VALUE
    ):
        raise PrepareIOError("invalid_control_limit")
    return value


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(_: str) -> None:
    raise ValueError("non-standard JSON numeric constant")


def _strict_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON number")
    return parsed


def _assert_unicode_scalars(value: object) -> None:
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in current):
                raise ValueError("JSON string contains an unpaired surrogate")
        elif type(current) is dict:
            pending.extend(current.keys())
            pending.extend(current.values())
        elif type(current) is list:
            pending.extend(current)


def _assert_parent_unchanged(snapshot: DirectorySnapshot) -> None:
    if not verify_directory_unchanged(snapshot):
        raise PrepareIOError("control_parent_changed")


def _open_private_staging(parent: Path) -> tuple[int, Path]:
    for _ in range(_STAGING_ATTEMPTS):
        candidate = parent / (
            f"{_STAGING_PREFIX}{secrets.token_hex(16)}{_STAGING_SUFFIX}"
        )
        try:
            return _open_private_new_file(candidate), candidate
        except FileExistsError:
            continue
        except _PrivatePermissionError:
            raise
        except OSError:
            raise PrepareIOError("control_write_failed") from None
    raise PrepareIOError("control_write_failed")


def _open_private_new_file(path: Path) -> int:
    if os.name == "nt":
        try:
            return _windows_create_private_file(path)
        except (FileExistsError, _PrivatePermissionError):
            raise
        except (
            AttributeError,
            ImportError,
            OSError,
            TypeError,
            ValueError,
            ctypes.ArgumentError,
        ):
            raise _PrivatePermissionError from None
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
    except OSError:
        try:
            os.close(descriptor)
        except OSError:
            pass
        # Do not resolve the staging name for cleanup after an unexpected
        # failure: the parent could have changed since its last checkpoint.
        # A private empty orphan is safer than deleting through a replaced path.
        raise _PrivatePermissionError from None
    return descriptor


def create_private_temporary_directory(
    *,
    prefix: str = ".sharesafe-private-",
) -> DirectorySnapshot:
    """Create and verify an owner-only directory in the system temp location.

    Windows creation supplies a protected current-user-only DACL atomically.
    POSIX creation is verified as a directory owned by the effective user with
    mode 0700.  The returned identity remains a path checkpoint rather than a
    directory-handle anchor.
    """

    if (
        not prefix
        or len(prefix) > 128
        or any(character in prefix for character in ("/", "\\", ":"))
    ):
        raise PrepareIOError("control_write_failed")
    try:
        parent_snapshot = snapshot_verified_directory(Path(tempfile.gettempdir()))
    except FileIdentityChangedError:
        raise PrepareIOError("control_parent_unsafe") from None

    for _ in range(_STAGING_ATTEMPTS):
        candidate = parent_snapshot.path / f"{prefix}{secrets.token_hex(16)}"
        created_snapshot: DirectorySnapshot | None = None
        try:
            _assert_parent_unchanged(parent_snapshot)
            if os.name == "nt":
                _windows_create_private_directory(candidate)
            else:
                candidate.mkdir(mode=0o700)
                os.chmod(candidate, 0o700, follow_symlinks=False)
            created_snapshot = snapshot_verified_directory(candidate)
            if os.name == "nt":
                _windows_verify_private_directory(candidate)
            else:
                status_value = candidate.stat(follow_symlinks=False)
                get_euid = getattr(os, "geteuid", None)
                if (
                    stat.S_IMODE(status_value.st_mode) != 0o700
                    or get_euid is None
                    or status_value.st_uid != get_euid()
                ):
                    raise _PrivatePermissionError
            _assert_parent_unchanged(parent_snapshot)
            if not verify_directory_unchanged(created_snapshot):
                raise _PrivatePermissionError
            return created_snapshot
        except FileExistsError:
            continue
        except _PrivatePermissionError:
            if (
                created_snapshot is not None
                and verify_directory_unchanged(parent_snapshot)
                and verify_directory_unchanged(created_snapshot)
            ):
                try:
                    candidate.rmdir()
                except OSError:
                    pass
            raise PrepareIOError("private_permissions_unavailable") from None
        except PrepareIOError:
            raise
        except (FileIdentityChangedError, OSError):
            if (
                created_snapshot is not None
                and verify_directory_unchanged(parent_snapshot)
                and verify_directory_unchanged(created_snapshot)
            ):
                try:
                    candidate.rmdir()
                except OSError:
                    pass
            raise PrepareIOError("control_write_failed") from None
    raise PrepareIOError("control_write_failed")


def _verify_private_open_file(handle: BinaryIO) -> str:
    status_value = os.fstat(handle.fileno())
    if not stat.S_ISREG(status_value.st_mode):
        raise _PrivatePermissionError
    if os.name == "nt":
        try:
            _windows_verify_private_file(handle.fileno())
        except _PrivatePermissionError:
            raise
        except (
            AttributeError,
            ImportError,
            OSError,
            TypeError,
            ValueError,
            ctypes.ArgumentError,
        ):
            raise _PrivatePermissionError from None
        return "windows_protected_current_user_dacl"
    if stat.S_IMODE(status_value.st_mode) != 0o600:
        raise _PrivatePermissionError
    get_euid = getattr(os, "geteuid", None)
    if get_euid is None or status_value.st_uid != get_euid():
        raise _PrivatePermissionError
    return "posix_owner_mode_0600"


def _assert_published_identity(
    target: Path, handle: BinaryIO, *, require_links: int
) -> None:
    try:
        descriptor_status = os.fstat(handle.fileno())
        target_status = target.lstat()
    except OSError:
        raise PrepareIOError("control_write_failed") from None
    attributes = getattr(target_status, "st_file_attributes", 0)
    if (
        not stat.S_ISREG(descriptor_status.st_mode)
        or not stat.S_ISREG(target_status.st_mode)
        or attributes & _REPARSE_ATTRIBUTE
        or file_identity(descriptor_status) != file_identity(target_status)
        or descriptor_status.st_nlink != require_links
        or target_status.st_nlink != require_links
    ):
        raise PrepareIOError("control_write_failed")


def _safe_unlink_if_owned(
    path: Path,
    identity: tuple[int, ...],
    parent_snapshot: DirectorySnapshot,
) -> bool:
    if not verify_directory_unchanged(parent_snapshot):
        return False
    try:
        selected = path.lstat()
        if (
            stat.S_ISREG(selected.st_mode)
            and not getattr(selected, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
            and file_identity(selected) == identity
        ):
            path.unlink()
            return True
    except OSError:
        pass
    return False


def _cleanup_failed_write(
    target: Path,
    temporary: Path | None,
    identity: tuple[int, ...] | None,
    parent_snapshot: DirectorySnapshot,
    *,
    published: bool,
) -> None:
    if identity is None:
        return
    if published:
        _safe_unlink_if_owned(target, identity, parent_snapshot)
    if temporary is not None:
        _safe_unlink_if_owned(temporary, identity, parent_snapshot)


def _windows_current_user_sid() -> bytes:
    """Return a detached copy of the current process token's user SID."""

    if os.name != "nt":
        raise _PrivatePermissionError
    from ctypes import wintypes

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class TOKEN_USER(ctypes.Structure):
        _fields_ = [("User", SID_AND_ATTRIBUTES)]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.GetLengthSid.argtypes = [ctypes.c_void_p]
    advapi32.GetLengthSid.restype = wintypes.DWORD
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)
    ):
        raise _PrivatePermissionError
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if needed.value == 0:
            raise _PrivatePermissionError
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(
            token, 1, buffer, needed.value, ctypes.byref(needed)
        ):
            raise _PrivatePermissionError
        token_user = ctypes.cast(buffer, ctypes.POINTER(TOKEN_USER)).contents
        length = advapi32.GetLengthSid(token_user.User.Sid)
        if length == 0:
            raise _PrivatePermissionError
        return ctypes.string_at(token_user.User.Sid, length)
    finally:
        kernel32.CloseHandle(token)


def _windows_private_security_attributes(
    *,
    inherit_children: bool = False,
) -> tuple[object, tuple[object, ...]]:
    """Build a protected DACL granting file-all-access only to this user."""

    if os.name != "nt":
        raise _PrivatePermissionError
    from ctypes import wintypes

    class ACL(ctypes.Structure):
        _fields_ = [
            ("AclRevision", ctypes.c_ubyte),
            ("Sbz1", ctypes.c_ubyte),
            ("AclSize", wintypes.WORD),
            ("AceCount", wintypes.WORD),
            ("Sbz2", wintypes.WORD),
        ]

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.InitializeSecurityDescriptor.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    advapi32.InitializeSecurityDescriptor.restype = wintypes.BOOL
    advapi32.SetSecurityDescriptorOwner.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
    ]
    advapi32.SetSecurityDescriptorOwner.restype = wintypes.BOOL
    advapi32.InitializeAcl.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
    advapi32.InitializeAcl.restype = wintypes.BOOL
    advapi32.AddAccessAllowedAceEx.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    advapi32.AddAccessAllowedAceEx.restype = wintypes.BOOL
    advapi32.SetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        wintypes.BOOL,
        ctypes.c_void_p,
        wintypes.BOOL,
    ]
    advapi32.SetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.SetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        wintypes.WORD,
        wintypes.WORD,
    ]
    advapi32.SetSecurityDescriptorControl.restype = wintypes.BOOL

    sid_bytes = _windows_current_user_sid()
    sid = ctypes.create_string_buffer(sid_bytes)
    security_descriptor = ctypes.create_string_buffer(64)
    acl_size = ctypes.sizeof(ACL) + 8 + len(sid_bytes)
    acl = ctypes.create_string_buffer(acl_size)
    if not advapi32.InitializeSecurityDescriptor(security_descriptor, 1):
        raise _PrivatePermissionError
    if not advapi32.SetSecurityDescriptorOwner(security_descriptor, sid, False):
        raise _PrivatePermissionError
    if not advapi32.InitializeAcl(acl, acl_size, 2):
        raise _PrivatePermissionError
    inheritance_flags = 0x03 if inherit_children else 0
    if not advapi32.AddAccessAllowedAceEx(acl, 2, inheritance_flags, 0x001F01FF, sid):
        raise _PrivatePermissionError
    if not advapi32.SetSecurityDescriptorDacl(security_descriptor, True, acl, False):
        raise _PrivatePermissionError
    if not advapi32.SetSecurityDescriptorControl(security_descriptor, 0x1000, 0x1000):
        raise _PrivatePermissionError
    attributes = SECURITY_ATTRIBUTES(
        ctypes.sizeof(SECURITY_ATTRIBUTES),
        ctypes.cast(security_descriptor, ctypes.c_void_p),
        False,
    )
    return attributes, (sid, security_descriptor, acl)


def _windows_create_private_file(path: Path) -> int:
    if os.name != "nt":
        raise _PrivatePermissionError
    import msvcrt
    from ctypes import wintypes

    attributes, keepalive = _windows_private_security_attributes()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.CreateFileW(
        str(path),
        0xC0000000,
        0x00000007,
        ctypes.byref(attributes),
        1,
        0x00000080,
        None,
    )
    # Keep SID, ACL, and security descriptor buffers alive through CreateFileW.
    _ = keepalive
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        error = ctypes.get_last_error()
        if error in {80, 183}:
            raise FileExistsError
        raise _PrivatePermissionError
    try:
        descriptor = msvcrt.open_osfhandle(
            int(handle), os.O_RDWR | getattr(os, "O_BINARY", 0)
        )
    except OSError:
        kernel32.CloseHandle(handle)
        raise _PrivatePermissionError from None
    return descriptor


def _windows_create_private_directory(path: Path) -> None:
    if os.name != "nt":
        raise _PrivatePermissionError
    from ctypes import wintypes

    attributes, keepalive = _windows_private_security_attributes(inherit_children=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
    kernel32.CreateDirectoryW.restype = wintypes.BOOL
    if not kernel32.CreateDirectoryW(str(path), ctypes.byref(attributes)):
        error = ctypes.get_last_error()
        if error in {80, 183}:
            raise FileExistsError
        raise _PrivatePermissionError
    # Keep SID, ACL, and security descriptor buffers alive through creation.
    _ = keepalive


def _windows_verify_private_file(descriptor: int) -> None:
    """Verify owner and the complete protected DACL from an open file handle."""

    if os.name != "nt":
        raise _PrivatePermissionError
    import msvcrt

    _windows_verify_private_handle(
        msvcrt.get_osfhandle(descriptor),
        inherit_children=False,
    )


def _windows_verify_private_directory(path: Path) -> None:
    """Open a directory without following a final reparse point and verify it."""

    if os.name != "nt":
        raise _PrivatePermissionError
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.CreateFileW(
        str(path),
        0x00020000,
        0x00000007,
        None,
        3,
        0x02000000 | 0x00200000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        raise _PrivatePermissionError
    try:
        _windows_verify_private_handle(int(handle), inherit_children=True)
    finally:
        kernel32.CloseHandle(handle)


def _windows_verify_private_handle(
    native_handle: int,
    *,
    inherit_children: bool,
) -> None:
    """Verify current-user ownership and the complete protected DACL."""

    if os.name != "nt":
        raise _PrivatePermissionError
    from ctypes import wintypes

    class ACL_SIZE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("AceCount", wintypes.DWORD),
            ("AclBytesInUse", wintypes.DWORD),
            ("AclBytesFree", wintypes.DWORD),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    advapi32.EqualSid.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_int,
    ]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    security_descriptor = ctypes.c_void_p()
    result = advapi32.GetSecurityInfo(
        wintypes.HANDLE(native_handle),
        1,
        0x00000001 | 0x00000004,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(security_descriptor),
    )
    if result != 0 or not security_descriptor.value:
        raise _PrivatePermissionError
    try:
        sid = ctypes.create_string_buffer(_windows_current_user_sid())
        if not owner.value or not advapi32.EqualSid(owner, sid):
            raise _PrivatePermissionError

        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        descriptor_dacl = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorDacl(
            security_descriptor,
            ctypes.byref(present),
            ctypes.byref(descriptor_dacl),
            ctypes.byref(defaulted),
        ):
            raise _PrivatePermissionError
        if not present.value or not descriptor_dacl.value:
            raise _PrivatePermissionError

        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            security_descriptor, ctypes.byref(control), ctypes.byref(revision)
        ):
            raise _PrivatePermissionError
        if not control.value & 0x1000:
            raise _PrivatePermissionError

        information = ACL_SIZE_INFORMATION()
        if not advapi32.GetAclInformation(
            descriptor_dacl,
            ctypes.byref(information),
            ctypes.sizeof(information),
            2,
        ):
            raise _PrivatePermissionError
        if information.AceCount != 1:
            raise _PrivatePermissionError
        ace = ctypes.c_void_p()
        if not advapi32.GetAce(descriptor_dacl, 0, ctypes.byref(ace)):
            raise _PrivatePermissionError
        if not ace.value or ctypes.c_ubyte.from_address(ace.value).value != 0:
            raise _PrivatePermissionError
        expected_flags = 0x03 if inherit_children else 0
        if ctypes.c_ubyte.from_address(ace.value + 1).value != expected_flags:
            raise _PrivatePermissionError
        mask = ctypes.c_uint32.from_address(ace.value + 4).value
        ace_sid = ctypes.c_void_p(ace.value + 8)
        if mask & 0x001F01FF != 0x001F01FF:
            raise _PrivatePermissionError
        if not advapi32.EqualSid(ace_sid, sid):
            raise _PrivatePermissionError
    finally:
        kernel32.LocalFree(security_descriptor)


__all__ = [
    "MAX_CONTROL_ARTIFACT_BYTES",
    "LocalControlWriteResult",
    "PrepareIOError",
    "create_private_temporary_directory",
    "load_local_control_mapping",
    "load_prepare_approval_file",
    "load_prepare_plan_file",
    "write_prepare_approval_file",
    "write_prepare_plan_file",
]
