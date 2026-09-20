"""Handle-first helpers for reading untrusted filesystem entries.

The helpers compare the object selected during discovery with the descriptor
returned by the operating system *before* any bytes are read.  This closes the
most important final-component swap window and gives callers one shared
identity definition.  Parent-directory handle anchoring is platform-specific
and is intentionally tracked as a separate capability.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
from typing import BinaryIO


class FileIdentityChangedError(OSError):
    """The path no longer names the object selected by the caller."""


@dataclass(frozen=True, slots=True)
class DirectorySnapshot:
    """A path-based directory identity snapshot.

    This detects replacement at explicit checkpoints.  It is not a directory
    handle and does not claim to close the race between a successful check and
    a following path-based operation; ``doctor`` reports that distinction.
    """

    path: Path
    identity: tuple[int, int, int]


def file_identity(status: os.stat_result) -> tuple[int, ...]:
    """Return fields that must remain stable for one bounded file read."""

    identity = (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_size,
        status.st_mtime_ns,
    )
    # On Windows, Path.stat and fstat expose different meanings through
    # st_ctime_ns (metadata-change time versus creation time on supported
    # filesystems).  It therefore cannot be compared across those APIs.
    return identity if os.name == "nt" else (*identity, status.st_ctime_ns)


def _is_reparse(status: os.stat_result) -> bool:
    attributes = getattr(status, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse)


def directory_identity(status: os.stat_result) -> tuple[int, int, int]:
    """Return fields used to detect replacement of one directory object."""

    return status.st_dev, status.st_ino, stat.S_IFMT(status.st_mode)


def _plain_directory_status(path: Path) -> os.stat_result:
    try:
        status = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise FileIdentityChangedError("directory identity could not be verified") from exc
    if not stat.S_ISDIR(status.st_mode) or _is_reparse(status):
        raise FileIdentityChangedError("directory path contains a link or reparse point")
    return status


def _verify_plain_ancestors(path: Path) -> None:
    current = path
    while True:
        _plain_directory_status(current)
        parent = current.parent
        if parent == current:
            return
        current = parent


def snapshot_verified_directory(path: Path) -> DirectorySnapshot:
    """Snapshot an existing plain directory after checking every ancestor."""

    absolute = path.absolute()
    _verify_plain_ancestors(absolute)
    return DirectorySnapshot(absolute, directory_identity(_plain_directory_status(absolute)))


def prepare_verified_parent(target: Path) -> DirectorySnapshot:
    """Create missing parent directories and return a checked path snapshot.

    Each existing or newly created ancestor must be a plain directory.  This
    function detects checkpoint drift but intentionally does not advertise the
    stronger handle-anchored guarantee unavailable on all supported platforms.
    """

    parent = target.absolute().parent
    missing: list[Path] = []
    cursor = parent
    while True:
        try:
            status = cursor.stat(follow_symlinks=False)
        except FileNotFoundError:
            missing.append(cursor)
            next_cursor = cursor.parent
            if next_cursor == cursor:
                raise FileIdentityChangedError("output parent has no existing ancestor")
            cursor = next_cursor
            continue
        except OSError as exc:
            raise FileIdentityChangedError("output parent could not be inspected") from exc
        if not stat.S_ISDIR(status.st_mode) or _is_reparse(status):
            raise FileIdentityChangedError("output parent contains a link or reparse point")
        break

    _verify_plain_ancestors(cursor)
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        _plain_directory_status(directory)
    return snapshot_verified_directory(parent)


def verify_directory_unchanged(snapshot: DirectorySnapshot) -> bool:
    """Return whether a directory and its ancestors still pass path checks."""

    try:
        _verify_plain_ancestors(snapshot.path)
        current = _plain_directory_status(snapshot.path)
    except FileIdentityChangedError:
        return False
    return directory_identity(current) == snapshot.identity


def open_verified_binary(
    path: Path,
    *,
    expected: os.stat_result,
) -> tuple[BinaryIO, os.stat_result]:
    """Open ``path`` and verify its descriptor before exposing a read handle.

    ``expected`` must come from the discovery/limit-check step.  The returned
    handle owns the descriptor and must be closed by the caller.
    """

    if not stat.S_ISREG(expected.st_mode) or _is_reparse(expected):
        raise FileIdentityChangedError("selected entry is no longer a regular file")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOINHERIT", 0)
    # O_NOFOLLOW rejects a final-component symlink on platforms that expose it.
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or file_identity(expected) != file_identity(opened)
        ):
            raise FileIdentityChangedError(
                "selected entry changed before bytes could be read"
            )
        return os.fdopen(descriptor, "rb"), opened
    except Exception:
        os.close(descriptor)
        raise


def verify_open_file_unchanged(
    handle: BinaryIO,
    path: Path,
    *,
    opened: os.stat_result,
) -> bool:
    """Return whether descriptor and path still identify the opened snapshot."""

    try:
        descriptor_after = os.fstat(handle.fileno())
        path_after = path.stat(follow_symlinks=False)
    except OSError:
        return False
    expected = file_identity(opened)
    return (
        stat.S_ISREG(descriptor_after.st_mode)
        and not _is_reparse(path_after)
        and file_identity(descriptor_after) == expected
        and file_identity(path_after) == expected
    )


__all__ = [
    "DirectorySnapshot",
    "FileIdentityChangedError",
    "directory_identity",
    "file_identity",
    "open_verified_binary",
    "prepare_verified_parent",
    "snapshot_verified_directory",
    "verify_directory_unchanged",
    "verify_open_file_unchanged",
]
