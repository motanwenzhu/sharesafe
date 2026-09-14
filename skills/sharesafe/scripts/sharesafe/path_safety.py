"""Filesystem path comparisons used at write boundaries."""

from __future__ import annotations

import os
from pathlib import Path, PureWindowsPath


def _has_windows_alternate_stream_syntax(path: str | os.PathLike[str]) -> bool:
    r"""Interpret ``path`` with Windows rules and detect named data streams.

    A colon is valid only as the drive designator in forms such as ``C:`` or
    ``\\?\C:``.  Any other colon can select an NTFS alternate data stream and
    therefore cannot identify a safely separate output file.
    """

    normalized = str(PureWindowsPath(os.fspath(path)))
    drive = PureWindowsPath(normalized).drive
    if ":" in drive and not (
        drive.count(":") == 1
        and drive.endswith(":")
        and len(drive) >= 2
        and drive[-2].isascii()
        and drive[-2].isalpha()
    ):
        return True
    tail = normalized[len(drive) :] if drive else normalized
    return ":" in tail


def uses_windows_alternate_stream(path: str | os.PathLike[str]) -> bool:
    """Return whether the native path can address an NTFS named stream."""

    return os.name == "nt" and _has_windows_alternate_stream_syntax(path)


def same_or_within(candidate: Path, root: Path) -> bool:
    """Compare physical paths, resolving existing symlink/reparse parents."""

    try:
        candidate_text = os.path.normcase(str(candidate.absolute().resolve(strict=False)))
        root_text = os.path.normcase(str(root.absolute().resolve(strict=False)))
        if candidate_text == root_text:
            return True
        return os.path.commonpath([candidate_text, root_text]) == root_text
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("filesystem paths could not be resolved safely") from exc


__all__ = ["same_or_within", "uses_windows_alternate_stream"]
