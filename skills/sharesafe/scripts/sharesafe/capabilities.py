"""Local capability discovery used by ``doctor``.

Deep probes use only in-memory synthetic fixtures.  They never install a
dependency, read user artifacts, or contact a network service.
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import os
import platform
import re
import sys
from collections.abc import Callable
from io import BytesIO
from typing import Any


def _version(distribution: str) -> str | None:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return None


def _probe_pillow() -> None:
    from PIL import Image

    image = Image.new("RGB", (1, 1), (17, 34, 51))
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    buffer.seek(0)
    with Image.open(buffer) as reopened:
        reopened.load()
        if reopened.size != (1, 1):
            raise RuntimeError("synthetic image probe returned an unexpected size")


def _probe_pypdf() -> None:
    from pypdf import PdfReader, PdfWriter

    output = BytesIO()
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.write(output)
    output.seek(0)
    reader = PdfReader(output)
    if len(reader.pages) != 1:
        raise RuntimeError("synthetic PDF probe returned an unexpected page count")


_OPTIONAL_PROBES: tuple[tuple[str, str, str, int, Callable[[], None]], ...] = (
    ("Pillow", "PIL", "rich_image_metadata", 10, _probe_pillow),
    ("pypdf", "pypdf", "pdf_text_and_structure", 5, _probe_pypdf),
)


def _supported_major(version: str | None, minimum: int) -> bool | None:
    if version is None:
        return None
    match = re.match(r"^(\d+)", version)
    return bool(match and int(match.group(1)) >= minimum)


def optional_capabilities(*, deep: bool) -> list[dict[str, Any]]:
    """Return installed state and, when requested, a synthetic usability probe."""

    records: list[dict[str, Any]] = []
    for distribution, module, capability, minimum_major, probe in _OPTIONAL_PROBES:
        installed = importlib.util.find_spec(module) is not None
        version = _version(distribution)
        version_supported = (
            _supported_major(version, minimum_major) if installed else None
        )
        record: dict[str, Any] = {
            "name": distribution,
            "available": installed,
            "version": version,
            "supported_version": f">={minimum_major}",
            "version_supported": version_supported,
            "capability": capability,
            "isolation": "in_process_bounded_adapter",
        }
        if deep:
            if not installed:
                record.update({"usable": False, "probe": "missing"})
            elif version_supported is not True:
                record.update({"usable": False, "probe": "unsupported_version"})
            else:
                try:
                    probe()
                except Exception:  # noqa: BLE001 - adapters expose unstable exception trees.
                    # Parser/import exception text may contain local paths or
                    # environment details, so only a stable class is exposed.
                    record.update({"usable": False, "probe": "failed"})
                else:
                    record.update({"usable": True, "probe": "passed"})
        records.append(record)
    return records


def filesystem_safety_capabilities() -> dict[str, Any]:
    """Describe guarantees implemented by the portable safe-I/O layer."""

    return {
        "descriptor_identity_before_read": True,
        "final_component_nofollow": hasattr(os, "O_NOFOLLOW"),
        "parent_directory_identity_checkpoints": True,
        "parent_directory_handle_anchoring": False,
        "exclusive_destination_creation": True,
        "atomic_multi_file_directory_publish": os.name == "nt",
        "private_temporary_staging_fail_closed": True,
        "private_temporary_staging_permission": (
            "windows_protected_current_user_inheritable_dacl"
            if os.name == "nt"
            else "posix_effective_user_mode_0700"
        ),
        "platform": platform.system(),
        "note": (
            "Parent-directory handle anchoring is not yet portable; concurrent "
            "parent replacement remains an explicit hardening gap."
        ),
    }


def doctor_payload(*, deep: bool, tool_version: str) -> dict[str, Any]:
    python_ok = sys.version_info >= (3, 11)
    optional = optional_capabilities(deep=deep)
    deep_ok = not deep or all(
        not item["available"] or item.get("usable") is True for item in optional
    )
    return {
        "schema": "sharesafe.doctor/v1",
        "tool": {"name": "sharesafe", "version": tool_version},
        "status": "ready" if python_ok and deep_ok else "incomplete",
        "offline": True,
        "telemetry": False,
        "probe_mode": "deep" if deep else "discovery",
        "runtime": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.system(),
        },
        "core": {"available": python_ok, "minimum_python": "3.11"},
        "optional": optional,
        "filesystem_safety": filesystem_safety_capabilities(),
        "note": (
            "Missing or unusable optional dependencies are surfaced as coverage "
            "gaps when they affect an input."
        ),
    }


__all__ = [
    "doctor_payload",
    "filesystem_safety_capabilities",
    "optional_capabilities",
]
