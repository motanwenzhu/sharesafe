from __future__ import annotations

from pathlib import Path

import pytest

import sharesafe.reporting as reporting
import sharesafe.sanitize as sanitize
from sharesafe.engine import Scanner
from sharesafe.limits import Limits
from sharesafe.sanitize import UnsafeSanitizeRequest


def _report(tmp_path: Path) -> dict:
    source = tmp_path / "synthetic.txt"
    source.write_text("synthetic public text", encoding="utf-8")
    return Scanner().scan([source]).to_dict()


def test_report_parent_drift_before_publish_never_creates_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "output" / "report.json"
    calls = 0

    def checkpoint(_snapshot) -> bool:  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        return calls == 1

    monkeypatch.setattr(reporting, "verify_directory_unchanged", checkpoint)

    with pytest.raises(OSError):
        reporting.write_json_atomic(destination, _report(tmp_path))

    assert calls >= 2
    assert not destination.exists()


def test_sanitize_parent_drift_before_commit_never_creates_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.txt"
    destination = tmp_path / "output" / "prepared.txt"
    source.write_text("synthetic public text", encoding="utf-8")
    monkeypatch.setattr(sanitize, "verify_directory_unchanged", lambda _snapshot: False)

    with pytest.raises(UnsafeSanitizeRequest, match="destination parent changed"):
        sanitize.create_sanitized_copy(source, destination, Limits())

    assert not destination.exists()


def test_output_parent_rejects_linked_ancestor_when_supported(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks are unavailable on this host")

    destination = linked / "report.json"
    with pytest.raises(OSError):
        reporting.write_json_atomic(destination, _report(tmp_path))

    assert not (real / "report.json").exists()
