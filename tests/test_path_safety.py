from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from sharesafe.cli import main
from sharesafe.limits import Limits
from sharesafe.path_safety import _has_windows_alternate_stream_syntax, same_or_within
from sharesafe.reporting import write_json_atomic
from sharesafe.sanitize import UnsafeSanitizeRequest, create_sanitized_copy


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (r"C:\folder\file.txt", False),
        (r"\\?\C:\folder\file.txt", False),
        (r"\\server\share\file.txt", False),
        (r"file.txt:stream", True),
        (r"C:\folder\file.txt:stream", True),
        (r"\\?\C:\folder\file.txt::$DATA", True),
        (r"\\server:443\share\file.txt", True),
    ),
)
def test_windows_stream_syntax_is_detected_cross_platform(value: str, expected: bool) -> None:
    assert _has_windows_alternate_stream_syntax(value) is expected


@pytest.mark.skipif(os.name != "nt", reason="NTFS alternate streams are Windows-specific")
def test_sanitize_and_report_reject_alternate_stream_destinations(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_bytes(b"synthetic public content")
    before = (source.read_bytes(), source.stat().st_mtime_ns)
    stream = Path(f"{source}:sharesafe-test")

    with pytest.raises(UnsafeSanitizeRequest, match="alternate data stream"):
        create_sanitized_copy(source, stream, Limits())
    with pytest.raises(ValueError, match="alternate data stream"):
        write_json_atomic(stream, {"synthetic": True})

    assert (source.read_bytes(), source.stat().st_mtime_ns) == before


def test_resolved_containment_blocks_alias_into_scan_boundary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "note.txt").write_text("synthetic public note", encoding="utf-8")
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(source, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this host")

    report = alias / "report.json"
    destination = alias / "prepared"
    assert same_or_within(report, source)

    code = main(["scan", str(source), "--report", str(report), "--json"])
    captured = capsys.readouterr()
    assert code == 3 and captured.err == ""
    assert json.loads(captured.out)["error"]["code"] == "unsafe_or_invalid_request"
    assert not (source / "report.json").exists()

    with pytest.raises(UnsafeSanitizeRequest):
        create_sanitized_copy(source, destination, Limits())
    assert not (source / "prepared").exists()
