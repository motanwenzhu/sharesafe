from __future__ import annotations

from dataclasses import replace
import io
from pathlib import Path
import stat
import warnings
import zipfile

from sharesafe.engine import ScanConfig, Scanner
from sharesafe.limits import Limits
from sharesafe.reporting import render_scan


def _zip(entries: list[tuple[str, bytes]], *, compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for name, value in entries:
            archive.writestr(name, value)
    return buffer.getvalue()


def _rules(report: dict[str, object]) -> set[str]:
    return {item["rule_id"] for item in report["findings"]}  # type: ignore[index]


def test_nested_zip_text_is_scanned_without_extraction(tmp_path: Path) -> None:
    email = "archive" + "@example.test"
    data = _zip([("nested/notes.txt", email.encode())])
    sample = tmp_path / "bundle.zip"
    sample.write_bytes(data)

    report = Scanner().scan([sample]).to_dict()

    assert "pii.email" in _rules(report)
    assert email not in str(report)
    assert any("!/nested/notes.txt" in artifact["path"] for artifact in report["artifacts"])
    assert not (tmp_path / "nested").exists()


def test_archive_traversal_is_never_opened(tmp_path: Path) -> None:
    data = _zip([("../escape.txt", b"should not be read")])
    sample = tmp_path / "traversal.zip"
    sample.write_bytes(data)
    public = Scanner().scan([sample]).to_dict()
    assert "SS-ARCHIVE-PATH-TRAVERSAL" in _rules(public)
    assert any(gap["reason"] == "unsafe_member_name" for gap in public["gaps"])
    assert not (tmp_path.parent / "escape.txt").exists()


def test_archive_duplicate_names_are_reported(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("same.txt", b"one")
            archive.writestr("same.txt", b"two")
    sample = tmp_path / "duplicate.zip"
    sample.write_bytes(buffer.getvalue())

    report = Scanner().scan([sample]).to_dict()

    assert "SS-ARCHIVE-DUPLICATE-NAME" in _rules(report)
    assert any("duplicate 2" in artifact["path"] for artifact in report["artifacts"])


def test_archive_symlink_is_not_followed(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("link.txt")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "../../outside")
    sample = tmp_path / "link.zip"
    sample.write_bytes(buffer.getvalue())

    report = Scanner().scan([sample]).to_dict()

    assert "SS-ARCHIVE-SYMLINK" in _rules(report)
    assert any(gap["reason"] == "archive_link_not_followed" for gap in report["gaps"])


def test_nested_depth_limit_is_incomplete(tmp_path: Path) -> None:
    inner = _zip([("public.txt", b"public")])
    outer = _zip([("inner.zip", inner)])
    sample = tmp_path / "nested.zip"
    sample.write_bytes(outer)
    limits = replace(Limits(), max_archive_depth=1)

    report = Scanner(ScanConfig(limits=limits)).scan([sample]).to_dict()

    assert any(gap["reason"] == "archive_depth_limit" for gap in report["gaps"])
    assert report["summary"]["verdict"] == "incomplete"


def test_high_compression_ratio_is_bounded(tmp_path: Path) -> None:
    data = _zip([("compressible.txt", b"A" * (2 * 1024 * 1024))])
    sample = tmp_path / "ratio.zip"
    sample.write_bytes(data)

    report = Scanner().scan([sample]).to_dict()

    assert any(gap["reason"] == "compression_ratio_limit" for gap in report["gaps"])
    assert not any(artifact["path"].endswith("compressible.txt") for artifact in report["artifacts"])


def test_archive_member_controls_are_visible_in_human_output(tmp_path: Path) -> None:
    controls = "\r\n\t\x1b\x7f\x85"
    data = _zip([(f"folder/{controls}forged.txt", b"person@example.test")])
    sample = tmp_path / "control-name.zip"
    sample.write_bytes(data)

    report = Scanner().scan([sample]).to_dict()
    member_path = next(
        artifact["path"] for artifact in report["artifacts"]
        if "!/folder/" in artifact["path"]
    )
    output = io.StringIO()
    render_scan(report, output)
    rendered = output.getvalue()

    assert all(character not in member_path for character in controls)
    assert all(f"U+{ord(character):04X}" in member_path for character in controls)
    assert member_path in rendered
    assert controls not in rendered
