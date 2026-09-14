from __future__ import annotations

import io
import json
from pathlib import Path
import zipfile

import pytest

from sharesafe.cli import main
from sharesafe.detectors import sanitize_display_path, temporary_hmac_key
from sharesafe.engine import ScanConfig, Scanner
from sharesafe.verify import compare_reports


def _rules(report: dict) -> set[str]:
    return {finding["rule_id"] for finding in report["findings"]}


def test_single_root_directory_name_is_scanned_and_masked(tmp_path: Path) -> None:
    email = "root-folder" + "@example.test"
    root = tmp_path / f"bundle-{email}"
    root.mkdir()
    (root / "clean.txt").write_text("public", encoding="utf-8")

    report = Scanner(ScanConfig(optional_tools=False)).scan([root]).to_dict()
    serialized = json.dumps(report)

    assert "SS-GEN-PII-FILENAME" in _rules(report)
    assert email not in serialized
    assert any(artifact["media_type"] == "inode/directory" for artifact in report["artifacts"])


def test_selected_user_home_root_never_exposes_bare_username(tmp_path: Path) -> None:
    username = "synthetic-private-user"
    root = tmp_path / "Users" / username
    root.mkdir(parents=True)
    (root / "clean.txt").write_text("public", encoding="utf-8")

    report = Scanner(ScanConfig(optional_tools=False)).scan([root]).to_dict()
    serialized = json.dumps(report)

    assert username not in serialized
    assert report["artifacts"][0]["path"] == "<user>"
    assert "privacy.unix_user_path" in _rules(report)


def test_relative_user_home_directory_component_is_masked(tmp_path: Path) -> None:
    username = "synthetic-relative-user"
    root = tmp_path / "bundle"
    (root / "Users" / username).mkdir(parents=True)

    report = Scanner(ScanConfig(optional_tools=False)).scan([root]).to_dict()
    serialized = json.dumps(report)

    assert username not in serialized
    assert "privacy.windows_user_path" in _rules(report)


@pytest.mark.parametrize(
    ("container", "rule_id"),
    (("Users", "privacy.windows_user_path"), ("home", "privacy.unix_user_path")),
)
def test_selected_user_home_container_masks_first_descendant(
    tmp_path: Path,
    container: str,
    rule_id: str,
) -> None:
    username = f"synthetic-{container.casefold()}-user"
    root = tmp_path / container
    (root / username).mkdir(parents=True)
    (root / username / "clean.txt").write_text("public", encoding="utf-8")

    report = Scanner(ScanConfig(optional_tools=False)).scan([root]).to_dict()
    serialized = json.dumps(report)

    assert username not in serialized
    assert rule_id in _rules(report)
    assert any(artifact["path"] == "<user>/clean.txt" for artifact in report["artifacts"])


def test_sanitize_and_verify_inherit_selected_user_container_context(
    tmp_path: Path,
    capsys,
) -> None:
    username = "synthetic-container-user"
    root = tmp_path / "Users"
    (root / username).mkdir(parents=True)
    (root / username / "clean.txt").write_text("public", encoding="utf-8")
    prepared = tmp_path / "prepared"

    sanitize_code = main([
        "sanitize",
        str(root),
        "--out",
        str(prepared),
        "--json",
        "--no-optional-tools",
    ])
    sanitize_capture = capsys.readouterr()
    sanitize_payload = json.loads(sanitize_capture.out)

    verify_code = main([
        "verify",
        str(root),
        str(prepared),
        "--json",
        "--no-optional-tools",
    ])
    verify_capture = capsys.readouterr()
    verify_payload = json.loads(verify_capture.out)

    assert sanitize_code == 1
    assert verify_code == 1
    assert sanitize_capture.err == verify_capture.err == ""
    assert username not in json.dumps(sanitize_payload)
    assert username not in json.dumps(verify_payload)
    assert sanitize_payload["verification"]["integrity"]["outcome"] == "preserved"
    assert verify_payload["verification"]["integrity"]["outcome"] == "preserved"
    assert "privacy.windows_user_path" in _rules(sanitize_payload["before"])
    assert "privacy.windows_user_path" in _rules(sanitize_payload["after"])


def test_deleted_empty_directory_is_visible_to_verification(tmp_path: Path) -> None:
    email = "empty-folder" + "@example.test"
    original = tmp_path / "original"
    prepared = tmp_path / "prepared"
    (original / f"empty-{email}").mkdir(parents=True)
    prepared.mkdir()
    key = temporary_hmac_key()
    config = ScanConfig(logical_paths=True, optional_tools=False)

    before = Scanner(config, evidence_key=key).scan([original]).to_dict()
    after = Scanner(config, evidence_key=key).scan([prepared]).to_dict()
    result = compare_reports(before, after)

    assert "SS-GEN-PII-FILENAME" in _rules(before)
    assert len(before["artifacts"]) == 2
    assert len(after["artifacts"]) == 1
    assert result["outcome"] == "incomplete"
    assert result["integrity"]["outcome"] == "unverified"
    assert result["ready_for_review"] is False


def test_zip_directory_entry_name_is_inventory_and_scanned(tmp_path: Path) -> None:
    email = "zip-folder" + "@example.test"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        info = zipfile.ZipInfo(f"empty-{email}/", date_time=(2000, 1, 1, 0, 0, 0))
        archive.writestr(info, b"")
    sample = tmp_path / "bundle.zip"
    sample.write_bytes(output.getvalue())

    report = Scanner(ScanConfig(optional_tools=False)).scan([sample]).to_dict()

    assert "SS-GEN-PII-FILENAME" in _rules(report)
    assert any(
        artifact["media_type"] == "inode/directory" and "!/" in artifact["path"]
        for artifact in report["artifacts"]
    )
    assert email not in json.dumps(report)


def test_ooxml_xml_part_name_is_scanned_without_exposing_it(tmp_path: Path) -> None:
    email = "xml-part" + "@example.test"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            b'<Types><Override PartName="/word/document.xml" ContentType="application/xml"/></Types>',
        )
        archive.writestr("word/document.xml", b"<document/>")
        archive.writestr(f"unusual/private-{email}.xml", b"<public/>")
    sample = tmp_path / "sample.docx"
    sample.write_bytes(output.getvalue())

    report = Scanner(ScanConfig(optional_tools=False)).scan([sample]).to_dict()

    assert "SS-GEN-PII-FILENAME" in _rules(report)
    assert email not in json.dumps(report)


def test_repeated_separator_user_paths_are_detected_and_masked() -> None:
    samples = (
        "prefix-//synthetic-host/Users/synthetic-user/private.txt",
        "prefix-C://Users//synthetic-user/private.txt",
        "prefix-\\\\synthetic-host\\Users\\synthetic-user\\private.txt",
    )

    for raw in samples:
        sanitized = sanitize_display_path(raw)
        assert "synthetic-host" not in sanitized
        assert "synthetic-user" not in sanitized
        assert "<user>" in sanitized


def test_zip_unc_style_member_never_leaks_host_or_user(tmp_path: Path) -> None:
    host = "synthetic-private-host"
    user = "synthetic-private-user"
    member = f"prefix-\\\\{host}\\Users\\{user}\\public.txt"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        info = zipfile.ZipInfo(member, date_time=(2000, 1, 1, 0, 0, 0))
        archive.writestr(info, b"public")
    sample = tmp_path / "bundle.zip"
    sample.write_bytes(output.getvalue())

    report = Scanner(ScanConfig(optional_tools=False)).scan([sample]).to_dict()
    serialized = json.dumps(report)

    assert "privacy.windows_user_path" in _rules(report)
    assert host not in serialized and user not in serialized


def test_finding_ids_are_unique_for_repeated_rule_and_location(tmp_path: Path) -> None:
    sample = tmp_path / "first@example.test,second@example.test.txt"
    sample.write_text("public", encoding="utf-8")

    findings = Scanner(ScanConfig(optional_tools=False)).scan([sample]).to_dict()["findings"]
    ids = [finding["id"] for finding in findings]

    assert len(findings) >= 2
    assert len(ids) == len(set(ids))
