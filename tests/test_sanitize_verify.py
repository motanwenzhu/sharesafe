from __future__ import annotations

import io
from copy import deepcopy
import json
from pathlib import Path
import struct
import zlib
import zipfile

import pytest

from sharesafe.detectors import temporary_hmac_key
from sharesafe.engine import ScanConfig, Scanner
from sharesafe.limits import Limits
from sharesafe.sanitize import UnsafeSanitizeRequest, _sanitize_png, create_sanitized_copy
from sharesafe.reporting import write_json_atomic
from sharesafe.verify import compare_reports


def _chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)


def _png_with_text(text: str) -> bytes:
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    scanline = b"\x00\xff\x00\x00\xff"
    return b"".join(
        [
            signature,
            _chunk(b"IHDR", ihdr),
            _chunk(b"tEXt", b"Comment\x00" + text.encode()),
            _chunk(b"IDAT", zlib.compress(scanline)),
            _chunk(b"IEND", b""),
        ]
    )


def test_png_sanitize_removes_text_chunk_without_changing_source(tmp_path: Path) -> None:
    email = "image" + "@example.test"
    source = tmp_path / "source.png"
    output = tmp_path / "prepared.png"
    source.write_bytes(_png_with_text(email))
    original = source.read_bytes()

    actions = create_sanitized_copy(source, output, Limits())
    cleaned, removed, reason = _sanitize_png(original)

    assert source.read_bytes() == original
    assert output.read_bytes() == cleaned
    assert removed == 1
    assert reason is None
    assert email.encode() not in output.read_bytes()
    assert any(item["action"] == "strip_png_metadata" and item["status"] == "applied" for item in actions)


def test_sanitize_refuses_overwrite_and_output_inside_source(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "notes.txt").write_text("public", encoding="utf-8")
    existing = tmp_path / "existing"
    existing.mkdir()

    with pytest.raises(UnsafeSanitizeRequest, match="never overwrites"):
        create_sanitized_copy(source, existing, Limits())
    with pytest.raises(UnsafeSanitizeRequest, match="inside"):
        create_sanitized_copy(source, source / "prepared", Limits())


def test_unchanged_sensitive_file_is_remaining_not_introduced(tmp_path: Path) -> None:
    email = "same" + "@example.test"
    original = tmp_path / "original.txt"
    prepared = tmp_path / "prepared.txt"
    original.write_text(email, encoding="utf-8")
    prepared.write_text(email, encoding="utf-8")
    key = temporary_hmac_key()
    config = ScanConfig(logical_paths=True)

    before = Scanner(config, evidence_key=key).scan([original]).to_dict()
    after = Scanner(config, evidence_key=key).scan([prepared]).to_dict()
    result = compare_reports(before, after)

    assert result["outcome"] == "unchanged"
    assert result["counts"]["remaining"] == 1
    assert result["counts"]["introduced"] == 0
    assert result["counts"]["resolved"] == 0


def test_verify_counts_duplicate_semantic_findings_as_distinct_occurrences(tmp_path: Path) -> None:
    email = "duplicate" + "@example.test"
    source = tmp_path / "source.txt"
    source.write_text(email, encoding="utf-8")
    report = Scanner(ScanConfig(logical_paths=True)).scan([source]).to_dict()
    duplicate = deepcopy(report["findings"][0])
    duplicate["id"] = "synthetic-duplicate-finding"

    before = deepcopy(report)
    before["findings"].append(duplicate)
    after = deepcopy(report)
    improved = compare_reports(before, after)
    regressed = compare_reports(after, before)

    assert improved["counts"] == {"resolved": 1, "remaining": 1, "introduced": 0}
    assert improved["outcome"] == "improved"
    assert regressed["counts"] == {"resolved": 0, "remaining": 1, "introduced": 1}
    assert regressed["outcome"] == "regressed"


def test_deleted_content_cannot_pass_artifact_verification(tmp_path: Path) -> None:
    original = tmp_path / "original.txt"
    prepared = tmp_path / "prepared.txt"
    original.write_text("contact=" + "deleted@example.test", encoding="utf-8")
    prepared.write_bytes(b"")
    key = temporary_hmac_key()
    config = ScanConfig(logical_paths=True)

    before = Scanner(config, evidence_key=key).scan([original]).to_dict()
    after = Scanner(config, evidence_key=key).scan([prepared]).to_dict()
    result = compare_reports(before, after)

    assert result["outcome"] == "incomplete"
    assert result["ready_for_review"] is False
    assert result["integrity"]["outcome"] == "unverified"
    assert {issue["code"] for issue in result["integrity"]["issues"]} == {
        "artifact_content_changed"
    }


def test_recorded_ooxml_metadata_transform_can_verify(tmp_path: Path) -> None:
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr(
            "docProps/core.xml",
            b'<cp:coreProperties xmlns:cp="urn:cp" xmlns:dc="urn:dc">'
            b"<dc:creator>Synthetic Author</dc:creator></cp:coreProperties>",
        )
        archive.writestr(
            "word/document.xml",
            b'<w:document xmlns:w="urn:w"><w:body><w:p><w:r><w:t>public</w:t>'
            b"</w:r></w:p></w:body></w:document>",
        )
    original = tmp_path / "original.docx"
    prepared = tmp_path / "prepared.docx"
    original.write_bytes(package.getvalue())
    key = temporary_hmac_key()
    config = ScanConfig(logical_paths=True)
    before = Scanner(config, evidence_key=key).scan([original]).to_dict()

    actions = create_sanitized_copy(original, prepared, Limits())
    after = Scanner(config, evidence_key=key).scan([prepared]).to_dict()
    result = compare_reports(before, after, allowed_actions=actions)

    assert [artifact["path"] for artifact in before["artifacts"]] == ["artifact"]
    assert [artifact["path"] for artifact in after["artifacts"]] == ["artifact"]
    assert before["artifacts"][0]["media_type"] == (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    assert after["artifacts"][0]["media_type"] == before["artifacts"][0]["media_type"]
    assert result["outcome"] == "improved"
    assert result["ready_for_review"] is True
    assert result["integrity"]["outcome"] == "transformed"
    assert result["integrity"]["allowed_transforms"][0]["action"] == "remove_ooxml_metadata"


def test_sanitize_actions_and_reports_never_contain_raw_filename_pii(tmp_path: Path) -> None:
    email = "filename" + "@example.test"
    source = tmp_path / f"photo-{email}.png"
    output = tmp_path / "prepared.png"
    source.write_bytes(_png_with_text("public"))

    actions = create_sanitized_copy(source, output, Limits())

    assert email not in json.dumps(actions, ensure_ascii=False)


def test_destination_race_never_overwrites_competing_file(tmp_path: Path, monkeypatch) -> None:
    import sharesafe.sanitize as sanitize_module

    source = tmp_path / "source.txt"
    destination = tmp_path / "prepared.txt"
    source.write_text("public", encoding="utf-8")

    def racing_link(staged, target, **kwargs):
        Path(target).write_text("competitor", encoding="utf-8")
        raise FileExistsError("synthetic race")

    monkeypatch.setattr(sanitize_module.os, "link", racing_link)
    with pytest.raises(UnsafeSanitizeRequest, match="nothing was overwritten"):
        create_sanitized_copy(source, destination, Limits())
    assert destination.read_text(encoding="utf-8") == "competitor"


def test_report_race_never_overwrites_competing_file(tmp_path: Path, monkeypatch) -> None:
    import sharesafe.reporting as reporting_module

    destination = tmp_path / "report.json"

    def racing_link(staged, target, **kwargs):
        Path(target).write_text("competitor", encoding="utf-8")
        raise FileExistsError("synthetic race")

    monkeypatch.setattr(reporting_module.os, "link", racing_link)
    with pytest.raises(FileExistsError, match="nothing was overwritten"):
        write_json_atomic(destination, {"synthetic": True})
    assert destination.read_text(encoding="utf-8") == "competitor"
