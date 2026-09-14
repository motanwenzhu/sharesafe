from __future__ import annotations

import io
import json
from pathlib import Path
import zipfile

from sharesafe.cli import main


def _call_json(capsys, arguments: list[str]) -> tuple[int, dict[str, object], str]:
    code = main([*arguments, "--json"])
    captured = capsys.readouterr()
    return code, json.loads(captured.out), captured.err


def _docx_with_author() -> bytes:
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
    return package.getvalue()


def _write_incomplete_blocking_tree(root: Path) -> None:
    root.mkdir()
    (root / "risky.txt").write_text(
        "contact=" + "person@example.test", encoding="utf-8"
    )
    (root / "opaque.bin").write_bytes(b"\x00\x01\x02" * 20)


def test_cli_exit_codes_and_json_stdout(tmp_path: Path, capsys) -> None:
    clean = tmp_path / "clean.txt"
    risky = tmp_path / "risky.txt"
    opaque = tmp_path / "opaque.bin"
    clean.write_text("public notes", encoding="utf-8")
    risky.write_text("contact=" + "person@example.test", encoding="utf-8")
    opaque.write_bytes(b"\x00\x01\x02" * 20)

    code, payload, error = _call_json(capsys, ["scan", str(clean)])
    assert code == 0 and payload["schema"] == "sharesafe.report/v1" and error == ""
    code, payload, error = _call_json(capsys, ["scan", str(risky)])
    assert code == 1 and payload["summary"]["verdict"] == "block" and error == ""  # type: ignore[index]
    code, payload, error = _call_json(capsys, ["scan", str(opaque)])
    assert code == 2 and payload["summary"]["verdict"] == "incomplete" and error == ""  # type: ignore[index]


def test_incomplete_exit_takes_precedence_over_high_risk_findings(tmp_path: Path, capsys) -> None:
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.comment = ("sk-" + "S" * 28).encode()
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/document.xml", b"<broken>")
    sample = tmp_path / "synthetic.docx"
    sample.write_bytes(package.getvalue())

    code, payload, error = _call_json(capsys, ["scan", str(sample)])

    assert code == 2 and error == ""
    assert payload["summary"]["verdict"] == "incomplete"  # type: ignore[index]
    assert payload["summary"]["gaps"] > 0  # type: ignore[index]
    assert payload["summary"]["findings"]["critical"] > 0  # type: ignore[index]


def test_cli_invalid_limit_and_overwrite_return_three(tmp_path: Path, capsys) -> None:
    source = tmp_path / "source.txt"
    output = tmp_path / "output.txt"
    source.write_text("public", encoding="utf-8")
    output.write_text("keep", encoding="utf-8")

    code, payload, _ = _call_json(capsys, ["scan", str(source), "--max-archive-depth", "-1"])
    assert code == 3 and payload["schema"] == "sharesafe.error/v1"
    code, payload, _ = _call_json(capsys, ["scan", str(source), "--max-findings-total", "0"])
    assert code == 3 and payload["schema"] == "sharesafe.error/v1"
    code, payload, _ = _call_json(capsys, ["sanitize", str(source), "--out", str(output)])
    assert code == 3 and payload["schema"] == "sharesafe.error/v1"
    assert output.read_text(encoding="utf-8") == "keep"


def test_cli_finding_limits_are_configurable_and_fail_closed(tmp_path: Path, capsys) -> None:
    source = tmp_path / "many.txt"
    source.write_text(
        "\n".join(f"cli{index}@example.test" for index in range(5)),
        encoding="utf-8",
    )

    code, payload, error = _call_json(
        capsys,
        [
            "scan",
            str(source),
            "--max-findings-per-artifact",
            "2",
            "--max-findings-total",
            "4",
        ],
    )

    assert code == 2 and error == ""
    assert len(payload["findings"]) == 2
    assert any(gap["reason"] == "artifact_finding_limit" for gap in payload["gaps"])
    assert payload["run"]["limits"]["max_findings_per_artifact"] == 2


def test_cli_report_is_atomic_new_file_and_collision_is_refused(tmp_path: Path, capsys) -> None:
    source = tmp_path / "source.txt"
    report_path = tmp_path / "report.json"
    source.write_text("public", encoding="utf-8")

    code = main(["scan", str(source), "--json", "--report", str(report_path)])
    first = capsys.readouterr()
    assert code == 0
    assert json.loads(first.out) == json.loads(report_path.read_text(encoding="utf-8"))

    code = main(["scan", str(source), "--json", "--report", str(report_path)])
    second = capsys.readouterr()
    assert code == 3
    assert json.loads(second.out)["error"]["code"] == "unsafe_or_invalid_request"


def test_cli_verify_uses_shared_evidence_key(tmp_path: Path, capsys) -> None:
    value = "unchanged" + "@example.test"
    original = tmp_path / "original.txt"
    prepared = tmp_path / "prepared.txt"
    original.write_text(value, encoding="utf-8")
    prepared.write_text(value, encoding="utf-8")

    code, payload, error = _call_json(capsys, ["verify", str(original), str(prepared)])

    assert code == 1 and error == ""
    verification = payload["verification"]  # type: ignore[index]
    assert verification["outcome"] == "unchanged"
    assert verification["counts"] == {"resolved": 0, "remaining": 1, "introduced": 0}
    assert value not in json.dumps(payload)


def test_cli_verify_rejects_empty_replacement_for_sensitive_file(tmp_path: Path, capsys) -> None:
    original = tmp_path / "original.txt"
    prepared = tmp_path / "prepared.txt"
    original.write_text("contact=" + "removed@example.test", encoding="utf-8")
    prepared.write_bytes(b"")

    code, payload, error = _call_json(capsys, ["verify", str(original), str(prepared)])

    assert code == 2 and error == ""
    verification = payload["verification"]  # type: ignore[index]
    assert verification["outcome"] == "incomplete"
    assert verification["ready_for_review"] is False
    assert verification["integrity"]["outcome"] == "unverified"


def test_cli_sanitize_verifies_recorded_docx_metadata_change(tmp_path: Path, capsys) -> None:
    original = tmp_path / "original.docx"
    prepared = tmp_path / "prepared.docx"
    original.write_bytes(_docx_with_author())

    code, payload, error = _call_json(
        capsys,
        ["sanitize", str(original), "--out", str(prepared)],
    )

    assert code == 0 and error == ""
    assert payload["before"]["artifacts"][0]["path"] == "artifact"  # type: ignore[index]
    assert payload["after"]["artifacts"][0]["path"] == "artifact"  # type: ignore[index]
    expected_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    assert payload["before"]["artifacts"][0]["media_type"] == expected_type  # type: ignore[index]
    assert payload["after"]["artifacts"][0]["media_type"] == expected_type  # type: ignore[index]
    verification = payload["verification"]  # type: ignore[index]
    assert verification["outcome"] == "improved"
    assert verification["ready_for_review"] is True
    assert verification["integrity"]["outcome"] == "transformed"


def test_cli_sanitize_incomplete_exit_precedes_blocking_findings(
    tmp_path: Path, capsys
) -> None:
    source = tmp_path / "original"
    prepared = tmp_path / "prepared"
    _write_incomplete_blocking_tree(source)

    code, payload, error = _call_json(
        capsys,
        [
            "sanitize",
            str(source),
            "--out",
            str(prepared),
            "--no-optional-tools",
        ],
    )

    after_summary = payload["after"]["summary"]  # type: ignore[index]
    assert code == 2 and error == ""
    assert after_summary["verdict"] == "incomplete"
    assert after_summary["gaps"] > 0
    assert after_summary["findings"]["high"] > 0
    assert payload["verification"]["outcome"] == "incomplete"  # type: ignore[index]


def test_cli_verify_incomplete_exit_precedes_blocking_findings(
    tmp_path: Path, capsys
) -> None:
    original = tmp_path / "original"
    prepared = tmp_path / "prepared"
    _write_incomplete_blocking_tree(original)
    _write_incomplete_blocking_tree(prepared)

    code, payload, error = _call_json(
        capsys,
        [
            "verify",
            str(original),
            str(prepared),
            "--no-optional-tools",
        ],
    )

    assert code == 2 and error == ""
    for side in ("original", "prepared"):
        summary = payload[side]["summary"]  # type: ignore[index]
        assert summary["verdict"] == "incomplete"
        assert summary["gaps"] > 0
        assert summary["findings"]["high"] > 0
    assert payload["verification"]["outcome"] == "incomplete"  # type: ignore[index]
    assert payload["verification"]["integrity"]["outcome"] == "preserved"  # type: ignore[index]


def test_report_cannot_be_written_inside_scanned_directory(tmp_path: Path, capsys) -> None:
    source = tmp_path / "bundle"
    source.mkdir()
    (source / "file.txt").write_text("public", encoding="utf-8")

    code, payload, _ = _call_json(
        capsys,
        ["scan", str(source), "--report", str(source / "report.json")],
    )

    assert code == 3
    assert payload["error"]["code"] == "unsafe_or_invalid_request"  # type: ignore[index]
    assert not (source / "report.json").exists()


def test_argparse_errors_use_contract_exit_three_and_json(capsys) -> None:
    code = main(["scan", "--json"])
    captured = capsys.readouterr()

    assert code == 3
    assert captured.err == ""
    assert json.loads(captured.out)["error"]["code"] == "invalid_arguments"


def test_self_test_checks_report_privacy_invariants(capsys) -> None:
    code, payload, error = _call_json(capsys, ["self-test"])

    assert code == 0 and error == ""
    assert payload["passed"] is True
    checks = payload["checks"]
    assert checks["raw_file_digest_absent"] is True  # type: ignore[index]
    assert checks["content_token_is_keyed"] is True  # type: ignore[index]


def test_doctor_lists_only_integrated_optional_dependencies(capsys) -> None:
    code, payload, error = _call_json(capsys, ["doctor"])

    assert code == 0 and error == ""
    optional = payload["optional"]
    assert {item["name"] for item in optional} == {"Pillow", "pypdf"}  # type: ignore[union-attr]
