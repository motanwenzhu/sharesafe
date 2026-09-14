from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from sharesafe.engine import ScanConfig, Scanner
from sharesafe.limits import Limits
from sharesafe.models import ReportBuilder


def _rules(report: dict[str, object]) -> set[str]:
    return {item["rule_id"] for item in report["findings"]}  # type: ignore[index]


def test_clean_text_is_no_findings_not_safe(tmp_path: Path) -> None:
    sample = tmp_path / "notes.txt"
    sample.write_text("Public release notes only.\n", encoding="utf-8")

    builder = Scanner().scan([sample])
    report = builder.to_dict()

    assert report["summary"]["verdict"] == "no_findings"
    assert builder.exit_code("high") == 0
    assert "safe" not in report["summary"]["verdict"]


def test_report_masks_content_filename_and_absolute_root(tmp_path: Path) -> None:
    email = "reviewer" + "@example.test"
    token = "sk-" + "Q7_" * 9
    sample = tmp_path / f"export-{email}.txt"
    sample.write_text(f"contact={email}\napi_key={token}\n", encoding="utf-8")

    report = Scanner().scan([sample]).to_dict()
    serialized = json.dumps(report, ensure_ascii=False)

    assert email not in serialized
    assert token not in serialized
    assert str(tmp_path) not in serialized
    assert "<email:redacted>" in serialized
    assert {"pii.email", "secret.openai_api_key", "SS-GEN-PII-FILENAME"} <= _rules(report)


def test_unknown_binary_is_incomplete_and_exit_two(tmp_path: Path) -> None:
    sample = tmp_path / "opaque.bin"
    sample.write_bytes(b"\x00\x01\x02\x03" * 64)

    builder = Scanner().scan([sample])
    report = builder.to_dict()

    assert report["summary"]["verdict"] == "incomplete"
    assert builder.exit_code("never") == 2
    assert any(gap["reason"] == "unsupported_format" for gap in report["gaps"])


def test_sensitive_filename_blocks_even_with_benign_body(tmp_path: Path) -> None:
    sample = tmp_path / ".env"
    sample.write_text("DEBUG=false\n", encoding="utf-8")

    builder = Scanner().scan([sample])

    assert "SS-GEN-SENSITIVE-FILENAME" in _rules(builder.to_dict())
    assert builder.to_dict()["summary"]["verdict"] == "block"
    assert builder.exit_code("high") == 1


@pytest.mark.parametrize(
    ("filename", "rule_id", "category"),
    (
        ("sk-" + "S" * 28 + ".txt", "secret.openai_api_key", "secret"),
        ("/home/synthetic-user/private/notes.txt", "privacy.unix_user_path", "path_disclosure"),
        ("proposal\u202ereview.txt", "unicode.bidi_control", "unicode_control"),
    ),
)
def test_non_pii_filename_detector_hits_are_structured_findings(
    filename: str, rule_id: str, category: str
) -> None:
    builder = ReportBuilder(limits=Limits())
    Scanner().scan_bytes(
        b"synthetic public note\n",
        "artifact.txt",
        builder,
        depth=0,
        sniff_path="artifact.txt",
        filename_scan_path=filename,
    )

    finding = next(item for item in builder.to_dict()["findings"] if item["rule_id"] == rule_id)
    assert finding["category"] == category
    assert finding["location"] == {"kind": "filename"}
    assert finding["evidence"]["mode"] == "masked"
    assert builder.to_dict()["summary"]["verdict"] != "no_findings"
    assert filename not in json.dumps(builder.to_dict(), ensure_ascii=False)


def test_per_artifact_finding_limit_is_bounded_and_incomplete(tmp_path: Path) -> None:
    sample = tmp_path / "many.txt"
    sample.write_text(
        "\n".join(f"synthetic{index}@example.test" for index in range(8)),
        encoding="utf-8",
    )
    limits = replace(Limits(), max_findings_per_artifact=3, max_findings_total=20)

    builder = Scanner(ScanConfig(limits=limits)).scan([sample])
    report = builder.to_dict()

    assert len(report["findings"]) == 3
    assert [item["location"]["line"] for item in report["findings"]] == [1, 2, 3]
    assert [gap["reason"] for gap in report["gaps"]].count("artifact_finding_limit") == 1
    assert report["summary"]["verdict"] == "incomplete"
    assert builder.exit_code("never") == 2


def test_text_finding_locations_track_lines_and_columns_in_one_pass(tmp_path: Path) -> None:
    sample = tmp_path / "locations.txt"
    sample.write_text(
        "prefix first@example.test suffix\n\n  second@example.test",
        encoding="utf-8",
    )

    findings = Scanner().scan([sample]).to_dict()["findings"]

    locations = [item["location"] for item in findings if item["rule_id"] == "pii.email"]
    assert [(item["line"], item["column"]) for item in locations] == [(1, 8), (3, 3)]


def test_global_finding_limit_is_bounded_once_and_incomplete(tmp_path: Path) -> None:
    for name in ("a.txt", "b.txt"):
        (tmp_path / name).write_text(
            "\n".join(f"{name[0]}{index}@example.test" for index in range(4)),
            encoding="utf-8",
        )
    limits = replace(Limits(), max_findings_per_artifact=10, max_findings_total=5)

    builder = Scanner(ScanConfig(limits=limits)).scan([tmp_path])
    report = builder.to_dict()

    assert len(report["findings"]) == 5
    global_gaps = [gap for gap in report["gaps"] if gap["reason"] == "global_finding_limit"]
    assert len(global_gaps) == 1
    assert global_gaps[0]["artifact_id"] is None
    assert report["summary"]["verdict"] == "incomplete"
    assert builder.exit_code("high") == 2


def test_exact_finding_limit_does_not_claim_truncation(tmp_path: Path) -> None:
    sample = tmp_path / "exact.txt"
    sample.write_text(
        "\n".join(f"exact{index}@example.test" for index in range(3)),
        encoding="utf-8",
    )
    limits = replace(Limits(), max_findings_per_artifact=3, max_findings_total=3)

    builder = Scanner(ScanConfig(limits=limits)).scan([sample])
    report = builder.to_dict()

    assert len(report["findings"]) == 3
    assert not any(gap["reason"].endswith("finding_limit") for gap in report["gaps"])
    assert report["summary"]["verdict"] == "block"
    assert builder.exit_code("high") == 1


@pytest.mark.parametrize("incomplete_state", ("gap", "error", "partial"))
def test_incomplete_state_takes_precedence_over_blocking_findings(
    incomplete_state: str, tmp_path: Path
) -> None:
    sample = tmp_path / "risky.txt"
    sample.write_text("contact=" + "person@example.test", encoding="utf-8")
    builder = Scanner().scan([sample])

    assert builder.to_dict()["summary"]["verdict"] == "block"
    assert builder.exit_code("high") == 1
    artifact = builder.artifacts[0]
    if incomplete_state == "gap":
        builder.add_gap(artifact, "text", "synthetic_gap", "Synthetic coverage gap.")
    elif incomplete_state == "error":
        builder.add_error("synthetic_error", "Synthetic processing error.")
    else:
        artifact.set_coverage("text", "partial")

    assert builder.to_dict()["summary"]["verdict"] == "incomplete"
    assert builder.exit_code("high") == 2
    assert builder.exit_code("never") == 2


def test_vcs_metadata_is_not_traversed_and_forces_incomplete(tmp_path: Path) -> None:
    repository = tmp_path / "bundle"
    git_dir = repository / ".git"
    git_dir.mkdir(parents=True)
    (git_dir / "config").write_text("synthetic history", encoding="utf-8")
    (repository / "README.txt").write_text("public", encoding="utf-8")

    report = Scanner().scan([repository]).to_dict()

    assert "SS-GEN-VCS-METADATA" in _rules(report)
    assert any(gap["reason"] == "vcs_history_not_scanned" for gap in report["gaps"])
    assert not any("config" in artifact["path"] for artifact in report["artifacts"])
    assert report["summary"]["verdict"] == "incomplete"


def test_utf16_and_gb18030_are_scanned(tmp_path: Path) -> None:
    email_one = "utf16" + "@example.test"
    email_two = "gb18030" + "@example.test"
    first = tmp_path / "one.txt"
    second = tmp_path / "two.txt"
    first.write_bytes(("联系人 " + email_one).encode("utf-16"))
    second.write_bytes(("联系人 " + email_two).encode("gb18030"))

    report = Scanner().scan([first, second]).to_dict()

    assert [finding["rule_id"] for finding in report["findings"]].count("pii.email") == 2
    serialized = json.dumps(report, ensure_ascii=False)
    assert email_one not in serialized and email_two not in serialized


def test_total_file_count_limit_is_explicit(tmp_path: Path) -> None:
    for index in range(3):
        (tmp_path / f"{index}.txt").write_text("public", encoding="utf-8")
    scanner = Scanner(ScanConfig(limits=replace(Limits(), max_files=2)))
    report = scanner.scan([tmp_path]).to_dict()

    assert any(gap["reason"] == "file_count_limit" for gap in report["gaps"])
    assert report["summary"]["verdict"] == "incomplete"
