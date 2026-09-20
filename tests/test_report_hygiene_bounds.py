from __future__ import annotations

from copy import deepcopy
import io
import json
from pathlib import Path

import pytest

from sharesafe.engine import Scanner
from sharesafe.limits import Limits
from sharesafe.models import REPORT_FIELD_LIMIT_PLACEHOLDER, ReportBuilder
from sharesafe.redaction import (
    DISPLAY_PATH_LIMIT_PLACEHOLDER,
    NAME_LIMIT_PLACEHOLDER,
    sanitize_display_path_result,
)
from sharesafe.report_hygiene import ReportHygieneError, validate_masked_payload
from sharesafe.reporting import json_text, render_scan, write_json_atomic


def _clean_report(tmp_path: Path) -> dict:
    sample = tmp_path / "synthetic.txt"
    sample.write_text("synthetic public text", encoding="utf-8")
    return Scanner().scan([sample]).to_dict()


def test_limits_allow_zero_directory_and_archive_depth() -> None:
    limits = Limits(max_directory_depth=0, max_archive_depth=0)

    assert limits.max_directory_depth == 0
    assert limits.max_archive_depth == 0


def test_oversized_name_is_wholly_replaced_and_makes_report_incomplete() -> None:
    limits = Limits(max_name_bytes=64, max_display_path_chars=256)
    builder = ReportBuilder(limits)

    artifact = builder.add_artifact(
        path="folder/" + "界" * 40 + ".txt",
        content_token=None,
        size=0,
        media_type="text/plain",
    )
    report = builder.to_dict()

    assert NAME_LIMIT_PLACEHOLDER in artifact.path
    assert "界" not in artifact.path
    assert artifact.status == "partial"
    assert report["summary"]["verdict"] == "incomplete"
    assert any(gap["reason"] == "name_limit" for gap in report["gaps"])


def test_control_character_expansion_never_leaks_a_raw_prefix() -> None:
    result = sanitize_display_path_result(
        "prefix-" + "\x1b" * 200,
        max_name_bytes=4096,
        max_display_path_chars=256,
    )

    assert result.value == DISPLAY_PATH_LIMIT_PLACEHOLDER
    assert "display_path_limit" in result.limit_reasons
    assert "prefix" not in result.value


def test_gap_and_error_budgets_reserve_a_control_gap() -> None:
    builder = ReportBuilder(Limits(max_gaps_total=4, max_errors_total=1))
    artifact = builder.add_artifact(
        path="artifact", content_token=None, size=0, media_type="text/plain"
    )

    for index in range(20):
        builder.add_gap(artifact, "synthetic", f"reason_{index}", "bounded detail")
        builder.add_error(f"error_{index}", "bounded message")
    report = builder.to_dict()

    assert len(report["gaps"]) <= 4
    assert len(report["errors"]) == 1
    reasons = {gap["reason"] for gap in report["gaps"]}
    assert "global_gap_limit" in reasons
    assert "global_error_limit" in reasons
    assert report["summary"]["verdict"] == "incomplete"


def test_long_report_field_is_fixed_placeholder_with_explicit_gap() -> None:
    builder = ReportBuilder(Limits(max_report_field_chars=256))
    artifact = builder.add_artifact(
        path="artifact", content_token=None, size=0, media_type="text/plain"
    )
    finding = builder.add_finding(
        artifact,
        rule_id="synthetic.rule",
        category="synthetic",
        severity="low",
        confidence=1.0,
        title="x" * 257,
    )
    report = builder.to_dict()

    assert finding is not None
    assert finding.title == REPORT_FIELD_LIMIT_PLACEHOLDER
    assert any(gap["reason"] == "report_field_limit" for gap in report["gaps"])
    assert report["summary"]["verdict"] == "incomplete"


def test_report_size_limit_returns_complete_minimal_json_not_a_prefix() -> None:
    builder = ReportBuilder(
        Limits(
            max_report_bytes=4096,
            max_findings_per_artifact=100,
            max_findings_total=100,
        )
    )
    artifact = builder.add_artifact(
        path="artifact", content_token=None, size=0, media_type="text/plain"
    )
    for index in range(100):
        builder.add_finding(
            artifact,
            rule_id=f"synthetic.rule.{index}",
            category="synthetic",
            severity="low",
            confidence=1.0,
            title="bounded synthetic title",
        )

    report = builder.to_dict()
    encoded = json_text(report).encode("utf-8")

    assert len(encoded) <= 4096
    assert report["summary"]["verdict"] == "incomplete"
    assert report["artifacts"] == []
    assert report["findings"] == []
    assert [gap["reason"] for gap in report["gaps"]] == ["report_size_limit"]
    assert json.loads(encoded) == report


@pytest.mark.parametrize(
    "mutation",
    (
        lambda report: report.update({"raw": "C:/Users/Synthetic Person/private.txt"}),
        lambda report: report.update({"raw": "line\nforgery"}),
        lambda report: report["findings"].append(
            {
                "id": "f-" + "0" * 20,
                "artifact_id": report["artifacts"][0]["id"],
                "rule_id": "synthetic.raw",
                "category": "synthetic",
                "severity": "high",
                "confidence": 1.0,
                "title": "raw evidence",
                "location": {"kind": "artifact"},
                "evidence": {"mode": "raw", "value": "synthetic-private-canary"},
                "remediation": {"supported": False, "action": "manual_review"},
            }
        ),
    ),
    ids=("absolute-home", "raw-control", "raw-evidence"),
)
def test_hygiene_rejects_injected_sensitive_or_untyped_fields(
    tmp_path: Path, mutation
) -> None:
    report = deepcopy(_clean_report(tmp_path))
    mutation(report)

    with pytest.raises(ReportHygieneError):
        validate_masked_payload(report)


def test_all_output_sinks_validate_before_emitting_or_creating(
    tmp_path: Path,
) -> None:
    report = _clean_report(tmp_path)
    report["raw"] = "C:/Users/Synthetic Person/private.txt"
    stream = io.StringIO()
    destination = tmp_path / "report.json"

    with pytest.raises(ReportHygieneError):
        json_text(report)
    with pytest.raises(ReportHygieneError):
        render_scan(report, stream)
    with pytest.raises(ReportHygieneError):
        write_json_atomic(destination, report)

    assert stream.getvalue() == ""
    assert not destination.exists()
