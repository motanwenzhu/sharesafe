from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest
from sharesafe.check import build_check
from sharesafe.limits import Limits
from sharesafe.models import ReportBuilder
from sharesafe.policy import policy_from_mapping
from sharesafe.report_tools import (
    REPORT_DIFF_SCHEMA,
    REPORT_SHOW_SCHEMA,
    SHARE_SUMMARY_SCHEMA,
    ReportToolError,
    diff_report_files,
    diff_reports,
    load_report_file,
    share_summary,
    show_report,
)

CONTENT_TOKEN_A = "hmac-sha256:content-v1:" + "1" * 32
CONTENT_TOKEN_B = "hmac-sha256:content-v1:" + "2" * 32
EVIDENCE_TOKEN_A = "hmac-sha256:v1:" + "3" * 32
EVIDENCE_TOKEN_B = "hmac-sha256:v1:" + "4" * 32


def _synthetic_report(*, duplicate_medium: bool = False) -> dict:
    builder = ReportBuilder(limits=Limits(), report_mode="local")
    first = builder.add_artifact(
        path="docs/alpha.txt",
        content_token=CONTENT_TOKEN_A,
        size=123,
        media_type="text/plain",
    )
    first.set_coverage("text", "complete")
    second = builder.add_artifact(
        path="docs/beta.txt",
        content_token=CONTENT_TOKEN_B,
        size=456,
        media_type="text/plain",
    )
    second.set_coverage("text", "complete")
    builder.add_finding(
        first,
        rule_id="synthetic.rule.alpha",
        category="synthetic_category",
        severity="medium",
        confidence=0.8,
        title="Synthetic medium signal",
        location={"kind": "text", "line": 2, "column": 3, "encoding": "utf-8"},
        evidence={
            "mode": "masked",
            "masked": "<synthetic:masked>",
            "value_class": "synthetic",
            "token": EVIDENCE_TOKEN_A,
        },
    )
    if duplicate_medium:
        builder.add_finding(
            first,
            rule_id="synthetic.rule.alpha",
            category="synthetic_category",
            severity="medium",
            confidence=0.7,
            title="Synthetic duplicate structural signal",
            location={"kind": "text", "line": 2, "column": 3, "encoding": "utf-8"},
            evidence={
                "mode": "masked",
                "masked": "<synthetic:other>",
                "value_class": "synthetic",
                "token": EVIDENCE_TOKEN_B,
            },
        )
    builder.add_finding(
        second,
        rule_id="synthetic.rule.beta",
        category="other_category",
        severity="critical",
        confidence=1.0,
        title="Synthetic critical signal",
        location={"kind": "filename"},
        evidence={"mode": "omitted", "value_class": "synthetic"},
    )
    return builder.to_dict()


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True), encoding="utf-8"
    )


def test_load_report_file_accepts_strict_report_and_check_documents(
    tmp_path: Path,
) -> None:
    report = _synthetic_report()
    check = build_check(report, policy_from_mapping({"fail_on": "critical"}))
    report_path = tmp_path / "report.json"
    check_path = tmp_path / "check.json"
    _write_json(report_path, report)
    _write_json(check_path, check)

    assert load_report_file(report_path) == report
    assert load_report_file(check_path) == check


def test_load_report_file_rejects_oversize_before_parsing(tmp_path: Path) -> None:
    selected = tmp_path / "oversize.json"
    selected.write_bytes(b"{" + b"x" * 64 + b"}")

    with pytest.raises(ReportToolError) as captured:
        load_report_file(selected, max_bytes=32)

    assert captured.value.code == "report_too_large"
    assert str(selected) not in str(captured.value)


def test_load_report_file_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    selected = tmp_path / "duplicate.json"
    selected.write_text(
        '{"schema":"sharesafe.report/v1","schema":"sharesafe.check/v1"}',
        encoding="utf-8",
    )

    with pytest.raises(ReportToolError) as captured:
        load_report_file(selected)

    assert captured.value.code == "invalid_report_json"


@pytest.mark.parametrize("data", (b"not-json", b'"not-an-object"', b"\xff"))
def test_load_report_file_rejects_malformed_input_without_echoing_it(
    tmp_path: Path, data: bytes
) -> None:
    selected = tmp_path / "synthetic-private-canary.json"
    selected.write_bytes(data)

    with pytest.raises(ReportToolError) as captured:
        load_report_file(selected)

    assert captured.value.code in {"invalid_report_json", "invalid_report_document"}
    assert "synthetic-private-canary" not in str(captured.value)
    assert str(selected) not in str(captured.value)


def test_load_report_file_rejects_final_component_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    selected = tmp_path / "selected.json"
    _write_json(target, _synthetic_report())
    try:
        selected.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(ReportToolError) as captured:
        load_report_file(selected)

    assert captured.value.code == "report_link_rejected"


def test_load_report_file_rejects_identity_swap_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = tmp_path / "selected.json"
    replacement = tmp_path / "replacement.json"
    _write_json(selected, _synthetic_report())
    replacement_report = _synthetic_report()
    replacement_report["artifacts"][0]["path"] = "replacement.txt"
    _write_json(replacement, replacement_report)
    selected_absolute = selected.absolute()
    original_open = os.open

    def swapped_open(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if Path(path).absolute() == selected_absolute:
            return original_open(replacement, *args, **kwargs)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", swapped_open)

    with pytest.raises(ReportToolError) as captured:
        load_report_file(selected)

    assert captured.value.code == "report_changed_during_read"
    assert "replacement.txt" not in str(captured.value)


def test_load_report_file_rejects_change_detected_after_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = tmp_path / "selected.json"
    _write_json(selected, _synthetic_report())
    monkeypatch.setattr(
        "sharesafe.report_tools.verify_open_file_unchanged",
        lambda *args, **kwargs: False,
    )

    with pytest.raises(ReportToolError) as captured:
        load_report_file(selected)

    assert captured.value.code == "report_changed_during_read"


def test_load_report_file_strictly_rejects_unmasked_report_fields(
    tmp_path: Path,
) -> None:
    report = _synthetic_report()
    canary = "synthetic-private-canary"
    report["artifacts"][0]["path"] = f"C:\\Users\\{canary}\\note.txt"
    selected = tmp_path / "report.json"
    _write_json(selected, report)

    with pytest.raises(ReportToolError) as captured:
        load_report_file(selected)

    assert captured.value.code == "invalid_report_document"
    assert canary not in str(captured.value)


def test_load_report_file_strictly_rejects_tampered_check_receipt(
    tmp_path: Path,
) -> None:
    check = build_check(_synthetic_report())
    check["policy"]["digest"] = "sha256:" + "f" * 64
    selected = tmp_path / "check.json"
    _write_json(selected, check)

    with pytest.raises(ReportToolError) as captured:
        load_report_file(selected)

    assert captured.value.code == "invalid_report_document"


@pytest.mark.parametrize(
    ("group_by", "expected"),
    (
        ("rule", {"synthetic.rule.alpha": 1, "synthetic.rule.beta": 1}),
        ("category", {"synthetic_category": 1, "other_category": 1}),
        ("severity", {"medium": 1, "critical": 1}),
    ),
)
def test_show_report_groups_aggregate_findings(
    group_by: str, expected: dict[str, int]
) -> None:
    view = show_report(_synthetic_report(), group_by=group_by)

    assert view["schema"] == REPORT_SHOW_SCHEMA
    assert {item["value"]: item["count"] for item in view["groups"]} == expected
    assert view["selection"]["selected_findings"] == 2
    assert view["summary"]["technical_verdict"] == "block"


def test_show_report_applies_minimum_severity_and_omits_sensitive_records() -> None:
    report = _synthetic_report()
    view = show_report(report, group_by="rule", min_severity="high")
    serialized = json.dumps(view, ensure_ascii=False)

    assert [item["value"] for item in view["groups"]] == ["synthetic.rule.beta"]
    assert view["selection"] == {
        "group_by": "rule",
        "min_severity": "high",
        "selected_findings": 1,
        "filtered_findings": 1,
    }
    assert CONTENT_TOKEN_A not in serialized
    assert EVIDENCE_TOKEN_A not in serialized
    assert report["findings"][0]["id"] not in serialized
    assert "<synthetic:masked>" not in serialized


@pytest.mark.parametrize(
    ("kwargs", "code"),
    (
        ({"group_by": "path"}, "invalid_group_by"),
        ({"min_severity": "urgent"}, "invalid_min_severity"),
    ),
)
def test_show_report_rejects_unknown_selection(kwargs: dict, code: str) -> None:
    with pytest.raises(ReportToolError) as captured:
        show_report(_synthetic_report(), **kwargs)

    assert captured.value.code == code


def test_diff_uses_only_rule_path_location_and_ignores_identity_material() -> None:
    old = _synthetic_report()
    new = deepcopy(old)
    new["artifacts"][0]["content_token"] = "hmac-sha256:content-v1:" + "a" * 32
    new["findings"][0]["id"] = "f-" + "b" * 20
    new["findings"][0]["evidence"] = {
        "mode": "masked",
        "masked": "<synthetic:changed>",
        "value_class": "synthetic",
        "token": "hmac-sha256:v1:" + "c" * 32,
    }
    view = diff_reports(old, new)
    serialized = json.dumps(view, ensure_ascii=False)

    assert view["schema"] == REPORT_DIFF_SCHEMA
    assert view["summary"] == {
        "same_rule_path_location": 2,
        "structure_new": 0,
        "structure_resolved": 0,
    }
    assert view["comparison_basis"] == "rule_path_location_multiset"
    assert old["findings"][0]["id"] not in serialized
    assert new["findings"][0]["id"] not in serialized
    assert CONTENT_TOKEN_A not in serialized
    assert "<synthetic:changed>" not in serialized


def test_diff_reports_new_resolved_and_duplicate_structures_as_multiset() -> None:
    old = _synthetic_report(duplicate_medium=True)
    new = _synthetic_report()
    new["findings"][1]["rule_id"] = "synthetic.rule.gamma"
    view = diff_reports(old, new)

    assert view["summary"] == {
        "same_rule_path_location": 1,
        "structure_new": 1,
        "structure_resolved": 2,
    }
    assert any(
        item["rule_id"] == "synthetic.rule.alpha" and item["count"] == 1
        for item in view["structure_resolved"]
    )
    assert view["structure_new"][0]["classification"] == "structure_new"


def test_diff_reports_schema_ruleset_and_policy_context_changes() -> None:
    report = _synthetic_report()
    old = build_check(
        report,
        policy_from_mapping({"fail_on": "high"}),
        ruleset_version="sharesafe.rules/v1",
    )
    new = build_check(
        report,
        policy_from_mapping({"fail_on": "critical"}),
        ruleset_version="sharesafe.rules/v2",
    )

    changed = diff_reports(old, new)
    schema_changed = diff_reports(report, old)

    assert changed["context"]["schema_changed"] is False
    assert changed["context"]["ruleset_changed"] is True
    assert changed["context"]["policy_changed"] is True
    assert schema_changed["context"]["schema_changed"] is True
    assert schema_changed["context"]["ruleset_changed"] is None
    assert schema_changed["context"]["policy_changed"] is None
    assert "digest" not in json.dumps(changed)


def test_diff_report_files_uses_the_same_safe_loading_boundary(tmp_path: Path) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    _write_json(old, _synthetic_report())
    _write_json(new, _synthetic_report())

    view = diff_report_files(old, new)

    assert view["summary"]["same_rule_path_location"] == 2


def test_share_summary_is_minimal_and_contains_no_per_artifact_disclosures() -> None:
    report = _synthetic_report()
    check = build_check(report, policy_from_mapping({"fail_on": "critical"}))
    view = share_summary(check)
    serialized = json.dumps(view, ensure_ascii=False)

    assert view["schema"] == SHARE_SUMMARY_SCHEMA
    assert view["source_schema"] == "sharesafe.check/v1"
    assert view["summary"]["policy_outcome"] == "block"
    assert view["summary"]["decision_exit_code"] == 1
    assert view["summary"]["artifacts_total"] == 2
    for forbidden in (
        "docs/alpha.txt",
        "docs/beta.txt",
        CONTENT_TOKEN_A,
        CONTENT_TOKEN_B,
        EVIDENCE_TOKEN_A,
        report["run"]["id"],
        report["run"]["started_at"],
    ):
        assert forbidden not in serialized
    assert set(view) == {"schema", "source_schema", "summary"}


def test_derived_views_enforce_an_independent_output_budget() -> None:
    with pytest.raises(ReportToolError) as captured:
        diff_reports(_synthetic_report(), _synthetic_report(), max_output_bytes=64)

    assert captured.value.code == "derived_report_too_large"


def test_diff_uses_union_limits_after_each_source_is_independently_validated() -> None:
    narrow = _synthetic_report()
    wide = _synthetic_report()
    narrow["run"]["limits"]["max_display_path_chars"] = 256
    wide["run"]["limits"]["max_display_path_chars"] = 512
    wide_path = "docs/" + "x" * 280
    wide["artifacts"][0]["path"] = wide_path

    view = diff_reports(narrow, wide)

    assert any(item["path"] == wide_path for item in view["structure_new"])


def test_public_mapping_entrypoints_reject_unknown_or_malformed_schema() -> None:
    with pytest.raises(ReportToolError) as captured:
        share_summary({"schema": "sharesafe.verify/v1"})
    assert captured.value.code == "unsupported_report_schema"

    with pytest.raises(ReportToolError) as captured:
        diff_reports(_synthetic_report(), {"schema": "sharesafe.report/v1"})
    assert captured.value.code == "invalid_report_document"
