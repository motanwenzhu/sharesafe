from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from sharesafe.check import build_check
from sharesafe.cli import main
from sharesafe.limits import Limits
from sharesafe.models import ReportBuilder
from sharesafe.policy import policy_from_mapping

CONTENT_TOKEN_A = "hmac-sha256:content-v1:" + "1" * 32
CONTENT_TOKEN_B = "hmac-sha256:content-v1:" + "2" * 32
EVIDENCE_TOKEN = "hmac-sha256:v1:" + "3" * 32


def _synthetic_report() -> dict:
    builder = ReportBuilder(limits=Limits(), report_mode="local_masked")
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
            "token": EVIDENCE_TOKEN,
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


def _call_json(capsys, arguments: list[str]) -> tuple[int, dict, str]:
    code = main([*arguments, "--json"])
    captured = capsys.readouterr()
    return code, json.loads(captured.out), captured.err


def test_report_show_cli_filters_and_groups_saved_report(
    tmp_path: Path, capsys
) -> None:
    selected = tmp_path / "report.json"
    _write_json(selected, _synthetic_report())

    code, payload, error = _call_json(
        capsys,
        [
            "report",
            "show",
            str(selected),
            "--group-by",
            "severity",
            "--min-severity",
            "high",
        ],
    )

    assert code == 0 and error == ""
    assert payload["schema"] == "sharesafe.report-show/v1"
    assert payload["selection"]["selected_findings"] == 1
    assert [item["value"] for item in payload["groups"]] == ["critical"]


def test_report_diff_cli_is_structural_and_omits_identity_material(
    tmp_path: Path, capsys
) -> None:
    old = _synthetic_report()
    new = deepcopy(old)
    new["findings"][0]["rule_id"] = "synthetic.rule.changed"
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    _write_json(old_path, old)
    _write_json(new_path, new)

    code, payload, error = _call_json(
        capsys, ["report", "diff", str(old_path), str(new_path)]
    )
    serialized = json.dumps(payload, ensure_ascii=False)

    assert code == 0 and error == ""
    assert payload["schema"] == "sharesafe.report-diff/v1"
    assert payload["summary"] == {
        "same_rule_path_location": 1,
        "structure_new": 1,
        "structure_resolved": 1,
    }
    for forbidden in (
        CONTENT_TOKEN_A,
        CONTENT_TOKEN_B,
        EVIDENCE_TOKEN,
        old["findings"][0]["id"],
        new["findings"][0]["id"],
    ):
        assert forbidden not in serialized


def test_report_share_summary_cli_has_no_per_artifact_disclosure(
    tmp_path: Path, capsys
) -> None:
    report = _synthetic_report()
    selected = tmp_path / "report.json"
    _write_json(selected, report)

    code, payload, error = _call_json(
        capsys, ["report", "share-summary", str(selected)]
    )
    serialized = json.dumps(payload, ensure_ascii=False)

    assert code == 0 and error == ""
    assert payload["schema"] == "sharesafe.share-summary/v1"
    assert payload["summary"]["artifacts_total"] == 2
    for forbidden in (
        "docs/alpha.txt",
        "docs/beta.txt",
        CONTENT_TOKEN_A,
        CONTENT_TOKEN_B,
        report["run"]["id"],
        report["run"]["started_at"],
    ):
        assert forbidden not in serialized


def test_report_text_views_are_concise_and_preserve_semantic_warnings(
    tmp_path: Path, capsys
) -> None:
    selected = tmp_path / "report.json"
    _write_json(selected, _synthetic_report())

    assert main(["report", "show", str(selected), "--min-severity", "high"]) == 0
    shown = capsys.readouterr()
    assert "1 selected" in shown.out
    assert "critical" in shown.out
    assert CONTENT_TOKEN_A not in shown.out
    assert shown.err == ""

    assert main(["report", "diff", str(selected), str(selected)]) == 0
    diffed = capsys.readouterr()
    assert "2 unchanged" in diffed.out
    assert "schema=no, ruleset=unknown, policy=unknown" in diffed.out
    assert "does not establish finding or content identity" in diffed.out
    assert CONTENT_TOKEN_A not in diffed.out
    assert diffed.err == ""

    assert main(["report", "share-summary", str(selected)]) == 0
    summarized = capsys.readouterr()
    assert "does not authorize uploading or sharing" in summarized.out
    assert "docs/alpha.txt" not in summarized.out
    assert summarized.err == ""


def test_report_text_views_surface_recorded_policy_decision(
    tmp_path: Path, capsys
) -> None:
    check = build_check(
        _synthetic_report(), policy_from_mapping({"fail_on": "critical"})
    )
    selected = tmp_path / "check.json"
    _write_json(selected, check)

    assert main(["report", "show", str(selected)]) == 0
    shown = capsys.readouterr()
    assert "Recorded policy outcome: block." in shown.out
    assert shown.err == ""

    assert main(["report", "share-summary", str(selected)]) == 0
    summarized = capsys.readouterr()
    assert "Recorded policy outcome: block (exit 1)." in summarized.out
    assert summarized.err == ""


def test_report_cli_errors_are_stable_and_do_not_echo_path_or_input(
    tmp_path: Path, capsys
) -> None:
    canary = "synthetic-private-canary"
    selected = tmp_path / f"{canary}.json"
    selected.write_text(json.dumps({"private": canary}), encoding="utf-8")

    code, payload, error = _call_json(
        capsys, ["report", "show", str(selected)]
    )
    serialized = json.dumps(payload, ensure_ascii=False)

    assert code == 3 and error == ""
    assert payload["schema"] == "sharesafe.error/v1"
    assert payload["error"]["code"] == "unsupported_report_schema"
    assert canary not in serialized
    assert str(selected) not in serialized

    code = main(["report", "show", str(selected)])
    captured = capsys.readouterr()
    assert code == 3 and captured.out == ""
    assert "Report inspection failed" in captured.err
    assert canary not in captured.err
    assert str(selected) not in captured.err


def test_report_cli_argument_errors_do_not_echo_attacker_controlled_values(
    tmp_path: Path, capsys
) -> None:
    canary = "synthetic-private-canary"
    selected = tmp_path / f"{canary}.json"

    code, payload, error = _call_json(
        capsys,
        [
            "report",
            "show",
            str(selected),
            "--min-severity",
            canary,
        ],
    )
    serialized = json.dumps(payload, ensure_ascii=False)

    assert code == 3 and error == ""
    assert payload["error"]["code"] == "invalid_arguments"
    assert canary not in serialized
    assert str(selected) not in serialized


def test_report_cli_help_discovers_commands_and_comparison_boundary(capsys) -> None:
    with pytest.raises(SystemExit) as captured:
        main(["report", "--help"])
    report_help = capsys.readouterr()

    assert captured.value.code == 0
    assert report_help.err == ""
    assert "show" in report_help.out
    assert "diff" in report_help.out
    assert "share-summary" in report_help.out

    with pytest.raises(SystemExit) as captured:
        main(["report", "diff", "--help"])
    diff_help = capsys.readouterr()

    assert captured.value.code == 0
    assert diff_help.err == ""
    assert "rule/path/location" in diff_help.out


def test_report_cli_missing_input_is_stable_usage_error_without_path_echo(
    tmp_path: Path, capsys
) -> None:
    canary = "synthetic-private-canary"
    selected = tmp_path / f"{canary}.json"

    code, payload, error = _call_json(
        capsys, ["report", "share-summary", str(selected)]
    )
    serialized = json.dumps(payload, ensure_ascii=False)

    assert code == 3 and error == ""
    assert payload == {
        "schema": "sharesafe.error/v1",
        "error": {
            "code": "report_unavailable",
            "message": "Report inspection failed; no derived view was produced.",
        },
    }
    assert canary not in serialized
    assert str(selected) not in serialized


def test_report_diff_cli_accepts_individually_valid_heterogeneous_limits(
    tmp_path: Path, capsys
) -> None:
    narrow = _synthetic_report()
    wide = _synthetic_report()
    narrow["run"]["limits"]["max_display_path_chars"] = 256
    wide["run"]["limits"]["max_display_path_chars"] = 512
    wide_path = "docs/" + "x" * 280
    wide["artifacts"][0]["path"] = wide_path
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    _write_json(old_path, narrow)
    _write_json(new_path, wide)

    code, payload, error = _call_json(
        capsys, ["report", "diff", str(old_path), str(new_path)]
    )

    assert code == 0 and error == ""
    assert any(item["path"] == wide_path for item in payload["structure_new"])


def test_report_cli_rejects_source_that_exceeds_its_recorded_byte_budget(
    tmp_path: Path, capsys
) -> None:
    report = _synthetic_report()
    report["run"]["limits"]["max_report_bytes"] = 4096
    report["findings"][0]["title"] = "x" * 5000
    selected = tmp_path / "oversized-for-recorded-budget.json"
    _write_json(selected, report)

    code, payload, error = _call_json(
        capsys, ["report", "show", str(selected)]
    )

    assert code == 3 and error == ""
    assert payload["error"]["code"] == "invalid_report_document"
