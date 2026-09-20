from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from sharesafe.cli import main

ROOT = Path(__file__).resolve().parents[1]


def _call_json(capsys, arguments: list[str]) -> tuple[int, dict[str, object], str]:
    code = main([*arguments, "--json"])
    captured = capsys.readouterr()
    return code, json.loads(captured.out), captured.err


def _source_and_decisions(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "source"
    source.mkdir()
    (source / "include.txt").write_text("synthetic public note", encoding="utf-8")
    (source / "omit.txt").write_text(
        "synthetic local token=" + "sk-" + "S" * 28,
        encoding="utf-8",
    )
    decisions = tmp_path / "decisions.json"
    decisions.write_text(
        json.dumps(
            {
                "schema": "sharesafe.prepare-decisions/v1",
                "classification": "local_only_do_not_share",
                "source_boundary": "<selected-source>",
                "actions": [
                    {
                        "source_path": "include.txt",
                        "target_path": "include.txt",
                        "action": "copy_unchanged",
                        "reason_code": "explicit_include",
                    },
                    {
                        "source_path": "omit.txt",
                        "target_path": None,
                        "action": "omit_from_boundary",
                        "reason_code": "explicit_omit",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return source, decisions


def _validator(name: str) -> Draft202012Validator:
    schemas = {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in (ROOT / "schemas").glob("*.schema.json")
    }
    registry = Registry().with_resources(
        (str(schema["$id"]), Resource.from_contents(schema))
        for schema in schemas.values()
    )
    return Draft202012Validator(schemas[name], registry=registry)


def _make_plan_and_approval(
    tmp_path: Path,
    capsys,
) -> tuple[Path, Path, Path]:
    source, decisions = _source_and_decisions(tmp_path)
    plan = tmp_path / "plan.json"
    approval = tmp_path / "approval.json"
    code, payload, error = _call_json(
        capsys,
        [
            "prepare",
            "plan",
            str(source),
            "--decisions",
            str(decisions),
            "--out-plan",
            str(plan),
            "--no-optional-tools",
        ],
    )
    assert code == 0 and error == ""
    _validator("prepare-control-write-v1.schema.json").validate(payload)
    code, payload, error = _call_json(
        capsys,
        [
            "prepare",
            "approve",
            str(plan),
            "--out-approval",
            str(approval),
            "--approve-all",
        ],
    )
    assert code == 0 and error == ""
    _validator("prepare-control-write-v1.schema.json").validate(payload)
    return source, plan, approval


def test_prepare_cli_complete_copy_omit_workflow(tmp_path: Path, capsys) -> None:
    source, plan, approval = _make_plan_and_approval(tmp_path, capsys)
    output = tmp_path / "bundle"
    report = tmp_path / "prepare-result.json"

    code, inspection, error = _call_json(
        capsys,
        ["prepare", "inspect", str(plan)],
    )
    assert code == 0 and error == ""
    assert inspection["executable"] is True
    assert "sha256:" not in json.dumps(inspection)
    _validator("prepare-inspection-v1.schema.json").validate(inspection)

    code, result, error = _call_json(
        capsys,
        [
            "prepare",
            "apply",
            str(plan),
            "--approval",
            str(approval),
            "--source",
            str(source),
            "--out",
            str(output),
            "--report",
            str(report),
            "--no-optional-tools",
        ],
    )
    assert code == 0 and error == ""
    assert (output / "include.txt").read_text(
        encoding="utf-8"
    ) == "synthetic public note"
    assert not (output / "omit.txt").exists()
    assert json.loads(report.read_text(encoding="utf-8")) == result
    _validator("prepare-result-v1.schema.json").validate(result)

    code, verification, error = _call_json(
        capsys,
        [
            "prepare",
            "verify",
            str(plan),
            "--source",
            str(source),
            "--output",
            str(output),
            "--no-optional-tools",
        ],
    )
    assert code == 0 and error == ""
    assert verification["verification"]["outcome"] == "verified"
    _validator("prepare-result-v1.schema.json").validate(verification)


def test_prepare_approve_requires_explicit_all_flag(tmp_path: Path, capsys) -> None:
    source, decisions = _source_and_decisions(tmp_path)
    plan = tmp_path / "plan.json"
    code, _, _ = _call_json(
        capsys,
        [
            "prepare",
            "plan",
            str(source),
            "--decisions",
            str(decisions),
            "--out-plan",
            str(plan),
            "--no-optional-tools",
        ],
    )
    assert code == 0

    code, payload, error = _call_json(
        capsys,
        [
            "prepare",
            "approve",
            str(plan),
            "--out-approval",
            str(tmp_path / "approval.json"),
        ],
    )

    assert code == 3 and error == ""
    assert payload["error"]["code"] == "invalid_arguments"


def test_prepare_plan_rejects_control_artifacts_inside_source(
    tmp_path: Path, capsys
) -> None:
    source, decisions = _source_and_decisions(tmp_path)
    inside = source / "decisions.json"
    inside.write_bytes(decisions.read_bytes())

    code, payload, error = _call_json(
        capsys,
        [
            "prepare",
            "plan",
            str(source),
            "--decisions",
            str(inside),
            "--out-plan",
            str(tmp_path / "plan.json"),
            "--no-optional-tools",
        ],
    )

    assert code == 3 and error == ""
    assert payload["error"]["code"] == "control_artifact_inside_source"
    assert not (tmp_path / "plan.json").exists()


def test_prepare_apply_reports_source_drift_without_path_leak(
    tmp_path: Path, capsys
) -> None:
    source, plan, approval = _make_plan_and_approval(tmp_path, capsys)
    (source / "include.txt").write_text("changed after approval", encoding="utf-8")
    output = tmp_path / "bundle"

    code, payload, error = _call_json(
        capsys,
        [
            "prepare",
            "apply",
            str(plan),
            "--approval",
            str(approval),
            "--source",
            str(source),
            "--out",
            str(output),
            "--no-optional-tools",
        ],
    )

    serialized = json.dumps(payload, ensure_ascii=False)
    assert code == 3 and error == ""
    assert payload["error"]["code"] == "source_drift"
    assert str(source) not in serialized
    assert "changed after approval" not in serialized
    assert not output.exists()


def test_prepare_help_lists_verified_subcommands(capsys) -> None:
    parser = __import__("sharesafe.cli", fromlist=["build_parser"]).build_parser()

    help_text = parser.format_help()
    prepare_parser = next(
        action.choices["prepare"]
        for action in parser._actions
        if getattr(action, "choices", None) and "prepare" in action.choices
    )
    prepare_help = prepare_parser.format_help()

    assert "prepare" in help_text
    for command in ("plan", "inspect", "approve", "apply", "verify"):
        assert command in prepare_help
