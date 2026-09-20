from __future__ import annotations

import json
from pathlib import Path

from sharesafe.cli import main


def _call_json(capsys, arguments: list[str]) -> tuple[int, dict, str]:
    code = main([*arguments, "--json"])
    captured = capsys.readouterr()
    return code, json.loads(captured.out), captured.err


def test_policy_init_validate_and_show_round_trip(tmp_path: Path, capsys) -> None:
    policy_path = tmp_path / ".sharesafe.toml"

    code, created, error = _call_json(
        capsys, ["policy", "init", "--out", str(policy_path)]
    )
    assert code == 0 and error == ""
    assert created["schema"] == "sharesafe.policy-init/v1"
    assert created["destination"] == "<new-policy>"
    assert policy_path.is_file()

    code, validated, error = _call_json(
        capsys, ["policy", "validate", "--config", str(policy_path)]
    )
    assert code == 0 and error == ""
    assert validated["valid"] is True
    assert validated["policy_digest"] == created["policy_digest"]

    code, shown, error = _call_json(
        capsys, ["policy", "show", "--config", str(policy_path)]
    )
    assert code == 0 and error == ""
    assert shown["policy_digest"] == created["policy_digest"]
    assert shown["policy"]["schema"] == "sharesafe.policy/v1"
    assert shown["ruleset_version"] == "sharesafe.rules/v1"

    original = policy_path.read_bytes()
    code, collision, _ = _call_json(
        capsys, ["policy", "init", "--out", str(policy_path)]
    )
    assert code == 3
    assert collision["schema"] == "sharesafe.error/v1"
    assert policy_path.read_bytes() == original


def test_check_embeds_policy_and_preserves_native_report(tmp_path: Path, capsys) -> None:
    source = tmp_path / "synthetic.txt"
    source.write_text("contact=person@example.test", encoding="utf-8")
    config = tmp_path / "policy.toml"
    config.write_text('fail_on = "critical"\n', encoding="utf-8")

    code, payload, error = _call_json(
        capsys,
        ["check", str(source), "--config", str(config)],
    )

    assert code == 0 and error == ""
    assert payload["schema"] == "sharesafe.check/v1"
    assert payload["report"]["schema"] == "sharesafe.report/v1"
    assert payload["report"]["summary"]["verdict"] == "block"
    assert payload["policy"]["fail_on"] == "critical"
    assert payload["decision"]["technical_verdict"] == "block"
    assert payload["decision"]["policy_outcome"] == "review"
    assert payload["decision"]["exit_code"] == 0


def test_check_cli_override_wins_over_project_and_explicit_policy(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    source = tmp_path / "synthetic.txt"
    source.write_text("contact=person@example.test", encoding="utf-8")
    (tmp_path / ".sharesafe.toml").write_text('fail_on = "low"\n', encoding="utf-8")
    explicit = tmp_path / "explicit.toml"
    explicit.write_text('fail_on = "high"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    code, payload, _ = _call_json(
        capsys,
        [
            "check",
            str(source),
            "--config",
            str(explicit),
            "--fail-on",
            "critical",
            "--no-optional-tools",
        ],
    )

    assert code == 0
    assert payload["policy"]["fail_on"] == "critical"
    assert payload["policy"]["optional_tools"] is False


def test_invalid_policy_error_never_echoes_path_or_canary(tmp_path: Path, capsys) -> None:
    source = tmp_path / "synthetic.txt"
    source.write_text("public", encoding="utf-8")
    config = tmp_path / "private-policy.toml"
    canary = "synthetic-private-canary"
    config.write_text(f'unknown = "{canary}"\n', encoding="utf-8")

    code, payload, error = _call_json(
        capsys, ["check", str(source), "--config", str(config)]
    )

    serialized = json.dumps(payload)
    assert code == 3 and error == ""
    assert payload["error"]["code"] == "unknown_policy_field"
    assert canary not in serialized
    assert str(config) not in serialized


def test_enabled_manifest_never_silently_passes_without_exact_validation(
    tmp_path: Path, capsys
) -> None:
    source = tmp_path / "synthetic.txt"
    source.write_text("public", encoding="utf-8")
    config = tmp_path / "policy.toml"
    config.write_text(
        '[manifest]\nenabled = true\npath = "input.manifest.json"\nrequire_exact = true\n',
        encoding="utf-8",
    )

    code, payload, error = _call_json(
        capsys, ["check", str(source), "--config", str(config)]
    )

    assert code == 2 and error == ""
    assert payload["decision"]["policy_outcome"] == "incomplete"
    assert payload["decision"]["manifest_validation"] == "missing"
    assert "manifest_validation_missing" in payload["decision"]["reason_codes"]
