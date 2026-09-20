from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource
from sharesafe.check import CheckError, build_check
from sharesafe.engine import ScanConfig, Scanner
from sharesafe.policy import (
    POLICY_SCHEMA,
    PolicyError,
    default_policy,
    load_policy,
    normalize_policy,
    policy_digest,
    policy_from_mapping,
    resolve_policy,
)

ROOT = Path(__file__).resolve().parents[1]


def _validator(name: str) -> Draft202012Validator:
    schemas = {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((ROOT / "schemas").glob("*.schema.json"))
    }
    registry = Registry().with_resources(
        (str(schema["$id"]), Resource.from_contents(schema))
        for schema in schemas.values()
    )
    return Draft202012Validator(schemas[name], registry=registry)


def _scan(tmp_path: Path, content: bytes, name: str = "synthetic.txt") -> dict:
    sample = tmp_path / name
    sample.write_bytes(content)
    return Scanner(ScanConfig(optional_tools=False)).scan([sample]).to_dict()


def test_load_policy_normalizes_complete_effective_policy(tmp_path: Path) -> None:
    config = tmp_path / ".sharesafe.toml"
    config.write_text(
        """
schema = "sharesafe.policy/v1"
fail_on = "critical"
required_capabilities = ["text", "metadata"]
blocking_categories = ["secret", "active_content"]
optional_tools = false

[limits]
max_file_bytes = "2MiB"
max_archive_depth = 0

[manifest]
enabled = true
path = "share/input.manifest"
require_exact = true
""".strip(),
        encoding="utf-8",
    )

    policy = load_policy(config)
    normalized = normalize_policy(policy)

    assert normalized["schema"] == POLICY_SCHEMA
    assert normalized["fail_on"] == "critical"
    assert normalized["required_capabilities"] == ["metadata", "text"]
    assert normalized["blocking_categories"] == ["active_content", "secret"]
    assert normalized["optional_tools"] is False
    assert normalized["limits"]["max_file_bytes"] == 2 * 1024 * 1024
    assert normalized["limits"]["max_archive_depth"] == 0
    assert normalized["manifest"] == {
        "enabled": True,
        "path": "share/input.manifest",
        "require_exact": True,
    }


def test_policy_digest_is_canonical_and_changes_with_effective_settings() -> None:
    first = policy_from_mapping(
        {
            "blocking_categories": ["secret", "pii"],
            "required_capabilities": ["text", "metadata"],
        }
    )
    reordered = policy_from_mapping(
        {
            "blocking_categories": ["pii", "secret"],
            "required_capabilities": ["metadata", "text"],
        }
    )
    changed = policy_from_mapping(
        {
            "blocking_categories": ["pii", "secret"],
            "required_capabilities": ["metadata", "text"],
            "fail_on": "critical",
        }
    )

    assert policy_digest(first) == policy_digest(reordered)
    assert policy_digest(first).startswith("sha256:")
    assert len(policy_digest(first)) == len("sha256:") + 64
    assert policy_digest(changed) != policy_digest(first)


def test_policy_resolution_has_fixed_explicit_precedence(tmp_path: Path) -> None:
    project = tmp_path / "project.toml"
    explicit = tmp_path / "explicit.toml"
    project.write_text(
        'fail_on = "low"\noptional_tools = false\n[limits]\nmax_files = 10\n',
        encoding="utf-8",
    )
    explicit.write_text(
        'fail_on = "critical"\n[limits]\nmax_files = 20\n',
        encoding="utf-8",
    )

    policy = resolve_policy(
        project_config=project,
        explicit_config=explicit,
        overrides={"fail_on": "never"},
    )

    assert policy.fail_on == "never"
    assert policy.optional_tools is False
    assert policy.limits.max_files == 20


def test_higher_precedence_policy_can_explicitly_disable_inherited_manifest(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project.toml"
    explicit = tmp_path / "explicit.toml"
    project.write_text(
        '[manifest]\nenabled = true\npath = "share/input.manifest"\n',
        encoding="utf-8",
    )
    explicit.write_text("[manifest]\nenabled = false\n", encoding="utf-8")

    policy = resolve_policy(project_config=project, explicit_config=explicit)

    assert policy.manifest.enabled is False
    assert policy.manifest.path is None
    assert policy.manifest.require_exact is True


def test_policy_never_reads_implicit_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHARESAFE_FAIL_ON", "never")
    monkeypatch.setenv("SHARESAFE_CONFIG", "untrusted.toml")

    assert default_policy().fail_on == "high"
    assert resolve_policy().fail_on == "high"


@pytest.mark.parametrize(
    ("raw", "code"),
    (
        ({"disabled_rules": ["secret.*"]}, "unknown_policy_field"),
        ({"suppress_findings": True}, "unknown_policy_field"),
        ({"allow_incomplete": True}, "unknown_policy_field"),
        ({"limits": {"unknown_budget": 10}}, "unknown_limit"),
        ({"limits": {"max_files": True}}, "invalid_limit"),
        ({"limits": {"max_files": 0}}, "limit_out_of_range"),
        ({"limits": {"max_file_bytes": "100TiB"}}, "invalid_limit"),
        ({"limits": {"max_file_bytes": 2**63}}, "limit_out_of_range"),
        ({"fail_on": "HIGH"}, "invalid_policy_value"),
        ({"required_capabilities": ["text", "text"]}, "duplicate_policy_value"),
        ({"required_capabilities": ["face_recognition"]}, "invalid_policy_value"),
        ({"blocking_categories": ["Secret"]}, "invalid_policy_value"),
        ({"blocking_categories": ["pii", "pii"]}, "duplicate_policy_value"),
        ({"optional_tools": 1}, "invalid_policy_value"),
        ({"manifest": {"extra": True}}, "unknown_manifest_field"),
        ({"manifest": {"enabled": True}}, "manifest_path_required"),
        (
            {"manifest": {"enabled": False, "path": "share.manifest"}},
            "manifest_disabled_with_path",
        ),
        (
            {"manifest": {"enabled": True, "path": "../share.manifest"}},
            "invalid_manifest_path",
        ),
        (
            {"manifest": {"enabled": True, "path": "${HOME}/share.manifest"}},
            "implicit_environment_path",
        ),
        (
            {"manifest": {"enabled": True, "path": "share/*.txt"}},
            "invalid_manifest_path",
        ),
    ),
)
def test_policy_rejects_unknown_suppressive_or_invalid_settings(
    raw: dict, code: str
) -> None:
    with pytest.raises(PolicyError) as captured:
        policy_from_mapping(raw)

    assert captured.value.code == code


def test_policy_rejects_invalid_or_duplicate_toml_without_echoing_content(
    tmp_path: Path,
) -> None:
    canary = "synthetic-private-canary"
    config = tmp_path / "invalid.toml"
    config.write_text(
        f'fail_on = "high"\nfail_on = "never"\nprivate = "{canary}"\n',
        encoding="utf-8",
    )

    with pytest.raises(PolicyError) as captured:
        load_policy(config)

    assert captured.value.code == "invalid_policy_toml"
    assert canary not in str(captured.value)
    assert str(config) not in str(captured.value)


def test_policy_rejects_identity_swap_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = tmp_path / "selected.toml"
    replacement = tmp_path / "replacement.toml"
    selected.write_text('fail_on = "high"\n', encoding="utf-8")
    replacement.write_text('fail_on = "never"\n', encoding="utf-8")
    selected_absolute = selected.absolute()
    original_open = os.open

    def swapped_open(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if Path(path).absolute() == selected_absolute:
            return original_open(replacement, *args, **kwargs)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", swapped_open)

    with pytest.raises(PolicyError) as captured:
        load_policy(selected)

    assert captured.value.code == "policy_changed_during_read"
    assert str(selected) not in str(captured.value)


def test_clean_check_records_full_policy_and_preserves_report(tmp_path: Path) -> None:
    report = _scan(tmp_path, b"synthetic public note")
    original = deepcopy(report)
    policy = policy_from_mapping({"fail_on": "critical"})

    check = build_check(report, policy)

    assert report == original
    assert check["report"] == original
    assert check["report"] is not report
    assert check["schema"] == "sharesafe.check/v1"
    assert check["policy"]["schema"] == POLICY_SCHEMA
    assert check["policy"]["ruleset_version"] == "sharesafe.rules/v1"
    assert check["policy"]["digest"] == policy.digest
    assert check["policy"]["fail_on"] == "critical"
    assert check["decision"] == {
        "technical_verdict": "no_findings",
        "policy_outcome": "pass",
        "exit_code": 0,
        "manifest_validation": "not_required",
        "reason_codes": ["no_findings_observed"],
    }


def test_enabled_manifest_requires_explicit_successful_validation(
    tmp_path: Path,
) -> None:
    report = _scan(tmp_path, b"synthetic public note")
    policy = policy_from_mapping(
        {
            "manifest": {
                "enabled": True,
                "path": "share/input.manifest",
                "require_exact": True,
            }
        }
    )

    missing = build_check(report, policy)
    incomplete = build_check(report, policy, manifest_validation="incomplete")
    complete = build_check(report, policy, manifest_validation="complete")

    assert missing["decision"]["manifest_validation"] == "missing"
    assert missing["decision"]["policy_outcome"] == "incomplete"
    assert missing["decision"]["exit_code"] == 2
    assert "manifest_validation_missing" in missing["decision"]["reason_codes"]
    assert incomplete["decision"]["manifest_validation"] == "incomplete"
    assert incomplete["decision"]["exit_code"] == 2
    assert "manifest_validation_incomplete" in incomplete["decision"]["reason_codes"]
    assert complete["decision"]["manifest_validation"] == "complete"
    assert complete["decision"]["policy_outcome"] == "pass"
    assert complete["decision"]["exit_code"] == 0


def test_non_exact_manifest_cannot_produce_passing_validation(tmp_path: Path) -> None:
    report = _scan(tmp_path, b"synthetic public note")
    policy = policy_from_mapping(
        {
            "manifest": {
                "enabled": True,
                "path": "share/input.manifest",
                "require_exact": False,
            }
        }
    )

    check = build_check(report, policy, manifest_validation="complete")

    assert check["decision"]["manifest_validation"] == "incomplete"
    assert check["decision"]["policy_outcome"] == "incomplete"
    assert check["decision"]["exit_code"] == 2
    assert "manifest_not_exact" in check["decision"]["reason_codes"]


def test_check_keeps_technical_verdict_separate_from_policy_threshold(
    tmp_path: Path,
) -> None:
    report = _scan(tmp_path, b"contact=synthetic.person@example.test")

    review = build_check(report, policy_from_mapping({"fail_on": "critical"}))
    blocked = build_check(
        report,
        policy_from_mapping(
            {"fail_on": "critical", "blocking_categories": ["pii"]}
        ),
    )

    assert report["summary"]["verdict"] == "block"
    assert review["decision"]["technical_verdict"] == "block"
    assert review["decision"]["policy_outcome"] == "review"
    assert review["decision"]["exit_code"] == 0
    assert "findings_below_threshold" in review["decision"]["reason_codes"]
    assert blocked["decision"]["policy_outcome"] == "block"
    assert blocked["decision"]["exit_code"] == 1
    assert "blocking_category_present" in blocked["decision"]["reason_codes"]
    assert blocked["report"]["findings"] == report["findings"]


def test_incomplete_report_cannot_be_overridden_by_never_threshold(
    tmp_path: Path,
) -> None:
    report = _scan(tmp_path, b"\x00synthetic unsupported bytes\x00", "sample.bin")
    finding_count = len(report["findings"])
    gap_count = len(report["gaps"])

    check = build_check(report, policy_from_mapping({"fail_on": "never"}))

    assert check["decision"]["technical_verdict"] == "incomplete"
    assert check["decision"]["policy_outcome"] == "incomplete"
    assert check["decision"]["exit_code"] == 2
    assert "coverage_gap_present" in check["decision"]["reason_codes"]
    assert len(check["report"]["findings"]) == finding_count
    assert len(check["report"]["gaps"]) == gap_count


@pytest.mark.parametrize("reason", ("encrypted_pdf", "malformed_archive", "file_size_limit"))
def test_encryption_corruption_and_resource_limits_are_non_passing(
    tmp_path: Path, reason: str
) -> None:
    report = _scan(tmp_path, b"synthetic public note")
    artifact = report["artifacts"][0]
    artifact["status"] = "partial"
    artifact["coverage"]["text"] = "partial"
    report["gaps"].append(
        {
            "id": "g-0123456789abcdef0123",
            "artifact_id": artifact["id"],
            "capability": "text",
            "reason": reason,
            "detail": "Synthetic incomplete coverage.",
        }
    )
    report["summary"]["verdict"] = "incomplete"
    report["summary"]["artifacts_complete"] = 0
    report["summary"]["artifacts_partial"] = 1
    report["summary"]["gaps"] = 1

    check = build_check(report, policy_from_mapping({"fail_on": "never"}))

    assert check["decision"]["technical_verdict"] == "incomplete"
    assert check["decision"]["policy_outcome"] == "incomplete"
    assert check["decision"]["exit_code"] == 2
    assert "coverage_gap_present" in check["decision"]["reason_codes"]


def test_errors_and_missing_dependencies_are_always_incomplete(tmp_path: Path) -> None:
    missing_report = Scanner(ScanConfig(optional_tools=False)).scan(
        [tmp_path / "missing.txt"]
    ).to_dict()
    error_check = build_check(
        missing_report, policy_from_mapping({"fail_on": "never"})
    )
    assert error_check["decision"]["exit_code"] == 2
    assert "scan_error_present" in error_check["decision"]["reason_codes"]

    dependency_report = _scan(tmp_path, b"synthetic public note")
    dependency_report["dependencies"].append(
        {
            "name": "synthetic-parser",
            "available": False,
            "version": None,
            "capability": "synthetic_structure",
        }
    )
    dependency_check = build_check(
        dependency_report, policy_from_mapping({"fail_on": "never"})
    )
    assert dependency_check["decision"]["technical_verdict"] == "incomplete"
    assert dependency_check["decision"]["policy_outcome"] == "incomplete"
    assert dependency_check["decision"]["exit_code"] == 2
    assert "optional_dependency_unavailable" in dependency_check["decision"]["reason_codes"]


def test_required_capability_is_fail_closed_when_receipt_is_missing(
    tmp_path: Path,
) -> None:
    report = _scan(tmp_path, b"synthetic public note")
    del report["artifacts"][0]["coverage"]["text"]

    check = build_check(
        report, policy_from_mapping({"required_capabilities": ["text"]})
    )

    assert check["decision"]["technical_verdict"] == "no_findings"
    assert check["decision"]["policy_outcome"] == "incomplete"
    assert check["decision"]["exit_code"] == 2
    assert "required_capability_incomplete" in check["decision"]["reason_codes"]


def test_ruleset_version_is_explicit_and_validated(tmp_path: Path) -> None:
    report = _scan(tmp_path, b"synthetic public note")

    versioned = build_check(report, ruleset_version="sharesafe.rules/v2")
    assert versioned["policy"]["ruleset_version"] == "sharesafe.rules/v2"
    with pytest.raises(CheckError, match="Ruleset version"):
        build_check(report, ruleset_version="latest")


def test_check_rejects_non_report_input() -> None:
    with pytest.raises(CheckError) as captured:
        build_check({"schema": "sharesafe.verify/v1"})

    assert captured.value.code == "unsupported_report_schema"


def test_policy_and_check_validate_against_public_schemas(tmp_path: Path) -> None:
    report = _scan(tmp_path, b"synthetic public note")
    policy = default_policy()
    check = build_check(report, policy)

    _validator("policy-v1.schema.json").validate(policy.to_dict())
    _validator("check-v1.schema.json").validate(check)

    unexpected_policy = deepcopy(policy.to_dict())
    unexpected_policy["disabled_rules"] = ["secret.*"]
    with pytest.raises(ValidationError):
        _validator("policy-v1.schema.json").validate(unexpected_policy)

    suppressive_check = deepcopy(check)
    suppressive_check["decision"]["exit_code"] = 0
    suppressive_check["decision"]["policy_outcome"] = "incomplete"
    with pytest.raises(ValidationError):
        _validator("check-v1.schema.json").validate(suppressive_check)
