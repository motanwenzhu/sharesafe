"""Reproducible ``sharesafe.check/v1`` decision wrappers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any

from . import __version__
from .policy import (
    RULESET_VERSION,
    Policy,
    normalize_policy,
    policy_digest,
    policy_from_mapping,
)

CHECK_SCHEMA = "sharesafe.check/v1"
_REPORT_SCHEMA = "sharesafe.report/v1"
_SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEVERITY_RANK = {value: index for index, value in enumerate(_SEVERITIES)}
_TECHNICAL_VERDICTS = {"no_findings", "review", "block", "incomplete"}
_COVERAGE_VALUES = {"complete", "partial", "unsupported", "not_applicable"}
_RULESET_PREFIX = "sharesafe.rules/v"

_REASON_ORDER = (
    "scan_error_present",
    "coverage_gap_present",
    "partial_artifact_present",
    "optional_dependency_unavailable",
    "technical_incomplete_reported",
    "manifest_validation_missing",
    "manifest_validation_incomplete",
    "manifest_not_exact",
    "required_capability_incomplete",
    "blocking_category_present",
    "severity_threshold_met",
    "technical_block_reported",
    "findings_below_threshold",
    "no_findings_observed",
)


class CheckError(ValueError):
    """A stable failure to construct a check from a malformed report."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def build_check(
    report: Mapping[str, Any],
    policy: Policy | Mapping[str, Any] | None = None,
    *,
    ruleset_version: str = RULESET_VERSION,
    manifest_validation: str | None = None,
) -> dict[str, Any]:
    """Wrap an unchanged report with its complete effective policy decision.

    Incompleteness always wins over finding thresholds.  The embedded report is
    a deep copy: this function neither removes findings nor mutates its caller's
    report object.
    """

    normalized_policy = _validated_policy(policy)
    _validate_ruleset_version(ruleset_version)
    embedded_report = _validated_report_copy(report)

    signals = _report_signals(embedded_report)
    technical_verdict = _technical_verdict(embedded_report, signals)
    missing_capabilities = _missing_required_capabilities(
        embedded_report, normalized_policy.required_capabilities
    )
    manifest_state, manifest_incomplete_reason = _manifest_state(
        normalized_policy, manifest_validation
    )
    reason_codes: set[str] = set()

    if signals["errors"]:
        reason_codes.add("scan_error_present")
    if signals["gaps"]:
        reason_codes.add("coverage_gap_present")
    if signals["partial"]:
        reason_codes.add("partial_artifact_present")
    if signals["dependency"]:
        reason_codes.add("optional_dependency_unavailable")
    if embedded_report["summary"]["verdict"] == "incomplete":
        reason_codes.add("technical_incomplete_reported")
    if missing_capabilities:
        reason_codes.add("required_capability_incomplete")
    if manifest_incomplete_reason is not None:
        reason_codes.add(manifest_incomplete_reason)

    findings = embedded_report["findings"]
    category_block = any(
        finding["category"] in normalized_policy.blocking_categories
        for finding in findings
    )
    severity_block = _threshold_met(findings, normalized_policy.fail_on)
    if category_block:
        reason_codes.add("blocking_category_present")
    if severity_block:
        reason_codes.add("severity_threshold_met")

    if (
        technical_verdict == "incomplete"
        or missing_capabilities
        or manifest_incomplete_reason is not None
    ):
        policy_outcome = "incomplete"
        exit_code = 2
    elif category_block or severity_block:
        policy_outcome = "block"
        exit_code = 1
    elif findings:
        policy_outcome = "review"
        exit_code = 0
        reason_codes.add("findings_below_threshold")
    else:
        policy_outcome = "pass"
        exit_code = 0
        reason_codes.add("no_findings_observed")

    if technical_verdict == "block":
        reason_codes.add("technical_block_reported")

    effective = normalize_policy(normalized_policy)
    policy_receipt = dict(effective)
    policy_receipt["digest"] = policy_digest(normalized_policy)
    policy_receipt["ruleset_version"] = ruleset_version
    return {
        "schema": CHECK_SCHEMA,
        "tool": {"name": "sharesafe", "version": __version__},
        "policy": policy_receipt,
        "decision": {
            "technical_verdict": technical_verdict,
            "policy_outcome": policy_outcome,
            "exit_code": exit_code,
            "manifest_validation": manifest_state,
            "reason_codes": [
                reason for reason in _REASON_ORDER if reason in reason_codes
            ],
        },
        "report": embedded_report,
    }


def _validated_policy(policy: Policy | Mapping[str, Any] | None) -> Policy:
    if policy is None:
        return policy_from_mapping({})
    if isinstance(policy, Policy):
        # Re-parse the public representation so direct dataclass construction
        # cannot bypass validation at this trust boundary.
        return policy_from_mapping(policy.to_dict())
    return policy_from_mapping(policy)


def _manifest_state(policy: Policy, validation: str | None) -> tuple[str, str | None]:
    if not policy.manifest.enabled:
        if validation is not None:
            raise CheckError(
                "unexpected_manifest_validation",
                "Manifest validation was supplied while the policy manifest is disabled.",
            )
        return "not_required", None
    if validation is None:
        return "missing", "manifest_validation_missing"
    if validation not in {"complete", "incomplete"}:
        raise CheckError("invalid_manifest_validation", "Manifest validation status is invalid.")
    if not policy.manifest.require_exact:
        return "incomplete", "manifest_not_exact"
    if validation == "incomplete":
        return "incomplete", "manifest_validation_incomplete"
    return "complete", None


def _validate_ruleset_version(value: str) -> None:
    suffix = value[len(_RULESET_PREFIX) :] if isinstance(value, str) and value.startswith(_RULESET_PREFIX) else ""
    if not suffix.isdigit() or int(suffix) < 1 or str(int(suffix)) != suffix:
        raise CheckError("invalid_ruleset_version", "Ruleset version is invalid.")


def _validated_report_copy(report: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(report, Mapping):
        raise CheckError("invalid_report", "Check input must be a ShareSafe report object.")
    copied = deepcopy(dict(report))
    if copied.get("schema") != _REPORT_SCHEMA:
        raise CheckError("unsupported_report_schema", "Check input is not sharesafe.report/v1.")
    required = {
        "tool",
        "run",
        "summary",
        "artifacts",
        "findings",
        "gaps",
        "errors",
        "dependencies",
    }
    if not required <= set(copied):
        raise CheckError("invalid_report", "ShareSafe report is missing a required field.")
    if not isinstance(copied["summary"], Mapping):
        raise CheckError("invalid_report", "ShareSafe report summary is invalid.")
    verdict = copied["summary"].get("verdict")
    if verdict not in _TECHNICAL_VERDICTS:
        raise CheckError("invalid_report", "ShareSafe report verdict is invalid.")
    for name in ("artifacts", "findings", "gaps", "errors", "dependencies"):
        if not isinstance(copied[name], list):
            raise CheckError("invalid_report", f"ShareSafe report field {name} is invalid.")

    for artifact in copied["artifacts"]:
        if not isinstance(artifact, Mapping) or artifact.get("status") not in {"scanned", "partial"}:
            raise CheckError("invalid_report", "ShareSafe report contains an invalid artifact.")
        coverage = artifact.get("coverage")
        if not isinstance(coverage, Mapping) or any(
            not isinstance(capability, str) or value not in _COVERAGE_VALUES
            for capability, value in coverage.items()
        ):
            raise CheckError("invalid_report", "ShareSafe report contains invalid coverage.")

    for finding in copied["findings"]:
        if (
            not isinstance(finding, Mapping)
            or finding.get("severity") not in _SEVERITY_RANK
            or not isinstance(finding.get("category"), str)
            or not finding["category"]
        ):
            raise CheckError("invalid_report", "ShareSafe report contains an invalid finding.")
    for name in ("gaps", "errors"):
        if any(not isinstance(item, Mapping) for item in copied[name]):
            raise CheckError("invalid_report", f"ShareSafe report contains an invalid {name[:-1]}.")
    for dependency in copied["dependencies"]:
        if not isinstance(dependency, Mapping) or type(dependency.get("available")) is not bool:
            raise CheckError("invalid_report", "ShareSafe report contains an invalid dependency.")

    summary = copied["summary"]
    for name in ("gaps", "errors"):
        value = summary.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise CheckError("invalid_report", f"ShareSafe report summary field {name} is invalid.")
    return copied


def _report_signals(report: Mapping[str, Any]) -> dict[str, bool]:
    summary = report["summary"]
    artifacts = report["artifacts"]
    return {
        "errors": bool(report["errors"]) or summary["errors"] > 0,
        "gaps": bool(report["gaps"]) or summary["gaps"] > 0,
        "partial": any(
            artifact["status"] == "partial"
            or any(value in {"partial", "unsupported"} for value in artifact["coverage"].values())
            for artifact in artifacts
        ),
        "dependency": any(not dependency["available"] for dependency in report["dependencies"]),
    }


def _technical_verdict(report: Mapping[str, Any], signals: Mapping[str, bool]) -> str:
    reported = report["summary"]["verdict"]
    if reported == "incomplete" or any(signals.values()):
        return "incomplete"
    if reported == "block" or any(
        finding["severity"] in {"high", "critical"} for finding in report["findings"]
    ):
        return "block"
    if reported == "review" or report["findings"]:
        return "review"
    return "no_findings"


def _missing_required_capabilities(
    report: Mapping[str, Any], required: Sequence[str]
) -> tuple[str, ...]:
    missing: set[str] = set()
    for capability in required:
        for artifact in report["artifacts"]:
            value = artifact["coverage"].get(capability)
            if value not in {"complete", "not_applicable"}:
                missing.add(capability)
                break
    return tuple(sorted(missing))


def _threshold_met(findings: Sequence[Mapping[str, Any]], fail_on: str) -> bool:
    if fail_on == "never":
        return False
    threshold = _SEVERITY_RANK[fail_on]
    return any(_SEVERITY_RANK[finding["severity"]] >= threshold for finding in findings)
