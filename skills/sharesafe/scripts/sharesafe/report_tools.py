"""Safe, bounded derived views for saved ShareSafe reports.

The helpers in this module deliberately never compare finding IDs, evidence
tokens, or content tokens.  A structural diff means only that a rule ID,
masked display path, and structured location have the same JSON value.
"""

from __future__ import annotations

import json
import os
import stat
from collections import Counter
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from .check import CheckError, build_check
from .limits import DEFAULT_MAX_REPORT_BYTES, MAX_LIMIT_VALUE, Limits
from .path_safety import uses_windows_alternate_stream
from .policy import PolicyError, policy_from_mapping
from .report_hygiene import (
    ReportHygieneError,
    json_within_byte_limit,
    validate_masked_payload,
)
from .safe_io import (
    FileIdentityChangedError,
    open_verified_binary,
    verify_open_file_unchanged,
)

REPORT_SCHEMA = "sharesafe.report/v1"
CHECK_SCHEMA = "sharesafe.check/v1"
REPORT_SHOW_SCHEMA = "sharesafe.report-show/v1"
REPORT_DIFF_SCHEMA = "sharesafe.report-diff/v1"
SHARE_SUMMARY_SCHEMA = "sharesafe.share-summary/v1"

MAX_REPORT_DOCUMENT_BYTES = DEFAULT_MAX_REPORT_BYTES

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {value: index for index, value in enumerate(SEVERITIES)}
GROUP_BY_VALUES = ("rule", "category", "severity")

_CHECK_KEYS = {"schema", "tool", "policy", "decision", "report"}
_POLICY_CONTEXT_KEYS = {"digest", "ruleset_version"}
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class ReportToolError(ValueError):
    """A stable, path-free failure while reading or deriving a report view."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class _ReportDocument:
    document: dict[str, Any]
    report: dict[str, Any]
    document_schema: str
    report_schema: str
    ruleset_version: str | None
    policy_digest: str | None
    policy_outcome: str | None
    decision_exit_code: int | None
    limits: Limits


def load_report_file(
    path: str | os.PathLike[str],
    *,
    max_bytes: int = MAX_REPORT_DOCUMENT_BYTES,
) -> dict[str, Any]:
    """Read and validate one explicitly selected JSON report document.

    Reading is handle-first and bounded.  A final-component link/reparse point,
    object swap, mid-read change, non-UTF-8 input, unknown schema, or malformed
    report is rejected with a non-sensitive error.
    """

    limit = _positive_limit(max_bytes, "max_bytes")
    selected = Path(path)
    if uses_windows_alternate_stream(selected):
        raise ReportToolError(
            "report_stream_rejected",
            "Report input must not select an alternate data stream.",
        )

    data = _read_report_bytes(selected, limit)
    try:
        document = json.loads(
            data.decode("utf-8"),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_strict_json_object,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise ReportToolError(
            "invalid_report_json", "Report input is not valid bounded UTF-8 JSON."
        ) from exc
    if type(document) is not dict:
        raise ReportToolError(
            "invalid_report_document", "Report input must be a JSON object."
        )
    _inspect_document(document)
    return document


def show_report(
    document: Mapping[str, Any],
    *,
    group_by: str = "rule",
    min_severity: str = "info",
    max_output_bytes: int = DEFAULT_MAX_REPORT_BYTES,
) -> dict[str, Any]:
    """Build an aggregate local view grouped by rule, category, or severity."""

    if group_by not in GROUP_BY_VALUES:
        raise ReportToolError(
            "invalid_group_by", "Report grouping must be rule, category, or severity."
        )
    if min_severity not in SEVERITY_RANK:
        raise ReportToolError("invalid_min_severity", "Minimum severity is invalid.")
    output_limit = _positive_limit(max_output_bytes, "max_output_bytes")
    inspected = _inspect_document(document)

    threshold = SEVERITY_RANK[min_severity]
    selected = [
        item
        for item in inspected.report["findings"]
        if SEVERITY_RANK[item["severity"]] >= threshold
    ]
    grouped: dict[str, list[dict[str, Any]]] = {}
    group_field = {"rule": "rule_id", "category": "category", "severity": "severity"}[
        group_by
    ]
    for finding in selected:
        grouped.setdefault(finding[group_field], []).append(finding)

    def group_sort_key(value: str) -> tuple[int, str]:
        if group_by == "severity":
            return (-SEVERITY_RANK[value], value)
        return (0, value)

    groups = []
    for key in sorted(grouped, key=group_sort_key):
        findings = grouped[key]
        groups.append(
            {
                "value": key,
                "count": len(findings),
                "findings_by_severity": _severity_counts(findings),
            }
        )

    report_summary = inspected.report["summary"]
    payload = {
        "schema": REPORT_SHOW_SCHEMA,
        "source": _source_context(inspected),
        "selection": {
            "group_by": group_by,
            "min_severity": min_severity,
            "selected_findings": len(selected),
            "filtered_findings": len(inspected.report["findings"]) - len(selected),
        },
        "summary": {
            "technical_verdict": report_summary["verdict"],
            "policy_outcome": inspected.policy_outcome,
            "artifacts_total": report_summary["artifacts_total"],
            "artifacts_complete": report_summary["artifacts_complete"],
            "artifacts_partial": report_summary["artifacts_partial"],
            "gaps": report_summary["gaps"],
            "errors": report_summary["errors"],
        },
        "groups": groups,
    }
    return _validated_derived(payload, inspected.limits, output_limit)


def diff_reports(
    old_document: Mapping[str, Any],
    new_document: Mapping[str, Any],
    *,
    max_output_bytes: int = DEFAULT_MAX_REPORT_BYTES,
) -> dict[str, Any]:
    """Compare two reports as multisets of rule/path/location structures.

    The comparison intentionally ignores every finding ID, artifact ID,
    evidence field, content token, title, category, confidence, severity, and
    remediation field.  It therefore cannot establish content identity.
    """

    output_limit = _positive_limit(max_output_bytes, "max_output_bytes")
    old = _inspect_document(old_document)
    new = _inspect_document(new_document)
    old_counts, old_records = _structural_inventory(old.report)
    new_counts, new_records = _structural_inventory(new.report)

    same: list[dict[str, Any]] = []
    introduced: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    all_keys = sorted(set(old_counts) | set(new_counts))
    for key in all_keys:
        old_count = old_counts[key]
        new_count = new_counts[key]
        shared = min(old_count, new_count)
        if shared:
            same.append(
                _classified_structure(
                    "same_rule_path_location",
                    old_records.get(key) or new_records[key],
                    shared,
                )
            )
        if new_count > shared:
            introduced.append(
                _classified_structure(
                    "structure_new", new_records[key], new_count - shared
                )
            )
        if old_count > shared:
            resolved.append(
                _classified_structure(
                    "structure_resolved", old_records[key], old_count - shared
                )
            )

    context = {
        "schema_changed": (
            old.document_schema != new.document_schema
            or old.report_schema != new.report_schema
        ),
        "ruleset_changed": _changed_if_recorded(
            old.ruleset_version, new.ruleset_version
        ),
        "policy_changed": _changed_if_recorded(old.policy_digest, new.policy_digest),
        "old": _source_context(old, include_policy_outcome=False),
        "new": _source_context(new, include_policy_outcome=False),
    }
    payload = {
        "schema": REPORT_DIFF_SCHEMA,
        "comparison_basis": "rule_path_location_multiset",
        "context": context,
        "summary": {
            "same_rule_path_location": sum(item["count"] for item in same),
            "structure_new": sum(item["count"] for item in introduced),
            "structure_resolved": sum(item["count"] for item in resolved),
        },
        "same_rule_path_location": same,
        "structure_new": introduced,
        "structure_resolved": resolved,
        "interpretation": [
            "A structural match means only equal rule ID, masked display path, and structured location.",
            "Finding identity and content identity are outside this comparison.",
        ],
    }
    limits = _merge_limits(old.limits, new.limits)
    return _validated_derived(payload, limits, output_limit)


def share_summary(
    document: Mapping[str, Any],
    *,
    max_output_bytes: int = DEFAULT_MAX_REPORT_BYTES,
) -> dict[str, Any]:
    """Return a minimal aggregate view suitable for separately authorized sharing.

    The result contains no artifact list, display filename, byte size, content
    or evidence token, run identifier, or timestamp.  Producing this view does
    not authorize uploading it.
    """

    output_limit = _positive_limit(max_output_bytes, "max_output_bytes")
    inspected = _inspect_document(document)
    summary = inspected.report["summary"]
    unavailable_dependencies = sum(
        1
        for dependency in inspected.report["dependencies"]
        if dependency["available"] is False
    )
    payload = {
        "schema": SHARE_SUMMARY_SCHEMA,
        "source_schema": inspected.document_schema,
        "summary": {
            "technical_verdict": summary["verdict"],
            "policy_outcome": inspected.policy_outcome,
            "decision_exit_code": inspected.decision_exit_code,
            "artifacts_total": summary["artifacts_total"],
            "artifacts_complete": summary["artifacts_complete"],
            "artifacts_partial": summary["artifacts_partial"],
            "findings_by_severity": {
                severity: summary["findings"][severity] for severity in SEVERITIES
            },
            "gaps": summary["gaps"],
            "errors": summary["errors"],
            "unavailable_dependencies": unavailable_dependencies,
        },
    }
    return _validated_derived(payload, inspected.limits, output_limit)


def show_report_file(
    path: str | os.PathLike[str],
    *,
    group_by: str = "rule",
    min_severity: str = "info",
    max_input_bytes: int = MAX_REPORT_DOCUMENT_BYTES,
    max_output_bytes: int = DEFAULT_MAX_REPORT_BYTES,
) -> dict[str, Any]:
    """Safely load a report file and return :func:`show_report`."""

    return show_report(
        load_report_file(path, max_bytes=max_input_bytes),
        group_by=group_by,
        min_severity=min_severity,
        max_output_bytes=max_output_bytes,
    )


def diff_report_files(
    old_path: str | os.PathLike[str],
    new_path: str | os.PathLike[str],
    *,
    max_input_bytes: int = MAX_REPORT_DOCUMENT_BYTES,
    max_output_bytes: int = DEFAULT_MAX_REPORT_BYTES,
) -> dict[str, Any]:
    """Safely load two report files and return :func:`diff_reports`."""

    old_document = load_report_file(old_path, max_bytes=max_input_bytes)
    new_document = load_report_file(new_path, max_bytes=max_input_bytes)
    return diff_reports(old_document, new_document, max_output_bytes=max_output_bytes)


def share_summary_file(
    path: str | os.PathLike[str],
    *,
    max_input_bytes: int = MAX_REPORT_DOCUMENT_BYTES,
    max_output_bytes: int = DEFAULT_MAX_REPORT_BYTES,
) -> dict[str, Any]:
    """Safely load a report file and return :func:`share_summary`."""

    return share_summary(
        load_report_file(path, max_bytes=max_input_bytes),
        max_output_bytes=max_output_bytes,
    )


def _read_report_bytes(path: Path, max_bytes: int) -> bytes:
    try:
        before = path.lstat()
        attributes = getattr(before, "st_file_attributes", 0)
        if not stat.S_ISREG(before.st_mode) or attributes & _REPARSE_ATTRIBUTE:
            raise ReportToolError(
                "report_link_rejected",
                "Report input must be a regular non-link file.",
            )
        if before.st_size > max_bytes:
            raise ReportToolError(
                "report_too_large", "Report input exceeds the configured byte limit."
            )
        handle, opened = open_verified_binary(path, expected=before)
        with handle:
            data = handle.read(max_bytes + 1)
            unchanged = verify_open_file_unchanged(handle, path, opened=opened)
    except ReportToolError:
        raise
    except FileIdentityChangedError as exc:
        raise ReportToolError(
            "report_changed_during_read",
            "Report input changed while it was being read.",
        ) from exc
    except OSError as exc:
        raise ReportToolError(
            "report_unavailable", "Report input could not be read safely."
        ) from exc

    if not unchanged:
        raise ReportToolError(
            "report_changed_during_read",
            "Report input changed while it was being read.",
        )
    if len(data) > max_bytes:
        raise ReportToolError(
            "report_too_large", "Report input exceeds the configured byte limit."
        )
    return data


def _inspect_document(document: Mapping[str, Any]) -> _ReportDocument:
    try:
        if type(document) is not dict:
            raise ReportToolError(
                "invalid_report_document", "Report input must be a JSON object."
            )
        copied = deepcopy(document)
        schema = copied.get("schema")
        if schema == REPORT_SCHEMA:
            report = copied
            ruleset_version = None
            policy_digest = None
            policy_outcome = None
            decision_exit_code = None
        elif schema == CHECK_SCHEMA:
            _validate_check_document(copied)
            report = copied["report"]
            ruleset_version = copied["policy"]["ruleset_version"]
            policy_digest = copied["policy"]["digest"]
            policy_outcome = copied["decision"]["policy_outcome"]
            decision_exit_code = copied["decision"]["exit_code"]
        else:
            raise ReportToolError(
                "unsupported_report_schema",
                "Report input schema is missing or unsupported.",
            )

        limits = _limits_from_report(report)
        validate_masked_payload(copied, limits=limits)
        if not json_within_byte_limit(report, limits.max_report_bytes):
            raise ReportToolError(
                "invalid_report_document",
                "Report input exceeds its recorded report byte budget.",
            )
    except ReportToolError:
        raise
    except (
        ReportHygieneError,
        CheckError,
        PolicyError,
        KeyError,
        TypeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise ReportToolError(
            "invalid_report_document", "Report input failed structural validation."
        ) from exc
    return _ReportDocument(
        document=copied,
        report=report,
        document_schema=schema,
        report_schema=report["schema"],
        ruleset_version=ruleset_version,
        policy_digest=policy_digest,
        policy_outcome=policy_outcome,
        decision_exit_code=decision_exit_code,
        limits=limits,
    )


def _validate_check_document(document: dict[str, Any]) -> None:
    if set(document) != _CHECK_KEYS:
        raise ReportToolError(
            "invalid_report_document", "Check report contains unsupported fields."
        )
    tool = document.get("tool")
    if (
        type(tool) is not dict
        or set(tool) != {"name", "version"}
        or tool.get("name") != "sharesafe"
        or not isinstance(tool.get("version"), str)
    ):
        raise ReportToolError(
            "invalid_report_document", "Check report tool identity is invalid."
        )
    policy_receipt = document.get("policy")
    decision = document.get("decision")
    if type(policy_receipt) is not dict or not _POLICY_CONTEXT_KEYS <= set(
        policy_receipt
    ):
        raise ReportToolError(
            "invalid_report_document", "Check report policy receipt is invalid."
        )
    if type(decision) is not dict:
        raise ReportToolError(
            "invalid_report_document", "Check report decision is invalid."
        )
    policy_mapping = {
        key: value
        for key, value in policy_receipt.items()
        if key not in _POLICY_CONTEXT_KEYS
    }
    policy = policy_from_mapping(policy_mapping)
    manifest_state = decision.get("manifest_validation")
    if manifest_state in {"not_required", "missing"}:
        manifest_validation = None
    elif manifest_state in {"complete", "incomplete"}:
        manifest_validation = manifest_state
    else:
        raise ReportToolError(
            "invalid_report_document", "Check report decision is invalid."
        )
    expected = build_check(
        document.get("report"),
        policy,
        ruleset_version=policy_receipt["ruleset_version"],
        manifest_validation=manifest_validation,
    )
    # The v1 decision contract is reproducible across producer versions.  The
    # wrapper's recorded producer version is nevertheless allowed to differ
    # from the currently installed version.
    expected["tool"] = deepcopy(tool)
    if expected != document:
        raise ReportToolError(
            "invalid_report_document", "Check report decision is inconsistent."
        )


def _limits_from_report(report: dict[str, Any]) -> Limits:
    try:
        raw = report["run"]["limits"]
    except (KeyError, TypeError) as exc:
        raise ReportToolError(
            "invalid_report_document", "Report limits are missing or invalid."
        ) from exc
    if type(raw) is not dict:
        raise ReportToolError(
            "invalid_report_document", "Report limits are missing or invalid."
        )
    defaults = Limits()
    known = {item.name for item in fields(Limits)}
    values = {name: raw.get(name, getattr(defaults, name)) for name in known}
    try:
        return Limits(**values)
    except (TypeError, ValueError) as exc:
        raise ReportToolError(
            "invalid_report_document", "Report limits are missing or invalid."
        ) from exc


def _source_context(
    document: _ReportDocument, *, include_policy_outcome: bool = True
) -> dict[str, Any]:
    context: dict[str, Any] = {
        "document_schema": document.document_schema,
        "report_schema": document.report_schema,
        "ruleset_version": document.ruleset_version,
        "policy_recorded": document.policy_digest is not None,
    }
    if include_policy_outcome:
        context["policy_outcome"] = document.policy_outcome
    return context


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding["severity"]] += 1
    return counts


def _structural_inventory(
    report: dict[str, Any],
) -> tuple[Counter[str], dict[str, dict[str, Any]]]:
    artifact_paths = {
        artifact["id"]: artifact["path"] for artifact in report["artifacts"]
    }
    counts: Counter[str] = Counter()
    records: dict[str, dict[str, Any]] = {}
    for finding in report["findings"]:
        record = {
            "rule_id": finding["rule_id"],
            "path": artifact_paths[finding["artifact_id"]],
            "location": deepcopy(finding["location"]),
        }
        key = json.dumps(
            record,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        counts[key] += 1
        records.setdefault(key, record)
    return counts, records


def _classified_structure(
    classification: str, record: dict[str, Any], count: int
) -> dict[str, Any]:
    return {
        "classification": classification,
        "rule_id": record["rule_id"],
        "path": record["path"],
        "location": deepcopy(record["location"]),
        "count": count,
    }


def _merge_limits(first: Limits, second: Limits) -> Limits:
    # Each source has already been validated against its own recorded limits.
    # The derived diff is their union, so it needs the wider valid envelope for
    # field/path checks.  Taking the minimum would reject a perfectly valid
    # path from the source that intentionally recorded a larger display limit.
    # Input and output resource usage remain independently bounded by
    # ``max_input_bytes`` and ``max_output_bytes``.
    return Limits(
        **{
            item.name: max(getattr(first, item.name), getattr(second, item.name))
            for item in fields(Limits)
        }
    )


def _validated_derived(
    payload: dict[str, Any], limits: Limits, max_output_bytes: int
) -> dict[str, Any]:
    try:
        validate_masked_payload(payload, limits=limits)
        if not json_within_byte_limit(payload, max_output_bytes):
            raise ReportToolError(
                "derived_report_too_large",
                "Derived report exceeds the configured output byte limit.",
            )
    except ReportToolError:
        raise
    except ReportHygieneError as exc:
        raise ReportToolError(
            "invalid_derived_report", "Derived report failed output validation."
        ) from exc
    return payload


def _positive_limit(value: int, name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > MAX_LIMIT_VALUE
    ):
        raise ReportToolError(
            "invalid_report_limit", f"{name} must be a positive integer."
        )
    return value


def _changed_if_recorded(first: str | None, second: str | None) -> bool | None:
    """Compare recorded context, returning unknown when either side omitted it."""

    return None if first is None or second is None else first != second


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(_: str) -> None:
    raise ValueError("non-standard JSON numeric constant")


# Compact aliases for CLI integration and programmatic users.
load_report = load_report_file
report_show = show_report
report_diff = diff_reports


__all__ = [
    "CHECK_SCHEMA",
    "GROUP_BY_VALUES",
    "MAX_REPORT_DOCUMENT_BYTES",
    "REPORT_DIFF_SCHEMA",
    "REPORT_SCHEMA",
    "REPORT_SHOW_SCHEMA",
    "SHARE_SUMMARY_SCHEMA",
    "ReportToolError",
    "diff_report_files",
    "diff_reports",
    "load_report",
    "load_report_file",
    "report_diff",
    "report_show",
    "share_summary",
    "share_summary_file",
    "show_report",
    "show_report_file",
]
