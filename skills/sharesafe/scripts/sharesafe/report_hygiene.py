"""Mechanical privacy and integrity checks for every masked report sink.

The validator deliberately does not inspect source files or try to infer missing
evidence.  It verifies that an already-built payload stays within the masked
report contract before JSON or terminal output begins.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterator
from typing import Any

from .limits import DEFAULT_MAX_REPORT_BYTES, MAX_LIMIT_VALUE, Limits
from .redaction import (
    DISPLAY_PATH_LIMIT_PLACEHOLDER,
    NAME_LIMIT_PLACEHOLDER,
    sanitize_display_path_result,
)

_RAW_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_INVISIBLE_FORMAT_RE = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]"
)
_WINDOWS_ABSOLUTE_RE = re.compile(r"(?i)^[a-z]:[\\/]")
_UNMASKED_HOME_RE = re.compile(
    r"(?i)(?:[a-z]:[\\/]+(?:users|documents and settings)[\\/]+(?!<user>)[^\\/!\s]+"
    r"|/(?:home|users)/(?!<user>)[^/!\s]+|/root(?:/|!|$))"
)
_UNMASKED_UNC_RE = re.compile(r"^[\\/]{2}(?!<host>)[^\\/!\s]+[\\/]")
_ARTIFACT_ID_RE = re.compile(r"^a-[0-9a-f]{20}$")
_FINDING_ID_RE = re.compile(r"^f-[0-9a-f]{20}$")
_GAP_ID_RE = re.compile(r"^g-[0-9a-f]{20}$")
_CONTENT_TOKEN_RE = re.compile(r"^hmac-sha256:content-v1:[0-9a-f]{32}$")
_EVIDENCE_TOKEN_RE = re.compile(r"^hmac-sha256:v1:[0-9a-f]{32}$")
_MASKED_VALUE_RE = re.compile(r"^<[^<>\r\n]+>$")

_REPORT_KEYS = {
    "schema",
    "tool",
    "run",
    "summary",
    "artifacts",
    "findings",
    "gaps",
    "errors",
    "dependencies",
}
_ARTIFACT_KEYS = {
    "id",
    "path",
    "content_token",
    "size",
    "media_type",
    "status",
    "coverage",
}
_FINDING_KEYS = {
    "id",
    "artifact_id",
    "rule_id",
    "category",
    "severity",
    "confidence",
    "title",
    "location",
    "evidence",
    "remediation",
}
_GAP_KEYS = {"id", "artifact_id", "capability", "reason", "detail"}
_SEVERITIES = ("info", "low", "medium", "high", "critical")
_COVERAGE_VALUES = {"complete", "partial", "unsupported", "not_applicable"}
_LOCATION_KEYS = {
    "artifact": {"kind"},
    "filename": {"kind"},
    "container_part_name": {"kind", "part"},
    "text": {"kind", "line", "column", "encoding"},
    "container_part": {"kind", "part", "line", "column"},
    "archive_member": {"kind", "index", "occurrence"},
    "archive_metadata": {"kind"},
    "image_chunk": {"kind", "chunk"},
    "image_segment": {"kind", "marker"},
    "image_metadata": {"kind", "tag", "tag_count"},
    "ooxml_package": {"kind", "part_count"},
    "ooxml_part": {"kind", "index", "occurrence", "part", "count", "field"},
    "pdf_dictionary": {"kind", "field"},
    "pdf_metadata": {"kind", "field"},
    "pdf_structure": {"kind"},
    "pdf_trailer": {"kind"},
}


class ReportHygieneError(ValueError):
    """A stable, non-sensitive report rejection.

    The message never includes the rejected value or a user-controlled object
    key, so routing this exception through a generic error handler cannot create
    a secondary disclosure.
    """

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"masked report hygiene check failed ({code})")


def _fail(code: str) -> None:
    raise ReportHygieneError(code)


def _dict(value: object, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(code)
    return value


def _list(value: object, code: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(code)
    return value


def _string(value: object, code: str) -> str:
    if not isinstance(value, str):
        _fail(code)
    return value


def _integer(value: object, code: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(code)
    if value < minimum or value > MAX_LIMIT_VALUE:
        _fail(code)
    return value


def _number(value: object, code: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(code)
    number = float(value)
    if not math.isfinite(number):
        _fail(code)
    return number


def _exact_keys(value: dict[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        _fail(code)


def _path_is_relative_or_placeholder(value: str) -> bool:
    if value in {DISPLAY_PATH_LIMIT_PLACEHOLDER, NAME_LIMIT_PLACEHOLDER}:
        return True
    outer = value.split("!/", 1)[0]
    if outer.startswith("<") and outer.endswith(">"):
        return True
    return not (
        outer.startswith(("/", "\\")) or bool(_WINDOWS_ABSOLUTE_RE.match(outer))
    )


def _validate_json_tree(
    value: object,
    limits: Limits,
    *,
    key_context: str | None = None,
    depth: int = 0,
) -> None:
    if depth > 64:
        _fail("nesting_limit")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > MAX_LIMIT_VALUE:
            _fail("integer_limit")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            _fail("non_finite_number")
        return
    if isinstance(value, str):
        if len(value) > limits.max_report_field_chars:
            _fail("report_field_limit")
        if _RAW_CONTROL_RE.search(value) or _INVISIBLE_FORMAT_RE.search(value):
            _fail("raw_control_character")
        if _UNMASKED_HOME_RE.search(value) or _UNMASKED_UNC_RE.search(value):
            _fail("unmasked_home_path")
        if key_context in {"path", "part"}:
            if len(value) > limits.max_display_path_chars:
                _fail("display_path_limit")
            rendered = sanitize_display_path_result(
                value,
                max_name_bytes=limits.max_name_bytes,
                max_display_path_chars=limits.max_display_path_chars,
            )
            if rendered.value != value:
                _fail("unmasked_display_path")
            if not _path_is_relative_or_placeholder(value):
                _fail("absolute_display_path")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_tree(item, limits, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail("non_string_key")
            _validate_json_tree(key, limits, depth=depth + 1)
            _validate_json_tree(item, limits, key_context=key, depth=depth + 1)
        return
    _fail("non_json_value")


def _validate_location(location: object) -> None:
    record = _dict(location, "invalid_location")
    kind = _string(record.get("kind"), "invalid_location")
    allowed = _LOCATION_KEYS.get(kind)
    if allowed is None or not set(record) <= allowed:
        _fail("invalid_location")
    if kind in {"text", "container_part"}:
        _integer(record.get("line"), "invalid_location", minimum=1)
        _integer(record.get("column"), "invalid_location", minimum=1)
    for key in ("index", "occurrence", "count", "part_count", "tag_count"):
        if key in record:
            _integer(record[key], "invalid_location", minimum=0)


def _validate_evidence(evidence: object) -> None:
    record = _dict(evidence, "invalid_evidence")
    if not set(record) <= {"mode", "masked", "value_class", "token"}:
        _fail("invalid_evidence")
    mode = record.get("mode")
    if mode == "masked":
        if not {"mode", "masked", "value_class"} <= set(record):
            _fail("invalid_evidence")
        masked = _string(record["masked"], "invalid_evidence")
        value_class = _string(record["value_class"], "invalid_evidence")
        if value_class in {"path", "user_path"}:
            if sanitize_display_path_result(masked).value != masked:
                _fail("invalid_masked_evidence")
        elif not _MASKED_VALUE_RE.fullmatch(masked):
            _fail("invalid_masked_evidence")
        if "token" in record and not _EVIDENCE_TOKEN_RE.fullmatch(
            _string(record["token"], "invalid_evidence")
        ):
            _fail("invalid_evidence_token")
    elif mode == "omitted":
        if "masked" in record or "token" in record:
            _fail("invalid_evidence")
        if "value_class" in record:
            _string(record["value_class"], "invalid_evidence")
    else:
        _fail("invalid_evidence")


def _validate_scan_report(report: dict[str, Any]) -> None:
    _exact_keys(report, _REPORT_KEYS, "invalid_report_schema")
    if report.get("schema") != "sharesafe.report/v1":
        _fail("invalid_report_schema")

    tool = _dict(report.get("tool"), "invalid_tool")
    _exact_keys(tool, {"name", "version"}, "invalid_tool")
    if tool.get("name") != "sharesafe":
        _fail("invalid_tool")
    _string(tool.get("version"), "invalid_tool")

    run = _dict(report.get("run"), "invalid_run")
    _exact_keys(
        run, {"id", "started_at", "offline", "report_mode", "limits"}, "invalid_run"
    )
    if not re.fullmatch(r"run-[0-9a-f]{16}", _string(run.get("id"), "invalid_run")):
        _fail("invalid_run")
    _string(run.get("started_at"), "invalid_run")
    if run.get("offline") is not True or run.get("report_mode") not in {
        "local_masked",
        "share_summary",
        "shareable",
        "local",
    }:
        _fail("invalid_run")
    run_limits = _dict(run.get("limits"), "invalid_run")
    if not run_limits:
        _fail("invalid_run")
    for value in run_limits.values():
        _integer(value, "invalid_run")

    artifacts = _list(report.get("artifacts"), "invalid_artifacts")
    artifact_ids: set[str] = set()
    complete = 0
    partial = 0
    for item in artifacts:
        artifact = _dict(item, "invalid_artifact")
        _exact_keys(artifact, _ARTIFACT_KEYS, "invalid_artifact")
        artifact_id = _string(artifact.get("id"), "invalid_artifact")
        if not _ARTIFACT_ID_RE.fullmatch(artifact_id) or artifact_id in artifact_ids:
            _fail("invalid_artifact")
        artifact_ids.add(artifact_id)
        _string(artifact.get("path"), "invalid_artifact")
        token = artifact.get("content_token")
        if token is not None and not _CONTENT_TOKEN_RE.fullmatch(
            _string(token, "invalid_artifact")
        ):
            _fail("invalid_artifact")
        if artifact.get("size") is not None:
            _integer(artifact["size"], "invalid_artifact")
        _string(artifact.get("media_type"), "invalid_artifact")
        status = artifact.get("status")
        if status == "scanned":
            complete += 1
        elif status == "partial":
            partial += 1
        else:
            _fail("invalid_artifact")
        coverage = _dict(artifact.get("coverage"), "invalid_artifact")
        if not all(
            isinstance(key, str) and value in _COVERAGE_VALUES
            for key, value in coverage.items()
        ):
            _fail("invalid_artifact")

    findings = _list(report.get("findings"), "invalid_findings")
    finding_ids: set[str] = set()
    severity_counts = {severity: 0 for severity in _SEVERITIES}
    for item in findings:
        finding = _dict(item, "invalid_finding")
        _exact_keys(finding, _FINDING_KEYS, "invalid_finding")
        finding_id = _string(finding.get("id"), "invalid_finding")
        if not _FINDING_ID_RE.fullmatch(finding_id) or finding_id in finding_ids:
            _fail("invalid_finding")
        finding_ids.add(finding_id)
        if finding.get("artifact_id") not in artifact_ids:
            _fail("invalid_finding_reference")
        _string(finding.get("rule_id"), "invalid_finding")
        _string(finding.get("category"), "invalid_finding")
        severity = finding.get("severity")
        if severity not in severity_counts:
            _fail("invalid_finding")
        severity_counts[severity] += 1
        confidence = _number(finding.get("confidence"), "invalid_finding")
        if not 0 <= confidence <= 1:
            _fail("invalid_finding")
        _string(finding.get("title"), "invalid_finding")
        _validate_location(finding.get("location"))
        _validate_evidence(finding.get("evidence"))
        remediation = _dict(finding.get("remediation"), "invalid_remediation")
        _exact_keys(remediation, {"supported", "action"}, "invalid_remediation")
        if not isinstance(remediation.get("supported"), bool):
            _fail("invalid_remediation")
        _string(remediation.get("action"), "invalid_remediation")

    gaps = _list(report.get("gaps"), "invalid_gaps")
    gap_ids: set[str] = set()
    for item in gaps:
        gap = _dict(item, "invalid_gap")
        _exact_keys(gap, _GAP_KEYS, "invalid_gap")
        gap_id = _string(gap.get("id"), "invalid_gap")
        if not _GAP_ID_RE.fullmatch(gap_id) or gap_id in gap_ids:
            _fail("invalid_gap")
        gap_ids.add(gap_id)
        if (
            gap.get("artifact_id") is not None
            and gap.get("artifact_id") not in artifact_ids
        ):
            _fail("invalid_gap_reference")
        _string(gap.get("capability"), "invalid_gap")
        _string(gap.get("reason"), "invalid_gap")
        _string(gap.get("detail"), "invalid_gap")

    errors = _list(report.get("errors"), "invalid_errors")
    for item in errors:
        error = _dict(item, "invalid_error")
        _exact_keys(error, {"code", "message"}, "invalid_error")
        _string(error.get("code"), "invalid_error")
        _string(error.get("message"), "invalid_error")

    dependencies = _list(report.get("dependencies"), "invalid_dependencies")
    for item in dependencies:
        dependency = _dict(item, "invalid_dependency")
        _exact_keys(
            dependency,
            {"name", "available", "version", "capability"},
            "invalid_dependency",
        )
        _string(dependency.get("name"), "invalid_dependency")
        if not isinstance(dependency.get("available"), bool):
            _fail("invalid_dependency")
        if dependency.get("version") is not None:
            _string(dependency.get("version"), "invalid_dependency")
        _string(dependency.get("capability"), "invalid_dependency")

    summary = _dict(report.get("summary"), "invalid_summary")
    _exact_keys(
        summary,
        {
            "verdict",
            "artifacts_total",
            "artifacts_complete",
            "artifacts_partial",
            "findings",
            "gaps",
            "errors",
        },
        "invalid_summary",
    )
    if _integer(summary.get("artifacts_total"), "invalid_summary") != len(artifacts):
        _fail("invalid_summary")
    if _integer(summary.get("artifacts_complete"), "invalid_summary") != complete:
        _fail("invalid_summary")
    if _integer(summary.get("artifacts_partial"), "invalid_summary") != partial:
        _fail("invalid_summary")
    summary_findings = _dict(summary.get("findings"), "invalid_summary")
    _exact_keys(summary_findings, set(_SEVERITIES), "invalid_summary")
    if any(
        _integer(summary_findings[key], "invalid_summary") != value
        for key, value in severity_counts.items()
    ):
        _fail("invalid_summary")
    if _integer(summary.get("gaps"), "invalid_summary") != len(gaps):
        _fail("invalid_summary")
    if _integer(summary.get("errors"), "invalid_summary") != len(errors):
        _fail("invalid_summary")
    expected_verdict = (
        "incomplete"
        if gaps or errors or partial
        else "block"
        if severity_counts["high"] or severity_counts["critical"]
        else "review"
        if findings
        else "no_findings"
    )
    if summary.get("verdict") != expected_verdict:
        _fail("invalid_summary")


def _reports_in(value: object, *, depth: int = 0) -> Iterator[dict[str, Any]]:
    if depth > 64:
        return
    if isinstance(value, dict):
        if value.get("schema") == "sharesafe.report/v1":
            yield value
            return
        for item in value.values():
            yield from _reports_in(item, depth=depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from _reports_in(item, depth=depth + 1)


def validate_masked_payload(
    payload: dict[str, Any], *, limits: Limits | None = None
) -> None:
    """Reject structurally invalid, unbounded, or unmasked output payloads."""

    if not isinstance(payload, dict):
        _fail("invalid_payload")
    effective_limits = limits or Limits()
    _validate_json_tree(payload, effective_limits)
    for report in _reports_in(payload):
        _validate_scan_report(report)


def json_within_byte_limit(payload: dict[str, Any], max_bytes: int) -> bool:
    """Measure pretty JSON incrementally and stop immediately after ``max_bytes``."""

    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    encoder = json.JSONEncoder(
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    )
    total = 1  # trailing newline written by every JSON sink
    try:
        for chunk in encoder.iterencode(payload):
            total += len(chunk.encode("utf-8"))
            if total > max_bytes:
                return False
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ReportHygieneError("json_encoding") from exc
    return True


def payload_byte_limit(payload: dict[str, Any]) -> int:
    """Use a scan report's recorded limit, otherwise the bounded sink default."""

    if payload.get("schema") == "sharesafe.report/v1":
        value = payload.get("run", {}).get("limits", {}).get("max_report_bytes")
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    if payload.get("schema") == "sharesafe.prepare-result/v1":
        value = payload.get("reporting", {}).get("max_bytes")
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    return DEFAULT_MAX_REPORT_BYTES


def validated_json_text(
    payload: dict[str, Any], *, limits: Limits | None = None
) -> str:
    """Return complete JSON only after hygiene and byte-budget validation."""

    validate_masked_payload(payload, limits=limits)
    max_bytes = (
        limits.max_report_bytes if limits is not None else payload_byte_limit(payload)
    )
    if not json_within_byte_limit(payload, max_bytes):
        _fail("report_size_limit")
    try:
        return (
            json.dumps(
                payload,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ReportHygieneError("json_encoding") from exc


__all__ = [
    "ReportHygieneError",
    "json_within_byte_limit",
    "payload_byte_limit",
    "validate_masked_payload",
    "validated_json_text",
]
