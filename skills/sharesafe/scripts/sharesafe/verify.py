"""Before/after comparison that never overstates safety."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from .models import artifact_map, stable_id
from .receipts import TransformReceipt, bind_and_validate_receipt, trusted_receipts


_OOXML_MEDIA_TYPES = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}
_ACTION_MEDIA_TYPES = {
    "remove_ooxml_metadata": _OOXML_MEDIA_TYPES,
    "strip_png_metadata": {"image/png"},
    "strip_jpeg_metadata": {"image/jpeg"},
}


def _finding_key(report: dict[str, Any], finding: dict[str, Any]) -> str:
    artifacts = artifact_map(report)
    artifact = artifacts.get(finding.get("artifact_id"), {})
    evidence = finding.get("evidence") or {}
    return stable_id(
        "comparison",
        artifact.get("path"),
        finding.get("rule_id"),
        finding.get("location"),
        evidence.get("token"),
    )


def _index_findings(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    artifacts = artifact_map(report)
    indexed: dict[str, dict[str, Any]] = {}
    occurrences: dict[str, int] = defaultdict(int)
    for finding in report.get("findings", []):
        semantic_key = _finding_key(report, finding)
        occurrences[semantic_key] += 1
        key = stable_id(
            "comparison-occurrence",
            semantic_key,
            occurrences[semantic_key],
        )
        artifact = artifacts.get(finding.get("artifact_id"), {})
        indexed[key] = {
            "rule_id": finding.get("rule_id"),
            "severity": finding.get("severity"),
            "path": artifact.get("path"),
            "location": finding.get("location"),
        }
    return indexed


def _applied_actions(actions: Iterable[dict[str, Any]] | None) -> dict[str, list[str]]:
    by_path: dict[str, list[str]] = defaultdict(list)
    for record in actions or ():
        path = record.get("path")
        action = record.get("action")
        if (
            record.get("status") == "applied"
            and isinstance(path, str)
            and action in _ACTION_MEDIA_TYPES
        ):
            by_path[path].append(action)
    return dict(by_path)


def _artifact_groups(report: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for artifact in report.get("artifacts", []):
        path = artifact.get("path")
        if isinstance(path, str):
            groups[path].append(artifact)
    return dict(groups)


def _artifact_signature(artifact: dict[str, Any]) -> tuple[object, object, object]:
    return (artifact.get("media_type"), artifact.get("content_token"), artifact.get("size"))


def _allowed_transform(
    path: str,
    before: dict[str, Any],
    after: dict[str, Any],
    actions: dict[str, list[str]],
) -> list[str]:
    before_type = before.get("media_type")
    if before_type != after.get("media_type"):
        return []
    return sorted(
        action
        for action in actions.get(path, ())
        if before_type in _ACTION_MEDIA_TYPES[action]
    )


def _receipt_groups(
    receipts: Iterable[TransformReceipt],
) -> dict[tuple[str, str], list[TransformReceipt]]:
    groups: dict[tuple[str, str], list[TransformReceipt]] = defaultdict(list)
    for receipt in receipts:
        groups[(receipt.relative_path, receipt.action_kind)].append(receipt)
    return dict(groups)


def _compare_artifacts(
    before: dict[str, Any],
    after: dict[str, Any],
    actions: Iterable[dict[str, Any]] | None,
) -> dict[str, Any]:
    receipts = trusted_receipts(actions)
    receipt_groups = _receipt_groups(receipts)
    before_artifacts = before.get("artifacts", [])
    after_artifacts = after.get("artifacts", [])
    before_groups = _artifact_groups(before)
    after_groups = _artifact_groups(after)
    action_records = list(actions or ())
    applied = _applied_actions(action_records)
    issues: list[dict[str, str]] = []
    allowed: list[dict[str, str]] = []
    unchanged = 0

    for record in action_records:
        status = record.get("status")
        if status not in {"unsupported", "skipped", "partial", "failed"}:
            continue
        path = record.get("path") if isinstance(record.get("path"), str) else "<artifact-set>"
        issues.append({
            "code": f"transform_{status}",
            "path": path,
            "detail": "A requested copy transformation was not fully applied and verified.",
        })

    if len(before_artifacts) != len(after_artifacts):
        issues.append({
            "code": "artifact_count_changed",
            "path": "<artifact-set>",
            "detail": "The prepared artifact count differs from the original scan.",
        })

    for path in sorted(set(before_groups) | set(after_groups)):
        left = before_groups.get(path, [])
        right = after_groups.get(path, [])
        if not left:
            issues.append({
                "code": "artifact_added",
                "path": path,
                "detail": "The prepared scan contains an artifact absent from the original scan.",
            })
            continue
        if not right:
            issues.append({
                "code": "artifact_removed",
                "path": path,
                "detail": "An original artifact is absent from the prepared scan.",
            })
            continue
        if len(left) != 1 or len(right) != 1:
            left_signatures = sorted(repr(_artifact_signature(item)) for item in left)
            right_signatures = sorted(repr(_artifact_signature(item)) for item in right)
            if left_signatures == right_signatures:
                unchanged += len(left)
            else:
                issues.append({
                    "code": "ambiguous_artifact_identity",
                    "path": path,
                    "detail": "Duplicate display paths prevent a one-to-one artifact comparison.",
                })
            continue

        original = left[0]
        prepared = right[0]
        if original.get("media_type") != prepared.get("media_type"):
            issues.append({
                "code": "artifact_type_changed",
                "path": path,
                "detail": "The prepared artifact has a different detected media type.",
            })
            continue
        if _artifact_signature(original) == _artifact_signature(prepared):
            unchanged += 1
            continue
        candidate_actions = _allowed_transform(path, original, prepared, applied)
        if len(candidate_actions) > 1:
            issues.append({
                "code": "transform_action_ambiguous",
                "path": path,
                "detail": "More than one applied transform record claims the same artifact change.",
            })
            continue
        if candidate_actions:
            action = candidate_actions[0]
            matching_receipts = receipt_groups.get((path, action), [])
            if not matching_receipts:
                issues.append({
                    "code": "transform_receipt_missing",
                    "path": path,
                    "detail": "An applied transform record has no core-issued byte-bound receipt.",
                })
                continue
            if len(matching_receipts) != 1:
                issues.append({
                    "code": "transform_receipt_ambiguous",
                    "path": path,
                    "detail": "Transform receipts do not identify exactly one operation for this artifact.",
                })
                continue
            receipt = matching_receipts[0]
            if receipt.status != "applied":
                issues.append({
                    "code": "transform_receipt_status_mismatch",
                    "path": path,
                    "detail": "The action record and its internal transform receipt disagree on status.",
                })
                continue
            receipt_failure = bind_and_validate_receipt(
                receipt,
                before_artifact=original,
                after_artifact=prepared,
            )
            if receipt_failure is not None:
                issues.append({
                    "code": receipt_failure,
                    "path": path,
                    "detail": "The transform receipt did not validate against exact scan snapshots and protected content.",
                })
                continue
            allowed.append({
                "path": path,
                "action": action,
                "media_type": str(original.get("media_type")),
            })
            continue
        issues.append({
            "code": "artifact_content_changed",
            "path": path,
            "detail": "Size or byte identity changed without a recorded supported metadata transformation.",
        })

    if issues:
        outcome = "unverified"
    elif allowed:
        outcome = "transformed"
    else:
        outcome = "preserved"
    return {
        "outcome": outcome,
        "artifacts_before": len(before_artifacts),
        "artifacts_after": len(after_artifacts),
        "unchanged": unchanged,
        "allowed_transforms": allowed,
        "issues": issues,
    }


def compare_reports(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    allowed_actions: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compare findings and fail closed on unexplained artifact changes.

    ``allowed_actions`` is reserved for transformation records emitted by the
    bundled sanitizer. A standalone verification has no trusted transform
    manifest, so any byte-identity or size change remains unverified.
    """

    before_findings = _index_findings(before)
    after_findings = _index_findings(after)
    before_keys = set(before_findings)
    after_keys = set(after_findings)
    resolved_keys = sorted(before_keys - after_keys)
    remaining_keys = sorted(before_keys & after_keys)
    introduced_keys = sorted(after_keys - before_keys)
    integrity = _compare_artifacts(before, after, allowed_actions)

    before_verdict = before.get("summary", {}).get("verdict")
    after_verdict = after.get("summary", {}).get("verdict")
    coverage_complete = (
        before_verdict in {"no_findings", "review", "block"}
        and after_verdict in {"no_findings", "review", "block"}
    )
    if not coverage_complete or integrity["outcome"] == "unverified":
        outcome = "incomplete"
    elif introduced_keys:
        outcome = "regressed"
    elif resolved_keys:
        outcome = "improved"
    else:
        outcome = "unchanged"
    ready_for_review = (
        coverage_complete
        and integrity["outcome"] != "unverified"
        and after_verdict == "no_findings"
        and not introduced_keys
    )
    if ready_for_review:
        statement = "No findings were observed within completed coverage; this is not a guarantee of safety."
    elif integrity["outcome"] == "unverified":
        statement = "Artifact deletion, replacement, or an unexplained content change prevents verification."
    else:
        statement = "Residual findings or coverage gaps require review before sharing."
    return {
        "outcome": outcome,
        "ready_for_review": ready_for_review,
        "statement": statement,
        "counts": {
            "resolved": len(resolved_keys),
            "remaining": len(remaining_keys),
            "introduced": len(introduced_keys),
        },
        "resolved": [before_findings[key] for key in resolved_keys],
        "remaining": [after_findings[key] for key in remaining_keys],
        "introduced": [after_findings[key] for key in introduced_keys],
        "integrity": integrity,
    }
