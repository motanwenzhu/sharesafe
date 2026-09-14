"""Report models and the only supported report builder."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import secrets
from typing import Any, Iterable

from . import __version__
from .limits import Limits


SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
COVERAGE_VALUES = {"complete", "partial", "unsupported", "not_applicable"}


def stable_id(prefix: str, *parts: Any) -> str:
    encoded = json.dumps(parts, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:20]}"


@dataclass(slots=True)
class Artifact:
    id: str
    path: str
    content_token: str | None
    size: int | None
    media_type: str
    status: str = "scanned"
    coverage: dict[str, str] = field(default_factory=lambda: {
        "metadata": "not_applicable",
        "text": "not_applicable",
        "hidden_content": "not_applicable",
        "embedded_objects": "not_applicable",
        "ocr": "not_applicable",
    })

    def set_coverage(self, capability: str, value: str) -> None:
        if value not in COVERAGE_VALUES:
            raise ValueError(f"invalid coverage value: {value}")
        current = self.coverage.get(capability, "not_applicable")
        ordering = {"complete": 0, "not_applicable": 0, "partial": 1, "unsupported": 2}
        if capability not in self.coverage or ordering[value] >= ordering[current]:
            self.coverage[capability] = value
        if value in {"partial", "unsupported"}:
            self.status = "partial"


@dataclass(slots=True)
class Finding:
    id: str
    artifact_id: str
    rule_id: str
    category: str
    severity: str
    confidence: float
    title: str
    location: dict[str, Any]
    evidence: dict[str, Any]
    remediation: dict[str, Any]


@dataclass(slots=True)
class Gap:
    id: str
    artifact_id: str | None
    capability: str
    reason: str
    detail: str


@dataclass(slots=True)
class ReportBuilder:
    limits: Limits
    report_mode: str = "shareable"
    artifacts: list[Artifact] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    dependencies: list[dict[str, Any]] = field(default_factory=list)
    run_id: str = field(default_factory=lambda: f"run-{secrets.token_hex(8)}")
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    _finding_counts_by_artifact: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _artifact_occurrences_by_path: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _finding_occurrences: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _gaps_by_id: dict[str, Gap] = field(default_factory=dict, init=False, repr=False)
    _finding_limit_artifacts: set[str] = field(default_factory=set, init=False, repr=False)
    _global_finding_limit_reported: bool = field(default=False, init=False, repr=False)

    def add_artifact(
        self,
        *,
        path: str,
        content_token: str | None,
        size: int | None,
        media_type: str,
        status: str = "scanned",
    ) -> Artifact:
        occurrence = self._artifact_occurrences_by_path.get(path, 0) + 1
        self._artifact_occurrences_by_path[path] = occurrence
        artifact = Artifact(
            id=stable_id("a", path, media_type, occurrence),
            path=path,
            content_token=content_token,
            size=size,
            media_type=media_type,
            status=status,
        )
        self.artifacts.append(artifact)
        return artifact

    def add_finding(
        self,
        artifact: Artifact,
        *,
        rule_id: str,
        category: str,
        severity: str,
        confidence: float,
        title: str,
        location: dict[str, Any] | None = None,
        evidence: dict[str, Any] | None = None,
        remediation_supported: bool = False,
        remediation_action: str = "manual_review",
    ) -> Finding | None:
        if severity not in SEVERITY_RANK:
            raise ValueError(f"invalid severity: {severity}")
        artifact_count = self._finding_counts_by_artifact.get(artifact.id, 0)
        artifact_limit_reached = artifact_count >= self.limits.max_findings_per_artifact
        global_limit_reached = len(self.findings) >= self.limits.max_findings_total
        if artifact_limit_reached or global_limit_reached:
            if artifact_limit_reached and artifact.id not in self._finding_limit_artifacts:
                self._finding_limit_artifacts.add(artifact.id)
                self.add_gap(
                    artifact,
                    "findings",
                    "artifact_finding_limit",
                    "Additional findings for this artifact were omitted at the configured limit.",
                )
            if global_limit_reached and not self._global_finding_limit_reported:
                self._global_finding_limit_reported = True
                self.add_gap(
                    None,
                    "findings",
                    "global_finding_limit",
                    "Additional findings for the scan were omitted at the configured global limit.",
                )
            return None
        location = location or {"kind": "artifact"}
        evidence = evidence or {"mode": "omitted"}
        occurrence_key = stable_id("fo", artifact.id, rule_id, location)
        occurrence = self._finding_occurrences.get(occurrence_key, 0) + 1
        self._finding_occurrences[occurrence_key] = occurrence
        finding = Finding(
            id=stable_id("f", artifact.id, rule_id, location, occurrence),
            artifact_id=artifact.id,
            rule_id=rule_id,
            category=category,
            severity=severity,
            confidence=round(max(0.0, min(1.0, confidence)), 3),
            title=title,
            location=location,
            evidence=evidence,
            remediation={"supported": remediation_supported, "action": remediation_action},
        )
        self.findings.append(finding)
        self._finding_counts_by_artifact[artifact.id] = artifact_count + 1
        return finding

    def remaining_finding_capacity(self, artifact: Artifact) -> int:
        """Return how many more findings can be retained for ``artifact``."""

        artifact_remaining = self.limits.max_findings_per_artifact - self._finding_counts_by_artifact.get(
            artifact.id, 0
        )
        global_remaining = self.limits.max_findings_total - len(self.findings)
        return max(0, min(artifact_remaining, global_remaining))

    def add_gap(self, artifact: Artifact | None, capability: str, reason: str, detail: str) -> Gap:
        if artifact is not None:
            artifact.set_coverage(capability, "unsupported" if reason == "unsupported_format" else "partial")
        gap_id = stable_id("g", artifact.id if artifact else None, capability, reason, detail)
        existing = self._gaps_by_id.get(gap_id)
        if existing is not None:
            return existing
        gap = Gap(
            id=gap_id,
            artifact_id=artifact.id if artifact else None,
            capability=capability,
            reason=reason,
            detail=detail,
        )
        self.gaps.append(gap)
        self._gaps_by_id[gap_id] = gap
        return gap

    def add_error(self, code: str, message: str) -> None:
        self.errors.append({"code": code, "message": message})

    def add_dependency(self, name: str, available: bool, version: str | None, capability: str) -> None:
        record = {
            "name": name,
            "available": available,
            "version": version,
            "capability": capability,
        }
        if record not in self.dependencies:
            self.dependencies.append(record)

    def verdict(self) -> str:
        if self.gaps or self.errors or any(a.status == "partial" for a in self.artifacts):
            return "incomplete"
        if any(f.severity in {"high", "critical"} for f in self.findings):
            return "block"
        if self.findings:
            return "review"
        return "no_findings"

    def severity_counts(self) -> dict[str, int]:
        return {severity: sum(1 for finding in self.findings if finding.severity == severity) for severity in SEVERITIES}

    def to_dict(self) -> dict[str, Any]:
        complete = sum(1 for artifact in self.artifacts if artifact.status == "scanned")
        return {
            "schema": "sharesafe.report/v1",
            "tool": {"name": "sharesafe", "version": __version__},
            "run": {
                "id": self.run_id,
                "started_at": self.started_at,
                "offline": True,
                "report_mode": self.report_mode,
                "limits": self.limits.to_dict(),
            },
            "summary": {
                "verdict": self.verdict(),
                "artifacts_total": len(self.artifacts),
                "artifacts_complete": complete,
                "artifacts_partial": len(self.artifacts) - complete,
                "findings": self.severity_counts(),
                "gaps": len(self.gaps),
                "errors": len(self.errors),
            },
            "artifacts": [asdict(item) for item in self.artifacts],
            "findings": [asdict(item) for item in self.findings],
            "gaps": [asdict(item) for item in self.gaps],
            "errors": list(self.errors),
            "dependencies": sorted(self.dependencies, key=lambda item: item["name"]),
        }

    def exit_code(self, fail_on: str = "high") -> int:
        if fail_on not in SEVERITY_RANK and fail_on != "never":
            raise ValueError(f"invalid fail-on severity: {fail_on}")
        if self.gaps or self.errors or any(a.status == "partial" for a in self.artifacts):
            return 2
        if fail_on == "never":
            return 0
        threshold = SEVERITY_RANK[fail_on]
        return 1 if any(SEVERITY_RANK[f.severity] >= threshold for f in self.findings) else 0


def artifact_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in report.get("artifacts", [])}


def finding_semantic_keys(report: dict[str, Any]) -> set[str]:
    artifacts = artifact_map(report)
    keys: set[str] = set()
    for finding in report.get("findings", []):
        artifact = artifacts.get(finding["artifact_id"], {})
        payload = (
            artifact.get("path"),
            finding.get("rule_id"),
            finding.get("location"),
            finding.get("evidence", {}).get("token"),
        )
        keys.add(stable_id("k", *payload))
    return keys


def max_severity(findings: Iterable[dict[str, Any]]) -> str | None:
    values = [item.get("severity") for item in findings if item.get("severity") in SEVERITY_RANK]
    return max(values, key=SEVERITY_RANK.__getitem__) if values else None
