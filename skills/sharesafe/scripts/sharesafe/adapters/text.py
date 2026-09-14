"""Text decoding and deterministic detector dispatch."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..detectors import detect_text, hit_to_dict
from ..sniff import decode_text

if TYPE_CHECKING:
    from ..models import Artifact, ReportBuilder


def scan_text(
    data: bytes,
    artifact: "Artifact",
    builder: "ReportBuilder",
    *,
    evidence_key: bytes,
    part: str | None = None,
) -> bool:
    text, encoding = decode_text(data)
    if text is None:
        builder.add_gap(artifact, "text", "unsupported_encoding", "Text-like bytes could not be decoded conservatively.")
        return False

    artifact.set_coverage("text", "complete")
    # Ask for one result beyond the retained capacity so the report builder can
    # distinguish an exact fit from actual truncation without materializing an
    # unbounded hit list. Hits are ordered by source offset.
    capacity = builder.remaining_finding_capacity(artifact)
    hits = detect_text(text, max_hits=capacity + 1)
    line = 1
    line_start = 0
    newline_cursor = 0
    for hit in hits:
        while True:
            newline = text.find("\n", newline_cursor, hit.start)
            if newline < 0:
                break
            line += 1
            line_start = newline + 1
            newline_cursor = newline + 1
        newline_cursor = max(newline_cursor, hit.start)
        column = hit.start - line_start + 1
        location: dict[str, object] = {"kind": "text", "line": line, "column": column, "encoding": encoding}
        if part:
            location = {"kind": "container_part", "part": part, "line": line, "column": column}
        builder.add_finding(
            artifact,
            rule_id=hit.rule_id,
            category=hit.category,
            severity=hit.severity,
            confidence=hit.confidence,
            title=hit.title,
            location=location,
            evidence=hit_to_dict(hit, text, evidence_key),
            remediation_supported=False,
            remediation_action="review_and_redact_source_content",
        )
    return True
