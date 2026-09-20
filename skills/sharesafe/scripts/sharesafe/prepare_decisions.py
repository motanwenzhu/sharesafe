"""Strict local decision input for building a ShareSafe prepare plan."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from .prepare_io import PrepareIOError, load_local_control_mapping

DECISIONS_SCHEMA = "sharesafe.prepare-decisions/v1"
LOCAL_CLASSIFICATION = "local_only_do_not_share"
SOURCE_BOUNDARY = "<selected-source>"
_TOP_FIELDS = {"schema", "classification", "source_boundary", "actions"}
_ACTION_FIELDS = {"source_path", "target_path", "action", "reason_code"}
_MAX_ACTIONS = 999_999


class PrepareDecisionError(ValueError):
    """Stable, non-sensitive rejection for a decision artifact."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code.replace("_", " "))


def decisions_from_mapping(value: Mapping[str, Any]) -> tuple[dict[str, object], ...]:
    if not isinstance(value, Mapping) or set(value) != _TOP_FIELDS:
        raise PrepareDecisionError("invalid_decisions_contract")
    if (
        value.get("schema") != DECISIONS_SCHEMA
        or value.get("classification") != LOCAL_CLASSIFICATION
        or value.get("source_boundary") != SOURCE_BOUNDARY
    ):
        raise PrepareDecisionError("invalid_decisions_contract")
    actions = value.get("actions")
    if not isinstance(actions, list) or not actions or len(actions) > _MAX_ACTIONS:
        raise PrepareDecisionError("invalid_decisions_actions")

    normalized: list[dict[str, object]] = []
    for item in actions:
        if not isinstance(item, Mapping) or set(item) != _ACTION_FIELDS:
            raise PrepareDecisionError("invalid_decision_record")
        source_path = item.get("source_path")
        target_path = item.get("target_path")
        action = item.get("action")
        reason_code = item.get("reason_code")
        if (
            not isinstance(source_path, str)
            or (target_path is not None and not isinstance(target_path, str))
            or not isinstance(action, str)
            or not isinstance(reason_code, str)
        ):
            raise PrepareDecisionError("invalid_decision_record")
        normalized.append(
            {
                "source_path": source_path,
                "target_path": target_path,
                "action": action,
                "reason_code": reason_code,
            }
        )
    return tuple(normalized)


def load_prepare_decisions_file(
    path: str | os.PathLike[str],
) -> tuple[dict[str, object], ...]:
    try:
        mapping = load_local_control_mapping(path)
    except PrepareIOError as exc:
        raise PrepareDecisionError(exc.code) from exc
    return decisions_from_mapping(mapping)


__all__ = [
    "DECISIONS_SCHEMA",
    "PrepareDecisionError",
    "decisions_from_mapping",
    "load_prepare_decisions_file",
]
