"""Strict, deterministic policy loading for ``sharesafe.policy/v1``.

Policies control the disposition of an unchanged scan report.  They never
disable detectors, remove findings, rewrite severities, or turn incomplete
coverage into a passing decision.
"""

from __future__ import annotations

import hashlib
import json
import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from pathlib import Path, PurePosixPath
from typing import Any

from .limits import Limits, parse_size
from .safe_io import (
    FileIdentityChangedError,
    open_verified_binary,
    verify_open_file_unchanged,
)

POLICY_SCHEMA = "sharesafe.policy/v1"
RULESET_VERSION = "sharesafe.rules/v1"
MAX_POLICY_BYTES = 1024 * 1024

FAIL_ON_VALUES = ("info", "low", "medium", "high", "critical", "never")
REQUIRED_CAPABILITY_VALUES = (
    "embedded_objects",
    "hidden_content",
    "metadata",
    "ocr",
    "text",
)

_TOP_LEVEL_FIELDS = {
    "schema",
    "fail_on",
    "limits",
    "required_capabilities",
    "blocking_categories",
    "optional_tools",
    "manifest",
}
_MANIFEST_FIELDS = {"enabled", "path", "require_exact"}
_CATEGORY_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._-")

# Bounds are part of the policy contract, not parser implementation details.
# They prevent a typo or hostile project file from silently removing resource
# protection.  The additional output bounds are present for v0.2's bounded
# reporting model and become active as soon as the matching Limits fields are
# available.
_LIMIT_BOUNDS: dict[str, tuple[int, int]] = {
    "max_file_bytes": (1, 4 * 1024**3),
    "max_total_file_bytes": (1, 64 * 1024**3),
    "max_files": (1, 1_000_000),
    "max_directory_depth": (0, 256),
    "max_text_bytes": (1, 1024**3),
    "max_findings_per_artifact": (1, 100_000),
    "max_findings_total": (1, 1_000_000),
    "max_archive_entries": (1, 1_000_000),
    "max_archive_member_bytes": (1, 4 * 1024**3),
    "max_expanded_bytes": (1, 64 * 1024**3),
    "max_compression_ratio": (1, 1_000_000),
    "max_archive_depth": (0, 20),
    "max_xml_bytes": (1, 1024**3),
    "max_pdf_pages": (1, 100_000),
    "max_name_bytes": (64, 1024**2),
    "max_display_path_chars": (256, 1024**2),
    "max_report_field_chars": (256, 1024**2),
    "max_gaps_total": (4, 100_000),
    "max_errors_total": (1, 10_000),
    "max_report_bytes": (8192, 1024**3),
}


class PolicyError(ValueError):
    """A stable, path-free policy loading or validation failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ManifestPolicy:
    """Settings for an explicitly selected input manifest."""

    enabled: bool = False
    path: str | None = None
    require_exact: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "path": self.path,
            "require_exact": self.require_exact,
        }


@dataclass(frozen=True, slots=True)
class Policy:
    """Normalized effective policy used to construct a check decision."""

    fail_on: str = "high"
    limits: Limits = field(default_factory=Limits)
    required_capabilities: tuple[str, ...] = ()
    blocking_categories: tuple[str, ...] = ()
    optional_tools: bool = True
    manifest: ManifestPolicy = field(default_factory=ManifestPolicy)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": POLICY_SCHEMA,
            "fail_on": self.fail_on,
            "limits": {
                name: getattr(self.limits, name)
                for name in sorted(_limit_field_names())
            },
            "required_capabilities": list(self.required_capabilities),
            "blocking_categories": list(self.blocking_categories),
            "optional_tools": self.optional_tools,
            "manifest": self.manifest.to_dict(),
        }

    @property
    def digest(self) -> str:
        return policy_digest(self)


def default_policy() -> Policy:
    """Return the built-in policy without consulting files or environment."""

    return Policy()


def normalize_policy(policy: Policy | Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical JSON-compatible effective policy."""

    normalized = (
        policy_from_mapping(policy.to_dict())
        if isinstance(policy, Policy)
        else policy_from_mapping(policy)
    )
    # Round-tripping through JSON also guarantees that callers cannot retain
    # references to mutable values inside the returned object.
    return json.loads(_canonical_json(normalized.to_dict()).decode("utf-8"))


def policy_digest(policy: Policy | Mapping[str, Any]) -> str:
    """Digest the full normalized policy using canonical UTF-8 JSON."""

    normalized = normalize_policy(policy)
    return f"sha256:{hashlib.sha256(_canonical_json(normalized)).hexdigest()}"


def policy_from_mapping(
    raw: Mapping[str, Any],
    *,
    base: Policy | None = None,
) -> Policy:
    """Validate and merge one explicit policy mapping over ``base``.

    The mapping may be a complete normalized policy or a TOML policy fragment.
    Any unknown key fails closed.  Lists are treated as sets and sorted so their
    semantically irrelevant source order cannot change the digest.
    """

    if not isinstance(raw, Mapping):
        raise PolicyError("policy_type", "Policy content must be a table/object.")
    if any(not isinstance(key, str) for key in raw):
        raise PolicyError("unknown_policy_field", "Policy contains an unsupported field.")
    if set(raw) - _TOP_LEVEL_FIELDS:
        raise PolicyError("unknown_policy_field", "Policy contains an unsupported field.")
    if "schema" in raw and raw["schema"] != POLICY_SCHEMA:
        raise PolicyError("unsupported_policy_schema", "Policy schema is missing or unsupported.")

    current = base or default_policy()
    fail_on = _enum_value(raw.get("fail_on", current.fail_on), FAIL_ON_VALUES, "fail_on")
    limits = _limits_from_mapping(raw.get("limits"), current.limits)
    required_capabilities = _string_set(
        raw.get("required_capabilities", current.required_capabilities),
        field_name="required_capabilities",
        allowed=frozenset(REQUIRED_CAPABILITY_VALUES),
    )
    blocking_categories = _category_set(
        raw.get("blocking_categories", current.blocking_categories)
    )
    optional_tools = _bool_value(
        raw.get("optional_tools", current.optional_tools), "optional_tools"
    )
    manifest = _manifest_from_mapping(raw.get("manifest"), current.manifest)
    return Policy(
        fail_on=fail_on,
        limits=limits,
        required_capabilities=required_capabilities,
        blocking_categories=blocking_categories,
        optional_tools=optional_tools,
        manifest=manifest,
    )


def merge_policy_overrides(policy: Policy, overrides: Mapping[str, Any]) -> Policy:
    """Apply an explicit, already-authorized override mapping."""

    return policy_from_mapping(overrides, base=policy)


def load_policy(path: str | os.PathLike[str], *, base: Policy | None = None) -> Policy:
    """Load one explicitly named UTF-8 TOML policy without environment lookup."""

    data = _read_policy_file(Path(path))
    try:
        text = data.decode("utf-8")
        raw = tomllib.loads(text)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PolicyError("invalid_policy_toml", "Policy is not valid UTF-8 TOML.") from exc
    return policy_from_mapping(raw, base=base)


def resolve_policy(
    *,
    project_config: str | os.PathLike[str] | None = None,
    explicit_config: str | os.PathLike[str] | None = None,
    overrides: Mapping[str, Any] | None = None,
) -> Policy:
    """Resolve defaults < project < explicit config < explicit overrides.

    Paths and overrides must be supplied by the caller.  This function never
    searches parent directories, user configuration, or environment variables.
    """

    policy = default_policy()
    if project_config is not None:
        policy = load_policy(project_config, base=policy)
    if explicit_config is not None:
        policy = load_policy(explicit_config, base=policy)
    if overrides:
        policy = merge_policy_overrides(policy, overrides)
    return policy


def _limit_field_names() -> frozenset[str]:
    return frozenset(item.name for item in fields(Limits))


def _limits_from_mapping(raw: Any, base: Limits) -> Limits:
    if raw is None:
        return base
    if not isinstance(raw, Mapping):
        raise PolicyError("limits_type", "Policy limits must be a table/object.")
    if any(not isinstance(key, str) for key in raw):
        raise PolicyError("unknown_limit", "Policy contains an unsupported limit.")
    allowed = _limit_field_names()
    if set(raw) - allowed:
        raise PolicyError("unknown_limit", "Policy contains an unsupported limit.")

    values = {name: getattr(base, name) for name in allowed}
    for name, value in raw.items():
        minimum, maximum = _LIMIT_BOUNDS.get(name, (1, 2**31 - 1))
        if isinstance(value, str) and name.endswith("_bytes"):
            try:
                value = parse_size(value)
            except ValueError as exc:
                raise PolicyError("invalid_limit", f"Policy limit {name} is invalid.") from exc
        if isinstance(value, bool) or not isinstance(value, int):
            raise PolicyError("invalid_limit", f"Policy limit {name} is invalid.")
        if value < minimum or value > maximum:
            raise PolicyError("limit_out_of_range", f"Policy limit {name} is outside its supported range.")
        values[name] = value
    try:
        return Limits(**values)
    except (TypeError, ValueError) as exc:
        raise PolicyError("invalid_limit", "Policy limits could not be applied.") from exc


def _manifest_from_mapping(raw: Any, base: ManifestPolicy) -> ManifestPolicy:
    if raw is None:
        return base
    if not isinstance(raw, Mapping):
        raise PolicyError("manifest_type", "Policy manifest settings must be a table/object.")
    if any(not isinstance(key, str) for key in raw) or set(raw) - _MANIFEST_FIELDS:
        raise PolicyError("unknown_manifest_field", "Policy manifest contains an unsupported field.")

    enabled = _bool_value(raw.get("enabled", base.enabled), "manifest.enabled")
    require_exact = _bool_value(
        raw.get("require_exact", base.require_exact), "manifest.require_exact"
    )
    if "path" in raw:
        path = raw["path"]
    elif "enabled" in raw and not enabled:
        # TOML has no null literal.  An explicit disable therefore also clears
        # an inherited path without requiring a magic sentinel value.
        path = None
    else:
        path = base.path
    if path is not None:
        path = _manifest_path(path)
    if enabled and path is None:
        raise PolicyError("manifest_path_required", "An enabled manifest requires an explicit relative path.")
    if not enabled and path is not None:
        raise PolicyError("manifest_disabled_with_path", "A disabled manifest cannot name a path.")
    return ManifestPolicy(enabled=enabled, path=path, require_exact=require_exact)


def _manifest_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096:
        raise PolicyError("invalid_manifest_path", "Manifest path is invalid.")
    if "\\" in value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise PolicyError("invalid_manifest_path", "Manifest path is invalid.")
    if "$" in value or "%" in value:
        raise PolicyError("implicit_environment_path", "Manifest path must not use environment expansion.")
    if any(character in value for character in "*?[]{}"):
        raise PolicyError("invalid_manifest_path", "Manifest path must not contain a glob pattern.")
    pure = PurePosixPath(value)
    if pure.is_absolute() or ":" in pure.parts[0] or any(part in {"", ".", ".."} for part in pure.parts):
        raise PolicyError("invalid_manifest_path", "Manifest path must be a normalized relative path.")
    normalized = pure.as_posix()
    if normalized != value:
        raise PolicyError("invalid_manifest_path", "Manifest path must be a normalized relative path.")
    return normalized


def _string_set(value: Any, *, field_name: str, allowed: frozenset[str]) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise PolicyError("invalid_policy_list", f"Policy field {field_name} must be a list.")
    if any(not isinstance(item, str) or item not in allowed for item in value):
        raise PolicyError("invalid_policy_value", f"Policy field {field_name} contains an invalid value.")
    if len(set(value)) != len(value):
        raise PolicyError("duplicate_policy_value", f"Policy field {field_name} contains a duplicate value.")
    return tuple(sorted(value))


def _category_set(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise PolicyError("invalid_policy_list", "Policy field blocking_categories must be a list.")
    for category in value:
        if (
            not isinstance(category, str)
            or not 1 <= len(category) <= 64
            or category[0] not in "abcdefghijklmnopqrstuvwxyz"
            or category[-1] in "._-"
            or any(character not in _CATEGORY_CHARS for character in category)
            or any(marker in category for marker in ("..", "__", "--", "._", ".-", "_.", "_-", "-.", "-_"))
        ):
            raise PolicyError("invalid_policy_value", "Policy contains an invalid blocking category.")
    if len(set(value)) != len(value):
        raise PolicyError("duplicate_policy_value", "Policy contains a duplicate blocking category.")
    return tuple(sorted(value))


def _enum_value(value: Any, allowed: tuple[str, ...], field_name: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise PolicyError("invalid_policy_value", f"Policy field {field_name} is invalid.")
    return value


def _bool_value(value: Any, field_name: str) -> bool:
    if type(value) is not bool:
        raise PolicyError("invalid_policy_value", f"Policy field {field_name} must be boolean.")
    return value


def _read_policy_file(path: Path) -> bytes:
    try:
        before = path.lstat()
        if before.st_size > MAX_POLICY_BYTES:
            raise PolicyError("policy_too_large", "Policy exceeds the supported size limit.")
        handle, opened = open_verified_binary(path, expected=before)
        with handle:
            data = handle.read(MAX_POLICY_BYTES + 1)
            unchanged = verify_open_file_unchanged(handle, path, opened=opened)
    except PolicyError:
        raise
    except FileIdentityChangedError as exc:
        raise PolicyError(
            "policy_changed_during_read", "Policy changed while it was being read."
        ) from exc
    except OSError as exc:
        raise PolicyError("policy_unavailable", "Policy file could not be read.") from exc

    if not unchanged:
        raise PolicyError("policy_changed_during_read", "Policy changed while it was being read.")
    if len(data) > MAX_POLICY_BYTES:
        raise PolicyError("policy_too_large", "Policy exceeds the supported size limit.")
    return data


def _canonical_json(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
