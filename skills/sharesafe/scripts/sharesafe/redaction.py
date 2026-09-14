"""Safe evidence rendering for ShareSafe findings.

The functions in this module deliberately accept sensitive values only as local
arguments.  They never cache them, and the returned strings are suitable for a
report or console display.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import unicodedata


_WINDOWS_HOME_RE = re.compile(
    r"(?i)(?P<prefix>(?<![A-Za-z0-9])(?:[A-Z]:[\\/]+(?:Users|Documents and Settings)[\\/]+))"
    r"(?P<user>[^\\/!:\x00-\x1f]+)"
)
_UNC_HOME_RE = re.compile(
    r"(?i)(?P<lead>(?<![A-Za-z0-9:/\\])[\\/]{2,})(?P<host>[^\\/!\s]+)"
    r"(?P<prefix>[\\/]+(?:Users|Documents and Settings)[\\/]+)"
    r"(?P<user>[^\\/!:\x00-\x1f]+)"
)
_UNC_HOST_RE = re.compile(
    r"(?P<lead>(?<![A-Za-z0-9:/\\])[\\/]{2,})(?P<host>[^\\/!\s]+)(?P<separator>[\\/]+)"
)
_WSL_WINDOWS_HOME_RE = re.compile(
    r"(?i)(?P<prefix>(?<![A-Za-z0-9:/])/+mnt/+[a-z]/+(?:Users|Documents and Settings)/+)"
    r"(?P<user>[^/!\x00-\x1f]+)"
)
_UNIX_HOME_RE = re.compile(
    r"(?P<prefix>(?<![A-Za-z0-9:/])/+(?:home|Users)/+)(?P<user>[^/!\x00-\x1f]+)"
)
_ROOT_HOME_RE = re.compile(r"(?<![A-Za-z0-9:/])/+root(?P<boundary>(?=/|!|$))")
_RELATIVE_HOME_RE = re.compile(
    r"(?i)(?P<prefix>(?<![A-Za-z0-9])(?:home|Users|Documents and Settings)[\\/]+)"
    r"(?P<user>[^\\/!:\x00-\x1f]+)"
)
_DISPLAY_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_USER_HOME_CONTAINERS = frozenset({"users", "home", "documents and settings"})


def temporary_hmac_key(length: int = 32) -> bytes:
    """Return an in-memory key for correlating evidence within one run.

    Callers should create one key per report and must not serialize the key.
    A minimum of 128 bits prevents accidental use of a weak human password.
    """

    if length < 16:
        raise ValueError("temporary HMAC keys must contain at least 16 bytes")
    return secrets.token_bytes(length)


def hmac_token(value: str, key: bytes | bytearray | memoryview) -> str:
    """Return a non-reversible, run-scoped token for a sensitive value."""

    if not isinstance(value, str):
        raise TypeError("value must be str")
    key_bytes = bytes(key)
    if len(key_bytes) < 16:
        raise ValueError("HMAC key must contain at least 16 bytes")
    message = b"sharesafe-evidence/v1\0" + value.encode("utf-8", "surrogatepass")
    digest = hmac.new(key_bytes, message, hashlib.sha256).hexdigest()
    return f"hmac-sha256:v1:{digest[:32]}"


def content_hmac_token(value: bytes | bytearray | memoryview, key: bytes | bytearray | memoryview) -> str:
    """Return a run-scoped token for byte-identity comparisons.

    A raw file digest can reveal low-entropy content by enumeration.  This
    domain-separated HMAC lets one scan run compare artifacts without placing
    an offline-guessable digest or the key in the report.
    """

    value_bytes = bytes(value)
    key_bytes = bytes(key)
    if len(key_bytes) < 16:
        raise ValueError("HMAC key must contain at least 16 bytes")
    digest_builder = hmac.new(key_bytes, b"sharesafe-content/v1\0", hashlib.sha256)
    digest_builder.update(value_bytes)
    digest = digest_builder.hexdigest()
    return f"hmac-sha256:content-v1:{digest[:32]}"


def _masked_tail(value: str, label: str, visible_digits: int = 4) -> str:
    digits = "".join(character for character in value if character.isascii() and character.isdigit())
    if not digits:
        return f"<{label}:redacted>"
    tail = digits[-visible_digits:]
    hidden_count = max(4, len(digits) - len(tail))
    return f"<{label}:{'*' * hidden_count}{tail}>"


def _mask_control_characters(value: str) -> str:
    codepoints = ",".join(f"U+{ord(character):04X}" for character in value)
    names = {
        unicodedata.name(character, "UNKNOWN")
        for character in value
        if len(value) == 1
    }
    suffix = f":{next(iter(names))}" if names else ""
    return f"<unicode-control:{codepoints}{suffix}>"


def mask_value(value: str, value_class: str) -> str:
    """Mask ``value`` according to its semantic class.

    No supported class returns the original value.  Secret-like classes expose
    no prefix or suffix; PII classes expose at most a few trailing digits.
    """

    if not isinstance(value, str):
        raise TypeError("value must be str")
    normalized_class = value_class.strip().lower().replace("-", "_")

    if normalized_class in {"secret", "credential", "private_key", "jwt"}:
        return f"<{normalized_class}:redacted>"
    if normalized_class == "email":
        return "<email:redacted>"
    if normalized_class in {"phone", "cn_mobile"}:
        return _masked_tail(value, "phone")
    if normalized_class in {"government_id", "cn_resident_id"}:
        return _masked_tail(value, "cn-id", visible_digits=2)
    if normalized_class in {"payment_card", "bank_card"}:
        return _masked_tail(value, "card")
    if normalized_class in {"unicode_control", "control_character"}:
        return _mask_control_characters(value)
    if normalized_class in {"path", "user_path"}:
        sanitized = sanitize_display_path(value)
        return sanitized if sanitized != value else "<path:redacted>"
    label = re.sub(r"[^a-z0-9_]+", "-", normalized_class).strip("-") or "value"
    return f"<{label}:redacted>"


def sanitize_display_path(path: str) -> str:
    """Remove user-identifying components and embedded PII from a display path.

    Both slash styles and ``!/`` archive boundaries are preserved so a finding
    remains locatable.  This function is display-only; its output must never be
    used to open a file.
    """

    if not isinstance(path, str):
        raise TypeError("path must be str")

    # Filesystem and archive labels are untrusted terminal content.  Make all
    # C0/C1 controls and DEL visible before applying any other masking so a
    # member name cannot forge report lines or emit terminal control sequences.
    sanitized = _DISPLAY_CONTROL_RE.sub(
        lambda match: _mask_control_characters(match.group(0)), path
    )
    sanitized = _UNC_HOME_RE.sub(
        lambda match: f"{match.group('lead')}<host>{match.group('prefix')}<user>",
        sanitized,
    )
    sanitized = _UNC_HOST_RE.sub(
        lambda match: f"{match.group('lead')}<host>{match.group('separator')}",
        sanitized,
    )
    sanitized = _WINDOWS_HOME_RE.sub(
        lambda match: f"{match.group('prefix')}<user>", sanitized
    )
    sanitized = _WSL_WINDOWS_HOME_RE.sub(
        lambda match: f"{match.group('prefix')}<user>", sanitized
    )
    sanitized = _UNIX_HOME_RE.sub(
        lambda match: f"{match.group('prefix')}<user>", sanitized
    )
    sanitized = _ROOT_HOME_RE.sub("/<user>", sanitized)
    sanitized = _RELATIVE_HOME_RE.sub(
        lambda match: f"{match.group('prefix')}<user>", sanitized
    )

    # Import lazily to keep detector definitions independent from report
    # rendering while still sharing validators for path-segment PII.
    from .detectors import detect_text

    candidates: list[tuple[object, int, int]] = []
    # Detect within individual path components. Several sensitive-value
    # grammars legitimately allow '/' in ordinary prose; running them across
    # a display path would let one match consume and erase the ``!/`` archive
    # boundary or neighboring components.
    for component in re.finditer(r"[^\\/]+", sanitized):
        component_text = component.group(0)
        for hit in detect_text(component_text):
            if hit.category in {"pii", "secret", "unicode_control"}:
                candidates.append(
                    (hit, component.start() + hit.start, component.start() + hit.end)
                )
    # Specific/high-confidence matches win if two detectors cover the same
    # filename characters.  Applying overlapping replacements independently
    # could otherwise splice part of a sensitive value back into the result.
    selected: list[tuple[object, int, int]] = []
    for hit, start, end in sorted(
        candidates,
        key=lambda item: (
            -item[0].confidence,
            -(item[2] - item[1]),
            item[1],
            item[0].rule_id,
        ),
    ):
        if any(start < existing_end and existing_start < end for _, existing_start, existing_end in selected):
            continue
        selected.append((hit, start, end))

    replacements: list[tuple[int, int, str]] = []
    for hit, start, end in selected:
        raw_value = sanitized[start:end]
        replacements.append(
            (start, end, mask_value(raw_value, hit.value_class))
        )
    for start, end, replacement in sorted(replacements, reverse=True):
        sanitized = sanitized[:start] + replacement + sanitized[end:]
    return sanitized


def user_home_container_context(path_name: str) -> str | None:
    """Return a relative detector prefix for a selected user-home container.

    Selecting ``C:/Users`` or ``/home`` removes the parent context that makes
    the first descendant recognizable as a username.  Callers can retain this
    non-secret basename as scan-only context without serializing an absolute
    path.
    """

    if not isinstance(path_name, str):
        raise TypeError("path_name must be str")
    normalized = path_name.replace("\\", "/").rstrip("/")
    component = normalized.rsplit("/", 1)[-1] if normalized else ""
    return component if component.casefold() in _USER_HOME_CONTAINERS else None


def contextual_relative_path(
    relative_path: str,
    context_prefix: str | None,
) -> tuple[str, str]:
    """Return ``(safe_display_path, raw_detector_path)`` for a relative path.

    ``context_prefix`` is a non-secret structural label such as ``Users`` or
    ``home``.  It is retained only while detecting and masking identity-bearing
    descendants, then removed again so the serialized path stays relative to
    the selected root.
    """

    if not isinstance(relative_path, str):
        raise TypeError("relative_path must be str")
    relative = relative_path.replace("\\", "/").lstrip("/")
    if not context_prefix:
        return sanitize_display_path(relative), relative

    context = context_prefix.replace("\\", "/").strip("/")
    detector_path = f"{context}/{relative}" if relative else context
    safe_detector_path = sanitize_display_path(detector_path)
    safe_context = sanitize_display_path(context).rstrip("/")
    removable_prefix = f"{safe_context}/"
    if relative and safe_detector_path.startswith(removable_prefix):
        return safe_detector_path[len(removable_prefix):], detector_path
    return safe_detector_path, detector_path


__all__ = [
    "contextual_relative_path",
    "content_hmac_token",
    "hmac_token",
    "mask_value",
    "sanitize_display_path",
    "temporary_hmac_key",
    "user_home_container_context",
]
