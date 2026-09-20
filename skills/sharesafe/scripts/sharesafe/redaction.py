"""Safe evidence rendering for ShareSafe findings.

The functions in this module deliberately accept sensitive values only as local
arguments.  They never cache them, and the returned strings are suitable for a
report or console display.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import re
import secrets
import unicodedata

from .limits import DEFAULT_MAX_DISPLAY_PATH_CHARS, DEFAULT_MAX_NAME_BYTES


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
_PATH_COMPONENT_RE = re.compile(r"[^\\/]+")
_USER_HOME_CONTAINERS = frozenset({"users", "home", "documents and settings"})
NAME_LIMIT_PLACEHOLDER = "<name:omitted-limit>"
DISPLAY_PATH_LIMIT_PLACEHOLDER = "<path:omitted-limit>"


@dataclass(frozen=True, slots=True)
class DisplayPathResult:
    """A display-only path plus any fail-closed resource-limit reasons."""

    value: str
    limit_reasons: tuple[str, ...] = ()


def _utf8_size_exceeds(value: str, limit: int) -> bool:
    """Check a UTF-8 byte bound without allocating an encoded copy."""

    total = 0
    for character in value:
        codepoint = ord(character)
        if codepoint <= 0x7F:
            total += 1
        elif codepoint <= 0x7FF:
            total += 2
        elif codepoint <= 0xFFFF:
            # This also matches ``surrogatepass`` for filesystem surrogate
            # escapes, which must never make report generation fail open.
            total += 3
        else:
            total += 4
        if total > limit:
            return True
    return False


def path_limit_reasons(
    path: str,
    *,
    max_name_bytes: int = DEFAULT_MAX_NAME_BYTES,
    max_display_path_chars: int = DEFAULT_MAX_DISPLAY_PATH_CHARS,
) -> tuple[str, ...]:
    """Return deterministic reasons that make a raw path unsafe to process fully."""

    if not isinstance(path, str):
        raise TypeError("path must be str")
    if max_name_bytes <= 0 or max_display_path_chars <= 0:
        raise ValueError("path limits must be greater than zero")

    reasons: list[str] = []
    components = _PATH_COMPONENT_RE.finditer(path)
    if any(
        component.group(0) == NAME_LIMIT_PLACEHOLDER
        or _utf8_size_exceeds(component.group(0), max_name_bytes)
        for component in components
    ):
        reasons.append("name_limit")
    if path == DISPLAY_PATH_LIMIT_PLACEHOLDER or len(path) > max_display_path_chars:
        reasons.append("display_path_limit")
    return tuple(reasons)


def _replace_oversized_components(path: str, max_name_bytes: int) -> tuple[str, bool]:
    pieces: list[str] = []
    cursor = 0
    limited = False
    for component in _PATH_COMPONENT_RE.finditer(path):
        pieces.append(path[cursor : component.start()])
        value = component.group(0)
        if value == NAME_LIMIT_PLACEHOLDER or _utf8_size_exceeds(value, max_name_bytes):
            pieces.append(NAME_LIMIT_PLACEHOLDER)
            limited = True
        else:
            pieces.append(value)
        cursor = component.end()
    pieces.append(path[cursor:])
    return "".join(pieces), limited


def _mask_controls_bounded(value: str, limit: int) -> str | None:
    """Expand terminal controls only while the output remains within ``limit``."""

    pieces: list[str] = []
    cursor = 0
    total = 0
    for match in _DISPLAY_CONTROL_RE.finditer(value):
        literal = value[cursor : match.start()]
        replacement = _mask_control_characters(match.group(0))
        total += len(literal) + len(replacement)
        if total > limit:
            return None
        pieces.extend((literal, replacement))
        cursor = match.end()
    tail = value[cursor:]
    if total + len(tail) > limit:
        return None
    pieces.append(tail)
    return "".join(pieces)


class _FenwickOccupancy:
    """Range occupancy for priority-ordered intervals in O(log n) per query."""

    def __init__(self, size: int) -> None:
        self._tree = [0] * (size + 1)

    def _prefix(self, end: int) -> int:
        total = 0
        index = end
        while index > 0:
            total += self._tree[index]
            index -= index & -index
        return total

    def occupied(self, start: int, end: int) -> bool:
        return self._prefix(end) != self._prefix(start)

    def mark(self, index: int) -> None:
        cursor = index + 1
        while cursor < len(self._tree):
            self._tree[cursor] += 1
            cursor += cursor & -cursor


def _select_non_overlapping(
    candidates: list[tuple[object, int, int]],
) -> list[tuple[object, int, int]]:
    """Apply the existing confidence/length priority without quadratic scans.

    Accepted intervals are disjoint, so each elementary coordinate segment is
    marked at most once.  Sorting dominates the total O(n log n) work.
    """

    if not candidates:
        return []
    boundaries = sorted({position for _, start, end in candidates for position in (start, end)})
    coordinate = {position: index for index, position in enumerate(boundaries)}
    occupancy = _FenwickOccupancy(max(0, len(boundaries) - 1))
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
        left = coordinate[start]
        right = coordinate[end]
        if left >= right or occupancy.occupied(left, right):
            continue
        selected.append((hit, start, end))
        # No accepted interval overlaps another accepted interval.  Across the
        # full algorithm, each segment therefore incurs at most one update.
        for segment in range(left, right):
            occupancy.mark(segment)
    return selected


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


def sanitize_display_path_result(
    path: str,
    *,
    max_name_bytes: int = DEFAULT_MAX_NAME_BYTES,
    max_display_path_chars: int = DEFAULT_MAX_DISPLAY_PATH_CHARS,
) -> DisplayPathResult:
    """Return a bounded, masked display path and explicit limit reasons.

    Both slash styles and ``!/`` archive boundaries are preserved when they fit
    the display budget.  A limit never produces a raw prefix: overlong names are
    replaced as whole components and an overlong final path becomes one fixed
    placeholder.
    """

    if not isinstance(path, str):
        raise TypeError("path must be str")
    if max_name_bytes <= 0 or max_display_path_chars <= 0:
        raise ValueError("path limits must be greater than zero")

    initial_reasons = path_limit_reasons(
        path,
        max_name_bytes=max_name_bytes,
        max_display_path_chars=max_display_path_chars,
    )
    if "display_path_limit" in initial_reasons:
        return DisplayPathResult(DISPLAY_PATH_LIMIT_PLACEHOLDER, initial_reasons)

    sanitized, name_limited = _replace_oversized_components(path, max_name_bytes)
    reasons: list[str] = ["name_limit"] if name_limited else []

    # Filesystem and archive labels are untrusted terminal content.  Make all
    # C0/C1 controls and DEL visible before applying any other masking so a
    # member name cannot forge report lines or emit terminal control sequences.
    controls_masked = _mask_controls_bounded(sanitized, max_display_path_chars)
    if controls_masked is None:
        return DisplayPathResult(
            DISPLAY_PATH_LIMIT_PLACEHOLDER,
            tuple((*reasons, "display_path_limit")),
        )
    sanitized = controls_masked
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
    if len(sanitized) > max_display_path_chars:
        return DisplayPathResult(
            DISPLAY_PATH_LIMIT_PLACEHOLDER,
            tuple((*reasons, "display_path_limit")),
        )

    # Import lazily to keep detector definitions independent from report
    # rendering while still sharing validators for path-segment PII.
    from .detectors import detect_text

    candidates: list[tuple[object, int, int]] = []
    # Detect within individual path components. Several sensitive-value
    # grammars legitimately allow '/' in ordinary prose; running them across
    # a display path would let one match consume and erase the ``!/`` archive
    # boundary or neighboring components.
    for component in _PATH_COMPONENT_RE.finditer(sanitized):
        component_text = component.group(0)
        for hit in detect_text(component_text):
            if hit.category in {"pii", "secret", "unicode_control"}:
                candidates.append(
                    (hit, component.start() + hit.start, component.start() + hit.end)
                )
    # Specific/high-confidence matches win if two detectors cover the same
    # filename characters.  Applying overlapping replacements independently
    # could otherwise splice part of a sensitive value back into the result.
    selected = sorted(_select_non_overlapping(candidates), key=lambda item: item[1])
    pieces: list[str] = []
    cursor = 0
    output_chars = 0
    for hit, start, end in selected:
        literal = sanitized[cursor:start]
        replacement = mask_value(sanitized[start:end], hit.value_class)
        output_chars += len(literal) + len(replacement)
        if output_chars > max_display_path_chars:
            return DisplayPathResult(
                DISPLAY_PATH_LIMIT_PLACEHOLDER,
                tuple((*reasons, "display_path_limit")),
            )
        pieces.extend((literal, replacement))
        cursor = end
    tail = sanitized[cursor:]
    if output_chars + len(tail) > max_display_path_chars:
        return DisplayPathResult(
            DISPLAY_PATH_LIMIT_PLACEHOLDER,
            tuple((*reasons, "display_path_limit")),
        )
    pieces.append(tail)
    return DisplayPathResult("".join(pieces), tuple(reasons))


def sanitize_display_path(
    path: str,
    *,
    max_name_bytes: int = DEFAULT_MAX_NAME_BYTES,
    max_display_path_chars: int = DEFAULT_MAX_DISPLAY_PATH_CHARS,
) -> str:
    """Return only the display value from :func:`sanitize_display_path_result`.

    This compatibility wrapper is display-only; its output must never be used
    to open a file.  Report construction uses the structured result so a limit
    also becomes an explicit coverage gap.
    """

    return sanitize_display_path_result(
        path,
        max_name_bytes=max_name_bytes,
        max_display_path_chars=max_display_path_chars,
    ).value


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
    "DISPLAY_PATH_LIMIT_PLACEHOLDER",
    "DisplayPathResult",
    "NAME_LIMIT_PLACEHOLDER",
    "contextual_relative_path",
    "content_hmac_token",
    "hmac_token",
    "mask_value",
    "path_limit_reasons",
    "sanitize_display_path",
    "sanitize_display_path_result",
    "temporary_hmac_key",
    "user_home_container_context",
]
