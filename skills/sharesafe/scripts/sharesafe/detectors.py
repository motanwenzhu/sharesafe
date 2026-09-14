"""Deterministic text detectors used by ShareSafe.

Detector hits intentionally contain offsets, classifications, and rule metadata
only.  The sensitive source slice is never retained on a hit object.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
from dataclasses import asdict, dataclass
from collections.abc import Callable
from typing import Final

from .redaction import hmac_token, mask_value, sanitize_display_path, temporary_hmac_key


RULESET_VERSION: Final = "sharesafe.rules/v1"
SEVERITIES: Final = frozenset({"low", "medium", "high", "critical"})


@dataclass(frozen=True, slots=True)
class DetectorHit:
    """A source location and safe classification for a sensitive value.

    ``start`` and ``end`` are Python string (Unicode code-point) offsets.  Raw
    evidence is deliberately absent, so ``dataclasses.asdict`` is safe.
    """

    rule_id: str
    category: str
    severity: str
    confidence: float
    title: str
    start: int
    end: int
    value_class: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_.-]*", self.rule_id):
            raise ValueError(f"invalid rule_id: {self.rule_id!r}")
        if not re.fullmatch(r"[a-z][a-z0-9_]*", self.category):
            raise ValueError(f"invalid category: {self.category!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity!r}")
        if (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, (int, float))
            or not 0.0 <= self.confidence <= 1.0
        ):
            raise ValueError("confidence must be a number from 0.0 through 1.0")
        if not self.title:
            raise ValueError("title must not be empty")
        if self.start < 0 or self.end <= self.start:
            raise ValueError("hit offsets must describe a non-empty source slice")
        if not re.fullmatch(r"[a-z][a-z0-9_]*", self.value_class):
            raise ValueError(f"invalid value_class: {self.value_class!r}")

    def to_dict(self) -> dict[str, object]:
        """Return the stable, raw-evidence-free intermediate representation."""

        return asdict(self)


@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    category: str
    severity: str
    confidence: float
    title: str
    value_class: str
    pattern: re.Pattern[str]
    group: str | int = 0
    validator: Callable[[str], bool] | None = None


_EMAIL_RE = re.compile(
    r"(?i)(?<![A-Z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}"
    r"@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?){1,10}"
    r"(?![A-Z0-9-])"
)
_CN_MOBILE_RE = re.compile(
    r"(?<![0-9])(?:\+?86[ -]?)?1[3-9][0-9](?:[ -]?[0-9]){8}(?![0-9])"
)
_CN_RESIDENT_ID_RE = re.compile(
    r"(?<![0-9A-Za-z])"
    r"[1-9][0-9]{5}(?:18|19|20)[0-9]{2}"
    r"(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])"
    r"[0-9]{3}[0-9Xx]"
    r"(?![0-9A-Za-z])"
)
_BANK_CARD_RE = re.compile(r"(?<![0-9])(?:[0-9][ -]?){12,18}[0-9](?![0-9])")
_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?P<label>(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----"
    r"[\s\S]{16,131072}?"
    r"-----END (?P=label)-----"
)
_AWS_ACCESS_KEY_RE = re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")
_GITHUB_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{70,255})"
    r"(?![A-Za-z0-9_])"
)
_OPENAI_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_-])sk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,512}"
    r"(?![A-Za-z0-9_-])"
)
_SLACK_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9-])xox[baprs]-[A-Za-z0-9-]{10,512}(?![A-Za-z0-9-])"
)
_GOOGLE_API_KEY_RE = re.compile(r"(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])")
_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,4093}\."
    r"[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,4096}(?![A-Za-z0-9_-])"
)
_AWS_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?ix)[\"']?aws_secret_access_key[\"']?\s*(?:=|:)\s*"
    r"(?:\"(?P<double>[A-Za-z0-9/+=]{40})\"|"
    r"'(?P<single>[A-Za-z0-9/+=]{40})'|"
    r"(?P<bare>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=]))"
)
_GENERIC_CREDENTIAL_RE = re.compile(
    r"(?ix)[\"']?\b(?:password|passwd|pwd|secret|token|api[-_]?key|"
    r"access[-_]?key|client[-_]?secret|auth[-_]?token)\b[\"']?"
    r"[ \t]*(?P<operator>=|:)[ \t]*"
    r"(?:\"(?P<double>[^\"\r\n]{4,256})\"|"
    r"'(?P<single>[^'\r\n]{4,256})'|"
    r"(?P<bare>[^\s,;#\"']{4,256}))"
)
_WINDOWS_USER_PATH_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9:])(?:"
    r"[A-Z]:[\\/]+(?:Users|Documents and Settings)[\\/]+"
    r"|[\\/]{2,}[^\\/\s!]+[\\/]+(?:Users|Documents and Settings)[\\/]+"
    r"|(?:Users|Documents and Settings)[\\/]+"
    r")[^\\/\s!\"'<>|:]+(?:[\\/][^\\/\s!\"'<>|:]+)*"
)
_UNIX_USER_PATH_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9:/])(?:"
    r"/+(?:home|Users)/+[^/\s!\"'<>]+(?:/+[^/\s!\"'<>]+)*"
    r"|/+root(?:/+[^/\s!\"'<>]+)+"
    r"|/+mnt/+[a-z]/+(?:Users|Documents and Settings)/+[^/\s!\"'<>]+"
    r"(?:/+[^/\s!\"'<>]+)*"
    r"|home/+[^/\s!\"'<>]+(?:/+[^/\s!\"'<>]+)*"
    r")"
)
_BIDI_CONTROL_RE = re.compile(r"[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_ZERO_WIDTH_RE = re.compile(r"[\u00ad\u200b-\u200d\u2060\ufeff]")


def _is_valid_cn_mobile(value: str) -> bool:
    digits = re.sub(r"[ +\-]", "", value)
    if digits.startswith("86"):
        digits = digits[2:]
    return len(digits) == 11 and digits.startswith("1") and digits[1] in "3456789"


def _is_valid_cn_resident_id(value: str) -> bool:
    candidate = value.upper()
    if len(candidate) != 18 or not candidate[:17].isdigit():
        return False
    try:
        year = int(candidate[6:10])
        month = int(candidate[10:12])
        day = int(candidate[12:14])
        # Importing datetime at module load is needless work for most scans.
        from datetime import date

        date(year, month, day)
    except ValueError:
        return False
    weights = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    checksum_chars = "10X98765432"
    checksum = checksum_chars[sum(int(digit) * weight for digit, weight in zip(candidate[:17], weights)) % 11]
    return hmac.compare_digest(checksum, candidate[-1])


def _is_valid_bank_card(value: str) -> bool:
    digits = value.replace(" ", "").replace("-", "")
    if not 13 <= len(digits) <= 19 or not digits.isascii() or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        digit = int(character)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _decode_base64url_json(component: str) -> object:
    padded = component + "=" * (-len(component) % 4)
    decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    return json.loads(decoded.decode("utf-8"))


def _is_valid_jwt(value: str) -> bool:
    try:
        header_component, payload_component, signature_component = value.split(".")
        header = _decode_base64url_json(header_component)
        payload = _decode_base64url_json(payload_component)
    except (ValueError, UnicodeError, binascii.Error, json.JSONDecodeError):
        return False
    return (
        isinstance(header, dict)
        and isinstance(header.get("alg"), str)
        and header.get("alg", "").lower() != "none"
        and isinstance(payload, dict)
        and len(signature_component) >= 8
    )


def _is_non_placeholder_credential(value: str) -> bool:
    stripped = value.strip()
    normalized = re.sub(r"[^a-z0-9]+", "", stripped.lower())
    if len(stripped) < 6 or len(set(stripped)) < 3:
        return False
    placeholder_fragments = (
        "changeme",
        "dummy",
        "example",
        "placeholder",
        "redacted",
        "replace",
        "sample",
        "yourpassword",
        "yourtoken",
    )
    if any(fragment in normalized for fragment in placeholder_fragments):
        return False
    if stripped.startswith(("${", "{{", "<")) or stripped.endswith(("}", ">")):
        return False
    return True


def _looks_like_python_type_annotation(value: str) -> bool:
    candidate = value.strip().rstrip(")")
    lowered = candidate.casefold()
    if lowered in {
        "any", "bool", "bytearray", "bytes", "float", "int", "memoryview",
        "none", "object", "path", "str", "typing.any",
    }:
        return True
    return re.fullmatch(
        r"(?i)(?:typing\.)?(?:annotated|callable|dict|frozenset|iterable|list|"
        r"literal|mapping|mutablemapping|optional|sequence|set|tuple|union)\["
        r"[a-z0-9_.,|\[\]]+\]?",
        candidate,
    ) is not None


_RULES: tuple[_Rule, ...] = (
    _Rule("pii.email", "pii", "high", 0.98, "Email address", "email", _EMAIL_RE),
    _Rule(
        "pii.cn_mobile",
        "pii",
        "high",
        0.98,
        "Mainland China mobile number",
        "cn_mobile",
        _CN_MOBILE_RE,
        validator=_is_valid_cn_mobile,
    ),
    _Rule(
        "pii.cn_resident_id",
        "pii",
        "critical",
        0.99,
        "Chinese resident identity number",
        "cn_resident_id",
        _CN_RESIDENT_ID_RE,
        validator=_is_valid_cn_resident_id,
    ),
    _Rule(
        "pii.bank_card",
        "pii",
        "critical",
        0.98,
        "Luhn-valid payment card number",
        "bank_card",
        _BANK_CARD_RE,
        validator=_is_valid_bank_card,
    ),
    _Rule(
        "secret.pem_private_key",
        "secret",
        "critical",
        1.0,
        "PEM private key",
        "private_key",
        _PEM_PRIVATE_KEY_RE,
    ),
    _Rule(
        "secret.aws_access_key_id",
        "secret",
        "critical",
        0.99,
        "AWS access key identifier",
        "secret",
        _AWS_ACCESS_KEY_RE,
    ),
    _Rule(
        "secret.github_token",
        "secret",
        "critical",
        0.99,
        "GitHub token",
        "secret",
        _GITHUB_TOKEN_RE,
    ),
    _Rule(
        "secret.openai_api_key",
        "secret",
        "critical",
        0.99,
        "OpenAI API key",
        "secret",
        _OPENAI_KEY_RE,
    ),
    _Rule(
        "secret.slack_token",
        "secret",
        "critical",
        0.99,
        "Slack token",
        "secret",
        _SLACK_TOKEN_RE,
    ),
    _Rule(
        "secret.google_api_key",
        "secret",
        "critical",
        0.99,
        "Google API key",
        "secret",
        _GOOGLE_API_KEY_RE,
    ),
    _Rule(
        "secret.jwt",
        "secret",
        "high",
        0.95,
        "Signed JSON Web Token",
        "jwt",
        _JWT_RE,
        validator=_is_valid_jwt,
    ),
    _Rule(
        "privacy.windows_user_path",
        "path_disclosure",
        "medium",
        0.95,
        "Windows user absolute path",
        "user_path",
        _WINDOWS_USER_PATH_RE,
    ),
    _Rule(
        "privacy.unix_user_path",
        "path_disclosure",
        "medium",
        0.95,
        "Unix user absolute path",
        "user_path",
        _UNIX_USER_PATH_RE,
    ),
    _Rule(
        "unicode.bidi_control",
        "unicode_control",
        "high",
        0.98,
        "Bidirectional text control character",
        "unicode_control",
        _BIDI_CONTROL_RE,
    ),
    _Rule(
        "unicode.zero_width",
        "unicode_control",
        "medium",
        0.75,
        "Zero-width control character",
        "unicode_control",
        _ZERO_WIDTH_RE,
    ),
)


def _rule_hits(text: str, rule: _Rule, max_hits: int | None = None) -> list[DetectorHit]:
    hits: list[DetectorHit] = []
    for match in rule.pattern.finditer(text):
        value = match.group(rule.group)
        if not isinstance(value, str):
            continue
        validator = rule.validator
        if validator is not None and not validator(value):
            continue
        start, end = match.span(rule.group)
        hits.append(
            DetectorHit(
                rule_id=rule.rule_id,
                category=rule.category,
                severity=rule.severity,
                confidence=rule.confidence,
                title=rule.title,
                start=start,
                end=end,
                value_class=rule.value_class,
            )
        )
        if max_hits is not None and len(hits) >= max_hits:
            break
    return hits


def _assignment_value_hits(
    text: str,
    pattern: re.Pattern[str],
    *,
    rule_id: str,
    severity: str,
    confidence: float,
    title: str,
    validator: Callable[[str], bool] | None = None,
    reject_bare_colon_type_annotation: bool = False,
    reject_bare_code_expression: bool = False,
    max_hits: int | None = None,
) -> list[DetectorHit]:
    hits: list[DetectorHit] = []
    for match in pattern.finditer(text):
        group = next(
            (name for name in ("double", "single", "bare") if match.group(name) is not None),
            None,
        )
        if group is None:
            continue
        value = match.group(group)
        if reject_bare_code_expression and group == "bare" and any(
            character in value for character in "()[]{}"
        ):
            continue
        if (
            reject_bare_colon_type_annotation
            and group == "bare"
            and match.groupdict().get("operator") == ":"
            and _looks_like_python_type_annotation(value)
        ):
            continue
        if validator is not None and not validator(value):
            continue
        start, end = match.span(group)
        hits.append(
            DetectorHit(
                rule_id=rule_id,
                category="secret",
                severity=severity,
                confidence=confidence,
                title=title,
                start=start,
                end=end,
                value_class="credential",
            )
        )
        if max_hits is not None and len(hits) >= max_hits:
            break
    return hits


def _overlaps(left: DetectorHit, right: DetectorHit) -> bool:
    return left.start < right.end and right.start < left.end


def detect_text(text: str, *, max_hits: int | None = None) -> list[DetectorHit]:
    """Detect PII, secrets, user paths, and invisible controls in ``text``.

    Results are sorted by source offset, then by end offset and rule ID.  The
    function is deterministic and performs no I/O.
    """

    if not isinstance(text, str):
        raise TypeError("text must be str")
    if max_hits is not None and (
        isinstance(max_hits, bool) or not isinstance(max_hits, int) or max_hits < 0
    ):
        raise ValueError("max_hits must be a non-negative integer or None")
    if max_hits == 0:
        return []

    hits = [hit for rule in _RULES for hit in _rule_hits(text, rule, max_hits)]
    hits.extend(
        _assignment_value_hits(
            text,
            _AWS_SECRET_ASSIGNMENT_RE,
            rule_id="secret.aws_secret_access_key",
            severity="critical",
            confidence=0.99,
            title="AWS secret access key",
            max_hits=max_hits,
        )
    )

    generic_hits = _assignment_value_hits(
        text,
        _GENERIC_CREDENTIAL_RE,
        rule_id="secret.credential_assignment",
        severity="high",
        confidence=0.72,
        title="Credential-like assignment",
        validator=_is_non_placeholder_credential,
        reject_bare_colon_type_annotation=True,
        reject_bare_code_expression=True,
        max_hits=max_hits,
    )
    protected_hits = [
        hit
        for hit in hits
        if hit.confidence >= 0.9 and hit.category in {"pii", "secret"}
    ]
    hits.extend(
        generic
        for generic in generic_hits
        if not any(_overlaps(generic, protected) for protected in protected_hits)
    )

    unique = {(hit.rule_id, hit.start, hit.end): hit for hit in hits}
    ordered = sorted(unique.values(), key=lambda hit: (hit.start, hit.end, hit.rule_id))
    return ordered if max_hits is None else ordered[:max_hits]


def hit_to_dict(
    hit: DetectorHit,
    source_text: str,
    hmac_key: bytes | bytearray | memoryview | None = None,
) -> dict[str, object]:
    """Render masked evidence and an optional run-scoped correlation token."""

    if not isinstance(source_text, str):
        raise TypeError("source_text must be str")
    if hit.end > len(source_text):
        raise ValueError("hit offsets exceed source text")
    value = source_text[hit.start : hit.end]
    evidence: dict[str, object] = {
        "mode": "masked",
        "masked": mask_value(value, hit.value_class),
        "value_class": hit.value_class,
    }
    if hmac_key is not None:
        evidence["token"] = hmac_token(value, hmac_key)
    return evidence


__all__ = [
    "DetectorHit",
    "RULESET_VERSION",
    "detect_text",
    "hit_to_dict",
    "sanitize_display_path",
    "temporary_hmac_key",
]
