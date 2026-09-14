from __future__ import annotations

import base64
import json
import sys
from dataclasses import asdict
from pathlib import Path

import pytest


PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "skills" / "sharesafe" / "scripts"
sys.path.insert(0, str(PACKAGE_ROOT))

from sharesafe.detectors import DetectorHit, detect_text, hit_to_dict  # noqa: E402
from sharesafe.redaction import (  # noqa: E402
    hmac_token,
    mask_value,
    sanitize_display_path,
    temporary_hmac_key,
)


def _valid_cn_id() -> str:
    # 99 is not an assigned province prefix; the value is synthetic but still
    # exercises the official 18-character checksum.
    body = "".join(("990000", "20000101", "001"))
    weights = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    checksum_chars = "10X98765432"
    check = checksum_chars[sum(int(digit) * weight for digit, weight in zip(body, weights)) % 11]
    return body + check


def _jwt() -> str:
    def component(value: dict[str, object]) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return ".".join(
        (component({"alg": "HS256", "typ": "JWT"}), component({"sub": "synthetic"}), "notASignature")
    )


def _synthetic_values() -> dict[str, str]:
    return {
        "pii.email": "reviewer" + "@example.test",
        "pii.cn_mobile": "+86 199" + " 0000 0000",
        "pii.cn_resident_id": _valid_cn_id(),
        "pii.bank_card": "4242" + " 4242" * 3,
        "secret.pem_private_key": (
            "-----BEGIN "
            + "PRIVATE KEY-----\n"
            + "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="
            + "\n-----END "
            + "PRIVATE KEY-----"
        ),
        "secret.aws_access_key_id": "AKIA" + "A" * 16,
        "secret.aws_secret_access_key": "aB3/" * 10,
        "secret.github_token": "ghp_" + "aB3c" * 9,
        "secret.openai_api_key": "sk-proj-" + "aB3_" * 7,
        "secret.slack_token": "xoxb-" + "1234567890-ABCDEFGHIJ",
        "secret.google_api_key": "AIza" + "aB3_" * 8 + "XYZ",
        "secret.jwt": _jwt(),
        "secret.credential_assignment": "sYnthetic-Only-987!",
        "privacy.windows_user_path": "C:\\Users\\Synthetic Person\\work\\notes.txt",
        "privacy.unix_user_path": "/home/synthetic/work/notes.txt",
        "unicode.bidi_control": "\u202e",
        "unicode.zero_width": "\u200b",
    }


def _document_with_synthetic_values() -> str:
    values = _synthetic_values()
    lines = [
        values["pii.email"],
        values["pii.cn_mobile"],
        values["pii.cn_resident_id"],
        values["pii.bank_card"],
        values["secret.pem_private_key"],
        values["secret.aws_access_key_id"],
        f'aws_secret_access_key = "{values["secret.aws_secret_access_key"]}"',
        values["secret.github_token"],
        values["secret.openai_api_key"],
        values["secret.slack_token"],
        values["secret.google_api_key"],
        values["secret.jwt"],
        f'password = "{values["secret.credential_assignment"]}"',
        values["privacy.windows_user_path"],
        values["privacy.unix_user_path"],
        "visible" + values["unicode.bidi_control"] + "reordered",
        "zero" + values["unicode.zero_width"] + "width",
    ]
    return "\n".join(lines)


def test_detects_every_supported_rule_with_stable_order() -> None:
    text = _document_with_synthetic_values()
    hits = detect_text(text)
    rule_ids = {hit.rule_id for hit in hits}

    assert set(_synthetic_values()) <= rule_ids
    assert hits == sorted(hits, key=lambda hit: (hit.start, hit.end, hit.rule_id))
    assert all(not hasattr(hit, "value") for hit in hits)
    assert all("synthetic" not in json.dumps(asdict(hit)).lower() for hit in hits)
    assert {
        hit.category for hit in hits if hit.rule_id.startswith("privacy.")
    } == {"path_disclosure"}


def test_cn_id_requires_real_checksum_and_calendar_date() -> None:
    valid = _valid_cn_id()
    bad_checksum = valid[:-1] + ("0" if valid[-1] != "0" else "1")
    bad_date_body = "".join(("990000", "20000231", "001"))
    weights = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    chars = "10X98765432"
    bad_date = bad_date_body + chars[
        sum(int(digit) * weight for digit, weight in zip(bad_date_body, weights)) % 11
    ]

    assert "pii.cn_resident_id" in {hit.rule_id for hit in detect_text(valid)}
    assert "pii.cn_resident_id" not in {hit.rule_id for hit in detect_text(bad_checksum)}
    assert "pii.cn_resident_id" not in {hit.rule_id for hit in detect_text(bad_date)}


def test_near_misses_and_placeholders_are_not_findings() -> None:
    invalid_card = "4242" + " 4242" * 2 + " 4243"
    near_misses = "\n".join(
        (
            "user@localhost",
            "129" + "00000000",
            _valid_cn_id()[:-1] + ("0" if _valid_cn_id()[-1] != "0" else "1"),
            invalid_card,
            "AKIA" + "A" * 15,
            "ghp_" + "a" * 35,
            "sk-too-short",
            "AIza" + "a" * 34,
            "eyJbroken.payload.signature",
            "password = changeme",
            "api_key = ${API_KEY}",
        )
    )

    assert detect_text(near_misses) == []


def test_detector_hit_materialization_can_be_bounded() -> None:
    text = "\n".join(f"bounded{index}@example.test" for index in range(50))

    hits = detect_text(text, max_hits=4)

    assert len(hits) == 4
    assert [hit.start for hit in hits] == sorted(hit.start for hit in hits)
    with pytest.raises(ValueError):
        detect_text(text, max_hits=-1)


def test_chinese_context_and_unicode_boundaries_do_not_hide_ascii_pii() -> None:
    email = "reviewer" + "@example.test"
    mobile = "199" + "00000000"
    text = f"联系人：邮箱{email}，手机{mobile}。全角数字１９９００００００００不是 ASCII 号码。"

    hits = detect_text(text)
    assert {hit.rule_id for hit in hits} == {"pii.email", "pii.cn_mobile"}
    assert {text[hit.start : hit.end] for hit in hits} == {email, mobile}


def test_malformed_jwt_like_input_never_crashes_detector() -> None:
    malformed = "eyJ" + "a" * 10 + "." + "b" * 9 + "." + "c" * 9
    assert "secret.jwt" not in {hit.rule_id for hit in detect_text(malformed)}


def test_generic_assignment_is_lower_confidence_and_specific_secret_wins() -> None:
    synthetic_key = "sk-proj-" + "Z9_" * 9
    text = f'api_key = "{synthetic_key}"\npassword = "sYnthetic-Only-987!"'
    hits = detect_text(text)

    assert [hit.rule_id for hit in hits].count("secret.openai_api_key") == 1
    assert [hit.rule_id for hit in hits].count("secret.credential_assignment") == 1
    generic = next(hit for hit in hits if hit.rule_id == "secret.credential_assignment")
    assert generic.confidence == pytest.approx(0.72)


def test_all_serialized_evidence_is_masked_and_raw_free() -> None:
    text = _document_with_synthetic_values()
    key = b"test-only-hmac-key-material-32!!"

    for hit in detect_text(text):
        raw = text[hit.start : hit.end]
        rendered = hit_to_dict(hit, text, key)
        serialized = json.dumps(rendered, ensure_ascii=False)
        assert raw not in serialized
        assert rendered["masked"] != raw
        assert rendered["token"].startswith("hmac-sha256:v1:")  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("value", "value_class"),
    (
        ("reviewer@example.test", "email"),
        ("19900000000", "cn_mobile"),
        (_valid_cn_id(), "cn_resident_id"),
        ("4242424242424242", "bank_card"),
        ("synthetic-secret", "secret"),
        ("C:\\Users\\Synthetic\\private.txt", "user_path"),
        ("\u202e", "unicode_control"),
    ),
)
def test_mask_value_never_contains_original(value: str, value_class: str) -> None:
    masked = mask_value(value, value_class)
    assert value not in masked
    assert masked != value


def test_hmac_tokens_are_keyed_deterministic_and_non_revealing() -> None:
    value = "synthetic-value"
    key = b"0123456789abcdef0123456789abcdef"
    another_key = b"abcdef0123456789abcdef0123456789"

    first = hmac_token(value, key)
    assert first == hmac_token(value, key)
    assert first != hmac_token(value, another_key)
    assert value not in first
    assert temporary_hmac_key() != temporary_hmac_key()
    with pytest.raises(ValueError):
        hmac_token(value, b"too-short")


def test_display_path_masks_users_and_embedded_pii_but_preserves_archive_location() -> None:
    email = "reviewer" + "@example.test"
    mobile = "199" + "00000000"
    display = f"bundle.zip!/C:\\Users\\Alice\\exports\\{email}\\{mobile}.txt"

    sanitized = sanitize_display_path(display)

    assert sanitized.startswith("bundle.zip!/")
    assert "C:\\Users\\<user>\\exports\\" in sanitized
    assert "Alice" not in sanitized
    assert email not in sanitized
    assert mobile not in sanitized
    assert "!/" in sanitized


def test_display_path_masks_embedded_secret_and_invisible_control() -> None:
    token = "ghp_" + "z9Yx" * 9
    raw = f"bundle.zip!/exports/{token}\u202e.txt"
    sanitized = sanitize_display_path(raw)

    assert sanitized.startswith("bundle.zip!/exports/")
    assert token not in sanitized
    assert "\u202e" not in sanitized
    assert "<secret:redacted>" in sanitized
    assert "<unicode-control:U+202E" in sanitized


def test_display_path_masks_unix_macos_wsl_and_unc_homes() -> None:
    paths = {
        "/home/alice/report.txt": "/home/<user>/report.txt",
        "/Users/alice/report.txt": "/Users/<user>/report.txt",
        "/mnt/c/Users/alice/report.txt": "/mnt/c/Users/<user>/report.txt",
        "\\\\server\\Users\\alice\\report.txt": "\\\\<host>\\Users\\<user>\\report.txt",
        "\\\\internal-host\\share\\report.txt": "\\\\<host>\\share\\report.txt",
        "/root/report.txt": "/<user>/report.txt",
    }
    for raw, expected in paths.items():
        assert sanitize_display_path(raw) == expected


def test_display_path_makes_all_c0_c1_and_del_controls_visible() -> None:
    controls = "".join(chr(codepoint) for codepoint in (*range(0x20), 0x7F, *range(0x80, 0xA0)))

    sanitized = sanitize_display_path(f"bundle.zip!/before{controls}after.txt")

    assert all(character not in sanitized for character in controls)
    assert all(f"U+{ord(character):04X}" in sanitized for character in controls)


def test_hit_validation_and_out_of_range_serialization() -> None:
    with pytest.raises(ValueError):
        DetectorHit("Bad Rule", "pii", "high", 0.98, "Bad", 0, 1, "email")

    hit = DetectorHit("pii.email", "pii", "high", 0.98, "Email", 0, 10, "email")
    with pytest.raises(ValueError):
        hit_to_dict(hit, "short")
