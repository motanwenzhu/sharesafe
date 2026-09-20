from __future__ import annotations

import json

from sharesafe.catalog import RULESET_VERSION, exact_rule_catalog
from sharesafe.cli import main


def test_exact_rule_catalog_is_versioned_unique_and_machine_readable() -> None:
    rules = exact_rule_catalog()
    identifiers = [item["rule_id"] for item in rules]

    assert RULESET_VERSION == "sharesafe.rules/v1"
    assert identifiers == sorted(identifiers)
    assert len(identifiers) == len(set(identifiers))
    assert "pii.email" in identifiers
    assert "secret.openai_api_key" in identifiers
    assert "SS-OOXML-TRACKED-CHANGES" in identifiers
    assert "SS-PDF-ENCRYPTED" in identifiers
    assert "SS-IMAGE-GPS" in identifiers

    for rule in rules:
        assert set(rule) == {
            "rule_id",
            "category",
            "default_severity",
            "confidence",
            "representations",
            "formats",
            "validator",
            "automatic_remediation",
        }
        assert "*" not in rule["rule_id"]
        assert rule["default_severity"] in {"info", "low", "medium", "high", "critical"}
        assert 0 <= rule["confidence"] <= 1
        assert rule["representations"]
        assert rule["formats"]


def test_exact_rule_catalog_returns_copies() -> None:
    first = exact_rule_catalog()
    first[0]["formats"].append("mutated")

    assert "mutated" not in exact_rule_catalog()[0]["formats"]


def test_rules_detail_cli_returns_exact_versioned_inventory(capsys) -> None:
    code = main(["rules", "--detail", "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 0
    assert captured.err == ""
    assert payload["schema"] == "sharesafe.rules/v1"
    assert payload["ruleset_version"] == RULESET_VERSION
    assert payload["detail"] == "exact"
    assert payload["items"] == exact_rule_catalog()
