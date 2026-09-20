from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from sharesafe.prepare_decisions import (
    PrepareDecisionError,
    decisions_from_mapping,
    load_prepare_decisions_file,
)

ROOT = Path(__file__).resolve().parents[1]


def _payload() -> dict[str, object]:
    return {
        "schema": "sharesafe.prepare-decisions/v1",
        "classification": "local_only_do_not_share",
        "source_boundary": "<selected-source>",
        "actions": [
            {
                "source_path": "note.txt",
                "target_path": "note.txt",
                "action": "copy_unchanged",
                "reason_code": "explicit_include",
            }
        ],
    }


def test_decisions_parse_and_validate_against_schema(tmp_path: Path) -> None:
    path = tmp_path / "decisions.json"
    path.write_text(json.dumps(_payload()), encoding="utf-8")

    decisions = load_prepare_decisions_file(path)

    assert decisions == (
        {
            "source_path": "note.txt",
            "target_path": "note.txt",
            "action": "copy_unchanged",
            "reason_code": "explicit_include",
        },
    )
    schemas = {
        item.name: json.loads(item.read_text(encoding="utf-8"))
        for item in (ROOT / "schemas").glob("*.schema.json")
    }
    registry = Registry().with_resources(
        (str(schema["$id"]), Resource.from_contents(schema))
        for schema in schemas.values()
    )
    Draft202012Validator(
        schemas["prepare-decisions-v1.schema.json"],
        registry=registry,
    ).validate(_payload())


@pytest.mark.parametrize(
    "mutate",
    (
        lambda value: value.update({"unknown": True}),
        lambda value: value.update({"schema": "sharesafe.prepare-decisions/v2"}),
        lambda value: value["actions"][0].update({"shell": "synthetic"}),
        lambda value: value.update({"actions": "not-a-list"}),
    ),
)
def test_decisions_reject_unknown_or_malformed_contract(mutate) -> None:
    payload = _payload()
    mutate(payload)

    with pytest.raises(PrepareDecisionError):
        decisions_from_mapping(payload)


def test_decisions_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "decisions.json"
    path.write_text(
        '{"schema":"sharesafe.prepare-decisions/v1",'
        '"schema":"sharesafe.prepare-decisions/v1",'
        '"classification":"local_only_do_not_share",'
        '"source_boundary":"<selected-source>","actions":[]}',
        encoding="utf-8",
    )

    with pytest.raises(PrepareDecisionError) as captured:
        load_prepare_decisions_file(path)

    assert captured.value.code == "invalid_control_json"
