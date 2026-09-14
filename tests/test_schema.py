from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

from sharesafe.cli import main
from sharesafe.engine import Scanner


ROOT = Path(__file__).resolve().parents[1]


def _schemas() -> dict[str, dict[str, object]]:
    return {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((ROOT / "schemas").glob("*.schema.json"))
    }


def _validator(name: str) -> Draft202012Validator:
    schemas = _schemas()
    registry = Registry().with_resources(
        (str(schema["$id"]), Resource.from_contents(schema))
        for schema in schemas.values()
    )
    return Draft202012Validator(schemas[name], registry=registry)


def test_all_json_schemas_are_valid() -> None:
    for schema in _schemas().values():
        Draft202012Validator.check_schema(schema)


def test_scan_report_validates_against_public_schema(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("contact=" + "schema@example.test", encoding="utf-8")
    report = Scanner().scan([sample]).to_dict()

    _validator("report-v1.schema.json").validate(report)


def test_sanitize_and_verify_results_resolve_local_urn_schemas(
    tmp_path: Path, capsys
) -> None:
    source = tmp_path / "source.txt"
    prepared = tmp_path / "prepared.txt"
    source.write_text("synthetic public note", encoding="utf-8")

    sanitize_code = main(["sanitize", str(source), "--out", str(prepared), "--json"])
    sanitize_capture = capsys.readouterr()
    sanitize_result = json.loads(sanitize_capture.out)

    assert sanitize_code == 0 and sanitize_capture.err == ""
    _validator("sanitize-v1.schema.json").validate(sanitize_result)

    verify_code = main(["verify", str(source), str(prepared), "--json"])
    verify_capture = capsys.readouterr()
    verify_result = json.loads(verify_capture.out)

    assert verify_code == 0 and verify_capture.err == ""
    _validator("verify-v1.schema.json").validate(verify_result)

    for schema_name, result in (
        ("sanitize-v1.schema.json", sanitize_result),
        ("verify-v1.schema.json", verify_result),
    ):
        unexpected = deepcopy(result)
        unexpected["unexpected"] = "must be rejected"
        with pytest.raises(ValidationError):
            _validator(schema_name).validate(unexpected)

        unexpected = deepcopy(result)
        unexpected["verification"]["counts"]["unexpected"] = 1
        with pytest.raises(ValidationError):
            _validator(schema_name).validate(unexpected)
