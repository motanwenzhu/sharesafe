from __future__ import annotations

import json

from sharesafe.cli import main


def test_doctor_deep_json_reports_executed_synthetic_probes(capsys) -> None:
    code = main(["doctor", "--deep", "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code in {0, 2}
    assert captured.err == ""
    assert payload["schema"] == "sharesafe.doctor/v1"
    assert payload["probe_mode"] == "deep"
    assert payload["offline"] is True
    assert payload["telemetry"] is False
    assert payload["filesystem_safety"]["descriptor_identity_before_read"] is True
    for dependency in payload["optional"]:
        assert dependency["probe"] in {
            "passed", "failed", "missing", "unsupported_version"
        }
        assert dependency["usable"] is (dependency["probe"] == "passed")


def test_doctor_default_remains_non_executing_discovery(capsys) -> None:
    code = main(["doctor", "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 0
    assert payload["probe_mode"] == "discovery"
    assert all("probe" not in item and "usable" not in item for item in payload["optional"])
