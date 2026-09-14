from __future__ import annotations

import json
from pathlib import Path

from sharesafe.cli import main


def test_malformed_jpeg_sanitize_returns_incomplete_operation(
    tmp_path: Path, capsys,
) -> None:
    source = tmp_path / "broken.jpg"
    output = tmp_path / "prepared.jpg"
    source.write_bytes(b"\xff\xd8\xff\xe1\x00\x10xx")

    code = main([
        "sanitize",
        str(source),
        "--out",
        str(output),
        "--json",
        "--no-optional-tools",
    ])
    payload = json.loads(capsys.readouterr().out)

    assert code == 2
    assert payload["schema"] == "sharesafe.sanitize/v1"
    assert output.read_bytes() == source.read_bytes()
    assert any(
        action["action"] == "strip_jpeg_metadata"
        and action["status"] == "skipped"
        and action.get("reason") == "invalid_jpeg_structure"
        for action in payload["actions"]
    )
    assert payload["verification"]["outcome"] == "incomplete"
