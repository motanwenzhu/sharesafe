from __future__ import annotations

import errno
import json
from pathlib import Path

import pytest

import sharesafe.cli as cli


@pytest.mark.parametrize("as_json", (False, True), ids=("stderr", "json"))
@pytest.mark.parametrize(
    ("exception_kind", "expected_code", "expected_message", "expected_exit"),
    (
        (
            "file_exists",
            "unsafe_or_invalid_request",
            "The request was refused because it is unsafe or invalid.",
            cli.EXIT_USAGE,
        ),
        (
            "value_error",
            "unsafe_or_invalid_request",
            "The request was refused because it is unsafe or invalid.",
            cli.EXIT_USAGE,
        ),
        (
            "permission",
            "filesystem_error",
            "A filesystem operation failed; no safety conclusion was produced.",
            cli.EXIT_INTERNAL,
        ),
        (
            "os_error",
            "filesystem_error",
            "A filesystem operation failed; no safety conclusion was produced.",
            cli.EXIT_INTERNAL,
        ),
        (
            "unexpected",
            "internal_error",
            "Unexpected failure; no safety conclusion was produced.",
            cli.EXIT_INTERNAL,
        ),
    ),
)
def test_cli_exception_output_never_discloses_a_local_path(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    as_json: bool,
    exception_kind: str,
    expected_code: str,
    expected_message: str,
    expected_exit: int,
) -> None:
    private_root = tmp_path / "Users" / "SyntheticUser_PrivateMarker"
    private_root.mkdir(parents=True)
    private_file = private_root / "confidential-input.txt"
    private_file.write_text("synthetic", encoding="utf-8")

    if exception_kind == "file_exists":
        failure: Exception = FileExistsError(
            errno.EEXIST,
            "synthetic collision",
            str(private_file),
        )
    elif exception_kind == "value_error":
        failure = ValueError(f"synthetic invalid path: {private_file}")
    elif exception_kind == "permission":
        failure = PermissionError(
            errno.EACCES,
            "synthetic access denial",
            str(private_file),
        )
    elif exception_kind == "os_error":
        failure = OSError(errno.EIO, "synthetic filesystem failure", str(private_file))
    else:
        failure = RuntimeError(f"synthetic unexpected failure at {private_file}")

    def fail_scan(_args: object) -> int:
        raise failure

    monkeypatch.setattr(cli, "_scan_command", fail_scan)
    arguments = ["scan", str(private_file)]
    if as_json:
        arguments.append("--json")

    code = cli.main(arguments)
    captured = capsys.readouterr()
    combined = captured.out + captured.err

    assert code == expected_exit
    assert "SyntheticUser_PrivateMarker" not in combined
    assert "confidential-input.txt" not in combined
    assert str(tmp_path) not in combined
    assert "synthetic collision" not in combined
    assert "synthetic access denial" not in combined
    assert "synthetic filesystem failure" not in combined

    if as_json:
        assert captured.err == ""
        payload = json.loads(captured.out)
        assert payload == {
            "schema": "sharesafe.error/v1",
            "error": {"code": expected_code, "message": expected_message},
        }
    else:
        assert captured.out == ""
        assert captured.err == f"ShareSafe: {expected_message}\n"
