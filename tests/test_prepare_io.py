from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from sharesafe import prepare_io, reporting
from sharesafe.prepare_io import (
    PrepareIOError,
    create_private_temporary_directory,
    load_local_control_mapping,
    load_prepare_approval_file,
    load_prepare_plan_file,
    write_prepare_approval_file,
    write_prepare_plan_file,
)
from sharesafe.prepare_plan import create_prepare_approval, create_prepare_plan
from sharesafe.safe_io import verify_directory_unchanged


def _plan(tmp_path: Path):  # type: ignore[no-untyped-def]
    source = tmp_path / "source"
    source.mkdir()
    (source / "public-note.txt").write_text(
        "ordinary synthetic content", encoding="utf-8"
    )
    return create_prepare_plan(
        source,
        [
            {
                "source_path": "public-note.txt",
                "target_path": "public-note.txt",
                "action": "copy_unchanged",
                "reason_code": "explicit_include",
            }
        ],
    )


def _approval(plan):  # type: ignore[no-untyped-def]
    return create_prepare_approval(plan, [item.action_id for item in plan.actions])


def test_private_temporary_directory_is_verified_owner_only() -> None:
    snapshot = create_private_temporary_directory(prefix=".sharesafe-test-stage-")
    try:
        assert verify_directory_unchanged(snapshot)
        status_value = snapshot.path.stat(follow_symlinks=False)
        if os.name != "nt":
            assert stat.S_IMODE(status_value.st_mode) == 0o700
            assert status_value.st_uid == os.geteuid()
        else:
            prepare_io._windows_verify_private_directory(snapshot.path)
    finally:
        if verify_directory_unchanged(snapshot):
            snapshot.path.rmdir()


def test_private_plan_and_approval_round_trip_without_report_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _plan(tmp_path)
    approval = _approval(plan)
    plan_path = tmp_path / "control" / "plan.json"
    approval_path = tmp_path / "control" / "approval.json"

    def forbidden(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("masked report writer must not receive local controls")

    monkeypatch.setattr(reporting, "write_json_atomic", forbidden)
    plan_result = write_prepare_plan_file(plan_path, plan)
    approval_result = write_prepare_approval_file(
        approval_path, approval, plan=plan
    )

    assert load_prepare_plan_file(plan_path) == plan
    assert load_prepare_approval_file(approval_path, plan=plan) == approval
    assert plan_path.read_bytes().endswith(b"\n")
    assert not plan_path.read_bytes().startswith(b"\xef\xbb\xbf")
    assert not list(plan_path.parent.glob(".sharesafe-control-*.tmp"))
    assert plan_result.to_dict() == {
        "artifact_kind": "plan",
        "classification": "local_only_do_not_share",
        "bytes_written": len(plan_path.read_bytes()),
        "owner_only_verified": True,
        "permission_control": (
            "windows_protected_current_user_dacl"
            if os.name == "nt"
            else "posix_owner_mode_0600"
        ),
        "atomic_publish": "same_directory_hardlink_create_new",
        "parent_directory_identity_checkpoints": True,
        "parent_directory_handle_anchoring": False,
    }
    assert approval_result.artifact_kind == "approval"
    if os.name != "nt":
        assert stat.S_IMODE(plan_path.stat().st_mode) == 0o600
        assert plan_path.stat().st_uid == os.geteuid()


@pytest.mark.parametrize(
    ("content", "code"),
    (
        (b'\xef\xbb\xbf{"synthetic":true}', "control_bom_rejected"),
        (b'{"synthetic":1,"synthetic":2}', "invalid_control_json"),
        (b'{"outer":{"duplicate":1,"duplicate":2}}', "invalid_control_json"),
        (b'{"number":NaN}', "invalid_control_json"),
        (b'{"number":Infinity}', "invalid_control_json"),
        (b'{"number":-Infinity}', "invalid_control_json"),
        (b'{"number":1e9999}', "invalid_control_json"),
        (b'{"text":"\\ud800"}', "invalid_control_json"),
        (b'{"text":"\xff"}', "invalid_control_json"),
        (b'["not", "an", "object"]', "control_object_required"),
    ),
)
def test_generic_loader_enforces_strict_utf8_json_object(
    tmp_path: Path, content: bytes, code: str
) -> None:
    selected = tmp_path / "local-control.json"
    selected.write_bytes(content)

    with pytest.raises(PrepareIOError) as captured:
        load_local_control_mapping(selected)

    assert captured.value.code == code


def test_generic_loader_returns_mapping_for_a_schema_parser(tmp_path: Path) -> None:
    selected = tmp_path / "decisions.json"
    payload = {"schema": "sharesafe.synthetic-decisions/v1", "decisions": []}
    selected.write_text(json.dumps(payload), encoding="utf-8")

    loaded = load_local_control_mapping(selected)

    assert loaded == payload
    assert loaded is not payload


def test_loader_rejects_oversize_before_opening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = tmp_path / "large.json"
    selected.write_bytes(b'{"synthetic":true}')

    def forbidden(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("oversized control must not be opened")

    monkeypatch.setattr(prepare_io, "open_verified_binary", forbidden)
    with pytest.raises(PrepareIOError) as captured:
        load_local_control_mapping(selected, max_bytes=1)
    assert captured.value.code == "control_too_large"


@pytest.mark.parametrize("limit", (0, -1, True, "16"))
def test_loader_rejects_invalid_limits(tmp_path: Path, limit: object) -> None:
    selected = tmp_path / "control.json"
    selected.write_text("{}", encoding="utf-8")

    with pytest.raises(PrepareIOError) as captured:
        load_local_control_mapping(selected, max_bytes=limit)  # type: ignore[arg-type]

    assert captured.value.code == "invalid_control_limit"


def test_loader_rejects_nonregular_entry(tmp_path: Path) -> None:
    selected = tmp_path / "directory.json"
    selected.mkdir()

    with pytest.raises(PrepareIOError) as captured:
        load_local_control_mapping(selected)

    assert captured.value.code == "control_not_regular"


def test_loader_rejects_final_component_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    selected = tmp_path / "linked.json"
    try:
        selected.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("file symlinks are unavailable on this host")

    with pytest.raises(PrepareIOError) as captured:
        load_local_control_mapping(selected)

    assert captured.value.code == "control_not_regular"


def test_loader_rejects_linked_parent(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "control.json").write_text("{}", encoding="utf-8")
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks are unavailable on this host")

    with pytest.raises(PrepareIOError) as captured:
        load_local_control_mapping(linked / "control.json")

    assert captured.value.code == "control_not_regular"


def test_loader_rejects_identity_swap_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = tmp_path / "selected.json"
    selected.write_text("{}", encoding="utf-8")
    replacement = tmp_path / "replacement.json"
    replacement.write_text('{"replacement":true}', encoding="utf-8")
    original_open = os.open
    selected_absolute = selected.absolute()

    def swapped_open(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if Path(path).absolute() == selected_absolute:
            return original_open(replacement, *args, **kwargs)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", swapped_open)
    with pytest.raises(PrepareIOError) as captured:
        load_local_control_mapping(selected)

    assert captured.value.code == "control_changed_during_read"


def test_loader_rejects_change_detected_after_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = tmp_path / "selected.json"
    selected.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        prepare_io, "verify_open_file_unchanged", lambda *_args, **_kwargs: False
    )

    with pytest.raises(PrepareIOError) as captured:
        load_local_control_mapping(selected)

    assert captured.value.code == "control_changed_during_read"


def test_semantic_loader_calls_exact_plan_and_approval_parsers(tmp_path: Path) -> None:
    invalid_plan = tmp_path / "invalid-plan.json"
    invalid_plan.write_text('{"schema":"wrong"}', encoding="utf-8")
    with pytest.raises(PrepareIOError) as plan_error:
        load_prepare_plan_file(invalid_plan)
    assert plan_error.value.code == "prepare_plan_invalid"

    plan = _plan(tmp_path)
    approval = _approval(plan).to_dict()
    approval["plan_digest"] = "sha256:" + "0" * 64
    invalid_approval = tmp_path / "invalid-approval.json"
    invalid_approval.write_text(json.dumps(approval), encoding="utf-8")
    with pytest.raises(PrepareIOError) as approval_error:
        load_prepare_approval_file(invalid_approval, plan=plan)
    assert approval_error.value.code == "prepare_approval_invalid"


def test_writer_never_overwrites_existing_destination(tmp_path: Path) -> None:
    destination = tmp_path / "plan.json"
    original = b"synthetic competing content"
    destination.write_bytes(original)

    with pytest.raises(PrepareIOError) as captured:
        write_prepare_plan_file(destination, _plan(tmp_path))

    assert captured.value.code == "control_destination_exists"
    assert destination.read_bytes() == original


def test_destination_race_preserves_competing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "out" / "plan.json"
    competing = b"synthetic race winner"
    original_link = os.link

    def raced_link(source, target, **kwargs):  # type: ignore[no-untyped-def]
        Path(target).write_bytes(competing)
        return original_link(source, target, **kwargs)

    monkeypatch.setattr(prepare_io.os, "link", raced_link)
    with pytest.raises(PrepareIOError) as captured:
        write_prepare_plan_file(destination, _plan(tmp_path))

    assert captured.value.code == "control_destination_exists"
    assert destination.read_bytes() == competing


def test_parent_checkpoint_failure_before_publish_creates_no_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "out" / "plan.json"
    calls = 0
    original_verify = prepare_io.verify_directory_unchanged

    def checkpoint(snapshot):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        if calls == 2:
            return False
        return original_verify(snapshot)

    monkeypatch.setattr(prepare_io, "verify_directory_unchanged", checkpoint)
    with pytest.raises(PrepareIOError) as captured:
        write_prepare_plan_file(destination, _plan(tmp_path))

    assert captured.value.code == "control_parent_changed"
    assert not destination.exists()


def test_writer_fails_closed_when_private_permission_check_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "out" / "plan.json"

    def unavailable(_handle):  # type: ignore[no-untyped-def]
        raise prepare_io._PrivatePermissionError

    monkeypatch.setattr(prepare_io, "_verify_private_open_file", unavailable)
    with pytest.raises(PrepareIOError) as captured:
        write_prepare_plan_file(destination, _plan(tmp_path))

    assert captured.value.code == "private_permissions_unavailable"
    assert not destination.exists()


def test_writer_fails_closed_without_atomic_create_new_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "out" / "plan.json"

    def unsupported(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise OSError(errno_value, "synthetic unsupported link")

    errno_value = getattr(os, "EXDEV", 18)
    monkeypatch.setattr(prepare_io.os, "link", unsupported)
    with pytest.raises(PrepareIOError) as captured:
        write_prepare_plan_file(destination, _plan(tmp_path))

    assert captured.value.code == "atomic_publish_unavailable"
    assert not destination.exists()


def test_write_budget_and_invalid_plan_fail_before_destination_creation(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "new-parent" / "plan.json"
    plan = _plan(tmp_path)
    with pytest.raises(PrepareIOError) as too_large:
        write_prepare_plan_file(destination, plan, max_bytes=8)
    assert too_large.value.code == "control_too_large"
    assert not destination.parent.exists()

    with pytest.raises(PrepareIOError) as invalid:
        write_prepare_plan_file(destination, {"schema": "wrong"})
    assert invalid.value.code == "prepare_plan_invalid"
    assert not destination.parent.exists()


def test_errors_do_not_echo_path_or_content(tmp_path: Path) -> None:
    filename_canary = "private-name-canary"
    content_canary = "secret-content-canary"
    selected = tmp_path / f"{filename_canary}.json"
    selected.write_text(f'{{"value":"{content_canary}",', encoding="utf-8")

    with pytest.raises(PrepareIOError) as captured:
        load_local_control_mapping(selected)

    rendered = f"{captured.value.code} {captured.value}"
    assert filename_canary not in rendered
    assert content_canary not in rendered


@pytest.mark.skipif(os.name != "nt", reason="Windows alternate streams only")
def test_windows_alternate_stream_path_is_rejected(tmp_path: Path) -> None:
    selected = Path(f"{tmp_path / 'control.json'}:stream")

    with pytest.raises(PrepareIOError) as captured:
        load_local_control_mapping(selected)

    assert captured.value.code == "control_path_rejected"
