from __future__ import annotations

import json
import struct
import zlib
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from sharesafe import prepare
from sharesafe.limits import Limits
from sharesafe.prepare import (
    PrepareWorkflowError,
    apply_prepare_plan,
    prepare_inspection,
    verify_prepare_output,
)
from sharesafe.prepare_io import PrepareIOError
from sharesafe.prepare_plan import create_prepare_approval, create_prepare_plan
from sharesafe.reporting import json_text

ROOT = Path(__file__).resolve().parents[1]


def _schema_validator(name: str) -> Draft202012Validator:
    schemas = {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in (ROOT / "schemas").glob("*.schema.json")
    }
    registry = Registry().with_resources(
        (str(schema["$id"]), Resource.from_contents(schema))
        for schema in schemas.values()
    )
    return Draft202012Validator(schemas[name], registry=registry)


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def _png(*, metadata: bool) -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    chunks = [_png_chunk(b"IHDR", ihdr)]
    if metadata:
        chunks.append(_png_chunk(b"tEXt", b"Comment\x00synthetic metadata"))
    chunks.extend(
        (
            _png_chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00\xff")),
            _png_chunk(b"IEND", b""),
        )
    )
    return b"\x89PNG\r\n\x1a\n" + b"".join(chunks)


def _source_tree(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    (source / "copy.txt").write_text("synthetic public note", encoding="utf-8")
    (source / "old-name.txt").write_text("synthetic renamed note", encoding="utf-8")
    (source / "omit.txt").write_text(
        "synthetic local-only value=" + "sk-" + "S" * 28,
        encoding="utf-8",
    )
    (source / "photo.png").write_bytes(_png(metadata=True))
    return source


def _decisions() -> list[dict[str, object]]:
    return [
        {
            "source_path": "copy.txt",
            "target_path": "copy.txt",
            "action": "copy_unchanged",
            "reason_code": "explicit_include",
        },
        {
            "source_path": "old-name.txt",
            "target_path": "renamed.txt",
            "action": "rename_in_bundle",
            "reason_code": "explicit_rename",
        },
        {
            "source_path": "omit.txt",
            "target_path": None,
            "action": "omit_from_boundary",
            "reason_code": "explicit_omit",
        },
        {
            "source_path": "photo.png",
            "target_path": "photo.png",
            "action": "strip_png_metadata",
            "reason_code": "metadata_detected",
        },
    ]


def _plan_and_approval(source: Path):
    plan = create_prepare_plan(source, _decisions())
    approval = create_prepare_approval(
        plan,
        [action.action_id for action in plan.actions],
    )
    return plan, approval


def test_apply_builds_new_boundary_and_emits_only_masked_result(tmp_path: Path) -> None:
    source = _source_tree(tmp_path)
    output = tmp_path / "bundle"
    plan, approval = _plan_and_approval(source)

    result = apply_prepare_plan(
        source,
        output,
        plan,
        approval,
        optional_tools=False,
        tool_version="0.3.0-test",
    )

    # Exact bundle relations pass, while the final PNG scan remains incomplete
    # because ShareSafe intentionally has no OCR/pixel-content coverage.
    assert result.exit_code == 2
    assert sorted(
        path.relative_to(output).as_posix()
        for path in output.rglob("*")
        if path.is_file()
    ) == [
        "copy.txt",
        "photo.png",
        "renamed.txt",
    ]
    assert (output / "copy.txt").read_bytes() == (source / "copy.txt").read_bytes()
    assert (output / "renamed.txt").read_bytes() == (
        source / "old-name.txt"
    ).read_bytes()
    assert b"synthetic metadata" not in (output / "photo.png").read_bytes()
    assert not (output / "omit.txt").exists()

    payload = result.payload
    assert payload["schema"] == "sharesafe.prepare-result/v1"
    assert payload["verification"]["outcome"] == "verified"
    assert payload["verification"]["expected_files"] == 3
    assert payload["verification"]["observed_files"] == 3
    assert payload["final_scan"]["summary"]["verdict"] == "incomplete"
    serialized = json_text(payload)
    assert plan.plan_digest not in serialized
    assert str(source.absolute()) not in serialized
    assert '"digest": "sha256:' not in serialized
    assert '"plan_digest"' not in serialized
    assert "sk-" + "S" * 28 not in serialized
    _schema_validator("prepare-result-v1.schema.json").validate(payload)


def test_standalone_prepare_verify_recomputes_exact_transform(tmp_path: Path) -> None:
    source = _source_tree(tmp_path)
    output = tmp_path / "bundle"
    plan, approval = _plan_and_approval(source)
    apply_prepare_plan(source, output, plan, approval, optional_tools=False)

    result = verify_prepare_output(
        source,
        output,
        plan,
        optional_tools=False,
        tool_version="0.3.0-test",
    )

    assert result.exit_code == 2
    assert result.payload["operation"] == "verify"
    assert result.payload["commit"] == {"state": "not_applicable", "mode": None}
    assert result.payload["verification"]["outcome"] == "verified"


def test_verify_fails_closed_for_tamper_and_extra_file(tmp_path: Path) -> None:
    source = _source_tree(tmp_path)
    output = tmp_path / "bundle"
    plan, approval = _plan_and_approval(source)
    apply_prepare_plan(source, output, plan, approval, optional_tools=False)
    (output / "copy.txt").write_text("tampered", encoding="utf-8")
    (output / "extra.txt").write_text("synthetic extra", encoding="utf-8")

    result = verify_prepare_output(source, output, plan, optional_tools=False)

    assert result.exit_code == 2
    assert result.payload["verification"]["outcome"] == "incomplete"
    codes = {item["code"] for item in result.payload["verification"]["issues"]}
    assert codes == {
        "final_scan_snapshot_mismatch",
        "output_relation_mismatch",
        "unexpected_output_file",
    }
    assert result.payload["ready_for_review"] is False


def test_verify_fails_closed_for_extra_empty_directory(tmp_path: Path) -> None:
    source = _source_tree(tmp_path)
    output = tmp_path / "bundle"
    plan, approval = _plan_and_approval(source)
    apply_prepare_plan(source, output, plan, approval, optional_tools=False)
    (output / "unexpected-empty-directory").mkdir()

    result = verify_prepare_output(source, output, plan, optional_tools=False)

    assert result.exit_code == 2
    assert result.payload["verification"]["outcome"] == "incomplete"
    assert {item["code"] for item in result.payload["verification"]["issues"]} == {
        "unexpected_output_directory"
    }


def test_apply_rejects_source_drift_before_output_creation(tmp_path: Path) -> None:
    source = _source_tree(tmp_path)
    output = tmp_path / "bundle"
    plan, approval = _plan_and_approval(source)
    (source / "copy.txt").write_text("changed after planning", encoding="utf-8")

    with pytest.raises(PrepareWorkflowError) as captured:
        apply_prepare_plan(source, output, plan, approval, optional_tools=False)

    assert captured.value.code == "source_drift"
    assert not output.exists()


def test_apply_detects_drift_during_action_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sharesafe.prepare as prepare_module

    source = _source_tree(tmp_path)
    output = tmp_path / "bundle"
    plan, approval = _plan_and_approval(source)
    original = prepare_module._read_bound_source
    calls = 0

    def changing_read(source_path, action, *, limits):
        nonlocal calls
        data = original(source_path, action, limits=limits)
        calls += 1
        if calls == 1:
            (source / "old-name.txt").write_text(
                "changed during apply", encoding="utf-8"
            )
        return data

    monkeypatch.setattr(prepare_module, "_read_bound_source", changing_read)

    with pytest.raises(PrepareWorkflowError) as captured:
        apply_prepare_plan(source, output, plan, approval, optional_tools=False)

    assert captured.value.code == "source_drift"
    assert not output.exists()


def test_apply_binds_final_scan_to_exact_expected_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sharesafe.prepare as prepare_module

    source = _source_tree(tmp_path)
    output = tmp_path / "bundle"
    plan, approval = _plan_and_approval(source)
    original_scan = prepare_module._scan_output

    def mutate_then_scan(output_path, **kwargs):
        (output_path / "copy.txt").write_text(
            "synthetic benign replacement",
            encoding="utf-8",
        )
        return original_scan(output_path, **kwargs)

    monkeypatch.setattr(prepare_module, "_scan_output", mutate_then_scan)

    result = apply_prepare_plan(source, output, plan, approval, optional_tools=False)

    assert result.exit_code == 2
    codes = {item["code"] for item in result.payload["verification"]["issues"]}
    assert "final_scan_snapshot_mismatch" in codes
    assert "output_relation_mismatch" in codes
    assert result.payload["ready_for_review"] is False


def test_standalone_verify_binds_scan_to_exact_expected_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sharesafe.prepare as prepare_module

    source = _source_tree(tmp_path)
    output = tmp_path / "bundle"
    plan, approval = _plan_and_approval(source)
    apply_prepare_plan(source, output, plan, approval, optional_tools=False)
    original_scan = prepare_module._scan_output

    def mutate_then_scan(output_path, **kwargs):
        (output_path / "copy.txt").write_text(
            "synthetic benign replacement",
            encoding="utf-8",
        )
        return original_scan(output_path, **kwargs)

    monkeypatch.setattr(prepare_module, "_scan_output", mutate_then_scan)

    result = verify_prepare_output(source, output, plan, optional_tools=False)

    assert result.exit_code == 2
    codes = {item["code"] for item in result.payload["verification"]["issues"]}
    assert "final_scan_snapshot_mismatch" in codes
    assert "output_relation_mismatch" in codes


def test_parent_replacement_before_staging_does_not_receive_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sharesafe.prepare as prepare_module

    source = _source_tree(tmp_path)
    destination_parent = tmp_path / "destination-parent"
    destination_parent.mkdir()
    output = destination_parent / "bundle"
    displaced_parent = tmp_path / "displaced-parent"
    plan, approval = _plan_and_approval(source)
    original_check = prepare_module._check_output_boundary

    def replace_after_snapshot(source_path, output_path):
        snapshot = original_check(source_path, output_path)
        destination_parent.rename(displaced_parent)
        destination_parent.mkdir()
        return snapshot

    monkeypatch.setattr(
        prepare_module, "_check_output_boundary", replace_after_snapshot
    )

    with pytest.raises(PrepareWorkflowError) as captured:
        apply_prepare_plan(source, output, plan, approval, optional_tools=False)

    assert captured.value.code == "output_parent_changed"
    assert list(destination_parent.iterdir()) == []
    assert not output.exists()


def test_commit_never_overwrites_concurrently_inserted_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sharesafe.prepare as prepare_module

    source = _source_tree(tmp_path)
    output = tmp_path / "bundle"
    plan, approval = _plan_and_approval(source)
    original_copy = prepare_module._copy_staged_file_exclusive
    inserted = False

    def insert_before_copy(staged, destination):
        nonlocal inserted
        if not inserted:
            destination.write_text("concurrent sentinel", encoding="utf-8")
            inserted = True
        return original_copy(staged, destination)

    monkeypatch.setattr(
        prepare_module,
        "_copy_staged_file_exclusive",
        insert_before_copy,
    )

    with pytest.raises(PrepareWorkflowError) as captured:
        apply_prepare_plan(source, output, plan, approval, optional_tools=False)

    assert captured.value.code == "commit_target_appeared"
    assert captured.value.output_may_exist is True
    sentinels = [
        path
        for path in output.rglob("*")
        if path.is_file()
        and path.read_text(encoding="utf-8", errors="ignore") == "concurrent sentinel"
    ]
    assert len(sentinels) == 1


def test_apply_requires_transform_to_be_actually_applied(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "photo.png").write_bytes(_png(metadata=False))
    decisions = [
        {
            "source_path": "photo.png",
            "target_path": "photo.png",
            "action": "strip_png_metadata",
            "reason_code": "explicit_strip",
        }
    ]
    plan = create_prepare_plan(source, decisions)
    approval = create_prepare_approval(plan, [plan.actions[0].action_id])
    output = tmp_path / "bundle"

    with pytest.raises(PrepareWorkflowError) as captured:
        apply_prepare_plan(source, output, plan, approval, optional_tools=False)

    assert captured.value.code == "transform_not_applied"
    assert captured.value.exit_code == 2
    assert not output.exists()


def test_apply_never_overwrites_or_nests_output(tmp_path: Path) -> None:
    source = _source_tree(tmp_path)
    plan, approval = _plan_and_approval(source)
    existing = tmp_path / "existing"
    existing.mkdir()
    sentinel = existing / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(PrepareWorkflowError) as existing_error:
        apply_prepare_plan(source, existing, plan, approval, optional_tools=False)
    assert existing_error.value.code == "output_exists"
    assert sentinel.read_text(encoding="utf-8") == "keep"

    with pytest.raises(PrepareWorkflowError) as nested_error:
        apply_prepare_plan(
            source,
            source / "nested-output",
            plan,
            approval,
            optional_tools=False,
        )
    assert nested_error.value.code == "overlapping_boundaries"


def test_inspection_masks_paths_and_omits_control_digests(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    name = "person@example.test.txt"
    (source / name).write_text("synthetic public note", encoding="utf-8")
    plan = create_prepare_plan(
        source,
        [
            {
                "source_path": name,
                "target_path": name,
                "action": "copy_unchanged",
                "reason_code": "explicit_include",
            }
        ],
    )

    view = prepare_inspection(plan)
    serialized = json.dumps(view, ensure_ascii=False)

    assert view["classification"] == "local_masked"
    assert name not in serialized
    assert plan.plan_digest not in serialized
    assert plan.actions[0].source_binding.digest not in serialized
    json_text(view)
    _schema_validator("prepare-inspection-v1.schema.json").validate(view)


def test_apply_commits_then_returns_complete_bounded_incomplete_result(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    decisions: list[dict[str, object]] = []
    for index in range(40):
        name = f"synthetic-{index:03d}-" + "n" * 48 + ".txt"
        (source / name).write_text(f"public synthetic note {index}", encoding="utf-8")
        decisions.append(
            {
                "source_path": name,
                "target_path": name,
                "action": "copy_unchanged",
                "reason_code": "explicit_include",
            }
        )
    limits = Limits(max_report_bytes=4096)
    plan = create_prepare_plan(source, decisions, limits=limits)
    approval = create_prepare_approval(
        plan,
        [action.action_id for action in plan.actions],
    )
    output = tmp_path / "bundle"

    result = apply_prepare_plan(
        source,
        output,
        plan,
        approval,
        limits=limits,
        optional_tools=False,
        tool_version="0.3.0-test",
    )

    assert output.is_dir()
    assert len(list(output.glob("*.txt"))) == 40
    assert result.exit_code == 2
    assert result.payload["reporting"]["detail"] == "truncated"
    assert result.payload["reporting"]["final_scan_detail"] in {
        "complete",
        "summarized",
    }
    assert result.payload["reporting"]["max_bytes"] == 4096
    assert result.payload["ready_for_review"] is False
    assert result.payload["verification"]["outcome"] == "incomplete"
    assert result.payload["plan_summary"]["action_results_omitted"] > 0
    assert result.payload["verification"]["issues"][0]["code"] == (
        "prepare_result_size_limit"
    )
    rendered = json_text(result.payload)
    assert len(rendered.encode("utf-8")) <= limits.max_report_bytes
    _schema_validator("prepare-result-v1.schema.json").validate(result.payload)


def test_apply_fails_closed_when_private_staging_cannot_be_proven(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _source_tree(tmp_path)
    plan, approval = _plan_and_approval(source)
    output = tmp_path / "bundle"

    def unavailable(*, prefix: str):  # type: ignore[no-untyped-def]
        assert prefix == ".sharesafe-prepare-"
        raise PrepareIOError("private_permissions_unavailable")

    monkeypatch.setattr(prepare, "create_private_temporary_directory", unavailable)
    with pytest.raises(PrepareWorkflowError) as captured:
        apply_prepare_plan(source, output, plan, approval, optional_tools=False)

    assert captured.value.code == "private_staging_unavailable"
    assert captured.value.exit_code == 4
    assert captured.value.output_may_exist is False
    assert not output.exists()
