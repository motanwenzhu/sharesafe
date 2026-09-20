from __future__ import annotations

import hashlib
import json
import os
import struct
import unicodedata
import zlib
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError
from sharesafe.prepare_plan import (
    PreparePlanError,
    canonical_approval_digest,
    canonical_plan_digest,
    create_prepare_approval,
    create_prepare_plan,
    prepare_approval_from_mapping,
    prepare_plan_from_mapping,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"


def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(
        json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
    )


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def _png() -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    return b"".join(
        (
            b"\x89PNG\r\n\x1a\n",
            _png_chunk(b"IHDR", ihdr),
            _png_chunk(b"tEXt", b"Comment\x00synthetic metadata"),
            _png_chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00\xff")),
            _png_chunk(b"IEND", b""),
        )
    )


def _source_tree(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    (source / "notes.txt").write_text("synthetic public note", encoding="utf-8")
    (source / "photo.png").write_bytes(_png())
    return source


def _decisions() -> list[dict[str, object]]:
    return [
        {
            "source_path": "photo.png",
            "target_path": "photo.png",
            "action": "strip_png_metadata",
            "reason_code": "metadata_detected",
        },
        {
            "source_path": "notes.txt",
            "target_path": "notes.txt",
            "action": "copy_unchanged",
            "reason_code": "explicit_include",
        },
    ]


def test_plan_is_complete_deterministic_and_strongly_bound(tmp_path: Path) -> None:
    source = _source_tree(tmp_path)

    plan = create_prepare_plan(source, _decisions())
    payload = plan.to_dict()

    assert payload["schema"] == "sharesafe.prepare-plan/v1"
    assert payload["classification"] == "local_only_do_not_share"
    assert payload["source_boundary"] == "<selected-source>"
    assert payload["destination_boundary"] == "<new-bundle>"
    assert payload["item_count"] == 2
    assert [item["source_path"] for item in payload["actions"]] == [
        "notes.txt",
        "photo.png",
    ]
    assert [item["action_id"] for item in payload["actions"]] == [
        "prepare-action-000001",
        "prepare-action-000002",
    ]
    note = payload["actions"][0]
    assert note["source_binding"] == {
        "algorithm": "sha256",
        "digest": f"sha256:{hashlib.sha256(b'synthetic public note').hexdigest()}",
        "size": len(b"synthetic public note"),
    }
    assert note["approval_required"] is True
    assert note["expected_relation"] == "byte_identical"
    assert note["known_losses"] == []
    image = payload["actions"][1]
    assert image["media_type"] == "image/png"
    assert image["expected_relation"] == "metadata_reduced_format_preserved"
    assert image["known_losses"] == ["image_metadata_removed"]
    assert payload["plan_digest"] == canonical_plan_digest(payload)
    assert str(source.absolute()) not in json.dumps(payload, ensure_ascii=False)

    reparsed = prepare_plan_from_mapping(payload)
    assert reparsed.to_dict() == payload
    _validator("prepare-plan-v1.schema.json").validate(payload)


@pytest.mark.parametrize(
    ("decisions", "code"),
    (
        (
            [
                {
                    "source_path": "notes.txt",
                    "target_path": "notes.txt",
                    "action": "copy_unchanged",
                    "reason_code": "explicit_include",
                }
            ],
            "inventory_action_missing",
        ),
        (
            _decisions()
            + [
                {
                    "source_path": "notes.txt",
                    "target_path": None,
                    "action": "omit_from_boundary",
                    "reason_code": "duplicate_decision",
                }
            ],
            "duplicate_source_action",
        ),
        (
            _decisions()
            + [
                {
                    "source_path": "unknown.txt",
                    "target_path": "unknown.txt",
                    "action": "copy_unchanged",
                    "reason_code": "not_in_inventory",
                }
            ],
            "action_source_unknown",
        ),
    ),
)
def test_every_inventory_item_has_exactly_one_action(
    tmp_path: Path,
    decisions: list[dict[str, object]],
    code: str,
) -> None:
    source = _source_tree(tmp_path)

    with pytest.raises(PreparePlanError) as captured:
        create_prepare_plan(source, decisions)

    assert captured.value.code == code


def test_decisions_and_persisted_objects_reject_unknown_fields(tmp_path: Path) -> None:
    source = _source_tree(tmp_path)
    decisions = _decisions()
    decisions[0]["command"] = "synthetic-command"
    with pytest.raises(PreparePlanError) as decision_error:
        create_prepare_plan(source, decisions)
    assert decision_error.value.code == "unknown_decision_field"

    payload = create_prepare_plan(source, _decisions()).to_dict()
    payload["upload"] = True
    with pytest.raises(PreparePlanError) as plan_error:
        prepare_plan_from_mapping(payload)
    assert plan_error.value.code == "unknown_plan_field"
    with pytest.raises(ValidationError):
        _validator("prepare-plan-v1.schema.json").validate(payload)


@pytest.mark.parametrize(
    "target",
    (
        "../escape.txt",
        "/absolute.txt",
        "C:/absolute.txt",
        "//server/share.txt",
        r"\\server\share.txt",
        "name.txt:stream",
        "CON",
        "folder/Lpt1.txt",
        "folder./item.txt",
        "folder/item.txt ",
    ),
)
def test_plan_rejects_nonportable_or_escaping_target_paths(
    tmp_path: Path,
    target: str,
) -> None:
    source = _source_tree(tmp_path)
    decisions = _decisions()
    decisions[0] = {
        "source_path": "photo.png",
        "target_path": target,
        "action": "rename_in_bundle",
        "reason_code": "explicit_rename",
    }

    with pytest.raises(PreparePlanError) as captured:
        create_prepare_plan(source, decisions)

    assert captured.value.code == "invalid_relative_path"


@pytest.mark.parametrize(
    ("left", "right"),
    (
        ("Bundle/File.txt", "bundle/file.TXT"),
        ("Dir/first.txt", "dir/second.txt"),
        ("bundle", "bundle/child.txt"),
        (
            "caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt",
            "cafe\N{COMBINING ACUTE ACCENT}.txt",
        ),
    ),
    ids=("casefold-file", "casefold-parent", "file-ancestor", "unicode-nfc"),
)
def test_plan_rejects_casefold_nfc_and_tree_target_collisions(
    tmp_path: Path,
    left: str,
    right: str,
) -> None:
    source = _source_tree(tmp_path)
    left_parts = [
        unicodedata.normalize("NFC", part).casefold() for part in left.split("/")
    ]
    right_parts = [
        unicodedata.normalize("NFC", part).casefold() for part in right.split("/")
    ]
    assert (
        left_parts == right_parts
        or left_parts == right_parts[: len(left_parts)]
        or left_parts[:-1] == right_parts[:-1]
    )
    decisions = [
        {
            "source_path": "notes.txt",
            "target_path": left,
            "action": "rename_in_bundle",
            "reason_code": "explicit_rename",
        },
        {
            "source_path": "photo.png",
            "target_path": right,
            "action": "rename_in_bundle",
            "reason_code": "explicit_rename",
        },
    ]

    with pytest.raises(PreparePlanError) as captured:
        create_prepare_plan(source, decisions)

    assert captured.value.code == "portable_path_collision"


def test_action_allowlist_media_and_target_contracts_are_strict(tmp_path: Path) -> None:
    source = _source_tree(tmp_path)
    invalid_cases = [
        ({**_decisions()[0], "action": "run_command"}, "unsupported_action"),
        (
            {
                "source_path": "notes.txt",
                "target_path": "notes.txt",
                "action": "strip_png_metadata",
                "reason_code": "wrong_media",
            },
            "action_media_mismatch",
        ),
        ({**_decisions()[0], "target_path": "renamed.png"}, "action_target_mismatch"),
        (
            {
                "source_path": "notes.txt",
                "target_path": "notes.txt",
                "action": "omit_from_boundary",
                "reason_code": "bad_omit_target",
            },
            "action_target_mismatch",
        ),
    ]
    for replacement, code in invalid_cases:
        decisions = _decisions()
        index = 0 if replacement["source_path"] == "photo.png" else 1
        decisions[index] = replacement
        with pytest.raises(PreparePlanError) as captured:
            create_prepare_plan(source, decisions)
        assert captured.value.code == code


@pytest.mark.parametrize("displaced_action", ("omit_from_boundary", "rename_in_bundle"))
def test_plan_rejects_reusing_an_omitted_or_renamed_source_path(
    tmp_path: Path,
    displaced_action: str,
) -> None:
    source = _source_tree(tmp_path)
    decisions = [
        {
            "source_path": "notes.txt",
            "target_path": (
                "renamed-notes.txt" if displaced_action == "rename_in_bundle" else None
            ),
            "action": displaced_action,
            "reason_code": "explicit_boundary_change",
        },
        {
            "source_path": "photo.png",
            "target_path": "notes.txt",
            "action": "rename_in_bundle",
            "reason_code": "ambiguous_old_name",
        },
    ]

    with pytest.raises(PreparePlanError) as captured:
        create_prepare_plan(source, decisions)

    assert captured.value.code == "source_target_alias_collision"


def test_plan_rejects_recreating_omitted_source_as_directory(tmp_path: Path) -> None:
    source = _source_tree(tmp_path)
    decisions = [
        {
            "source_path": "notes.txt",
            "target_path": None,
            "action": "omit_from_boundary",
            "reason_code": "explicit_omit",
        },
        {
            "source_path": "photo.png",
            "target_path": "notes.txt/child.png",
            "action": "rename_in_bundle",
            "reason_code": "ambiguous_old_name_directory",
        },
    ]

    with pytest.raises(PreparePlanError) as captured:
        create_prepare_plan(source, decisions)

    assert captured.value.code == "source_target_alias_collision"


def test_plan_rejects_empty_source_inventory(tmp_path: Path) -> None:
    source = tmp_path / "empty"
    source.mkdir()

    with pytest.raises(PreparePlanError) as captured:
        create_prepare_plan(source, [])

    assert captured.value.code == "source_inventory_empty"


def test_plan_digest_and_derived_fields_cannot_be_tampered(tmp_path: Path) -> None:
    source = _source_tree(tmp_path)
    payload = create_prepare_plan(source, _decisions()).to_dict()

    changed_digest = deepcopy(payload)
    changed_digest["actions"][0]["reason_code"] = "tampered_reason"
    with pytest.raises(PreparePlanError) as digest_error:
        prepare_plan_from_mapping(changed_digest)
    assert digest_error.value.code == "plan_digest_mismatch"

    forged_derived = deepcopy(payload)
    forged_derived["actions"][0]["approval_required"] = False
    forged_derived["plan_digest"] = canonical_plan_digest(forged_derived)
    with pytest.raises(PreparePlanError) as derived_error:
        prepare_plan_from_mapping(forged_derived)
    assert derived_error.value.code == "action_contract_mismatch"


def test_approval_binds_exact_plan_and_every_explicit_action_id(tmp_path: Path) -> None:
    plan = create_prepare_plan(_source_tree(tmp_path), _decisions())
    action_ids = [action.action_id for action in plan.actions]

    approval = create_prepare_approval(plan, reversed(action_ids))
    payload = approval.to_dict()

    assert payload["schema"] == "sharesafe.prepare-approval/v1"
    assert payload["classification"] == "local_only_do_not_share"
    assert payload["status"] == "approved_for_apply"
    assert payload["plan_digest"] == plan.plan_digest
    assert payload["approved_action_ids"] == sorted(action_ids)
    assert payload["approval_digest"] == canonical_approval_digest(payload)
    assert prepare_approval_from_mapping(payload, plan=plan).to_dict() == payload
    _validator("prepare-approval-v1.schema.json").validate(payload)


@pytest.mark.parametrize(
    ("selector", "code"),
    (
        (lambda ids: [ids[0]], "approval_incomplete"),
        (lambda ids: [*ids, "prepare-action-999999"], "approval_action_unknown"),
        (lambda ids: [ids[0], ids[0], ids[1]], "duplicate_approval_action"),
    ),
    ids=("missing", "injected", "duplicate"),
)
def test_approval_rejects_missing_injected_and_duplicate_ids(
    tmp_path: Path,
    selector,
    code: str,
) -> None:
    plan = create_prepare_plan(_source_tree(tmp_path), _decisions())
    action_ids = [action.action_id for action in plan.actions]

    with pytest.raises(PreparePlanError) as captured:
        create_prepare_approval(plan, selector(action_ids))

    assert captured.value.code == code


@pytest.mark.parametrize("action", ("manual_or_external_required", "block"))
def test_nonexecutable_plan_cannot_receive_apply_approval(
    tmp_path: Path,
    action: str,
) -> None:
    source = _source_tree(tmp_path)
    decisions = _decisions()
    decisions[0] = {
        "source_path": "photo.png",
        "target_path": None,
        "action": action,
        "reason_code": "manual_review_required",
    }
    plan = create_prepare_plan(source, decisions)

    with pytest.raises(PreparePlanError) as captured:
        create_prepare_approval(
            plan, [item.action_id for item in plan.actions if item.approval_required]
        )

    assert captured.value.code == "plan_not_executable"


def test_approval_rejects_unknown_fields_wrong_plan_and_tampering(
    tmp_path: Path,
) -> None:
    source = _source_tree(tmp_path)
    plan = create_prepare_plan(source, _decisions())
    payload = create_prepare_approval(
        plan, [item.action_id for item in plan.actions]
    ).to_dict()

    unknown = deepcopy(payload)
    unknown["shell"] = "synthetic"
    with pytest.raises(PreparePlanError) as unknown_error:
        prepare_approval_from_mapping(unknown, plan=plan)
    assert unknown_error.value.code == "unknown_approval_field"
    with pytest.raises(ValidationError):
        _validator("prepare-approval-v1.schema.json").validate(unknown)

    wrong_plan = deepcopy(payload)
    wrong_plan["plan_digest"] = "sha256:" + "0" * 64
    wrong_plan["approval_digest"] = canonical_approval_digest(wrong_plan)
    with pytest.raises(PreparePlanError) as plan_error:
        prepare_approval_from_mapping(wrong_plan, plan=plan)
    assert plan_error.value.code == "approval_plan_mismatch"

    tampered = deepcopy(payload)
    tampered["approved_action_ids"].pop()
    with pytest.raises(PreparePlanError) as tamper_error:
        prepare_approval_from_mapping(tampered, plan=plan)
    assert tamper_error.value.code == "approval_digest_mismatch"


def test_source_hardlinks_are_not_accepted_as_independent_inventory_items(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    first = source / "first.txt"
    second = source / "second.txt"
    first.write_text("synthetic public note", encoding="utf-8")
    try:
        os.link(first, second)
    except OSError as exc:
        pytest.skip(
            f"hardlinks unavailable in test environment: {exc.__class__.__name__}"
        )

    decisions = [
        {
            "source_path": name,
            "target_path": name,
            "action": "copy_unchanged",
            "reason_code": "explicit_include",
        }
        for name in ("first.txt", "second.txt")
    ]
    with pytest.raises(PreparePlanError) as captured:
        create_prepare_plan(source, decisions)

    assert captured.value.code == "unsafe_source_hardlink"


def test_recomputed_approval_digest_cannot_authorize_an_incomplete_set(
    tmp_path: Path,
) -> None:
    plan = create_prepare_plan(_source_tree(tmp_path), _decisions())
    payload = create_prepare_approval(
        plan, [item.action_id for item in plan.actions]
    ).to_dict()
    payload["approved_action_ids"].pop()
    payload["approval_digest"] = canonical_approval_digest(payload)

    with pytest.raises(PreparePlanError) as captured:
        prepare_approval_from_mapping(payload, plan=plan)

    assert captured.value.code == "approval_incomplete"
