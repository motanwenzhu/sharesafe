from __future__ import annotations

from sharesafe import capabilities
from sharesafe.capabilities import doctor_payload, optional_capabilities


def test_discovery_capabilities_preserve_the_stable_dependency_inventory() -> None:
    records = optional_capabilities(deep=False)

    assert {record["name"] for record in records} == {"Pillow", "pypdf"}
    assert all("usable" not in record and "probe" not in record for record in records)
    assert all(record["supported_version"].startswith(">=") for record in records)
    assert all(
        record["isolation"] == "in_process_bounded_adapter" for record in records
    )


def test_deep_doctor_uses_only_integrated_synthetic_probes() -> None:
    payload = doctor_payload(deep=True, tool_version="test")

    assert payload["offline"] is True
    assert payload["telemetry"] is False
    assert payload["probe_mode"] == "deep"
    assert payload["filesystem_safety"]["descriptor_identity_before_read"] is True
    assert payload["filesystem_safety"]["parent_directory_identity_checkpoints"] is True
    assert payload["filesystem_safety"]["parent_directory_handle_anchoring"] is False
    assert payload["filesystem_safety"]["private_temporary_staging_fail_closed"] is True
    assert payload["filesystem_safety"]["private_temporary_staging_permission"] in {
        "posix_effective_user_mode_0700",
        "windows_protected_current_user_inheritable_dacl",
    }
    for dependency in payload["optional"]:
        if dependency["available"] and dependency["version_supported"] is True:
            assert dependency["usable"] is True
            assert dependency["probe"] == "passed"
        elif dependency["available"]:
            assert dependency["usable"] is False
            assert dependency["probe"] == "unsupported_version"
        else:
            assert dependency["usable"] is False
            assert dependency["probe"] == "missing"


def test_failed_deep_probe_does_not_expose_exception_text(monkeypatch) -> None:
    synthetic_path = "C:/Users/Synthetic Person/private/probe.bin"

    def fail_probe() -> None:
        raise RuntimeError(synthetic_path)

    first = capabilities._OPTIONAL_PROBES[0]
    monkeypatch.setattr(
        capabilities,
        "_OPTIONAL_PROBES",
        ((first[0], first[1], first[2], first[3], fail_probe),),
    )
    monkeypatch.setattr(
        capabilities.importlib.util, "find_spec", lambda _module: object()
    )

    payload = doctor_payload(deep=True, tool_version="test")

    assert payload["status"] == "incomplete"
    assert payload["optional"][0]["probe"] == "failed"
    assert synthetic_path not in str(payload)
