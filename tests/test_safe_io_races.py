from __future__ import annotations

import os
from pathlib import Path

from sharesafe.engine import Scanner


def test_scanner_rejects_opened_identity_swap_before_reading(
    tmp_path: Path,
    monkeypatch,
) -> None:
    selected = tmp_path / "selected.txt"
    selected.write_text("ordinary synthetic text\n", encoding="utf-8")
    replacement = tmp_path / "replacement.txt"
    synthetic_email = "race.canary@example.invalid"
    replacement.write_text(f"private={synthetic_email}\n", encoding="utf-8")

    selected_absolute = selected.absolute()
    original_open = os.open

    def swapped_open(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if Path(path).absolute() == selected_absolute:
            return original_open(replacement, *args, **kwargs)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", swapped_open)

    report = Scanner().scan([selected]).to_dict()
    serialized = str(report)

    assert report["summary"]["verdict"] == "incomplete"
    assert any(gap["reason"] == "file_identity_changed_before_read" for gap in report["gaps"])
    assert not report["findings"]
    assert synthetic_email not in serialized
