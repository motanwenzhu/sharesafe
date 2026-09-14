from __future__ import annotations

from dataclasses import replace
import io
from pathlib import Path
import zipfile

import pytest

from sharesafe.engine import ScanConfig, Scanner
from sharesafe.limits import Limits


def _commented_zip(*, archive_comment: bytes = b"", member_comment: bytes = b"") -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.comment = archive_comment
        info = zipfile.ZipInfo("public.txt", date_time=(2000, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.comment = member_comment
        archive.writestr(info, b"public")
    return output.getvalue()


@pytest.mark.parametrize("location", ("archive", "member"))
def test_zip_comments_are_scanned_with_masked_secret_findings(
    location: str, tmp_path: Path,
) -> None:
    secret = ("sk-" + "S" * 28).encode()
    package = _commented_zip(
        archive_comment=secret if location == "archive" else b"",
        member_comment=secret if location == "member" else b"",
    )
    sample = tmp_path / f"{location}.zip"
    sample.write_bytes(package)

    report = Scanner(ScanConfig(optional_tools=False)).scan([sample]).to_dict()

    assert "secret.openai_api_key" in {finding["rule_id"] for finding in report["findings"]}
    assert secret.decode() not in str(report)


def test_zip_comment_cumulative_text_budget_is_incomplete(tmp_path: Path) -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.comment = b"public"
        for index in range(2):
            info = zipfile.ZipInfo(f"public-{index}.txt", date_time=(2000, 1, 1, 0, 0, 0))
            info.comment = b"public"
            archive.writestr(info, b"public")
    sample = tmp_path / "comments.zip"
    sample.write_bytes(output.getvalue())
    limits = replace(Limits(), max_text_bytes=8)

    report = Scanner(ScanConfig(limits=limits, optional_tools=False)).scan([sample]).to_dict()

    assert report["summary"]["verdict"] == "incomplete"
    gaps = [gap for gap in report["gaps"] if gap["reason"] == "archive_comment_text_limit"]
    assert len(gaps) == 1
