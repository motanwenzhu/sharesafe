from __future__ import annotations

from dataclasses import replace
import io
from pathlib import Path
import struct
import zipfile

from sharesafe.engine import ScanConfig, Scanner
from sharesafe.limits import Limits
from sharesafe.sanitize import _sanitize_ooxml
from sharesafe.zip_safety import preflight_zip


def _zip(names: tuple[str, ...]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in names:
            archive.writestr(name, b"synthetic public content")
    return output.getvalue()


def _minimal_docx(extra_parts: int = 0) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/document.xml", b"<document/>")
        for index in range(extra_parts):
            archive.writestr(f"word/media/item-{index}.bin", b"public")
    return output.getvalue()


def _with_forged_classic_count(data: bytes, count: int) -> bytes:
    changed = bytearray(data)
    eocd = changed.rfind(b"PK\x05\x06")
    assert eocd >= 0
    struct.pack_into("<HH", changed, eocd + 8, count, count)
    return bytes(changed)


def _as_zip64(data: bytes, count: int) -> bytes:
    eocd = data.rfind(b"PK\x05\x06")
    assert eocd >= 0
    _, _, _, _, _, directory_size, directory_offset, comment_size = struct.unpack_from(
        "<4s4H2LH", data, eocd
    )
    assert comment_size == 0
    zip64_record = struct.pack(
        "<4sQ2H2L4Q",
        b"PK\x06\x06",
        44,
        45,
        45,
        0,
        0,
        count,
        count,
        directory_size,
        directory_offset,
    )
    locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, eocd, 1)
    sentinel_eocd = struct.pack(
        "<4s4H2LH",
        b"PK\x05\x06",
        0,
        0,
        0xFFFF,
        0xFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0,
    )
    return data[:eocd] + zip64_record + locator + sentinel_eocd


def test_preflight_counts_normal_and_prefixed_archives() -> None:
    package = _zip(("one.txt", "two.txt"))

    assert preflight_zip(package, 2).status == "ok"
    assert preflight_zip(b"synthetic-prefix" + package, 2).status == "ok"


def test_preflight_walks_directory_when_classic_count_is_forged_low() -> None:
    package = _with_forged_classic_count(_zip(("one", "two", "three")), 1)

    result = preflight_zip(package, 2)

    assert result.status == "entry_limit"
    assert result.entries == 3


def test_preflight_reads_zip64_count_without_materializing_entries() -> None:
    package = _as_zip64(_zip(("one", "two", "three")), 3)

    result = preflight_zip(package, 2)

    assert result.status == "entry_limit"
    assert result.entries == 3


def test_zip_scanner_rejects_entry_limit_before_infolist(
    tmp_path: Path, monkeypatch,
) -> None:
    sample = tmp_path / "many.zip"
    sample.write_bytes(_zip(("one", "two", "three")))
    limits = replace(Limits(), max_archive_entries=2)

    def unexpected_infolist(_archive: zipfile.ZipFile):
        raise AssertionError("infolist must not run after the preflight limit")

    monkeypatch.setattr(zipfile.ZipFile, "infolist", unexpected_infolist)
    report = Scanner(ScanConfig(limits=limits, optional_tools=False)).scan([sample]).to_dict()

    assert report["summary"]["verdict"] == "incomplete"
    assert any(gap["reason"] == "archive_entry_limit" for gap in report["gaps"])


def test_ooxml_sanitizer_rejects_entry_limit_before_infolist(monkeypatch) -> None:
    package = _minimal_docx(extra_parts=1)
    limits = replace(Limits(), max_archive_entries=2)

    def unexpected_infolist(_archive: zipfile.ZipFile):
        raise AssertionError("infolist must not run after the preflight limit")

    monkeypatch.setattr(zipfile.ZipFile, "infolist", unexpected_infolist)
    cleaned, status, reason = _sanitize_ooxml(package, "sample.docx", limits)

    assert cleaned == package
    assert status == "skipped"
    assert reason == "package_resource_limit"
