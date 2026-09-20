from __future__ import annotations

import io
import json
from pathlib import Path
import struct
from typing import Callable
import zipfile
import zlib

import pytest

from sharesafe.detectors import temporary_hmac_key
from sharesafe.engine import ScanConfig, Scanner
from sharesafe.limits import Limits
from sharesafe.receipts import trusted_receipts
import sharesafe.sanitize as sanitize_module
from sharesafe.sanitize import create_sanitized_copy
from sharesafe.verify import compare_reports


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def _png(comment: bytes, *, pixel: bytes = b"\xff\x00\x00\xff") -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    return b"".join(
        (
            b"\x89PNG\r\n\x1a\n",
            _png_chunk(b"IHDR", ihdr),
            _png_chunk(b"tEXt", b"Comment\x00" + comment),
            _png_chunk(b"IDAT", zlib.compress(b"\x00" + pixel)),
            _png_chunk(b"IEND", b""),
        )
    )


def _replace_png_pixels(data: bytes) -> bytes:
    offset = 8
    chunks: list[bytes] = [data[:8]]
    while offset < len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        payload = data[offset + 8 : offset + 8 + length]
        if kind == b"IDAT":
            payload = zlib.compress(b"\x00\x00\xff\x00\xff")
        chunks.append(_png_chunk(kind, payload))
        offset += length + 12
    return b"".join(chunks)


def _jpeg_segment(marker: int, payload: bytes) -> bytes:
    return b"\xff" + bytes((marker,)) + struct.pack(">H", len(payload) + 2) + payload


def _jpeg() -> bytes:
    comment = _jpeg_segment(0xFE, b"synthetic metadata")
    sos = _jpeg_segment(0xDA, b"\x01\x01\x00\x00\x3f\x00")
    return b"\xff\xd8" + comment + sos + b"\x11\x22\xff\x00\x33" + b"\xff\xd9"


def _replace_jpeg_scan(data: bytes) -> bytes:
    marker = data.index(b"\x11\x22\xff\x00\x33")
    return data[:marker] + b"\x12\x22\xff\x00\x33" + data[marker + 5 :]


def _docx() -> bytes:
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            b'<Types><Override PartName="/word/document.xml" ContentType="application/xml"/></Types>',
        )
        archive.writestr(
            "docProps/core.xml",
            b'<cp:coreProperties xmlns:cp="urn:cp" xmlns:dc="urn:dc">'
            b"<dc:creator>Synthetic Author</dc:creator></cp:coreProperties>",
        )
        archive.writestr("word/document.xml", b"<document><body>public</body></document>")
    return package.getvalue()


def _replace_docx_body(data: bytes) -> bytes:
    source = zipfile.ZipFile(io.BytesIO(data))
    output = io.BytesIO()
    with source, zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as target:
        for info in source.infolist():
            payload = source.read(info)
            if info.filename == "word/document.xml":
                payload = b"<document><body>changed</body></document>"
            target.writestr(info, payload)
    return output.getvalue()


def _scan(path: Path, key: bytes) -> dict[str, object]:
    return Scanner(
        ScanConfig(logical_paths=True, optional_tools=False),
        evidence_key=key,
    ).scan([path]).to_dict()


def _integrity_codes(result: dict[str, object]) -> set[str]:
    integrity = result["integrity"]
    assert isinstance(integrity, dict)
    issues = integrity["issues"]
    assert isinstance(issues, list)
    return {str(issue["code"]) for issue in issues}


def test_receipt_binds_all_four_snapshots_without_entering_json_report(tmp_path: Path) -> None:
    key = temporary_hmac_key()
    source = tmp_path / "private-synthetic@example.test.png"
    prepared = tmp_path / "prepared.png"
    source.write_bytes(_png(b"metadata@example.test"))
    before = _scan(source, key)
    actions = create_sanitized_copy(
        source,
        prepared,
        Limits(),
        evidence_key=key,
        before_report=before,
    )
    receipts = trusted_receipts(actions)

    assert len(receipts) == 1
    receipt = receipts[0]
    assert receipt.before_content_token == receipt.transform_input_token
    assert receipt.expected_after_token != receipt.transform_input_token
    assert receipt.postscan_content_token is None
    assert receipt.exact_scan_binding is True
    assert receipt.relative_path == "artifact"
    assert receipt.preserved_facets
    assert all(facet.preserved for facet in receipt.preserved_facets)

    after = _scan(prepared, key)
    result = compare_reports(before, after, allowed_actions=actions)

    assert result["integrity"]["outcome"] == "transformed"  # type: ignore[index]
    assert receipt.postscan_content_token == receipt.expected_after_token
    serialized_actions = json.dumps(actions, ensure_ascii=False)
    assert "content_token" not in serialized_actions
    assert "metadata@example.test" not in serialized_actions
    assert str(tmp_path) not in serialized_actions


def test_receipt_rejects_source_swap_between_prescan_and_transform(tmp_path: Path) -> None:
    key = temporary_hmac_key()
    source = tmp_path / "source.png"
    prepared = tmp_path / "prepared.png"
    source.write_bytes(_png(b"first@example.test"))
    before = _scan(source, key)

    source.write_bytes(_png(b"second@example.test"))
    actions = create_sanitized_copy(
        source,
        prepared,
        Limits(),
        evidence_key=key,
        before_report=before,
    )
    result = compare_reports(before, _scan(prepared, key), allowed_actions=actions)

    assert result["outcome"] == "incomplete"
    assert result["integrity"]["outcome"] == "unverified"  # type: ignore[index]
    assert "transform_source_snapshot_mismatch" in _integrity_codes(result)


def test_receipt_rejects_output_tamper_before_postscan(tmp_path: Path) -> None:
    key = temporary_hmac_key()
    source = tmp_path / "source.png"
    prepared = tmp_path / "prepared.png"
    source.write_bytes(_png(b"metadata@example.test"))
    before = _scan(source, key)
    actions = create_sanitized_copy(
        source,
        prepared,
        Limits(),
        evidence_key=key,
        before_report=before,
    )

    prepared.write_bytes(_replace_png_pixels(prepared.read_bytes()))
    result = compare_reports(before, _scan(prepared, key), allowed_actions=actions)

    assert result["outcome"] == "incomplete"
    assert "transform_output_snapshot_mismatch" in _integrity_codes(result)


def test_plain_applied_action_cannot_forge_a_trusted_transform(tmp_path: Path) -> None:
    key = temporary_hmac_key()
    source = tmp_path / "source.png"
    prepared = tmp_path / "prepared.png"
    source.write_bytes(_png(b"metadata@example.test", pixel=b"\xff\x00\x00\xff"))
    prepared.write_bytes(_png(b"", pixel=b"\x00\xff\x00\xff"))
    forged = [{"path": "artifact", "action": "strip_png_metadata", "status": "applied"}]

    result = compare_reports(
        _scan(source, key),
        _scan(prepared, key),
        allowed_actions=forged,
    )

    assert result["outcome"] == "incomplete"
    assert "transform_receipt_missing" in _integrity_codes(result)


@pytest.mark.parametrize(
    ("suffix", "payload", "sanitizer_name", "mutator"),
    (
        (".png", lambda: _png(b"synthetic metadata"), "_sanitize_png", _replace_png_pixels),
        (".jpg", _jpeg, "_sanitize_jpeg", _replace_jpeg_scan),
        (".docx", _docx, "_sanitize_ooxml", _replace_docx_body),
    ),
    ids=("png-idat", "jpeg-scan", "ooxml-document-part"),
)
def test_receipt_rejects_accidental_protected_content_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
    payload: Callable[[], bytes],
    sanitizer_name: str,
    mutator: Callable[[bytes], bytes],
) -> None:
    key = temporary_hmac_key()
    source = tmp_path / f"source{suffix}"
    prepared = tmp_path / f"prepared{suffix}"
    source.write_bytes(payload())
    before = _scan(source, key)
    real_sanitizer = getattr(sanitize_module, sanitizer_name)

    def broken_sanitizer(*args: object, **kwargs: object):
        transformed = real_sanitizer(*args, **kwargs)
        output = mutator(transformed[0])
        return (output, *transformed[1:])

    monkeypatch.setattr(sanitize_module, sanitizer_name, broken_sanitizer)
    actions = create_sanitized_copy(
        source,
        prepared,
        Limits(),
        evidence_key=key,
        before_report=before,
    )
    result = compare_reports(before, _scan(prepared, key), allowed_actions=actions)

    assert result["outcome"] == "incomplete"
    assert "transform_preservation_failed" in _integrity_codes(result)
