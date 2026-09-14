from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile
import zlib
import xml.etree.ElementTree as ET

import pytest

from sharesafe.cli import main
from sharesafe.detectors import detect_text
from sharesafe.engine import ScanConfig, Scanner
from sharesafe.limits import Limits
from sharesafe.sanitize import (
    NORMALIZED_ZIP_TIME,
    _sanitize_jpeg,
    _sanitize_ooxml,
    _sanitize_png,
    create_sanitized_copy,
)


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def _tiff_orientation(orientation: int) -> bytes:
    # Little-endian TIFF with one SHORT Orientation entry.
    return (
        b"II"
        + struct.pack("<H", 42)
        + struct.pack("<I", 8)
        + struct.pack("<H", 1)
        + struct.pack("<HHI", 0x0112, 3, 1)
        + struct.pack("<H", orientation)
        + b"\x00\x00"
        + struct.pack("<I", 0)
    )


def _tiff_with_invalid_next_ifd() -> bytes:
    return (
        b"II"
        + struct.pack("<H", 42)
        + struct.pack("<I", 8)
        + struct.pack("<H", 0)
        + struct.pack("<I", 0xFFFFFFFE)
    )


def _tiff_with_invalid_orientation_type() -> bytes:
    return (
        b"II"
        + struct.pack("<H", 42)
        + struct.pack("<I", 8)
        + struct.pack("<H", 1)
        + struct.pack("<HHI", 0x0112, 4, 1)
        + struct.pack("<I", 6)
        + struct.pack("<I", 0)
    )


def _oriented_png(orientation: int, *extra_chunks: tuple[bytes, bytes]) -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    scanline = b"\x00\xff\x00\x00\xff"
    return b"".join(
        (
            b"\x89PNG\r\n\x1a\n",
            _png_chunk(b"IHDR", ihdr),
            _png_chunk(b"eXIf", _tiff_orientation(orientation)),
            *(_png_chunk(kind, payload) for kind, payload in extra_chunks),
            _png_chunk(b"IDAT", zlib.compress(scanline)),
            _png_chunk(b"IEND", b""),
        )
    )


def _jpeg_segment(marker: int, payload: bytes) -> bytes:
    return b"\xff" + bytes((marker,)) + struct.pack(">H", len(payload) + 2) + payload


def _multiscan_jpeg(comment: bytes) -> tuple[bytes, bytes]:
    sos = _jpeg_segment(0xDA, b"\x01\x01\x00\x00\x3f\x00")
    metadata = _jpeg_segment(0xFE, comment)
    first_scan = b"\x11\x22\xff\x00\x33\xff\xd0\x44"
    second_scan = b"\x55\xff\x00\x66"
    data = b"\xff\xd8" + sos + first_scan + metadata + sos + second_scan + b"\xff\xd9"
    return data, metadata


def _minimal_docx(
    *,
    package_comment: bytes = b"",
    part_comment: bytes = b"",
    document_xml: bytes = b"<document><body>public</body></document>",
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.comment = package_comment
        archive.writestr(
            "[Content_Types].xml",
            b'<Types><Override PartName="/word/document.xml" ContentType="application/xml"/></Types>',
        )
        info = zipfile.ZipInfo("word/document.xml")
        info.compress_type = zipfile.ZIP_DEFLATED
        info.comment = part_comment
        archive.writestr(info, document_xml)
    return output.getvalue()


def _unsafe_docx_variant(kind: str) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        if kind == "duplicate":
            with pytest.warns(UserWarning):
                archive.writestr("[Content_Types].xml", b"<Types/>")
        elif kind == "traversal":
            archive.writestr("../word/document.xml", b"<document/>")
        elif kind == "symlink":
            info = zipfile.ZipInfo("word/document.xml")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            archive.writestr(info, b"target")
        else:
            archive.writestr("word/document.xml", b"<document/>")
    data = bytearray(output.getvalue())
    if kind == "encrypted":
        # Mark the first member encrypted in both its local and central headers.
        local = data.find(b"PK\x03\x04")
        central = data.find(b"PK\x01\x02")
        assert local >= 0 and central >= 0
        struct.pack_into("<H", data, local + 6, struct.unpack_from("<H", data, local + 6)[0] | 1)
        struct.pack_into("<H", data, central + 8, struct.unpack_from("<H", data, central + 8)[0] | 1)
    return bytes(data)


def test_png_orientation_is_not_destroyed_by_metadata_removal(tmp_path: Path) -> None:
    original = _oriented_png(6)
    cleaned, removed, reason = _sanitize_png(original)

    assert cleaned == original
    assert removed == 0
    assert reason == "exif_orientation_requires_lossless_normalization"

    source = tmp_path / "oriented.png"
    output = tmp_path / "prepared.png"
    source.write_bytes(original)
    actions = create_sanitized_copy(source, output, Limits())
    assert output.read_bytes() == original
    assert any(
        item["action"] == "strip_png_metadata"
        and item["status"] == "skipped"
        and item.get("reason") == reason
        for item in actions
    )


def test_png_sanitizer_removes_exact_allowlist_when_orientation_is_neutral() -> None:
    original = _oriented_png(
        1,
        (b"tEXt", b"Comment\x00synthetic"),
        (b"zTXt", b"Comment\x00\x00" + zlib.compress(b"synthetic")),
        (b"iTXt", b"Comment\x00\x00\x00\x00\x00synthetic"),
        (b"tIME", struct.pack(">HBBBBB", 2020, 1, 2, 3, 4, 5)),
        (b"pHYs", struct.pack(">IIB", 1000, 1000, 1)),
    )

    cleaned, removed, reason = _sanitize_png(original)

    assert removed == 5 and reason is None
    for chunk_name in (b"eXIf", b"tEXt", b"zTXt", b"iTXt", b"tIME"):
        assert chunk_name not in cleaned
    assert b"pHYs" in cleaned


def test_png_sanitizer_marks_partial_when_it_retains_oriented_exif() -> None:
    original = _oriented_png(6, (b"tEXt", b"Comment\x00synthetic"))

    cleaned, removed, reason = _sanitize_png(original)

    assert removed == 1
    assert reason == "exif_orientation_requires_lossless_normalization"
    assert b"eXIf" in cleaned and b"tEXt" not in cleaned


def test_png_sanitizer_retains_truncated_exif_instead_of_assuming_it_parsed() -> None:
    truncated = _tiff_orientation(1)[:-4]
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    original = b"".join(
        (
            b"\x89PNG\r\n\x1a\n",
            _png_chunk(b"IHDR", ihdr),
            _png_chunk(b"eXIf", truncated),
            _png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00\x00")),
            _png_chunk(b"IEND", b""),
        )
    )

    cleaned, removed, reason = _sanitize_png(original)

    assert cleaned == original and removed == 0
    assert reason == "exif_orientation_requires_lossless_normalization"


@pytest.mark.parametrize(
    "malformed_tiff",
    (_tiff_with_invalid_next_ifd(), _tiff_with_invalid_orientation_type()),
    ids=("invalid-next-ifd", "invalid-orientation-type"),
)
def test_png_and_jpeg_sanitizers_retain_structurally_invalid_exif(malformed_tiff: bytes) -> None:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    png = b"".join(
        (
            b"\x89PNG\r\n\x1a\n",
            _png_chunk(b"IHDR", ihdr),
            _png_chunk(b"eXIf", malformed_tiff),
            _png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00\x00")),
            _png_chunk(b"IEND", b""),
        )
    )
    jpeg = b"\xff\xd8" + _jpeg_segment(0xE1, b"Exif\x00\x00" + malformed_tiff) + b"\xff\xd9"

    for original, sanitizer in ((png, _sanitize_png), (jpeg, _sanitize_jpeg)):
        cleaned, removed, reason = sanitizer(original)
        assert cleaned == original and removed == 0
        assert reason == "exif_orientation_requires_lossless_normalization"


def test_jpeg_metadata_between_scans_is_detected_and_removed(tmp_path: Path) -> None:
    email = b"progressive" + b"@example.test"
    original, metadata = _multiscan_jpeg(email)

    sample = tmp_path / "image.jpg"
    sample.write_bytes(original)
    report = Scanner(ScanConfig(optional_tools=False)).scan([sample]).to_dict()
    rules = {item["rule_id"] for item in report["findings"]}
    assert {"SS-IMAGE-JPEG-COMMENT", "pii.email"} <= rules
    assert email.decode() not in json.dumps(report)

    cleaned, removed, reason = _sanitize_jpeg(original)
    assert cleaned == original.replace(metadata, b"", 1)
    assert removed == 1
    assert reason is None


def test_jpeg_sanitizer_removes_declared_segments_and_retains_unlisted_app(tmp_path: Path) -> None:
    exif = _jpeg_segment(0xE1, b"Exif\x00\x00" + _tiff_orientation(1))
    xmp = _jpeg_segment(0xE1, b"http://ns.adobe.com/xap/1.0/\x00synthetic packet")
    unrelated_app1 = _jpeg_segment(0xE1, b"contains-xmp-text-but-is-not-a-standard-xmp-packet")
    app13 = _jpeg_segment(0xED, b"synthetic photoshop metadata")
    comment = _jpeg_segment(0xFE, b"synthetic comment")
    retained_app2 = _jpeg_segment(0xE2, b"ICC_PROFILE\x00synthetic")
    sos = _jpeg_segment(0xDA, b"\x01\x01\x00\x00\x3f\x00")
    scan_data = b"\x11\x22\xff\x00\x33"
    original = (
        b"\xff\xd8" + retained_app2 + unrelated_app1 + exif + xmp + app13 + comment + sos + scan_data + b"\xff\xd9"
    )

    cleaned, removed, reason = _sanitize_jpeg(original)

    assert removed == 4 and reason is None
    assert retained_app2 in cleaned and unrelated_app1 in cleaned
    assert exif not in cleaned and xmp not in cleaned and app13 not in cleaned and comment not in cleaned
    assert sos + scan_data + b"\xff\xd9" in cleaned

    sample = tmp_path / "xmp.jpg"
    sample.write_bytes(original)
    report = Scanner(ScanConfig(optional_tools=False)).scan([sample]).to_dict()
    assert [item["rule_id"] for item in report["findings"]].count("SS-IMAGE-JPEG-XMP") == 1


def test_jpeg_sanitizer_marks_partial_when_it_retains_oriented_exif() -> None:
    exif = _jpeg_segment(0xE1, b"Exif\x00\x00" + _tiff_orientation(6))
    comment = _jpeg_segment(0xFE, b"synthetic comment")
    original = b"\xff\xd8" + exif + comment + b"\xff\xd9"

    cleaned, removed, reason = _sanitize_jpeg(original)

    assert removed == 1
    assert reason == "exif_orientation_requires_lossless_normalization"
    assert exif in cleaned and comment not in cleaned


def test_ooxml_sanitizer_enforces_documented_property_and_zip_allowlist() -> None:
    core_fields = {
        "creator", "lastModifiedBy", "title", "subject", "description", "keywords",
        "category", "identifier", "created", "modified", "lastPrinted", "revision",
        "contentStatus", "language", "version",
    }
    app_fields = {"Manager", "Company", "Template", "HyperlinkBase", "Application", "AppVersion"}
    core_xml = (
        '<p:coreProperties xmlns:p="urn:synthetic">'
        + "".join(f"<p:{name}>synthetic</p:{name}>" for name in sorted(core_fields))
        + "<p:retained>public</p:retained></p:coreProperties>"
    ).encode()
    app_xml = (
        '<p:Properties xmlns:p="urn:synthetic">'
        + "".join(f"<p:{name}>synthetic</p:{name}>" for name in sorted(app_fields))
        + "<p:Retained>public</p:Retained></p:Properties>"
    ).encode()
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.comment = b"synthetic package comment"
        archive.writestr(
            "[Content_Types].xml",
            b'<Types><Override PartName="/docProps/custom.xml" ContentType="synthetic"/>'
            b'<Override PartName="/word/document.xml" ContentType="application/xml"/></Types>',
        )
        archive.writestr(
            "_rels/.rels",
            b'<Relationships><Relationship Type="urn:custom-properties" '
            b'Target="docProps/custom.xml"/></Relationships>',
        )
        archive.writestr("docProps/core.xml", core_xml)
        archive.writestr("docProps/app.xml", app_xml)
        archive.writestr("docProps/custom.xml", b"<Properties/>")
        body = zipfile.ZipInfo("word/document.xml", date_time=(2024, 1, 2, 3, 4, 6))
        body.compress_type = zipfile.ZIP_DEFLATED
        body.comment = b"synthetic member comment"
        body.extra = b"\xfe\xca\x00\x00"
        archive.writestr(body, b"<document><body>public</body></document>")

    cleaned, status, reason = _sanitize_ooxml(package.getvalue(), "sample.docx", Limits())

    assert status == "applied" and reason is None
    with zipfile.ZipFile(io.BytesIO(cleaned)) as archive:
        assert archive.comment == b""
        assert "docProps/custom.xml" not in archive.namelist()
        assert b"custom.xml" not in archive.read("[Content_Types].xml")
        assert b"custom-properties" not in archive.read("_rels/.rels")
        for name, removed_fields, retained in (
            ("docProps/core.xml", core_fields, "retained"),
            ("docProps/app.xml", app_fields, "Retained"),
        ):
            root = ET.fromstring(archive.read(name))
            local_names = {child.tag.rsplit("}", 1)[-1] for child in root}
            assert removed_fields.isdisjoint(local_names)
            assert retained in local_names
        body_info = archive.getinfo("word/document.xml")
        assert body_info.date_time == NORMALIZED_ZIP_TIME
        assert body_info.comment == b"" and body_info.extra == b""
        assert (body_info.external_attr >> 16) & 0o777 == 0o600
        assert archive.read(body_info) == b"<document><body>public</body></document>"


def test_ooxml_property_rewrite_preserves_comments_and_processing_instructions(
    tmp_path: Path,
) -> None:
    email = "xml-comment" + "@example.test"
    core_xml = (
        b'<c:coreProperties xmlns:c="urn:core">'
        + f"<!--{email}-->".encode()
        + b"<?sharesafe retain?>"
        + b"<c:creator>Synthetic Author</c:creator>"
        + b"<c:retained>public</c:retained>"
        + b"</c:coreProperties>"
    )
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/document.xml", b"<document><body>public</body></document>")
        archive.writestr("docProps/core.xml", core_xml)
    source = tmp_path / "comments.docx"
    output = tmp_path / "prepared.docx"
    source.write_bytes(package.getvalue())

    before = Scanner(ScanConfig(optional_tools=False)).scan([source]).to_dict()
    actions = create_sanitized_copy(source, output, Limits())
    after = Scanner(ScanConfig(optional_tools=False)).scan([output]).to_dict()

    assert "pii.email" in {item["rule_id"] for item in before["findings"]}
    assert "pii.email" in {item["rule_id"] for item in after["findings"]}
    assert email not in json.dumps(before) and email not in json.dumps(after)
    assert any(item["action"] == "remove_ooxml_metadata" and item["status"] == "applied" for item in actions)
    with zipfile.ZipFile(output) as archive:
        rewritten = archive.read("docProps/core.xml")
        assert email.encode() in rewritten
        assert b"<!--" in rewritten and b"<?sharesafe retain?>" in rewritten
        assert b"Synthetic Author" not in rewritten and b"public" in rewritten


def test_ooxml_sanitizer_rewrites_non_normalized_member_permissions() -> None:
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w") as archive:
        for name, payload, mode in (
            ("[Content_Types].xml", b"<Types/>", 0o600),
            ("word/document.xml", b"<document><body>public</body></document>", 0o644),
        ):
            info = zipfile.ZipInfo(name, date_time=NORMALIZED_ZIP_TIME)
            info.create_system = 3
            info.external_attr = mode << 16
            archive.writestr(info, payload)
    original = package.getvalue()

    cleaned, status, reason = _sanitize_ooxml(original, "sample.docx", Limits())

    assert cleaned != original and status == "applied" and reason is None
    with zipfile.ZipFile(io.BytesIO(cleaned)) as archive:
        assert (archive.getinfo("word/document.xml").external_attr >> 16) & 0o777 == 0o600


def test_ooxml_sanitizer_retains_custom_typed_relationship_to_other_part() -> None:
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/document.xml", b"<document><body>public</body></document>")
        archive.writestr("word/other.xml", b"<other>public</other>")
        archive.writestr(
            "word/_rels/document.xml.rels",
            b'<Relationships><Relationship Type="urn:custom-properties" '
            b'Target="other.xml"/></Relationships>',
        )

    cleaned, status, reason = _sanitize_ooxml(package.getvalue(), "sample.docx", Limits())

    assert status == "applied" and reason is None
    with zipfile.ZipFile(io.BytesIO(cleaned)) as archive:
        relationship = archive.read("word/_rels/document.xml.rels")
        assert b' Type="urn:custom-properties"' in relationship
        assert b'Target="other.xml"' in relationship
        assert archive.read("word/other.xml") == b"<other>public</other>"


def test_ooxml_sanitizer_resolves_relationship_targets_from_their_source_part() -> None:
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            b'<Types><Override PartName="/docProps/custom.xml" ContentType="synthetic"/></Types>',
        )
        archive.writestr("word/document.xml", b"<document><body>public</body></document>")
        archive.writestr("docProps/custom.xml", b"<Properties/>")
        archive.writestr("word/docProps/custom.xml", b"<local>retain</local>")
        archive.writestr(
            "_rels/.rels",
            b'<Relationships><Relationship Id="root" Target="docProps/custom.xml"/></Relationships>',
        )
        archive.writestr(
            "word/_rels/document.xml.rels",
            b'<Relationships>'
            b'<Relationship Id="local" Target="docProps/custom.xml"/>'
            b'<Relationship Id="root-from-part" Target="../docProps/custom.xml"/>'
            b'<Relationship Id="external" TargetMode="External" '
            b'Target="https://example.test/docProps/custom.xml"/>'
            b'</Relationships>',
        )

    cleaned, status, reason = _sanitize_ooxml(package.getvalue(), "sample.docx", Limits())

    assert status == "applied" and reason is None
    with zipfile.ZipFile(io.BytesIO(cleaned)) as archive:
        assert "docProps/custom.xml" not in archive.namelist()
        assert archive.read("word/docProps/custom.xml") == b"<local>retain</local>"
        assert list(ET.fromstring(archive.read("_rels/.rels"))) == []
        relationships = ET.fromstring(archive.read("word/_rels/document.xml.rels"))
        remaining_ids = {element.attrib["Id"] for element in relationships}
        assert remaining_ids == {"local", "external"}


def test_ooxml_sanitizer_skips_vbadata_macro_signal() -> None:
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/document.xml", b"<document><body>public</body></document>")
        archive.writestr("word/vbaData.xml", b"<vbaData/>")
    original = package.getvalue()

    cleaned, status, reason = _sanitize_ooxml(original, "sample.docx", Limits())

    assert cleaned == original and status == "skipped" and reason == "macro_enabled_document"


def test_ooxml_sanitizer_skips_zip_disguised_as_docx() -> None:
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("unrelated/data.xml", b"<data>public</data>")
    original = package.getvalue()

    cleaned, status, reason = _sanitize_ooxml(original, "sample.docx", Limits())

    assert cleaned == original and status == "skipped" and reason == "ooxml_type_mismatch"


def test_ooxml_sanitizer_skips_custom_location_digital_signature(tmp_path: Path) -> None:
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.comment = b"would otherwise be removed"
        archive.writestr(
            "[Content_Types].xml",
            b'<Types>'
            b'<Override PartName="/word/document.xml" ContentType="application/xml"/>'
            b'<Override PartName="/signatures/origin.sigs" '
            b'ContentType="application/vnd.openxmlformats-package.digital-signature-origin"/>'
            b'</Types>',
        )
        archive.writestr(
            "_rels/.rels",
            b'<Relationships><Relationship '
            b'Type="http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin" '
            b'Target="signatures/origin.sigs"/></Relationships>',
        )
        archive.writestr("word/document.xml", b"<document><body>public</body></document>")
        archive.writestr("signatures/origin.sigs", b"")
    original = package.getvalue()

    cleaned, status, reason = _sanitize_ooxml(original, "sample.docx", Limits())

    assert cleaned == original and status == "skipped" and reason == "digitally_signed_document"
    sample = tmp_path / "signed.docx"
    sample.write_bytes(original)
    report = Scanner(ScanConfig(optional_tools=False)).scan([sample]).to_dict()
    assert "SS-OOXML-DIGITAL-SIGNATURE" in {item["rule_id"] for item in report["findings"]}


def test_compound_ooxml_container_is_copied_with_a_skipped_transform(tmp_path: Path) -> None:
    original = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"synthetic compound package"
    source = tmp_path / "encrypted.docx"
    output = tmp_path / "prepared.docx"
    source.write_bytes(original)

    actions = create_sanitized_copy(source, output, Limits())

    assert output.read_bytes() == original
    assert any(
        item["action"] == "remove_ooxml_metadata"
        and item["status"] == "skipped"
        and item.get("reason") == "encrypted_or_compound_ooxml_container"
        for item in actions
    )


def test_real_progressive_jpeg_keeps_pixels_while_removing_late_comment() -> None:
    image_module = pytest.importorskip("PIL.Image")
    image = image_module.new("RGB", (8, 8), (20, 40, 60))
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", progressive=True)
    base = buffer.getvalue()
    comment = _jpeg_segment(0xFE, b"late" + b"@example.test")
    original = base[:-2] + comment + base[-2:]

    cleaned, removed, reason = _sanitize_jpeg(original)
    assert cleaned == base
    assert removed == 1 and reason is None
    with image_module.open(io.BytesIO(original)) as before_image:
        before_pixels = before_image.convert("RGB").tobytes()
    with image_module.open(io.BytesIO(cleaned)) as after_image:
        assert after_image.convert("RGB").tobytes() == before_pixels


def test_python_type_annotations_are_not_credentials() -> None:
    annotations = """
def probe(token: bytes, password: str, secret: object) -> bool:
    api_key: Optional[str] = None
    token = content_hmac_token(data, evidence_key)
    return False
"""
    assert "secret.credential_assignment" not in {hit.rule_id for hit in detect_text(annotations)}
    assert "secret.credential_assignment" in {
        hit.rule_id for hit in detect_text('token: "sYnthetic-Only-987!"')
    }


def test_logical_comparison_paths_do_not_hide_filename_pii(tmp_path: Path) -> None:
    email = "filename" + "@example.test"
    sample = tmp_path / f"release-{email}.txt"
    sample.write_text("public", encoding="utf-8")

    report = Scanner(ScanConfig(logical_paths=True, optional_tools=False)).scan([sample]).to_dict()

    assert report["artifacts"][0]["path"] == "artifact"
    assert "SS-GEN-PII-FILENAME" in {item["rule_id"] for item in report["findings"]}
    assert email not in json.dumps(report)


def test_reports_use_keyed_content_tokens_instead_of_raw_file_digests(tmp_path: Path) -> None:
    raw = b"low-entropy" + b"@example.test"
    sample = tmp_path / "small.txt"
    sample.write_bytes(raw)
    first = Scanner(evidence_key=b"A" * 32).scan([sample]).to_dict()
    repeated = Scanner(evidence_key=b"A" * 32).scan([sample]).to_dict()
    another_run = Scanner(evidence_key=b"B" * 32).scan([sample]).to_dict()

    artifact = first["artifacts"][0]
    assert "sha256" not in artifact
    assert artifact["content_token"].startswith("hmac-sha256:content-v1:")
    assert artifact["content_token"] == repeated["artifacts"][0]["content_token"]
    assert artifact["content_token"] != another_run["artifacts"][0]["content_token"]
    assert artifact["id"] == another_run["artifacts"][0]["id"]
    assert hashlib.sha256(raw).hexdigest() not in json.dumps(first)


def test_ooxml_package_and_part_comments_are_scanned_masked_and_removed(tmp_path: Path) -> None:
    email = "comment" + "@example.test"
    source = tmp_path / "comments.docx"
    output = tmp_path / "prepared.docx"
    source.write_bytes(
        _minimal_docx(package_comment=email.encode(), part_comment=email.encode())
    )

    report = Scanner(ScanConfig(optional_tools=False)).scan([source]).to_dict()
    rules = {item["rule_id"] for item in report["findings"]}
    assert {"SS-OOXML-PACKAGE-COMMENT", "SS-OOXML-PART-COMMENT", "pii.email"} <= rules
    assert email not in json.dumps(report)

    actions = create_sanitized_copy(source, output, Limits())
    assert any(
        item["action"] == "remove_ooxml_metadata" and item["status"] == "applied"
        for item in actions
    )
    with zipfile.ZipFile(output) as archive:
        assert archive.comment == b""
        assert all(info.comment == b"" for info in archive.infolist())


def test_ooxml_sanitizer_enforces_compression_ratio_without_expanding(tmp_path: Path) -> None:
    original = _minimal_docx(document_xml=b"<document>" + b"A" * (2 * 1024 * 1024) + b"</document>")
    source = tmp_path / "compressed.docx"
    output = tmp_path / "prepared.docx"
    source.write_bytes(original)

    actions = create_sanitized_copy(source, output, Limits(max_compression_ratio=1))
    assert output.read_bytes() == original
    assert any(
        item["action"] == "remove_ooxml_metadata"
        and item["status"] == "skipped"
        and item.get("reason") == "package_resource_limit"
        for item in actions
    )


@pytest.mark.parametrize("kind", ("duplicate", "traversal", "symlink", "encrypted"))
def test_ooxml_sanitizer_refuses_ambiguous_or_unsafe_packages(kind: str) -> None:
    original = _unsafe_docx_variant(kind)
    cleaned, status, reason = _sanitize_ooxml(original, "sample.docx", Limits())
    assert cleaned == original
    assert status == "skipped"
    assert reason == "unsafe_or_ambiguous_package_structure"


@pytest.mark.parametrize(
    ("kind", "rule"),
    (
        ("duplicate", "SS-OOXML-DUPLICATE-PART"),
        ("traversal", "SS-ARCHIVE-PATH-TRAVERSAL"),
        ("symlink", "SS-OOXML-SYMLINK-PART"),
        ("encrypted", "SS-OOXML-ENCRYPTED-PART"),
    ),
)
def test_ooxml_scanner_marks_unsafe_package_structures_incomplete(
    kind: str, rule: str, tmp_path: Path
) -> None:
    sample = tmp_path / f"{kind}.docx"
    sample.write_bytes(_unsafe_docx_variant(kind))

    report = Scanner(ScanConfig(optional_tools=False)).scan([sample]).to_dict()

    assert report["summary"]["verdict"] == "incomplete"
    assert rule in {item["rule_id"] for item in report["findings"]}


def test_skipped_ooxml_transform_makes_cli_result_incomplete(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "ambiguous.docx"
    output = tmp_path / "prepared.docx"
    source.write_bytes(_unsafe_docx_variant("duplicate"))

    code = main(["sanitize", str(source), "--out", str(output), "--json", "--no-optional-tools"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 2
    assert payload["verification"]["outcome"] == "incomplete"
    assert payload["verification"]["ready_for_review"] is False
    assert "transform_skipped" in {
        item["code"] for item in payload["verification"]["integrity"]["issues"]
    }


def test_unsupported_plain_zip_transform_cannot_look_successful(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w") as archive:
        info = zipfile.ZipInfo("notes.txt", date_time=(2000, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, b"public")
    source = tmp_path / "source.zip"
    output = tmp_path / "prepared.zip"
    source.write_bytes(package.getvalue())

    code = main(["sanitize", str(source), "--out", str(output), "--json", "--no-optional-tools"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 2
    assert output.read_bytes() == source.read_bytes()
    assert payload["before"]["summary"]["verdict"] == "no_findings"
    assert payload["after"]["summary"]["verdict"] == "no_findings"
    assert payload["verification"]["outcome"] == "incomplete"
    assert any(
        item["code"] == "transform_unsupported"
        for item in payload["verification"]["integrity"]["issues"]
    )


def test_ooxml_dtd_after_long_prefix_is_never_expanded_or_rewritten(tmp_path: Path) -> None:
    xml = b" " * 5000 + b"<!DOCTYPE x [<!ENTITY e 'hidden'>]><document>&e;</document>"
    original = _minimal_docx(document_xml=xml)
    sample = tmp_path / "unsafe.docx"
    sample.write_bytes(original)

    report = Scanner(ScanConfig(optional_tools=False)).scan([sample]).to_dict()
    assert any(gap["reason"] == "xml_parse_error" for gap in report["gaps"])

    core_package = io.BytesIO()
    with zipfile.ZipFile(core_package, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/document.xml", b"<document/>")
        archive.writestr("docProps/core.xml", xml)
    unsafe_core = core_package.getvalue()
    cleaned, status, reason = _sanitize_ooxml(unsafe_core, "unsafe.docx", Limits())
    assert cleaned == unsafe_core
    assert status == "skipped" and reason == "package_rewrite_error"


@pytest.mark.parametrize(
    "document_xml",
    (
        b"<document><unclosed></document>",
        b" " * 5000 + b"<!DOCTYPE x [<!ENTITY e 'hidden'>]><document>&e;</document>",
    ),
    ids=("parse-error", "forbidden-dtd"),
)
def test_ooxml_sanitizer_preflights_every_xml_part(document_xml: bytes) -> None:
    original = _minimal_docx(package_comment=b"would otherwise be removed", document_xml=document_xml)

    cleaned, status, reason = _sanitize_ooxml(original, "sample.docx", Limits())

    assert cleaned == original and status == "skipped" and reason == "package_rewrite_error"


def test_pdf_sanitize_is_explicitly_audit_only(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pdf = (
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Author (Synthetic Author) >>\n"
        b"endobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
    )
    source = tmp_path / "source.pdf"
    output = tmp_path / "prepared.pdf"
    source.write_bytes(pdf)

    code = main(["sanitize", str(source), "--out", str(output), "--json", "--no-optional-tools"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 2
    assert output.read_bytes() == pdf
    assert payload["after"]["summary"]["verdict"] == "incomplete"
    assert any(
        item["action"] == "use_specialized_pdf_tool_on_a_copy"
        and item["status"] == "unsupported"
        and item.get("reason") == "v0.1_does_not_rewrite_pdf"
        for item in payload["actions"]
    )
    assert any(
        item["rule_id"] == "SS-PDF-METADATA-AUTHOR"
        and item["remediation"]["supported"] is False
        and item["remediation"]["action"] == "use_specialized_pdf_tool_on_a_copy"
        for item in payload["after"]["findings"]
    )
