from __future__ import annotations

import io
from pathlib import Path
import zipfile

import pytest

from sharesafe.engine import ScanConfig, Scanner
from sharesafe.limits import Limits
from sharesafe.sanitize import (
    _clean_properties_xml,
    _remove_custom_property_reference,
    _sanitize_ooxml,
)


_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _docx(parts: dict[str, bytes]) -> bytes:
    content = {
        "[Content_Types].xml": (
            b'<Types><Override PartName="/word/document.xml" '
            b'ContentType="application/xml"/></Types>'
        ),
        "word/document.xml": b"<document><body>public</body></document>",
    }
    content.update(parts)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in content.items():
            archive.writestr(name, payload)
    return output.getvalue()


def _scan_package(tmp_path: Path, package: bytes, name: str = "sample.docx") -> dict:
    sample = tmp_path / name
    sample.write_bytes(package)
    return Scanner(ScanConfig(optional_tools=False)).scan([sample]).to_dict()


@pytest.mark.parametrize("encoding", ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"))
def test_encoded_dtd_is_rejected_before_ooxml_parsing(
    encoding: str, tmp_path: Path,
) -> None:
    xml = "<!DOCTYPE d [<!ENTITY e 'synthetic'>]><document>&e;</document>".encode(encoding)
    package = _docx({"word/document.xml": xml})

    report = _scan_package(tmp_path, package, f"unsafe-{encoding}.docx")
    cleaned, status, reason = _sanitize_ooxml(package, "sample.docx", Limits())

    assert report["summary"]["verdict"] == "incomplete"
    assert any(gap["reason"] == "xml_parse_error" for gap in report["gaps"])
    assert cleaned == package
    assert status == "skipped" and reason == "package_rewrite_error"


def test_malformed_relationship_text_is_still_scanned(tmp_path: Path) -> None:
    email = "relationship" + "@example.test"
    relationship = (
        f'<Relationships><Relationship Target="mailto:{email}"></Relationships>'
    ).encode()
    report = _scan_package(tmp_path, _docx({"word/_rels/document.xml.rels": relationship}))

    assert report["summary"]["verdict"] == "incomplete"
    assert any(gap["reason"] == "xml_parse_error" for gap in report["gaps"])
    assert "pii.email" in {finding["rule_id"] for finding in report["findings"]}
    assert email not in str(report)


def test_macro_declaration_at_custom_paths_is_detected_and_blocks_rewrite(
    tmp_path: Path,
) -> None:
    content_types = (
        b'<Types><Override PartName="/word/document.xml" ContentType="application/xml"/>'
        b'<Override PartName="/unusual/payload.bin" '
        b'ContentType="application/vnd.ms-office.vbaProject"/></Types>'
    )
    package = _docx({
        "[Content_Types].xml": content_types,
        "unusual/payload.bin": b"synthetic macro placeholder",
    })

    report = _scan_package(tmp_path, package)
    cleaned, status, reason = _sanitize_ooxml(package, "sample.docx", Limits())

    assert "SS-OOXML-MACRO" in {finding["rule_id"] for finding in report["findings"]}
    assert any(gap["reason"] == "macro_not_analyzed" for gap in report["gaps"])
    assert cleaned == package
    assert status == "skipped" and reason == "macro_enabled_document"


@pytest.mark.parametrize("signal", ("declaration", "compound-magic"))
def test_embedded_objects_at_custom_paths_are_explicit_and_not_rewritten(
    signal: str, tmp_path: Path,
) -> None:
    if signal == "declaration":
        content_types = (
            b'<Types><Override PartName="/word/document.xml" ContentType="application/xml"/>'
            b'<Override PartName="/unusual/payload.bin" '
            b'ContentType="application/vnd.openxmlformats-officedocument.oleObject"/></Types>'
        )
        parts = {
            "[Content_Types].xml": content_types,
            "unusual/payload.bin": b"synthetic opaque placeholder",
        }
    else:
        parts = {"unusual/payload.bin": _OLE_MAGIC + b"synthetic compound placeholder"}
    package = _docx(parts)

    report = _scan_package(tmp_path, package)
    cleaned, status, reason = _sanitize_ooxml(package, "sample.docx", Limits())

    assert "SS-OOXML-EMBEDDED-OBJECT" in {
        finding["rule_id"] for finding in report["findings"]
    }
    assert any("embedded_object" in gap["reason"] for gap in report["gaps"])
    assert report["summary"]["verdict"] == "incomplete"
    assert cleaned == package
    assert status == "skipped" and reason == "embedded_object_not_supported"


def test_removed_property_element_keeps_following_text() -> None:
    original = (
        b'<core xmlns:dc="urn:dc"><dc:creator>Synthetic</dc:creator>'
        b'KEEP-TAIL<other>public</other></core>'
    )

    cleaned, changed = _clean_properties_xml(original, "core")

    assert changed is True
    assert b"Synthetic" not in cleaned
    assert b"KEEP-TAIL" in cleaned


def test_removed_relationship_element_keeps_following_text() -> None:
    original = (
        b'<Relationships><Relationship Target="docProps/custom.xml"/>'
        b'KEEP-TAIL<Relationship Target="public.xml"/></Relationships>'
    )

    cleaned, changed = _remove_custom_property_reference(
        original,
        content_types=False,
        relationship_part="_rels/.rels",
    )

    assert changed is True
    assert b"docProps/custom.xml" not in cleaned
    assert b"KEEP-TAIL" in cleaned


def test_all_sanitized_core_and_app_fields_are_detected_before_rewrite(
    tmp_path: Path,
) -> None:
    core = (
        b'<cp:coreProperties xmlns:cp="urn:cp" xmlns:dcterms="urn:dcterms">'
        b'<cp:revision>7</cp:revision><dcterms:created>2026-01-01</dcterms:created>'
        b'</cp:coreProperties>'
    )
    app = b"<Properties><HyperlinkBase>C:/synthetic/private</HyperlinkBase></Properties>"
    report = _scan_package(tmp_path, _docx({"docProps/core.xml": core, "docProps/app.xml": app}))
    rules = {finding["rule_id"] for finding in report["findings"]}

    assert {
        "SS-OOXML-CORE-REVISION",
        "SS-OOXML-CORE-CREATED",
        "SS-OOXML-APP-HYPERLINK-BASE",
    } <= rules


def test_ooxml_comments_share_one_cumulative_text_budget(tmp_path: Path) -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.comment = b"public"
        content_type = zipfile.ZipInfo("[Content_Types].xml")
        content_type.comment = b"public"
        archive.writestr(content_type, b"<Types/>")
        document = zipfile.ZipInfo("word/document.xml")
        document.comment = b"public"
        archive.writestr(document, b"<document/>")
    sample = tmp_path / "comments.docx"
    sample.write_bytes(output.getvalue())
    report = Scanner(
        ScanConfig(limits=Limits(max_text_bytes=8), optional_tools=False)
    ).scan([sample]).to_dict()

    gaps = [gap for gap in report["gaps"] if gap["reason"] == "ooxml_comment_text_limit"]
    assert len(gaps) == 1
    assert report["summary"]["verdict"] == "incomplete"
