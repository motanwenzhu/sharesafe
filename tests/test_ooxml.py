from __future__ import annotations

import io
from pathlib import Path
import zipfile

from sharesafe.engine import Scanner
from sharesafe.limits import Limits
from sharesafe.sanitize import create_sanitized_copy


CONTENT_TYPES = b'''<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Override PartName="/word/document.xml" ContentType="application/xml"/>
  <Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/>
</Types>'''


def _word_package(*, macro: bool = False) -> bytes:
    email_left = "reviewer"
    email_right = "@example.test"
    parts: dict[str, bytes] = {
        "[Content_Types].xml": CONTENT_TYPES,
        "_rels/.rels": b'''<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="r1" Type="http://example.test/external" Target="https://example.test/data" TargetMode="External"/>
          <Relationship Id="r2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties" Target="docProps/custom.xml"/>
        </Relationships>''',
        "docProps/core.xml": b'''<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Synthetic Author</dc:creator><cp:lastModifiedBy>Synthetic Editor</cp:lastModifiedBy></cp:coreProperties>''',
        "docProps/app.xml": b'''<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Company>Synthetic Org</Company><Application>Synthetic Writer</Application></Properties>''',
        "docProps/custom.xml": b'''<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"><property name="Internal"><value>Synthetic</value></property></Properties>''',
        "word/document.xml": f'''<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>{email_left}</w:t></w:r><w:r><w:t>{email_right}</w:t></w:r><w:ins><w:r><w:t>revision</w:t></w:r></w:ins></w:p></w:body></w:document>'''.encode(),
        "word/comments.xml": b'''<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:comment w:author="Synthetic Reviewer"><w:p><w:r><w:t>private note</w:t></w:r></w:p></w:comment></w:comments>''',
    }
    if macro:
        parts["word/vbaProject.bin"] = b"synthetic macro bytes"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in parts.items():
            archive.writestr(name, data)
    return output.getvalue()


def _xlsx_hidden_package() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr(
            "xl/workbook.xml",
            b'''<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Hidden" sheetId="1" state="veryHidden"/></sheets></workbook>''',
        )
        archive.writestr(
            "xl/worksheets/sheet1.xml",
            b'''<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1" hidden="1"><c r="A1"><v>1</v></c></row></sheetData></worksheet>''',
        )
    return output.getvalue()


def _rules(report: dict[str, object]) -> set[str]:
    return {item["rule_id"] for item in report["findings"]}  # type: ignore[index]


def test_word_hidden_content_metadata_links_and_split_pii(tmp_path: Path) -> None:
    sample = tmp_path / "review.docx"
    sample.write_bytes(_word_package())

    report = Scanner().scan([sample]).to_dict()
    rules = _rules(report)

    assert {
        "SS-OOXML-CORE-CREATOR",
        "SS-OOXML-COMMENTS",
        "SS-OOXML-TRACKED-CHANGES",
        "SS-OOXML-EXTERNAL-RELATIONSHIP",
        "SS-OOXML-CUSTOM-PROPERTIES",
        "pii.email",
    } <= rules
    assert "reviewer@example.test" not in str(report)


def test_excel_hidden_sheet_rows_and_columns(tmp_path: Path) -> None:
    sample = tmp_path / "hidden.xlsx"
    sample.write_bytes(_xlsx_hidden_package())

    report = Scanner().scan([sample]).to_dict()

    assert {"SS-OOXML-HIDDEN-SHEET", "SS-OOXML-HIDDEN-ROWS-COLUMNS"} <= _rules(report)


def test_ooxml_sanitize_removes_properties_but_leaves_editorial_content(tmp_path: Path) -> None:
    source = tmp_path / "source.docx"
    output = tmp_path / "prepared.docx"
    source.write_bytes(_word_package())
    original_bytes = source.read_bytes()
    original_mtime = source.stat().st_mtime_ns

    actions = create_sanitized_copy(source, output, Limits())

    assert source.read_bytes() == original_bytes
    assert source.stat().st_mtime_ns == original_mtime
    assert output.exists()
    assert any(item["action"] == "remove_ooxml_metadata" and item["status"] == "applied" for item in actions)
    with zipfile.ZipFile(output) as archive:
        assert "docProps/custom.xml" not in archive.namelist()
        assert b"Synthetic Author" not in archive.read("docProps/core.xml")
        assert b"Synthetic Org" not in archive.read("docProps/app.xml")
        assert b"custom-properties" not in archive.read("_rels/.rels")
    after_rules = _rules(Scanner().scan([output]).to_dict())
    assert "SS-OOXML-CORE-CREATOR" not in after_rules
    assert "SS-OOXML-CUSTOM-PROPERTIES" not in after_rules
    assert {"SS-OOXML-COMMENTS", "SS-OOXML-TRACKED-CHANGES", "pii.email"} <= after_rules


def test_macro_document_is_not_rewritten(tmp_path: Path) -> None:
    source = tmp_path / "macro.docm"
    output = tmp_path / "macro-copy.docm"
    source.write_bytes(_word_package(macro=True))

    actions = create_sanitized_copy(source, output, Limits())

    assert output.read_bytes() == source.read_bytes()
    assert any(item.get("reason") == "macro_enabled_document" and item["status"] == "skipped" for item in actions)
    report = Scanner().scan([output]).to_dict()
    assert "SS-OOXML-MACRO" in _rules(report)
    assert report["summary"]["verdict"] == "incomplete"
