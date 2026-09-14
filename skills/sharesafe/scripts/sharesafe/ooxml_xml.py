"""Shared, conservative OOXML XML parsing helpers."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET


_FORBIDDEN_XML_DECLARATION = re.compile(br"<!\s*(?:DOCTYPE|ENTITY)\b", re.I)
_SIGNATURE_MARKERS = ("digital-signature", "xmlsignature", "xmldsig")
_MACRO_MARKERS = ("macroenabled", "vbaproject", "vbadata")
_EMBEDDED_VALUE_MARKERS = ("oleobject", "activex", "embeddedpackage")
_EMBEDDED_RELATIONSHIP_SUFFIXES = ("/relationships/package", "/relationships/control")


def parse_xml(data: bytes) -> ET.Element:
    """Parse bounded package XML without entities while retaining comments and PIs."""

    # Removing NUL code units exposes the XML declaration vocabulary in
    # UTF-16/UTF-32 byte streams as well as UTF-8.  XML grammar keywords
    # cannot be character references, so this closes encoding-based DTD and
    # entity-expansion bypasses before ElementTree sees the document.
    if _FORBIDDEN_XML_DECLARATION.search(data.replace(b"\x00", b"")):
        raise ValueError("DTD or entity declaration is not allowed")
    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True, insert_pis=True))
    return ET.fromstring(data, parser=parser)


def local_name(tag: object) -> str:
    """Return an XML local name, ignoring comment and processing-instruction nodes."""

    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def declares_digital_signature(root: ET.Element) -> bool:
    """Recognize OPC signature relationship/content-type identifiers."""

    for element in root.iter():
        for value in element.attrib.values():
            folded = str(value).casefold()
            if any(marker in folded for marker in _SIGNATURE_MARKERS):
                return True
    return False


def declares_macros(root: ET.Element) -> bool:
    """Recognize macro/VBA declarations independent of package part names."""

    for element in root.iter():
        for value in element.attrib.values():
            folded = str(value).casefold()
            if any(marker in folded for marker in _MACRO_MARKERS):
                return True
    return False


def declares_embedded_object(root: ET.Element) -> bool:
    """Recognize OLE/package/ActiveX declarations without trusting part names."""

    for element in root.iter():
        if local_name(element.tag).casefold() in {"oleobj", "oleobject", "control"}:
            return True
        for value in element.attrib.values():
            folded = str(value).casefold().rstrip("/")
            if any(marker in folded for marker in _EMBEDDED_VALUE_MARKERS):
                return True
            if any(folded.endswith(suffix) for suffix in _EMBEDDED_RELATIONSHIP_SUFFIXES):
                return True
    return False


__all__ = [
    "declares_digital_signature",
    "declares_embedded_object",
    "declares_macros",
    "local_name",
    "parse_xml",
]
