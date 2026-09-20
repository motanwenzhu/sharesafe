"""Process-local receipts for byte-bound metadata transformations.

Receipts deliberately are not dictionaries and are not included in ShareSafe's
shareable JSON reports.  They bind one sanitizer invocation to the pre-scan and
post-scan content tokens while retaining only keyed, run-scoped format facet
tokens.  A plain action record, including one loaded from JSON, is never a
trusted receipt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import io
import json
from pathlib import PurePosixPath
import secrets
import struct
from typing import Any, Iterable, Mapping
from urllib.parse import unquote, urlsplit
import zipfile
import xml.etree.ElementTree as ET

from .adapters.image import _is_jpeg_xmp, _jpeg_segment_records, _png_chunks
from .limits import Limits
from .ooxml_xml import local_name, parse_xml
from .redaction import content_hmac_token


_ISSUER = object()
_TRANSFORM_ACTIONS = {
    "remove_ooxml_metadata",
    "strip_png_metadata",
    "strip_jpeg_metadata",
}
_CORE_PROPERTY_FIELDS = {
    "creator",
    "lastModifiedBy",
    "title",
    "subject",
    "description",
    "keywords",
    "category",
    "identifier",
    "created",
    "modified",
    "lastPrinted",
    "revision",
    "contentStatus",
    "language",
    "version",
}
_APP_PROPERTY_FIELDS = {
    "Manager",
    "Company",
    "Template",
    "HyperlinkBase",
    "Application",
    "AppVersion",
}


@dataclass(frozen=True, slots=True)
class PreservedFacet:
    """One keyed comparison of content outside an action's allowlist."""

    name: str
    before_token: str
    after_token: str
    preserved: bool


@dataclass(slots=True)
class TransformReceipt:
    """A core-issued, process-local record for one attempted transform."""

    action_id: str
    relative_path: str
    action_kind: str
    media_type_before: str
    media_type_after: str
    before_content_token: str | None
    transform_input_token: str
    expected_after_token: str
    postscan_content_token: str | None
    preserved_facets: tuple[PreservedFacet, ...]
    status: str
    reason: str | None
    exact_scan_binding: bool
    _issuer: object = field(repr=False, compare=False)


class SanitizationActions(list[dict[str, Any]]):
    """JSON-compatible action list carrying non-serializable internal receipts."""

    __slots__ = ("_receipts", "_issuer", "_key", "_before_artifacts", "_exact_scan_binding")

    def __init__(
        self,
        *,
        evidence_key: bytes | None,
        before_report: Mapping[str, Any] | None,
    ) -> None:
        super().__init__()
        if before_report is not None and evidence_key is None:
            raise ValueError("an evidence key is required when binding a pre-scan report")
        self._issuer = _ISSUER
        self._key = bytes(evidence_key) if evidence_key is not None else secrets.token_bytes(32)
        self._exact_scan_binding = before_report is not None and evidence_key is not None
        self._before_artifacts = _unique_artifacts(before_report)
        self._receipts: list[TransformReceipt] = []

    @property
    def receipts(self) -> tuple[TransformReceipt, ...]:
        return tuple(self._receipts)

    def add_transform_receipt(
        self,
        *,
        relative_path: str,
        action_kind: str,
        media_type_before: str,
        media_type_after: str,
        transform_input: bytes,
        expected_after: bytes,
        status: str,
        reason: str | None,
        limits: Limits,
    ) -> None:
        if self._issuer is not _ISSUER or action_kind not in _TRANSFORM_ACTIONS:
            raise ValueError("unsupported internal transform receipt")
        scanned = self._before_artifacts.get(relative_path)
        before_token = scanned.get("content_token") if scanned is not None else None
        if not isinstance(before_token, str):
            before_token = None
        facets = _preserved_facets(
            transform_input,
            expected_after,
            action_kind=action_kind,
            key=self._key,
            limits=limits,
        )
        self._receipts.append(
            TransformReceipt(
                action_id=f"transform-{len(self._receipts) + 1:06d}",
                relative_path=relative_path,
                action_kind=action_kind,
                media_type_before=media_type_before,
                media_type_after=media_type_after,
                before_content_token=before_token,
                transform_input_token=content_hmac_token(transform_input, self._key),
                expected_after_token=content_hmac_token(expected_after, self._key),
                postscan_content_token=None,
                preserved_facets=facets,
                status=status,
                reason=reason,
                exact_scan_binding=self._exact_scan_binding,
                _issuer=_ISSUER,
            )
        )


def new_sanitization_actions(
    *,
    evidence_key: bytes | None = None,
    before_report: Mapping[str, Any] | None = None,
) -> SanitizationActions:
    """Create the only action carrier whose receipts the verifier will trust."""

    return SanitizationActions(evidence_key=evidence_key, before_report=before_report)


def trusted_receipts(actions: object) -> tuple[TransformReceipt, ...]:
    """Return core-issued receipts; ordinary lists and reconstructed JSON yield none."""

    if not isinstance(actions, SanitizationActions) or actions._issuer is not _ISSUER:
        return ()
    return tuple(receipt for receipt in actions.receipts if receipt._issuer is _ISSUER)


def bind_and_validate_receipt(
    receipt: TransformReceipt,
    *,
    before_artifact: Mapping[str, Any],
    after_artifact: Mapping[str, Any],
) -> str | None:
    """Bind the post-scan token and return a stable failure code, if any."""

    if receipt._issuer is not _ISSUER:
        return "transform_receipt_untrusted"
    postscan = after_artifact.get("content_token")
    receipt.postscan_content_token = postscan if isinstance(postscan, str) else None
    if (
        before_artifact.get("media_type") != receipt.media_type_before
        or after_artifact.get("media_type") != receipt.media_type_after
        or receipt.media_type_before != receipt.media_type_after
    ):
        return "transform_receipt_media_mismatch"
    if receipt.exact_scan_binding:
        prescan = before_artifact.get("content_token")
        if (
            not isinstance(prescan, str)
            or receipt.before_content_token is None
            or not _same_token(prescan, receipt.before_content_token)
            or not _same_token(receipt.before_content_token, receipt.transform_input_token)
        ):
            return "transform_source_snapshot_mismatch"
        if (
            receipt.postscan_content_token is None
            or not _same_token(receipt.expected_after_token, receipt.postscan_content_token)
        ):
            return "transform_output_snapshot_mismatch"
    if not receipt.preserved_facets or not all(facet.preserved for facet in receipt.preserved_facets):
        return "transform_preservation_failed"
    return None


def _same_token(left: str, right: str) -> bool:
    try:
        return hmac.compare_digest(left.encode("ascii", "strict"), right.encode("ascii", "strict"))
    except UnicodeEncodeError:
        return False


def _unique_artifacts(report: Mapping[str, Any] | None) -> dict[str, Mapping[str, Any]]:
    if report is None:
        return {}
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    artifacts = report.get("artifacts", [])
    if not isinstance(artifacts, list):
        return {}
    for artifact in artifacts:
        if not isinstance(artifact, Mapping):
            continue
        path = artifact.get("path")
        if isinstance(path, str):
            grouped.setdefault(path, []).append(artifact)
    return {path: items[0] for path, items in grouped.items() if len(items) == 1}


def _preserved_facets(
    before: bytes,
    after: bytes,
    *,
    action_kind: str,
    key: bytes,
    limits: Limits,
) -> tuple[PreservedFacet, ...]:
    try:
        if action_kind == "strip_png_metadata":
            before_values = _png_facets(before, key)
            after_values = _png_facets(after, key)
        elif action_kind == "strip_jpeg_metadata":
            before_values = _jpeg_facets(before, key)
            after_values = _jpeg_facets(after, key)
        elif action_kind == "remove_ooxml_metadata":
            before_values = _ooxml_facets(before, key, limits)
            after_values = _ooxml_facets(after, key, limits)
        else:
            before_values = {"copy.byte_identity": content_hmac_token(before, key)}
            after_values = {"copy.byte_identity": content_hmac_token(after, key)}
    except (EOFError, KeyError, OSError, RuntimeError, ValueError, zipfile.BadZipFile, ET.ParseError):
        return (
            PreservedFacet(
                name="format.parseable",
                before_token=_facet_token(key, "format.parseable", (b"before",)),
                after_token=_facet_token(key, "format.parseable", (b"after",)),
                preserved=False,
            ),
        )
    names = sorted(set(before_values) | set(after_values))
    missing_before = _facet_token(key, "missing.before", (b"missing",))
    missing_after = _facet_token(key, "missing.after", (b"missing",))
    return tuple(
        PreservedFacet(
            name=name,
            before_token=before_values.get(name, missing_before),
            after_token=after_values.get(name, missing_after),
            preserved=(name in before_values and name in after_values and before_values[name] == after_values[name]),
        )
        for name in names
    )


def _facet_token(key: bytes, name: str, parts: Iterable[bytes]) -> str:
    digest = hmac.new(key, b"sharesafe-preserved-facet/v1\0" + name.encode("ascii") + b"\0", hashlib.sha256)
    for part in parts:
        digest.update(struct.pack(">Q", len(part)))
        digest.update(part)
    return f"hmac-sha256:facet-v1:{digest.hexdigest()[:32]}"


def _framed(kind: str, payload: bytes) -> bytes:
    name = kind.encode("utf-8", "surrogatepass")
    return struct.pack(">I", len(name)) + name + struct.pack(">Q", len(payload)) + payload


def _png_facets(data: bytes, key: bytes) -> dict[str, str]:
    records = list(_png_chunks(data))
    critical: list[bytes] = []
    idat: list[bytes] = []
    ihdr: list[bytes] = []
    retained_exif: list[bytes] = []
    protected: list[bytes] = []
    for kind, payload in records:
        record = _framed(kind, payload)
        if kind and kind[0].isupper():
            critical.append(record)
        if kind == "IDAT":
            idat.append(record)
        if kind == "IHDR":
            ihdr.append(record)
        removable = kind in {"tEXt", "zTXt", "iTXt", "tIME"}
        if kind == "eXIf":
            orientation, parsed = _exif_orientation(payload)
            removable = parsed and orientation in {None, 1}
            if not removable:
                retained_exif.append(record)
        if not removable:
            protected.append(record)
    return {
        "png.critical_chunks": _facet_token(key, "png.critical_chunks", critical),
        "png.idat_data": _facet_token(key, "png.idat_data", idat),
        "png.image_header": _facet_token(key, "png.image_header", ihdr),
        "png.protected_chunks": _facet_token(key, "png.protected_chunks", protected),
        "png.retained_exif_orientation": _facet_token(
            key, "png.retained_exif_orientation", retained_exif
        ),
    }


def _jpeg_facets(data: bytes, key: bytes) -> dict[str, str]:
    records = list(_jpeg_segment_records(data))
    removable_spans: list[tuple[int, int]] = []
    scan_data: list[bytes] = []
    sof: list[bytes] = []
    cursor = 2
    for marker, payload, start, end in records:
        if start > cursor:
            scan_data.append(data[cursor:start])
        cursor = end
        is_exif = payload.startswith(b"Exif\x00\x00")
        removable = marker in {0xED, 0xFE}
        if marker == 0xE1 and (is_exif or _is_jpeg_xmp(payload)):
            removable = True
            if is_exif:
                orientation, parsed = _exif_orientation(payload)
                removable = parsed and orientation in {None, 1}
        if removable:
            removable_spans.append((start, end))
        if marker in {
            0xC0,
            0xC1,
            0xC2,
            0xC3,
            0xC5,
            0xC6,
            0xC7,
            0xC9,
            0xCA,
            0xCB,
            0xCD,
            0xCE,
            0xCF,
        }:
            sof.append(_framed(f"{marker:02x}", payload))
    protected = _without_spans(data, removable_spans)
    return {
        "jpeg.encoded_scan_data": _facet_token(key, "jpeg.encoded_scan_data", scan_data),
        "jpeg.frame_headers": _facet_token(key, "jpeg.frame_headers", sof),
        "jpeg.protected_stream": _facet_token(key, "jpeg.protected_stream", (protected,)),
    }


def _without_spans(data: bytes, spans: Iterable[tuple[int, int]]) -> bytes:
    output = bytearray()
    cursor = 0
    for start, end in sorted(spans):
        if start < cursor or end < start or end > len(data):
            raise ValueError("invalid removable span")
        output.extend(data[cursor:start])
        cursor = end
    output.extend(data[cursor:])
    return bytes(output)


def _ooxml_facets(data: bytes, key: bytes, limits: Limits) -> dict[str, str]:
    members = _read_ooxml_members(data, limits)
    member_set: list[bytes] = []
    protected_contents: list[bytes] = []
    retained_properties: list[bytes] = []
    retained_content_types: list[bytes] = []
    retained_relationships: list[bytes] = []
    relationship_targets: list[bytes] = []
    for name, lower, payload, is_directory in members:
        if lower != "docprops/custom.xml":
            member_set.append(name.encode("utf-8", "surrogatepass"))
        if is_directory or lower == "docprops/custom.xml":
            continue
        if lower == "docprops/core.xml":
            projected = _project_properties(payload, _CORE_PROPERTY_FIELDS)
            retained_properties.append(_framed(name, projected))
        elif lower == "docprops/app.xml":
            projected = _project_properties(payload, _APP_PROPERTY_FIELDS)
            retained_properties.append(_framed(name, projected))
        elif lower == "[content_types].xml":
            retained_content_types.append(_framed(name, _project_content_types(payload)))
        elif lower.endswith(".rels"):
            projected, targets = _project_relationships(payload, name)
            retained_relationships.append(_framed(name, projected))
            relationship_targets.extend(_framed(name, target) for target in targets)
        else:
            protected_contents.append(_framed(name, payload))
    return {
        "ooxml.member_set": _facet_token(key, "ooxml.member_set", sorted(member_set)),
        "ooxml.protected_member_contents": _facet_token(
            key, "ooxml.protected_member_contents", sorted(protected_contents)
        ),
        "ooxml.retained_properties": _facet_token(
            key, "ooxml.retained_properties", sorted(retained_properties)
        ),
        "ooxml.retained_content_types": _facet_token(
            key, "ooxml.retained_content_types", sorted(retained_content_types)
        ),
        "ooxml.retained_relationships": _facet_token(
            key, "ooxml.retained_relationships", sorted(retained_relationships)
        ),
        "ooxml.relationship_targets": _facet_token(
            key, "ooxml.relationship_targets", sorted(relationship_targets)
        ),
    }


def _read_ooxml_members(
    data: bytes,
    limits: Limits,
) -> list[tuple[str, str, bytes, bool]]:
    output: list[tuple[str, str, bytes, bool]] = []
    expanded = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) > limits.max_archive_entries:
            raise ValueError("OOXML member limit exceeded")
        normalized = [info.filename.replace("\\", "/") for info in infos]
        if len({name.casefold() for name in normalized}) != len(normalized):
            raise ValueError("ambiguous OOXML member names")
        for info, name in zip(infos, normalized):
            if info.flag_bits & 0x1 or info.file_size > limits.max_archive_member_bytes:
                raise ValueError("unreadable OOXML member")
            expanded += info.file_size
            if expanded > limits.max_expanded_bytes:
                raise ValueError("OOXML expansion limit exceeded")
            payload = b"" if info.is_dir() else archive.read(info)
            if len(payload) != info.file_size:
                raise ValueError("OOXML member size mismatch")
            output.append((name, name.casefold(), payload, info.is_dir()))
    return output


def _project_properties(payload: bytes, removable: set[str]) -> bytes:
    root = parse_xml(payload)
    for child in list(root):
        if local_name(child.tag) in removable and ("".join(child.itertext()).strip() or child.attrib):
            _remove_child_preserving_tail(root, child)
    return _canonical_xml(root)


def _project_content_types(payload: bytes) -> bytes:
    root = parse_xml(payload)
    for child in list(root):
        attributes = {key.rsplit("}", 1)[-1]: value for key, value in child.attrib.items()}
        part_name = attributes.get("PartName", "")
        resolved = _resolve_relationship_target("_rels/.rels", part_name)
        if (
            local_name(child.tag) == "Override"
            and part_name.startswith("/")
            and (resolved or "").casefold() == "docprops/custom.xml"
        ):
            _remove_child_preserving_tail(root, child)
    return _canonical_xml(root)


def _project_relationships(payload: bytes, relationship_part: str) -> tuple[bytes, list[bytes]]:
    root = parse_xml(payload)
    for child in list(root):
        attributes = {key.rsplit("}", 1)[-1]: value for key, value in child.attrib.items()}
        target_mode = attributes.get("TargetMode", "").strip().casefold()
        resolved = (
            _resolve_relationship_target(relationship_part, attributes.get("Target", ""))
            if target_mode != "external"
            else None
        )
        if (
            local_name(child.tag) == "Relationship"
            and resolved is not None
            and resolved.casefold() == "docprops/custom.xml"
        ):
            _remove_child_preserving_tail(root, child)
    targets: list[bytes] = []
    for child in root:
        if local_name(child.tag) != "Relationship":
            continue
        attributes = {key.rsplit("}", 1)[-1]: value for key, value in child.attrib.items()}
        targets.append(
            json.dumps(
                {
                    "target": attributes.get("Target", ""),
                    "target_mode": attributes.get("TargetMode", ""),
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
    return _canonical_xml(root), targets


def _canonical_xml(root: ET.Element) -> bytes:
    def element_value(element: ET.Element) -> dict[str, object]:
        if isinstance(element.tag, str):
            tag = element.tag
        elif element.tag is ET.Comment:
            tag = "#comment"
        elif element.tag is ET.ProcessingInstruction:
            tag = "#processing-instruction"
        else:
            tag = "#non-element-node"
        return {
            "tag": tag,
            "attributes": sorted(element.attrib.items()),
            "text": element.text or "",
            "tail": element.tail or "",
            "children": [element_value(child) for child in element],
        }

    return json.dumps(
        element_value(root),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _remove_child_preserving_tail(root: ET.Element, child: ET.Element) -> None:
    children = list(root)
    position = children.index(child)
    tail = child.tail
    root.remove(child)
    if not tail:
        return
    remaining = list(root)
    if position > 0 and position - 1 < len(remaining):
        previous = remaining[position - 1]
        previous.tail = (previous.tail or "") + tail
    else:
        root.text = (root.text or "") + tail


def _relationship_source_parts(relationship_part: str) -> tuple[str, ...] | None:
    normalized = relationship_part.replace("\\", "/").strip("/")
    parts = tuple(part for part in normalized.split("/") if part)
    if tuple(part.casefold() for part in parts) == ("_rels", ".rels"):
        return ()
    if (
        len(parts) >= 2
        and parts[-2].casefold() == "_rels"
        and parts[-1].casefold().endswith(".rels")
        and len(parts[-1]) > len(".rels")
    ):
        return (*parts[:-2], parts[-1][: -len(".rels")])
    return None


def _resolve_relationship_target(relationship_part: str, target: str) -> str | None:
    try:
        parsed = urlsplit(target)
    except ValueError:
        return None
    if parsed.scheme or parsed.netloc or not parsed.path:
        return None
    path = unquote(parsed.path)
    if "\x00" in path or "\\" in path:
        return None
    source_parts = _relationship_source_parts(relationship_part)
    if source_parts is None:
        return None
    resolved = [] if path.startswith("/") else list(source_parts[:-1] if source_parts else ())
    for part in path.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not resolved:
                return None
            resolved.pop()
            continue
        resolved.append(part)
    return "/".join(resolved)


def _exif_orientation(payload: bytes) -> tuple[int | None, bool]:
    tiff = payload[6:] if payload.startswith(b"Exif\x00\x00") else payload
    if len(tiff) < 8:
        return None, False
    if tiff[:2] == b"II":
        endian = "<"
    elif tiff[:2] == b"MM":
        endian = ">"
    else:
        return None, False
    try:
        if struct.unpack(endian + "H", tiff[2:4])[0] != 42:
            return None, False
        offset = struct.unpack(endian + "I", tiff[4:8])[0]
        orientations: list[int] = []
        seen_offsets: set[int] = set()
        for _ in range(64):
            if offset == 0:
                non_neutral = next((value for value in orientations if value != 1), None)
                return (non_neutral if non_neutral is not None else (1 if orientations else None)), True
            if offset < 8 or offset % 2 or offset in seen_offsets or offset + 2 > len(tiff):
                return None, False
            seen_offsets.add(offset)
            count = struct.unpack(endian + "H", tiff[offset : offset + 2])[0]
            cursor = offset + 2
            table_end = cursor + count * 12
            if table_end + 4 > len(tiff):
                return None, False
            orientation_in_ifd = False
            for _entry in range(count):
                tag, kind, item_count = struct.unpack(endian + "HHI", tiff[cursor : cursor + 8])
                if tag == 0x0112:
                    if kind != 3 or item_count != 1 or orientation_in_ifd:
                        return None, False
                    orientation_in_ifd = True
                    orientations.append(struct.unpack(endian + "H", tiff[cursor + 8 : cursor + 10])[0])
                cursor += 12
            offset = struct.unpack(endian + "I", tiff[table_end : table_end + 4])[0]
        return None, False
    except struct.error:
        return None, False


__all__ = [
    "SanitizationActions",
    "TransformReceipt",
    "bind_and_validate_receipt",
    "new_sanitization_actions",
    "trusted_receipts",
]
