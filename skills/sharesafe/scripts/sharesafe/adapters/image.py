"""Bounded image metadata inspection. Pixel OCR is intentionally out of scope."""

from __future__ import annotations

import io
import struct
from typing import TYPE_CHECKING, Iterator
import warnings
import zlib

from .text import scan_text

if TYPE_CHECKING:
    from ..engine import Scanner
    from ..models import Artifact, ReportBuilder


_JPEG_XMP_APP1_PREFIXES = (
    b"http://ns.adobe.com/xap/1.0/\x00",
    b"http://ns.adobe.com/xmp/extension/\x00",
)

# PNG permits applications to split image data across many chunks.  A fixed
# ceiling keeps both scanning and lossless metadata rewriting from allocating
# an attacker-controlled number of Python objects.  Ordinary encoders produce
# far fewer chunks, while 4,096 still leaves ample room for unusually segmented
# images and animated PNGs.
_MAX_PNG_CHUNKS = 4_096


class _PNGChunkLimitError(ValueError):
    """Raised when a PNG exceeds the parser's structural work budget."""


class _PNGTextLimitError(ValueError):
    """Raised when decoded PNG text would exceed the cumulative text budget."""


class _PNGTextFormatError(ValueError):
    """Raised when a PNG text chunk cannot be decoded unambiguously."""


def _is_jpeg_xmp(payload: bytes) -> bool:
    """Return whether an APP1 payload uses an Adobe XMP namespace header."""

    return payload.startswith(_JPEG_XMP_APP1_PREFIXES)


def _png_chunks(
    data: bytes,
    *,
    max_chunks: int = _MAX_PNG_CHUNKS,
) -> Iterator[tuple[str, bytes]]:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("invalid PNG signature")
    offset = 8
    saw_iend = False
    chunk_count = 0
    while offset + 12 <= len(data):
        if chunk_count >= max_chunks:
            raise _PNGChunkLimitError("PNG chunk count limit exceeded")
        chunk_count += 1
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        if length > 128 * 1024 * 1024 or offset + 12 + length > len(data):
            raise ValueError("invalid PNG chunk length")
        kind_bytes = data[offset + 4 : offset + 8]
        payload = data[offset + 8 : offset + 8 + length]
        declared_crc = struct.unpack(">I", data[offset + 8 + length : offset + 12 + length])[0]
        if zlib.crc32(kind_bytes + payload) & 0xFFFFFFFF != declared_crc:
            raise ValueError("invalid PNG chunk CRC")
        try:
            kind = kind_bytes.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("invalid PNG chunk name") from exc
        yield kind, payload
        offset += 12 + length
        if kind == "IEND":
            saw_iend = True
            break
    if not saw_iend or offset != len(data):
        raise ValueError("PNG is truncated or has trailing data")


def _bounded_zlib(data: bytes, limit: int) -> bytes:
    """Decode one zlib stream without ever materializing more than limit + 1 bytes."""

    if limit < 0:
        raise _PNGTextLimitError("PNG text budget exhausted")
    try:
        inflater = zlib.decompressobj()
        value = inflater.decompress(data, limit + 1)
        if len(value) > limit or inflater.unconsumed_tail:
            raise _PNGTextLimitError("decoded PNG text exceeds limit")
        value += inflater.flush(limit + 1 - len(value))
    except zlib.error as exc:
        raise _PNGTextFormatError("invalid compressed PNG text") from exc
    if len(value) > limit:
        raise _PNGTextLimitError("decoded PNG text exceeds limit")
    if not inflater.eof or inflater.unused_data:
        raise _PNGTextFormatError("PNG text is not exactly one complete zlib stream")
    return value


def _join_png_text(parts: tuple[bytes, ...], limit: int) -> bytes:
    size = sum(len(part) for part in parts) + max(0, len(parts) - 1)
    if size > limit:
        raise _PNGTextLimitError("decoded PNG text exceeds limit")
    return b"\n".join(parts)


def _png_text(kind: str, payload: bytes, limit: int) -> bytes | None:
    if kind == "tEXt":
        if len(payload) > limit:
            raise _PNGTextLimitError("decoded PNG text exceeds limit")
        return payload
    if kind == "zTXt":
        try:
            keyword, remainder = payload.split(b"\x00", 1)
        except ValueError as exc:
            raise _PNGTextFormatError("invalid zTXt fields") from exc
        if len(remainder) < 2 or remainder[0] != 0:
            raise _PNGTextFormatError("invalid zTXt compression method")
        prefix_size = len(keyword) + 1
        if prefix_size > limit:
            raise _PNGTextLimitError("decoded PNG text exceeds limit")
        inflated = _bounded_zlib(remainder[1:], limit - prefix_size)
        return _join_png_text((keyword, inflated), limit)
    if kind == "iTXt":
        # keyword NUL, compression flag, method, language NUL, translated NUL, text
        try:
            keyword, remainder = payload.split(b"\x00", 1)
            flag, method = remainder[0], remainder[1]
            remainder = remainder[2:]
            language, remainder = remainder.split(b"\x00", 1)
            translated, text = remainder.split(b"\x00", 1)
        except (ValueError, IndexError) as exc:
            raise _PNGTextFormatError("invalid iTXt fields") from exc
        if flag not in {0, 1} or method != 0:
            raise _PNGTextFormatError("invalid iTXt compression fields")
        prefix_size = len(keyword) + len(language) + len(translated) + 3
        if prefix_size > limit:
            raise _PNGTextLimitError("decoded PNG text exceeds limit")
        if flag == 1:
            text = _bounded_zlib(text, limit - prefix_size)
        return _join_png_text((keyword, language, translated, text), limit)
    return None


def _jpeg_segment_records(data: bytes) -> Iterator[tuple[int, bytes, int, int]]:
    """Yield every JPEG marker segment, including markers between scans.

    JPEG entropy-coded data may contain stuffed ``FF 00`` bytes and restart
    markers.  Progressive and multi-scan files can then return to ordinary
    marker segments before another SOS.  Stopping at the first SOS would miss
    valid COM/APP metadata later in the file, so this parser tracks both
    states and exposes exact source spans for lossless metadata removal.
    """

    if not data.startswith(b"\xff\xd8"):
        raise ValueError("invalid JPEG signature")
    offset = 2
    in_scan = False

    while True:
        if offset >= len(data):
            raise ValueError("JPEG data lacks an EOI marker")

        marker_from_scan = in_scan
        if in_scan:
            while offset < len(data):
                if data[offset] != 0xFF:
                    offset += 1
                    continue
                marker_start = offset
                while offset < len(data) and data[offset] == 0xFF:
                    offset += 1
                if offset >= len(data):
                    raise ValueError("truncated JPEG marker in scan data")
                marker = data[offset]
                offset += 1
                if marker == 0x00:  # Byte-stuffed entropy data.
                    continue
                if 0xD0 <= marker <= 0xD7 or marker == 0x01:
                    yield marker, b"", marker_start, offset
                    continue
                in_scan = False
                break
            else:
                raise ValueError("JPEG scan data lacks an EOI marker")
        else:
            marker_start = offset
            if data[offset] != 0xFF:
                raise ValueError("invalid JPEG marker")
            while offset < len(data) and data[offset] == 0xFF:
                offset += 1
            if offset >= len(data):
                raise ValueError("truncated JPEG marker")
            marker = data[offset]
            offset += 1
            if marker == 0x00:
                raise ValueError("stuffed JPEG byte outside scan data")

        if marker == 0xD8:
            raise ValueError("unexpected nested JPEG SOI marker")
        if marker == 0xD9:
            yield marker, b"", marker_start, offset
            if offset != len(data):
                raise ValueError("JPEG has trailing data after EOI")
            return
        if 0xD0 <= marker <= 0xD7 or marker == 0x01:
            yield marker, b"", marker_start, offset
            continue
        if offset + 2 > len(data):
            raise ValueError("truncated JPEG segment length")
        length = struct.unpack(">H", data[offset : offset + 2])[0]
        end = offset + length
        if length < 2 or end > len(data):
            raise ValueError("invalid JPEG segment length")
        payload = data[offset + 2 : end]
        yield marker, payload, marker_start, end
        offset = end
        # SOS begins (or resumes) entropy-coded data. DNL is the one
        # length-bearing marker that may occur inside and then resume a scan.
        in_scan = marker == 0xDA or (marker_from_scan and marker == 0xDC)


def _jpeg_segments(data: bytes) -> Iterator[tuple[int, bytes]]:
    for marker, payload, _start, _end in _jpeg_segment_records(data):
        yield marker, payload


def scan_image(
    scanner: "Scanner",
    data: bytes,
    kind: str,
    artifact: "Artifact",
    builder: "ReportBuilder",
) -> None:
    artifact.set_coverage("text", "not_applicable")
    artifact.set_coverage("hidden_content", "not_applicable")
    artifact.set_coverage("embedded_objects", "not_applicable")
    artifact.set_coverage("ocr", "unsupported")
    builder.add_gap(artifact, "ocr", "ocr_not_available", "Image pixels were not checked for visible personal information.")

    raw_metadata_found = False
    png_text_budget = scanner.config.limits.max_text_bytes
    png_text_unavailable = False
    try:
        if kind == "png":
            for chunk_kind, payload in _png_chunks(data):
                if chunk_kind in {"eXIf", "tEXt", "zTXt", "iTXt", "tIME"}:
                    raw_metadata_found = True
                    severity = "medium" if chunk_kind in {"eXIf", "tEXt", "zTXt", "iTXt"} else "low"
                    builder.add_finding(
                        artifact,
                        rule_id=f"SS-IMAGE-PNG-{chunk_kind.upper()}",
                        category="image_metadata",
                        severity=severity,
                        confidence=1.0,
                        title=f"PNG {chunk_kind} metadata chunk is present",
                        location={"kind": "image_chunk", "chunk": chunk_kind},
                        remediation_supported=True,
                        remediation_action="strip_image_metadata_from_copy",
                    )
                    if not png_text_unavailable:
                        try:
                            text_payload = _png_text(chunk_kind, payload, png_text_budget)
                        except _PNGTextLimitError:
                            builder.add_gap(
                                artifact,
                                "metadata",
                                "png_text_resource_limit",
                                "PNG text metadata exceeded the cumulative decoded-text limit.",
                            )
                            png_text_unavailable = True
                        except _PNGTextFormatError:
                            builder.add_gap(
                                artifact,
                                "metadata",
                                "png_text_metadata_error",
                                "Compressed PNG text metadata could not be decoded safely.",
                            )
                            png_text_unavailable = True
                        else:
                            if text_payload is not None:
                                png_text_budget -= len(text_payload)
                            if text_payload:
                                scan_text(
                                    text_payload,
                                    artifact,
                                    builder,
                                    evidence_key=scanner.evidence_key,
                                    part=f"PNG/{chunk_kind}",
                                )
        elif kind == "jpeg":
            for marker, payload in _jpeg_segments(data):
                label: str | None = None
                if marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):
                    label = "EXIF"
                elif marker == 0xE1 and _is_jpeg_xmp(payload):
                    label = "XMP"
                elif marker == 0xED:
                    label = "IPTC/Photoshop"
                elif marker == 0xFE:
                    label = "comment"
                if label:
                    raw_metadata_found = True
                    builder.add_finding(
                        artifact,
                        rule_id=f"SS-IMAGE-JPEG-{label.split('/')[0].upper()}",
                        category="image_metadata",
                        severity="medium",
                        confidence=1.0,
                        title=f"JPEG {label} metadata is present",
                        location={"kind": "image_segment", "marker": f"0x{marker:02x}"},
                        remediation_supported=True,
                        remediation_action="strip_image_metadata_from_copy",
                    )
                    if label in {"XMP", "comment"}:
                        scan_text(
                            payload[: scanner.config.limits.max_text_bytes], artifact, builder,
                            evidence_key=scanner.evidence_key, part=f"JPEG/{label}",
                        )
    except _PNGChunkLimitError:
        builder.add_gap(
            artifact,
            "metadata",
            "png_chunk_limit",
            f"PNG contains more than {_MAX_PNG_CHUNKS} chunks; remaining chunks were not inspected.",
        )
        return
    except ValueError:
        builder.add_gap(artifact, "metadata", "image_structure_error", "Image metadata structure could not be parsed safely.")
        return

    # Pillow eagerly expands PNG text chunks while opening the image.  If the
    # bounded parser rejected one, do not hand the same input to an optional
    # decoder with a different (and potentially larger) resource budget.
    if kind == "png" and png_text_unavailable:
        return

    _scan_with_pillow(scanner, data, kind, artifact, builder, raw_metadata_found)


def _scan_with_pillow(
    scanner: "Scanner",
    data: bytes,
    kind: str,
    artifact: "Artifact",
    builder: "ReportBuilder",
    raw_metadata_found: bool,
) -> None:
    if not scanner.config.optional_tools:
        builder.add_dependency("Pillow", False, None, "rich_image_metadata")
        if kind in {"tiff", "webp"}:
            builder.add_gap(artifact, "metadata", "optional_dependency_disabled", "Pillow is disabled; this image format has no metadata parser.")
        else:
            artifact.set_coverage("metadata", "partial")
            builder.add_gap(artifact, "metadata", "optional_dependency_disabled", "Only container-level image metadata was checked.")
        return

    try:
        import PIL
        from PIL import ExifTags, Image
    except ImportError:
        builder.add_dependency("Pillow", False, None, "rich_image_metadata")
        if kind in {"tiff", "webp"}:
            builder.add_gap(artifact, "metadata", "optional_dependency_missing", "Install the image extra to inspect this image format.")
        else:
            builder.add_gap(artifact, "metadata", "optional_dependency_missing", "Container metadata was checked, but rich EXIF tags were not decoded.")
        return

    builder.add_dependency("Pillow", True, getattr(PIL, "__version__", None), "rich_image_metadata")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as image:
                exif = image.getexif()
                metadata_text: list[str] = []
                identity_tags: list[str] = []
                software_tags: list[str] = []
                gps = False
                for tag_id, value in exif.items():
                    name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    folded = name.casefold()
                    if folded == "gpsinfo":
                        gps = True
                    elif any(token in folded for token in ("artist", "owner", "serial", "copyright", "cameraowner")):
                        identity_tags.append(name)
                    elif any(token in folded for token in ("make", "model", "software", "datetime", "hostcomputer")):
                        software_tags.append(name)
                    if isinstance(value, str) and len(value) <= 4096:
                        metadata_text.append(value)
                for key, value in image.info.items():
                    folded = str(key).casefold()
                    if folded in {"comment", "description", "author", "artist", "copyright", "xmp", "xml"}:
                        identity_tags.append(str(key))
                        if isinstance(value, str) and len(value) <= 4096:
                            metadata_text.append(value)
                if gps:
                    builder.add_finding(
                        artifact,
                        rule_id="SS-IMAGE-GPS",
                        category="location_metadata",
                        severity="critical",
                        confidence=1.0,
                        title="Image contains GPS metadata",
                        location={"kind": "image_metadata", "tag": "GPSInfo"},
                        remediation_supported=True,
                        remediation_action="strip_image_metadata_from_copy",
                    )
                if identity_tags:
                    builder.add_finding(
                        artifact,
                        rule_id="SS-IMAGE-IDENTITY-METADATA",
                        category="identity_metadata",
                        severity="high",
                        confidence=1.0,
                        title="Image contains author, owner, serial, or descriptive metadata",
                        location={"kind": "image_metadata", "tag_count": len(set(identity_tags))},
                        remediation_supported=True,
                        remediation_action="strip_image_metadata_from_copy",
                    )
                if software_tags:
                    builder.add_finding(
                        artifact,
                        rule_id="SS-IMAGE-DEVICE-METADATA",
                        category="device_metadata",
                        severity="medium",
                        confidence=1.0,
                        title="Image contains device, software, or capture-time metadata",
                        location={"kind": "image_metadata", "tag_count": len(set(software_tags))},
                        remediation_supported=True,
                        remediation_action="strip_image_metadata_from_copy",
                    )
                if metadata_text:
                    joined = "\n".join(metadata_text)
                    scan_text(
                        joined.encode("utf-8"), artifact, builder,
                        evidence_key=scanner.evidence_key, part="image/decoded-metadata",
                    )
        artifact.set_coverage("metadata", "complete")
    except (OSError, ValueError, SyntaxError, Image.DecompressionBombWarning, Image.DecompressionBombError):
        builder.add_gap(artifact, "metadata", "image_parser_error", "Pillow could not inspect image metadata within safety limits.")
