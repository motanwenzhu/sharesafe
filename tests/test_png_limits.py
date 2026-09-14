from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import struct
import zlib

import pytest

from sharesafe.adapters.image import _MAX_PNG_CHUNKS, _png_text
from sharesafe.engine import ScanConfig, Scanner
from sharesafe.limits import Limits
from sharesafe.sanitize import _sanitize_png, create_sanitized_copy


def _chunk(kind: bytes, payload: bytes) -> bytes:
    checksum = zlib.crc32(kind + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", checksum)


def _png(*extra_chunks: tuple[bytes, bytes]) -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    scanline = b"\x00\x00\x00\x00\xff"
    return b"".join(
        (
            b"\x89PNG\r\n\x1a\n",
            _chunk(b"IHDR", ihdr),
            *(_chunk(kind, payload) for kind, payload in extra_chunks),
            _chunk(b"IDAT", zlib.compress(scanline)),
            _chunk(b"IEND", b""),
        )
    )


def _compressed_text_payload(kind: bytes, text: bytes) -> bytes:
    if kind == b"zTXt":
        return b"Comment\x00\x00" + zlib.compress(text)
    if kind == b"iTXt":
        return b"Comment\x00\x01\x00en\x00Translated\x00" + zlib.compress(text)
    raise AssertionError(f"unsupported test chunk: {kind!r}")


def _scan_png(tmp_path: Path, data: bytes, limits: Limits) -> dict:
    sample = tmp_path / "synthetic.png"
    sample.write_bytes(data)
    return Scanner(ScanConfig(limits=limits, optional_tools=False)).scan([sample]).to_dict()


@pytest.mark.parametrize("kind", (b"zTXt", b"iTXt"))
def test_png_compressed_text_uses_one_cumulative_decoded_budget(
    kind: bytes, tmp_path: Path
) -> None:
    payload = _compressed_text_payload(kind, b"synthetic-metadata")
    decoded_size = len(_png_text(kind.decode("ascii"), payload, 1_000_000) or b"")
    # Each chunk fits independently.  Together they do not fit, proving the
    # scanner cannot reset max_text_bytes for every compressed text chunk.
    limits = replace(Limits(), max_text_bytes=decoded_size + 1)

    report = _scan_png(tmp_path, _png((kind, payload), (kind, payload)), limits)

    assert report["summary"]["verdict"] == "incomplete"
    assert "png_text_resource_limit" in {gap["reason"] for gap in report["gaps"]}


def test_png_compressed_text_accepts_an_exact_cumulative_budget(tmp_path: Path) -> None:
    first = _compressed_text_payload(b"zTXt", b"first")
    second = _compressed_text_payload(b"zTXt", b"second")
    budget = len(_png_text("zTXt", first, 1_000_000) or b"") + len(
        _png_text("zTXt", second, 1_000_000) or b""
    )

    report = _scan_png(
        tmp_path,
        _png((b"zTXt", first), (b"zTXt", second)),
        replace(Limits(), max_text_bytes=budget),
    )

    assert "png_text_resource_limit" not in {gap["reason"] for gap in report["gaps"]}
    assert "png_text_metadata_error" not in {gap["reason"] for gap in report["gaps"]}


def test_png_text_limit_never_falls_through_to_pillow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sharesafe.adapters.image as image_adapter

    payload = _compressed_text_payload(b"zTXt", b"A" * 1_024)

    def unexpected_pillow_call(*args: object, **kwargs: object) -> None:
        raise AssertionError("Pillow must not reopen over-budget PNG text metadata")

    monkeypatch.setattr(image_adapter, "_scan_with_pillow", unexpected_pillow_call)
    report = _scan_png(
        tmp_path,
        _png((b"zTXt", payload)),
        replace(Limits(), max_text_bytes=32),
    )

    assert "png_text_resource_limit" in {gap["reason"] for gap in report["gaps"]}


@pytest.mark.parametrize(
    ("kind", "payload"),
    (
        (b"zTXt", b"Comment\x00\x00not-a-zlib-stream"),
        (b"zTXt", b"Comment\x00\x00" + zlib.compress(b"truncated")[:-1]),
        (b"iTXt", b"Comment\x00\x01\x00en\x00Translated\x00not-a-zlib-stream"),
        (b"iTXt", b"Comment\x00\x02\x00en\x00Translated\x00text"),
    ),
    ids=("ztxt-invalid", "ztxt-truncated", "itxt-invalid", "itxt-invalid-flag"),
)
def test_png_malformed_compressed_text_is_an_explicit_gap(
    kind: bytes, payload: bytes, tmp_path: Path
) -> None:
    report = _scan_png(tmp_path, _png((kind, payload)), Limits())

    assert report["summary"]["verdict"] == "incomplete"
    assert "png_text_metadata_error" in {gap["reason"] for gap in report["gaps"]}


def _png_over_chunk_limit(*, include_text: bool) -> bytes:
    chunks: list[bytes] = [_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))]
    if include_text:
        chunks.append(_chunk(b"tEXt", b"Comment\x00synthetic"))
    chunks.extend(_chunk(b"IDAT", b"") for _ in range(_MAX_PNG_CHUNKS - len(chunks)))
    chunks.append(_chunk(b"IEND", b""))
    return b"\x89PNG\r\n\x1a\n" + b"".join(chunks)


def test_png_chunk_count_limit_is_an_explicit_scan_gap(tmp_path: Path) -> None:
    report = _scan_png(tmp_path, _png_over_chunk_limit(include_text=False), Limits())

    assert report["summary"]["verdict"] == "incomplete"
    assert "png_chunk_limit" in {gap["reason"] for gap in report["gaps"]}


def test_png_sanitizer_never_commits_a_partial_rewrite_after_chunk_limit(
    tmp_path: Path,
) -> None:
    original = _png_over_chunk_limit(include_text=True)
    cleaned, removed, reason = _sanitize_png(original)

    assert cleaned == original
    assert removed == 0
    assert reason == "png_chunk_limit"

    source = tmp_path / "source.png"
    output = tmp_path / "prepared.png"
    source.write_bytes(original)
    actions = create_sanitized_copy(source, output, Limits())

    assert output.read_bytes() == original
    assert any(
        action["action"] == "strip_png_metadata"
        and action["status"] == "skipped"
        and action.get("reason") == "png_chunk_limit"
        for action in actions
    )
