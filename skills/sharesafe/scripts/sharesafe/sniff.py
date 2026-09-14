"""Conservative media-type detection and text decoding."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import codecs
import re


TEXT_EXTENSIONS = {
    ".txt", ".md", ".rst", ".csv", ".tsv", ".json", ".jsonl", ".yaml", ".yml",
    ".toml", ".xml", ".html", ".htm", ".css", ".js", ".jsx", ".ts", ".tsx",
    ".py", ".pyi", ".java", ".c", ".h", ".cpp", ".hpp", ".cs", ".go", ".rs",
    ".rb", ".php", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
    ".ini", ".cfg", ".conf", ".properties", ".env", ".log", ".sql", ".graphql",
    ".gitignore", ".gitattributes", ".editorconfig", ".dockerignore", ".lock",
}

OOXML_EXTENSIONS = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp"}


@dataclass(frozen=True, slots=True)
class MediaInfo:
    kind: str
    media_type: str
    expected_extension: str | None = None
    extension_mismatch: bool = False


def _extension(path: str) -> str:
    name = PurePosixPath(path.replace("\\", "/")).name.lower()
    if name in {".env", ".gitignore", ".gitattributes", ".editorconfig", ".dockerignore"}:
        return name
    return PurePosixPath(name).suffix.lower()


def sniff(data: bytes, path: str) -> MediaInfo:
    extension = _extension(path)

    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08"):
        if extension in OOXML_EXTENSIONS:
            subtype = {
                ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                ".docm": "application/vnd.ms-word.document.macroEnabled.12",
                ".xlsm": "application/vnd.ms-excel.sheet.macroEnabled.12",
                ".pptm": "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
            }[extension]
            return MediaInfo("ooxml", subtype)
        return MediaInfo("zip", "application/zip", ".zip", extension not in {".zip", ".jar", ".epub", ".whl"})

    signatures: list[tuple[bytes, str, str, set[str]]] = [
        (b"%PDF-", "pdf", "application/pdf", {".pdf"}),
        (b"\x89PNG\r\n\x1a\n", "png", "image/png", {".png"}),
        (b"\xff\xd8\xff", "jpeg", "image/jpeg", {".jpg", ".jpeg"}),
        (b"II*\x00", "tiff", "image/tiff", {".tif", ".tiff"}),
        (b"MM\x00*", "tiff", "image/tiff", {".tif", ".tiff"}),
        (b"MZ", "executable", "application/vnd.microsoft.portable-executable", {".exe", ".dll"}),
        (b"\x7fELF", "executable", "application/x-elf", {""}),
        (b"SQLite format 3\x00", "binary", "application/vnd.sqlite3", {".sqlite", ".sqlite3", ".db"}),
    ]
    for signature, kind, media_type, extensions in signatures:
        if data.startswith(signature):
            return MediaInfo(kind, media_type, next(iter(extensions)) or None, extension not in extensions)

    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP":
        return MediaInfo("webp", "image/webp", ".webp", extension != ".webp")

    if extension in TEXT_EXTENSIONS or _looks_like_text(data):
        return MediaInfo("text", "text/plain")

    if extension in OOXML_EXTENSIONS:
        return MediaInfo("binary", "application/octet-stream", None, True)
    if extension == ".pdf":
        return MediaInfo("binary", "application/octet-stream", None, True)
    if extension in IMAGE_EXTENSIONS:
        return MediaInfo("binary", "application/octet-stream", None, True)
    return MediaInfo("binary", "application/octet-stream")


def _looks_like_text(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:8192]
    if sample.startswith((codecs.BOM_UTF8, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return True
    nul_ratio = sample.count(0) / len(sample)
    if nul_ratio > 0.20:
        # UTF-16 without a BOM commonly has alternating NUL bytes.
        even_nuls = sample[0::2].count(0)
        odd_nuls = sample[1::2].count(0)
        if max(even_nuls, odd_nuls) < len(sample) // 4:
            return False
    control = sum(1 for byte in sample if byte < 32 and byte not in b"\t\n\r\f\b\x00")
    if control / len(sample) > 0.02:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def decode_text(data: bytes) -> tuple[str | None, str | None]:
    """Return decoded text and encoding, or ``(None, None)`` conservatively."""

    candidates: list[str] = []
    if data.startswith(codecs.BOM_UTF8):
        candidates.append("utf-8-sig")
    elif data.startswith(codecs.BOM_UTF16_LE):
        candidates.append("utf-16-le")
    elif data.startswith(codecs.BOM_UTF16_BE):
        candidates.append("utf-16-be")
    else:
        sample = data[:8192]
        odd_nuls = sample[1::2].count(0)
        even_nuls = sample[0::2].count(0)
        if odd_nuls > max(2, len(sample) // 8):
            candidates.append("utf-16-le")
        elif even_nuls > max(2, len(sample) // 8):
            candidates.append("utf-16-be")
        candidates.extend(["utf-8", "gb18030"])

    for encoding in candidates:
        try:
            text = data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
        if "\x00" in text and text.count("\x00") > max(1, len(text) // 100):
            continue
        if _decoded_text_is_plausible(text):
            return text.lstrip("\ufeff"), encoding
    return None, None


def _decoded_text_is_plausible(text: str) -> bool:
    if not text:
        return True
    controls = sum(1 for char in text[:8192] if ord(char) < 32 and char not in "\t\n\r\f\b")
    replacements = text[:8192].count("\ufffd")
    return controls + replacements <= max(1, len(text[:8192]) // 100)


def suspicious_extension(path: str, info: MediaInfo) -> bool:
    return info.extension_mismatch or bool(re.search(r"\.(?:jpg|png|pdf|docx|xlsx|pptx)\.(?:exe|scr|bat|cmd)$", path, re.I))
