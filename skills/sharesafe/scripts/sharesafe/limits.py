"""Resource limits used by every parser.

The defaults intentionally favor bounded, explainable work over heroic parsing. A
limit hit is a coverage gap, never a clean result.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re


@dataclass(frozen=True, slots=True)
class Limits:
    max_file_bytes: int = 50 * 1024 * 1024
    max_total_file_bytes: int = 1024 * 1024 * 1024
    max_files: int = 20_000
    max_directory_depth: int = 64
    max_text_bytes: int = 16 * 1024 * 1024
    max_findings_per_artifact: int = 1_000
    max_findings_total: int = 10_000
    max_archive_entries: int = 2_000
    max_archive_member_bytes: int = 32 * 1024 * 1024
    max_expanded_bytes: int = 256 * 1024 * 1024
    max_compression_ratio: int = 200
    max_archive_depth: int = 3
    max_xml_bytes: int = 16 * 1024 * 1024
    max_pdf_pages: int = 500

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


_SIZE_RE = re.compile(r"^(?P<number>\d+)(?P<unit>b|kb|kib|mb|mib|gb|gib)?$", re.I)
_MULTIPLIERS = {
    None: 1,
    "b": 1,
    "kb": 1_000,
    "kib": 1_024,
    "mb": 1_000_000,
    "mib": 1_048_576,
    "gb": 1_000_000_000,
    "gib": 1_073_741_824,
}


def parse_size(value: str) -> int:
    """Parse a non-negative human size without accepting floats or ambiguity."""

    match = _SIZE_RE.fullmatch(value.strip())
    if not match:
        raise ValueError(f"invalid size: {value!r}")
    number = int(match.group("number"))
    unit = match.group("unit")
    multiplier = _MULTIPLIERS[unit.lower() if unit else None]
    result = number * multiplier
    if result <= 0:
        raise ValueError("size must be greater than zero")
    return result
