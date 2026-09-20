"""Resource limits used by every parser.

The defaults intentionally favor bounded, explainable work over heroic parsing. A
limit hit is a coverage gap, never a clean result.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re


DEFAULT_MAX_NAME_BYTES = 4 * 1024
DEFAULT_MAX_DISPLAY_PATH_CHARS = 16 * 1024
DEFAULT_MAX_REPORT_FIELD_CHARS = 16 * 1024
DEFAULT_MAX_GAPS_TOTAL = 10_000
DEFAULT_MAX_ERRORS_TOTAL = 1_000
DEFAULT_MAX_REPORT_BYTES = 32 * 1024 * 1024

# ``ReportBuilder`` may need to communicate that ordinary gaps, errors, fields,
# or the report itself were truncated.  These slots are therefore never made
# available to ordinary parser gaps.
REPORT_CONTROL_GAP_RESERVE = 4
MIN_REPORT_BYTES = 4 * 1024
MAX_LIMIT_VALUE = (1 << 63) - 1


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
    max_name_bytes: int = DEFAULT_MAX_NAME_BYTES
    max_display_path_chars: int = DEFAULT_MAX_DISPLAY_PATH_CHARS
    max_report_field_chars: int = DEFAULT_MAX_REPORT_FIELD_CHARS
    max_gaps_total: int = DEFAULT_MAX_GAPS_TOTAL
    max_errors_total: int = DEFAULT_MAX_ERRORS_TOTAL
    max_report_bytes: int = DEFAULT_MAX_REPORT_BYTES

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
            minimum = 0 if name in {"max_archive_depth", "max_directory_depth"} else 1
            if value < minimum or value > MAX_LIMIT_VALUE:
                raise ValueError(f"{name} must be between {minimum} and {MAX_LIMIT_VALUE}")
        if self.max_name_bytes < 64:
            raise ValueError("max_name_bytes must be at least 64")
        if self.max_display_path_chars < 256:
            raise ValueError("max_display_path_chars must be at least 256")
        if self.max_report_field_chars < 256:
            raise ValueError("max_report_field_chars must be at least 256")
        if self.max_gaps_total < REPORT_CONTROL_GAP_RESERVE:
            raise ValueError(
                f"max_gaps_total must be at least {REPORT_CONTROL_GAP_RESERVE}"
            )
        if self.max_report_bytes < MIN_REPORT_BYTES:
            raise ValueError(f"max_report_bytes must be at least {MIN_REPORT_BYTES}")

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
