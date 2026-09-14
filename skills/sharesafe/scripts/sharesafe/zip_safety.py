"""Small, allocation-bounded ZIP central-directory preflight checks."""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Literal


_EOCD = b"PK\x05\x06"
_ZIP64_EOCD = b"PK\x06\x06"
_ZIP64_LOCATOR = b"PK\x06\x07"
_CENTRAL_FILE = b"PK\x01\x02"
_CENTRAL_SIGNATURE = b"PK\x05\x05"
_EOCD_SIZE = 22
_MAX_COMMENT = 65_535


@dataclass(frozen=True, slots=True)
class ZipPreflight:
    """Result returned before ``zipfile`` materializes one object per entry."""

    status: Literal["ok", "entry_limit", "malformed"]
    entries: int | None = None


def _find_eocd(data: bytes) -> int | None:
    start = max(0, len(data) - _EOCD_SIZE - _MAX_COMMENT)
    cursor = data.rfind(_EOCD, start)
    while cursor >= 0:
        if cursor + _EOCD_SIZE <= len(data):
            comment_size = struct.unpack_from("<H", data, cursor + 20)[0]
            if cursor + _EOCD_SIZE + comment_size == len(data):
                return cursor
        cursor = data.rfind(_EOCD, start, cursor)
    return None


def _zip64_record(data: bytes, locator: int) -> tuple[int, int, int] | None:
    """Return physical record offset, entry count, and central-directory size."""

    if locator < 20 or data[locator : locator + 4] != _ZIP64_LOCATOR:
        return None
    _, locator_disk, _relative_offset, disks = struct.unpack_from("<4sLQL", data, locator)
    if locator_disk != 0 or disks != 1:
        return None

    cursor = data.rfind(_ZIP64_EOCD, 0, locator)
    while cursor >= 0:
        if cursor + 12 <= locator:
            record_payload_size = struct.unpack_from("<Q", data, cursor + 4)[0]
            if record_payload_size >= 44 and cursor + 12 + record_payload_size == locator:
                if cursor + 56 > locator:
                    return None
                (
                    _version_made,
                    _version_needed,
                    disk_number,
                    directory_disk,
                    entries_on_disk,
                    entries_total,
                    directory_size,
                    _directory_offset,
                ) = struct.unpack_from("<2H2L4Q", data, cursor + 12)
                if disk_number != 0 or directory_disk != 0 or entries_on_disk != entries_total:
                    return None
                return cursor, entries_total, directory_size
        cursor = data.rfind(_ZIP64_EOCD, 0, cursor)
    return None


def preflight_zip(data: bytes, max_entries: int) -> ZipPreflight:
    """Count ZIP entries without creating an unbounded ``ZipInfo`` list.

    The central directory is walked directly and stops after ``max_entries +
    1`` records. Any ambiguity is returned as ``malformed`` so callers can
    report incomplete coverage instead of passing attacker-controlled counts
    to :mod:`zipfile`.
    """

    if max_entries < 1:
        raise ValueError("max_entries must be positive")
    eocd = _find_eocd(data)
    if eocd is None:
        return ZipPreflight("malformed")
    try:
        (
            disk_number,
            directory_disk,
            entries_on_disk,
            entries_total,
            directory_size,
            _directory_offset,
            _comment_size,
        ) = struct.unpack_from("<4H2LH", data, eocd + 4)
    except struct.error:
        return ZipPreflight("malformed")
    if disk_number != 0 or directory_disk != 0 or entries_on_disk != entries_total:
        return ZipPreflight("malformed")

    directory_end = eocd
    locator = eocd - 20
    has_zip64_locator = locator >= 0 and data[locator : locator + 4] == _ZIP64_LOCATOR
    needs_zip64 = (
        entries_on_disk == 0xFFFF
        or entries_total == 0xFFFF
        or directory_size == 0xFFFFFFFF
        or _directory_offset == 0xFFFFFFFF
    )
    if has_zip64_locator or needs_zip64:
        record = _zip64_record(data, locator)
        if record is None:
            return ZipPreflight("malformed")
        directory_end, entries_total, directory_size = record

    if entries_total > max_entries:
        return ZipPreflight("entry_limit", entries_total)
    if directory_size > directory_end:
        return ZipPreflight("malformed")

    cursor = directory_end - directory_size
    observed = 0
    while cursor + 4 <= directory_end and data[cursor : cursor + 4] == _CENTRAL_FILE:
        if cursor + 46 > directory_end:
            return ZipPreflight("malformed")
        try:
            name_size, extra_size, comment_size = struct.unpack_from("<3H", data, cursor + 28)
        except struct.error:
            return ZipPreflight("malformed")
        record_size = 46 + name_size + extra_size + comment_size
        if record_size < 46 or cursor + record_size > directory_end:
            return ZipPreflight("malformed")
        observed += 1
        if observed > max_entries:
            return ZipPreflight("entry_limit", observed)
        cursor += record_size

    # The only non-file record allowed at the end of a central directory is
    # its optional digital signature.
    if cursor < directory_end and data[cursor : cursor + 4] == _CENTRAL_SIGNATURE:
        if cursor + 6 > directory_end:
            return ZipPreflight("malformed")
        signature_size = struct.unpack_from("<H", data, cursor + 4)[0]
        cursor += 6 + signature_size
    if cursor != directory_end or observed != entries_total:
        return ZipPreflight("malformed", observed)
    return ZipPreflight("ok", observed)


__all__ = ["ZipPreflight", "preflight_zip"]
