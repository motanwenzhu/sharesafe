"""Safe JSON and terminal rendering."""

from __future__ import annotations

import json
import errno
import os
from pathlib import Path
import tempfile
from typing import Any, TextIO

from .path_safety import uses_windows_alternate_stream


def json_text(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path = path.absolute()
    if uses_windows_alternate_stream(path):
        raise ValueError("Windows alternate data stream report paths are not supported")
    if path.exists() or path.is_symlink():
        raise FileExistsError("report destination already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".sharesafe-report-", suffix=".tmp", dir=path.parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temp_path, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise FileExistsError("report destination appeared while writing; nothing was overwritten") from exc
        except (NotImplementedError, OSError) as exc:
            if isinstance(exc, OSError) and exc.errno == errno.EEXIST:
                raise FileExistsError("report destination appeared while writing; nothing was overwritten") from exc
            try:
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            except FileExistsError as nested:
                raise FileExistsError("report destination appeared while writing; nothing was overwritten") from nested
            try:
                with temp_path.open("rb") as source, os.fdopen(descriptor, "wb") as destination:
                    descriptor = -1
                    while chunk := source.read(1024 * 1024):
                        destination.write(chunk)
                    destination.flush()
                    os.fsync(destination.fileno())
            except Exception:
                if descriptor >= 0:
                    os.close(descriptor)
                try:
                    path.unlink()
                except OSError:
                    pass
                raise
    finally:
        if temp_path.exists():
            temp_path.unlink()


def render_scan(report: dict[str, Any], stream: TextIO) -> None:
    summary = report["summary"]
    counts = summary["findings"]
    stream.write(
        f"ShareSafe: {summary['verdict']} | artifacts {summary['artifacts_total']} | "
        f"findings C:{counts['critical']} H:{counts['high']} M:{counts['medium']} "
        f"L:{counts['low']} I:{counts['info']} | gaps {summary['gaps']}\n"
    )
    artifacts = {item["id"]: item for item in report.get("artifacts", [])}
    for finding in report.get("findings", []):
        path = artifacts.get(finding["artifact_id"], {}).get("path", "<unknown>")
        stream.write(f"- [{finding['severity'].upper()}] {finding['rule_id']} — {path}: {finding['title']}\n")
    for gap in report.get("gaps", []):
        artifact = artifacts.get(gap.get("artifact_id"), {})
        path = artifact.get("path", "<scan boundary>")
        stream.write(f"- [INCOMPLETE] {path}: {gap['capability']} / {gap['reason']}\n")
    if summary["verdict"] == "no_findings":
        stream.write("No findings were observed within completed coverage. This is not a guarantee of safety.\n")
    else:
        stream.write("Review findings and all coverage gaps before sharing.\n")


def render_operation(payload: dict[str, Any], stream: TextIO) -> None:
    operation = payload.get("operation", "operation")
    verification = payload.get("verification", {})
    counts = verification.get("counts", {})
    stream.write(
        f"ShareSafe {operation}: {verification.get('outcome', 'unknown')} | "
        f"resolved {counts.get('resolved', 0)} | remaining {counts.get('remaining', 0)} | "
        f"introduced {counts.get('introduced', 0)} | "
        f"integrity {verification.get('integrity', {}).get('outcome', 'unknown')}\n"
    )
    for action in payload.get("actions", []):
        if action.get("status") in {"unsupported", "skipped", "partial", "failed"}:
            reason = f" ({action['reason']})" if action.get("reason") else ""
            stream.write(
                f"- [TRANSFORM {str(action.get('status')).upper()}] "
                f"{action.get('path', '<artifact>')}: {action.get('action', 'unknown')}{reason}\n"
            )
    for issue in verification.get("integrity", {}).get("issues", []):
        stream.write(
            f"- [UNVERIFIED] {issue.get('path', '<artifact>')}: "
            f"{issue.get('code', 'integrity_issue')}\n"
        )
    stream.write(f"{verification.get('statement', 'Review the JSON report before sharing.')}\n")
