"""ShareSafe command-line interface."""

from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import platform
import sys
import tempfile
from typing import Any, Sequence

from . import __version__
from .catalog import FORMATS, RULE_GROUPS
from .detectors import temporary_hmac_key
from .engine import ScanConfig, Scanner
from .limits import Limits, parse_size
from .models import SEVERITIES
from .path_safety import same_or_within, uses_windows_alternate_stream
from .reporting import json_text, render_operation, render_scan, write_json_atomic
from .redaction import user_home_container_context
from .sanitize import UnsafeSanitizeRequest, create_sanitized_copy
from .verify import compare_reports


EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INCOMPLETE = 2
EXIT_USAGE = 3
EXIT_INTERNAL = 4

_INVALID_ARGUMENTS_MESSAGE = "Invalid command-line arguments; run sharesafe --help."
_UNSAFE_REQUEST_MESSAGE = "The request was refused because it is unsafe or invalid."
_FILESYSTEM_ERROR_MESSAGE = "A filesystem operation failed; no safety conclusion was produced."
_INTERNAL_ERROR_MESSAGE = "Unexpected failure; no safety conclusion was produced."


class CLIUsageError(ValueError):
    pass


class ShareSafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CLIUsageError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = ShareSafeArgumentParser(
        prog="sharesafe",
        description="Audit files locally for privacy leaks before sharing. No findings is not a safety guarantee.",
    )
    parser.add_argument("--version", action="version", version=f"ShareSafe {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan files or directories without modifying them")
    scan.add_argument("paths", nargs="+", metavar="PATH")
    _add_scan_options(scan)
    _add_output_options(scan)

    sanitize = commands.add_parser("sanitize", help="create a metadata-reduced copy and rescan it")
    sanitize.add_argument("source", metavar="PATH")
    sanitize.add_argument("--out", required=True, metavar="NEW_PATH")
    _add_scan_options(sanitize)
    _add_output_options(sanitize)

    verify = commands.add_parser("verify", help="compare original and prepared copies with fresh scans")
    verify.add_argument("original")
    verify.add_argument("prepared")
    _add_scan_options(verify)
    _add_output_options(verify)

    doctor = commands.add_parser("doctor", help="show local capabilities and optional dependencies")
    doctor.add_argument("--json", action="store_true", dest="as_json")

    rules = commands.add_parser("rules", help="list stable rule groups")
    rules.add_argument("--json", action="store_true", dest="as_json")

    formats = commands.add_parser("formats", help="show the v0.1 support matrix")
    formats.add_argument("--json", action="store_true", dest="as_json")

    self_test = commands.add_parser("self-test", help="run a small offline synthetic smoke test")
    self_test.add_argument("--json", action="store_true", dest="as_json")
    return parser


def _add_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--fail-on", choices=[*SEVERITIES, "never"], default="high")
    parser.add_argument("--max-file-size", type=parse_size, default=Limits().max_file_bytes, metavar="SIZE")
    parser.add_argument("--max-archive-depth", type=int, default=Limits().max_archive_depth, metavar="N")
    parser.add_argument("--max-archive-entries", type=int, default=Limits().max_archive_entries, metavar="N")
    parser.add_argument(
        "--max-findings-per-artifact",
        type=int,
        default=Limits().max_findings_per_artifact,
        metavar="N",
    )
    parser.add_argument("--max-findings-total", type=int, default=Limits().max_findings_total, metavar="N")
    parser.add_argument("--no-optional-tools", action="store_true")


def _add_output_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", dest="as_json", help="emit only machine-readable JSON to stdout")
    parser.add_argument("--report", type=Path, help="write JSON atomically to a new file")


def _limits_from_args(args: argparse.Namespace) -> Limits:
    if args.max_archive_depth < 0 or args.max_archive_depth > 20:
        raise ValueError("max archive depth must be between 0 and 20")
    if args.max_archive_entries <= 0:
        raise ValueError("max archive entries must be greater than zero")
    if args.max_findings_per_artifact <= 0:
        raise ValueError("max findings per artifact must be greater than zero")
    if args.max_findings_total <= 0:
        raise ValueError("max findings total must be greater than zero")
    return replace(
        Limits(),
        max_file_bytes=args.max_file_size,
        max_archive_depth=args.max_archive_depth,
        max_archive_entries=args.max_archive_entries,
        max_findings_per_artifact=args.max_findings_per_artifact,
        max_findings_total=args.max_findings_total,
    )


def _scanner_from_args(
    args: argparse.Namespace,
    *,
    logical_paths: bool,
    key: bytes | None = None,
    root_directory_context: str | None = None,
) -> Scanner:
    config = ScanConfig(
        limits=_limits_from_args(args),
        optional_tools=not args.no_optional_tools,
        logical_paths=logical_paths,
    )
    return Scanner(
        config,
        evidence_key=key,
        root_directory_context=root_directory_context,
    )


def _emit(payload: dict[str, Any], args: argparse.Namespace, *, operation: bool = False) -> None:
    if getattr(args, "report", None):
        write_json_atomic(args.report, payload)
    if getattr(args, "as_json", False):
        sys.stdout.write(json_text(payload))
    elif operation:
        render_operation(payload, sys.stdout)
    else:
        render_scan(payload, sys.stdout)


def _emit_error(*, code: str, message: str, as_json: bool) -> None:
    """Emit only stable, path-free error contract fields.

    Exception strings are intentionally never accepted here: OSError and its
    subclasses commonly embed absolute filenames (and therefore usernames) in
    ``str(exc)`` on every supported platform.
    """

    payload = {
        "schema": "sharesafe.error/v1",
        "error": {"code": code, "message": message},
    }
    if as_json:
        sys.stdout.write(json_text(payload))
    else:
        sys.stderr.write(f"ShareSafe: {message}\n")


def _same_or_within(candidate: Path, root: Path) -> bool:
    return same_or_within(candidate, root)


def _preflight_report_target(report: Path | None, protected: Sequence[Path]) -> None:
    if report is None:
        return
    if uses_windows_alternate_stream(report):
        raise ValueError("Windows alternate data stream report paths are not supported")
    if report.exists() or report.is_symlink():
        raise FileExistsError("report destination already exists")
    for path in protected:
        if path.exists() and path.is_dir() and _same_or_within(report, path):
            raise ValueError("report destination cannot be inside a scanned directory")
        if _same_or_within(report, path) and not path.is_dir():
            raise ValueError("report destination conflicts with a scanned artifact")


def _scan_command(args: argparse.Namespace) -> int:
    _preflight_report_target(args.report, [Path(path) for path in args.paths])
    scanner = _scanner_from_args(args, logical_paths=False)
    builder = scanner.scan(args.paths)
    report = builder.to_dict()
    _emit(report, args)
    return builder.exit_code(args.fail_on)


def _sanitize_command(args: argparse.Namespace) -> int:
    source_path = Path(args.source)
    output_path = Path(args.out)
    protected = [source_path, output_path]
    _preflight_report_target(args.report, protected)
    key = temporary_hmac_key()
    root_context = (
        user_home_container_context(source_path.name) if source_path.is_dir() else None
    )
    before_scanner = _scanner_from_args(
        args,
        logical_paths=True,
        key=key,
        root_directory_context=root_context,
    )
    before_builder = before_scanner.scan([args.source])
    actions = create_sanitized_copy(source_path, output_path, before_scanner.config.limits)
    after_scanner = _scanner_from_args(
        args,
        logical_paths=True,
        key=key,
        root_directory_context=root_context,
    )
    after_builder = after_scanner.scan([args.out])
    before = before_builder.to_dict()
    after = after_builder.to_dict()
    verification = compare_reports(before, after, allowed_actions=actions)
    payload = {
        "schema": "sharesafe.sanitize/v1",
        "tool": {"name": "sharesafe", "version": __version__},
        "operation": "sanitize",
        "source": "<scan-boundary>",
        "destination": "<new-copy>",
        "actions": actions,
        "before": before,
        "after": after,
        "verification": verification,
    }
    _emit(payload, args, operation=True)
    after_code = after_builder.exit_code(args.fail_on)
    if after_code == EXIT_INCOMPLETE or verification["outcome"] == "incomplete":
        return EXIT_INCOMPLETE
    if verification["outcome"] == "regressed" or not verification["ready_for_review"]:
        return EXIT_FINDINGS
    return after_code


def _verify_command(args: argparse.Namespace) -> int:
    original_path = Path(args.original)
    prepared_path = Path(args.prepared)
    _preflight_report_target(args.report, [original_path, prepared_path])
    key = temporary_hmac_key()
    root_context = (
        user_home_container_context(original_path.name) if original_path.is_dir() else None
    )
    before_builder = _scanner_from_args(
        args,
        logical_paths=True,
        key=key,
        root_directory_context=root_context,
    ).scan([args.original])
    after_builder = _scanner_from_args(
        args,
        logical_paths=True,
        key=key,
        root_directory_context=root_context,
    ).scan([args.prepared])
    before = before_builder.to_dict()
    after = after_builder.to_dict()
    verification = compare_reports(before, after)
    payload = {
        "schema": "sharesafe.verify/v1",
        "tool": {"name": "sharesafe", "version": __version__},
        "operation": "verify",
        "original": before,
        "prepared": after,
        "verification": verification,
    }
    _emit(payload, args, operation=True)
    if (
        before_builder.exit_code("never") == EXIT_INCOMPLETE
        or after_builder.exit_code("never") == EXIT_INCOMPLETE
        or verification["outcome"] == "incomplete"
    ):
        return EXIT_INCOMPLETE
    if verification["outcome"] == "regressed" or not verification["ready_for_review"]:
        return EXIT_FINDINGS
    return after_builder.exit_code(args.fail_on)


def _optional_version(distribution: str) -> str | None:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return None


def doctor_payload() -> dict[str, Any]:
    python_ok = sys.version_info >= (3, 11)
    optional_python = [
        {"name": "Pillow", "available": importlib.util.find_spec("PIL") is not None, "version": _optional_version("Pillow"), "capability": "rich_image_metadata"},
        {"name": "pypdf", "available": importlib.util.find_spec("pypdf") is not None, "version": _optional_version("pypdf"), "capability": "pdf_text_and_structure"},
    ]
    return {
        "schema": "sharesafe.doctor/v1",
        "tool": {"name": "sharesafe", "version": __version__},
        "status": "ready" if python_ok else "unsupported_python",
        "offline": True,
        "telemetry": False,
        "runtime": {"python": platform.python_version(), "implementation": platform.python_implementation(), "platform": platform.system()},
        "core": {"available": python_ok, "minimum_python": "3.11"},
        "optional": optional_python,
        "note": "Missing optional Python dependencies are surfaced as coverage gaps when they affect an input.",
    }


def _print_simple(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        sys.stdout.write(json_text(payload))
    else:
        if "items" in payload:
            for item in payload["items"]:
                name = item.get("prefix") or item.get("format")
                description = item.get("description") or item.get("scan")
                sys.stdout.write(f"- {name}: {description}\n")
        else:
            sys.stdout.write(f"ShareSafe doctor: {payload['status']} (offline, no telemetry)\n")
            for item in payload["optional"]:
                state = "available" if item["available"] else "missing"
                sys.stdout.write(f"- {item['name']}: {state} — {item['capability']}\n")


def _self_test_payload() -> tuple[dict[str, Any], int]:
    synthetic_email = "demo.person" + "@example.invalid"
    synthetic_key = "sk-" + "S" * 28
    sample_bytes = f"contact={synthetic_email}\napi_key={synthetic_key}\n".encode("utf-8")
    first_hmac_key = temporary_hmac_key()
    second_hmac_key = temporary_hmac_key()
    with tempfile.TemporaryDirectory(prefix="sharesafe-self-test-") as directory:
        sample = Path(directory) / "synthetic.txt"
        sample.write_bytes(sample_bytes)
        builder = Scanner(ScanConfig(optional_tools=False), evidence_key=first_hmac_key).scan([sample])
        report = builder.to_dict()
        repeated_report = Scanner(
            ScanConfig(optional_tools=False), evidence_key=first_hmac_key
        ).scan([sample]).to_dict()
        second_key_report = Scanner(
            ScanConfig(optional_tools=False), evidence_key=second_hmac_key
        ).scan([sample]).to_dict()
    serialized = json.dumps(report, ensure_ascii=False)
    rules = {finding["rule_id"] for finding in report["findings"]}
    content_token = report["artifacts"][0].get("content_token")
    repeated_content_token = repeated_report["artifacts"][0].get("content_token")
    second_key_content_token = second_key_report["artifacts"][0].get("content_token")
    raw_file_digest = hashlib.sha256(sample_bytes).hexdigest()
    checks = {
        "email_detected": "pii.email" in rules,
        "secret_detected": "secret.openai_api_key" in rules,
        "raw_email_absent": synthetic_email not in serialized,
        "raw_secret_absent": synthetic_key not in serialized,
        "raw_file_digest_absent": raw_file_digest not in serialized,
        "content_token_is_keyed": (
            isinstance(content_token, str)
            and content_token.startswith("hmac-sha256:content-v1:")
            and content_token == repeated_content_token
            and isinstance(second_key_content_token, str)
            and content_token != second_key_content_token
        ),
        "absolute_temp_path_absent": directory not in serialized,
        "offline_declared": report["run"]["offline"] is True,
    }
    passed = all(checks.values())
    payload = {
        "schema": "sharesafe.self-test/v1",
        "tool": {"name": "sharesafe", "version": __version__},
        "passed": passed,
        "checks": checks,
    }
    return payload, EXIT_OK if passed else EXIT_INTERNAL


def main(argv: Sequence[str] | None = None) -> int:
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    parser = build_parser()
    try:
        args = parser.parse_args(raw_argv)
    except CLIUsageError:
        _emit_error(
            code="invalid_arguments",
            message=_INVALID_ARGUMENTS_MESSAGE,
            as_json="--json" in raw_argv,
        )
        return EXIT_USAGE
    try:
        if args.command == "scan":
            return _scan_command(args)
        if args.command == "sanitize":
            return _sanitize_command(args)
        if args.command == "verify":
            return _verify_command(args)
        if args.command == "doctor":
            payload = doctor_payload()
            _print_simple(payload, args.as_json)
            return EXIT_OK if payload["status"] == "ready" else EXIT_INCOMPLETE
        if args.command == "rules":
            _print_simple({"schema": "sharesafe.rules/v1", "items": list(RULE_GROUPS)}, args.as_json)
            return EXIT_OK
        if args.command == "formats":
            _print_simple({"schema": "sharesafe.formats/v1", "items": list(FORMATS)}, args.as_json)
            return EXIT_OK
        if args.command == "self-test":
            payload, code = _self_test_payload()
            if args.as_json:
                sys.stdout.write(json_text(payload))
            else:
                sys.stdout.write(f"ShareSafe self-test: {'passed' if payload['passed'] else 'failed'}\n")
            return code
        parser.error("unknown command")
    except (UnsafeSanitizeRequest, ValueError, FileExistsError):
        _emit_error(
            code="unsafe_or_invalid_request",
            message=_UNSAFE_REQUEST_MESSAGE,
            as_json=getattr(args, "as_json", False),
        )
        return EXIT_USAGE
    except OSError:
        _emit_error(
            code="filesystem_error",
            message=_FILESYSTEM_ERROR_MESSAGE,
            as_json=getattr(args, "as_json", False),
        )
        return EXIT_INTERNAL
    except KeyboardInterrupt:
        sys.stderr.write("ShareSafe interrupted; no safety conclusion was produced.\n")
        return EXIT_INTERNAL
    except Exception:  # Keep raw paths and sensitive parser text out of error output.
        _emit_error(
            code="internal_error",
            message=_INTERNAL_ERROR_MESSAGE,
            as_json=getattr(args, "as_json", False),
        )
        return EXIT_INTERNAL
    return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
