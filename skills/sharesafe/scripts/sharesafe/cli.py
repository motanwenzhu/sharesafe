"""ShareSafe command-line interface."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from . import __version__
from .capabilities import doctor_payload as build_doctor_payload
from .catalog import FORMATS, RULE_GROUPS, RULESET_VERSION, exact_rule_catalog
from .check import CheckError, build_check
from .detectors import temporary_hmac_key
from .engine import ScanConfig, Scanner
from .limits import Limits, parse_size
from .models import SEVERITIES
from .path_safety import same_or_within, uses_windows_alternate_stream
from .policy import Policy, PolicyError, load_policy, normalize_policy, resolve_policy
from .prepare import (
    PrepareWorkflowError,
    apply_prepare_plan,
    prepare_inspection,
    verify_prepare_output,
)
from .prepare_decisions import PrepareDecisionError, load_prepare_decisions_file
from .prepare_io import (
    PrepareIOError,
    load_prepare_approval_file,
    load_prepare_plan_file,
    write_prepare_approval_file,
    write_prepare_plan_file,
)
from .prepare_plan import PreparePlanError, create_prepare_approval, create_prepare_plan
from .redaction import user_home_container_context
from .report_tools import (
    GROUP_BY_VALUES,
    REPORT_DIFF_SCHEMA,
    REPORT_SHOW_SCHEMA,
    SHARE_SUMMARY_SCHEMA,
    ReportToolError,
    diff_report_files,
    share_summary_file,
    show_report_file,
)
from .reporting import json_text, render_operation, render_scan, write_json_atomic
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

    check = commands.add_parser("check", help="scan and record a reproducible policy decision")
    check.add_argument("paths", nargs="+", metavar="PATH")
    check.add_argument("--config", type=Path, help="explicit policy TOML; overrides ./.sharesafe.toml")
    _add_check_options(check)
    _add_output_options(check)

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
    doctor.add_argument("--deep", action="store_true", help="execute offline synthetic dependency probes")
    doctor.add_argument("--json", action="store_true", dest="as_json")

    rules = commands.add_parser("rules", help="list stable rule groups")
    rules.add_argument("--detail", action="store_true", help="list every exact versioned rule")
    rules.add_argument("--json", action="store_true", dest="as_json")

    formats = commands.add_parser("formats", help="show the supported format matrix")
    formats.add_argument("--json", action="store_true", dest="as_json")

    policy = commands.add_parser("policy", help="create, validate, or display a strict local policy")
    policy_commands = policy.add_subparsers(dest="policy_command", required=True)
    policy_init = policy_commands.add_parser("init", help="create a new default policy without overwriting")
    policy_init.add_argument("--out", required=True, type=Path, metavar="NEW_FILE")
    policy_init.add_argument("--json", action="store_true", dest="as_json")
    for action in ("validate", "show"):
        subcommand = policy_commands.add_parser(action, help=f"{action} an explicit policy file")
        subcommand.add_argument("--config", required=True, type=Path)
        subcommand.add_argument("--json", action="store_true", dest="as_json")

    report = commands.add_parser(
        "report", help="inspect or compare saved masked reports without rescanning"
    )
    report_commands = report.add_subparsers(dest="report_command", required=True)
    report_show = report_commands.add_parser(
        "show",
        help="show a bounded aggregate view of one report",
        description=(
            "Show a bounded aggregate view of one already-masked report without "
            "rescanning source files."
        ),
    )
    report_show.add_argument("report_path", type=Path, metavar="REPORT")
    report_show.add_argument("--group-by", choices=GROUP_BY_VALUES, default="rule")
    report_show.add_argument("--min-severity", choices=SEVERITIES, default="info")
    report_show.add_argument("--json", action="store_true", dest="as_json")

    report_diff = report_commands.add_parser(
        "diff",
        help="compare rule/path/location structures in two reports",
        description=(
            "Compare only rule/path/location structures in two masked reports; "
            "structural equality does not establish finding or content identity."
        ),
    )
    report_diff.add_argument("old_report", type=Path, metavar="OLD")
    report_diff.add_argument("new_report", type=Path, metavar="NEW")
    report_diff.add_argument("--json", action="store_true", dest="as_json")

    report_summary = report_commands.add_parser(
        "share-summary",
        help="derive a minimal aggregate view for optional sharing",
        description=(
            "Derive a minimal aggregate view without per-artifact details. "
            "Generation does not authorize sharing or uploading it."
        ),
    )
    report_summary.add_argument("report_path", type=Path, metavar="REPORT")
    report_summary.add_argument("--json", action="store_true", dest="as_json")

    prepare = commands.add_parser(
        "prepare",
        help="build a new share boundary from an explicit local-only plan",
    )
    prepare_commands = prepare.add_subparsers(dest="prepare_command", required=True)

    prepare_plan = prepare_commands.add_parser(
        "plan",
        help="bind explicit decisions to the complete current source inventory",
    )
    prepare_plan.add_argument("source", metavar="SOURCE")
    prepare_plan.add_argument(
        "--decisions",
        required=True,
        type=Path,
        metavar="LOCAL_DECISIONS_JSON",
        help="strict local-only decisions covering every source file",
    )
    prepare_plan.add_argument(
        "--out-plan",
        required=True,
        type=Path,
        metavar="NEW_LOCAL_PLAN",
    )
    _add_scan_options(prepare_plan)
    prepare_plan.add_argument("--json", action="store_true", dest="as_json")

    prepare_inspect = prepare_commands.add_parser(
        "inspect",
        help="show a masked review view without source bindings",
    )
    prepare_inspect.add_argument("plan", type=Path, metavar="LOCAL_PLAN")
    prepare_inspect.add_argument("--json", action="store_true", dest="as_json")

    prepare_approve = prepare_commands.add_parser(
        "approve",
        help="approve every action in one exact executable plan",
    )
    prepare_approve.add_argument("plan", type=Path, metavar="LOCAL_PLAN")
    prepare_approve.add_argument(
        "--out-approval",
        required=True,
        type=Path,
        metavar="NEW_LOCAL_APPROVAL",
    )
    prepare_approve.add_argument(
        "--approve-all",
        action="store_true",
        required=True,
        help="explicitly approve the complete action set after inspection",
    )
    prepare_approve.add_argument("--json", action="store_true", dest="as_json")

    prepare_apply = prepare_commands.add_parser(
        "apply",
        help="execute an exact approved plan into one absent output directory",
    )
    prepare_apply.add_argument("plan", type=Path, metavar="LOCAL_PLAN")
    prepare_apply.add_argument("--approval", required=True, type=Path, metavar="LOCAL_APPROVAL")
    prepare_apply.add_argument("--source", required=True, metavar="SOURCE")
    prepare_apply.add_argument("--out", required=True, metavar="NEW_OUTPUT_DIRECTORY")
    _add_scan_options(prepare_apply)
    _add_output_options(prepare_apply)

    prepare_verify = prepare_commands.add_parser(
        "verify",
        help="recompute expected bytes from SOURCE and verify an existing output",
    )
    prepare_verify.add_argument("plan", type=Path, metavar="LOCAL_PLAN")
    prepare_verify.add_argument("--source", required=True, metavar="SOURCE")
    prepare_verify.add_argument("--output", required=True, metavar="OUTPUT_DIRECTORY")
    _add_scan_options(prepare_verify)
    _add_output_options(prepare_verify)

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


def _add_check_options(parser: argparse.ArgumentParser) -> None:
    """Add policy overrides while retaining whether the user set each value."""

    parser.add_argument("--fail-on", choices=[*SEVERITIES, "never"], default=None)
    parser.add_argument("--max-file-size", type=parse_size, default=None, metavar="SIZE")
    parser.add_argument("--max-archive-depth", type=int, default=None, metavar="N")
    parser.add_argument("--max-archive-entries", type=int, default=None, metavar="N")
    parser.add_argument("--max-findings-per-artifact", type=int, default=None, metavar="N")
    parser.add_argument("--max-findings-total", type=int, default=None, metavar="N")
    optional = parser.add_mutually_exclusive_group()
    optional.add_argument("--optional-tools", action="store_true", dest="optional_tools")
    optional.add_argument("--no-optional-tools", action="store_false", dest="optional_tools")
    parser.set_defaults(optional_tools=None)


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


def _check_policy_overrides(args: argparse.Namespace) -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    if args.fail_on is not None:
        overrides["fail_on"] = args.fail_on
    if args.optional_tools is not None:
        overrides["optional_tools"] = args.optional_tools
    limits: dict[str, int] = {}
    for argument, field in (
        ("max_file_size", "max_file_bytes"),
        ("max_archive_depth", "max_archive_depth"),
        ("max_archive_entries", "max_archive_entries"),
        ("max_findings_per_artifact", "max_findings_per_artifact"),
        ("max_findings_total", "max_findings_total"),
    ):
        value = getattr(args, argument)
        if value is not None:
            limits[field] = value
    if limits:
        overrides["limits"] = limits
    return overrides


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left.absolute())) == os.path.normcase(str(right.absolute()))


def _resolved_check_policy(args: argparse.Namespace) -> Policy:
    project_candidate = Path.cwd() / ".sharesafe.toml"
    project_config: Path | None = None
    if project_candidate.exists() or project_candidate.is_symlink():
        project_config = project_candidate
    if args.config is not None and project_config is not None and _same_path(args.config, project_config):
        project_config = None
    return resolve_policy(
        project_config=project_config,
        explicit_config=args.config,
        overrides=_check_policy_overrides(args),
    )


def _emit_check(payload: dict[str, Any], args: argparse.Namespace) -> None:
    if args.report:
        write_json_atomic(args.report, payload)
    if args.as_json:
        sys.stdout.write(json_text(payload))
        return
    render_scan(payload["report"], sys.stdout)
    decision = payload["decision"]
    sys.stdout.write(
        "Policy decision: "
        f"{decision['policy_outcome']} (exit {decision['exit_code']}; "
        f"technical {decision['technical_verdict']})\n"
    )


def _check_command(args: argparse.Namespace) -> int:
    paths = [Path(path) for path in args.paths]
    _preflight_report_target(args.report, paths)
    policy = _resolved_check_policy(args)
    scanner = Scanner(
        ScanConfig(
            limits=policy.limits,
            optional_tools=policy.optional_tools,
            logical_paths=False,
        )
    )
    report = scanner.scan(args.paths).to_dict()
    # An enabled manifest cannot be treated as validated merely because its
    # settings parsed.  Until an exact inventory validator supplies a success
    # receipt, build_check intentionally returns incomplete.
    payload = build_check(report, policy, manifest_validation=None)
    _emit_check(payload, args)
    return int(payload["decision"]["exit_code"])


def _policy_toml(policy: Policy) -> str:
    normalized = normalize_policy(policy)
    lines = [
        f'schema = "{normalized["schema"]}"',
        f'fail_on = "{normalized["fail_on"]}"',
        "required_capabilities = []",
        "blocking_categories = []",
        f'optional_tools = {str(normalized["optional_tools"]).lower()}',
        "",
        "[limits]",
    ]
    lines.extend(f"{name} = {value}" for name, value in normalized["limits"].items())
    lines.extend(
        (
            "",
            "[manifest]",
            "enabled = false",
            "require_exact = true",
            "",
        )
    )
    return "\n".join(lines)


def _emit_policy_result(payload: dict[str, Any], args: argparse.Namespace, text: str) -> None:
    if args.as_json:
        sys.stdout.write(json_text(payload))
    else:
        sys.stdout.write(text + "\n")


def _policy_command(args: argparse.Namespace) -> int:
    if args.policy_command == "init":
        destination = args.out.absolute()
        if uses_windows_alternate_stream(destination):
            raise ValueError("Windows alternate data stream policy paths are not supported")
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("policy destination already exists")
        destination.parent.mkdir(parents=True, exist_ok=True)
        policy = resolve_policy()
        with destination.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(_policy_toml(policy))
            handle.flush()
            os.fsync(handle.fileno())
        payload = {
            "schema": "sharesafe.policy-init/v1",
            "created": True,
            "destination": "<new-policy>",
            "policy_digest": policy.digest,
        }
        _emit_policy_result(payload, args, "ShareSafe policy created at the requested new path.")
        return EXIT_OK

    policy = load_policy(args.config)
    normalized = normalize_policy(policy)
    if args.policy_command == "validate":
        payload = {
            "schema": "sharesafe.policy-validation/v1",
            "valid": True,
            "policy_digest": policy.digest,
            "ruleset_version": RULESET_VERSION,
        }
        _emit_policy_result(payload, args, "ShareSafe policy: valid.")
        return EXIT_OK
    if args.policy_command == "show":
        payload = {
            "schema": "sharesafe.policy-view/v1",
            "policy": normalized,
            "policy_digest": policy.digest,
            "ruleset_version": RULESET_VERSION,
        }
        _emit_policy_result(payload, args, "ShareSafe policy loaded; use --json to inspect it.")
        return EXIT_OK
    raise CLIUsageError("unknown policy command")


def _format_severity_counts(counts: dict[str, Any]) -> str:
    rendered = [
        f"{severity}={counts[severity]}"
        for severity in SEVERITIES
        if counts[severity]
    ]
    return ", ".join(rendered) if rendered else "none"


def _render_report_view(payload: dict[str, Any]) -> None:
    """Render only fields already bounded and validated by ``report_tools``."""

    schema = payload["schema"]
    if schema == REPORT_SHOW_SCHEMA:
        selection = payload["selection"]
        summary = payload["summary"]
        sys.stdout.write(
            "ShareSafe report view: "
            f"{summary['technical_verdict']}; "
            f"{selection['selected_findings']} selected, "
            f"{selection['filtered_findings']} filtered.\n"
        )
        sys.stdout.write(
            f"Grouped by {selection['group_by']} at minimum severity "
            f"{selection['min_severity']}.\n"
        )
        if summary["policy_outcome"] is not None:
            sys.stdout.write(
                f"Recorded policy outcome: {summary['policy_outcome']}.\n"
            )
        for group in payload["groups"]:
            counts = _format_severity_counts(group["findings_by_severity"])
            sys.stdout.write(f"- {group['value']}: {group['count']} ({counts})\n")
        return

    if schema == REPORT_DIFF_SCHEMA:
        summary = payload["summary"]
        context = payload["context"]
        sys.stdout.write(
            "ShareSafe structural diff: "
            f"{summary['same_rule_path_location']} unchanged, "
            f"{summary['structure_new']} new, "
            f"{summary['structure_resolved']} resolved.\n"
        )
        change_labels = {True: "yes", False: "no", None: "unknown"}
        sys.stdout.write(
            "Context changed: "
            f"schema={change_labels[context['schema_changed']]}, "
            f"ruleset={change_labels[context['ruleset_changed']]}, "
            f"policy={change_labels[context['policy_changed']]}.\n"
        )
        for field, heading in (
            ("structure_new", "New structures"),
            ("structure_resolved", "Resolved structures"),
        ):
            records = payload[field]
            if records:
                sys.stdout.write(f"{heading}:\n")
            for record in records:
                location = json.dumps(
                    record["location"],
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                sys.stdout.write(
                    f"- {record['rule_id']} at {record['path']} {location} "
                    f"(count={record['count']})\n"
                )
        sys.stdout.write(
            "Structural equality does not establish finding or content identity.\n"
        )
        return

    if schema == SHARE_SUMMARY_SCHEMA:
        summary = payload["summary"]
        sys.stdout.write(
            "ShareSafe share summary: "
            f"{summary['technical_verdict']}; "
            f"{summary['artifacts_total']} artifacts, "
            f"{_format_severity_counts(summary['findings_by_severity'])} findings.\n"
        )
        sys.stdout.write(
            f"Coverage: {summary['artifacts_complete']} complete, "
            f"{summary['artifacts_partial']} partial, {summary['gaps']} gaps, "
            f"{summary['errors']} errors, "
            f"{summary['unavailable_dependencies']} unavailable dependencies.\n"
        )
        if summary["policy_outcome"] is not None:
            sys.stdout.write(
                "Recorded policy outcome: "
                f"{summary['policy_outcome']} (exit {summary['decision_exit_code']}).\n"
            )
        sys.stdout.write(
            "Generating this aggregate view does not authorize uploading or sharing it.\n"
        )
        return

    raise ReportToolError(
        "invalid_derived_report", "Derived report has an unsupported schema."
    )


def _emit_report_view(payload: dict[str, Any], args: argparse.Namespace) -> None:
    if args.as_json:
        # The report-tools boundary has already validated the unchanged payload
        # against its source limits and an independent serialized byte budget.
        sys.stdout.write(
            json.dumps(
                payload,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        )
    else:
        _render_report_view(payload)


def _report_command(args: argparse.Namespace) -> int:
    if args.report_command == "show":
        payload = show_report_file(
            args.report_path,
            group_by=args.group_by,
            min_severity=args.min_severity,
        )
    elif args.report_command == "diff":
        payload = diff_report_files(args.old_report, args.new_report)
    elif args.report_command == "share-summary":
        payload = share_summary_file(args.report_path)
    else:
        raise CLIUsageError("unknown report command")
    _emit_report_view(payload, args)
    return EXIT_OK


def _control_path_outside_source(source: Path, candidate: Path) -> None:
    """Keep decisions and control output outside the selected share source."""

    try:
        inside = source.exists() and source.is_dir() and same_or_within(candidate, source)
    except ValueError as exc:
        raise PrepareWorkflowError("unsafe_path") from exc
    if inside:
        raise PrepareWorkflowError("control_artifact_inside_source")


def _emit_prepare_control(payload: dict[str, Any], args: argparse.Namespace) -> None:
    if args.as_json:
        sys.stdout.write(json_text(payload))
        return
    operation = payload["operation"]
    if operation == "plan":
        sys.stdout.write(
            "ShareSafe local-only plan created. Inspect it before approval; do not share it.\n"
        )
    else:
        sys.stdout.write(
            "ShareSafe local-only approval created for the exact plan; do not share it.\n"
        )


def _render_prepare_inspection(payload: dict[str, Any]) -> None:
    state = "executable" if payload["executable"] else "not executable"
    sys.stdout.write(
        f"ShareSafe prepare inspection: {payload['item_count']} actions; {state}.\n"
    )
    for action in payload["actions"]:
        target = action["target_path"] if action["target_path"] is not None else "<omitted>"
        losses = ",".join(action["known_losses"]) or "none"
        sys.stdout.write(
            f"- {action['action_id']}: {action['source_path']} -> {target}; "
            f"{action['action']} ({action['reason_code']}); "
            f"relation={action['expected_relation']}; losses={losses}\n"
        )
    sys.stdout.write(
        "This masked view omits strong source bindings; approval still binds the exact local plan.\n"
    )


def _emit_prepare_result(payload: dict[str, Any], args: argparse.Namespace) -> None:
    if args.report:
        write_json_atomic(args.report, payload)
    if args.as_json:
        sys.stdout.write(json_text(payload))
        return
    render_scan(payload["final_scan"], sys.stdout)
    verification = payload["verification"]
    sys.stdout.write(
        "Prepare verification: "
        f"{verification['outcome']}; {verification['observed_files']}/"
        f"{verification['expected_files']} output files observed; "
        f"{verification['issue_count']} verification/reporting issues.\n"
    )
    reporting = payload["reporting"]
    if reporting["detail"] == "truncated":
        plan_summary = payload["plan_summary"]
        sys.stdout.write(
            "Prepare result detail was bounded: "
            f"{plan_summary['action_results_omitted']} action records and "
            f"{verification['issues_omitted']} issue records omitted; "
            f"final scan detail={reporting['final_scan_detail']}.\n"
        )
    sys.stdout.write(payload["statement"] + "\n")


def _prepare_plan_command(args: argparse.Namespace) -> int:
    source = Path(args.source)
    _control_path_outside_source(source, args.decisions)
    _control_path_outside_source(source, args.out_plan)
    decisions = load_prepare_decisions_file(args.decisions)
    plan = create_prepare_plan(
        source,
        decisions,
        limits=_limits_from_args(args),
    )
    write_result = write_prepare_plan_file(
        args.out_plan,
        plan,
        limits=_limits_from_args(args),
    )
    payload = {
        "schema": "sharesafe.prepare-control-write/v1",
        "operation": "plan",
        "artifact": "<local-plan>",
        "classification": "local_only_do_not_share",
        "created": True,
        "item_count": plan.item_count,
        "executable": plan.executable,
        "storage": write_result.to_dict(),
    }
    _emit_prepare_control(payload, args)
    return EXIT_OK


def _prepare_inspect_command(args: argparse.Namespace) -> int:
    plan = load_prepare_plan_file(args.plan)
    payload = prepare_inspection(plan)
    if args.as_json:
        sys.stdout.write(json_text(payload))
    else:
        _render_prepare_inspection(payload)
    return EXIT_OK


def _prepare_approve_command(args: argparse.Namespace) -> int:
    plan = load_prepare_plan_file(args.plan)
    approval = create_prepare_approval(
        plan,
        [action.action_id for action in plan.actions],
    )
    write_result = write_prepare_approval_file(
        args.out_approval,
        approval,
        plan=plan,
    )
    payload = {
        "schema": "sharesafe.prepare-control-write/v1",
        "operation": "approve",
        "artifact": "<local-approval>",
        "classification": "local_only_do_not_share",
        "created": True,
        "item_count": plan.item_count,
        "executable": plan.executable,
        "storage": write_result.to_dict(),
    }
    _emit_prepare_control(payload, args)
    return EXIT_OK


def _prepare_apply_command(args: argparse.Namespace) -> int:
    source = Path(args.source)
    output = Path(args.out)
    protected = [source, output, args.plan, args.approval]
    _preflight_report_target(args.report, protected)
    plan = load_prepare_plan_file(args.plan, limits=_limits_from_args(args))
    approval = load_prepare_approval_file(args.approval, plan=plan)
    result = apply_prepare_plan(
        source,
        output,
        plan,
        approval,
        limits=_limits_from_args(args),
        optional_tools=not args.no_optional_tools,
        fail_on=args.fail_on,
        tool_version=__version__,
    )
    _emit_prepare_result(result.payload, args)
    return result.exit_code


def _prepare_verify_command(args: argparse.Namespace) -> int:
    source = Path(args.source)
    output = Path(args.output)
    _preflight_report_target(args.report, [source, output, args.plan])
    plan = load_prepare_plan_file(args.plan, limits=_limits_from_args(args))
    result = verify_prepare_output(
        source,
        output,
        plan,
        limits=_limits_from_args(args),
        optional_tools=not args.no_optional_tools,
        fail_on=args.fail_on,
        tool_version=__version__,
    )
    _emit_prepare_result(result.payload, args)
    return result.exit_code


def _prepare_command(args: argparse.Namespace) -> int:
    if args.prepare_command == "plan":
        return _prepare_plan_command(args)
    if args.prepare_command == "inspect":
        return _prepare_inspect_command(args)
    if args.prepare_command == "approve":
        return _prepare_approve_command(args)
    if args.prepare_command == "apply":
        return _prepare_apply_command(args)
    if args.prepare_command == "verify":
        return _prepare_verify_command(args)
    raise CLIUsageError("unknown prepare command")


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
    before = before_builder.to_dict()
    actions = create_sanitized_copy(
        source_path,
        output_path,
        before_scanner.config.limits,
        evidence_key=key,
        before_report=before,
    )
    after_scanner = _scanner_from_args(
        args,
        logical_paths=True,
        key=key,
        root_directory_context=root_context,
    )
    after_builder = after_scanner.scan([args.out])
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


def doctor_payload(*, deep: bool = False) -> dict[str, Any]:
    """Compatibility wrapper around the capability module."""

    return build_doctor_payload(deep=deep, tool_version=__version__)


def _print_simple(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        sys.stdout.write(json_text(payload))
    else:
        if "items" in payload:
            for item in payload["items"]:
                name = item.get("prefix") or item.get("format") or item.get("rule_id")
                description = item.get("description") or item.get("scan") or item.get("validator")
                sys.stdout.write(f"- {name}: {description}\n")
        else:
            sys.stdout.write(f"ShareSafe doctor: {payload['status']} (offline, no telemetry)\n")
            for item in payload["optional"]:
                state = "available" if item["available"] else "missing"
                sys.stdout.write(f"- {item['name']}: {state} — {item['capability']}\n")


def _self_test_payload() -> tuple[dict[str, Any], int]:
    synthetic_email = "demo.person" + "@example.invalid"
    synthetic_key = "sk-" + "S" * 28
    sample_bytes = f"contact={synthetic_email}\napi_key={synthetic_key}\n".encode()
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
        if args.command == "check":
            return _check_command(args)
        if args.command == "sanitize":
            return _sanitize_command(args)
        if args.command == "verify":
            return _verify_command(args)
        if args.command == "doctor":
            payload = doctor_payload(deep=args.deep)
            _print_simple(payload, args.as_json)
            return EXIT_OK if payload["status"] == "ready" else EXIT_INCOMPLETE
        if args.command == "rules":
            payload = {
                "schema": "sharesafe.rules/v1",
                "ruleset_version": RULESET_VERSION,
                "detail": "exact" if args.detail else "groups",
                "items": exact_rule_catalog() if args.detail else list(RULE_GROUPS),
            }
            _print_simple(payload, args.as_json)
            return EXIT_OK
        if args.command == "formats":
            _print_simple({"schema": "sharesafe.formats/v1", "items": list(FORMATS)}, args.as_json)
            return EXIT_OK
        if args.command == "policy":
            return _policy_command(args)
        if args.command == "report":
            return _report_command(args)
        if args.command == "prepare":
            return _prepare_command(args)
        if args.command == "self-test":
            payload, code = _self_test_payload()
            if args.as_json:
                sys.stdout.write(json_text(payload))
            else:
                sys.stdout.write(f"ShareSafe self-test: {'passed' if payload['passed'] else 'failed'}\n")
            return code
        parser.error("unknown command")
    except PolicyError as exc:
        _emit_error(
            code=exc.code,
            message="Policy validation failed; no policy decision was produced.",
            as_json=getattr(args, "as_json", False),
        )
        return EXIT_USAGE
    except CheckError as exc:
        _emit_error(
            code=exc.code,
            message="Check construction failed; no policy decision was produced.",
            as_json=getattr(args, "as_json", False),
        )
        return EXIT_USAGE
    except ReportToolError as exc:
        _emit_error(
            code=exc.code,
            message="Report inspection failed; no derived view was produced.",
            as_json=getattr(args, "as_json", False),
        )
        return EXIT_USAGE
    except PrepareWorkflowError as exc:
        message = (
            "Prepare failed after reserving the new output; an incomplete output may remain and must not be shared."
            if exc.output_may_exist
            else "Prepare refused the request or could not establish the required exact relation."
        )
        _emit_error(
            code=exc.code,
            message=message,
            as_json=getattr(args, "as_json", False),
        )
        return exc.exit_code
    except PrepareIOError as exc:
        _emit_error(
            code=exc.code,
            message="Local prepare control-artifact I/O failed; no new control artifact was accepted.",
            as_json=getattr(args, "as_json", False),
        )
        return EXIT_USAGE
    except (PrepareDecisionError, PreparePlanError) as exc:
        _emit_error(
            code=exc.code,
            message="Prepare control data was invalid; no prepare action was authorized.",
            as_json=getattr(args, "as_json", False),
        )
        return EXIT_USAGE
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
    except Exception:  # noqa: BLE001 - sanitize every unexpected CLI failure.
        _emit_error(
            code="internal_error",
            message=_INTERNAL_ERROR_MESSAGE,
            as_json=getattr(args, "as_json", False),
        )
        return EXIT_INTERNAL
    return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
