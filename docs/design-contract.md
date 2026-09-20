# ShareSafe v0.3 design contract

This file is the implementation contract. Public behavior must not drift without a schema or major-version decision.

## Promise

ShareSafe is a local, offline privacy gate for files before they leave a machine. It detects likely disclosure risks and coverage gaps. It never labels a result `safe`; the best verdict is `no_findings` for the capabilities actually completed.

The default operation is read-only. Sanitization creates a new path, never overwrites an input, never edits body text, and immediately rescans its output. Prepare builds only a new directory from a complete explicit plan and approval. Unknown, encrypted, malformed, resource-limited, unsupported, relation-mismatched, or report-truncated results are `incomplete`.

## CLI

```text
sharesafe scan PATH [PATH ...] [--json] [--report FILE] [--fail-on LEVEL]
sharesafe sanitize PATH --out NEW_PATH [--json] [--report FILE]
sharesafe verify ORIGINAL SANITIZED [--json] [--report FILE]
sharesafe check PATH [PATH ...] [--policy FILE] [--json] [--report FILE]
sharesafe policy init --out NEW_FILE
sharesafe report {show,diff,share-summary} ... --json
sharesafe prepare plan SOURCE --decisions LOCAL_JSON --out-plan NEW_PLAN [--json]
sharesafe prepare inspect LOCAL_PLAN [--json]
sharesafe prepare approve LOCAL_PLAN --out-approval NEW_APPROVAL --approve-all [--json]
sharesafe prepare apply LOCAL_PLAN --approval LOCAL_APPROVAL --source SOURCE --out NEW_DIRECTORY [--json] [--report FILE]
sharesafe prepare verify LOCAL_PLAN --source SOURCE --output DIRECTORY [--json] [--report FILE]
sharesafe doctor [--deep] [--json]
sharesafe rules [--detail] [--json]
sharesafe formats [--json]
sharesafe self-test [--json]
```

Exit codes:

- `0`: operation complete and no finding meets the configured threshold.
- `1`: one or more findings meet the threshold, or verification did not pass.
- `2`: coverage is incomplete because parsing, support, encryption, or a resource limit prevented a complete check.
- `3`: invalid arguments or unsafe requested operation.
- `4`: filesystem or unexpected internal failure; no safety conclusion was produced.

Incomplete coverage takes precedence over ordinary findings.

## Stable report shape

All scan-like reports use `sharesafe.report/v1` and contain `tool`, `run`, `summary`, `artifacts`, `findings`, `gaps`, `errors`, and `dependencies`.

- Paths are relative display paths; an absolute scan root never appears in a report.
- Evidence is masked. Raw PII, secrets, metadata values, user names, and host names are forbidden.
- Finding IDs are unique and deterministic from non-secret artifact identity, rule ID, structured location, and occurrence. They never hash the sensitive evidence or raw artifact bytes. Byte comparisons use a temporary, run-scoped HMAC content token instead of a published file digest.
- Verdict is one of `no_findings`, `review`, `block`, or `incomplete`.
- Coverage values are `complete`, `partial`, `unsupported`, or `not_applicable`.

## Adapter contract

Adapters receive immutable bytes, a display-only virtual path, limits, and a finding sink. They must never open paths, execute embedded content, use the network, or write files. A parser exception becomes a coverage gap. Archive readers preflight classic/ZIP64 entry counts before materializing per-entry objects and then enforce byte, ratio, comment-text, and nesting limits. Finding truncation must create a gap.

## Transformations and prepare

Sanitization is deliberately narrower than detection. It sets filesystem access and modification times to a fixed value where the platform permits and may remove high-confidence metadata from OOXML, PNG, and JPEG copies. Windows creation/birth time is not promised to be normalized, and ownership, ACLs, extended attributes, alternate data streams, and other platform metadata are not promised to be copied or sanitized. PDF rewriting is unsupported; optional `pypdf` only improves scan-time text extraction. Sanitization and prepare do not remove comments, revisions, notes, hidden sheets/slides, attachments, macros, external links, or body-text findings.

Every transformed artifact is rescanned. Residual or newly introduced findings are reported; successful file creation alone is never called successful verification.

Prepare controls are strictly separated from reports. Decisions, plans, and approvals are local-only and may contain exact relative paths plus stable SHA-256 source bindings. The masked inspection and result omit those bindings. Plan and approval digests detect inconsistency but are not signatures or same-account attacker protection.

Every source regular file has exactly one explicit decision; empty or incomplete inventories and implicit copying are rejected. Only format-matched copy, omit, rename, and documented OOXML/PNG/JPEG metadata-strip actions are executable. Apply rebinds the source, uses verified owner-only staging, reserves an absent output without replacement, verifies exact relations before and after a final scan, and returns a bounded complete JSON result. Report-budget degradation records omissions, forces `incomplete`, and returns exit code `2` even when output was already committed.

Filesystem parent checks are identity checkpoints, not portable directory-handle anchoring. Output inherits the chosen destination parent's security properties and is a release copy rather than an ACL/owner/xattr/ADS-faithful backup.
