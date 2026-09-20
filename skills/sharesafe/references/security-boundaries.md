# Security boundaries

Use this reference when explaining ShareSafe's guarantees, deciding whether a request belongs to this Skill, or handling unexpected sensitive output.

## What ShareSafe is

ShareSafe is a local, offline pre-share privacy gate. It detects likely disclosure risks and records coverage gaps across supported file content, names, metadata, archives, and document internals. Its strongest positive statement is "no findings within completed coverage."

The default operation is read-only. Sanitization is a separate, explicitly authorized transformation that writes a new copy and verifies that copy by rescanning it.

## What ShareSafe is not

Do not use or describe ShareSafe as:

- malware, antivirus, exploit, or sandbox analysis;
- a compliance certification, legal opinion, or guarantee of anonymization;
- a general document editor or a substitute for format-native review;
- a complete body-text redaction engine;
- proof that a file is safe to execute, open, upload, or publish.

Route ordinary edits to the appropriate document workflow. Recommend a dedicated malware scanner for hostile-file concerns and a qualified reviewer for legal or regulatory decisions.

## Data-handling invariants

- Keep artifacts, sanitized copies, and reports local unless the user explicitly authorizes a separate transfer.
- Do not send content to web services, remote models, telemetry, paste sites, or external validators.
- Do not execute embedded programs, macros, scripts, formulas, external links, or archive contents.
- Never expose raw findings in chat, logs, filenames, report summaries, screenshots, or issue reports.
- Use only masked evidence emitted by a conforming report. Do not reread the matching source span to "confirm" it in model context.
- Never enable a raw-evidence, debug-evidence, or unmasked reporting mode, even if a future CLI exposes one.
- Treat encrypted, malformed, unsupported, skipped, or resource-limited data as incomplete coverage, not as clean.
- Preserve the original exactly. Every transformation targets a distinct, absent output path and is followed by a scan.

## Transformation limits

ShareSafe sanitization is intentionally narrower than detection. It may remove supported high-confidence metadata from OOXML, PNG, and JPEG copies. It never rewrites PDF files: optional `pypdf` support only enhances PDF text and basic-structure scanning. A PDF sanitize request creates a byte-unchanged copy, reports the attempted transform as `unsupported`, and retains detected risks as residual findings. Macro-, signature-, or embedded-object-bearing OOXML is likewise retained byte-for-byte with a skipped transform. ShareSafe does not silently alter body text and does not promise removal of comments, tracked revisions, speaker notes, hidden sheets or slides, attachments, macros, or external links.

When a finding is detectable but not safely auto-remediable, report it and recommend a format-native manual review. Do not improvise destructive XML edits or byte replacement outside the ShareSafe CLI.

## Prepare trust boundary

`prepare` constructs a new directory only from a complete explicit plan. It rejects empty inventories, implicit actions, path traversal, alternate streams, nonportable names, Unicode/case-fold/tree collisions, links, reparse points, hard links, special files, source drift, stale approvals, and an existing destination. Omitted or renamed source paths cannot be recreated by another target path or target subtree.

Plans, decisions, and approvals are sensitive local controls. They contain exact names and stable source digests and are not masked reports. Approval covers every action in one exact executable plan. Its checksum detects mismatched data but does not authenticate a person or resist a process with the same account permissions.

Apply staging is outside the destination parent so replacement of that parent cannot redirect pre-commit payload writes. On Windows the staging root is created atomically with a protected, inheritable DACL granting full access only to the current user; on POSIX it is verified as effective-user-owned mode `0700`. If private permissions cannot be established and checked, apply fails before reserving the output.

Destination publication reserves a new directory and creates every child without replacement. ShareSafe uses parent and directory identity checkpoints before and after path operations, not cross-platform directory-handle anchoring. A malicious concurrent process with sufficient same-account filesystem authority may still win a path race between checkpoints. The incomplete marker and `output_may_exist` failure state prevent such a partially populated directory from being presented as a completed bundle, but the user must place source and destination parents in a trusted location.

Exact output relations are checked before the final scan, bound to the scanner's actual reads with run-scoped HMAC content tokens, and checked again afterward. This detects substitutions around scanning but does not make the filesystem immutable. A successfully built bundle remains a release copy, not an access-control-preserving backup: it does not clone source owners, ACLs, alternate streams, extended attributes, or every timestamp.

## Authorization boundaries

A request to scan authorizes reading only the named target for analysis. It does not authorize sanitization, deletion, upload, publication, dependency installation, recursive expansion to sibling directories, or replacement of an existing output.

A request to sanitize authorizes only creation of the named copy. It does not authorize deleting the original or publishing the result. Installation of optional dependencies, use of external tools, and any network action require separate authorization.

A request to prepare a bundle authorizes only the named local control artifacts and absent output directory. Creating the approval remains a distinct authorization point after masked inspection. It does not authorize publishing the bundle, deleting controls, deleting source files, or overwriting an earlier bundle.

## Failure handling

Stop the sharing recommendation when:

- the verdict or process exit code indicates incomplete coverage;
- required JSON sections are missing or malformed;
- the report contains raw sensitive evidence or an absolute scan root;
- sanitization lacks a post-write scan;
- verification fails or reports unresolved blocking findings;
- the CLI encounters an internal failure.

Describe the class of failure without echoing sensitive values. If reporting a defect, construct a synthetic reproducer rather than attaching the user's source or report.
