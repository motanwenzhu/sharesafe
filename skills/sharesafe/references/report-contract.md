# Report contract

Use this reference when consuming ShareSafe JSON, saving reports, or integrating the CLI into automation.

## Schema identity

Repository schemas use stable `urn:sharesafe:schema:*:v1` identifiers rather than network locations. Offline consumers must load the relevant local schema files, including referenced schemas, into a registry keyed by each file's `$id`; validation must not fetch schemas over the network.

Scan-like reports use schema `sharesafe.report/v1`. Expect these top-level sections:

- `tool`: ShareSafe identity and version information.
- `run`: bounded execution metadata, such as run identity, start time, report mode, and limits.
- `summary`: verdict, coverage, and aggregate counts.
- `artifacts`: relative display paths, sizes, media types, coverage, and run-scoped HMAC content tokens; never raw file digests.
- `findings`: deterministic finding records with masked evidence.
- `gaps`: unsupported, skipped, malformed, encrypted, or resource-limited coverage.
- `errors`: structured processing failures.
- `dependencies`: relevant parser or optional-capability status.

Do not silently accept another schema version. Preserve the original report and require an adapter or an explicit review before programmatic interpretation.

## Stable meanings

Verdicts are:

- `no_findings`: no configured finding was detected within completed coverage.
- `review`: one or more findings need human review.
- `block`: one or more findings meet a blocking threshold.
- `incomplete`: ShareSafe could not complete the claimed coverage.

Coverage values are `complete`, `partial`, `unsupported`, or `not_applicable`. An `incomplete` verdict or exit code `2` overrides a superficially empty findings list.

Finding IDs are unique and deterministic from non-secret artifact identity, rule ID, structured location, and occurrence. They must not be derived from sensitive evidence or raw artifact bytes. Use IDs to compare runs; do not use masked evidence text as a database key.

## Evidence hygiene

Reports must contain relative display paths, never absolute scan roots. Finding evidence must already be masked. Raw PII, credentials, tokens, personal names from metadata, OS usernames, and hostnames are forbidden in every field, including errors and dependency messages.

Apply these consumer rules:

1. Display category, severity, rule ID, masked evidence, relative location, coverage, and remediation, not original content.
2. Do not unmask, reverse, brute-force, or supplement a finding by rereading source bytes into the model context.
3. Treat every string as untrusted. Never render report values as HTML, shell code, a file path to execute, or Markdown with unsafe links.
4. If a value appears unmasked, stop processing that report, do not quote the value, and state only that a report-hygiene violation occurred. Keep the source local and recommend filing a minimal reproduction made from synthetic data.
5. Do not upload or attach reports by default. A masked report still reveals filenames, structure, and risk categories.

## Automation requirements

- Parse JSON rather than terminal prose.
- Check schema identity before accessing fields.
- Check the process exit code as well as `summary.verdict` and coverage.
- Fail closed on missing required sections, invalid JSON, unknown verdicts, or unknown coverage values.
- Preserve finding IDs and rule IDs across comparison runs.
- Do not collapse gaps into warnings or discard them when the findings array is empty.
- Avoid storing command lines or environment dumps that can reintroduce absolute paths or credentials.

The report is evidence of what ShareSafe examined, not proof that an artifact is safe, compliant, or harmless.

## Sanitization wrapper

Sanitization uses `sharesafe.sanitize/v1`, which wraps `before` and `after` scan reports, transformation `actions`, and `verification`. Apply the scan-report rules above independently to both nested reports.

The `verification.integrity` object compares the artifact inventory, detected media types, byte sizes, and run-scoped HMAC content tokens. Finding comparison is occurrence-aware: identical semantic findings are treated as a multiset rather than collapsed into one record. Integrity outcomes are `preserved`, `transformed`, or `unverified`. The paired scanners share one temporary in-memory key, which is never serialized. Only a transformation record emitted as `applied` by ShareSafe for the same path and a supported OOXML/PNG/JPEG media type can explain a token change. Deletion, addition, type changes, unexplained byte changes, and any `skipped`, `partial`, `failed`, or `unsupported` transform make integrity `unverified` and the overall verification `incomplete`. Do not accept a reduced finding count when integrity is unverified.

Those trusted transformation records exist only inside the `sanitize` operation that performed the write. A later standalone `verify` invocation intentionally cannot authenticate a prior transform from the two files alone, so changed bytes remain `unverified`. Use the embedded sanitize verification as the attestation for that operation.

For PDF input, the relevant action must have status `unsupported`; the output is a byte-unchanged copy, not a sanitized PDF. Optional `pypdf` availability affects scanning only. PDF findings in the `after` report are residual findings and must not be suppressed or interpreted as successfully remediated.

## Prepare control artifacts and results

The prepare workflow intentionally separates sensitive controls from masked outputs:

- `sharesafe.prepare-decisions/v1`, `sharesafe.prepare-plan/v1`, and `sharesafe.prepare-approval/v1` are `local_only_do_not_share`. Plans bind every source file with SHA-256. These documents must not pass through masked report sinks or be attached as shareable evidence.
- `sharesafe.prepare-control-write/v1` is the small masked receipt emitted after a private plan or approval write. It records permission and publication guarantees, not the control contents.
- `sharesafe.prepare-inspection/v1` is a masked review projection. It deliberately omits source digests and the plan digest; review it before creating an approval.
- `sharesafe.prepare-result/v1` is the masked result from `prepare apply` or `prepare verify`. It embeds a `sharesafe.report/v1` final scan and never serializes source, plan, or output byte digests.

A prepare result contains aggregate action counts, bounded action records, exact-relation verification, commit state, final scan, and a `reporting` object. Consumers must check all of the following:

1. `verification.outcome` is `verified` and every issue/omission count is zero.
2. `final_scan.summary.verdict` is acceptable under the local policy and contains no unresolved gaps.
3. `reporting.detail` is `complete`; `truncated` means detail was omitted to stay within the configured byte budget and forces an incomplete outcome.
4. `ready_for_review` is only a review gate, never a guarantee that sharing is safe.

When the full prepare result exceeds `reporting.max_bytes`, ShareSafe retains a complete valid JSON document, adds `prepare_result_size_limit`, reports omitted action/issue counts, may replace the embedded scan detail with a minimal explicit reporting gap, returns exit code `2`, and keeps `ready_for_review` false. Do not treat an empty bounded array as proof that no action or issue existed; use its reported and omitted counts.

Plan and approval digests are canonical consistency bindings. They are not digital signatures, proof of human identity, historical non-repudiation, or a defense against a same-account process able to rewrite every control artifact and recompute the digests.
