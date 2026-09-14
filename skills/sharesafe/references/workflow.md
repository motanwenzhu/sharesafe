# ShareSafe workflow

Use this reference to select commands and decide when to stop. Commands below use the repository layout; replace `<skill-dir>` with the actual installed Skill directory and pass paths as separate, quoted arguments.

## Baseline audit

Run these commands in order:

```text
python <skill-dir>/scripts/run_sharesafe.py doctor --json
python <skill-dir>/scripts/run_sharesafe.py scan <input> --json
```

`doctor` reports capability and optional-dependency availability; it does not inspect the target. Continue to `scan` when the core scanner is available, even if optional adapters are unavailable. Report those missing adapters as coverage limits.

Scanning is the default because it is read-only. Use `--report <new-file>` only when the user wants a saved report. Do not choose a report path that already contains valuable data.

For multiple inputs, pass each as its own argument. Do not build commands from filenames discovered inside archives, and do not execute, import, render, or open embedded content outside ShareSafe.

## Interpret outcomes

Honor the process exit code together with the JSON body:

- `0`: operation completed and nothing met the configured threshold. Describe this only as "no findings at the configured threshold within completed coverage."
- `1`: findings met the threshold, or verification did not pass.
- `2`: coverage was incomplete. This takes precedence over ordinary findings and requires manual review or added local capability.
- `3`: arguments or the requested operation were unsafe or invalid. Correct the request only within the user's existing authorization.
- `4`: an internal or runtime failure prevented a trustworthy result. Stop and report the failure without guessing.

Do not infer that a lower finding count means an artifact is safe. Lead with blocking findings and gaps, then review-level findings and available remediation options.

## Create a sanitized copy

Sanitization is an opt-in write operation:

```text
python <skill-dir>/scripts/run_sharesafe.py sanitize <input> --out <new-output> --json
```

Before running it:

1. Resolve the input and output paths.
2. Verify that the output is distinct from the input and does not already exist.
3. State that ShareSafe v0.1 removes only supported metadata; it does not rewrite body text or promise removal of comments, revisions, notes, macros, attachments, hidden sheets/slides, or external links. It never rewrites PDF files.
4. Do not broaden a request to sanitize one artifact into sanitizing its parent folder or repository.

The sanitizer must create a copy and rescan it. Accept the operation as complete only when the returned report includes the post-sanitization scan. If that evidence is absent, run a separate scan of the new output and describe the missing automatic verification as a tool defect. Residual findings or gaps remain blockers; successful file creation is not verification.

For PDF input, `pypdf` only enhances text extraction and basic-structure inspection during scans. Its presence never enables PDF transformation. The v0.1 sanitizer copies PDF bytes unchanged, records the PDF action as `unsupported`, and preserves detected PDF risks as residual findings in the post-copy scan. Do not describe that copy as cleaned or metadata-reduced.

Never replace, rename over, delete, or edit the original. If the destination exists, stop and ask for another destination rather than inventing permission to overwrite it.

## Compare original and copy

Use standalone verification when the user wants a conservative fresh comparison of an original and a separately prepared copy:

```text
python <skill-dir>/scripts/run_sharesafe.py verify <original> <prepared> --json
```

The `sanitize` command already embeds the only verification that can trust its in-memory transformation records; do not follow it with standalone `verify` as though that could re-attest the operation. Standalone `verify` has no authenticated manifest for past or third-party transformations. It can prove that bytes were preserved, but any byte change is intentionally reported as `unverified` even if findings fall. Verification evaluates risk reduction and residual coverage; it does not establish semantic equivalence, legal sufficiency, or absolute privacy. A failed or incomplete verification should stop any recommendation to publish the copy.

## Saved reports and downstream automation

Use `--json` for machine consumption and `--report <new-file>` when a durable report is requested. Before parsing fields or wiring CI, read [report-contract.md](report-contract.md). Do not paste raw artifact contents into prompts to explain a finding. If more context is needed, ask the user to inspect the original locally and describe it without the sensitive value.

For CI, set an explicit `--fail-on` threshold rather than assuming a default. Preserve exit code `2` as a distinct incomplete-coverage failure so unsupported or malformed inputs cannot appear clean.

## Capability discovery and troubleshooting

Use the non-scanning commands only when their answer is relevant:

```text
python <skill-dir>/scripts/run_sharesafe.py formats --json
python <skill-dir>/scripts/run_sharesafe.py rules --json
python <skill-dir>/scripts/run_sharesafe.py self-test --json
```

Use `formats` to answer coverage questions, `rules` to map configured checks, and `self-test` after installation or an internal failure. Self-test must use bundled synthetic data and does not authorize inspecting additional user files.
