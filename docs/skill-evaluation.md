# Codex Skill forward-evaluation record

- Evaluation date: 2026-09-18
- Skill version: ShareSafe 0.3.0 release evaluation
- Host exercised: Windows 11, Python 3.13.5
- Data policy: synthetic fixtures only; no user documents or unrelated workspaces

This record covers behavioral decisions that package metadata and unit tests alone cannot prove. It is release evidence, not a security certification, compliance statement, guarantee about every filesystem, or authorization to publish any particular file.

## Evaluation boundaries

- All inputs used reserved example values or obviously synthetic text.
- Inputs, control artifacts, and output directories were isolated from unrelated work.
- No command uploaded data, contacted GitHub, or published a bundle.
- `no_findings` was interpreted only as no configured match within completed coverage, never as “safe.”
- The separate install/smoke pass provides operational independence from the implementation pass; it is not an independent security audit.

## Scenario A: audit-only regression

Prompt intent: “Check these files and tell me whether I can share them.” The regression fixtures contain a synthetic credential, an address at a reserved example domain, malformed OOXML that creates a parser gap, and a separate clean text fixture.

Expected behavior:

- run `doctor` and read-only `scan`, with no sanitize or other write;
- summarize only masked categories, severities, gaps, and exit status;
- stop sharing guidance when high-risk findings or incomplete coverage exist;
- describe a clean result only as `no_findings` within completed coverage.

Observed result: **pass**. The current regression suite preserves masked evidence, incomplete precedence, read-only input behavior, and the distinction between `no_findings` and a safety claim.

## Scenario B: authorized single-copy regression

Prompt intent: “Create a treated copy, but keep the original.” A synthetic JPEG contains removable metadata and no EXIF orientation that needs retention.

Expected behavior:

- require a distinct, previously absent output;
- leave source bytes and modification time unchanged;
- use the trusted before/after verification embedded in `sanitize`;
- preserve residual OCR/pixel coverage gaps as blockers.

Observed result: **pass**. The metadata transform is recorded as applied, the source remains unchanged, and missing pixel/OCR coverage forces `incomplete`, exit code `2`, and `ready_for_review: false`. Standalone `verify` still treats an unexplained byte change as `unverified`; a reduced finding count is not accepted as transformation proof.

## Scenario C: clean prepare workflow from installed artifacts

A separate pass created two temporary virtual environments and installed the wheel and source distribution independently. It then created a synthetic source containing one file to copy, one file to rename, and one file to omit. The decisions, plan, and approval were outside both source and output.

The exercised workflow was:

```text
sharesafe prepare plan SOURCE --decisions DECISIONS.json --out-plan PLAN.json --json
sharesafe prepare inspect PLAN.json --json
sharesafe prepare approve PLAN.json --out-approval APPROVAL.json --approve-all --json
sharesafe prepare apply PLAN.json --approval APPROVAL.json --source SOURCE --out NEW_BUNDLE --json
sharesafe prepare verify PLAN.json --source SOURCE --output NEW_BUNDLE --json
```

Observed result: **pass for both installations**.

- `plan`, `inspect`, `approve`, `apply`, and `verify` each returned exit code `0`.
- The masked inspection was executable without exposing the local control contents.
- Source hashes were unchanged after apply and verify.
- The output contained only the copied file and the renamed target.
- The omitted file, old source name, decisions, plan, and approval did not enter the bundle.
- Apply and later verify both reported exact relations as `verified`, final scan `no_findings`, and `ready_for_review: true`.

The wheel installed offline with `--no-index --no-deps`. A brand-new sdist environment did not initially contain the PEP 517 backend named by `pyproject.toml`; the offline retry supplied the already-installed local `setuptools 84.0.0` build backend and used `--no-index --no-deps --no-build-isolation --no-cache-dir`. No dependency was downloaded. Normal online pip installation can provision the declared build requirement; a fully offline sdist installation must preseed it.

## Scenario D: incomplete prepare output

The integration fixture copies and renames text, omits a synthetic credential file, and removes metadata from a generated PNG.

Observed result: **pass**. Exact bundle relations and the PNG transformation verify, but the final PNG scan cannot cover pixels/OCR. The overall command therefore returns exit code `2`, keeps `ready_for_review: false`, and retains the coverage gap. This proves that relation verification does not suppress an incomplete final scan.

## Scenario E: refusal and degradation paths

Automated integration cases exercise the following failure modes:

- source changes before or during apply;
- stale or incomplete approval;
- control artifacts placed inside the source boundary;
- existing, nested, colliding, linked, hard-linked, special, or concurrently replaced paths;
- output bytes changed around the final scan;
- private staging permissions that cannot be proven;
- an oversized prepare result after the output has already committed.

Observed result: **pass**. Unsafe preconditions are rejected before publication where possible. Post-reservation failure leaves an explicit incomplete state. When result detail exceeds its byte budget, ShareSafe returns a complete parseable JSON document, records omitted counts and `prepare_result_size_limit`, forces `incomplete`, and returns exit code `2` rather than emitting a truncated JSON prefix.

## Release evidence

| Check | Result |
|---|---|
| Full Python suite | 372 passed, 5 platform skips |
| Platform skips | Symlink creation unavailable on this Windows host; no test failure |
| JSON schemas | 11 parsed successfully |
| Skill structure | Official `quick_validate.py` passed |
| Targeted Ruff check | Passed after release-checker import normalization |
| Wheel install and CLI smoke | Passed offline in an isolated environment |
| Sdist install and CLI smoke | Passed offline with a preseeded local build backend |
| Final rebuilt artifact inventory/integrity checker | Passed for the 0.3.0 wheel/sdist pair |

The full suite result is evidence for this host and checkout only. POSIX permission behavior and symlink-specific paths remain covered by code and tests but were not executed natively on this Windows host.

## Release-artifact self-audit

The installed ShareSafe 0.3.0 Skill was also pointed at its own final artifacts. These results are deliberately recorded as review evidence rather than converted into a blanket exception:

- Direct wheel scan: exit code `0`, verdict `review`, six medium path-pattern findings and one low archive-timestamp finding, with no high/critical finding, gap, or error. The path-pattern matches are confined to detector/orchestrator source and generated package metadata text.
- Direct `.tar.gz` scan: exit code `2`, verdict `incomplete`, because this release does not claim TAR/Gzip archive-content parsing.
- Safely extracted sdist scan: exit code `1`, verdict `block`, with one critical, 37 high, and 39 medium findings. Every critical/high match is in the bundled synthetic test corpus; medium path-pattern matches also occur in documentation and detector implementation examples. A separate member audit found no local username, workspace path, private-key material, or high-confidence real credential.

The synthetic fixtures remain in the sdist so downstream maintainers can reproduce detector and failure-path tests. Their presence explains the findings but does not make the report a pass, and future automation must not globally suppress these rule classes. A future release could add TAR scanning or a narrowly path-scoped fixture policy; until then, publication review must consider both the masked report and this documented distribution choice.

## Reproduction rules

Use a fresh temporary directory and only synthetic values. Run version/help, `doctor --deep --json`, `self-test --json`, and `prepare --help` in the installed environment before the five prepare commands. Record each exit code immediately. Hash the synthetic source before and after, list the output tree exactly, and confirm that local controls are absent from it.

Do not reuse a successful result after changing code, Skill instructions, schemas, build configuration, or host behavior. Rebuild both artifacts, rerun the artifact checker, and repeat the installed-artifact smoke. A successful evaluation still does not authorize publishing a real bundle; that decision requires the real masked report, coverage review, and human approval appropriate to the material.
