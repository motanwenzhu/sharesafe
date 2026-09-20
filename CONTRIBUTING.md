# Contributing to ShareSafe

Thank you for helping build a more honest pre-share privacy gate. ShareSafe favors narrow, testable claims over broad but unverifiable coverage.

## Ground rules

- Use only synthetic data in code, fixtures, tests, screenshots, issues, reports, and pull requests.
- Never commit real PII, credentials, private documents, production filenames, usernames, hostnames, or absolute home paths—even after running a sanitizer.
- Preserve the rule that `no_findings` does not mean `safe`.
- Convert unsupported, encrypted, malformed, parser-failed, dependency-blocked, and resource-limited inspection into explicit gaps.
- Keep default scanning read-only. Sanitization must create a distinct copy, preserve the original, stay within documented transforms, and rescan output.
- Mask evidence before it reaches logs, exceptions, JSON, snapshots, or finding identifiers.
- Do not add network calls to the inspection path.

## Development setup

Python 3.11 or newer is required.

```bash
python -m venv .venv
python -m pip install -e ".[full,dev]"
python -m pytest
sharesafe self-test --json
```

Build the distribution before proposing a release-facing change:

```bash
python -m build
```

Use `sharesafe doctor --json`, `sharesafe formats --json`, and `sharesafe rules --json` to verify the installed command matches the documentation.

## Design contract

Read these before changing behavior:

- `docs/design-contract.md` — public CLI, exit code, adapter, report, and transformation contract;
- `THREAT_MODEL.md` — security assets, boundaries, and residual risk;
- `SUPPORT_MATRIX.md` — exact claims made to users;
- `docs/architecture.md` — component responsibilities and extension points.

If an implementation change would make any of those documents inaccurate, update them in the same pull request. Breaking JSON or exit-code semantics requires an explicit schema or major-version decision, not an incidental refactor.

## Synthetic fixture policy

A good fixture is small, deterministic, obviously fake, and regenerable. Prefer:

- reserved domains such as `example.com`;
- phone/identity samples documented as synthetic and constructed only for validator coverage;
- nonfunctional token prefixes and keys that cannot authenticate;
- generated ZIP and OOXML packages with minimal parts;
- generated JPEG/PNG/PDF files without copied user metadata;
- neutral relative paths rather than developer machine paths.

Never derive a fixture from a real person's document. Never submit a “sanitized” production file. Add a generator when a binary fixture cannot be reviewed reliably.

Tests must also check that synthetic raw values do **not** appear in reports, terminal output, errors, or deterministic IDs.

## Adding or changing a rule

Each rule needs:

1. a stable, namespaced rule ID;
2. a precise description, severity, and confidence;
3. positive, negative, boundary, and Unicode/encoding tests as applicable;
4. a masking strategy that reveals enough category/context to review without exposing the value;
5. false-positive analysis, especially for short or common strings;
6. deterministic location data that does not include raw evidence;
7. discovery output in `sharesafe rules --json`.

Validation such as checksums should be used when it materially improves precision. Do not log a raw match while debugging.

## Adding or changing an adapter

Adapters operate on immutable bytes, a display-only virtual path, resource limits, and a finding/gap sink. They must not:

- open arbitrary filesystem paths;
- write files;
- execute macros, scripts, formulas, or embedded content;
- follow external relationships or use the network;
- swallow parser failures;
- bypass resource accounting.

An adapter change needs tests for valid, empty, truncated, malformed, encrypted (when applicable), extension-mismatch, oversized, and nested inputs. Document precisely which representations are inspected and which are not. Technical parser capability alone does not justify a ShareSafe coverage claim.

## Adding a sanitizer

Detection breadth does not authorize transformation breadth. A sanitizer must have:

- a written, high-confidence transform list;
- canonical checks that the output cannot overwrite or nest unsafely within the input;
- original-integrity tests;
- failure atomicity appropriate to the target;
- content-preservation or documented-change tests;
- an immediate rescan of produced output;
- residual/new-finding reporting;
- clear incomplete behavior when a required parser or representation is unavailable.

Body-text replacement, visual redaction, comment/revision deletion, and active-content removal are outside the current supported boundary unless introduced through an explicit reviewed design change.

## Report and CLI compatibility

Machine-readable output is a public API. Under `--json`:

- stdout must remain valid JSON;
- human diagnostics belong on stderr and must also avoid raw evidence;
- required `sharesafe.report/v1` fields may not disappear or change meaning;
- display paths must remain relative;
- incomplete coverage must retain exit-code precedence;
- ordering and IDs should be deterministic where the contract promises it.

Add golden/schema tests for every report change. New optional fields should degrade safely for older consumers.

## Documentation and Skill changes

Keep the Codex Skill thin: it should choose safe CLI operations, explain gaps, and preserve authorization boundaries. Deterministic logic belongs in scripts. Validate Skill metadata after changing `SKILL.md`, and behavior-test a fresh agent against read-only scans, incomplete reports, requested sanitization, and unsafe overwrite prompts.

Documentation must not use “safe,” “clean,” “certified,” or “compliant” as an unqualified verdict. Examples must use synthetic paths and values.

## Pull-request checklist

- [ ] Scope is small and the security impact is explained.
- [ ] Tests use only synthetic data and pass on supported Python versions.
- [ ] No raw fixture values or absolute paths appear in output snapshots.
- [ ] Malformed/unsupported/resource-limited cases fail closed.
- [ ] Original inputs remain unchanged.
- [ ] JSON, exit codes, and command help remain aligned.
- [ ] Support matrix, threat model, changelog, and third-party notices are updated when relevant.
- [ ] `sharesafe self-test --json` and `python -m build` pass.

## Licensing

By submitting a contribution, you agree that it may be distributed under the repository's [Apache License 2.0](LICENSE). Preserve third-party notices and identify copied or adapted material in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
