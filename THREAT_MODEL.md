# ShareSafe threat model

Status: v0.1 design baseline
Last reviewed: 2026-09-14

## Purpose

ShareSafe is a local pre-share privacy gate. It inspects files and bundles, reports likely disclosure risks, identifies checks it could not complete, optionally removes a narrow set of high-confidence metadata into a new copy, and rescans that output.

The central safety statement is:

> `no_findings` is not `safe`. It describes only the configured checks that completed.

This threat model defines what ShareSafe protects, what it assumes, and what remains the user's responsibility. It is not a compliance certification or legal assessment.

## Assets

ShareSafe aims to protect:

- personal identifiers and contact details in content or metadata;
- API keys, tokens, private-key material, and credential-like strings;
- usernames, hostnames, local absolute paths, and tool fingerprints;
- author, company, GPS, camera, producer, revision, and similar metadata;
- material hidden in comments, tracked changes, speaker notes, hidden sheets/slides, package parts, filenames, or nested archives;
- the confidentiality of the scan itself, including reports and diagnostics;
- integrity of original inputs during sanitization;
- the reliability of release automation consuming the result.

## Actors and trust boundaries

The intended user controls the local machine, selects inputs, reviews reports, and chooses whether to release an output. ShareSafe code and explicitly installed Python dependencies execute inside that user's environment.

Untrusted data begins at every inspected byte, filename, archive entry name, document relationship, metadata field, parser return value, and embedded object. A file can be malformed or intentionally adversarial even when its extension looks ordinary.

The main trust boundaries are:

1. **Filesystem to discovery layer.** Paths may be deceptive, aliased, linked, renamed during a run, or arranged so output overlaps input.
2. **Raw bytes to format adapter.** Parsers process attacker-controlled structures and can fail, allocate excessively, or expose only partial content.
3. **Raw evidence to finding/report boundary.** A correct detector can still create a second leak if evidence is serialized without masking.
4. **Original to sanitized copy.** Transformations can lose content, preserve hidden content, overwrite an input, or claim more than they accomplished.
5. **CLI to automation or agent.** Exit codes and JSON can be misinterpreted as permission to publish.

Normal ShareSafe adapters are designed without a network boundary: they do not need a remote service and must not transfer file content.

## Adversaries and failure sources

The model includes both malicious inputs and ordinary mistakes:

- a user accidentally includes a private file, sensitive filename, token, or author metadata;
- a producer application stores content somewhere the user did not know to inspect;
- an archive contains traversal names, extreme compression, excessive entries, deep nesting, or misleading extensions;
- a file is encrypted, truncated, malformed, parser-hostile, or valid in a variant the adapter does not support;
- a detector produces false positives or false negatives;
- a dependency is missing, incompatible, or behaves differently across versions;
- an automation checks only process success and ignores coverage;
- a local attacker supplies a crafted file to exhaust resources or exploit a parser;
- a sanitizer preserves a residual signal or creates a new one.

## Security goals

### G1 — Local-first inspection

Core scanning, report generation, sanitization, and verification must not require network access. Adapters must not fetch external relationships, URLs, remote images, linked workbooks, or fonts.

### G2 — Honest coverage

Unsupported, encrypted, malformed, parser-failed, dependency-blocked, and resource-limited content must create an explicit gap. A relevant gap makes the overall verdict `incomplete`; it cannot be collapsed into `no_findings`.

### G3 — Non-disclosing reports

Reports and normal diagnostics must contain masked detector evidence and display-only relative paths. Raw matched PII, secrets, metadata values, absolute scan roots, and recognized identity components from user-home/UNC paths are forbidden. User-selected relative filenames remain visible and may themselves be sensitive; reports therefore remain protected artifacts. Unique deterministic finding IDs derive from artifact identity, rule ID, structural location, and occurrence—not from the sensitive evidence.

### G4 — Preserve originals

Default scanning is read-only. Sanitization writes only to a distinct destination, refuses unsafe path relationships, and never modifies the input. Safe output creation must account for archive entry paths and links.

### G5 — Narrow, observable transformation

v0.1 sanitization may remove only documented high-confidence metadata. It must not silently rewrite body text, resolve disclosure policy, or imply true redaction. Every output is rescanned; residual findings and gaps remain visible.

### G6 — Bounded hostile-input handling

Directory and archive traversal must enforce bounded nesting, entry count, decompressed bytes, compression ratio, and per-artifact processing limits. Parser exceptions become structured gaps or errors instead of being ignored.

### G7 — Automation-safe semantics

JSON has a versioned schema and stderr/stdout separation appropriate for machines. Exit code `2` represents incomplete coverage and takes precedence over ordinary findings. Invalid or unsafe operations fail closed.

## Threats and mitigations

| Threat | v0.1 mitigation | Residual risk |
|---|---|---|
| Visible PII or credentials | Deterministic pattern rules, validation where practical, severity/confidence, masked findings | Contextual identifiers and unknown key formats can be missed |
| Sensitive filename/path | Inspect selected root, file, empty-directory, and container-entry names; mask user/host/path components and remove the absolute scan root | Non-empty parent directories are represented through descendant paths; filesystem side channels remain outside the report |
| OOXML hidden content | Inspect package parts and flag relevant structures | Rendering semantics, macros, embedded objects, and vendor extensions may remain partial |
| PDF hidden or inaccessible content | Built-in selected metadata/structure checks plus optional parser-based text inspection; encrypted/parser failures become gaps | Deep structure stays partial even with the parser; image-only pages, incremental revisions, attachments, complex encodings, and rendering-only content are not fully covered |
| Image location/device metadata | JPEG/PNG metadata inspection; optional deeper parsing | Pixel content is not OCR-scanned; uncommon containers and sidecars may be missed |
| Nested archive concealment | Recursive virtual paths, bounded comment scanning, and name inventory | Unsupported compression/encryption and limit hits remain incomplete |
| ZIP bomb or deep nesting | Classic/ZIP64 central-directory preflight before `ZipInfo` materialization, followed by size/ratio/count/depth budgets | Crafted parser workloads can still consume time within limits |
| Archive path traversal | Treat entry names as virtual labels; do not extract unchecked paths | Sanitizers and future extractors must preserve this invariant |
| Report becomes a second leak | Mask at finding creation, normalize separator variants for matching, and emit path-free CLI errors | New rules can violate the boundary without tests/review |
| Input overwrite or output-inside-input recursion | Distinct output requirement and canonical path checks | Concurrent filesystem changes and unusual filesystem semantics remain possible |
| Sanitization creates false confidence | Narrow transform list, copy-only behavior, mandatory rescan | Absence of a detected residual is still not proof of removal |
| Active content execution | Parse bytes only; never run macros/scripts/formulas or fetch links | Third-party parser vulnerabilities remain possible |
| CI incorrectly publishes | Stable verdict/coverage/exit codes; incomplete precedence | A consumer can still ignore documented semantics |

## Coverage semantics

Coverage is recorded per artifact as `complete`, `partial`, `unsupported`, or `not_applicable`.

- `complete` means all v0.1 checks claimed for that artifact and installed capability completed. It does not mean all possible privacy checks exist.
- `partial` means some relevant inspection ran and some did not.
- `unsupported` means ShareSafe has no applicable adapter or cannot inspect a relevant representation.
- `not_applicable` means a named capability genuinely does not apply; it must not be used as a softer synonym for unsupported.

Overall verdicts are `no_findings`, `review`, `block`, and `incomplete`. If any relevant artifact is partial/unsupported because of a gap, or parsing/resource constraints prevent promised inspection, the overall verdict is `incomplete` even if findings also exist. Findings are still retained for review.

## Sanitization guarantees

For a sanitization operation that reaches output creation, ShareSafe intends to guarantee:

- input bytes and input paths are not modified;
- output is placed at the explicitly supplied distinct path;
- only documented transformations for a recognized format are attempted;
- a failed transformation is visible and not substituted with a success label;
- the output is scanned as a new artifact set;
- reports distinguish transformation status from scan verdict.

ShareSafe does **not** guarantee secure erasure, byte-for-byte preservation of non-metadata structures, visual fidelity across all viewers, removal of body-text PII, irreversible redaction, or anonymity of the resulting file.

PDF transformation is unsupported in v0.1. A PDF can be copied unchanged as part of an output tree, but that action is not PDF sanitization and remains visible as unsupported/incomplete.

Sanitized output is also not a filesystem-faithful backup. ShareSafe sets access and modification times to a fixed value where the platform permits, but it does not promise to normalize Windows creation/birth time. Only executable/non-executable permission class is preserved where meaningful. Exact modes, ownership, ACLs, extended attributes, alternate data streams, and other platform-specific metadata are neither guaranteed to be copied nor guaranteed to be sanitized. Output receives or inherits access-control properties from the chosen destination parent according to the operating system, so that parent is part of the user's trust boundary.

## Out of scope for v0.1

- OCR and semantic inspection of pixels, handwriting, audio, video, or scanned PDF pages.
- Malware detection and safe execution of active content.
- Steganography, watermark, font fingerprint, printer mark, or forensic provenance detection.
- Complete interpretation of macros, formulas, embedded objects, external links, digital signatures, or every vendor-specific document extension.
- True PDF/content redaction and legal disclosure review.
- PDF metadata rewriting in v0.1.
- Preventing a compromised OS, Python runtime, dependency, administrator, endpoint monitor, or backup service from reading inputs.
- Protecting shell history, terminal scrollback, filesystem journals, swap, caches, cloud-sync folders, backups, or copies created by other applications.
- Proving compliance with GDPR, HIPAA, CCPA, export controls, discovery rules, or organizational policy.
- Verifying what a third-party sharing platform does after upload.

## User responsibilities

Users must choose the correct input scope, install needed optional adapters, review every gap, inspect sanitized output, choose a destination parent with suitable access controls, and apply domain-specific release policy. High-risk material needs an independent specialist tool and human review. Never use `no_findings` as the sole authorization to publish.

Users must also protect reports. Although evidence and byte identity are represented with run-scoped HMAC tokens rather than raw values or file digests, filenames, rule categories, sizes, counts, and structure can still be sensitive in context.

## Validation strategy

Security invariants require synthetic regression tests for raw-evidence absence, absolute-path absence, deterministic IDs, malformed/encrypted/unsupported inputs, resource limits, archive traversal, unsafe output relationships, original preservation, mandatory rescan, and exit-code precedence. Forward behavioral testing of the Codex Skill must check that it communicates uncertainty and does not broaden sanitization without authorization; the current reproducible record is [docs/skill-evaluation.md](docs/skill-evaluation.md).

## Change control

Any new adapter, parser, detector, transformation, report field, or dependency changes this threat model. Pull requests must update tests and, when the public boundary changes, this file, [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md), and the versioned report contract. Weakening a fail-closed behavior requires explicit security review and a documented migration.
