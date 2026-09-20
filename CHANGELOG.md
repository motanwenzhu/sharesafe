# Changelog

All notable changes to ShareSafe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Security fixes may intentionally tighten parsing or fail-closed behavior in a patch release.

## [Unreleased]

## [0.3.0] - 2026-09-20

### Added

- Added the `prepare plan`, `prepare inspect`, `prepare approve`, `prepare apply`, and `prepare verify` workflow for constructing a new directory from complete explicit per-file decisions.
- Added strict local-only decision, plan, and approval schemas plus masked control-write, inspection, and result schemas.
- Added allow-listed copy, omit, rename, and OOXML/PNG/JPEG metadata-strip actions with exact source binding and output-relation verification.
- Added private local control-artifact I/O: strict bounded UTF-8 JSON, duplicate/non-finite/surrogate rejection, exclusive publication, POSIX `0600`, and a verified protected current-user-only Windows DACL.
- Added system-temporary prepare staging with verified POSIX current-user `0700` or a protected inheritable current-user-only Windows DACL.

### Security

- Reject empty or incomplete plans, implicit copying, path traversal/ADS/UNC/reserved/trailing-dot names, normalization/case/tree collisions, links/reparse points/hard links/special files, stale approvals, source drift, and source-path resurrection through materialized targets.
- Reserve output directories and create every child exclusively, retain an incomplete marker across post-reservation failures, and avoid replacing renames or unsafe recursive cleanup.
- Bind the final scanner's actual reads to expected output bytes with a shared run-scoped HMAC key, with exact tree verification both before and after the scan.
- Bound prepare-result action and issue detail. Oversized results remain complete valid JSON, record omissions and a reporting gap, force `incomplete`, and return exit code `2` even after a successful commit.
- Explicitly document that plan/approval digests are consistency checks rather than signatures, and that parent-path protection uses identity checkpoints rather than portable directory-handle anchoring.

### Documentation and release validation

- Added a detailed Chinese user guide and design/workflow manual covering decisions, approvals, apply/verify stages, recovery, exit codes, and residual trust boundaries.
- Expanded the release artifact checker for every v0.3 runtime module, all 11 schemas, the new manuals, prepare tests, version-matched artifacts, and wheel RECORD integrity.
- Repeated the forward evaluation from isolated wheel and sdist installations with synthetic data only.

## [0.2.0] - 2026-09-16

### Added

- Added descriptor-bound reads, parent-directory identity checkpoints, transformation receipts, and OOXML/PNG/JPEG preserved-facet verification.
- Added strict policy/check schemas and reproducible effective-policy receipts, `doctor --deep`, and the exact versioned `rules --detail` catalog.
- Added bounded complete report fallbacks, centralized masked-report hygiene, and `report show`, `report diff`, and `report share-summary` commands.

### Security

- Removed raw content digests from masked reports in favor of run-scoped HMAC tokens and made report/path/field/finding/gap/error limits fail closed.
- Hardened report and sanitized-output publication against parent replacement and destination takeover without overwriting competing files.

### Documentation

- Added a detailed Chinese user manual covering installation, scanning, report interpretation, sanitization, verification, Codex Skill usage, CI integration, limits, and troubleshooting.
- Added a Chinese design-and-workflow guide mapping components, trust boundaries, data models, scan/sanitize/verify flows, testing, release, and extension procedures.

## [0.1.0] - 2026-09-13

### Added

- Initial local, offline pre-share privacy gate.
- Read-only scanning for text/code/configuration, OOXML, ZIP, PDF, JPEG, and PNG inputs within documented limits.
- Rules for likely PII, credentials, identity-bearing paths, document metadata, and selected hidden Office structures.
- Versioned `sharesafe.report/v1` JSON with masked evidence, relative display paths, findings, coverage gaps, dependency state, and deterministic finding IDs.
- `scan`, `sanitize`, `verify`, `doctor`, `rules`, `formats`, and `self-test` commands.
- Copy-only, high-confidence metadata sanitization followed by mandatory output rescanning.
- Explicitly audit-only PDF handling; v0.1 does not rewrite or sanitize PDF metadata.
- Set release-copy access and modification times to a fixed value where supported and retained coarse executable/non-executable permissions, without claiming to normalize Windows creation/birth time or clone owners, ACLs, extended attributes, or alternate data streams.
- Companion Codex Skill for a cautious, authorization-preserving workflow.
- Synthetic unit, integration, adversarial-parser, and CLI-contract coverage, plus a forward-evaluation contract for the Codex Skill workflow.

### Security

- Unsupported, encrypted, malformed, parser-failed, dependency-blocked, and resource-limited content produces `incomplete` rather than a clean result.
- Archive entry, decompressed-byte, compression-ratio, and nesting limits guard recursive inspection.
- Classic and ZIP64 central directories are preflighted before per-entry objects are materialized; archive/member comments and directory names are scanned under bounded budgets.
- OOXML XML text traversal explicitly includes retained comments and processing instructions across supported CPython patch releases.
- Selected roots, empty-directory leaves, and OOXML part names participate in masked name inventory and verification; selecting a `Users`, `home`, or `Documents and Settings` container retains scan-only context so first-level usernames remain masked in scan, sanitize, and verify reports.
- PNG compressed-text parsing uses a cumulative text budget, strict single-stream validation, and a 4,096-chunk hard cap.
- Finding retention is bounded per artifact and per report; truncation becomes an explicit gap, and repeated matches retain unique deterministic IDs.
- Public CLI errors use stable path-free messages, including filesystem and internal failures.
- Sanitization refuses unsafe overwrite relationships and preserves original inputs.
- Reports are designed not to serialize raw evidence or absolute scan roots.
- Artifact byte identity uses temporary, run-scoped HMAC tokens instead of raw file digests, preventing offline enumeration of low-entropy files while retaining within-run comparisons.
- Verification checks artifact inventory, type, size, byte identity, and distinct repeated finding occurrences; unexplained changes or incomplete transformations fail closed instead of treating a lower finding count as improvement.

### Documentation

- Added bilingual quick starts, support matrix, security policy, threat model, architecture, research notes, contribution rules, and third-party notices.

[Unreleased]: https://github.com/motanwenzhu/sharesafe/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/motanwenzhu/sharesafe/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/motanwenzhu/sharesafe/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/motanwenzhu/sharesafe/releases/tag/v0.1.0
