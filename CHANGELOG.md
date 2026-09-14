# Changelog

All notable changes to ShareSafe will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Security fixes may intentionally tighten parsing or fail-closed behavior in a patch release.

## [Unreleased]

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

[Unreleased]: https://github.com/motanwenzhu/sharesafe/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/motanwenzhu/sharesafe/releases/tag/v0.1.0
