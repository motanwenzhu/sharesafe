# ShareSafe

**A local, offline privacy gate for files before they leave your machine.**

ShareSafe scans a file, directory, or release bundle for likely disclosure risks and coverage gaps. It looks beyond visible body text: names can leak through filenames, secrets through source files, identity through document properties, and hidden material through Office packages or nested archives. The CLI produces a masked, machine-readable report, and the companion Codex Skill applies the same cautious workflow consistently.

> [!IMPORTANT]
> `no_findings` means only that the checks which completed did not report a match. It does **not** mean “safe,” anonymous, compliant, or approved for release. Unsupported, encrypted, malformed, parser-failed, or resource-limited content makes coverage `incomplete`.

ShareSafe is alpha software. Review the report, the coverage gaps, and the files themselves before sharing anything sensitive.

[简体中文](README.zh-CN.md) · [Chinese user guide](docs/user-guide.zh-CN.md) · [Design & workflows (中文)](docs/design-and-workflows.zh-CN.md) · [Support matrix](SUPPORT_MATRIX.md) · [Threat model](THREAT_MODEL.md) · [Architecture](docs/architecture.md) · [Research](docs/research.md)

## What v0.1 is for

- Audit text, code, configuration, OOXML (`.docx`, `.xlsx`, `.pptx`), ZIP, PDF, JPEG, and PNG inputs before sharing.
- Detect likely PII, credentials, identity-bearing user-home/UNC paths, identifying metadata, and selected hidden-document structures.
- Inventory selected roots and empty directories, scan container names/comments, and traverse nested ZIP content under defensive resource limits.
- Keep raw evidence out of reports by masking sensitive values at the finding boundary.
- Create sanitized **copies** for a narrow set of high-confidence metadata transformations.
- Rescan transformed output and expose residual findings or incomplete coverage.
- Return stable JSON and meaningful exit codes for scripts, CI, and agent workflows.

ShareSafe is not a full document redactor. In v0.1, `sanitize` does not rewrite body text, apply visual redaction, run OCR, remove Office comments/revisions/notes/hidden sheets, or guarantee that every identifying signal is gone. Use a specialist redaction tool and human review when the content itself must change.

## Safety model in one minute

| Result | Meaning | Release action |
|---|---|---|
| `no_findings` | Completed checks found no configured match. | Still review scope and the file. |
| `review` | Findings need a human decision. | Inspect before sharing. |
| `block` | A high-risk finding crossed the configured threshold. | Do not share as-is. |
| `incomplete` | One or more relevant checks could not complete. | Treat as not cleared; resolve the gap or review with another tool. |

Coverage is tracked independently for each artifact. `incomplete` takes precedence over ordinary findings because a clean-looking partial scan is more dangerous than an explicit warning.

## Install

ShareSafe requires Python 3.11 or newer. The core scanner has no runtime dependency. Install optional PDF and image adapters with the `full` extra.

```bash
git clone https://github.com/motanwenzhu/sharesafe.git
cd sharesafe
```

Create the environment and install with its interpreter, without relying on shell activation:

```bash
# macOS / Linux
python3 -m venv .venv
./.venv/bin/python -m pip install ".[full]"
```

```powershell
# Windows PowerShell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install ".[full]"
```

Activate the virtual environment if you want to call `sharesafe` directly. Without activation, use the environment's explicit Python path shown above with `-m sharesafe`. The examples below assume activation.

For a minimal installation without optional PDF/image libraries:

```bash
# macOS / Linux
./.venv/bin/python -m pip install .
```

```powershell
# Windows PowerShell
.\.venv\Scripts\python.exe -m pip install .
```

Missing optional support is reported by `doctor` and becomes an explicit coverage gap when it affects an input; it is never silently treated as a successful scan.

## Quick start

First inspect capabilities on the current machine:

```bash
sharesafe doctor --json
sharesafe formats --json
sharesafe rules --json
```

Scan a file or folder without modifying it:

```bash
sharesafe scan ./bundle --json --report ./sharesafe-report.json
```

Create a separate sanitized output and rescan it:

```bash
sharesafe sanitize ./bundle --out ./bundle.sanitized --json --report ./sharesafe-sanitize-report.json
```

Compare an original with a proposed release copy:

```bash
sharesafe verify ./bundle ./bundle.sanitized --json --report ./sharesafe-verify-report.json
```

`sanitize` already returns its trusted before/after verification. Standalone `verify` is a conservative comparison for a separately prepared copy: because it has no authenticated transform manifest, any byte change remains `unverified` even when findings decrease.

Run the built-in synthetic smoke test:

```bash
sharesafe self-test --json
```

Use `sharesafe COMMAND --help` for the current options, including the scan threshold accepted by `--fail-on`.

## CLI contract

```text
sharesafe scan PATH [PATH ...] [--json] [--report FILE] [--fail-on LEVEL]
sharesafe sanitize PATH --out NEW_PATH [--json] [--report FILE]
sharesafe verify ORIGINAL PREPARED [--json] [--report FILE]
sharesafe doctor [--json]
sharesafe rules [--json]
sharesafe formats [--json]
sharesafe self-test [--json]
```

Scan-like JSON uses schema identifier `sharesafe.report/v1` and includes `tool`, `run`, `summary`, `artifacts`, `findings`, `gaps`, `errors`, and `dependencies`. Display paths are relative; reports must not contain the absolute scan root, raw file digests, or unmasked evidence. Artifact byte identity is represented by a temporary, run-scoped HMAC content token so paired scans can compare bytes without publishing an offline-guessable SHA-256. Finding identifiers are unique and deterministic without hashing the sensitive value itself.

`sanitize` and `verify` wrappers also include `verification.integrity`. Artifact deletion, addition, type changes, unexplained content-token/size changes, and skipped/partial/unsupported transforms make verification `incomplete`; a falling finding count alone is never treated as proof of a valid transformation.

Exit codes are designed for automation:

| Code | Meaning |
|---:|---|
| `0` | Operation completed and no finding met the configured threshold. |
| `1` | A finding met the threshold, or verification did not pass. |
| `2` | Coverage was incomplete. |
| `3` | Arguments or the requested operation were unsafe or invalid. |
| `4` | Filesystem or unexpected internal failure; no safety conclusion was produced. |

Do not write automation that interprets only code `0` as authorization to publish. Confirm the report schema, verdict, coverage, and the policy appropriate to your release.

## Sanitization boundaries

`sanitize` is intentionally narrower than `scan`:

- It writes to a new destination and refuses unsafe overwrite relationships.
- It preserves the original input.
- It may remove only high-confidence metadata from supported OOXML, JPEG, and PNG copies. PDF is audit-only in v0.1; a PDF may be copied into an output tree, but ShareSafe reports its metadata transformation as unsupported and does not call it sanitized.
- It does not silently modify body text or make editorial disclosure decisions.
- It rescans output immediately. Residual findings and coverage gaps remain visible.
- Where the platform permits, it sets output access and modification times to a fixed value. It does not promise to normalize Windows creation/birth time. It preserves only the executable/non-executable class of regular-file permissions where meaningful; exact modes, ownership, ACLs, extended attributes, alternate data streams, and other platform metadata are not cloned or sanitized. New output receives or inherits security properties from the destination parent according to the operating system.

Successful file creation is not successful verification. For exact format behavior, see [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md).

## Use as a Codex Skill

The repository includes a thin companion Skill in `skills/sharesafe`. The Skill teaches Codex to check capabilities first, default to read-only scanning, preserve masked evidence, request a separate output for transformations, and avoid calling a partial result “safe.” Deterministic detection and report generation remain in the bundled Python implementation.

The Skill is self-contained: `scripts/run_sharesafe.py` loads the implementation shipped inside its own folder. Installing the wheel is optional and is needed only when you want the global `sharesafe` shell command.

For a public GitHub checkout, the recommended Codex installation flow is to invoke `$skill-installer` and ask it to install:

```text
https://github.com/motanwenzhu/sharesafe/tree/main/skills/sharesafe
```

For a manual installation from a cloned repository, copy the folder to the current official user-scope location:

```bash
# macOS / Linux
mkdir -p "$HOME/.agents/skills"
cp -R skills/sharesafe "$HOME/.agents/skills/sharesafe"
```

```powershell
# Windows PowerShell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.agents\skills" | Out-Null
Copy-Item -Recurse -Force ".\skills\sharesafe" "$env:USERPROFILE\.agents\skills\sharesafe"
```

Codex normally detects the new Skill automatically; restart only if it does not appear. Then ask: “Audit this release folder with ShareSafe and explain every coverage gap.” See the [official OpenAI Build skills documentation](https://learn.chatgpt.com/docs/build-skills) for current discovery and installation behavior.

## Privacy and security properties

- Normal scanning and sanitization are designed to run locally without network access.
- Adapters receive bytes and a display-only virtual path; they must not execute embedded content.
- Reports mask evidence before serialization and avoid absolute source paths.
- Archive traversal preflights classic/ZIP64 central directories before entry objects are materialized, then enforces entry, decompressed-byte, compression-ratio, and nesting limits.
- Search results, PNG chunks/decompressed text, and archive-comment text have explicit caps; a truncation or malformed structure produces `incomplete`.
- CLI failure envelopes use stable path-free messages so diagnostics do not become a second disclosure.
- Parser failures become gaps instead of disappearing into logs.
- Sanitization never promises secure deletion of originals, temporary files, backups, or filesystem history.

Read [SECURITY.md](SECURITY.md) before testing with sensitive material and [THREAT_MODEL.md](THREAT_MODEL.md) before relying on ShareSafe in a high-risk workflow.

## Development

Use synthetic fixtures only. Never commit real personal data, credentials, private documents, or reports derived from them.

```bash
python -m pip install -e ".[full,dev]"
python -m pytest
sharesafe self-test --json
python -m build
```

Behavioral changes must preserve the contract in `docs/design-contract.md` or explicitly version the affected schema/semantics. See [CONTRIBUTING.md](CONTRIBUTING.md) for adapter, masking, fixture, and release requirements.

## Project status and non-goals

The v0.1 goal is a dependable pre-share audit layer, not broad automatic redaction. Near-term work should improve tested coverage, rule precision, report stability, and interoperability with mature specialist tools. It should not inflate `no_findings` into a certification claim.

ShareSafe does not provide legal advice, malware scanning, forensic anonymity, steganography detection, secure erasure, or a compliance certification. Its output is evidence for a release decision—not the decision itself.

## License and links

Licensed under [Apache-2.0](LICENSE).

- Repository: https://github.com/motanwenzhu/sharesafe
- Issues: https://github.com/motanwenzhu/sharesafe/issues
- Security reports: https://github.com/motanwenzhu/sharesafe/security/advisories/new
