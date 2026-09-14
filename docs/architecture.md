# ShareSafe architecture

Status: v0.1 architecture baseline
Audience: contributors, reviewers, and integrators

## System intent

ShareSafe is an evidence-producing privacy gate placed immediately before a file leaves a trusted local boundary. It has two layers:

1. a deterministic Python CLI that discovers bytes, invokes bounded adapters, records masked findings and coverage gaps, creates narrowly sanitized copies, and verifies output; and
2. a thin Codex Skill that selects the safe CLI workflow, preserves user authorization, and explains uncertainty without inventing stronger guarantees.

The Skill is not the scanner. Privacy-critical detection, masking, path checks, exit codes, and report serialization live in testable code.

## High-level data flow

```text
user-selected paths
        |
        v
discovery + boundary checks -----> unreadable/link/special-file gaps
        |
        v
bounded immutable bytes + display-only virtual path
        |
        v
type sniffing -----> mismatch finding / unsupported gap
        |
        v
format adapter -----> rule hits -----> mask at finding boundary
        |                    |                    |
        |                    +--------------------+
        v                                         v
coverage + parser/resource gaps             ReportBuilder
        |                                         |
        +-----------------------------------------+
                                                  v
                                      sharesafe.report/v1 + exit code

sanitize: input -> validate distinct destination -> transform copy
         -> scan produced output -> transformation + residual report

verify: original summary + independent candidate scan
        -> comparison/coverage decision -> verification report
```

Nothing in this flow authorizes publication. The final consumer—human, CI policy, or agent—must interpret findings and gaps in context.

## Repository layout

```text
pyproject.toml
skills/sharesafe/
  SKILL.md                         # agent workflow and safety boundaries
  agents/openai.yaml               # user-facing Skill metadata
  references/                      # progressively disclosed Skill guidance
  scripts/
    run_sharesafe.py               # repo/Skill-friendly launcher
    sharesafe/
      __main__.py                  # python -m sharesafe entry point
      cli.py                       # argument parsing and stdout/stderr contract
      engine.py                    # discovery and scan orchestration
      models.py                    # report objects, verdicts, stable identifiers
      limits.py                    # defensive resource policy
      zip_safety.py                # allocation-bounded central-directory preflight
      sniff.py                     # content-based type selection
      detectors.py                 # deterministic rules and validation
      redaction.py                 # evidence masking, not document redaction
      adapters/                    # format-specific byte inspection
      sanitize.py                  # copy-only transformation orchestration
      verify.py                    # original/candidate comparison
tests/                             # synthetic unit and integration tests
docs/                              # design, architecture, and research records
```

The exact module set can evolve, but the component boundaries below are public design constraints.

## Discovery and filesystem boundary

The scanner accepts one or more user-selected paths. Discovery creates stable, display-only relative paths and never emits the absolute scan root. The selected root and empty-directory leaves are inventory artifacts, so their names are scanned and deletion remains visible to verification. If the selected root is itself a `Users`, `home`, or `Documents and Settings` container, discovery retains that non-secret label only as detector context and removes it again from descendant display paths; paired sanitize/verify scans inherit the same context. Directories are enumerated deterministically where the platform permits.

Links/reparse points and special filesystem objects are not ordinary file bytes. They are not followed across the selected boundary; instead, ShareSafe records a finding or coverage gap. Version-control metadata is a release-risk signal because repository history can contain deleted secrets even when the working files look clean.

Files are opened in binary mode, bounded by the configured maximum, and checked for identity/metadata changes around the read. A race or read failure becomes a gap. The adapter receives the bytes already read; it does not reopen the path.

## Type selection

`sniff.py` selects an adapter using content signatures and constrained structural checks, with the display extension as supporting—not authoritative—information. A meaningful mismatch creates a deceptive-file finding. Ambiguous or unknown binary input becomes unsupported/incomplete instead of falling through to a text-success path.

This distinction prevents `invoice.pdf.exe`, a renamed ZIP, or arbitrary binary bytes from inheriting a stronger coverage claim merely from a suffix.

## Adapter contract

Every adapter receives:

- immutable bytes;
- a sanitized display-only virtual path;
- resource limits;
- a finding/gap sink through the report builder;
- bounded recursion state when it contains other artifacts.

Adapters must not open arbitrary paths, write files, execute active content, fetch external relationships, or use the network. They should inspect only representations they can account for. A parser exception, encrypted member, unsupported method, truncated structure, or limit hit becomes a structured gap.

### Text adapter

The text adapter performs bounded decoding and passes searchable text to deterministic rules. Encoding ambiguity that prevents the promised check must reduce coverage. Rule locations identify structure or offsets without placing raw evidence in identifiers.

### ZIP/archive adapter

The archive adapter treats member names as virtual labels, never as extraction destinations. Before `zipfile` creates a list of per-entry objects, a bounded parser validates classic or ZIP64 end records and walks no more than the configured central-directory entry count. It then rejects or flags absolute/traversal names, encryption, unsupported methods, suspicious sizes, excessive compression, duplicate ambiguity, deep nesting, and budget exhaustion. Directory entries enter inventory; archive/member comments are scanned under a cumulative text budget. Supported file members re-enter type sniffing as bytes under a `container!/member` display path.

### OOXML adapter

OOXML (`.docx`, `.xlsx`, `.pptx` and detected package variants) is inspected as a constrained ZIP/XML package without launching Office software. The adapter examines every bounded XML/relationship part, scans all part names and non-XML parts, and recognizes core/app/custom properties plus selected indicators such as comments, tracked changes, speaker notes, hidden worksheets/slides, macros, signatures, external data, custom XML, and embedded/ActiveX parts. DTD/entity-bearing or malformed XML is incomplete; raw malformed XML receives a bounded fallback text scan. Opaque embedded objects are reported but not interpreted or rewritten.

“Detected” and “removed” are separate capabilities. v0.1 sanitization is limited to high-confidence document properties; it does not automatically delete comments, revisions, notes, hidden content, macros, signatures, external links, embedded objects, or body text.

### PDF adapter

PDF inspection combines conservative built-in metadata/structure signals with optional parser-based text extraction. With a compatible `pypdf`, ShareSafe can inspect accessible page text, but deep structure remains partial in v0.1. It does not render pages, run OCR, rewrite PDF metadata, or perform true redaction. Encryption, parser failure, inaccessible representations, or missing dependency produces incomplete coverage. Sanitization may copy a PDF unchanged into a release tree, but records the PDF transform as unsupported.

### Image adapter

JPEG and PNG adapters inspect supported metadata/container structures; Pillow can add deeper parsing and metadata-rewrite capability. PNG parsing caps total chunks and applies one cumulative budget to strictly validated zTXt/iTXt decompression. With Pillow, v0.1 can also perform limited metadata inspection of detected TIFF and WebP inputs, but it does not sanitize those formats. Pixels remain unchanged and are not OCR-scanned. Metadata removal cannot establish that visible personal information, embedded watermarks, or steganographic content is absent.

## Detection and masking boundary

`detectors.py` contains deterministic, discoverable rules. A detector returns structured hit data; the report path converts it to a finding only after applying the masking policy in `redaction.py` (the module name refers to report evidence, not document-body redaction).

The report may retain a value class, masked prefix/suffix where policy permits, length bucket, structural location, and an ephemeral correlation tag. It must not serialize the raw match. Correlation material should be scoped to a run so reports cannot become a durable lookup oracle.

Finding IDs use non-secret artifact identity, stable rule ID, structured location, and deterministic occurrence. They remain unique when one location has repeated matches and do not hash raw sensitive evidence or file bytes: ordinary hashes of low-entropy PII are reversible by enumeration, and even strong keyed correlation is unnecessary for the public identifier.

## Report aggregation

`models.py` owns the `sharesafe.report/v1` envelope. Scan-like reports contain:

- `tool` and `run` provenance;
- `summary` verdict and counts;
- discovered `artifacts` with media type, size, run-scoped HMAC content token, status, and per-capability coverage;
- masked `findings`;
- structured `gaps`;
- non-sensitive `errors`;
- optional parser/dependency availability.

Artifact byte identity uses a domain-separated HMAC under the same temporary in-memory key as finding correlation. The key is never serialized, so paired before/after scans can compare bytes without exposing a raw digest that reveals membership in a guessed set. Reports should still be handled as sensitive operational records because paths, sizes, categories, and structure remain contextual disclosures.

Verdict precedence is fail-closed:

```text
any relevant gap/error/partial artifact -> incomplete
else any high/critical finding          -> block
else any finding                        -> review
else                                    -> no_findings
```

An incomplete report retains all findings discovered before the gap.

## Resource model

`limits.py` is a security boundary, not a performance tuning afterthought. Limits cover total file bytes, searchable text/XML bytes, archive member count, per-member bytes, total expanded bytes, compression ratio, nesting depth, and retained findings per artifact/run. Format-specific hard caps additionally bound PNG chunk traversal.

Adapters check declared sizes before materialization where possible and enforce limits again while reading. A limit hit stops only the unsafe work necessary, records the uninspected capability, and yields `incomplete`. Tightening defaults to address denial-of-service risk is allowed in a patch release when documented.

## Sanitization pipeline

Sanitization is a separate orchestration path, never a mode bit that gives scanners write access:

1. canonicalize input and requested destination;
2. reject equality, overwrite, dangerous nesting, and unsupported target relationships;
3. create a new output using a staging/atomic strategy appropriate to the platform;
4. copy unchanged files and apply only allow-listed metadata transforms to supported OOXML/JPEG/PNG formats;
5. preserve/report transform failures rather than substituting originals as “sanitized” success;
6. independently scan the produced output;
7. set release-copy access and modification times to a fixed value where supported, and preserve only coarse executable/non-executable permissions, without claiming to normalize Windows creation/birth time or preserve ownership, ACLs, extended attributes, or alternate data streams;
8. report transformed, unchanged, unsupported, failed, residual, and newly observed states.

Source integrity should be tested by before/after run-scoped content tokens and sizes. File creation alone never changes the verdict to success. Body-text editing requires a future explicit plan-and-apply design with independent verification.

The destination parent is a security boundary. Staged/new paths receive or inherit its platform access-control properties. ShareSafe does not clone source owners, ACLs, exact modes, extended attributes, alternate data streams, or every filesystem metadata field, and it does not promise to normalize Windows creation/birth time. A sanitized tree is therefore a release copy, not a backup.

## Verification

Verification is evidence comparison, not proof of safety. It should scan the candidate independently, compare artifact identities and relevant finding/gap classes, and make loss of coverage visible. A candidate can reduce one metadata finding while introducing a new filename leak or unsupported conversion; that is not a pass.

The v1 verifier compares artifact path inventories, detected media types, byte sizes, HMAC content tokens produced with one temporary key shared by the paired scans, and occurrence-aware finding multisets. A standalone `verify` has no trusted transformation manifest, so any content change is `unverified` and therefore `incomplete`. During `sanitize`, only an `applied` internal action for the same path and allow-listed OOXML/PNG/JPEG media type may explain a token change; skipped, partial, failed, or unsupported actions remain incomplete. This integrity gate prevents deleting a sensitive file—or replacing its body with an empty file—from appearing to be an improvement merely because findings disappeared.

The verifier must not trust a prior report in place of reading the candidate bytes. If either side cannot be interpreted sufficiently for the comparison being claimed, verification fails or is incomplete.

## CLI and Skill boundary

`cli.py` owns argument validation, JSON/human rendering, report-file writing, and exit codes. JSON stdout must remain parseable under failure; human diagnostics belong on stderr and use the same non-disclosure discipline. Exception strings and filesystem paths never enter the public error envelope; stable generic messages distinguish request, filesystem, and internal failure classes.

The companion Skill should:

- run `doctor` before a consequential audit;
- default to `scan`;
- explain findings and every gap without requesting raw evidence;
- use `sanitize` only when the user authorizes creation of a distinct output;
- never edit original/body content on ShareSafe's behalf;
- verify/rescan before discussing release readiness;
- avoid the words “safe,” “clean,” “certified,” or “compliant” as an unqualified verdict.

The Skill must not reimplement regexes or parse documents conversationally. That would make results model-dependent and harder to test.

## Extension rules

A new format adapter needs a precise support claim, hostile/malformed fixtures, resource accounting, dependency behavior, and explicit coverage for every representation it does not inspect. A new rule needs positive/negative tests and a masking test. A new sanitizer needs original-integrity, output-boundary, content-preservation, and mandatory-rescan tests.

Any incompatible report change requires a new schema identifier. Additive fields must have clear absence semantics. The support matrix and threat model are release artifacts and change with the code.

## Testing architecture

The test suite uses only synthetic data and has four layers:

1. **Unit tests** for validators, sniffing, masking, IDs, limits, and verdict precedence.
2. **Adapter tests** for valid, malformed, encrypted, oversized, nested, and misleading-extension inputs.
3. **CLI/integration tests** for stdout/stderr, JSON schema, exit codes, original preservation, sanitize-rescan behavior, and installed entry points.
4. **Skill behavior tests** in fresh agent contexts for triggering, read-only default, incomplete-result explanation, authorization boundaries, and refusal to overclaim.

Release verification requires all four layers above. Security regressions should assert the absence of raw synthetic detector evidence and absolute temporary paths from all captured output—not only the presence of expected findings. Relative display filenames are intentionally retained and need separate sensitivity tests/documentation.
