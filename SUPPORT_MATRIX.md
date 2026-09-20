# ShareSafe v0.3 support matrix

This matrix is the normative v0.3 boundary. It is deliberately conservative, and a release must test every claim it marks supported. Run `sharesafe doctor --deep --json` and `sharesafe formats --json` on the actual machine because optional dependencies affect available coverage.

Terms:

- **Scan** means inspect without intentionally modifying the input.
- **Sanitize** means write a new copy with only documented high-confidence metadata removed.
- **Incomplete** means ShareSafe could not perform one or more relevant checks. It is not a soft success.
- **Structural signal** means ShareSafe can flag that a risky document feature exists; it does not necessarily interpret or remove all content within that feature.

## Input and transformation coverage

| Input | Scan | Sanitize / prepare transform | Important limits |
|---|---|---|---|
| Plain text, source code, config, logs | Decode supported text and run PII, credential, and path rules; inspect filename | Copy-only; body text is never rewritten | Unknown/binary encodings, generated content, and context-dependent identifiers can be missed |
| Directory tree | Inventory the selected root, files, and empty-directory leaves; scan their names; recursively aggregate artifact coverage | Create a separate output tree; transform only formats listed below | A skipped, unreadable, changing, unsupported, or resource-limited entry makes coverage incomplete |
| `.docx` (OOXML) | Inspect ZIP/XML package text, properties, relationships, and selected comment/revision structures | Remove documented high-confidence package metadata in a new copy | Does not delete body text, comments, tracked revisions, macros, embedded objects, or external targets |
| `.xlsx` (OOXML) | Inspect ZIP/XML text, properties, shared strings, relationships, and selected hidden-sheet structures | Remove documented high-confidence package metadata in a new copy | Does not rewrite cells/formulas, unhide or delete sheets, remove comments/macros, or evaluate formulas |
| `.pptx` (OOXML) | Inspect ZIP/XML text, properties, relationships, notes, and selected hidden-slide structures | Remove documented high-confidence package metadata in a new copy | Does not rewrite slide text, remove speaker notes/hidden slides/comments/macros, or render slides |
| Generic `.zip` | Preflight classic/ZIP64 central directories; inventory names/directories; scan archive and member comments; recursively inspect supported entries using virtual paths | No general archive-content sanitization guarantee | Encryption, unsupported compression, malformed entries, comment/text/nesting/ratio/count/byte limits, or unsupported children produce gaps |
| Text-based `.pdf` | Inspect selected metadata/structural tokens; with compatible `pypdf`, also inspect extractable page text | No PDF metadata rewrite; a copy can be emitted but its transform is reported unsupported | Deep structure remains partial/incomplete even with `pypdf`; no OCR, visual analysis, true redaction, attachment guarantee, or exhaustive incremental-history analysis |
| Encrypted or malformed PDF | Detect condition where possible | No claimed cleanup | Always incomplete when relevant content cannot be inspected |
| JPEG | Inspect basic container/metadata; optional Pillow enables deeper supported metadata handling | Remove supported high-confidence metadata into a new copy | Pixels are unchanged and not OCR-scanned; sidecars and uncommon application segments may remain |
| PNG | Inspect bounded chunks/metadata with a cumulative decompressed-text budget; optional Pillow enables deeper supported metadata handling | Remove supported high-confidence textual/metadata chunks into a new copy | More than 4,096 chunks, invalid compressed text, or a text-budget overrun is incomplete; pixels are unchanged and not OCR-scanned |
| TIFF and WebP | With compatible Pillow, inspect supported decoded metadata | None | Pixels are unchanged and not OCR-scanned; without Pillow, metadata inspection is unsupported/incomplete |
| Other images (including HEIC, GIF, and RAW) | Filename/basic type handling only unless an adapter says otherwise | None | Treat as unsupported/incomplete for image privacy inspection |
| Other archives (`7z`, RAR, TAR, etc.) | No archive-content claim | None | Treat as unsupported/incomplete |
| Legacy Office (`.doc`, `.xls`, `.ppt`) | No document-content claim | None | Treat as unsupported/incomplete; converting formats can itself change or expose data |
| Audio, video, email databases, disk images, executables | No content claim | None | Treat as unsupported/incomplete; ShareSafe is not a malware scanner |

File extension alone is not authoritative. Format sniffing and parser results determine the actual adapter. A misleading extension, parser mismatch, or ambiguous binary must not be promoted to complete coverage.

## Exact transformation allowlist

ShareSafe transforms only the items below, always in a newly created output. Anything not listed is retained, copied unchanged, or reported unsupported.

- **OOXML (`.docx`, `.xlsx`, `.pptx`):** remove the package ZIP comment; remove `docProps/custom.xml` and its content-type/relationship references; remove non-empty core-property elements named `creator`, `lastModifiedBy`, `title`, `subject`, `description`, `keywords`, `category`, `identifier`, `created`, `modified`, `lastPrinted`, `revision`, `contentStatus`, `language`, and `version`; remove non-empty application-property elements named `Manager`, `Company`, `Template`, `HyperlinkBase`, `Application`, and `AppVersion`; rebuild ZIP members without member comments or extra fields and with normalized member timestamps and coarse permissions. Macro-enabled, embedded-object-bearing, digitally signed, encrypted, ambiguous, malformed, or resource-limited packages are copied byte-for-byte with a skipped transform and an `incomplete` result.
- **PNG:** remove `tEXt`, `zTXt`, `iTXt`, and `tIME` chunks; remove `eXIf` only when its TIFF structure parses and Orientation is absent or `1`. If EXIF cannot be parsed or Orientation is another value, retain that entire `eXIf` chunk to avoid rotating the displayed image; any other removed chunks make the transform `partial`, otherwise it is skipped, and verification remains `incomplete`.
- **JPEG:** remove COM segments, APP13 segments, XMP-bearing APP1 segments, and EXIF APP1 segments only when EXIF parses and Orientation is absent or `1`. If EXIF cannot be parsed or Orientation is another value, retain that entire EXIF segment; removing other eligible segments makes the transform `partial`, otherwise it is skipped, and verification remains `incomplete`. Encoded scan/pixel data and unlisted APP segments are retained.

The output tree also receives the filesystem metadata treatment documented below. ShareSafe does not delete ordinary document body content, comments, tracked changes, notes, hidden sheets/slides, macros, attachments, or external relationships.

## Prepare action coverage

Every regular source file must have exactly one explicit decision. Empty sources and undecided files are rejected; there is no default include or ignore behavior.

| Action | Executable condition | Verified relation |
|---|---|---|
| `copy_unchanged` | Target equals source-relative path | Same bytes, media type, and size |
| `rename_in_bundle` | Target is a different collision-free portable path | Same bytes and media type at the new path |
| `omit_from_boundary` | Target is null and no target recreates that source path/subtree | Source path and descendants are absent from output |
| `strip_ooxml_metadata` | Detected OOXML and the allow-listed transform is actually applied | Exact expected transformed bytes plus OOXML preserved facets |
| `strip_png_metadata` | Detected PNG and at least one allowed metadata chunk is removed | Exact expected transformed bytes plus PNG pixel/container facets |
| `strip_jpeg_metadata` | Detected JPEG and at least one allowed segment is removed | Exact expected transformed bytes plus JPEG scan/pixel facets |
| `manual_or_external_required` / `block` | Never executable | Forces review before any apply |

Prepare outputs are always new directories. Plans, decisions, and approvals are local-only. `prepare verify` also requires the bound source; a plan digest alone cannot prove unmodified format facets. Output relation checks do not replace the final privacy scan.

## Detection coverage

The rule set is intended to cover high-signal patterns such as:

- email addresses and Chinese mainland mobile-number-like values;
- Chinese resident identity numbers with checksum validation;
- common API keys, access tokens, private-key markers, and credential assignments;
- identity-bearing Windows/Unix user-home paths and selected UNC-style paths;
- high-confidence author, company, GPS, device, software, title, comment, and revision metadata;
- selected OOXML structural signals such as comments, tracked changes, notes, hidden sheets/slides, macros, embedded content, and external relationships.

Rule families and their purposes are discoverable through `sharesafe rules --json`; use `sharesafe rules --detail --json` for the exact versioned inventory. Exact IDs, severities, and confidence are included when a finding is emitted. Coverage limitations use structured `gaps` rather than synthetic rule IDs. Pattern matching cannot reliably detect every name, address, account number, business identifier, custom secret, or contextual disclosure. Absence of a match is never a universal negative.

## Optional dependencies

| Extra | Dependency | Capability it can add | Without it |
|---|---|---|---|
| `pdf` | `pypdf>=5` | Extract accessible PDF page text and improve parser-based inspection | Built-in structural/metadata checks still run, but text/deep PDF coverage remains explicitly incomplete; sanitization is unchanged and unsupported |
| `images` | `Pillow>=10` | Deeper metadata parsing for supported image inputs | Only built-in/basic parsing and built-in supported rewrites are available; affected checks must be reflected in coverage |
| `full` | Both of the above | All optional adapters | Same fail-closed rules apply per missing capability |

Optional libraries do not add OCR, semantic vision, PDF sanitization/true redaction, or support for every format those libraries can technically open. Deep PDF structure remains partial even when `pypdf` succeeds.

## Coverage outcomes

| Coverage | Use |
|---|---|
| `complete` | Every claimed check for that artifact and installed capability completed. This remains narrower than “all privacy risks.” |
| `partial` | Some relevant representation or check completed and another did not. |
| `unsupported` | No adapter can inspect a relevant representation. |
| `not_applicable` | The named check genuinely does not apply to the artifact. |

Encrypted, unsupported, malformed, parser-failed, dependency-blocked, or resource-limited content produces a gap and an overall `incomplete` verdict. Findings already discovered are preserved alongside the gap.

## Resource limits

ShareSafe applies limits before and during archive/parser work, including filesystem inventory, archive nesting, pre-materialization entry count, total decompressed bytes, compression ratio, searchable XML/text, PNG chunks and decompressed text, retained findings per artifact/run, per-artifact size, report fields, and complete JSON bytes. Effective configurable values are recorded in scan reports; command help lists overrides exposed by the current CLI. A finding cap records a gap rather than silently truncating. A scan or prepare-result byte cap returns a complete smaller JSON document with an explicit reporting gap/omission counts and an `incomplete` outcome; it never emits a valid-looking prefix. Defaults may be tightened in patch releases for security. Reaching any limit means `incomplete`, never that the remainder is clean.

## Filesystem metadata of sanitized output

Sanitized output is a release copy, not a filesystem-faithful backup:

- file and directory access and modification times are set to a fixed value where the platform permits;
- Windows creation/birth time is not promised to be normalized;
- regular files retain only executable versus non-executable permission class where that concept is supported;
- exact mode bits, ownership, ACLs, alternate data streams, extended attributes, and other platform metadata are not promised to be copied or sanitized;
- new paths receive or inherit security properties from the destination parent according to operating-system rules.

Choose a destination parent with appropriate access controls before running `sanitize`. If exact filesystem metadata matters, keep a separate original/archive and do not use the sanitized tree as its replacement.

Prepare uses a separate system-temporary staging root. Before source bytes are staged, ShareSafe verifies POSIX effective-user ownership and mode `0700`, or atomically creates and verifies a Windows protected current-user-only DACL with child inheritance. Failure to prove this protection aborts before output reservation. The final output still inherits or receives permissions from its destination parent. Parent and cleanup protection use identity checkpoints and do not claim portable directory-handle anchoring.

## Sanitization checklist

Before sharing a sanitized copy:

1. Confirm the destination is distinct from the input and contains only expected files.
2. Read both transformation status and rescan status.
3. Resolve every residual `review`, `block`, or `incomplete` item.
4. Open important files in an appropriate viewer and inspect content, comments, notes, revisions, hidden sheets/slides, and visual fidelity.
5. Use specialist redaction/OCR tooling when body content or pixels need removal.
6. Apply your organization's approval policy; ShareSafe does not replace it.
