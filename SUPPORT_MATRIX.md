# ShareSafe v0.1 support matrix

This matrix is the normative v0.1 boundary. It is deliberately conservative, and a release must test every claim it marks supported. Run `sharesafe doctor --json` and `sharesafe formats --json` on the actual machine because optional dependencies affect available coverage.

Terms:

- **Scan** means inspect without intentionally modifying the input.
- **Sanitize** means write a new copy with only documented high-confidence metadata removed.
- **Incomplete** means ShareSafe could not perform one or more relevant checks. It is not a soft success.
- **Structural signal** means ShareSafe can flag that a risky document feature exists; it does not necessarily interpret or remove all content within that feature.

## Input and transformation coverage

| Input | v0.1 scan | v0.1 sanitize | Important limits |
|---|---|---|---|
| Plain text, source code, config, logs | Decode supported text and run PII, credential, and path rules; inspect filename | Copy-only; body text is never rewritten | Unknown/binary encodings, generated content, and context-dependent identifiers can be missed |
| Directory tree | Inventory the selected root, files, and empty-directory leaves; scan their names; recursively aggregate artifact coverage | Create a separate output tree; transform only formats listed below | A skipped, unreadable, changing, unsupported, or resource-limited entry makes coverage incomplete |
| `.docx` (OOXML) | Inspect ZIP/XML package text, properties, relationships, and selected comment/revision structures | Remove documented high-confidence package metadata in a new copy | Does not delete body text, comments, tracked revisions, macros, embedded objects, or external targets |
| `.xlsx` (OOXML) | Inspect ZIP/XML text, properties, shared strings, relationships, and selected hidden-sheet structures | Remove documented high-confidence package metadata in a new copy | Does not rewrite cells/formulas, unhide or delete sheets, remove comments/macros, or evaluate formulas |
| `.pptx` (OOXML) | Inspect ZIP/XML text, properties, relationships, notes, and selected hidden-slide structures | Remove documented high-confidence package metadata in a new copy | Does not rewrite slide text, remove speaker notes/hidden slides/comments/macros, or render slides |
| Generic `.zip` | Preflight classic/ZIP64 central directories; inventory names/directories; scan archive and member comments; recursively inspect supported entries using virtual paths | No general archive-content sanitization guarantee in v0.1 | Encryption, unsupported compression, malformed entries, comment/text/nesting/ratio/count/byte limits, or unsupported children produce gaps |
| Text-based `.pdf` | Inspect selected metadata/structural tokens; with compatible `pypdf`, also inspect extractable page text | No PDF metadata rewrite in v0.1; a copy can be emitted but its transform is reported unsupported | Deep structure remains partial/incomplete even with `pypdf`; no OCR, visual analysis, true redaction, attachment guarantee, or exhaustive incremental-history analysis |
| Encrypted or malformed PDF | Detect condition where possible | No claimed cleanup | Always incomplete when relevant content cannot be inspected |
| JPEG | Inspect basic container/metadata; optional Pillow enables deeper supported metadata handling | Remove supported high-confidence metadata into a new copy | Pixels are unchanged and not OCR-scanned; sidecars and uncommon application segments may remain |
| PNG | Inspect bounded chunks/metadata with a cumulative decompressed-text budget; optional Pillow enables deeper supported metadata handling | Remove supported high-confidence textual/metadata chunks into a new copy | More than 4,096 chunks, invalid compressed text, or a text-budget overrun is incomplete; pixels are unchanged and not OCR-scanned |
| TIFF and WebP | With compatible Pillow, inspect supported decoded metadata | None | Pixels are unchanged and not OCR-scanned; without Pillow, metadata inspection is unsupported/incomplete |
| Other images (including HEIC, GIF, and RAW) | Filename/basic type handling only unless a future adapter says otherwise | None | Treat as unsupported/incomplete for image privacy inspection in v0.1 |
| Other archives (`7z`, RAR, TAR, etc.) | No archive-content claim in v0.1 | None | Treat as unsupported/incomplete |
| Legacy Office (`.doc`, `.xls`, `.ppt`) | No document-content claim in v0.1 | None | Treat as unsupported/incomplete; converting formats can itself change or expose data |
| Audio, video, email databases, disk images, executables | No content claim in v0.1 | None | Treat as unsupported/incomplete; ShareSafe is not a malware scanner |

File extension alone is not authoritative. Format sniffing and parser results determine the actual adapter. A misleading extension, parser mismatch, or ambiguous binary must not be promoted to complete coverage.

## Exact v0.1 transformation allowlist

ShareSafe transforms only the items below, always in a newly created output. Anything not listed is retained, copied unchanged, or reported unsupported.

- **OOXML (`.docx`, `.xlsx`, `.pptx`):** remove the package ZIP comment; remove `docProps/custom.xml` and its content-type/relationship references; remove non-empty core-property elements named `creator`, `lastModifiedBy`, `title`, `subject`, `description`, `keywords`, `category`, `identifier`, `created`, `modified`, `lastPrinted`, `revision`, `contentStatus`, `language`, and `version`; remove non-empty application-property elements named `Manager`, `Company`, `Template`, `HyperlinkBase`, `Application`, and `AppVersion`; rebuild ZIP members without member comments or extra fields and with normalized member timestamps and coarse permissions. Macro-enabled, embedded-object-bearing, digitally signed, encrypted, ambiguous, malformed, or resource-limited packages are copied byte-for-byte with a skipped transform and an `incomplete` result.
- **PNG:** remove `tEXt`, `zTXt`, `iTXt`, and `tIME` chunks; remove `eXIf` only when its TIFF structure parses and Orientation is absent or `1`. If EXIF cannot be parsed or Orientation is another value, retain that entire `eXIf` chunk to avoid rotating the displayed image; any other removed chunks make the transform `partial`, otherwise it is skipped, and verification remains `incomplete`.
- **JPEG:** remove COM segments, APP13 segments, XMP-bearing APP1 segments, and EXIF APP1 segments only when EXIF parses and Orientation is absent or `1`. If EXIF cannot be parsed or Orientation is another value, retain that entire EXIF segment; removing other eligible segments makes the transform `partial`, otherwise it is skipped, and verification remains `incomplete`. Encoded scan/pixel data and unlisted APP segments are retained.

The output tree also receives the filesystem metadata treatment documented below. ShareSafe does not delete ordinary document body content, comments, tracked changes, notes, hidden sheets/slides, macros, attachments, or external relationships in v0.1.

## Detection coverage

The v0.1 rule set is intended to cover high-signal patterns such as:

- email addresses and Chinese mainland mobile-number-like values;
- Chinese resident identity numbers with checksum validation;
- common API keys, access tokens, private-key markers, and credential assignments;
- identity-bearing Windows/Unix user-home paths and selected UNC-style paths;
- high-confidence author, company, GPS, device, software, title, comment, and revision metadata;
- selected OOXML structural signals such as comments, tracked changes, notes, hidden sheets/slides, macros, embedded content, and external relationships.

Rule families and their purposes are discoverable through `sharesafe rules --json`; exact IDs, severities, and confidence are included when a finding is emitted. Coverage limitations use structured `gaps` rather than synthetic rule IDs. Pattern matching cannot reliably detect every name, address, account number, business identifier, custom secret, or contextual disclosure. Absence of a match is never a universal negative.

## Optional dependencies

| Extra | Dependency | Capability it can add | Without it |
|---|---|---|---|
| `pdf` | `pypdf>=5` | Extract accessible PDF page text and improve parser-based inspection | Built-in structural/metadata checks still run, but text/deep PDF coverage remains explicitly incomplete; sanitization is unchanged and unsupported |
| `images` | `Pillow>=10` | Deeper metadata parsing for supported image inputs | Only built-in/basic parsing and built-in supported rewrites are available; affected checks must be reflected in coverage |
| `full` | Both of the above | All optional v0.1 adapters | Same fail-closed rules apply per missing capability |

Optional libraries do not add OCR, semantic vision, PDF sanitization/true redaction, or support for every format those libraries can technically open. Deep PDF structure remains partial in v0.1 even when `pypdf` succeeds.

## Coverage outcomes

| Coverage | Use |
|---|---|
| `complete` | Every v0.1 check claimed for that artifact and installed capability completed. This remains narrower than “all privacy risks.” |
| `partial` | Some relevant representation or check completed and another did not. |
| `unsupported` | No v0.1 adapter can inspect a relevant representation. |
| `not_applicable` | The named check genuinely does not apply to the artifact. |

Encrypted, unsupported, malformed, parser-failed, dependency-blocked, or resource-limited content produces a gap and an overall `incomplete` verdict. Findings already discovered are preserved alongside the gap.

## Resource limits

ShareSafe applies limits before and during archive/parser work, including filesystem inventory, archive nesting, pre-materialization entry count, total decompressed bytes, compression ratio, searchable XML/text, PNG chunks and decompressed text, retained findings per artifact/run, and per-artifact size. Effective configurable values are recorded in the report; command help lists overrides exposed by the current CLI. A finding cap records a gap rather than silently truncating. Defaults may be tightened in patch releases for security. Reaching any limit means `incomplete`, never that the remainder is clean.

## Filesystem metadata of sanitized output

Sanitized output is a release copy, not a filesystem-faithful backup:

- file and directory access and modification times are set to a fixed value where the platform permits;
- Windows creation/birth time is not promised to be normalized;
- regular files retain only executable versus non-executable permission class where that concept is supported;
- exact mode bits, ownership, ACLs, alternate data streams, extended attributes, and other platform metadata are not promised to be copied or sanitized;
- new paths receive or inherit security properties from the destination parent according to operating-system rules.

Choose a destination parent with appropriate access controls before running `sanitize`. If exact filesystem metadata matters, keep a separate original/archive and do not use the sanitized tree as its replacement.

## Sanitization checklist

Before sharing a sanitized copy:

1. Confirm the destination is distinct from the input and contains only expected files.
2. Read both transformation status and rescan status.
3. Resolve every residual `review`, `block`, or `incomplete` item.
4. Open important files in an appropriate viewer and inspect content, comments, notes, revisions, hidden sheets/slides, and visual fidelity.
5. Use specialist redaction/OCR tooling when body content or pixels need removal.
6. Apply your organization's approval policy; ShareSafe does not replace it.
