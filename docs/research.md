# ShareSafe research and positioning

Research snapshot: 2026-09-12
Purpose: validate the Skill-authoring approach, examine adjacent open-source tools, and identify a useful non-duplicative v0.1 boundary.

This is a product/architecture survey, not a security audit or endorsement. Feature descriptions reflect the linked project documentation at the snapshot date and can change.

## Answer: are there Skills that help create Skills?

Yes. The strongest starting point for this project is OpenAI's official **Skill Creator**, which was available in this Codex environment and is published in the `openai/skills` repository:

- [OpenAI Skill Creator](https://github.com/openai/skills/blob/main/skills/.system/skill-creator/SKILL.md) defines the expected `SKILL.md` frontmatter, concise/progressive-disclosure structure, deterministic scripts, `references/`, `agents/openai.yaml`, initialization, validation, and iteration workflow.
- [OpenAI CLI Creator](https://github.com/openai/skills/blob/main/skills/.curated/cli-creator/SKILL.md) is especially relevant because ShareSafe is a durable CLI paired with a thin Skill. It emphasizes explicit verbs, stable JSON, machine-readable errors, capability discovery, dry-run/preview boundaries for writes, and completing the CLI before relying on agent instructions.
- OpenAI's [Build skills](https://learn.chatgpt.com/docs/build-skills) and [Save workflows as skills](https://learn.chatgpt.com/use-cases/reusable-codex-skills) guidance explain discovery through name/description and the value of packaging repeatable workflows.

A third-party example, [mblode/agent-skills' Agent Skills Creator](https://github.com/mblode/agent-skills/blob/main/skills/agent-skills-creator/SKILL.md), adds useful ideas around routing evaluations, independent validators, installation smoke tests, and comparing with-skill versus without-skill behavior.

### Decision

ShareSafe uses the official local Skill Creator as the primary authoring process and the official CLI Creator as a design reference. No third-party creator was installed for v0.1. That avoids adding executable supply-chain surface merely to scaffold a small Skill; useful evaluation ideas can be implemented directly and reviewed in-repository.

The resulting design is deliberately two-part:

- deterministic security behavior in Python scripts with repeatable tests;
- a short Skill that orders operations and prevents unsafe conversational shortcuts.

## Adjacent tool landscape

The space already contains strong metadata scrubbers and redaction systems. ShareSafe should not pretend those tools do not exist.

| Project | Documented center of gravity | What it teaches ShareSafe | Why ShareSafe is not a clone |
|---|---|---|---|
| [mat2](https://github.com/jvoisin/mat2) | Metadata inspection/removal across many file formats | Mature format-specific metadata removal is valuable and difficult; interoperability is preferable to casually reimplementing every cleaner | ShareSafe centers on whole-boundary audit, masked evidence, coverage gaps, stable JSON, and post-transform verification |
| [nym](https://github.com/byteowlz/nym) | Fast local PII detection/anonymization, reversible strategies, Office/PDF document redaction, optional OCR | Full content anonymization needs richer pattern policy, document rewriting, and verification than a v0.1 metadata sanitizer | ShareSafe does not rewrite body text; it is a release gate that can later recommend/delegate to specialist redaction tooling |
| [metawipe](https://github.com/rwrife/metawipe) | Bootstrapping-stage design/roadmap for a friendly local desktop metadata viewer/scrubber across images, PDF, and Office | The proposed before/after visibility and local-first UX reflect a real user need, while project status shows that broad format claims require careful verification | ShareSafe is CLI/agent/CI oriented and makes only release-tested claims about filenames, code/secrets, nested archives, coverage gaps, and bundles |
| [PhilterDesktop](https://github.com/philterd/PhilterDesktop) | Windows desktop and headless PII redaction for documents, with policy/review workflows | Human review, residual verification, and explicit policy are essential for document disclosure | ShareSafe is cross-platform Python alpha, not a redaction queue/UI or policy engine; v0.1 deliberately avoids body modification |
| [doc_redaction](https://github.com/seanpedrick-case/doc_redaction) | GUI-assisted PDF/image/Word/tabular extraction and redaction, including OCR/model options | OCR and layout-aware redaction are separate product domains with substantial dependencies and review needs | ShareSafe records OCR as unsupported/incomplete instead of implying pixel coverage |
| [Synthetiq Redact](https://github.com/Synthetiq-HQ/synthetiq-redact) | Local-first OCR, layout mapping, PII detection, human review, burned PDF output, and provenance for casework | True redaction should remove or raster-burn content and retain review/audit evidence; drawing an overlay is insufficient | ShareSafe does not create redacted PDFs or make legal disclosure decisions; it checks a broader release bundle and fails closed on absent representations |

These projects overlap substantially with an initial “automatic file sanitizer” idea. Building another broad redactor would add little value and invite unsafe claims.

## The uncovered workflow

The meaningful gap is not a new regex collection. It is a single, automation-friendly **pre-share audit and verification layer** that asks:

> “Across everything I am about to send—not just the document I can see—what disclosure signals were found, and what could not be checked?”

A release boundary can include:

- source/config files and credential-like filenames;
- absolute paths, usernames, and host-specific traces;
- Office properties, comments, revisions, notes, hidden sheets/slides, external links, custom XML, macros, and embedded files;
- PDF metadata or unextractable/scanned pages;
- image metadata and visible-but-unread pixels;
- nested ZIP members, misleading extensions, encrypted members, and archive bombs;
- unsupported binaries mixed into an otherwise ordinary folder.

Many tools solve one transformation well. ShareSafe's role is to normalize risk and **coverage evidence** across the boundary, then direct the user to specialist tools when necessary.

## Product decisions derived from research

### 1. Scan first; transformation is optional

The default command is read-only. Privacy tools themselves can damage evidence or originals, so writing requires an explicit destination. The scanner and sanitizer have separate responsibilities.

### 2. “No findings” is intentionally weaker than “safe”

Pattern detection has false negatives, parsers expose partial representations, and formats evolve. The strongest honest success label is `no_findings` for checks that completed. Unsupported, encrypted, malformed, parser-failed, dependency-blocked, or resource-limited inspection yields `incomplete`.

### 3. Coverage is data, not a warning paragraph

Coverage appears per artifact/capability in versioned JSON and affects the overall verdict and exit code. This prevents CI or an agent from discarding a warning while reading a nominally successful status.

### 4. Reports must not become a second disclosure

Many security scanners echo the exact matching secret to make remediation convenient. A report meant to be attached to a sharing decision cannot do that. ShareSafe masks at the finding boundary, excludes the absolute root, and avoids IDs derived from sensitive evidence.

### 5. Archive and hidden-content inspection belong in the MVP

The unit a user shares is often a folder or ZIP, not one visible document. Recursive virtual inspection and OOXML structural signals provide more differentiated value than adding another body-text replacement mode.

### 6. Sanitization remains narrow

v0.1 removes only high-confidence metadata from new copies of supported formats. It does not modify body text, comments, revisions, notes, hidden sheets/slides, pixels, or active content. Residual findings are expected and visible.

### 7. Verification rereads output

A transformation log proves only that code attempted an operation. Verification independently scans produced bytes and makes new/residual findings and lost coverage visible.

### 8. Stable CLI before elaborate Skill behavior

Following the CLI Creator pattern, the CLI exposes explicit `scan`, `sanitize`, `verify`, `doctor`, `rules`, `formats`, and `self-test` commands plus versioned JSON. The Skill remains a cautious workflow wrapper rather than a second implementation.

## v0.1 scope selected

The initial release targets:

- text, source code, and common configuration/log files;
- OOXML Word, Excel, and PowerPoint packages;
- ZIP archives with bounded recursive inspection;
- basic/optional-parser PDF inspection;
- basic/optional-parser JPEG and PNG metadata inspection;
- likely email, Chinese mainland mobile, validated Chinese resident ID, common token/key, private-key, credential assignment, and identity-bearing user-home/UNC path patterns;
- risky filenames and selected Office hidden-content structures;
- shareable masked JSON, explicit gaps, deterministic identifiers, and automation exit codes;
- copy-only high-confidence metadata sanitization followed by rescan.

See [../SUPPORT_MATRIX.md](../SUPPORT_MATRIX.md) for normative format claims. Features outside that matrix are not implied by a dependency's capabilities.

## Explicitly deferred

- OCR, vision, handwriting, audio, and video analysis;
- named-entity models and context-aware semantic PII detection;
- body-text anonymization or reversible pseudonymization;
- true PDF redaction and visual review UI;
- full macro/embedded-object analysis and malware scanning;
- broad-format metadata rewriting already handled by mature tools;
- compliance certificates or automatic publish approval.

These are not dismissed as unimportant. They are deferred because each needs a stronger threat model, dependencies, domain policy, and independent verification than can responsibly fit in the first release.

## Future interoperability opportunities

Once the core report contract is stable, ShareSafe could support explicitly configured adapters for mature local tools such as mat2 or specialist redactors. Integration should capture tool/version provenance, preserve offline behavior, translate partial failures into gaps, rescan outputs, and never upgrade an external exit code into a ShareSafe safety claim.

Other useful extensions include SARIF/CI policy views, user-defined deterministic rule packs, reproducible report signing, richer dependency attestations, and a plan-and-apply workflow for transformations requiring human approval.

## Evaluation criteria

ShareSafe is useful only if it reduces repeated release work without manufacturing confidence. v0.1 should therefore be evaluated on:

- correct routing and safe defaults in fresh Codex sessions;
- absence of raw synthetic evidence and absolute paths from every output channel;
- explicit incomplete results for every tested blind spot;
- deterministic report structure and IDs;
- resistance to malformed/nested/resource-exhausting inputs;
- preservation of originals and mandatory output rescanning;
- actionable explanations that point to the next review/tool rather than saying “safe”;
- installation and execution from a clean environment.

This positioning is the core novelty: ShareSafe is not the last redaction engine. It is the small, repeatable gate that tells a person or agent what was found, what was changed, and—most importantly—what remains unknown.
