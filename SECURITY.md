# Security policy

ShareSafe handles material that may be highly sensitive. Please report vulnerabilities privately and minimize every artifact you share with maintainers.

## Supported versions

Until the first tagged release, security fixes are made on the default branch. After release, the policy is:

| Version | Security fixes |
|---|---|
| Latest `0.3.x` | Yes, on a best-effort alpha basis |
| `0.1.x`–`0.2.x` | Upgrade to the latest `0.3.x` patch first |
| Unreleased development snapshots | Default branch only |

This policy may change before `1.0.0`. Security fixes can include behavior changes when preserving old behavior would expose data.

## Report a vulnerability

Use a private GitHub Security Advisory:

https://github.com/motanwenzhu/sharesafe/security/advisories/new

Repository maintainers must enable GitHub private vulnerability reporting and verify this link from a signed-out session before the first public release. Do not publish a release while the private reporting path is unavailable.

Do not open a public issue for a vulnerability that could expose users or their files. Include:

- the affected ShareSafe version or commit;
- operating system and Python version;
- the smallest reproducible command;
- expected and observed behavior;
- security impact and plausible attack path;
- a **synthetic** minimal reproducer;
- whether the issue is already public or has been exploited.

Never attach a real document, credential, personal identifier, unsanitized report, home-directory path, username, hostname, or proprietary release bundle. Replace sensitive values with obviously synthetic examples. If a malformed binary is essential, generate it from a script or fixture that contains no real data.

We aim to acknowledge a report within seven days and provide an initial assessment within fourteen days. These are response goals, not service-level guarantees. Please allow coordinated remediation before public disclosure.

## Especially important vulnerability classes

- Raw detector evidence, absolute source roots, or recognized user/host identity from home/UNC paths appearing unmasked in JSON, terminal output, logs, exceptions, finding IDs, or test snapshots. User-selected relative filenames remain visible display data and must be treated as potentially sensitive.
- A parser, encrypted input, unsupported format, malformed file, or resource limit being reported as complete coverage.
- Archive traversal, symlink traversal, path confusion, unsafe output placement, or overwrite of an input.
- Sanitization that changes the original, reports success without rescanning, or silently drops content beyond its documented transform.
- Prepare plans that omit source entries, accept ambiguous/colliding paths, approve only part of an action set, fail to detect source drift, or let an omitted/renamed path reappear through another target.
- Prepare staging or local control artifacts that cannot prove owner-only permissions, destination publication that overwrites a concurrent entry, or final scanning that is not bound to the exact verified output bytes.
- A result-size limit that emits invalid/truncated JSON, hides omitted records without an explicit incomplete state, or turns a committed output into an ambiguous reporting failure.
- ZIP bombs, parser denial of service, unbounded recursion, or excessive allocation.
- Execution of macros, scripts, formulas, links, embedded files, or other active content while scanning.
- Unexpected network access or transfer of inspected content.
- Machine-readable output that is unstable, invalid, or mixes human diagnostics into JSON in a way that can bypass automation.
- Dependency substitution or packaging behavior that installs code outside the documented distribution.

False positives and ordinary missed patterns are generally quality bugs, not vulnerabilities. Treat a false negative as a security report when ShareSafe incorrectly claims complete coverage, contradicts the support matrix, leaks raw evidence, or creates a misleading verification result.

## Safe testing rules

All repository tests, issues, pull requests, demos, and benchmarks must use synthetic data. Good fixtures use reserved domains such as `example.com`, fake keys that cannot authenticate, generated OOXML packages, and invented identities. Do not “sanitize” real data and then commit the result; a sanitizer defect is exactly what the test may reveal.

Run tests in an isolated directory. Do not point a development build at irreplaceable material. Keep originals outside the output tree, and inspect paths before any sanitization command.

## Security guarantees and limits

ShareSafe is a decision-support tool, not a proof of anonymity or compliance. `no_findings` means no configured match was found by checks that completed. It never means “safe.” Any unsupported, encrypted, malformed, parser-failed, or resource-limited content must be treated as `incomplete`.

Normal operation is designed to be local and offline, but the project cannot control package installers, operating-system telemetry, shell history, backup software, endpoint agents, or tools a user invokes before or after ShareSafe. See [THREAT_MODEL.md](THREAT_MODEL.md) for the complete boundary.

## Disclosure and credit

We will coordinate a fix, regression tests, release notes, and advisory when warranted. Reporters may request credit or anonymity. Please do not include exploit details or sensitive examples in commit messages before disclosure.
