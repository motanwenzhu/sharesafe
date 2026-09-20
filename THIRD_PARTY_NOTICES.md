# Third-party notices

ShareSafe itself is licensed under the Apache License 2.0. This file records direct dependencies declared for v0.3; it is informational and does not replace the license files distributed by those projects.

No third-party project source code, model, rule corpus, binary, fixture, or media asset is intentionally vendored in this repository. Installed Python distributions retain their own license metadata and notices.

## Runtime-optional dependencies

| Project | Declared range | Purpose | License expression | Upstream |
|---|---:|---|---|---|
| Pillow | `>=10` | Optional deeper metadata parsing for supported image inputs | `MIT-CMU` for current releases; older releases commonly identify the Historical Permission Notice and Disclaimer | https://pypi.org/project/Pillow/ |
| pypdf | `>=5` | Optional PDF text extraction and parser-assisted inspection; not PDF sanitization | `BSD-3-Clause` | https://pypi.org/project/pypdf/ |

These dependencies are not installed by the zero-dependency core. Use the `images`, `pdf`, or `full` project extra to opt in. Their presence does not imply that ShareSafe supports every format or feature exposed by the library.

## Build and development dependencies

| Project | Declared range | Purpose | License expression | Upstream |
|---|---:|---|---|---|
| setuptools | `>=77` | PEP 517 build backend | `MIT` | https://pypi.org/project/setuptools/ |
| pytest | `>=8` | Test runner | `MIT` | https://pypi.org/project/pytest/ |
| build | `>=1.2` | Distribution build frontend | `MIT` | https://pypi.org/project/build/ |
| jsonschema | `>=4` | Development-time validation of versioned JSON report schemas | `MIT` | https://pypi.org/project/jsonschema/ |

Transitive dependencies may be installed by these projects and can vary by platform and resolved version. Before redistribution, generate an environment-specific dependency inventory and retain every license/notice required by the exact artifacts shipped.

## Referenced, not incorporated

Research documentation links to other privacy and redaction tools for comparison. ShareSafe does not incorporate their code or claim endorsement by their maintainers. See [docs/research.md](docs/research.md).

## Updating this file

Any dependency, copied algorithm, generated asset, bundled schema, borrowed rule list, or vendored fixture must be reviewed for provenance and license compatibility. Update this notice in the same pull request and include the upstream license text when its terms require distribution.
