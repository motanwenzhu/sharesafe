#!/usr/bin/env python3
"""Validate ShareSafe wheel and source-distribution contents."""

from __future__ import annotations

import argparse
import base64
import csv
from email.parser import BytesParser
from email.policy import default
import hashlib
import io
from pathlib import Path, PurePosixPath
import tarfile
import tomllib
import zipfile


REQUIRED_WHEEL_FILES = {
    "sharesafe/__init__.py",
    "sharesafe/__main__.py",
    "sharesafe/catalog.py",
    "sharesafe/cli.py",
    "sharesafe/detectors.py",
    "sharesafe/engine.py",
    "sharesafe/limits.py",
    "sharesafe/models.py",
    "sharesafe/ooxml_xml.py",
    "sharesafe/path_safety.py",
    "sharesafe/redaction.py",
    "sharesafe/reporting.py",
    "sharesafe/sanitize.py",
    "sharesafe/sniff.py",
    "sharesafe/verify.py",
    "sharesafe/zip_safety.py",
    "sharesafe/adapters/__init__.py",
    "sharesafe/adapters/archive.py",
    "sharesafe/adapters/image.py",
    "sharesafe/adapters/ooxml.py",
    "sharesafe/adapters/pdf.py",
    "sharesafe/adapters/text.py",
}

REQUIRED_SDIST_FILES = {
    ".github/scripts/check_release_artifacts.py",
    ".github/workflows/ci.yml",
    ".github/workflows/release.yml",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "MANIFEST.in",
    "README.md",
    "README.zh-CN.md",
    "SECURITY.md",
    "SUPPORT_MATRIX.md",
    "THIRD_PARTY_NOTICES.md",
    "THREAT_MODEL.md",
    "docs/architecture.md",
    "docs/design-contract.md",
    "docs/research.md",
    "docs/skill-evaluation.md",
    "pyproject.toml",
    "schemas/report-v1.schema.json",
    "schemas/sanitize-v1.schema.json",
    "schemas/verify-v1.schema.json",
    "skills/sharesafe/SKILL.md",
    "skills/sharesafe/agents/openai.yaml",
    "skills/sharesafe/references/report-contract.md",
    "skills/sharesafe/references/security-boundaries.md",
    "skills/sharesafe/references/workflow.md",
    "skills/sharesafe/scripts/run_sharesafe.py",
    "tests/conftest.py",
    "tests/test_cli.py",
}
REQUIRED_SDIST_FILES |= {
    f"skills/sharesafe/scripts/{name}" for name in REQUIRED_WHEEL_FILES
}

FORBIDDEN_PARTS = {
    ".git",
    ".pytest_cache",
    ".pytest-tmp",
    "__pycache__",
}

FORBIDDEN_SUFFIXES = {
    ".key",
    ".pem",
    ".pyc",
    ".pyo",
}


def fail(message: str) -> None:
    raise SystemExit(f"release artifact check failed: {message}")


def exactly_one(directory: Path, pattern: str) -> Path:
    matches = sorted(directory.glob(pattern))
    if len(matches) != 1:
        fail(f"expected exactly one {pattern!r} in {directory}, found {len(matches)}")
    return matches[0]


def forbidden(name: str) -> bool:
    path = PurePosixPath(name)
    folded_parts = {part.casefold() for part in path.parts}
    if folded_parts & FORBIDDEN_PARTS:
        return True
    folded_name = path.name.casefold()
    return folded_name == ".env" or any(folded_name.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES)


def verify_record(archive: zipfile.ZipFile, record_name: str) -> None:
    rows = list(csv.reader(io.StringIO(archive.read(record_name).decode("utf-8"))))
    archived = set(archive.namelist())
    recorded = {row[0] for row in rows}
    if archived != recorded:
        fail(
            "wheel RECORD inventory mismatch: "
            f"unrecorded={sorted(archived - recorded)!r}, missing={sorted(recorded - archived)!r}"
        )

    for name, hash_spec, size in rows:
        data = archive.read(name)
        if size and len(data) != int(size):
            fail(f"wheel RECORD size mismatch for {name}")
        if not hash_spec:
            continue
        algorithm, expected = hash_spec.split("=", 1)
        digest = hashlib.new(algorithm, data).digest()
        actual = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        if actual != expected:
            fail(f"wheel RECORD hash mismatch for {name}")


def check_wheel(path: Path, version: str) -> None:
    dist_info = f"sharesafe-{version}.dist-info"
    with zipfile.ZipFile(path) as archive:
        corrupt = archive.testzip()
        if corrupt is not None:
            fail(f"corrupt wheel member: {corrupt}")
        names = set(archive.namelist())
        missing = REQUIRED_WHEEL_FILES - names
        if missing:
            fail(f"wheel is missing core package files: {sorted(missing)!r}")
        rejected = sorted(name for name in names if forbidden(name) or name.startswith("tests/"))
        if rejected:
            fail(f"wheel contains forbidden files: {rejected!r}")

        metadata_name = f"{dist_info}/METADATA"
        wheel_name = f"{dist_info}/WHEEL"
        entry_points_name = f"{dist_info}/entry_points.txt"
        record_name = f"{dist_info}/RECORD"
        license_name = f"{dist_info}/licenses/LICENSE"
        for required in (metadata_name, wheel_name, entry_points_name, record_name, license_name):
            if required not in names:
                fail(f"wheel is missing {required}")

        metadata = BytesParser(policy=default).parsebytes(archive.read(metadata_name))
        if metadata["Name"] != "sharesafe" or metadata["Version"] != version:
            fail("wheel project name or version does not match pyproject.toml")
        if metadata["Requires-Python"] != ">=3.11":
            fail("wheel Requires-Python must remain >=3.11")
        if metadata["License-Expression"] != "Apache-2.0":
            fail("wheel must declare the Apache-2.0 SPDX license expression")

        wheel_metadata = archive.read(wheel_name).decode("utf-8")
        if "Root-Is-Purelib: true" not in wheel_metadata or "Tag: py3-none-any" not in wheel_metadata:
            fail("wheel must remain a platform-independent pure-Python package")
        entry_points = archive.read(entry_points_name).decode("utf-8")
        if "sharesafe = sharesafe.cli:main" not in entry_points:
            fail("wheel does not expose the sharesafe console command")
        verify_record(archive, record_name)


def check_sdist(path: Path, version: str) -> None:
    root = f"sharesafe-{version}"
    with tarfile.open(path, "r:gz") as archive:
        names = set(archive.getnames())

    for name in names:
        member = PurePosixPath(name)
        if member.is_absolute() or ".." in member.parts:
            fail(f"sdist contains an unsafe path: {name}")
        if member.parts and member.parts[0] != root:
            fail(f"sdist member is outside the expected root {root!r}: {name}")

    relative = {
        name[len(root) + 1 :]
        for name in names
        if name.startswith(root + "/")
    }
    missing = REQUIRED_SDIST_FILES - relative
    if missing:
        fail(f"sdist is missing release sources: {sorted(missing)!r}")
    rejected = sorted(name for name in relative if forbidden(name))
    if rejected:
        fail(f"sdist contains forbidden cache or secret-like files: {rejected!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", type=Path, help="directory containing one wheel and one sdist")
    parser.add_argument("--tag", help="optional release tag, which must be v<project-version>")
    args = parser.parse_args()

    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = project["version"]
    if args.tag is not None and args.tag != f"v{version}":
        fail(f"tag {args.tag!r} does not match project version v{version}")

    wheel = exactly_one(args.dist, "*.whl")
    sdist = exactly_one(args.dist, "*.tar.gz")
    check_wheel(wheel, version)
    check_sdist(sdist, version)
    print(f"release artifacts valid for ShareSafe {version}: {wheel.name}, {sdist.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
