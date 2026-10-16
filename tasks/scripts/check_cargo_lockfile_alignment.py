#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# /// script
# requires-python = ">=3.11"
# ///

"""Check that aligned Cargo workspaces lock shared crates like the root does.

Some workspaces outside the root build root crates through path
dependencies, for example the conformance suites build `openshell-sdk`. Each
workspace has its own Cargo.lock, and `cargo --locked` only checks a lockfile
against its own manifest, so nothing stops the two lockfiles from resolving
the same crate to different versions. The root's versions are the ones CI and
the Nix toolchain are built for; a newer `aws-lc-sys`, for example, does not
link against the AWS-LC that Nix provides.

This check fails when an aligned workspace locks a registry crate that the
root lockfile also contains at a version the root lockfile does not have.
With `--fix`, it re-locks each aligned workspace starting from the root
lockfile.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

# Workspaces whose shared crates must match the root lockfile. Add a
# workspace here once its lockfile has been aligned with `--fix`.
ALIGNED_WORKSPACES = ("tests/suites/conformance", "tests/testkit")


@dataclass(frozen=True)
class Mismatch:
    workspace: str
    name: str
    version: str
    root_versions: tuple[str, ...]

    def target(self) -> str | None:
        """The root version semver-compatible with the locked one, if any."""
        key = compat_key(self.version)
        candidates = [v for v in self.root_versions if compat_key(v) == key]
        return max(candidates, key=version_tuple) if candidates else None


def version_tuple(version: str) -> tuple[int, ...]:
    core = re.split(r"[-+]", version, maxsplit=1)[0]
    return tuple(int(part) for part in core.split("."))


def compat_key(version: str) -> tuple[int, ...]:
    """Cargo's caret-compatibility class: the leftmost non-zero component."""
    major, minor, patch = (*version_tuple(version), 0, 0, 0)[:3]
    if major:
        return (major,)
    if minor:
        return (0, minor)
    return (0, 0, patch)


def registry_versions(lockfile: Path) -> dict[str, set[str]]:
    """Versions of registry (non-path) packages in a lockfile, by name."""
    data = tomllib.loads(lockfile.read_text())
    versions: dict[str, set[str]] = {}
    for package in data.get("package", []):
        if "source" in package:
            versions.setdefault(package["name"], set()).add(package["version"])
    return versions


def mismatches(root: Path, workspace: str) -> list[Mismatch]:
    root_versions = registry_versions(root / "Cargo.lock")
    found = []
    for name, versions in sorted(
        registry_versions(root / workspace / "Cargo.lock").items()
    ):
        shared = root_versions.get(name)
        if shared is None:
            continue
        for version in sorted(versions - shared, key=version_tuple):
            found.append(
                Mismatch(
                    workspace, name, version, tuple(sorted(shared, key=version_tuple))
                )
            )
    return found


def fix(root: Path, workspace: str) -> list[Mismatch]:
    """Re-lock the workspace starting from the root lockfile.

    Coupled crates such as the `futures-*` family pin each other, so they
    cannot be moved one at a time. Seeding the workspace lockfile with the
    root's lets Cargo keep every root version that still fits, add only the
    crates the root does not have, and drop the rest. Returns what is still
    misaligned afterwards.
    """
    shutil.copyfile(root / "Cargo.lock", root / workspace / "Cargo.lock")
    subprocess.run(
        [
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--manifest-path",
            str(root / workspace / "Cargo.toml"),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return mismatches(root, workspace)


def report(problems: list[Mismatch]) -> None:
    for m in problems:
        target = m.target()
        hint = (
            f"; root has {target}"
            if target
            else f"; root has {', '.join(m.root_versions)}"
        )
        print(
            f"error: {m.workspace}: {m.name} {m.version} is not in the root Cargo.lock{hint}",
            file=sys.stderr,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--fix", action="store_true", help="update aligned lockfiles to root versions"
    )
    args = parser.parse_args(argv)

    root = Path(
        subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    problems: list[Mismatch] = []
    for workspace in ALIGNED_WORKSPACES:
        print(f"Checking {workspace}/Cargo.lock against Cargo.lock")
        problems += fix(root, workspace) if args.fix else mismatches(root, workspace)

    if problems:
        report(problems)
        if not args.fix:
            print(
                "Run `uv run tasks/scripts/check_cargo_lockfile_alignment.py --fix` to align them.",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
