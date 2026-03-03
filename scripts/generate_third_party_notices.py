#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate THIRD-PARTY-NOTICES from Rust and Python dependency metadata.

Usage:
    python scripts/generate_third_party_notices.py

Writes THIRD-PARTY-NOTICES to the repo root. Requires `cargo` on PATH
for Rust deps. Python deps are read from pyproject.toml.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def find_repo_root() -> Path:
    """Walk up from CWD to find the directory containing .git."""
    path = Path.cwd()
    while path != path.parent:
        if (path / ".git").exists():
            return path
        path = path.parent
    return Path.cwd()


# Workspace member crate names to exclude (these are ours, not third-party).
WORKSPACE_PREFIXES = ("navigator-",)


def get_rust_deps_from_cargo_metadata() -> list[dict[str, str]] | None:
    """Try to extract third-party Rust deps via `cargo metadata`."""
    try:
        result = subprocess.run(
            ["cargo", "metadata", "--format-version", "1"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None

    meta = json.loads(result.stdout)
    workspace_members = set(meta.get("workspace_members", []))

    deps = []
    for pkg in meta["packages"]:
        if pkg["id"] in workspace_members:
            continue
        if any(pkg["name"].startswith(p) for p in WORKSPACE_PREFIXES):
            continue
        deps.append({
            "name": pkg["name"],
            "version": pkg["version"],
            "license": pkg.get("license") or "Unknown",
            "repository": pkg.get("repository") or "",
        })

    return sorted(deps, key=lambda d: d["name"].lower())


def get_rust_deps_from_lockfile(root: Path) -> list[dict[str, str]]:
    """Fallback: parse Cargo.lock for name+version (no license info)."""
    lockfile = root / "Cargo.lock"
    if not lockfile.exists():
        return []

    deps = []
    content = lockfile.read_text()
    name = None
    version = None
    for line in content.splitlines():
        if line.startswith("name = "):
            name = line.split('"')[1]
        elif line.startswith("version = ") and '"' in line:
            version = line.split('"')[1]
        elif line == "[[package]]" or line == "":
            if name and version:
                if not any(name.startswith(p) for p in WORKSPACE_PREFIXES):
                    deps.append({
                        "name": name,
                        "version": version,
                        "license": "See crates.io",
                        "repository": f"https://crates.io/crates/{name}",
                    })
            name = None
            version = None

    # Catch the last entry.
    if name and version:
        if not any(name.startswith(p) for p in WORKSPACE_PREFIXES):
            deps.append({
                "name": name,
                "version": version,
                "license": "See crates.io",
                "repository": f"https://crates.io/crates/{name}",
            })

    return sorted(deps, key=lambda d: d["name"].lower())


def get_rust_deps(root: Path) -> list[dict[str, str]]:
    """Extract third-party Rust dependencies.

    Prefers `cargo metadata` for full license info. Falls back to parsing
    Cargo.lock when cargo is not available.
    """
    deps = get_rust_deps_from_cargo_metadata()
    if deps is not None:
        return deps

    print("  cargo not found, falling back to Cargo.lock parsing", file=sys.stderr)
    return get_rust_deps_from_lockfile(root)


def get_python_deps(root: Path) -> list[dict[str, str]]:
    """Extract Python dependencies from pyproject.toml [project.dependencies]."""
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return []

    # Simple parser: read the dependencies list without a TOML library.
    content = pyproject.read_text()
    deps = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("dependencies = ["):
            in_deps = True
            continue
        if in_deps:
            if stripped == "]":
                break
            # Parse "package>=version" style.
            dep = stripped.strip('",').strip()
            if dep:
                # Split on first version specifier.
                for sep in (">=", "==", "~=", "!=", "<", ">"):
                    if sep in dep:
                        name = dep[:dep.index(sep)].strip()
                        deps.append({
                            "name": name,
                            "version": dep[dep.index(sep):].strip(),
                            "license": "See PyPI",
                            "repository": f"https://pypi.org/project/{name}/",
                        })
                        break
                else:
                    deps.append({
                        "name": dep,
                        "version": "",
                        "license": "See PyPI",
                        "repository": f"https://pypi.org/project/{dep}/",
                    })

    return sorted(deps, key=lambda d: d["name"].lower())


def format_notices(rust_deps: list[dict], python_deps: list[dict]) -> str:
    """Format the THIRD-PARTY-NOTICES file content."""
    lines = [
        "THIRD-PARTY SOFTWARE NOTICES",
        "",
        "This file lists the third-party software packages used by NemoClaw,",
        "along with their respective licenses.",
        "",
        "To regenerate: uv run python scripts/generate_third_party_notices.py",
        "",
    ]

    if rust_deps:
        lines.append("=" * 80)
        lines.append("Rust Dependencies")
        lines.append("=" * 80)
        lines.append("")
        for dep in rust_deps:
            lines.append(f"Package: {dep['name']} {dep['version']}")
            lines.append(f"License: {dep['license']}")
            if dep["repository"]:
                lines.append(f"Repository: {dep['repository']}")
            lines.append("")

    if python_deps:
        lines.append("=" * 80)
        lines.append("Python Dependencies")
        lines.append("=" * 80)
        lines.append("")
        for dep in python_deps:
            version_str = f" {dep['version']}" if dep["version"] else ""
            lines.append(f"Package: {dep['name']}{version_str}")
            lines.append(f"License: {dep['license']}")
            if dep["repository"]:
                lines.append(f"Repository: {dep['repository']}")
            lines.append("")

    return "\n".join(lines)


def main() -> int:
    root = find_repo_root()

    print("Collecting Rust dependencies...")
    rust_deps = get_rust_deps(root)
    print(f"  Found {len(rust_deps)} Rust dependencies")

    print("Collecting Python dependencies...")
    python_deps = get_python_deps(root)
    print(f"  Found {len(python_deps)} Python dependencies")

    notices = format_notices(rust_deps, python_deps)
    output = root / "THIRD-PARTY-NOTICES"
    output.write_text(notices)
    print(f"Wrote {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
