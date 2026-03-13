#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate THIRD-PARTY-NOTICES with full license texts.

Uses cargo-about (Rust) and pip-licenses (Python) to collect third-party
dependency licenses and produce a single attribution file at the repo root.

Usage:
    uv run python scripts/generate_third_party_notices.py
    mise run notices

Requires cargo-about (installed via mise) and pip-licenses (fetched via uv).
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

# Our own workspace crates and packages — excluded from notices.
WORKSPACE_CRATES = frozenset(
    {
        "openshell-bootstrap",
        "openshell-cli",
        "openshell-core",
        "openshell-policy",
        "openshell-providers",
        "openshell-router",
        "openshell-sandbox",
        "openshell-server",
        "openshell-tui",
        "openshell-e2e",
    }
)

OWN_PYTHON_PACKAGES = frozenset(
    {
        "openshell",
    }
)

SEPARATOR = "=" * 80
THIN_SEP = "-" * 80


def find_repo_root() -> Path:
    """Walk up from CWD to find the directory containing .git."""
    path = Path.cwd()
    while path != path.parent:
        if (path / ".git").exists():
            return path
        path = path.parent
    return Path.cwd()


# ---------------------------------------------------------------------------
# Rust dependencies via cargo-about
# ---------------------------------------------------------------------------


def get_rust_notices() -> list[dict]:
    """Run cargo-about and return structured license groups.

    Each entry: {id, crates: [{name, version, repository, description}], text}
    """
    print("  Running cargo-about generate --format json ...")
    try:
        result = subprocess.run(
            ["cargo-about", "generate", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        print(
            "  WARNING: cargo-about not found, skipping Rust notices", file=sys.stderr
        )
        return []
    except subprocess.CalledProcessError as e:
        print(f"  WARNING: cargo-about failed: {e.stderr[:200]}", file=sys.stderr)
        return []

    data = json.loads(result.stdout)
    groups: list[dict] = []

    for lic in data.get("licenses", []):
        crates = []
        for entry in lic.get("used_by", []):
            crate = entry.get("crate", {})
            name = crate.get("name", "")
            if name in WORKSPACE_CRATES:
                continue
            crates.append(
                {
                    "name": name,
                    "version": crate.get("version", ""),
                    "repository": crate.get("repository", ""),
                    "description": crate.get("description", ""),
                }
            )

        if not crates:
            continue

        groups.append(
            {
                "id": lic.get("id", "Unknown"),
                "crates": sorted(crates, key=lambda c: c["name"].lower()),
                "text": (lic.get("text") or "").rstrip(),
            }
        )

    return groups


# ---------------------------------------------------------------------------
# Python dependencies via pip-licenses
# ---------------------------------------------------------------------------


def get_python_notices() -> list[dict]:
    """Run pip-licenses and return structured package notices.

    Each entry: {name, version, license_id, text}
    """
    print("  Running pip-licenses ...")
    try:
        result = subprocess.run(
            [
                "uv",
                "run",
                "--with",
                "pip-licenses",
                "pip-licenses",
                "--format=json",
                "--with-license-file",
                "--no-license-path",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        print("  WARNING: uv not found, skipping Python notices", file=sys.stderr)
        return []
    except subprocess.CalledProcessError as e:
        print(f"  WARNING: pip-licenses failed: {e.stderr[:200]}", file=sys.stderr)
        return []

    packages: list[dict] = []
    for pkg in json.loads(result.stdout):
        name = pkg.get("Name", "")
        if name.lower() in OWN_PYTHON_PACKAGES:
            continue
        # Skip pip/setuptools/wheel (installer tools, not shipped deps)
        if name.lower() in {"pip", "wheel"}:
            continue

        packages.append(
            {
                "name": name,
                "version": pkg.get("Version", ""),
                "license_id": pkg.get("License", "Unknown"),
                "text": (pkg.get("LicenseText") or "").rstrip(),
            }
        )

    return sorted(packages, key=lambda p: p["name"].lower())


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def format_notices(
    rust_groups: list[dict],
    python_packages: list[dict],
) -> str:
    """Format the complete THIRD-PARTY-NOTICES file."""
    lines: list[str] = [
        "THIRD-PARTY SOFTWARE NOTICES AND INFORMATION",
        "",
        "This product includes third-party software components. The following",
        "notices and licenses are provided in compliance with the terms of the",
        "respective licenses.",
        "",
        "To regenerate: mise run notices",
        "",
    ]

    # --- Rust section ---
    if rust_groups:
        rust_crate_count = sum(len(g["crates"]) for g in rust_groups)
        lines.append(SEPARATOR)
        lines.append(f"Rust Dependencies ({rust_crate_count} packages)")
        lines.append(SEPARATOR)
        lines.append("")

        for group in rust_groups:
            lines.append(SEPARATOR)
            lines.append(f"License: {group['id']}")
            lines.append(THIN_SEP)
            lines.append("")
            lines.append("Used by:")
            for crate in group["crates"]:
                repo = f"  ({crate['repository']})" if crate["repository"] else ""
                lines.append(f"  - {crate['name']} {crate['version']}{repo}")
            lines.append("")

            if group["text"]:
                lines.append(group["text"])
            lines.append("")

    # --- Python section ---
    if python_packages:
        lines.append(SEPARATOR)
        lines.append(f"Python Dependencies ({len(python_packages)} packages)")
        lines.append(SEPARATOR)
        lines.append("")

        for pkg in python_packages:
            lines.append(SEPARATOR)
            lines.append(f"{pkg['name']} {pkg['version']}")
            lines.append(f"License: {pkg['license_id']}")
            lines.append(THIN_SEP)
            lines.append("")
            if pkg["text"]:
                lines.append(pkg["text"])
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    root = find_repo_root()
    t0 = time.monotonic()

    print("Generating third-party notices...")
    print()

    print("Collecting Rust dependencies...")
    rust_groups = get_rust_notices()
    rust_count = sum(len(g["crates"]) for g in rust_groups)
    print(f"  {rust_count} Rust packages across {len(rust_groups)} license groups")
    print()

    print("Collecting Python dependencies...")
    python_packages = get_python_notices()
    print(f"  {len(python_packages)} Python packages")
    print()

    notices = format_notices(rust_groups, python_packages)
    output = root / "THIRD-PARTY-NOTICES"
    output.write_text(notices)

    elapsed = time.monotonic() - t0
    line_count = notices.count("\n") + 1
    print(f"Wrote {output.name} ({line_count} lines, {len(notices)} bytes)")
    print(f"Done in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
