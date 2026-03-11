#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Convert CycloneDX SBOM JSON files to CSV.

Usage:
    python sbom_to_csv.py                      # convert all *.cdx.json in deploy/sbom/output/
    python sbom_to_csv.py file1.json ...       # convert specific files
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path


def extract_licenses(component: dict) -> str:
    """Pull license IDs/names from CycloneDX license entries."""
    licenses = component.get("licenses", [])
    ids = []
    for entry in licenses:
        lic = entry.get("license", {})
        ids.append(lic.get("id") or lic.get("name", ""))
    return " | ".join(filter(None, ids))


def sbom_to_csv(json_path: Path) -> Path:
    """Read a CycloneDX JSON SBOM and write a CSV beside it."""
    with json_path.open() as f:
        sbom = json.load(f)

    csv_path = json_path.with_suffix(".csv")
    components = sbom.get("components", [])

    with csv_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["name", "version", "type", "purl", "licenses", "bom-ref"])

        for comp in components:
            writer.writerow(
                [
                    comp.get("name", ""),
                    comp.get("version", ""),
                    comp.get("type", ""),
                    comp.get("purl", ""),
                    extract_licenses(comp),
                    comp.get("bom-ref", ""),
                ]
            )

    return csv_path


def _find_sbom_files() -> list[Path]:
    """Find SBOM JSON files in the default output directory."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    output_dir = repo_root / "deploy" / "sbom" / "output"
    return sorted(output_dir.glob("*.cdx.json"))


def main() -> None:
    files = [Path(p) for p in sys.argv[1:]] if len(sys.argv) > 1 else _find_sbom_files()

    if not files:
        print("No SBOM JSON files found.")
        print("Run 'mise run sbom:generate' first, or pass file paths as arguments.")
        sys.exit(1)

    for path in files:
        csv_path = sbom_to_csv(path)
        with csv_path.open() as count_fh:
            components_count = sum(1 for _ in count_fh) - 1  # minus header
        print(f"{path.name} -> {csv_path.name}  ({components_count} components)")


if __name__ == "__main__":
    main()
