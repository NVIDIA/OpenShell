#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Preview repository label-definition preparation; never mutate GitHub labels."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

from check_review_readiness import LABEL, parse_reviewers

ROOT = Path(__file__).resolve().parents[2]
FIELDS = {"name", "description", "color"}


def _definition(value: dict) -> None:
    if set(value) != FIELDS or not isinstance(value["name"], str):
        raise ValueError("Definitions require name, description, and color")
    if not isinstance(value["color"], str) or not re.fullmatch(
        r"[0-9a-fA-F]{6}", value["color"]
    ):
        raise ValueError("Colors must contain six hexadecimal digits")
    if (
        not isinstance(value["description"], str)
        or not 1 <= len(value["description"]) <= 100
    ):
        raise ValueError("Descriptions must contain 1 to 100 characters")


def plan_definitions(catalog: dict, roster: str, current: list[dict]) -> dict:
    """Produce a reversible definition plan without changing item associations."""
    if (
        set(catalog) != {"schema_version", "active", "retire"}
        or catalog["schema_version"] != 1
    ):
        raise ValueError("Unsupported taxonomy catalog")
    active = {}
    for definition in catalog["active"]:
        _definition(definition)
        name = definition["name"]
        if not LABEL.fullmatch(name) or name in active:
            raise ValueError(f"Invalid or duplicate active label: {name}")
        active[name] = definition
    if set(active) != set(parse_reviewers(roster)):
        raise ValueError("Catalog active labels must match the reviewer roster exactly")

    retiring = {}
    for entry in catalog["retire"]:
        if set(entry) != {"name", "new_name", "description", "color"}:
            raise ValueError("Invalid retirement entry")
        name, target = entry["name"], entry["new_name"]
        if (
            not isinstance(name, str)
            or not LABEL.fullmatch(name)
            or name in retiring
            or name in active
        ):
            raise ValueError(f"Invalid or duplicate retiring label: {name}")
        if target != "retired:" + name:
            raise ValueError(
                f"Retirement must preserve the complete original name: {name}"
            )
        desired = {
            "name": target,
            "description": entry["description"],
            "color": entry["color"],
        }
        _definition(desired)
        retiring[name] = desired

    live = {}
    for entry in current:
        name = entry["name"]
        if name in live:
            raise ValueError(f"Duplicate live label: {name}")
        live[name] = entry
    unknown = (
        {name for name in live if name.startswith(("area:", "topic:"))}
        - active.keys()
        - retiring.keys()
    )
    if unknown:
        raise ValueError(
            "Unreviewed active classification labels: " + ", ".join(sorted(unknown))
        )

    operations = []

    def compare(before, after, action):
        if before and before.get("archived_at"):
            raise ValueError(f"Archived label needs separate review: {before['name']}")
        if before is None or any(
            (before.get(key) or "") != value for key, value in after.items()
        ):
            operations.append({"action": action, "before": before, "after": after})

    for name, desired in active.items():
        before = live.get(name)
        compare(before, desired, "update" if before else "create")
    for name, desired in retiring.items():
        old, renamed = live.get(name), live.get(desired["name"])
        if old and renamed:
            raise ValueError(f"Retirement target already exists: {desired['name']}")
        if old or renamed:
            compare(old or renamed, desired, "retire" if old else "update")

    return {
        "schema_version": 1,
        "applied": False,
        "operations": operations,
        "original_labels": current,
        "missing_descriptions": sorted(
            name
            for name, entry in live.items()
            if not (entry.get("description") or "").strip()
        ),
        "item_assignments_changed": False,
    }


def fetch_labels(repository: str) -> list[dict]:
    """GET every page; do not reuse an item-level labeling/mutation adapter."""
    result = subprocess.run(
        [
            "gh",
            "api",
            "--method",
            "GET",
            "--paginate",
            "--slurp",
            f"repos/{repository}/labels?per_page=100",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return [entry for page in json.loads(result.stdout) for entry in page]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="NVIDIA/OpenShell")
    parser.add_argument(
        "--catalog", type=Path, default=ROOT / "tasks/labels/taxonomy.json"
    )
    parser.add_argument("--reviewers", type=Path, default=ROOT / "REVIEWERS.md")
    parser.add_argument(
        "--labels-file", type=Path, help="Offline JSON array of live definitions"
    )
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
        parser.error("--repo must be OWNER/REPO")
    current = (
        json.loads(args.labels_file.read_text())
        if args.labels_file
        else fetch_labels(args.repo)
    )
    plan = plan_definitions(
        json.loads(args.catalog.read_text()), args.reviewers.read_text(), current
    )
    print(json.dumps({"repository": args.repo, **plan}, indent=2))


if __name__ == "__main__":
    main()
