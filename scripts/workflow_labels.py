#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Review and provision workflow label definitions without relabeling items."""

import argparse
import json
import re
import subprocess
from pathlib import Path

MANIFEST = Path(__file__).resolve().parents[1] / ".agents" / "workflow-labels.json"
AXES = ("type:", "state:", "needs:")


def load_manifest(path: Path) -> list[dict[str, str]]:
    data = json.loads(path.read_text())
    labels = data["labels"]
    if not isinstance(labels, list):
        raise ValueError("labels must be a list")

    seen = set()
    for label in labels:
        name = label["name"]
        if name in seen:
            raise ValueError(f"duplicate label: {name}")
        seen.add(name)
        if not name.startswith(AXES):
            raise ValueError(f"not a workflow-axis label: {name}")
        if not re.fullmatch(r"[0-9a-fA-F]{6}", label["color"]):
            raise ValueError(f"invalid color for {name}")
        if not label["description"] or len(label["description"]) > 100:
            raise ValueError(f"invalid description for {name}")
    return labels


def plan_changes(
    desired: list[dict[str, str]], existing: list[dict[str, str]]
) -> list[dict[str, str]]:
    by_name = {label["name"]: label for label in existing}
    changes = []
    for label in desired:
        current = by_name.get(label["name"])
        if current is None:
            action = "create"
        elif (current["color"].lower(), current.get("description") or "") != (
            label["color"].lower(),
            label["description"],
        ):
            action = "update"
        else:
            continue
        changes.append({"action": action, **label})
    return changes


def apply_changes(changes: list[dict[str, str]], repo: str, run) -> None:
    for change in changes:
        run(
            [
                "gh",
                "label",
                "create" if change["action"] == "create" else "edit",
                change["name"],
                "--repo",
                repo,
                "--color",
                change["color"],
                "--description",
                change["description"],
            ]
        )


def read_existing(repo: str) -> list[dict[str, str]]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("--repo must be OWNER/REPO")
    result = subprocess.run(
        ["gh", "api", "--paginate", "--slurp", f"repos/{repo}/labels?per_page=100"],
        check=True,
        capture_output=True,
        text=True,
    )
    return [label for page in json.loads(result.stdout) for label in page]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo", default="NVIDIA/OpenShell", help="OWNER/REPO to inspect"
    )
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument(
        "--apply", action="store_true", help="Create/update definitions after review"
    )
    args = parser.parse_args()

    changes = plan_changes(load_manifest(args.manifest), read_existing(args.repo))
    for change in changes:
        print(
            f"{change['action'].upper()} {change['name']}: {change['description']} ({change['color']})"
        )
    if not changes:
        print("Workflow label definitions are current.")
    if args.apply:

        def run(command):
            subprocess.run(command, check=True)

        apply_changes(changes, args.repo, run)


if __name__ == "__main__":
    main()
