#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reconcile PR reviewers from the merged REVIEWERS.md and current PR metadata.

Preview with --repo OWNER/REPO --pr NUMBER; add --apply to update requests.
Request all matching members with write access, excluding the author. Preserve
manual choices, unknown request provenance, and anyone who commented or reviewed.
The parser and planning helpers are importable. No state is stored between runs.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

HEADER = ["Name", "GitHub ID", "Company/Organization"]
LABEL = re.compile(r"(?:area|topic):[a-z0-9]+(?:-[a-z0-9]+)*")
PROFILE = re.compile(r"\[@([a-z0-9-]+)\]\(https://github\.com/([a-z0-9-]+)/?\)", re.I)


@dataclass(frozen=True)
class ReviewPlan:
    add: tuple[str, ...]
    remove: tuple[str, ...]


def parse_reviewers(markdown: str) -> dict[str, set[str]]:
    """Read category headings and three-column tables, validating identities.

    This reads the roster's plain Markdown format, not arbitrary Markdown.
    Empty tables are valid; duplicate categories or members are errors.
    """
    tables = {}
    label = None
    for raw in markdown.splitlines():
        line = raw.strip()
        if line.startswith("#"):
            label = line.removeprefix("### ")
            if not LABEL.fullmatch(label):
                label = None
                continue
            if label in tables:
                raise ValueError(f"duplicate category {label}")
            tables[label] = []
        elif label and line.startswith("|"):
            if not line.endswith("|"):
                raise ValueError(f"{label}: table rows need enclosing pipes")
            tables[label].append([cell.strip() for cell in line[1:-1].split("|")])
    if not tables:
        raise ValueError("no area/topic membership tables found")
    categories = {}
    for label, rows in tables.items():
        if (
            len(rows) < 2
            or rows[0] != HEADER
            or len(rows[1]) != 3
            or not all(re.fullmatch(r":?-{3,}:?", cell) for cell in rows[1])
        ):
            raise ValueError(f"{label}: expected a three-column membership table")
        members = set()
        for row in rows[2:]:
            match = PROFILE.fullmatch(row[1]) if len(row) == 3 else None
            if not match or match[1].lower() != match[2].lower():
                raise ValueError(f"{label}: GitHub ID must link to the same profile")
            login = match[1].lower()
            if login in members:
                raise ValueError(f"{label}: duplicate member @{login}")
            members.add(login)
        categories[label] = members
    return categories


def select_reviewers(categories: dict[str, set[str]], labels: set[str]) -> set[str]:
    """Return matching handles for one primary area and any number of topics."""
    relevant = {label for label in labels if label.startswith(("area:", "topic:"))}
    if sum(label.startswith("area:") for label in relevant) != 1:
        raise ValueError("a ready PR must have exactly one area label")
    unknown = relevant - categories.keys()
    if unknown:
        raise ValueError("unknown area/topic labels: " + ", ".join(sorted(unknown)))
    return set().union(*(categories[label] for label in relevant))


def engaged_reviewers(*feeds: list[dict]) -> set[str]:
    """Include every review state, general comment, and inline comment."""
    return {
        entry["user"]["login"].lower()
        for feed in feeds
        for entry in feed
        if (entry.get("user") or {}).get("login")
    }


def manual_reviewers(events: list[dict], requested: set[str]) -> set[str]:
    """Reconstruct human additions/removals; preserve unknown provenance too.

    Bot actors identify automated changes. A human request stays protected
    through repeated requests until removal. Human removals are also protected
    from immediate re-requesting. Team events do not affect individual requests.
    """
    active, manual = set(), set()
    changes = [
        event
        for event in events
        if event.get("event") in {"review_requested", "review_request_removed"}
    ]
    for event in sorted(changes, key=lambda entry: entry["id"]):
        login = (event.get("requested_reviewer") or {}).get("login")
        if not login:
            continue
        login = login.lower()
        automated = (event.get("actor") or {}).get("type") == "Bot"
        if event["event"] == "review_requested":
            if login not in active:
                manual.discard(login)
            active.add(login)
            if not automated:
                manual.add(login)
        else:
            active.discard(login)
            if automated:
                manual.discard(login)
            else:
                manual.add(login)
    return manual | ({login.lower() for login in requested} - active)


def plan_review_requests(
    selected: set[str],
    *,
    requested: set[str],
    engaged: set[str],
    manual: set[str],
) -> ReviewPlan:
    """Compute changes without IO, preserving engaged and manual reviewer state."""
    selected, requested, engaged, manual = (
        {login.lower() for login in group}
        for group in (selected, requested, engaged, manual)
    )
    protected = engaged | manual
    return ReviewPlan(
        tuple(sorted(selected - requested - protected)),
        tuple(sorted(requested - selected - protected)),
    )


def _api(path: str, *, method: str = "GET", data=None, pages: bool = False):
    command = ["gh", "api", path, "--method", method]
    if pages:
        command.extend(["--paginate", "--slurp"])
    if data is not None:
        command.extend(["--input", "-"])
    result = subprocess.run(
        command,
        input=json.dumps(data) if data is not None else None,
        capture_output=True,
        text=True,
        check=True,
    )
    value = json.loads(result.stdout) if result.stdout.strip() else None
    return [item for page in value for item in page] if pages else value


def _load_reviewers(repository: str, number: int, pr: dict) -> dict[str, set[str]]:
    root = f"repos/{repository}"
    pull = f"{root}/pulls/{number}"
    reviews = _api(f"{pull}/reviews?per_page=100", pages=True)
    comments = _api(f"{root}/issues/{number}/comments?per_page=100", pages=True)
    inline = _api(f"{pull}/comments?per_page=100", pages=True)
    timeline = _api(f"{root}/issues/{number}/timeline?per_page=100", pages=True)
    requested = {user["login"].lower() for user in pr["requested_reviewers"]}
    return {
        "requested": requested,
        "engaged": engaged_reviewers(reviews, comments, inline),
        "manual": manual_reviewers(timeline, requested),
    }


def _eligible_reviewers(repository: str, logins: set[str]) -> set[str]:
    eligible = set()
    for login in sorted(logins):
        value = _api(f"repos/{repository}/collaborators/{login}/permission")
        if value.get("permission") in {"write", "maintain", "admin"}:
            eligible.add(login)
    return eligible


def _routing_key(pr: dict):
    return pr["state"], pr["draft"], {
        label["name"]
        for label in pr["labels"]
        if label["name"].startswith(("area:", "topic:"))
    }


def check_review_readiness(
    categories: dict[str, set[str]],
    repository: str,
    number: int,
    *,
    apply=False,
) -> ReviewPlan | None:
    """Plan or apply routing. Callers must serialize runs for the same PR."""
    pull = f"repos/{repository}/pulls/{number}"
    pr = _api(pull)
    if pr["state"] != "open" or pr["draft"]:
        return None
    selected = select_reviewers(categories, {label["name"] for label in pr["labels"]})
    selected = _eligible_reviewers(repository, selected - {pr["user"]["login"].lower()})
    plan = plan_review_requests(selected, **_load_reviewers(repository, number, pr))
    if apply:
        endpoint = f"{pull}/requested_reviewers"
        if plan.add:
            _api(endpoint, method="POST", data={"reviewers": list(plan.add)})
        if plan.remove:
            # Re-read human choices and engagement immediately before removals.
            latest = _api(pull)
            if _routing_key(latest) != _routing_key(pr):
                raise ValueError("PR routing changed; rerun reconciliation")
            refreshed = plan_review_requests(
                selected, **_load_reviewers(repository, number, latest)
            )
            plan = ReviewPlan(plan.add, refreshed.remove)
            if plan.remove:
                _api(endpoint, method="DELETE", data={"reviewers": list(plan.remove)})
    return plan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reviewers", type=Path, default=Path("REVIEWERS.md"))
    parser.add_argument("--repo", required=True, help="target OWNER/REPO")
    parser.add_argument("--pr", required=True, type=int, help="pull request number")
    parser.add_argument(
        "--apply", action="store_true", help="apply requests; otherwise preview JSON"
    )
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo) or args.pr <= 0:
        parser.error("--repo must be OWNER/REPO and --pr must be positive")
    try:
        categories = parse_reviewers(args.reviewers.read_text(encoding="utf-8"))
        plan = check_review_readiness(categories, args.repo, args.pr, apply=args.apply)
    except (OSError, UnicodeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Review readiness: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(asdict(plan) if plan is not None else {"skipped": "closed or draft PR"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
