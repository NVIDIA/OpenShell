#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Decide whether a pull request carries an approval from a listed maintainer.

The logic here is pure so it can be unit tested. The calling workflow does the
I/O: it fetches MAINTAINERS.md pinned to the default branch, lists the pull
request's reviews, and passes both in as files.

Runs as bare `python3` on the Actions runner, so it must stay stdlib-only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Only a login that appears as a link to a GitHub profile counts. A bare
# "[@someone]" in prose must never widen the approver set.
MAINTAINER_RE = re.compile(
    r"\[@([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)\]\(https://github\.com/"
)

# States that express a standing position. COMMENTED and PENDING leave a
# reviewer's earlier approval intact, which is how GitHub itself treats them.
DECISIVE_STATES = frozenset({"APPROVED", "CHANGES_REQUESTED", "DISMISSED"})

# GitHub truncates commit status descriptions past this length.
DESCRIPTION_LIMIT = 140

COMMENT_MARKER = "<!-- core-approval-maintainer-delta -->"


def parse_maintainers(markdown: str) -> set[str]:
    """Return the lowercased GitHub logins listed in a MAINTAINERS.md table."""
    return {match.group(1).lower() for match in MAINTAINER_RE.finditer(markdown)}


def latest_positions(reviews: list[dict]) -> dict[str, str]:
    """Map each reviewer's lowercased login to their most recent decisive state.

    The reviews API returns reviews in ascending submission order, so a later
    entry for the same login supersedes an earlier one.
    """
    positions: dict[str, str] = {}
    for entry in reviews:
        state = str(entry.get("state") or "").upper()
        if state not in DECISIVE_STATES:
            continue
        login = str((entry.get("user") or {}).get("login") or "").lower()
        if login:
            positions[login] = state
    return positions


def approving_maintainers(
    reviews: list[dict], maintainers: set[str], author: str
) -> list[str]:
    """Return the listed maintainers whose standing position is an approval."""
    author = author.lower()
    return sorted(
        login
        for login, state in latest_positions(reviews).items()
        if state == "APPROVED" and login in maintainers and login != author
    )


def decide(markdown: str, reviews: list[dict], author: str) -> tuple[str, str]:
    """Return the (state, description) to publish as a commit status."""
    maintainers = parse_maintainers(markdown)
    if not maintainers:
        # Fail closed. An unparseable or empty list must never satisfy the gate.
        return "failure", "Could not parse any maintainers from MAINTAINERS.md"

    approvers = approving_maintainers(reviews, maintainers, author)
    if not approvers:
        return "failure", "Needs approval from a maintainer listed in MAINTAINERS.md"

    shown = ", ".join(f"@{login}" for login in approvers[:3])
    remainder = len(approvers) - 3
    if remainder > 0:
        shown = f"{shown} and {remainder} more"
    return "success", f"Approved by {shown}"[:DESCRIPTION_LIMIT]


def format_delta(before: str, after: str) -> str:
    """Render a review comment describing how the approver set changes."""
    old, new = parse_maintainers(before), parse_maintainers(after)
    added, removed = sorted(new - old), sorted(old - new)

    lines = [COMMENT_MARKER, "## Maintainer list change", ""]
    if not added and not removed:
        lines.append(
            "This pull request edits `MAINTAINERS.md` but does not change the set "
            "of logins the approval gate recognises."
        )
    else:
        if added:
            lines += ["**Gains approval rights:**", ""]
            lines += [f"- @{login}" for login in added]
            lines.append("")
        if removed:
            lines += ["**Loses approval rights:**", ""]
            lines += [f"- @{login}" for login in removed]
            lines.append("")
        lines.append(
            "Confirm every change is intended. Anyone listed here can single-handedly "
            "satisfy `OpenShell / Core Approval`."
        )

    if not new:
        lines += [
            "",
            "> [!WARNING]",
            "> No logins parse from the updated file. Merging this would make the "
            "approval gate fail closed on every pull request.",
        ]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    decide_cmd = subcommands.add_parser(
        "decide", help="print the commit status to publish, as 'state<TAB>description'"
    )
    decide_cmd.add_argument(
        "--maintainers",
        required=True,
        type=Path,
        help="MAINTAINERS.md fetched from the default branch",
    )
    decide_cmd.add_argument(
        "--reviews",
        required=True,
        type=Path,
        help="JSON array returned by the list-reviews API",
    )
    decide_cmd.add_argument(
        "--author", default="", help="pull request author, excluded from approvers"
    )

    diff_cmd = subcommands.add_parser(
        "diff", help="print a review comment describing the approver set change"
    )
    diff_cmd.add_argument(
        "--before", required=True, type=Path, help="MAINTAINERS.md at the base commit"
    )
    diff_cmd.add_argument(
        "--after", required=True, type=Path, help="MAINTAINERS.md at the head commit"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "decide":
        reviews = json.loads(args.reviews.read_text(encoding="utf-8"))
        state, description = decide(
            args.maintainers.read_text(encoding="utf-8"), reviews, args.author
        )
        print(f"{state}\t{description}")
    else:
        print(
            format_delta(
                args.before.read_text(encoding="utf-8"),
                args.after.read_text(encoding="utf-8"),
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
