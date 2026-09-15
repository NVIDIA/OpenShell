#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Exit non-zero unless a maintainer listed in MAINTAINERS.md has approved.

Runs as bare `python3` on the Actions runner, so it must stay stdlib-only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Only a login that appears as a link to a GitHub profile counts. A bare
# "[@someone]" in prose must never widen the approver set. Keep this in step
# with tasks/scripts/alert_maintainer_change.py, which reports the deltas this
# gate enforces.
MAINTAINER_RE = re.compile(
    r"\[@([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)\]\(https://github\.com/"
)

# States that express a standing position. COMMENTED and PENDING leave a
# reviewer's earlier approval intact, which is how GitHub itself treats them.
DECISIVE_STATES = frozenset({"APPROVED", "CHANGES_REQUESTED", "DISMISSED"})


def parse_maintainers(markdown: str) -> set[str]:
    """Return the lowercased GitHub logins listed in a MAINTAINERS.md table."""
    return {match.group(1).lower() for match in MAINTAINER_RE.finditer(markdown)}


def parse_reviews_to_approvers(reviews: list[dict]) -> set[str]:
    """Return the lowercased logins whose current review state is an approval.

    A reviewer's latest decisive review supersedes their earlier ones, ordered
    by review id rather than by the order the caller assembled the pages in.
    """
    positions: dict[str, str] = {}
    for entry in sorted(reviews, key=lambda r: r.get("id") or 0):
        state = str(entry.get("state") or "").upper()
        if state not in DECISIVE_STATES:
            continue
        login = str((entry.get("user") or {}).get("login") or "").lower()
        if login:
            positions[login] = state
    return {login for login, state in positions.items() if state == "APPROVED"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--maintainers",
        required=True,
        type=Path,
        help="MAINTAINERS.md read from the default branch",
    )
    parser.add_argument(
        "--reviews",
        required=True,
        type=Path,
        help="JSON array returned by the list-reviews API",
    )
    args = parser.parse_args(argv)

    maintainers = parse_maintainers(args.maintainers.read_text(encoding="utf-8"))
    if not maintainers:
        # Fail closed: an unparseable list must never satisfy the gate.
        print("Could not parse any maintainers from MAINTAINERS.md")
        return 1

    reviews = json.loads(args.reviews.read_text(encoding="utf-8"))
    approvers = sorted(parse_reviews_to_approvers(reviews) & maintainers)
    if not approvers:
        print("Needs approval from a maintainer listed in MAINTAINERS.md")
        return 1

    print("Approved by " + ", ".join(f"@{login}" for login in approvers))
    return 0


if __name__ == "__main__":
    sys.exit(main())
