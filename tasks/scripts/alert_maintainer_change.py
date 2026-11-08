#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Print a review comment describing how a pull request changes the approver set
to make sure that reviewers notice the change.

Prints nothing when the approver set is unchanged, and exits non-zero when the
updated file yields no maintainers at all.

Runs as bare `python3` on the Actions runner, so it must stay stdlib-only.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

# Only a login that appears as a link to a GitHub profile counts. A bare
# "[@someone]" in prose must never widen the approver set. Keep this in step
# with tasks/scripts/check_maintainer_approval.py, the gate this reports on.
MAINTAINER_RE = re.compile(
    r"\[@([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)\]\(https://github\.com/"
)


def parse_maintainers(markdown: str) -> set[str]:
    """Return the lowercased GitHub logins listed in a MAINTAINERS.md table."""
    return {match.group(1).lower() for match in MAINTAINER_RE.finditer(markdown)}


def format_delta(marker: str, before: str, after: str) -> str:
    """Render a review comment, or an empty string when nothing changed."""
    old, new = parse_maintainers(before), parse_maintainers(after)
    added, removed = sorted(new - old), sorted(old - new)
    if not added and not removed:
        return ""

    lines = [marker, "## Maintainer list change", ""]
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
        "satisfy `OpenShell / Maintainer Approval`."
    )

    if not new:
        lines += [
            "",
            "> [!WARNING]",
            "> No logins parse from the updated file. Merging this would make the "
            "approval gate fail closed on every pull request.",
        ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--before", required=True, type=Path, help="MAINTAINERS.md at the base commit"
    )
    parser.add_argument(
        "--after", required=True, type=Path, help="MAINTAINERS.md at the head commit"
    )
    args = parser.parse_args(argv)

    marker = os.environ.get("COMMENT_MARKER")
    if not marker:
        print("COMMENT_MARKER is not set", file=sys.stderr)
        return 1

    after = args.after.read_text(encoding="utf-8")
    body = format_delta(marker, args.before.read_text(encoding="utf-8"), after)
    if body:
        print(body)

    if not parse_maintainers(after):
        print(
            "No logins parse from the updated MAINTAINERS.md; the approval gate "
            "would fail closed on every pull request.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
