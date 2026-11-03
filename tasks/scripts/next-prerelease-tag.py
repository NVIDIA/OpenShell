#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Choose the next candidate in the checked-out branch's seeded prerelease series."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def next_tag(*, scheduled: bool = False) -> str:
    versions = {}
    for tag in git("tag", "--merged", "HEAD", "--list", "v*").splitlines():
        match = re.fullmatch(
            r"v([0-9]+)\.([0-9]+)\.([0-9]+)(?:-pre\.([1-9][0-9]*))?", tag
        )
        if match:
            versions[tag] = (
                *map(int, match.groups()[:3]),
                match[4] is None,
                int(match[4] or 0),
            )
    if not versions:
        raise ValueError(
            "No release series on this branch; create a vMAJOR.MINOR.PATCH-pre.1 seed"
        )
    latest = max(versions, key=versions.__getitem__)
    base, separator, _ = latest.partition("-pre.")
    if not separator or git("tag", "--list", base):
        raise ValueError(
            f"{base} is already stable; seed the next prerelease version explicitly"
        )
    if f"{base}-pre.1" not in versions:
        raise ValueError(f"No {base}-pre.1 seed is reachable from this branch")
    if scheduled and git("rev-list", f"{latest}..HEAD", "--count") == "0":
        return ""

    # Tag names are repository-wide even when branches share the same series.
    numbers = [
        int(tag.rsplit(".", 1)[1])
        for tag in git("tag", "--list", f"{base}-pre.*").splitlines()
        if re.fullmatch(re.escape(base) + r"-pre\.[1-9][0-9]*", tag)
    ]
    return f"{base}-pre.{max(numbers) + 1}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scheduled",
        action="store_true",
        help="Skip inactive series and unchanged commits",
    )
    args = parser.parse_args()
    try:
        tag = next_tag(scheduled=args.scheduled)
    except ValueError as error:
        if not args.scheduled:
            parser.error(str(error))
        print(error, file=sys.stderr)
        return
    if tag:
        print(tag)


if __name__ == "__main__":
    main()
