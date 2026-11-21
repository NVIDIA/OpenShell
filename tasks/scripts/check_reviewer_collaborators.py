#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Validate reviewer roster accounts against repository membership and permissions."""

import argparse
import subprocess
import sys
from pathlib import Path

from check_review_readiness import _api, parse_reviewers


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--reviewers", type=Path, default=Path("REVIEWERS.md"))
    args = parser.parse_args(argv)
    try:
        categories = parse_reviewers(args.reviewers.read_text(encoding="utf-8"))
        members = set().union(*categories.values())
        collaborators = {
            member["login"].lower()
            for member in _api(
                f"repos/{args.repo}/collaborators?per_page=100&affiliation=all",
                pages=True,
            )
        }
        invalid = []
        for login in sorted(members - collaborators):
            permission = _api(f"repos/{args.repo}/collaborators/{login}/permission")[
                "permission"
            ]
            if permission in ("read", "none"):
                invalid.append(login)
            elif permission not in ("write", "admin"):
                raise ValueError(f"unexpected repository permission for {login}")
        if invalid:
            raise ValueError(
                "ineligible accounts in REVIEWERS.md: " + ", ".join(invalid)
            )
    except subprocess.CalledProcessError as exc:
        print(
            "Cannot verify reviewer access: " + (exc.stderr or str(exc)).strip(),
            file=sys.stderr,
        )
        return 1
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Reviewer roster: {exc}", file=sys.stderr)
        return 1
    print(
        f"All {len(members)} reviewer roster accounts are eligible for review requests."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
