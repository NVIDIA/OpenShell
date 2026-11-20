#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Enforce commit signing and reject agent attribution on a pull request.

Signing applies to commits whose author has write or admin access to the
repository. External contributors and bots are exempt. Attribution applies to
every commit message, the PR title, and the PR body.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from typing import TYPE_CHECKING

from check_review_readiness import _api

if TYPE_CHECKING:
    from collections.abc import Callable

AGENT = re.compile(
    r"\b(?:claude|anthropic|copilot|codex|cursor|gemini|chatgpt|openai|devin|aider)\b",
    re.IGNORECASE,
)
CO_AUTHOR = re.compile(r"^[ \t]*co-authored-by:(.*)$", re.IGNORECASE | re.MULTILINE)
GENERATED = re.compile(r"^.*\bgenerated (?:with|by)\b.*$", re.IGNORECASE | re.MULTILINE)
SIGNING_PERMISSIONS = {"write", "admin"}


def attribution_problems(text: str) -> list[str]:
    """Name each kind of agent attribution found in `text`."""
    problems = []
    if any(AGENT.search(match.group(1)) for match in CO_AUTHOR.finditer(text)):
        problems.append("Co-authored-by trailer names an AI agent; see AGENTS.md")
    if any(AGENT.search(match.group(0)) for match in GENERATED.finditer(text)):
        problems.append("'Generated with' footer names an AI agent; see AGENTS.md")
    return problems


def _is_bot(author: dict) -> bool:
    return author.get("type") == "Bot" or str(author.get("login", "")).endswith("[bot]")


def signing_problem(commit: dict, permission_of: Callable[[str], str]) -> str | None:
    """Return why `commit` violates the signing rule, or None if it complies."""
    author = commit.get("author") or {}
    login = author.get("login")
    if not login or _is_bot(author):
        return None
    verification = commit["commit"].get("verification") or {}
    if verification.get("verified"):
        return None
    if permission_of(login) not in SIGNING_PERMISSIONS:
        return None
    reason = verification.get("reason", "unknown")
    return (
        f"not cryptographically signed (GitHub reports: {reason}); "
        "see CI.md#commit-signing"
    )


def find_problems(
    pull: dict, commits: list[dict], permission_of: Callable[[str], str]
) -> list[str]:
    """Return one line per violation across the PR text and its commits."""
    problems = []
    for label, text in (("PR title", pull.get("title")), ("PR body", pull.get("body"))):
        problems += [f"{label}: {p}" for p in attribution_problems(text or "")]
    for commit in commits:
        sha = commit["sha"][:9]
        problem = signing_problem(commit, permission_of)
        if problem:
            problems.append(f"{sha}  {problem}")
        message = commit["commit"].get("message", "")
        problems += [f"{sha}  {p}" for p in attribution_problems(message)]
    return problems


def _permission(repo: str, login: str) -> str:
    try:
        return _api(f"repos/{repo}/collaborators/{login}/permission")["permission"]
    except subprocess.CalledProcessError as exc:
        if "404" in (exc.stderr or ""):
            return "none"
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", required=True, type=int)
    args = parser.parse_args(argv)
    cache: dict[str, str] = {}

    def permission_of(login: str) -> str:
        key = login.lower()
        if key not in cache:
            cache[key] = _permission(args.repo, login)
        return cache[key]

    try:
        pull = _api(f"repos/{args.repo}/pulls/{args.pr}")
        commits = _api(
            f"repos/{args.repo}/pulls/{args.pr}/commits?per_page=100", pages=True
        )
        problems = find_problems(pull, commits, permission_of)
    except subprocess.CalledProcessError as exc:
        print(
            "Cannot verify commit policy: " + (exc.stderr or str(exc)).strip(),
            file=sys.stderr,
        )
        return 1
    except (KeyError, TypeError, ValueError) as exc:
        print(f"Commit policy: unexpected GitHub response: {exc}", file=sys.stderr)
        return 1
    if problems:
        print(f"Commit Policy: {len(problems)} problem(s)", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(f"All {len(commits)} commits and the PR text meet the commit policy.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
