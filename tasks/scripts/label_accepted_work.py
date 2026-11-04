#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reconcile the informational state:accepted label on open PRs.

Read trusted MAINTAINERS.md and GitHub metadata, never code from a PR head.
Preview with --repo OWNER/REPO and --pr NUMBER or --all-open; add --apply to label.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote

from check_maintainer_approval import parse_maintainers

ACCEPTED = "state:accepted"
CLOSING_ISSUES = """
query($owner: String!, $repo: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      closingIssuesReferences(first: 100, after: $cursor) {
        nodes { number repository { nameWithOwner } }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
"""


def _api(path: str, *, method="GET", data=None, pages=False):
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


class AcceptedWork:
    """Evaluate current PR authors and issue relationships; cache within a run."""

    def __init__(self, repository: str, maintainers: set[str]):
        if not maintainers:
            raise ValueError("Could not parse any maintainers from MAINTAINERS.md")
        self.repository = repository
        self.maintainers = {login.lower() for login in maintainers}
        self.permissions: dict[str, bool] = {}
        self.issues: dict[int, dict] = {}

    def privileged(self, author: str) -> bool:
        if author in self.maintainers:
            return True
        if author not in self.permissions:
            try:
                value = _api(
                    f"repos/{self.repository}/collaborators/"
                    f"{quote(author, safe='')}/permission"
                )
            except subprocess.CalledProcessError as exc:
                # GitHub returns 404 for users who are not collaborators.
                # Other errors must stop reconciliation, not revoke acceptance.
                if "(HTTP 404)" not in (exc.stderr or ""):
                    raise
                value = {"permission": "none"}
            self.permissions[author] = value["permission"] in {
                "write",
                "maintain",
                "admin",
            }
        return self.permissions[author]

    def closing_issues(self, number: int):
        owner, repo = self.repository.split("/")
        cursor = None
        while True:
            value = _api(
                "graphql",
                method="POST",
                data={
                    "query": CLOSING_ISSUES,
                    "variables": {
                        "owner": owner,
                        "repo": repo,
                        "number": number,
                        "cursor": cursor,
                    },
                },
            )
            if value.get("errors"):
                raise ValueError("GitHub could not resolve closing issues")
            pull = value["data"]["repository"]["pullRequest"]
            connection = pull["closingIssuesReferences"]
            yield from connection["nodes"]
            if not connection["pageInfo"]["hasNextPage"]:
                return
            cursor = connection["pageInfo"]["endCursor"]
            if not cursor:
                raise ValueError("GitHub returned a missing closing-issue cursor")

    def accepted(self, pr: dict) -> bool:
        author = pr["user"]["login"].lower()
        if self.privileged(author):
            return True
        for reference in self.closing_issues(pr["number"]):
            repository = reference["repository"]["nameWithOwner"]
            if repository.lower() != self.repository.lower():
                continue
            number = reference["number"]
            if number not in self.issues:
                root = f"repos/{self.repository}/issues/{number}"
                issue = _api(root)
                issue["labels"] = _api(f"{root}/labels?per_page=100", pages=True)
                self.issues[number] = issue
            issue = self.issues[number]
            if "pull_request" in issue:
                continue
            participants = {
                user["login"].lower()
                for user in [issue["user"], *issue["assignees"]]
                if user
            }
            if author in participants and any(
                label["name"] == ACCEPTED for label in issue["labels"]
            ):
                return True
        return False

    def reconcile(self, prs: list[dict], *, apply=False) -> list[dict]:
        # Resolve all reads before mutations, so lookup failures leave labels alone.
        plans = []
        for pr in prs:
            if pr["state"] != "open":
                continue
            accepted = self.accepted(pr)
            labeled = any(label["name"] == ACCEPTED for label in pr["labels"])
            action = "none" if accepted == labeled else "add" if accepted else "remove"
            plans.append(
                {"number": pr["number"], "accepted": accepted, "action": action}
            )
        if apply:
            for plan in plans:
                root = f"repos/{self.repository}/issues/{plan['number']}/labels"
                if plan["action"] == "add":
                    _api(root, method="POST", data={"labels": [ACCEPTED]})
                elif plan["action"] == "remove":
                    _api(f"{root}/{quote(ACCEPTED, safe='')}", method="DELETE")
        return plans


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--maintainers", type=Path, default=Path("MAINTAINERS.md"))
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--pr", type=int)
    target.add_argument("--all-open", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
        parser.error("--repo must be OWNER/REPO")
    if args.pr is not None and args.pr <= 0:
        parser.error("--pr must be positive")
    try:
        evaluator = AcceptedWork(
            args.repo, parse_maintainers(args.maintainers.read_text(encoding="utf-8"))
        )
        root = f"repos/{args.repo}/pulls"
        prs = (
            [_api(f"{root}/{args.pr}")]
            if args.pr is not None
            else _api(f"{root}?state=open&per_page=100", pages=True)
        )
        print(json.dumps(evaluator.reconcile(prs, apply=args.apply)))
    except (
        OSError,
        UnicodeError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.CalledProcessError,
    ) as exc:
        print(f"Accepted work: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
