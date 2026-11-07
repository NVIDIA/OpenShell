# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shared accepted-work classification; see CONTRIBUTING.md#accepted-work.

Use is_accepted_work with supplied facts, or check_pr_accepted_work and
check_issue_accepted_work with a GitHub API callable. These accept the same
path/method/data/pages arguments
as check_review_readiness._api. Both return a bool; API errors propagate.
This library has no CLI, label writes, or workflow lifecycle of its own.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import quote

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator

ACCEPTED_LABEL = "state:accepted"
WRITE_PERMISSIONS = frozenset({"write", "maintain", "admin"})
CLOSING_ISSUES_QUERY = """
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


@dataclass(frozen=True)
class ClosingIssue:
    """Facts about an issue GitHub reports that the PR closes."""

    repository: str
    accepted: bool
    author: str | None
    assignees: frozenset[str] = frozenset()


def is_accepted_work(
    author: str,
    *,
    repository: str,
    maintainers: set[str],
    permission: str,
    closing_issues: Iterable[ClosingIssue] = (),
) -> bool:
    """Classify supplied facts without IO; the triggering actor is irrelevant."""
    author = author.lower()
    if author in {login.lower() for login in maintainers}:
        return True
    if permission in WRITE_PERMISSIONS:
        return True
    for issue in closing_issues:
        if issue.repository.lower() != repository.lower() or not issue.accepted:
            continue
        participants = {login.lower() for login in issue.assignees}
        if issue.author:
            participants.add(issue.author.lower())
        if author in participants:
            return True
    return False


def _closing_issue_facts(
    repository: str, number: int, api: Callable
) -> Iterator[ClosingIssue]:
    owner, repo = repository.split("/")
    cursor = None
    while True:
        result = api(
            "graphql",
            method="POST",
            data={
                "query": CLOSING_ISSUES_QUERY,
                "variables": {
                    "owner": owner,
                    "repo": repo,
                    "number": number,
                    "cursor": cursor,
                },
            },
        )
        if result.get("errors"):
            raise ValueError("GitHub could not resolve closing issues")
        pull = result["data"]["repository"]["pullRequest"]
        connection = pull["closingIssuesReferences"]
        for reference in connection["nodes"]:
            source = reference["repository"]["nameWithOwner"]
            if source.lower() != repository.lower():
                continue
            root = f"repos/{repository}/issues/{reference['number']}"
            issue = api(root)
            if "pull_request" in issue:
                continue
            labels = api(f"{root}/labels?per_page=100", pages=True)
            yield ClosingIssue(
                repository=source,
                accepted=any(label["name"] == ACCEPTED_LABEL for label in labels),
                author=issue["user"]["login"] if issue["user"] else None,
                assignees=frozenset(user["login"] for user in issue["assignees"]),
            )
        if not connection["pageInfo"]["hasNextPage"]:
            return
        next_cursor = connection["pageInfo"]["endCursor"]
        if not next_cursor or next_cursor == cursor:
            raise ValueError("GitHub returned an invalid closing-issue cursor")
        cursor = next_cursor


def check_pr_accepted_work(
    repository: str, pr: dict, maintainers: set[str], *, api: Callable
) -> bool:
    """Load current facts using a read-only API callable and classify this PR.

    Callers supply maintainer membership from a trusted merged roster. A 404
    collaborator lookup means no repository access; other lookup errors propagate.
    Maintainer and write-access authors need no closing-issue lookup.
    """
    if not maintainers:
        raise ValueError("Could not parse any maintainers from MAINTAINERS.md")
    author = pr["user"]["login"]
    permission = "none"
    if author.lower() not in {login.lower() for login in maintainers}:
        try:
            result = api(
                f"repos/{repository}/collaborators/{quote(author, safe='')}/permission"
            )
            permission = result["permission"]
        except subprocess.CalledProcessError as exc:
            if "(HTTP 404)" not in (exc.stderr or ""):
                raise
    return is_accepted_work(
        author,
        repository=repository,
        maintainers=maintainers,
        permission=permission,
        closing_issues=_closing_issue_facts(repository, pr["number"], api),
    )


def check_issue_accepted_work(repository: str, issue: dict, maintainers: set[str], *, api: Callable) -> bool:
    """Check recorded acceptance or the issue author's trusted authority."""
    if "pull_request" in issue:
        raise ValueError("Use the PR adapter for pull requests")
    if not maintainers:
        raise ValueError("Could not parse any maintainers from MAINTAINERS.md")
    labels = api(f"repos/{repository}/issues/{issue['number']}/labels?per_page=100", pages=True)
    if any(label['name'] == ACCEPTED_LABEL for label in labels):
        return True
    author = issue['user']['login']
    if author.lower() in {login.lower() for login in maintainers}:
        return True
    try:
        permission = api(f"repos/{repository}/collaborators/{quote(author, safe='')}/permission")['permission']
    except subprocess.CalledProcessError as exc:
        if '(HTTP 404)' not in (exc.stderr or ''):
            raise
        permission = 'none'
    return permission in WRITE_PERMISSIONS
