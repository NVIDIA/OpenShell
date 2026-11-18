# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Select explicit acceptance and authorized human labeling-agent invocations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
COMMENT_COMMAND = re.compile(r"/label-issue(?:[ \t]+(force|--force))?")
HUMAN_PERMISSIONS = {"write", "maintain", "admin"}


@dataclass(frozen=True)
class Invocation:
    repository: str
    number: int
    force: bool
    source: str


def positive_number(value, message: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(message)
    return value


def item_number(item: str, repository: str) -> int:
    """Resolve one number or same-repository issue/PR URL without network access."""
    if not REPOSITORY.fullmatch(repository):
        raise ValueError("expected an OWNER/REPO repository")
    if re.fullmatch(r"[1-9][0-9]*", item):
        return int(item)
    url = urlsplit(item)
    if url.scheme != "https" or url.netloc != "github.com" or url.query or url.fragment:
        raise ValueError("expected an item number or a same-repository GitHub URL")
    match = re.fullmatch(r"/([^/]+/[^/]+)/(?:issues|pull)/([1-9][0-9]*)/?", url.path)
    if not match or match[1].casefold() != repository.casefold():
        raise ValueError("item must belong to the configured repository")
    return int(match[2])


def select_invocation(
    event_name: str,
    event: dict,
    repository: str,
    *,
    permission,
) -> Invocation | None:
    """Route events only; the shared preflight must still verify current eligibility.

    permission(login) returns the live repository permission or raises on lookup
    failure. An event payload's author association is not an authorization check.
    """
    if not REPOSITORY.fullmatch(repository):
        raise ValueError("expected an OWNER/REPO repository")
    actual_repository = (event.get("repository") or {}).get("full_name", "")
    if actual_repository.casefold() != repository.casefold():
        raise ValueError("event repository does not match the configured repository")
    if (
        event_name in {"issues", "pull_request_target"}
        and event.get("action") == "labeled"
        and (event.get("label") or {}).get("name") == "state:accepted"
    ):
        item = event.get("issue" if event_name == "issues" else "pull_request") or {}
        number = positive_number(
            item.get("number"), "acceptance event has no valid item number"
        )
        return Invocation(repository, number, False, "acceptance")
    if event_name not in {"issue_comment", "workflow_dispatch"}:
        return None
    sender = event.get("sender") or {}
    login = sender.get("login")
    if sender.get("type") != "User" or not isinstance(login, str) or not login:
        return None
    if event_name == "issue_comment":
        comment = event.get("comment") or {}
        author = comment.get("user") or {}
        issue = event.get("issue") or {}
        if (
            event.get("action") != "created"
            or not issue.get("pull_request")
            or author.get("type") != "User"
            or author.get("login") != login
        ):
            return None
        command = COMMENT_COMMAND.fullmatch((comment.get("body") or "").strip())
        if not command:
            return None
        number = positive_number(
            issue.get("number"), "comment event has no valid PR number"
        )
        force = command[1] is not None
    else:
        inputs = event.get("inputs") or {}
        number = item_number(str(inputs.get("item", "")), repository)
        force_input = inputs.get("force", False)
        if not (
            isinstance(force_input, bool)
            or (isinstance(force_input, str) and force_input in {"true", "false"})
        ):
            raise ValueError("force must be true or false")
        force = force_input is True or force_input == "true"
    if permission(login) not in HUMAN_PERMISSIONS:
        return None
    return Invocation(repository, number, force, "human")
