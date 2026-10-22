#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Check PR review readiness and reconcile area/topic reviewer requests.

The registry parser is importable by other tools. Repository roles and review
engagement are inputs to routing, rather than fields in REVIEWERS.md.

Preview with --repo OWNER/REPO --pr NUMBER. Add --apply to synchronize requests.
Each run reads the PR's current requests, request/removal timeline, comments,
and reviews. Human choices and engaged reviewers are preserved; other requests
follow the current area/topic labels. Requests with unknown provenance are
preserved too. No state is stored between runs. Serialize updates for each PR.
Both ready-for-review and label-change callers use the same reconciliation.

Read this helper and REVIEWERS.md from a trusted merged ref. The CLI uses gh
authentication, checks current write access, and paginates all engagement feeds.
It does not install a workflow, post comments, or change approval requirements.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, replace
from pathlib import Path

HEADER = ("Name", "GitHub ID", "Company/Organization")
LABEL = re.compile(r"(?:area|topic):[a-z0-9]+(?:-[a-z0-9]+)*")
PROFILE = re.compile(
    r"\[@([a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?)\]"
    r"\(https://github\.com/([a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?)/?\)",
    re.IGNORECASE,
)


class RegistryError(ValueError):
    """The source does not satisfy the registry format."""


@dataclass(frozen=True)
class Member:
    name: str
    login: str
    organization: str


@dataclass(frozen=True)
class Category:
    label: str
    description: str
    members: tuple[Member, ...]


class ReadinessError(ValueError):
    """The PR or reconciliation state cannot safely produce review requests."""


@dataclass(frozen=True)
class ReviewPlan:
    ready: bool
    reason: str
    selected: tuple[str, ...] = ()
    add: tuple[str, ...] = ()
    remove: tuple[str, ...] = ()
    keep: tuple[str, ...] = ()
    engaged: tuple[str, ...] = ()
    manual: tuple[str, ...] = ()
    ineligible: tuple[str, ...] = ()


def _error(line: int, message: str) -> RegistryError:
    return RegistryError(f"line {line}: {message}")


def _visible_lines(markdown: str):
    """Ignore comments and code examples without treating their links as members."""
    fence = None
    comment = False
    last_line = 1
    for number, raw in enumerate(markdown.splitlines(), 1):
        last_line = number
        if fence:
            closing = r" {0,3}" + re.escape(fence[0]) + "{" + str(len(fence)) + r",}\s*"
            if re.fullmatch(closing, raw):
                fence = None
            continue
        visible = ""
        remaining = raw
        while remaining:
            if comment:
                _, closing, remaining = remaining.partition("-->")
                if not closing:
                    break
                comment = False
            else:
                before, opening, remaining = remaining.partition("<!--")
                visible += before
                if not opening:
                    break
                comment = True
        if raw.strip() and not visible.strip():
            continue
        opening = re.match(r"^ {0,3}(`{3,}|~{3,})", visible)
        if opening:
            fence = opening[1]
            continue
        if not visible.startswith(("    ", "\t")):
            yield number, visible.strip()
    if fence or comment:
        raise _error(last_line, "unterminated code fence or HTML comment")


def _cells(line: str, number: int) -> tuple[str, ...]:
    if not line.endswith("|"):
        raise _error(number, "table rows must have leading and trailing pipes")
    cells, current = [], ""
    inner = iter(line[1:-1])
    for char in inner:
        if char == "\\":
            following = next(inner, "")
            current += following if following in {"|", "\\"} else char + following
        elif char == "|":
            cells.append(current.strip())
            current = ""
        else:
            current += char
    cells.append(current.strip())
    if len(cells) != len(HEADER):
        raise _error(number, "expected exactly three membership columns")
    return tuple(cells)


def parse_reviewers(markdown: str) -> tuple[Category, ...]:
    """Parse category tables, preserving their order and lowercasing logins.

    Explicit empty tables are valid. Missing tables, duplicate labels/members,
    mismatched profile links, and malformed rows raise RegistryError. Repeating
    a person across different categories is expected and remains valid.
    """
    categories = []
    labels, groups, logins = set(), set(), set()
    group = None
    label = None
    description, members = [], []
    start = 1
    table = 0  # 0: absent; 1: header; 2: rows; 3: closed

    def finish():
        if label is None:
            return
        if table < 2:
            raise _error(start, f"{label} needs a membership table and separator")
        summary = "\n".join(description).strip()
        if not summary:
            raise _error(start, f"{label} needs a scope description")
        categories.append(Category(label, summary, tuple(members)))

    for number, line in _visible_lines(markdown):
        heading = re.fullmatch(r"(#{1,3})\s+(.+?)(?:\s+#+)?", line)
        if heading:
            level, title = len(heading[1]), heading[2]
            finish()
            label = None
            if level <= 2:
                group = (
                    {"Areas": "area", "Topics": "topic"}.get(title)
                    if level == 2
                    else None
                )
                if group:
                    if group in groups:
                        raise _error(number, f"duplicate {title} section")
                    groups.add(group)
                continue
            if group is None:
                if LABEL.fullmatch(title):
                    raise _error(number, "category must be under Areas or Topics")
                continue
            if not LABEL.fullmatch(title) or title.split(":")[0] != group:
                raise _error(number, f"expected a {group}: category heading")
            if title in labels:
                raise _error(number, f"duplicate category {title}")
            labels.add(title)
            label, start = title, number
            description, members, logins, table = [], [], set(), 0
            continue
        if label is None:
            continue
        if table == 1:
            cells = _cells(line, number) if line.startswith("|") else ()
            if len(cells) != 3 or not all(
                re.fullmatch(r":?-{3,}:?", cell) for cell in cells
            ):
                raise _error(number, "membership header needs a three-column separator")
            table = 2
            continue
        if line.startswith("|"):
            cells = _cells(line, number)
            if table == 0:
                if cells != HEADER:
                    raise _error(
                        number, f"expected membership header: {' | '.join(HEADER)}"
                    )
                table = 1
                continue
            if table == 3:
                raise _error(
                    number,
                    "only one contiguous membership table is allowed per category",
                )
            name, profile, organization = cells
            match = PROFILE.fullmatch(profile)
            if not match or match[1].lower() != match[2].lower():
                raise _error(
                    number, "GitHub ID must link @login to the same GitHub profile"
                )
            if not name or not organization:
                raise _error(number, "member name and organization must be nonempty")
            login = match[1].lower()
            if login in logins:
                raise _error(number, f"duplicate member @{login} in {label}")
            logins.add(login)
            members.append(Member(name, login, organization))
        else:
            if table >= 2 and "|" in line:
                raise _error(number, "membership rows must start with a pipe")
            if table == 2:
                table = 3
            if table == 0:
                description.append(line)
    finish()
    if not categories:
        raise RegistryError("no area/topic membership tables found")
    return tuple(categories)


def select_reviewers(categories: tuple[Category, ...], labels: set[str]) -> set[str]:
    """Return the deduplicated union for one primary area and its topics."""
    areas = {label for label in labels if label.startswith("area:")}
    if len(areas) != 1:
        raise ReadinessError("a ready PR must have exactly one area label")
    relevant = {label for label in labels if label.startswith(("area:", "topic:"))}
    by_label = {category.label: category for category in categories}
    unknown = relevant - by_label.keys()
    if unknown:
        raise ReadinessError("unknown area/topic labels: " + ", ".join(sorted(unknown)))
    return {member.login for label in relevant for member in by_label[label].members}


def engaged_reviewers(*feeds: list[dict]) -> set[str]:
    """Protect authors of any review, general comment, or inline comment.

    Review state is deliberately irrelevant, including dismissed reviews. A
    person has engaged even if they have not approved or their review is stale.
    """
    return {
        entry["user"]["login"].lower()
        for feed in feeds
        for entry in feed
        if (entry.get("user") or {}).get("login")
    }


def manual_reviewers(events: list[dict], requested: set[str]) -> set[str]:
    """Reconstruct human choices from a complete review-request timeline.

    Bot actors identify automated changes. A human request stays protected
    through repeated requests until it is removed. Human removals also stay
    protected, so a later label change does not immediately re-request them.
    Unknown actors and current requests with missing history are preserved.
    Team events do not affect individual requests.
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
    categories: tuple[Category, ...],
    *,
    pull_request: dict,
    requested: set[str],
    engaged: set[str],
    eligible: set[str],
    manual: set[str],
) -> ReviewPlan:
    """Compute requests without IO; callers supply complete, current snapshots.

    Select all eligible matching members except the author. Never re-request
    participants or change a manually managed or engaged reviewer's state.
    Other pending requests follow the current label selection.
    """
    requested = {login.lower() for login in requested}
    engaged = {login.lower() for login in engaged}
    manual = {login.lower() for login in manual}
    if pull_request.get("state") != "open" or pull_request.get("draft", False):
        return ReviewPlan(False, "PR is closed or draft", keep=tuple(sorted(requested)))
    author = pull_request["user"]["login"].lower()
    labels = {label["name"] for label in pull_request["labels"]}
    matched = select_reviewers(categories, labels) - {author}
    selected = matched & {login.lower() for login in eligible}
    area = next(label for label in labels if label.startswith("area:"))
    area_members = {
        member.login
        for category in categories
        if category.label == area
        for member in category.members
    }
    if not selected & area_members:
        raise ReadinessError("primary area has no eligible non-author reviewer")
    add = selected - requested - engaged - manual
    remove = requested - selected - engaged - manual
    keep = requested - remove
    return ReviewPlan(
        True,
        "PR is ready for review routing",
        tuple(sorted(selected)),
        tuple(sorted(add)),
        tuple(sorted(remove)),
        tuple(sorted(keep)),
        tuple(sorted(engaged)),
        tuple(sorted(manual)),
        tuple(sorted(matched - selected)),
    )


def _api(
    path: str,
    *,
    method: str = "GET",
    data=None,
    pages: bool = False,
    collection: str | None = None,
):
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
    if pages:
        return [
            item for page in value for item in (page[collection] if collection else page)
        ]
    return value


def _load_context(repository: str, number: int) -> dict:
    root = f"repos/{repository}"
    pull = f"{root}/pulls/{number}"
    pr = _api(pull)
    request_pages = _api(
        f"{pull}/requested_reviewers?per_page=100", pages=True, collection="users"
    )
    reviews = _api(f"{pull}/reviews?per_page=100", pages=True)
    comments = _api(f"{root}/issues/{number}/comments?per_page=100", pages=True)
    inline = _api(f"{pull}/comments?per_page=100", pages=True)
    timeline = _api(f"{root}/issues/{number}/timeline?per_page=100", pages=True)
    requested = {user["login"].lower() for user in request_pages}
    return {
        "pull_request": pr,
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


def _routing_identity(context: dict):
    pr = context["pull_request"]
    return (
        pr["state"],
        pr["draft"],
        pr["user"]["login"].lower(),
        pr["head"]["sha"],
        sorted(label["name"] for label in pr["labels"]),
    )


def _apply_plan(
    *,
    repository: str,
    number: int,
    context: dict,
    categories: tuple[Category, ...],
    eligible: set[str],
) -> ReviewPlan:
    """Refresh metadata before changes, including human choices before removals."""
    fresh = _load_context(repository, number)
    if _routing_identity(fresh) != _routing_identity(context):
        raise ReadinessError("PR changed while planning; rerun before updating requests")
    plan = plan_review_requests(categories, **fresh, eligible=eligible)
    if not plan.ready:
        return plan
    endpoint = f"repos/{repository}/pulls/{number}/requested_reviewers"
    if plan.add:
        _api(endpoint, method="POST", data={"reviewers": list(plan.add)})
    latest = _load_context(repository, number)
    if _routing_identity(latest) != _routing_identity(context):
        raise ReadinessError("PR changed after additions; rerun reconciliation")
    latest_plan = plan_review_requests(categories, **latest, eligible=eligible)
    remove = set(latest_plan.remove)
    if remove:
        _api(endpoint, method="DELETE", data={"reviewers": sorted(remove)})
    remaining = latest["requested"] - remove
    return replace(
        latest_plan,
        add=plan.add,
        keep=tuple(sorted(remaining)),
    )


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
        context = _load_context(args.repo, args.pr)
        pr = context["pull_request"]
        selected = (
            select_reviewers(categories, {label["name"] for label in pr["labels"]})
            - {pr["user"]["login"].lower()}
            if pr["state"] == "open" and not pr["draft"]
            else set()
        )
        eligible = _eligible_reviewers(args.repo, selected)
        plan = plan_review_requests(categories, **context, eligible=eligible)
        if args.apply and plan.ready:
            plan = _apply_plan(
                repository=args.repo,
                number=args.pr,
                context=context,
                categories=categories,
                eligible=eligible,
            )
    except (OSError, UnicodeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Review readiness: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {"repository": args.repo, "pull_number": args.pr, **asdict(plan)}, indent=2
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
