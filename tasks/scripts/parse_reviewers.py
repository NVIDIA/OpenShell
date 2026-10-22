#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Validate REVIEWERS.md and emit its categories and members as JSON.

This dependency-free parser reads the documented registry format, not arbitrary
Markdown. It performs no GitHub requests and assigns no roles or review rights.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
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
                    number, "only one contiguous membership table is allowed per category"
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reviewers", type=Path, default=Path("REVIEWERS.md"))
    parser.add_argument(
        "--check", action="store_true", help="validate without emitting JSON"
    )
    args = parser.parse_args(argv)
    try:
        categories = parse_reviewers(args.reviewers.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, RegistryError) as exc:
        print(f"{args.reviewers}: {exc}", file=sys.stderr)
        return 1
    if args.check:
        count = sum(len(category.members) for category in categories)
        print(f"Validated {len(categories)} categories and {count} memberships")
    else:
        print(
            json.dumps(
                {"schema_version": 1, "categories": [asdict(c) for c in categories]},
                indent=2,
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
