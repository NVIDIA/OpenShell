# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for tasks/scripts/core_approval.py.

Run via `mise run test:core-approval`, which provides pytest through
`uv run --with pytest`. pytest puts this file's directory on sys.path, so the
sibling script imports directly as `core_approval`.
"""

from __future__ import annotations

import core_approval as ca

TABLE = """# Maintainers

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Derek Carr | [@derekwaynecarr](https://github.com/derekwaynecarr) | Red Hat |
| Jim Meyer | [@purp](https://github.com/purp) | NVIDIA |
| Mrunal Patel | [@mrunalp](https://github.com/mrunalp) | Red Hat |
"""


def review(login: str, state: str) -> dict:
    return {"user": {"login": login}, "state": state}


def test_parse_maintainers_extracts_linked_logins() -> None:
    assert ca.parse_maintainers(TABLE) == {"derekwaynecarr", "purp", "mrunalp"}


def test_parse_maintainers_ignores_unlinked_mentions() -> None:
    # A prose mention must not silently grant approval rights.
    prose = TABLE + "\nThanks to [@drive-by](mailto:nobody@example.com) too.\n"
    assert "drive-by" not in ca.parse_maintainers(prose)


def test_parse_maintainers_returns_empty_when_table_is_reformatted() -> None:
    assert ca.parse_maintainers("# Maintainers\n\n- derekwaynecarr\n- purp\n") == set()


def test_decide_fails_closed_on_unparseable_list() -> None:
    state, description = ca.decide("# Maintainers\n", [review("purp", "APPROVED")], "x")
    assert state == "failure"
    assert "MAINTAINERS.md" in description


def test_decide_succeeds_on_maintainer_approval() -> None:
    state, description = ca.decide(TABLE, [review("purp", "APPROVED")], "contributor")
    assert state == "success"
    assert "@purp" in description


def test_decide_fails_on_non_maintainer_approval() -> None:
    state, _ = ca.decide(TABLE, [review("outsider", "APPROVED")], "contributor")
    assert state == "failure"


def test_decide_matches_logins_case_insensitively() -> None:
    state, _ = ca.decide(TABLE, [review("PuRp", "APPROVED")], "contributor")
    assert state == "success"


def test_comment_after_approval_does_not_revoke_it() -> None:
    reviews = [review("purp", "APPROVED"), review("purp", "COMMENTED")]
    state, _ = ca.decide(TABLE, reviews, "contributor")
    assert state == "success"


def test_dismissed_review_revokes_approval() -> None:
    reviews = [review("purp", "APPROVED"), review("purp", "DISMISSED")]
    state, _ = ca.decide(TABLE, reviews, "contributor")
    assert state == "failure"


def test_changes_requested_after_approval_revokes_it() -> None:
    reviews = [review("purp", "APPROVED"), review("purp", "CHANGES_REQUESTED")]
    state, _ = ca.decide(TABLE, reviews, "contributor")
    assert state == "failure"


def test_author_cannot_satisfy_the_gate() -> None:
    state, _ = ca.decide(TABLE, [review("purp", "APPROVED")], "purp")
    assert state == "failure"


def test_another_maintainer_still_satisfies_a_maintainer_authored_pr() -> None:
    state, _ = ca.decide(TABLE, [review("mrunalp", "APPROVED")], "purp")
    assert state == "success"


def test_description_stays_within_the_github_limit() -> None:
    reviews = [
        review(login, "APPROVED") for login in ("purp", "mrunalp", "derekwaynecarr")
    ]
    _, description = ca.decide(TABLE, reviews, "contributor")
    assert len(description) <= 140


def test_format_delta_names_added_and_removed_logins() -> None:
    after = TABLE.replace(
        "| Mrunal Patel | [@mrunalp](https://github.com/mrunalp) | Red Hat |\n",
        "| New Person | [@newbie](https://github.com/newbie) | NVIDIA |\n",
    )
    body = ca.format_delta(TABLE, after)
    assert "@newbie" in body
    assert "@mrunalp" in body


def test_format_delta_reports_no_change_when_only_prose_moves() -> None:
    body = ca.format_delta(TABLE, TABLE + "\nSee also CONTRIBUTING.md.\n")
    assert "does not change" in body


def test_format_delta_warns_when_the_result_parses_empty() -> None:
    body = ca.format_delta(TABLE, "# Maintainers\n\n- purp\n")
    assert "WARNING" in body
