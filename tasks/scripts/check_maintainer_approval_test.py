# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for tasks/scripts/check_maintainer_approval.py.

Run via `mise run test:maintainer-approval`, which provides pytest through
`uv run --with pytest`. pytest puts this file's directory on sys.path, so the
sibling script imports directly.
"""

from __future__ import annotations

import json

import check_maintainer_approval as gate

TABLE = """# Maintainers

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Derek Carr | [@derekwaynecarr](https://github.com/derekwaynecarr) | Red Hat |
| Evan Lezar | [@elezar](https://github.com/elezar) | NVIDIA |
| Piotr Mlocek | [@pimlock](https://github.com/pimlock) | NVIDIA |
"""


def review(login: str, state: str) -> dict:
    return {"user": {"login": login}, "state": state}


def run(tmp_path, table: str, reviews: list[dict]) -> int:
    maintainers = tmp_path / "MAINTAINERS.md"
    maintainers.write_text(table, encoding="utf-8")
    reviews_file = tmp_path / "reviews.json"
    reviews_file.write_text(json.dumps(reviews), encoding="utf-8")
    return gate.main(
        ["--maintainers", str(maintainers), "--reviews", str(reviews_file)]
    )


def test_parse_maintainers_extracts_linked_logins() -> None:
    assert gate.parse_maintainers(TABLE) == {"derekwaynecarr", "elezar", "pimlock"}


def test_parse_maintainers_ignores_unlinked_mentions() -> None:
    # A prose mention must not silently grant approval rights.
    prose = TABLE + "\nThanks to [@drive-by](mailto:nobody@example.com) too.\n"
    assert "drive-by" not in gate.parse_maintainers(prose)


def test_comment_after_approval_does_not_revoke_it() -> None:
    reviews = [review("elezar", "APPROVED"), review("elezar", "COMMENTED")]
    assert gate.parse_reviews_to_approvers(reviews) == {"elezar"}


def test_dismissed_review_revokes_approval() -> None:
    reviews = [review("elezar", "APPROVED"), review("elezar", "DISMISSED")]
    assert gate.parse_reviews_to_approvers(reviews) == set()


def test_changes_requested_after_approval_revokes_it() -> None:
    reviews = [review("elezar", "APPROVED"), review("elezar", "CHANGES_REQUESTED")]
    assert gate.parse_reviews_to_approvers(reviews) == set()


def test_out_of_order_reviews_still_respect_the_latest_position() -> None:
    # Ordering comes from the review id, not the order the caller happened
    # to assemble the pages in.
    reviews = [
        {"id": 2, "user": {"login": "elezar"}, "state": "DISMISSED"},
        {"id": 1, "user": {"login": "elezar"}, "state": "APPROVED"},
    ]
    assert gate.parse_reviews_to_approvers(reviews) == set()


def test_exits_zero_when_a_maintainer_approved(tmp_path) -> None:
    assert run(tmp_path, TABLE, [review("pimlock", "APPROVED")]) == 0


def test_matches_logins_case_insensitively(tmp_path) -> None:
    assert run(tmp_path, TABLE, [review("PiMlOcK", "APPROVED")]) == 0


def test_exits_nonzero_with_no_reviews(tmp_path) -> None:
    # The exit code is the check result, so this is the gate's actual contract.
    assert run(tmp_path, TABLE, []) != 0


def test_exits_nonzero_on_non_maintainer_approval(tmp_path) -> None:
    assert run(tmp_path, TABLE, [review("outsider", "APPROVED")]) != 0


def test_fails_closed_on_unparseable_list(tmp_path) -> None:
    assert run(tmp_path, "# Maintainers\n", [review("pimlock", "APPROVED")]) != 0
