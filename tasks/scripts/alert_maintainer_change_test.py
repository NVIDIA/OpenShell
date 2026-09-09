# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for tasks/scripts/alert_maintainer_change.py.

Run via `mise run test:maintainer-approval`, which provides pytest through
`uv run --with pytest`. pytest puts this file's directory on sys.path, so the
sibling script imports directly.
"""

from __future__ import annotations

import alert_maintainer_change as alert

TABLE = """# Maintainers

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Derek Carr | [@derekwaynecarr](https://github.com/derekwaynecarr) | Red Hat |
| Evan Lezar | [@elezar](https://github.com/elezar) | NVIDIA |
| Piotr Mlocek | [@pimlock](https://github.com/pimlock) | NVIDIA |
"""


def test_parse_maintainers_extracts_linked_logins() -> None:
    assert alert.parse_maintainers(TABLE) == {"derekwaynecarr", "elezar", "pimlock"}


def test_names_added_and_removed_logins() -> None:
    after = TABLE.replace(
        "| Piotr Mlocek | [@pimlock](https://github.com/pimlock) | NVIDIA |\n",
        "| New Person | [@newbie](https://github.com/newbie) | NVIDIA |\n",
    )
    body = alert.format_delta(TABLE, after)
    assert "@newbie" in body
    assert "@pimlock" in body


def test_reports_no_change_when_only_prose_moves() -> None:
    body = alert.format_delta(TABLE, TABLE + "\nSee also CONTRIBUTING.md.\n")
    assert "does not change" in body


def test_warns_when_the_result_parses_empty() -> None:
    body = alert.format_delta(TABLE, "# Maintainers\n\n- pimlock\n")
    assert "WARNING" in body


def test_login_pattern_matches_the_gate() -> None:
    # Each tool parses MAINTAINERS.md on its own. If the patterns drift, this
    # alert reports a delta that differs from what the gate enforces.
    import check_maintainer_approval as gate

    assert alert.MAINTAINER_RE.pattern == gate.MAINTAINER_RE.pattern
