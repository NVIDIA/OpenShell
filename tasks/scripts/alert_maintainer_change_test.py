# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for tasks/scripts/alert_maintainer_change.py.

Run via `mise run test:maintainer-approval`, which provides pytest through
`uv run --with pytest`. pytest puts this file's directory on sys.path, so the
sibling script imports directly.
"""

from __future__ import annotations

import alert_maintainer_change as alert

MARKER = "<!-- maintainer-approval-delta -->"

TABLE = """# Maintainers

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Derek Carr | [@derekwaynecarr](https://github.com/derekwaynecarr) | Red Hat |
| Evan Lezar | [@elezar](https://github.com/elezar) | NVIDIA |
| Piotr Mlocek | [@pimlock](https://github.com/pimlock) | NVIDIA |
"""


def run(tmp_path, monkeypatch, before: str, after: str, marker: str = MARKER):
    """Return the tool's exit code and the comment body it printed."""
    monkeypatch.setenv("COMMENT_MARKER", marker)
    before_file = tmp_path / "before.md"
    before_file.write_text(before, encoding="utf-8")
    after_file = tmp_path / "after.md"
    after_file.write_text(after, encoding="utf-8")
    return alert.main(["--before", str(before_file), "--after", str(after_file)])


def test_parse_maintainers_extracts_linked_logins() -> None:
    assert alert.parse_maintainers(TABLE) == {"derekwaynecarr", "elezar", "pimlock"}


def test_names_added_and_removed_logins() -> None:
    after = TABLE.replace(
        "| Piotr Mlocek | [@pimlock](https://github.com/pimlock) | NVIDIA |\n",
        "| Mrunal Patel | [@mrunalp](https://github.com/mrunalp) | Red Hat |\n",
    )
    body = alert.format_delta(MARKER, TABLE, after)
    assert "@mrunalp" in body
    assert "@pimlock" in body


def test_says_nothing_when_only_prose_moves() -> None:
    # An unchanged approver set is not worth a comment.
    assert alert.format_delta(MARKER, TABLE, TABLE + "\nSee CONTRIBUTING.md.\n") == ""


def test_prints_nothing_when_the_approver_set_is_unchanged(
    tmp_path, monkeypatch, capsys
) -> None:
    assert run(tmp_path, monkeypatch, TABLE, TABLE) == 0
    assert capsys.readouterr().out == ""


def test_fails_when_the_result_parses_empty(tmp_path, monkeypatch, capsys) -> None:
    # Merging this would make the approval gate fail closed on every PR.
    assert run(tmp_path, monkeypatch, TABLE, "# Maintainers\n\n- pimlock\n") != 0
    assert "WARNING" in capsys.readouterr().out


def test_fails_when_the_marker_is_unset(tmp_path, monkeypatch) -> None:
    assert run(tmp_path, monkeypatch, TABLE, TABLE, marker="") != 0


def test_body_starts_with_the_marker_the_workflow_supplies(
    tmp_path, monkeypatch, capsys
) -> None:
    # The workflow finds its earlier comment with this prefix.
    after = TABLE + "| Jim Meyer | [@purp](https://github.com/purp) | NVIDIA |\n"
    assert run(tmp_path, monkeypatch, TABLE, after) == 0
    assert capsys.readouterr().out.startswith(MARKER)


def test_login_pattern_matches_the_gate() -> None:
    # Each tool parses MAINTAINERS.md on its own. If the patterns drift, this
    # alert reports a delta that differs from what the gate enforces.
    import check_maintainer_approval as gate

    assert alert.MAINTAINER_RE.pattern == gate.MAINTAINER_RE.pattern
