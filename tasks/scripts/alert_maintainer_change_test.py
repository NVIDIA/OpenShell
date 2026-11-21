# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for tasks/scripts/alert_maintainer_change.py.

Run via `mise run test:maintainer-approval`, which provides pytest through
`uv run --with pytest`. pytest puts this file's directory on sys.path, so the
sibling script imports directly.
"""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

import alert_maintainer_change as alert
import yaml

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


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/maintainers-change-alert.yml"
STEP_NAME = "Post the maintainer delta"


def workflow_step() -> dict:
    steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["describe-change"]["steps"]
    return next(step for step in steps if step.get("name") == STEP_NAME)


def run_alert_step(tmp_path, merge_responses):
    """Run the actual workflow step against a controlled GitHub API fixture.

    `merge_responses` lists the parents the merge ref reports on each
    successive call; the last entry repeats once the list is exhausted.
    """
    import json

    step = workflow_step()
    env_values = {
        "GH_REPO": "NVIDIA/OpenShell",
        "PR_NUMBER": "42",
        "BASE_SHA": "base",
        "HEAD_SHA": "head",
        "COMMENT_MARKER": MARKER,
        "GH_TOKEN": "token",
    }
    # A renamed or added variable must fail here, not pass silently.
    assert set(step["env"]) == set(env_values)
    for index, parents in enumerate(merge_responses):
        (tmp_path / f"merge{index}.json").write_text(
            json.dumps({"sha": "merge", "parents": [{"sha": p} for p in parents]})
        )
    (tmp_path / "merge-count").write_text(str(len(merge_responses)))
    (tmp_path / "base.md").write_text(TABLE)
    (tmp_path / "merged.md").write_text(
        TABLE + "| Jim | [@purp](https://github.com/purp) | NVIDIA |\n"
    )
    gh = tmp_path / "gh"
    gh.write_text(
        textwrap.dedent("""\
        #!/bin/sh
        case "$*" in
          *commits/refs/pull/42/merge*)
            n=$(cat calls 2>/dev/null || echo 0)
            echo $((n + 1)) > calls
            last=$(($(cat merge-count) - 1))
            [ "$n" -gt "$last" ] && n=$last
            cat "merge$n.json" ;;
          *contents/MAINTAINERS.md?ref=base*) cat base.md ;;
          *contents/MAINTAINERS.md?ref=merge*) cat merged.md ;;
          *issues/42/comments*--jq*) printf '1\\n' ;;
          *issues/comments/1*) cp body.md posted.md ;;
          *) echo "unexpected gh call: $*" >&2; exit 1 ;;
        esac
    """)
    )
    gh.chmod(0o755)
    # No real waiting between retries.
    sleep = tmp_path / "sleep"
    sleep.write_text("#!/bin/sh\nexit 0\n")
    sleep.chmod(0o755)
    env = (
        os.environ
        | env_values
        | {
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
        }
    )
    (tmp_path / "tasks/scripts").mkdir(parents=True)
    (tmp_path / "tasks/scripts/alert_maintainer_change.py").symlink_to(
        ROOT / "tasks/scripts/alert_maintainer_change.py"
    )
    return subprocess.run(
        ["bash", "-c", step["run"]],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )


def test_workflow_reports_delta_from_verified_merge(tmp_path):
    result = run_alert_step(tmp_path, [["base", "head"]])
    assert result.returncode == 0, result.stderr
    body = (tmp_path / "posted.md").read_text()
    assert "@purp" in body
    assert "Loses approval rights" not in body


def test_workflow_rejects_merge_for_different_head(tmp_path):
    result = run_alert_step(tmp_path, [["base", "other-head"]])
    assert result.returncode != 0
    assert not (tmp_path / "posted.md").exists()


def test_workflow_retries_until_the_merge_ref_catches_up(tmp_path):
    # Right after a push the ref still points at the previous merge.
    result = run_alert_step(tmp_path, [["base", "old-head"], ["base", "head"]])
    assert result.returncode == 0, result.stderr
    assert int((tmp_path / "calls").read_text()) == 2
    assert "@purp" in (tmp_path / "posted.md").read_text()
