# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import codex_security_range as ranges

SCRIPT = Path(__file__).resolve().parent / "codex_security_range.py"


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo).decode("utf-8").strip()


def _commit(repo: Path, name: str) -> None:
    (repo / "content.txt").write_text(f"{name}\n", encoding="utf-8")
    _git(repo, "add", "content.txt")
    _git(
        repo,
        "-c",
        "user.name=Codex Security Test",
        "-c",
        "user.email=codex-security-test@example.com",
        "commit",
        "-m",
        name,
    )


def _publish_main(repo: Path) -> None:
    _git(
        repo, "update-ref", "refs/remotes/origin/main", _git(repo, "rev-parse", "HEAD")
    )


def _run(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "--initial-branch=main")
    return tmp_path


def test_parses_strict_stable_and_prerelease_tags() -> None:
    assert ranges.parse_stable_tag("v0.1.0") == (0, 1, 0)
    assert ranges.parse_stable_tag("v0.1.0-pre.1") is None
    assert ranges.parse_stable_tag("dev") is None
    # release.py accepts a bare version; a release tag must carry the prefix.
    assert ranges.parse_stable_tag("0.1.0") is None

    assert ranges.parse_prerelease_tag("v2.10.3-pre.12") == (2, 10, 3, 12)
    assert ranges.parse_prerelease_tag("v2.10.3") is None
    assert ranges.parse_prerelease_tag("v2.10.3-pre.0") is None
    assert ranges.parse_prerelease_tag("2.10.3-pre.1") is None


def test_selects_the_newest_stable_strictly_before_the_candidate_train() -> None:
    tags = ["v0.1.9", "v0.1.10", "v0.2.0-pre.1", "v0.2.0", "vm-runtime", "0.1.11"]
    assert ranges.select_previous_stable(tags, (0, 2, 0)) == "v0.1.10"
    assert ranges.select_previous_stable(["v0.1.0"], (0, 1, 0)) is None


def test_resolves_a_cumulative_prerelease_range_from_git_history(repo: Path) -> None:
    _commit(repo, "stable")
    _git(repo, "tag", "v0.1.0")
    _commit(repo, "pre one")
    _git(repo, "tag", "v0.1.1-pre.1")
    _commit(repo, "pre two")
    _git(repo, "tag", "v0.1.1-pre.2")
    _publish_main(repo)

    result = ranges.resolve_range(repo=repo, candidate="v0.1.1-pre.2")

    assert result["base_tag"] == "v0.1.0"
    assert result["candidate_tag"] == "v0.1.1-pre.2"
    assert result["train"] == "v0.1.1"
    assert result["category"] == "codex-security/v0.1.1"
    assert result["scan_scope"] == "diff"
    assert result["commit_count"] == "2"


def test_rejects_a_candidate_that_is_not_a_prerelease_tag(repo: Path) -> None:
    _commit(repo, "stable")
    _git(repo, "tag", "v0.1.0")
    _publish_main(repo)

    for candidate in ("v0.1.0", "v0.1.0-pre.0", "0.1.1-pre.1", "dev"):
        with pytest.raises(ranges.ReleaseRangeError, match="candidate must match"):
            ranges.resolve_range(repo=repo, candidate=candidate)


def test_rejects_a_prerelease_that_is_not_on_main(repo: Path) -> None:
    _commit(repo, "stable")
    _git(repo, "tag", "v0.1.0")
    _publish_main(repo)
    _git(repo, "switch", "--create", "detached-release")
    _commit(repo, "off-main candidate")
    _git(repo, "tag", "v0.1.1-pre.1")

    with pytest.raises(
        ranges.ReleaseRangeError, match="is not an ancestor of origin/main"
    ):
        ranges.resolve_range(repo=repo, candidate="v0.1.1-pre.1")


def test_requires_explicit_approval_before_a_full_bootstrap_scan(repo: Path) -> None:
    _commit(repo, "first candidate")
    _git(repo, "tag", "v0.1.0-pre.1")
    _publish_main(repo)

    with pytest.raises(ranges.ReleaseRangeError, match="--allow-full-bootstrap"):
        ranges.resolve_range(repo=repo, candidate="v0.1.0-pre.1")

    approved = ranges.resolve_range(
        repo=repo, candidate="v0.1.0-pre.1", allow_full_bootstrap=True
    )
    assert approved["scan_scope"] == "full"
    assert approved["base_tag"] == ""
    assert approved["train"] == "v0.1.0"


def test_rejects_a_stable_override_newer_than_the_train(repo: Path) -> None:
    _commit(repo, "stable")
    _git(repo, "tag", "v0.2.0")
    _commit(repo, "candidate")
    _git(repo, "tag", "v0.1.1-pre.1")
    _publish_main(repo)

    with pytest.raises(ranges.ReleaseRangeError, match="must be older than"):
        ranges.resolve_range(repo=repo, candidate="v0.1.1-pre.1", stable="v0.2.0")


def test_cli_writes_github_outputs_and_json(repo: Path, tmp_path: Path) -> None:
    _commit(repo, "stable")
    _git(repo, "tag", "v0.1.0")
    _commit(repo, "candidate")
    _git(repo, "tag", "v0.1.1-pre.1")
    _publish_main(repo)
    outputs = tmp_path / "github-output.txt"

    result = _run(repo, "--candidate", "v0.1.1-pre.1", "--github-output", str(outputs))

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["scan_scope"] == "diff"
    written = dict(
        line.split("=", 1) for line in outputs.read_text(encoding="utf-8").splitlines()
    )
    assert written["base_tag"] == "v0.1.0"
    assert written["category"] == "codex-security/v0.1.1"


def test_cli_fails_without_bootstrap_approval(repo: Path) -> None:
    _commit(repo, "first candidate")
    _git(repo, "tag", "v0.1.0-pre.1")
    _publish_main(repo)

    result = _run(repo, "--candidate", "v0.1.0-pre.1")

    assert result.returncode == 1
    assert "--allow-full-bootstrap" in result.stderr
