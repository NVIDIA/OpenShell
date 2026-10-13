#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Resolve the Codex Security scan range for a pre-release candidate.

Tag parsing is reused from release.py so both stay on one definition of what a
release tag is. That module also accepts tags without the `v` prefix, which a
release workflow must not, so the prefix is required here.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from release import (
    _format_semver,
    _parse_prerelease_tag,
    _parse_semver_tag,
)


class ReleaseRangeError(Exception):
    """A scan range could not be resolved from the supplied refs."""


def _git(repo: Path, cmd: list[str]) -> str:
    return subprocess.check_output(["git", *cmd], cwd=repo).decode("utf-8").strip()


def _resolve_commit(repo: Path, ref: str) -> str:
    try:
        return _git(repo, ["rev-parse", "--verify", f"{ref}^{{commit}}"])
    except subprocess.CalledProcessError as error:
        raise ReleaseRangeError(
            f"Git reference does not resolve to a commit: {ref}"
        ) from error


def _is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=repo,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode in (0, 1):
        return result.returncode == 0
    raise ReleaseRangeError(
        f"git merge-base failed for {ancestor} and {descendant} "
        f"(exit {result.returncode})"
    )


def parse_stable_tag(tag: str) -> tuple[int, int, int] | None:
    return _parse_semver_tag(tag) if tag.startswith("v") else None


def parse_prerelease_tag(tag: str) -> tuple[int, int, int, int] | None:
    return _parse_prerelease_tag(tag) if tag.startswith("v") else None


def select_previous_stable(
    tags: list[str], candidate_version: tuple[int, int, int]
) -> str | None:
    older = [
        (version, tag)
        for tag in tags
        if (version := parse_stable_tag(tag)) and version < candidate_version
    ]
    return max(older)[1] if older else None


def resolve_range(
    *,
    repo: Path,
    candidate: str,
    stable: str = "",
    main_ref: str = "origin/main",
    allow_full_bootstrap: bool = False,
) -> dict[str, str]:
    parsed_candidate = parse_prerelease_tag(candidate)
    if parsed_candidate is None:
        raise ReleaseRangeError(
            f"candidate must match vMAJOR.MINOR.PATCH-pre.N: {candidate}"
        )
    candidate_version = parsed_candidate[:3]
    train = f"v{_format_semver(candidate_version)}"

    candidate_sha = _resolve_commit(repo, candidate)
    main_sha = _resolve_commit(repo, main_ref)
    if not _is_ancestor(repo, candidate_sha, main_sha):
        raise ReleaseRangeError(
            f"candidate {candidate} ({candidate_sha}) is not an ancestor of {main_ref}"
        )

    resolved = {
        "candidate_tag": candidate,
        "candidate_sha": candidate_sha,
        "train": train,
        "category": f"codex-security/{train}",
    }

    merged_tags = [
        tag
        for tag in _git(
            repo, ["tag", "--list", "v*", "--merged", candidate_sha]
        ).splitlines()
        if tag
    ]
    stable_tag = stable or select_previous_stable(merged_tags, candidate_version)
    if not stable_tag:
        if not allow_full_bootstrap:
            raise ReleaseRangeError(
                f"no previous stable tag exists for {candidate}; rerun with an "
                "approved base or --allow-full-bootstrap"
            )
        return {
            **resolved,
            "base_tag": "",
            "base_sha": "",
            "scan_scope": "full",
            "commit_count": _git(repo, ["rev-list", "--count", candidate_sha]),
        }

    stable_version = parse_stable_tag(stable_tag)
    if stable_version is None:
        raise ReleaseRangeError(
            "stable base must match vMAJOR.MINOR.PATCH without a prerelease: "
            f"{stable_tag}"
        )
    if stable_version >= candidate_version:
        raise ReleaseRangeError(
            f"stable base {stable_tag} must be older than release train {train}"
        )

    stable_sha = _resolve_commit(repo, stable_tag)
    if not _is_ancestor(repo, stable_sha, candidate_sha):
        raise ReleaseRangeError(
            f"stable base {stable_tag} ({stable_sha}) is not an ancestor of {candidate}"
        )

    commit_count = int(
        _git(repo, ["rev-list", "--count", f"{stable_sha}..{candidate_sha}"])
    )
    if commit_count <= 0:
        raise ReleaseRangeError(
            f"candidate {candidate} has no commits after stable base {stable_tag}"
        )

    return {
        **resolved,
        "base_tag": stable_tag,
        "base_sha": stable_sha,
        "scan_scope": "diff",
        "commit_count": str(commit_count),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Resolve the Codex Security scan range."
    )
    parser.add_argument(
        "--candidate", required=True, help="Pre-release tag (vMAJOR.MINOR.PATCH-pre.N)."
    )
    parser.add_argument("--stable", default="", help="Previous stable tag override.")
    parser.add_argument(
        "--main-ref",
        default="origin/main",
        help="Ref the candidate must be an ancestor of.",
    )
    parser.add_argument(
        "--allow-full-bootstrap",
        action="store_true",
        help="Allow a full scan when no previous stable tag exists.",
    )
    parser.add_argument(
        "--github-output",
        type=Path,
        default=None,
        help="File to append key=value outputs to (default: $GITHUB_OUTPUT).",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()

    try:
        outputs = resolve_range(
            repo=Path.cwd(),
            candidate=args.candidate,
            stable=args.stable,
            main_ref=args.main_ref,
            allow_full_bootstrap=args.allow_full_bootstrap,
        )
    except ReleaseRangeError as error:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print(f"::error::{error}", file=sys.stderr)
        else:
            print(f"codex-security-range: {error}", file=sys.stderr)
        raise SystemExit(1) from error

    environment_output = os.environ.get("GITHUB_OUTPUT")
    output_path = args.github_output or (
        Path(environment_output) if environment_output else None
    )
    if output_path is not None:
        with output_path.open("a", encoding="utf-8") as handle:
            for key, value in outputs.items():
                handle.write(f"{key}={value}\n")
    print(json.dumps(outputs, indent=2))


if __name__ == "__main__":
    main()
