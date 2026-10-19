#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Select a qualified prerelease reachable from the checked-out release branch."""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import zipfile
from typing import TYPE_CHECKING
from urllib.parse import urlencode

if TYPE_CHECKING:
    from collections.abc import Iterator


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def api_pages(path: str, key: str) -> Iterator[dict]:
    page = 1
    while True:
        items = json.loads(
            subprocess.check_output(["gh", "api", f"{path}&page={page}"])
        )[key]
        yield from items
        if len(items) < 100:
            return
        page += 1


def verify_summary(summary: dict, tag: str, sha: str, run: dict, attempt: int) -> None:
    if not (
        summary.get("schema_version") == 1
        and summary.get("tag") == tag
        and summary.get("source_sha") == sha
        and summary.get("is_prerelease") is True
        and summary.get("current_profile_passed") is True
        and summary.get("profile", {}).get("name") == "release-tag-v1"
        and summary.get("run", {}).get("id") == str(run["id"])
        and summary.get("run", {}).get("attempt") == str(attempt)
    ):
        raise ValueError(f"Qualification evidence does not match {tag} ({sha})")


def is_latest(tag: str) -> bool:
    version = tuple(map(int, tag.removeprefix("v").split(".")))
    return all(
        tuple(map(int, stable.removeprefix("v").split("."))) <= version
        for stable in git("tag", "--list", "v*").splitlines()
        if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", stable)
    )


def select_candidate(tag: str, branch: str) -> dict:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("Stable tag must match vMAJOR.MINOR.PATCH")

    candidates = {
        candidate: git("rev-parse", f"refs/tags/{candidate}^{{commit}}")
        for candidate in git(
            "tag", "--merged", "HEAD", "--list", f"{tag}-pre.*"
        ).splitlines()
        if re.fullmatch(re.escape(tag) + r"-pre\.[1-9][0-9]*", candidate)
    }
    if not candidates:
        raise ValueError(f"No {tag} prereleases are reachable from {branch}")

    repository = os.environ["GITHUB_REPOSITORY"]
    query = urlencode({"status": "success", "per_page": 100})
    artifacts_by_run = {}
    for candidate in sorted(
        candidates, key=lambda item: int(item.rsplit(".", 1)[1]), reverse=True
    ):
        sha = candidates[candidate]
        runs = api_pages(
            f"repos/{repository}/actions/workflows/release-prerelease.yml/runs?{query}",
            "workflow_runs",
        )
        for run in runs:
            if run["event"] not in {"push", "workflow_dispatch"}:
                continue
            if run["event"] == "workflow_dispatch" and run["head_branch"] != branch:
                continue
            if run["event"] == "push" and (
                run["head_branch"] != candidate or run["head_sha"] != sha
            ):
                continue
            if run["id"] not in artifacts_by_run:
                artifacts_by_run[run["id"]] = list(
                    api_pages(
                        f"repos/{repository}/actions/runs/{run['id']}/artifacts?per_page=100",
                        "artifacts",
                    )
                )
            evidence = {}
            for artifact in artifacts_by_run[run["id"]]:
                match = re.fullmatch(
                    rf"qualification-{re.escape(candidate)}"
                    rf"-run-{run['id']}-attempt-([1-9][0-9]*)",
                    artifact["name"],
                )
                if not match or artifact["expired"]:
                    continue
                attempt = int(match[1])
                if attempt <= run["run_attempt"]:
                    evidence[attempt] = artifact
            if evidence:
                attempt = max(evidence)
                artifact = evidence[attempt]
                break
        else:
            continue
        archive = subprocess.check_output(
            ["gh", "api", f"repos/{repository}/actions/artifacts/{artifact['id']}/zip"]
        )
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            summary = json.loads(bundle.read("qualification-summary.json"))
        verify_summary(summary, candidate, sha, run, attempt)

        # An existing stable tag may be retried, but must never be moved.
        existing = git("tag", "--list", tag)
        if existing and git("rev-parse", f"refs/tags/{tag}^{{commit}}") != sha:
            raise ValueError(f"Stable tag {tag} already exists at a different commit")
        return {
            "tag": tag,
            "candidate_tag": candidate,
            "source_sha": sha,
            "qualification_run_url": f"{run['html_url']}/attempts/{attempt}",
            "qualification_artifact_id": artifact["id"],
            "make_latest": is_latest(tag),
        }

    raise ValueError(
        f"No passing {tag} prerelease with available qualification evidence on {branch}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    parser.add_argument("--branch", required=True)
    args = parser.parse_args()
    print(json.dumps(select_candidate(args.tag, args.branch)))


if __name__ == "__main__":
    main()
