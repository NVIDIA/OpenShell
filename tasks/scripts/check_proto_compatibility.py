# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Check protobuf compatibility under the current, tag-defined release train."""

import argparse
import io
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from release import _parse_prerelease_tag, _parse_semver_tag


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def train_policy(ref: str, release: str | None) -> tuple[str, str, bool]:
    tags = git("tag", "--merged", ref, "--list", "v*").splitlines()
    stable = sorted(
        (version, tag)
        for tag in tags
        if tag != release and (version := _parse_semver_tag(tag))
    )
    if release is None:
        prereleases = sorted(
            (version, tag) for tag in tags if (version := _parse_prerelease_tag(tag))
        )
        if not prereleases or (stable and prereleases[-1][0][:3] <= stable[-1][0]):
            return "", "none", False
        release = prereleases[-1][1]

    if not stable:
        raise ValueError("No previous stable release baseline is available.")
    previous, baseline = stable[-1]
    prerelease = _parse_prerelease_tag(release)
    version = prerelease[:3] if prerelease else _parse_semver_tag(release)
    if version is None or not release.startswith("v"):
        raise ValueError(f"Invalid release tag: {release}")
    if version <= previous:
        raise ValueError(f"Release {release} must be newer than stable {baseline}.")
    train = "v" + ".".join(map(str, version))
    allows_breaks = version[:2] > previous[:2]
    return baseline, f"{train} (latest stable: {baseline})", allows_breaks


def export_proto(ref: str, destination: Path) -> None:
    archive = subprocess.check_output(
        ["git", "archive", ref, "--", "buf.yaml", "proto"]
    )
    with tarfile.open(fileobj=io.BytesIO(archive)) as snapshot:
        snapshot.extractall(destination, filter="data")


def compare(candidate: str, baseline: str, allows_breaks: bool) -> int:
    with tempfile.TemporaryDirectory(prefix="ryno-proto-") as directory:
        root = Path(directory)
        export_proto(baseline, root / "before")
        export_proto(candidate, root / "after")
        error_format = (
            "github-actions" if os.environ.get("GITHUB_ACTIONS") == "true" else "text"
        )
        # Buf also returns 100 for compiler diagnostics. Validate both snapshots
        # before treating that status from `breaking` as an allowed API change.
        for snapshot in ("before", "after"):
            subprocess.run(
                [
                    "buf",
                    "build",
                    "proto",
                    "--error-format",
                    error_format,
                    "-o",
                    os.devnull,
                ],
                cwd=root / snapshot,
                check=True,
            )
        result = subprocess.run(
            [
                "buf",
                "breaking",
                "proto",
                "--against",
                str(root / "before" / "proto"),
                "--config",
                "buf.yaml",
                "--error-format",
                error_format,
            ],
            cwd=root / "after",
            capture_output=True,
            text=True,
            check=False,
        )
        diagnostics = result.stdout + result.stderr
        if result.returncode == 100 and allows_breaks:
            print(diagnostics.replace("::error ", "::warning "), end="")
            print(
                "Breaking changes allowed by the version increment; review migration guidance."
            )
            return 0
        print(diagnostics, end="")
        return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ref", help="Target branch/commit, or release tag to qualify")
    args = parser.parse_args()
    ref = git(
        "rev-parse", "--symbolic-full-name", "--verify", "--end-of-options", args.ref
    )
    candidate = git(
        "rev-parse", "--verify", "--end-of-options", f"{args.ref}^{{commit}}"
    )
    release = ref.removeprefix("refs/tags/") if ref.startswith("refs/tags/") else None
    stable, train, allows_breaks = train_policy(candidate, release)
    baseline = f"refs/tags/{stable}" if release else candidate
    if not release:
        # merge-tree writes only Git objects, leaving HEAD and the worktree
        # intact. Target-only additions are therefore not mistaken for deletions.
        candidate = git("merge-tree", "--write-tree", baseline, "HEAD").splitlines()[0]
    print(
        f"Train: {train}; breaking changes {'allowed' if allows_breaks else 'forbidden'}"
    )
    print(f"Comparing {candidate} against {baseline}", flush=True)
    return compare(candidate, baseline, allows_breaks)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        print(error.stderr or error.stdout or str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, tarfile.TarError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
