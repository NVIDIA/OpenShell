#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

SEMVER_TAG_GLOB = "v[0-9]*.[0-9]*.[0-9]*"
SEMVER_TAG_RE = re.compile(r"^v?(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$")


@dataclass(frozen=True)
class Versions:
    python: str
    cargo: str
    docker: str
    deb: str
    rpm_version: str
    rpm_release: str
    git_tag: str
    git_sha: str
    git_distance: int


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _run(cmd: list[str], *, env: dict[str, str] | None = None) -> None:
    subprocess.run(cmd, check=True, env=env)


def _git(cmd: list[str]) -> str:
    return (
        subprocess.check_output(["git", *cmd], cwd=_repo_root()).decode("utf-8").strip()
    )


def _parse_semver_tag(tag: str) -> tuple[int, int, int] | None:
    match = SEMVER_TAG_RE.match(tag)
    if match is None:
        return None
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
    )


def _format_semver(version: tuple[int, int, int]) -> str:
    return f"{version[0]}.{version[1]}.{version[2]}"


def _next_patch(version: tuple[int, int, int]) -> tuple[int, int, int]:
    return version[0], version[1], version[2] + 1


def _latest_semver_tag() -> str | None:
    try:
        tag = _git(
            ["describe", "--tags", "--match", SEMVER_TAG_GLOB, "--abbrev=0", "HEAD"]
        )
    except subprocess.CalledProcessError:
        return None

    if _parse_semver_tag(tag) is None:
        raise RuntimeError(f"git describe returned non-semver release tag: {tag}")
    return tag


def _versions_from_parts(
    base_version: tuple[int, int, int],
    git_distance: int,
    git_sha: str,
    git_tag: str,
) -> Versions:
    if git_distance == 0:
        python_version = _format_semver(base_version)
        rpm_version = python_version
        rpm_release = "1"
    else:
        next_version = _format_semver(_next_patch(base_version))
        python_version = f"{next_version}.dev{git_distance}+g{git_sha}"
        rpm_version = next_version
        rpm_release = f"0.dev.{git_distance}.g{git_sha}"

    # Convert PEP 440 to a SemVer-ish string for Cargo:
    # 0.1.0.dev3+gabcdef -> 0.1.0-dev.3+gabcdef
    cargo_version = re.sub(r"\.dev(\d+)", r"-dev.\1", python_version)

    # Docker tags can't contain '+'.
    docker_version = cargo_version.replace("+", "-")

    # Debian versions use '~' so prereleases sort before the eventual release.
    deb_version = cargo_version
    deb_version = deb_version[1:] if deb_version.startswith("v") else deb_version
    deb_version = deb_version.replace("-dev.", "~dev.", 1)
    deb_version = f"{deb_version}-1"

    return Versions(
        python=python_version,
        cargo=cargo_version,
        docker=docker_version,
        deb=deb_version,
        rpm_version=rpm_version,
        rpm_release=rpm_release,
        git_tag=git_tag,
        git_sha=git_sha,
        git_distance=git_distance,
    )


def _compute_versions() -> Versions:
    git_tag = _latest_semver_tag()
    git_sha = _git(["rev-parse", "--short=9", "HEAD"])

    if git_tag is None:
        base_version = (0, 0, 0)
        git_distance = int(_git(["rev-list", "--count", "HEAD"]))
        return _versions_from_parts(base_version, git_distance, git_sha, "")

    parsed_tag = _parse_semver_tag(git_tag)
    if parsed_tag is None:
        raise RuntimeError(f"invalid semantic release tag: {git_tag}")

    git_distance = int(_git(["rev-list", f"{git_tag}..HEAD", "--count"]))
    return _versions_from_parts(parsed_tag, git_distance, git_sha, git_tag)


def _print_env(versions: Versions) -> None:
    print(f"VERSION_PY={versions.python}")
    print(f"VERSION_CARGO={versions.cargo}")
    print(f"VERSION_DOCKER={versions.docker}")
    print(f"VERSION_DEB={versions.deb}")
    print(f"VERSION_RPM={versions.rpm_version}")
    print(f"VERSION_RPM_RELEASE={versions.rpm_release}")
    print(f"GIT_TAG={versions.git_tag}")
    print(f"GIT_SHA={versions.git_sha}")
    print(f"GIT_DISTANCE={versions.git_distance}")


def get_version(format: str) -> None:
    versions = _compute_versions()
    if format == "python":
        print(versions.python)
    elif format == "cargo":
        print(versions.cargo)
    elif format == "docker":
        print(versions.docker)
    elif format == "deb":
        print(versions.deb)
    elif format == "rpm-version":
        print(versions.rpm_version)
    elif format == "rpm-release":
        print(versions.rpm_release)
    elif format == "json":
        print(json.dumps(asdict(versions), sort_keys=True))
    else:
        _print_env(versions)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OpenClaw release tooling.")
    sub = parser.add_subparsers(dest="command", required=True)

    get_version_parser = sub.add_parser("get-version", help="Print computed version.")
    get_version_parser.add_argument(
        "--python", action="store_true", help="Print Python version only."
    )
    get_version_parser.add_argument(
        "--cargo", action="store_true", help="Print Cargo version only."
    )
    get_version_parser.add_argument(
        "--docker", action="store_true", help="Print Docker version only."
    )
    get_version_parser.add_argument(
        "--deb", action="store_true", help="Print Debian package version only."
    )
    get_version_parser.add_argument(
        "--rpm-version", action="store_true", help="Print RPM Version only."
    )
    get_version_parser.add_argument(
        "--rpm-release", action="store_true", help="Print RPM Release only."
    )
    get_version_parser.add_argument(
        "--json", action="store_true", help="Print all versions as JSON."
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "get-version":
        if args.python:
            get_version("python")
        elif args.cargo:
            get_version("cargo")
        elif args.docker:
            get_version("docker")
        elif args.deb:
            get_version("deb")
        elif args.rpm_version:
            get_version("rpm-version")
        elif args.rpm_release:
            get_version("rpm-release")
        elif args.json:
            get_version("json")
        else:
            get_version("all")


if __name__ == "__main__":
    main()
