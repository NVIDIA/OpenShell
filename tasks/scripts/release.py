#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from setuptools_scm import get_version as scm_get_version


@dataclass(frozen=True)
class Versions:
    python: str
    cargo: str
    docker: str
    git_tag: str
    git_sha: str


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _run(cmd: list[str], *, env: dict[str, str] | None = None) -> None:
    subprocess.run(cmd, check=True, env=env)


def _git(cmd: list[str]) -> str:
    return (
        subprocess.check_output(["git", *cmd], cwd=_repo_root()).decode("utf-8").strip()
    )


def _compute_versions() -> Versions:
    root = _repo_root()
    python_version = scm_get_version(
        # NOTE: Cargo doesn't support .post versions, so when we are releasing,
        # but not on tag, we use a next version (bumps the patch).
        # EXAMPLE: if the last tag was 0.1.0, then the next version will be 0.1.1-dev.0
        version_scheme="guess-next-dev",
        root=str(root),
        fallback_version="0.0.0",
    )

    # Convert PEP 440 to a SemVer-ish string for Cargo:
    # 0.1.0.dev3+gabcdef -> 0.1.0-dev.3+gabcdef
    cargo_version = re.sub(r"\.dev(\d+)", r"-dev.\1", python_version)

    # Docker tags can't contain '+'.
    docker_version = cargo_version.replace("+", "-")

    git_tag = _git(["describe", "--tags", "--abbrev=0"])
    git_sha = _git(["rev-parse", "--short", "HEAD"])

    return Versions(
        python=python_version,
        cargo=cargo_version,
        docker=docker_version,
        git_tag=git_tag,
        git_sha=git_sha,
    )


def python_publish(
    version: str | None = None, wheel_glob: str = "nemoclaw-*.whl"
) -> None:
    if version is None:
        version = _compute_versions().python

    repo_url = os.getenv("NAV_PYPI_REPOSITORY_URL")
    username = os.getenv("NAV_PYPI_USERNAME")
    password = os.getenv("NAV_PYPI_PASSWORD")

    if not repo_url or not username or not password:
        raise SystemExit(
            "Auth is not set up for publishing to PyPI registry, see CONTRIBUTING.md for details."
        )

    env = dict(os.environ)
    env["UV_PUBLISH_USERNAME"] = username
    env["UV_PUBLISH_PASSWORD"] = password

    wheels_dir = _repo_root() / "target" / "wheels"
    wheels_dir.mkdir(parents=True, exist_ok=True)

    wheel_paths = sorted(
        p
        for p in wheels_dir.glob("*.whl")
        if f"-{version}-" in p.name and fnmatch.fnmatch(p.name, wheel_glob)
    )

    if not wheel_paths:
        available = "\n".join(sorted(p.name for p in wheels_dir.glob("*.whl")))
        raise SystemExit(
            f"No wheels found for version {version} in {wheels_dir}.\n"
            f"Available wheels:\n{available or '(none)'}"
        )

    _run(
        [
            "uv",
            "publish",
            "--publish-url",
            repo_url,
            *[str(path) for path in wheel_paths],
        ],
        env=env,
    )


def get_version(format: str) -> None:
    versions = _compute_versions()
    if format == "python":
        print(versions.python)
    elif format == "cargo":
        print(versions.cargo)
    elif format == "docker":
        print(versions.docker)
    else:
        print(f"VERSION_PY={versions.python}")
        print(f"VERSION_CARGO={versions.cargo}")
        print(f"VERSION_DOCKER={versions.docker}")
        print(f"GIT_TAG={versions.git_tag}")
        print(f"GIT_SHA={versions.git_sha}")


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

    python_publish_parser = sub.add_parser(
        "python-publish", help="Publish python wheel."
    )
    python_publish_parser.add_argument(
        "--version", help="Version to publish (defaults to computed version)."
    )
    python_publish_parser.add_argument(
        "--wheel-glob",
        default="nemoclaw-*.whl",
        help="Filename glob for wheels to publish (defaults to all nemoclaw wheels).",
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
        else:
            get_version("all")
    elif args.command == "python-publish":
        python_publish(version=args.version, wheel_glob=args.wheel_glob)


if __name__ == "__main__":
    main()
