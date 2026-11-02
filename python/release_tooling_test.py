# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_release_module():
    path = Path(__file__).resolve().parents[1] / "tasks/scripts/release.py"
    spec = importlib.util.spec_from_file_location("openshell_release_tooling", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


release = _load_release_module()


def test_exact_tag_versions_are_stable_release_versions() -> None:
    versions = release._versions_from_parts((0, 0, 37), 0, "152d05940", "v0.0.37")

    assert versions.python == "0.0.37"
    assert versions.cargo == "0.0.37"
    assert versions.docker == "0.0.37"
    assert versions.deb == "0.0.37-1"
    assert versions.rpm_version == "0.0.37"
    assert versions.rpm_release == "1"


def test_dev_versions_share_one_build_identity() -> None:
    versions = release._versions_from_parts((0, 0, 37), 108, "152d05940", "v0.0.37")

    assert versions.python == "0.0.38.dev108+g152d05940"
    assert versions.cargo == "0.0.38-dev.108+g152d05940"
    assert versions.docker == "0.0.38-dev.108-g152d05940"
    assert versions.deb == "0.0.38~dev.108+g152d05940-1"
    assert versions.rpm_version == "0.0.38"
    assert versions.rpm_release == "0.dev.108.g152d05940"


def test_prerelease_versions_share_tag_identity() -> None:
    versions = release._versions_from_prerelease(
        (0, 1, 0), 1, "152d05940", "v0.1.0-pre.1"
    )

    assert versions.python == "0.1.0rc1"
    assert versions.cargo == "0.1.0-pre.1"
    assert versions.npm == "0.1.0-pre.1"
    assert versions.docker == "0.1.0-pre.1"
    assert versions.deb == "0.1.0~pre.1-1"
    assert versions.snap == "0.1.0-pre.1"
    assert versions.rpm_version == "0.1.0"
    assert versions.rpm_release == "0.pre.1"


def test_semver_tag_parser_excludes_vm_tags() -> None:
    assert release._parse_semver_tag("v0.0.37") == (0, 0, 37)
    assert release._parse_semver_tag("0.0.37") == (0, 0, 37)
    assert release._parse_semver_tag("v0.1.0-pre.1") is None
    assert release._parse_semver_tag("vm-runtime") is None
    assert release._parse_semver_tag("vm-dev") is None


def test_prerelease_tag_parser_requires_positive_sequence() -> None:
    assert release._parse_prerelease_tag("v0.1.0-pre.1") == (0, 1, 0, 1)
    assert release._parse_prerelease_tag("0.1.0-pre.12") == (0, 1, 0, 12)
    assert release._parse_prerelease_tag("v0.1.0") is None
    assert release._parse_prerelease_tag("v0.1.0-pre.0") is None
    assert release._parse_prerelease_tag("v0.1.0-rc.1") is None


def test_dev_versions_ignore_exact_prerelease_tag(monkeypatch) -> None:
    def fake_git(args: list[str]) -> str:
        if args == ["rev-parse", "--short=9", "HEAD"]:
            return "152d05940"
        if args == ["tag", "--merged", "HEAD", "--list", "v*.*.*"]:
            return "v0.0.37\nv0.1.0-pre.1"
        if args == ["rev-list", "v0.0.37..HEAD", "--count"]:
            return "108"
        raise AssertionError(f"unexpected git command: {args}")

    monkeypatch.setattr(release, "_git", fake_git)

    versions = release._compute_dev_versions()

    assert versions.python == "0.0.38.dev108+g152d05940"
    assert versions.cargo == "0.0.38-dev.108+g152d05940"
    assert versions.git_tag == "v0.0.37"
