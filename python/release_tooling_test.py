# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


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


def _stable_workflow_step(name: str) -> dict:
    workflow = Path(__file__).resolve().parents[1] / ".github/workflows/release.yml"
    jobs = yaml.load(workflow.read_text(), Loader=yaml.BaseLoader)["jobs"]
    return next(
        step
        for job in jobs.values()
        for step in job.get("steps", [])
        if step.get("name") == name
    )


@pytest.mark.parametrize(
    ("scenario", "expected_error"),
    [
        ("valid", None),
        ("wrong-commit", "points to"),
        ("no-wheel", "Expected exactly one Python wheel"),
        ("multiple-wheels", "Expected exactly one Python wheel"),
        ("wrong-version", "is not an openshell"),
        ("wrong-project", "is not an openshell"),
        ("missing-checksum", "missing from the release checksums"),
        ("tampered-wheel", "FAILED"),
        ("release-download-fails", None),
    ],
)
def test_pypi_upload_validates_the_release_wheel(tmp_path, scenario, expected_error):
    wheel_name = "openshell-1.2.3-py3-none-any.whl"
    if scenario == "wrong-version":
        wheel_name = "openshell-1.2.4-py3-none-any.whl"
    elif scenario == "wrong-project":
        wheel_name = "other-1.2.3-py3-none-any.whl"
    dist = tmp_path / "dist"
    dist.mkdir()
    payload = b"release wheel"
    if scenario != "no-wheel":
        (dist / wheel_name).write_bytes(payload)
    if scenario == "multiple-wheels":
        (dist / "openshell-1.2.3-py3-none-linux_x86_64.whl").write_bytes(payload)
    if scenario == "tampered-wheel":
        (dist / wheel_name).write_bytes(b"changed wheel")
    digest = hashlib.sha256(payload).hexdigest()
    checksum_name = "other.whl" if scenario == "missing-checksum" else wheel_name
    (tmp_path / "release-checksums.txt").write_text(f"{digest}  {checksum_name}\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    gh.write_text(
        "#!/bin/bash\n"
        'if [[ "$1" == api ]]; then\n'
        '  echo "${TAG_SHA}"\n'
        'elif [[ "$1 $2" == "release download" ]]; then\n'
        '  [[ "${DOWNLOAD_FAIL}" == false ]] || exit 1\n'
        "  mkdir checksums\n"
        "  cp release-checksums.txt checksums/openshell-checksums-sha256.txt\n"
        "else\n"
        "  exit 1\n"
        "fi\n"
    )
    gh.chmod(0o755)
    result = subprocess.run(
        [
            "bash",
            "-c",
            _stable_workflow_step("Verify wheel against the stable release")["run"],
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "GITHUB_REPOSITORY": "NVIDIA/OpenShell",
            "RELEASE_TAG": "v1.2.3",
            "SOURCE_SHA": "source-commit",
            "TAG_SHA": "other-commit"
            if scenario == "wrong-commit"
            else "source-commit",
            "PYTHON_VERSION": "1.2.3",
            "DOWNLOAD_FAIL": "true"
            if scenario == "release-download-fails"
            else "false",
        },
        capture_output=True,
        text=True,
    )
    if scenario == "valid":
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0
        if expected_error:
            assert expected_error in result.stdout + result.stderr


@pytest.mark.parametrize("result", ["success", "failure", "skipped", "cancelled"])
def test_stable_publication_requires_pypi_success(result):
    outcome = subprocess.run(
        [
            "bash",
            "-c",
            _stable_workflow_step("Require every stable publisher to succeed")["run"],
        ],
        env={**os.environ, "NEEDS": '{"publish-pypi":{"result":"' + result + '"}}'},
        capture_output=True,
        text=True,
    )
    assert (outcome.returncode == 0) == (result == "success")
