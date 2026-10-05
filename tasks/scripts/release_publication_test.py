# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for qualification gates and staged Snap publication."""

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
TAG_JOBS = yaml.safe_load((ROOT / ".github/workflows/release-tag.yml").read_text())[
    "jobs"
]
SNAP_JOBS = yaml.safe_load((ROOT / ".github/workflows/snap-package.yml").read_text())[
    "jobs"
]
PUBLISH_JOBS = yaml.safe_load(
    (ROOT / ".github/workflows/snap-publish.yml").read_text()
)["jobs"]
SUITES = {
    "PROTO_COMPATIBILITY_RESULT": "protobuf-compatibility",
    "SECURITY_RESULT": "security",
    "CONFORMANCE_RESULT": "conformance-integration",
    "FEATURE_INTEGRATION_RESULT": "feature-specific-integration",
    "DOCKER_E2E_RESULT": "docker-e2e",
    "VM_E2E_RESULT": "vm-e2e",
}


@pytest.mark.parametrize("prerelease", ["true", "false"])
@pytest.mark.parametrize("result", ["success", "failure", "cancelled", "skipped", ""])
@pytest.mark.parametrize("suite", SUITES)
def test_publication_requires_every_suite_to_pass(tmp_path, prerelease, result, suite):
    env = dict(os.environ)
    env.update(dict.fromkeys(SUITES, "success"))
    env.update(
        RELEASE_TAG="v0.1.3-pre.3" if prerelease == "true" else "v0.1.3",
        SOURCE_SHA="0123456789abcdef0123456789abcdef01234567",
        IS_PRERELEASE=prerelease,
        GITHUB_RUN_ID="1234",
        GITHUB_RUN_ATTEMPT="1",
        GITHUB_SERVER_URL="https://github.com",
        GITHUB_REPOSITORY="NVIDIA/OpenShell",
    )
    env[suite] = result
    summary = tmp_path / "qualification-summary.json"
    generated = subprocess.run(
        [str(ROOT / "tasks/scripts/generate-qualification-summary.sh"), str(summary)],
        env=env,
        capture_output=True,
        text=True,
    )
    if not result:
        assert generated.returncode != 0
        assert suite in generated.stderr
        return
    assert generated.returncode == 0, generated.stderr
    passed = generated.stdout.strip()
    steps = TAG_JOBS["qualification-result"]["steps"]
    guard = next(
        step
        for step in steps
        if step.get("name")
        == "Require current qualification profile before publication"
    )
    assert guard["if"] == "steps.summary.outputs.current-profile-passed != 'true'"
    if passed != "true":
        rejected = subprocess.run(
            ["bash", "-c", guard["run"]], env=env, capture_output=True
        )
        assert rejected.returncode != 0
    assert (passed == "true") == (result == "success")
    assert summary.exists()
    upload_index = next(
        i
        for i, step in enumerate(steps)
        if step.get("name") == "Upload qualification result"
    )
    assert upload_index < steps.index(guard)


def test_all_tagged_publication_depends_on_qualification():
    qualification = TAG_JOBS["qualification-result"]
    assert qualification["if"] == "always()"
    assert set(SUITES.values()) <= set(qualification["needs"])
    assert (
        TAG_JOBS["release"]["if"]
        == "needs.qualification-result.outputs.current-profile-passed == 'true'"
    )

    publishers = (
        "release",
        "tag-ghcr-release",
        "release-helm",
        "publish-qualification",
        "publish-snap",
        "publish-sdk-typescript",
        "trigger-wheel-publish",
        "publish-fern-docs",
    )
    for publisher in publishers:
        pending = [publisher]
        ancestors = set()
        while pending:
            job = pending.pop()
            needs = TAG_JOBS[job].get("needs", [])
            needs = [needs] if isinstance(needs, str) else needs
            for dependency in needs:
                if dependency not in ancestors:
                    ancestors.add(dependency)
                    pending.append(dependency)
        assert "qualification-result" in ancestors, publisher
        condition = TAG_JOBS[publisher].get("if", "")
        assert "always()" not in condition, publisher
    assert "current-profile-passed == 'true'" in TAG_JOBS["publish-snap"]["if"]
    assert "current-profile-passed == 'true'" in TAG_JOBS["publish-qualification"]["if"]


def test_branch_checks_run_publication_regressions():
    jobs = yaml.safe_load((ROOT / ".github/workflows/branch-checks.yml").read_text())[
        "jobs"
    ]
    commands = [step.get("run", "") for step in jobs["python"]["steps"]]
    assert any(
        "mise run test:qualification-summary\n" in command
        and "mise run test:release-publication\n" in command
        for command in commands
    )


def test_snap_builds_remain_available_before_qualification():
    build = TAG_JOBS["build-snap"]
    assert "qualification-result" not in build["needs"]
    assert build["with"]["publish"] is False
    assert "release" in TAG_JOBS["publish-snap"]["needs"]
    assert "build-snap" in TAG_JOBS["release"]["needs"]
    assert SNAP_JOBS["publish-snap"]["needs"] == "build-snap"
    assert SNAP_JOBS["publish-snap"]["if"] == "inputs.publish"
    assert "environment" not in SNAP_JOBS["build-snap"]
    assert PUBLISH_JOBS["publish"]["environment"] == "${{ inputs.github-environment }}"
    build_steps = SNAP_JOBS["build-snap"]["steps"]
    assert all("snapcraft upload" not in step.get("run", "") for step in build_steps)
    upload = next(
        step
        for step in build_steps
        if step.get("name", "").startswith("Upload snap artifact")
    )
    assert "*.comp" in upload["with"]["path"]
    publish_steps = PUBLISH_JOBS["publish"]["steps"]
    assert publish_steps[0]["with"]["name"] == upload["with"]["name"]
    assert all("snapcraft pack" not in step.get("run", "") for step in publish_steps)


def test_snap_upload_uses_built_snap_and_components(tmp_path):
    steps = PUBLISH_JOBS["publish"]["steps"]
    upload = next(
        step for step in steps if step.get("name") == "Upload snap to Snap Store"
    )
    for filename in ("openshell_0.1.3_amd64.snap", "openshell+prover_0.1.3_amd64.comp"):
        (tmp_path / filename).touch()
    command = "snapcraft() { printf '%s\\n' \"$@\"; };\n" + upload["run"]
    result = subprocess.run(
        ["bash", "-c", command],
        cwd=tmp_path,
        env={**os.environ, "INPUTS_UPLOAD_CHANNEL": "latest/stable"},
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.splitlines() == [
        "upload",
        "--release",
        "latest/stable",
        "openshell_0.1.3_amd64.snap",
        "--component",
        "openshell+prover_0.1.3_amd64.comp",
    ]


@pytest.mark.parametrize("snap_count", [0, 2])
def test_snap_upload_rejects_ambiguous_artifacts(tmp_path, snap_count):
    for number in range(snap_count):
        (tmp_path / f"openshell_{number}_amd64.snap").touch()
    upload = next(
        step
        for step in PUBLISH_JOBS["publish"]["steps"]
        if step.get("name") == "Upload snap to Snap Store"
    )
    command = "snapcraft() { echo unexpected-upload; };\n" + upload["run"]
    result = subprocess.run(
        ["bash", "-c", command],
        cwd=tmp_path,
        env={**os.environ, "INPUTS_UPLOAD_CHANNEL": "latest/stable"},
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "unexpected-upload" not in result.stdout
