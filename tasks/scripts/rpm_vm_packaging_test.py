# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression checks for the RPM VM driver packaging inputs."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "workflow_name",
    ["branch-e2e.yml", "release-build.yml", "release-dev.yml"],
)
def test_rpm_waits_for_vm_driver_artifact(workflow_name: str) -> None:
    workflow_path = ROOT / ".github" / "workflows" / workflow_name
    workflow = yaml.load(
        workflow_path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader
    )
    jobs = workflow["jobs"]

    assert "build-vm-driver" in jobs["build-rpm"]["needs"]
    assert "build-binaries" in jobs["build-vm-driver"]["needs"]


def test_tmachine_rpm_stages_vm_driver_binary() -> None:
    artifacts = (ROOT / "tests" / "tmachine" / "artifacts.nix").read_text(
        encoding="utf-8"
    )
    rpm_builder = artifacts.split('name = "build-artifacts-rpm";', 1)[1].split(
        "\n  };", 1
    )[0]
    driver_path = "artifacts/binaries/${gnuToolchain.target}/openshell-driver-vm"

    assert f"{driver_path}; do" in rpm_builder
    assert (
        f'--volume "$root/{driver_path}:/binaries/openshell-driver-vm:ro"'
        in rpm_builder
    )


def test_vm_rpm_declares_bundled_native_runtime_licenses() -> None:
    spec = (ROOT / "openshell.spec").read_text(encoding="utf-8")
    vm_package = spec.split("%package driver-vm", 1)[1].split(
        "%description driver-vm", 1
    )[0]
    vm_files = spec.split("%files driver-vm", 1)[1].split("%files -n", 1)[0]
    license_expression = next(
        line.partition(":")[2]
        for line in vm_package.splitlines()
        if line.startswith("License:")
    )

    assert "GPL-2.0-only" in license_expression
    assert "LGPL-2.1-only" in license_expression
    for name, heading in (
        ("LICENSE-GPL-2.0-only", "GNU GENERAL PUBLIC LICENSE"),
        ("LICENSE-LGPL-2.1-only", "GNU LESSER GENERAL PUBLIC LICENSE"),
    ):
        path = ROOT / "deploy" / "rpm" / "licenses" / name
        assert heading in path.read_text(encoding="utf-8")
        assert f"%license deploy/rpm/licenses/{name}" in vm_files


def test_rpm_workflow_starts_installed_vm_driver() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "build-rpm.yml"
    workflow = yaml.load(
        workflow_path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader
    )
    steps = workflow["jobs"]["build"]["steps"]
    verify = next(
        step for step in steps if step.get("name") == "Verify installed VM driver RPM"
    )

    assert "bash tasks/scripts/test-rpm-vm-install.sh" in verify["run"]
