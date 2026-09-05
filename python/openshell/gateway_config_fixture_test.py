# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Schema-only checks for E2E gateway fixtures; these do not start a runtime."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "e2e/configs/gateway"
TEST_GUEST_ROLE_PATH = (
    REPO_ROOT
    / "nix/test-guest/provisioners/roles/gateway-rootless-podman/tasks/development-gateway.yml"
)


@pytest.mark.parametrize(
    ("fixture_name", "driver"),
    [("docker.toml", "docker"), ("podman.toml", "podman")],
)
def test_e2e_gateway_fixtures_use_schema_v2_scalar_driver(
    fixture_name: str, driver: str
) -> None:
    config = tomllib.loads((FIXTURE_DIR / fixture_name).read_text(encoding="utf-8"))
    gateway = config["openshell"]["gateway"]

    assert config["openshell"]["version"] == 2
    assert gateway["compute_driver"] == driver
    assert "compute_drivers" not in gateway
    assert "sandbox_namespace" not in gateway


def test_rootless_podman_test_guest_producer_uses_schema_v2() -> None:
    tasks = yaml.safe_load(TEST_GUEST_ROLE_PATH.read_text(encoding="utf-8"))
    producer = next(
        task
        for task in tasks
        if task.get("name") == "Write rootless Podman gateway configuration"
    )
    content = producer["ansible.builtin.copy"]["content"]
    config = tomllib.loads(content)
    gateway = config["openshell"]["gateway"]

    assert config["openshell"]["version"] == 2
    assert gateway["compute_driver"] == "podman"
    assert "compute_drivers" not in gateway
    assert "ttl_secs" not in gateway["gateway_jwt"]
    assert "podman" in config["openshell"]["drivers"]


def test_docker_e2e_gateway_fixture_uses_canonical_policy_and_label() -> None:
    config = tomllib.loads((FIXTURE_DIR / "docker.toml").read_text(encoding="utf-8"))
    docker = config["openshell"]["drivers"]["docker"]

    assert docker["image_pull_policy"] == "if_not_present"
    assert docker["sandbox_label"] == "openshell-e2e"
    assert "sandbox_namespace" not in docker


def test_podman_e2e_gateway_fixture_uses_canonical_policy_and_callbacks() -> None:
    config = tomllib.loads((FIXTURE_DIR / "podman.toml").read_text(encoding="utf-8"))
    podman = config["openshell"]["drivers"]["podman"]

    assert podman["image_pull_policy"] == "if_not_present"
    assert podman["health_check_interval_secs"] == 10
    assert podman["ssh_socket_path"] == "/run/openshell/ssh.sock"
    assert "sandbox_namespace" not in podman
