# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import tomllib
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
TELEMETRY_ENV = "OPENSHELL_TELEMETRY_ENABLED"


def load_yaml(relative_path: str) -> dict[str, object]:
    with (REPO_ROOT / relative_path).open(encoding="utf-8") as source:
        document = yaml.safe_load(source)
    assert isinstance(document, dict)
    return document


def test_rust_test_task_disables_telemetry() -> None:
    with (REPO_ROOT / "tasks/test.toml").open("rb") as source:
        tasks = tomllib.load(source)

    assert tasks["test:rust"]["env"][TELEMETRY_ENV] == "false"


def test_shared_e2e_harness_disables_telemetry_by_default() -> None:
    harness = (REPO_ROOT / "e2e/support/gateway-common.sh").read_text(encoding="utf-8")

    assert (
        'export OPENSHELL_TELEMETRY_ENABLED="${OPENSHELL_TELEMETRY_ENABLED:-false}"'
        in harness
    )


def test_kubernetes_e2e_propagates_shared_setting() -> None:
    wrapper = (REPO_ROOT / "e2e/with-kube-gateway.sh").read_text(encoding="utf-8")

    assert '--set "server.telemetryEnabled=${OPENSHELL_TELEMETRY_ENABLED}"' in wrapper


def test_release_canary_injects_opt_out_into_managed_gateways() -> None:
    document = load_yaml(".github/workflows/release-canary.yml")
    workflow_env = document.get("env")
    assert isinstance(workflow_env, dict)
    assert workflow_env.get(TELEMETRY_ENV) == "false"

    workflow = (REPO_ROOT / ".github/workflows/release-canary.yml").read_text(
        encoding="utf-8"
    )

    assert "launchctl setenv OPENSHELL_TELEMETRY_ENABLED" in workflow
    assert workflow.count("OPENSHELL_TELEMETRY_ENABLED=%s") == 2
    assert "systemctl set-environment" in workflow
    assert "server.telemetryEnabled=${OPENSHELL_TELEMETRY_ENABLED}" in workflow
