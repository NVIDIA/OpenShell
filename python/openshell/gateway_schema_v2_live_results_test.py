# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Validate machine-readable schema-v2 live parity results."""

from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS_PATH = REPO_ROOT / "e2e/configs/gateway/schema-v2-live-results.toml"
CAPABILITY_PATH = REPO_ROOT / "e2e/configs/gateway/schema-v2-capability-parity.toml"

REQUIRED_HEADER_FIELDS = {
    "manifest_version",
    "baseline_commit",
    "candidate_start_commit",
    "result",
}
REQUIRED_STEP_5_IDS = {
    "portable-lifecycle-docker",
    "portable-lifecycle-kubernetes",
    "portable-lifecycle-mxc",
    "portable-lifecycle-podman",
    "portable-lifecycle-vm",
}
REQUIRED_STEP_6_IDS = {
    "gateway-tls-client-auth-policy",
    "gateway-wide-process-options",
}
REQUIRED_STEP_7_IDS = {
    "docker-driver-option-parity",
    "podman-driver-option-parity",
    "podman-qualified-security-option-parity",
}
REQUIRED_STEP_8_IDS = {
    "kubernetes-core-option-parity",
    "kubernetes-qualified-option-parity",
}
REQUIRED_STEP_9_IDS = {
    "vm-guest-security-and-spiffe",
    "vm-launch-and-resource-configuration",
}
ALLOWED_STATUSES = {
    "pass",
    "intentional_change",
    "regression",
    "platform_blocked",
}
BASE_FIELDS = {"id", "step", "capability", "driver", "status", "lane"}
PASS_FIELDS = {
    "validated_baseline_commit",
    "validated_candidate_commit",
    "evidence",
}
BLOCKED_FIELDS = {"owner", "blocker"}


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as toml_file:
        return tomllib.load(toml_file)


def assert_full_sha(value: object, field: str) -> str:
    assert isinstance(value, str), f"{field} must be a string"
    assert len(value) == 40 and all(char in "0123456789abcdef" for char in value), (
        f"{field} must be a full lowercase SHA"
    )
    return value


def test_live_results_manifest_is_well_formed() -> None:
    manifest = load_toml(RESULTS_PATH)

    assert set(manifest) == REQUIRED_HEADER_FIELDS
    assert manifest["manifest_version"] == 1
    baseline = assert_full_sha(manifest["baseline_commit"], "baseline_commit")
    assert_full_sha(manifest["candidate_start_commit"], "candidate_start_commit")
    assert baseline == load_toml(CAPABILITY_PATH)["baseline_commit"]

    results = manifest["result"]
    assert isinstance(results, list) and results
    ids: list[str] = []
    for result in results:
        assert set(result) >= BASE_FIELDS
        result_id = result["id"]
        assert isinstance(result_id, str) and result_id.strip()
        ids.append(result_id)
        assert result["status"] in ALLOWED_STATUSES
        assert isinstance(result["step"], int) and 1 <= result["step"] <= 15
        for field in ("capability", "driver", "lane"):
            assert isinstance(result[field], str) and result[field].strip(), (
                f"{result_id}: {field} is required"
            )

    assert len(ids) == len(set(ids))


def test_step_5_covers_every_in_tree_compute_driver() -> None:
    results = [
        result for result in load_toml(RESULTS_PATH)["result"] if result["step"] == 5
    ]

    assert {result["id"] for result in results} == REQUIRED_STEP_5_IDS
    assert {result["driver"] for result in results} == {
        "docker",
        "kubernetes",
        "mxc",
        "podman",
        "vm",
    }


def test_executed_results_pin_commits_and_evidence() -> None:
    manifest = load_toml(RESULTS_PATH)
    for result in manifest["result"]:
        if result["status"] not in {"pass", "intentional_change"}:
            continue

        assert set(result) >= PASS_FIELDS, result["id"]
        assert result["validated_baseline_commit"] == manifest["baseline_commit"]
        candidate = assert_full_sha(
            result["validated_candidate_commit"],
            f"{result['id']}.validated_candidate_commit",
        )
        assert isinstance(result["evidence"], list) and result["evidence"]
        assert all(
            isinstance(item, str) and item.strip() for item in result["evidence"]
        )
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", candidate, "HEAD"],
            cwd=REPO_ROOT,
            check=True,
        )


def test_step_6_records_gateway_option_and_tls_dispositions() -> None:
    results = [
        result for result in load_toml(RESULTS_PATH)["result"] if result["step"] == 6
    ]

    assert {result["id"] for result in results} == REQUIRED_STEP_6_IDS
    statuses = {result["id"]: result["status"] for result in results}
    assert statuses["gateway-wide-process-options"] == "pass"
    assert statuses["gateway-tls-client-auth-policy"] == "intentional_change"


def test_step_7_records_driver_option_dispositions() -> None:
    results = [
        result for result in load_toml(RESULTS_PATH)["result"] if result["step"] == 7
    ]

    assert {result["id"] for result in results} == REQUIRED_STEP_7_IDS
    statuses = {result["id"]: result["status"] for result in results}
    assert statuses["podman-driver-option-parity"] == "intentional_change"
    assert statuses["docker-driver-option-parity"] == "platform_blocked"
    assert statuses["podman-qualified-security-option-parity"] == "platform_blocked"


def test_step_8_records_kubernetes_option_dispositions() -> None:
    results = [
        result for result in load_toml(RESULTS_PATH)["result"] if result["step"] == 8
    ]

    assert {result["id"] for result in results} == REQUIRED_STEP_8_IDS
    statuses = {result["id"]: result["status"] for result in results}
    assert statuses["kubernetes-core-option-parity"] == "pass"
    assert statuses["kubernetes-qualified-option-parity"] == "platform_blocked"


def test_step_9_records_vm_runtime_dispositions() -> None:
    results = [
        result for result in load_toml(RESULTS_PATH)["result"] if result["step"] == 9
    ]

    assert {result["id"] for result in results} == REQUIRED_STEP_9_IDS
    assert all(result["status"] == "platform_blocked" for result in results)
    assert all(result["driver"] == "vm" for result in results)


def test_platform_blocked_results_name_owner_lane_and_blocker() -> None:
    for result in load_toml(RESULTS_PATH)["result"]:
        if result["status"] != "platform_blocked":
            continue

        assert set(result) >= BLOCKED_FIELDS, result["id"]
        assert isinstance(result["owner"], str) and result["owner"].strip()
        assert isinstance(result["blocker"], str) and len(result["blocker"]) >= 80


def test_step_5_records_only_executed_podman_as_pass() -> None:
    statuses = {
        result["driver"]: result["status"]
        for result in load_toml(RESULTS_PATH)["result"]
        if result["step"] == 5
    }

    assert statuses["podman"] == "pass"
    assert all(
        status == "platform_blocked"
        for driver, status in statuses.items()
        if driver != "podman"
    )
