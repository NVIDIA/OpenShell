# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Validate machine-readable schema-v2 live parity results."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tomllib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS_PATH = REPO_ROOT / "e2e/configs/gateway/schema-v2-live-results.toml"
CAPABILITY_PATH = REPO_ROOT / "e2e/configs/gateway/schema-v2-capability-parity.toml"
COMPUTE_BOUNDARY_PATH = (
    REPO_ROOT / "e2e/configs/gateway/schema-v2-compute-boundary-comparison.json"
)
CROSS_CUTTING_DISPOSITIONS_PATH = (
    REPO_ROOT / "e2e/configs/gateway/schema-v2-cross-cutting-dispositions.toml"
)

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
REQUIRED_STEP_10_IDS = {"compute-driver-boundary-parity"}
REQUIRED_STEP_11_IDS = {
    "credential-driver-backend-tables",
    "credential-driver-selection-and-kek",
    "gateway-interceptor-registration",
    "gateway-minted-sandbox-jwt",
    "inference-control-plane-configuration",
    "mtls-user-authentication",
    "oidc-bearer-authentication",
    "otlp-observability",
    "provider-profile-sources",
    "supervisor-middleware-registration",
    "unsafe-unauthenticated-user-mode",
}
REQUIRED_STEP_12_IDS = {
    "debian-package-upgrade",
    "homebrew-package-upgrade",
    "rpm-package-upgrade",
    "snap-package-refresh",
}
STEP_10_CANDIDATE_COMMIT = "4a39da510e4d278a24dd60291149519c9a570b46"
STEP_10_REPORT_SHA256 = (
    "65541eec5f642461a88b04b5459474fd7a475adeb7071a65a53fe183caad6a01"
)
STEP_10_EVIDENCE_BUNDLES = {
    "in_tree": "target/parity/step10-intree-4a39da51",
    "external_uds": "target/parity/step10-external-4a39da51",
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


def test_step_10_records_verified_compute_boundary_parity(tmp_path: Path) -> None:
    results = [
        result for result in load_toml(RESULTS_PATH)["result"] if result["step"] == 10
    ]
    assert {result["id"] for result in results} == REQUIRED_STEP_10_IDS
    assert results[0]["status"] == "pass"

    with COMPUTE_BOUNDARY_PATH.open(encoding="utf-8") as report_file:
        report = json.load(report_file)
    assert report["manifest_version"] == 2
    assert report["baseline_commit"] == load_toml(RESULTS_PATH)["baseline_commit"]
    assert report["candidate_commit"] == results[0]["validated_candidate_commit"]
    assert report["candidate_commit"] == STEP_10_CANDIDATE_COMMIT
    assert report["retained_evidence_bundles"] == STEP_10_EVIDENCE_BUNDLES
    assert (
        hashlib.sha256(COMPUTE_BOUNDARY_PATH.read_bytes()).hexdigest()
        == STEP_10_REPORT_SHA256
    )
    assert report["classification"] == "pass"
    assert report["accepted"] is True
    assert all(report["oracle"].values())
    assert all(report["verification"].values())

    launch_attestations = []
    for topology_name in ("in_tree", "external_uds"):
        topology = report[topology_name]
        assert topology["classification"] == "pass"
        assert topology["parity"] is True
        assert topology["accepted"] is True
        assert re.fullmatch(r"[0-9a-f]{64}", topology["comparison_sha256"])
        baseline_launch = topology["baseline"]["launch_attestation"]
        candidate_launch = topology["candidate"]["launch_attestation"]
        for field in (
            "sandbox_image_id",
            "sandbox_image_digest",
            "sandbox_runtime_image",
            "supervisor_base_image",
            "supervisor_base_image_id",
            "supervisor_base_image_digest",
            "supervisor_package_manifest_sha256",
        ):
            assert baseline_launch[field] == candidate_launch[field]
        launch_attestations.extend((baseline_launch, candidate_launch))

        for variant_name, schema_version in (("baseline", 1), ("candidate", 2)):
            variant = topology[variant_name]
            assert variant["schema_version"] == schema_version
            assert variant["success"] is True
            assert variant["artifacts_verified"] is True
            assert variant["raw_output_verified"] is True
            assert all(
                re.fullmatch(r"[0-9a-f]{64}", digest)
                for digest in variant["artifact_sha256"].values()
            )
            assert all(
                re.fullmatch(r"[0-9a-f]{64}", digest)
                for digest in variant["raw_evidence_sha256"].values()
            )
            launch = variant["launch_attestation"]
            supervisor_digest = launch["supervisor_image_digest"]
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", supervisor_digest)
            assert launch["supervisor_runtime_image"].endswith(f"@{supervisor_digest}")
            sandbox_digest = launch["sandbox_image_digest"]
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", sandbox_digest)
            assert launch["sandbox_image_request"] == launch["sandbox_runtime_image"]
            assert launch["sandbox_runtime_image"].endswith(f"@{sandbox_digest}")

    for field in (
        "sandbox_image_id",
        "sandbox_image_digest",
        "sandbox_runtime_image",
        "supervisor_base_image",
        "supervisor_base_image_id",
        "supervisor_base_image_digest",
        "supervisor_base_runtime_image",
        "supervisor_package_manifest_sha256",
        "supervisor_dockerfile_sha256_before_execution",
    ):
        assert len({launch[field] for launch in launch_attestations}) == 1, field

    external_sockets = []
    for variant_name in ("baseline", "candidate"):
        external_variant = report["external_uds"][variant_name]
        external_launch = external_variant["launch_attestation"]
        assert external_launch["compute_driver_transport"] == "remote_uds"
        assert external_launch["external_compute_driver"] is True
        assert external_launch["external_driver_grpc_endpoint"].startswith("https://")
        assert external_launch["external_driver_host_gateway_ip"] == "host-gateway"
        assert external_launch["external_driver_userns"] is None
        assert external_launch["external_driver_spiffe"] is False
        assert external_launch["external_driver_proxy"] is False
        assert external_launch["external_driver_app_armor"] is False
        driver_environment = external_launch["external_driver_environment"]
        assert driver_environment["OPENSHELL_COMPUTE_DRIVER_SOCKET"]
        assert driver_environment["OPENSHELL_PODMAN_SOCKET"]
        assert driver_environment["OPENSHELL_GRPC_ENDPOINT"].startswith("https://")
        assert driver_environment["OPENSHELL_ENABLE_BIND_MOUNTS"] is True
        for tls_field in (
            "OPENSHELL_PODMAN_TLS_CA",
            "OPENSHELL_PODMAN_TLS_CERT",
            "OPENSHELL_PODMAN_TLS_KEY",
        ):
            assert re.fullmatch(
                r"[0-9a-f]{64}", driver_environment[tls_field]["sha256"]
            )
        external_sockets.append(driver_environment["OPENSHELL_COMPUTE_DRIVER_SOCKET"])
        assert f"{variant_name}.driver.log" in external_variant["raw_evidence_sha256"]
        assert f"{variant_name}.exec.stdout" in external_variant["raw_evidence_sha256"]
    assert len(set(external_sockets)) == 2

    evidence_paths = {
        name: REPO_ROOT / relative_path
        for name, relative_path in STEP_10_EVIDENCE_BUNDLES.items()
    }
    present = {name: path.is_dir() for name, path in evidence_paths.items()}
    assert len(set(present.values())) == 1, "Step 10 retained evidence is incomplete"
    if all(present.values()):
        reproduced = tmp_path / "schema-v2-compute-boundary-comparison.json"
        subprocess.run(
            [
                "python3",
                str(REPO_ROOT / "e2e/parity/verify-results.py"),
                "--baseline-sha",
                report["baseline_commit"],
                "--candidate-sha",
                STEP_10_CANDIDATE_COMMIT,
                "--in-tree",
                STEP_10_EVIDENCE_BUNDLES["in_tree"],
                "--external-uds",
                STEP_10_EVIDENCE_BUNDLES["external_uds"],
                "--output",
                str(reproduced),
            ],
            cwd=REPO_ROOT,
            check=True,
        )
        assert reproduced.read_bytes() == COMPUTE_BOUNDARY_PATH.read_bytes()


def test_step_11_records_cross_cutting_live_lane_dispositions() -> None:
    results = {
        result["id"]: result
        for result in load_toml(RESULTS_PATH)["result"]
        if result["step"] == 11
    }
    dispositions = {
        entry["id"]: entry
        for entry in load_toml(CROSS_CUTTING_DISPOSITIONS_PATH)["capabilities"]
    }

    assert set(results) == REQUIRED_STEP_11_IDS
    assert set(dispositions) == REQUIRED_STEP_11_IDS
    for result_id, result in results.items():
        disposition = dispositions[result_id]
        assert result["status"] == "platform_blocked"
        for field in ("status", "owner", "lane", "blocker"):
            assert result[field] == disposition[field]


def test_step_12_keeps_real_package_upgrade_lanes_blocked() -> None:
    results = [
        result for result in load_toml(RESULTS_PATH)["result"] if result["step"] == 12
    ]

    assert {result["id"] for result in results} == REQUIRED_STEP_12_IDS
    assert all(result["status"] == "platform_blocked" for result in results)
    by_id = {result["id"]: result for result in results}

    rpm = by_id["rpm-package-upgrade"]
    assert rpm["owner"] == "OpenShell RPM package upgrade CI lane"
    assert rpm["lane"] == "fedora-rpm-prior-release-upgrade"
    assert "prior RPM" in rpm["blocker"]
    assert "installed and upgraded" in rpm["blocker"]

    debian = by_id["debian-package-upgrade"]
    assert debian["owner"] == "OpenShell Debian package upgrade CI lane"
    assert debian["lane"] == "ubuntu-debian-prior-release-upgrade"
    assert "installed prior Debian artifact" in debian["blocker"]
    assert "source-tree tests" in debian["blocker"]

    snap = by_id["snap-package-refresh"]
    assert snap["owner"] == "OpenShell Snap refresh CI lane"
    assert snap["lane"] == "ubuntu-snap-prior-release-refresh"
    assert "refresh confined Snap revisions" in snap["blocker"]
    assert "source-tree tests" in snap["blocker"]

    homebrew = by_id["homebrew-package-upgrade"]
    assert homebrew["owner"] == "OpenShell macOS Homebrew package upgrade CI lane"
    assert homebrew["lane"] == "macos-homebrew-prior-release-upgrade"
    assert "prior-release upgrade" in homebrew["blocker"]
    assert "Linux host" in homebrew["blocker"]


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
