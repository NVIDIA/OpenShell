# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Exercise the retained-artifact verifier used by schema-v2 Step 10."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFIER_PATH = REPO_ROOT / "e2e/parity/verify-results.py"
BASELINE_SHA = "1" * 40
CANDIDATE_SHA = "2" * 40
IMAGE_ID = "3" * 64
IMAGE_DIGEST = f"sha256:{'4' * 64}"
RUNTIME_IMAGE = f"localhost/openshell/supervisor@{IMAGE_DIGEST}"
BASE_RUNTIME_IMAGE = f"docker.io/library/alpine@{IMAGE_DIGEST}"


def load_verifier() -> ModuleType:
    spec = importlib.util.spec_from_file_location("parity_verifier", VERIFIER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def create_variant(
    verifier: ModuleType,
    results_dir: Path,
    variant: str,
    source_sha: str,
    schema_version: int,
) -> None:
    artifact_dir = results_dir / "artifacts" / variant
    artifact_dir.mkdir(parents=True)
    artifacts = {
        "gateway": f"{variant}-gateway",
        "cli": f"{variant}-cli",
        "conformance": f"{variant}-conformance",
        "supervisor": f"{variant}-supervisor",
        "supervisor.Dockerfile": f"{variant}-dockerfile",
        "external-driver": f"{variant}-external-driver",
        "supervisor.packages.txt": "fixture-package-1.0-r0\n",
    }
    for filename, content in artifacts.items():
        (artifact_dir / filename).write_text(content, encoding="utf-8")

    write_json(
        results_dir / f"{variant}.json",
        {
            "variant": variant,
            "source_sha": source_sha,
            "schema_version": schema_version,
            "driver": "podman",
            "scenario": "external-driver",
            "gateway_profile": "driver-free",
            "gateway_cargo_features": "--no-default-features --features telemetry",
            "gateway_origin": "built_by_harness",
            "cli_origin": "built_by_harness",
            "conformance_origin": "built_by_harness",
            "external_driver_origin": "built_by_harness",
            "supervisor_origin": "built_by_harness",
            "gateway_sha256": verifier.sha256(artifact_dir / "gateway"),
            "cli_sha256": verifier.sha256(artifact_dir / "cli"),
            "conformance_sha256": verifier.sha256(artifact_dir / "conformance"),
            "supervisor_sha256": verifier.sha256(artifact_dir / "supervisor"),
            "supervisor_dockerfile_sha256": verifier.sha256(
                artifact_dir / "supervisor.Dockerfile"
            ),
            "external_driver_sha256": verifier.sha256(artifact_dir / "external-driver"),
            "success": True,
        },
    )
    selector = (
        'compute_drivers = ["podman"]'
        if schema_version == 1
        else 'compute_driver = "podman"'
    )
    (results_dir / f"{variant}.gateway.toml").write_text(
        f"""[openshell]
version = {schema_version}
[openshell.gateway]
{selector}
[openshell.drivers.podman]
socket_path = "/tmp/{variant}.sock"
""",
        encoding="utf-8",
    )
    policy = "missing" if schema_version == 1 else "if_not_present"
    package_hash = verifier.sha256(artifact_dir / "supervisor.packages.txt")
    result = json.loads((results_dir / f"{variant}.json").read_text(encoding="utf-8"))
    write_json(
        results_dir / f"{variant}.launch.json",
        {
            "schema_version": schema_version,
            "gateway_port": 18181,
            "external_compute_driver": True,
            "compute_driver_transport": "remote_uds",
            "external_driver_pull_policy": policy,
            "supervisor_image_id": IMAGE_ID,
            "supervisor_image_digest": IMAGE_DIGEST,
            "supervisor_runtime_image": RUNTIME_IMAGE,
            "supervisor_base_image": "alpine:fixture",
            "supervisor_base_image_id": IMAGE_ID,
            "supervisor_base_image_digest": IMAGE_DIGEST,
            "supervisor_base_runtime_image": BASE_RUNTIME_IMAGE,
            "supervisor_package_manifest_sha256": package_hash,
            "sandbox_image_request": "example.invalid/sandbox@" + IMAGE_DIGEST,
            "sandbox_image_id": IMAGE_ID,
            "sandbox_image_digest": IMAGE_DIGEST,
            "sandbox_runtime_image": "example.invalid/sandbox@" + IMAGE_DIGEST,
            "sandbox_client_image_alias": "example.invalid/sandbox:latest",
            "sandbox_client_image_alias_id": IMAGE_ID,
            "gateway_sha256_before_execution": result["gateway_sha256"],
            "cli_sha256_before_execution": result["cli_sha256"],
            "conformance_sha256_before_execution": result["conformance_sha256"],
            "external_driver_sha256_before_execution": result["external_driver_sha256"],
            "supervisor_sha256_before_execution": result["supervisor_sha256"],
            "supervisor_dockerfile_sha256_before_execution": result[
                "supervisor_dockerfile_sha256"
            ],
            "external_driver_grpc_endpoint": "https://host.containers.internal:18181",
            "external_driver_host_gateway_ip": "host-gateway",
            "external_driver_userns": None,
            "external_driver_spiffe": False,
            "external_driver_proxy": False,
            "external_driver_app_armor": False,
        },
    )
    lifecycle = "\n".join(
        f"[run fixture{marker} in 1ms: exit 0" for marker in verifier.ORACLE_MARKERS
    )
    (results_dir / f"{variant}.log").write_text(
        f"{lifecycle}\n{RUNTIME_IMAGE} {BASE_RUNTIME_IMAGE} example.invalid/sandbox@{IMAGE_DIGEST} example.invalid/sandbox:latest "
        f'{IMAGE_ID} {IMAGE_DIGEST} {package_hash}\n"passed": true\n',
        encoding="utf-8",
    )


def create_external_bundle(verifier: ModuleType, results_dir: Path) -> None:
    create_variant(verifier, results_dir, "baseline", BASELINE_SHA, 1)
    create_variant(verifier, results_dir, "candidate", CANDIDATE_SHA, 2)
    write_json(
        results_dir / "comparison.json",
        {
            "scenario": "external-driver",
            "baseline_success": True,
            "candidate_success": True,
            "parity": True,
            "accepted": True,
            "classification": "pass",
        },
    )


def test_verifier_recomputes_retained_artifact_hashes(tmp_path: Path) -> None:
    verifier = load_verifier()
    create_external_bundle(verifier, tmp_path)

    report = verifier.verify_topology(
        tmp_path, BASELINE_SHA, CANDIDATE_SHA, "external-driver"
    )
    assert report["baseline"]["artifacts_verified"] is True
    assert report["candidate"]["raw_output_verified"] is True

    (tmp_path / "artifacts/candidate/gateway").write_text(
        "mutated after execution", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="retained artifact hash mismatch"):
        verifier.verify_topology(
            tmp_path, BASELINE_SHA, CANDIDATE_SHA, "external-driver"
        )


def test_verifier_rejects_mutable_sandbox_request(tmp_path: Path) -> None:
    verifier = load_verifier()
    create_external_bundle(verifier, tmp_path)
    launch_path = tmp_path / "candidate.launch.json"
    launch = json.loads(launch_path.read_text(encoding="utf-8"))
    launch["sandbox_image_request"] = "example.invalid/sandbox:latest"
    write_json(launch_path, launch)

    with pytest.raises(
        ValueError, match="request was not the resolved digest reference"
    ):
        verifier.verify_topology(
            tmp_path, BASELINE_SHA, CANDIDATE_SHA, "external-driver"
        )


def test_verifier_rejects_different_sandbox_artifacts(tmp_path: Path) -> None:
    verifier = load_verifier()
    create_external_bundle(verifier, tmp_path)
    launch_path = tmp_path / "candidate.launch.json"
    launch = json.loads(launch_path.read_text(encoding="utf-8"))
    other_id = "5" * 64
    other_digest = f"sha256:{'6' * 64}"
    other_runtime = f"example.invalid/sandbox@{other_digest}"
    launch.update(
        {
            "sandbox_image_request": other_runtime,
            "sandbox_image_id": other_id,
            "sandbox_image_digest": other_digest,
            "sandbox_runtime_image": other_runtime,
            "sandbox_client_image_alias_id": other_id,
        }
    )
    write_json(launch_path, launch)
    with (tmp_path / "candidate.log").open("a", encoding="utf-8") as log:
        log.write(f"{other_id} {other_digest} {other_runtime}\n")

    with pytest.raises(ValueError, match="sandbox image ID differ"):
        verifier.verify_topology(
            tmp_path, BASELINE_SHA, CANDIDATE_SHA, "external-driver"
        )


def test_verifier_rejects_different_supervisor_packages(tmp_path: Path) -> None:
    verifier = load_verifier()
    create_external_bundle(verifier, tmp_path)
    package_path = tmp_path / "artifacts/candidate/supervisor.packages.txt"
    package_path.write_text("fixture-package-2.0-r0\n", encoding="utf-8")
    package_hash = verifier.sha256(package_path)
    launch_path = tmp_path / "candidate.launch.json"
    launch = json.loads(launch_path.read_text(encoding="utf-8"))
    launch["supervisor_package_manifest_sha256"] = package_hash
    write_json(launch_path, launch)
    with (tmp_path / "candidate.log").open("a", encoding="utf-8") as log:
        log.write(f"{package_hash}\n")

    with pytest.raises(ValueError, match="supervisor package manifest differ"):
        verifier.verify_topology(
            tmp_path, BASELINE_SHA, CANDIDATE_SHA, "external-driver"
        )


def test_verifier_rejects_cross_topology_sandbox_drift() -> None:
    verifier = load_verifier()
    launch = {
        "sandbox_image_id": IMAGE_ID,
        "sandbox_image_digest": IMAGE_DIGEST,
        "sandbox_runtime_image": "example.invalid/sandbox@" + IMAGE_DIGEST,
        "sandbox_client_image_alias": "example.invalid/sandbox:latest",
        "sandbox_client_image_alias_id": IMAGE_ID,
        "supervisor_base_image": "alpine:fixture",
        "supervisor_base_image_id": IMAGE_ID,
        "supervisor_base_image_digest": IMAGE_DIGEST,
        "supervisor_base_runtime_image": BASE_RUNTIME_IMAGE,
        "supervisor_package_manifest_sha256": "7" * 64,
    }
    in_tree = {
        "baseline": {"launch_attestation": dict(launch)},
        "candidate": {"launch_attestation": dict(launch)},
    }
    external = {
        "baseline": {"launch_attestation": dict(launch)},
        "candidate": {"launch_attestation": dict(launch)},
    }
    external["candidate"]["launch_attestation"]["sandbox_image_id"] = "8" * 64

    with pytest.raises(ValueError, match="four runs use different sandbox artifact"):
        verifier.verify_four_run_provenance(in_tree, external)
