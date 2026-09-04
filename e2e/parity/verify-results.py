#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Verify retained parity evidence and emit its normalized comparison."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tomllib
from pathlib import Path
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_REFERENCE_RE = re.compile(r"^[^@]+@sha256:([0-9a-f]{64})$")
ARTIFACT_FIELDS = {
    "gateway_sha256": "gateway",
    "cli_sha256": "cli",
    "conformance_sha256": "conformance",
    "supervisor_sha256": "supervisor",
    "supervisor_dockerfile_sha256": "supervisor.Dockerfile",
}
ORACLE_MARKERS = (
    "][smoke/status] completed",
    "][smoke/create] completed",
    "][smoke/get-ready] completed",
    "][smoke/list-visible/0] completed",
    "][smoke/exec] completed",
    "][smoke/delete] completed",
    "][smoke/list-empty/query/0] completed",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify_variant(
    results_dir: Path,
    variant: str,
    expected_sha: str,
    schema_version: int,
    scenario: str,
) -> dict[str, Any]:
    result_path = results_dir / f"{variant}.json"
    launch_path = results_dir / f"{variant}.launch.json"
    log_path = results_dir / f"{variant}.log"
    config_path = results_dir / f"{variant}.gateway.toml"
    result = load_json(result_path)
    launch = load_json(launch_path)
    require(config_path.is_file(), f"{config_path}: retained gateway config is missing")
    with config_path.open("rb") as config_file:
        config = tomllib.load(config_file)

    require(result.get("variant") == variant, f"{result_path}: variant mismatch")
    require(
        result.get("source_sha") == expected_sha, f"{result_path}: source SHA mismatch"
    )
    require(
        result.get("schema_version") == schema_version,
        f"{result_path}: schema mismatch",
    )
    require(result.get("scenario") == scenario, f"{result_path}: scenario mismatch")
    require(result.get("driver") == "podman", f"{result_path}: driver mismatch")
    expected_profile = "driver-free" if scenario == "external-driver" else "in-tree"
    expected_features = (
        "--no-default-features --features telemetry"
        if scenario == "external-driver"
        else "default"
    )
    require(
        result.get("gateway_profile") == expected_profile,
        f"{result_path}: gateway profile mismatch",
    )
    require(
        result.get("gateway_cargo_features") == expected_features,
        f"{result_path}: gateway feature profile mismatch",
    )
    require(result.get("success") is True, f"{result_path}: parity oracle did not pass")
    require(
        result.get("gateway_origin") == "built_by_harness",
        f"{result_path}: gateway was not built by the harness",
    )
    require(
        result.get("cli_origin") == "built_by_harness",
        f"{result_path}: CLI was not built by the harness",
    )
    require(
        result.get("conformance_origin") == "built_by_harness",
        f"{result_path}: conformance runner was not built by the harness",
    )
    require(
        result.get("supervisor_origin") == "built_by_harness",
        f"{result_path}: supervisor was not built by the harness",
    )

    external = scenario == "external-driver"
    expected_driver_origin = "built_by_harness" if external else "not_applicable"
    require(
        result.get("external_driver_origin") == expected_driver_origin,
        f"{result_path}: external driver origin mismatch",
    )
    require(
        launch.get("schema_version") == schema_version,
        f"{launch_path}: schema mismatch",
    )
    require(
        launch.get("external_compute_driver") is external,
        f"{launch_path}: topology mismatch",
    )
    expected_transport = "remote_uds" if external else "in_tree"
    require(
        launch.get("compute_driver_transport") == expected_transport,
        f"{launch_path}: transport mismatch",
    )
    expected_policy = "missing" if schema_version == 1 else "if_not_present"
    require(
        launch.get("external_driver_pull_policy") == expected_policy,
        f"{launch_path}: pull-policy mismatch",
    )

    openshell = config.get("openshell", {})
    gateway = openshell.get("gateway", {})
    podman_config = openshell.get("drivers", {}).get("podman", {})
    require(
        openshell.get("version") == schema_version, f"{config_path}: schema mismatch"
    )
    expected_selector = ["podman"] if schema_version == 1 else "podman"
    selector_field = "compute_drivers" if schema_version == 1 else "compute_driver"
    require(
        gateway.get(selector_field) == expected_selector,
        f"{config_path}: selected compute driver mismatch",
    )
    require(isinstance(podman_config, dict), f"{config_path}: Podman table is missing")
    if external:
        require(
            set(podman_config) == {"socket_path"},
            f"{config_path}: external gateway Podman table is not transport-only",
        )
    else:
        required_runtime_fields = {
            "socket_path",
            "network_name",
            "default_image",
            "image_pull_policy",
            "supervisor_image",
        }
        require(
            set(podman_config) >= required_runtime_fields,
            f"{config_path}: in-tree Podman runtime fields are incomplete",
        )
        require(
            DIGEST_REFERENCE_RE.fullmatch(podman_config["default_image"]) is not None,
            f"{config_path}: sandbox image is not digest-pinned",
        )
        require(
            DIGEST_REFERENCE_RE.fullmatch(podman_config["supervisor_image"])
            is not None,
            f"{config_path}: supervisor image is not digest-pinned",
        )

    artifact_fields = dict(ARTIFACT_FIELDS)
    if external:
        artifact_fields["external_driver_sha256"] = "external-driver"
    artifact_hashes: dict[str, str] = {}
    for field, filename in artifact_fields.items():
        expected_hash = result.get(field)
        require(
            isinstance(expected_hash, str)
            and SHA256_RE.fullmatch(expected_hash) is not None,
            f"{result_path}: invalid {field}",
        )
        artifact_path = results_dir / "artifacts" / variant / filename
        require(
            artifact_path.is_file(), f"{artifact_path}: retained artifact is missing"
        )
        actual_hash = sha256(artifact_path)
        require(
            actual_hash == expected_hash,
            f"{artifact_path}: retained artifact hash mismatch",
        )
        artifact_hashes[filename] = actual_hash

    image_id = launch.get("supervisor_image_id")
    image_digest = launch.get("supervisor_image_digest")
    runtime_image = launch.get("supervisor_runtime_image")
    require(
        isinstance(image_id, str) and SHA256_RE.fullmatch(image_id) is not None,
        f"{launch_path}: invalid supervisor image ID",
    )
    require(
        isinstance(image_digest, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest) is not None,
        f"{launch_path}: invalid supervisor image digest",
    )
    match = (
        DIGEST_REFERENCE_RE.fullmatch(runtime_image)
        if isinstance(runtime_image, str)
        else None
    )
    require(
        match is not None,
        f"{launch_path}: supervisor runtime image is not digest-pinned",
    )
    require(
        f"sha256:{match.group(1)}" == image_digest,
        f"{launch_path}: runtime reference digest mismatch",
    )

    sandbox_id = launch.get("sandbox_image_id")
    sandbox_digest = launch.get("sandbox_image_digest")
    sandbox_runtime = launch.get("sandbox_runtime_image")
    sandbox_match = (
        DIGEST_REFERENCE_RE.fullmatch(sandbox_runtime)
        if isinstance(sandbox_runtime, str)
        else None
    )
    require(
        isinstance(sandbox_id, str) and SHA256_RE.fullmatch(sandbox_id) is not None,
        f"{launch_path}: invalid sandbox image ID",
    )
    require(
        isinstance(sandbox_digest, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", sandbox_digest) is not None,
        f"{launch_path}: invalid sandbox image digest",
    )
    require(
        sandbox_match is not None
        and f"sha256:{sandbox_match.group(1)}" == sandbox_digest,
        f"{launch_path}: sandbox runtime image is not digest-pinned",
    )
    if not external:
        require(
            podman_config["default_image"] == sandbox_runtime
            and podman_config["supervisor_image"] == runtime_image,
            f"{config_path}: runtime image references differ from launch evidence",
        )

    for field in ("supervisor_base_image_id", "supervisor_package_manifest_sha256"):
        value = launch.get(field)
        require(
            isinstance(value, str) and SHA256_RE.fullmatch(value) is not None,
            f"{launch_path}: invalid {field}",
        )
    base_digest = launch.get("supervisor_base_image_digest")
    require(
        isinstance(base_digest, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", base_digest) is not None,
        f"{launch_path}: invalid supervisor base-image digest",
    )
    package_path = results_dir / "artifacts" / variant / "supervisor.packages.txt"
    require(package_path.is_file(), f"{package_path}: package manifest is missing")
    require(
        sha256(package_path) == launch["supervisor_package_manifest_sha256"],
        f"{package_path}: package manifest hash mismatch",
    )
    artifact_hashes["supervisor.packages.txt"] = sha256(package_path)

    require(log_path.is_file(), f"{log_path}: retained raw log is missing")
    raw_log = log_path.read_text(encoding="utf-8", errors="replace")
    for marker in ORACLE_MARKERS:
        require(
            re.search(re.escape(marker) + r".*exit 0", raw_log) is not None,
            f"{log_path}: missing successful lifecycle oracle marker {marker}",
        )
    require(
        '"passed": true' in raw_log,
        f"{log_path}: missing successful conformance result",
    )
    launch_markers = (
        runtime_image,
        image_id,
        image_digest,
        sandbox_runtime,
        sandbox_id,
        sandbox_digest,
        launch["supervisor_base_image_id"],
        base_digest,
        launch["supervisor_package_manifest_sha256"],
    )
    require(
        all(marker in raw_log for marker in launch_markers),
        f"{log_path}: launch provenance is absent from raw output",
    )

    return {
        "schema_version": schema_version,
        "source_sha": expected_sha,
        "gateway_profile": result["gateway_profile"],
        "gateway_cargo_features": result["gateway_cargo_features"],
        "artifact_origins": {
            "gateway": result["gateway_origin"],
            "cli": result["cli_origin"],
            "conformance": result["conformance_origin"],
            "external_driver": result["external_driver_origin"],
            "supervisor": result["supervisor_origin"],
        },
        "artifact_sha256": artifact_hashes,
        "launch_attestation": launch,
        "raw_evidence_sha256": {
            result_path.name: sha256(result_path),
            launch_path.name: sha256(launch_path),
            log_path.name: sha256(log_path),
            config_path.name: sha256(config_path),
        },
        "artifacts_verified": True,
        "raw_output_verified": True,
        "success": True,
    }


def verify_topology(
    results_dir: Path,
    baseline_sha: str,
    candidate_sha: str,
    scenario: str,
) -> dict[str, Any]:
    comparison_path = results_dir / "comparison.json"
    comparison = load_json(comparison_path)
    require(
        comparison.get("scenario") == scenario, f"{comparison_path}: scenario mismatch"
    )
    for field in ("baseline_success", "candidate_success", "parity", "accepted"):
        require(
            comparison.get(field) is True, f"{comparison_path}: {field} is not true"
        )
    require(
        comparison.get("classification") == "pass",
        f"{comparison_path}: classification is not pass",
    )

    baseline = verify_variant(results_dir, "baseline", baseline_sha, 1, scenario)
    candidate = verify_variant(results_dir, "candidate", candidate_sha, 2, scenario)
    if scenario == "external-driver":
        baseline_driver = results_dir / "artifacts/baseline/external-driver"
        candidate_driver = results_dir / "artifacts/candidate/external-driver"
        require(
            baseline_driver.resolve() != candidate_driver.resolve(),
            "external-driver artifacts resolve to the same path",
        )
        require(
            not baseline_driver.samefile(candidate_driver),
            "external-driver artifacts share an inode",
        )
        require(
            baseline["artifact_sha256"]["external-driver"]
            != candidate["artifact_sha256"]["external-driver"],
            "external-driver artifacts have identical content",
        )

    return {
        "baseline": baseline,
        "candidate": candidate,
        "comparison_sha256": sha256(comparison_path),
        "classification": "pass",
        "parity": True,
        "accepted": True,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-sha", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--in-tree", required=True, type=Path)
    parser.add_argument("--external-uds", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    require(
        re.fullmatch(r"[0-9a-f]{40}", args.baseline_sha) is not None,
        "invalid baseline SHA",
    )
    require(
        re.fullmatch(r"[0-9a-f]{40}", args.candidate_sha) is not None,
        "invalid candidate SHA",
    )

    report = {
        "manifest_version": 2,
        "baseline_commit": args.baseline_sha,
        "candidate_commit": args.candidate_sha,
        "lane": "local-linux-x86_64-rootless-podman-5.8.2",
        "oracle": {
            "status": True,
            "create": True,
            "ready": True,
            "list_visible": True,
            "callback_exec_exact_marker": True,
            "delete": True,
            "list_empty": True,
        },
        "in_tree": verify_topology(
            args.in_tree, args.baseline_sha, args.candidate_sha, "smoke"
        ),
        "external_uds": verify_topology(
            args.external_uds, args.baseline_sha, args.candidate_sha, "external-driver"
        ),
        "callback_listener": {
            "in_tree_baseline_exec": True,
            "in_tree_candidate_exec": True,
            "external_baseline_exec": True,
            "external_candidate_exec": True,
            "classification": "pass",
        },
        "classification": "pass",
        "accepted": True,
        "verification": {
            "retained_artifact_hashes_recomputed": True,
            "raw_lifecycle_output_inspected": True,
            "digest_pinned_supervisor_runtime_verified": True,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
