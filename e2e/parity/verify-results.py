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
    "cli_trace_wrapper_sha256": "cli-trace-wrapper",
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
        require(
            isinstance(podman_config["socket_path"], str)
            and Path(podman_config["socket_path"]).is_absolute(),
            f"{config_path}: external driver socket path is not absolute",
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

    sandbox_request = launch.get("sandbox_image_request")
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
    require(
        sandbox_request == sandbox_runtime,
        f"{launch_path}: sandbox image request was not the resolved digest reference",
    )
    if not external:
        require(
            podman_config["default_image"] == sandbox_runtime
            and podman_config["supervisor_image"] == runtime_image,
            f"{config_path}: runtime image references differ from launch evidence",
        )

    base_runtime = launch.get("supervisor_base_runtime_image")
    base_runtime_match = (
        DIGEST_REFERENCE_RE.fullmatch(base_runtime)
        if isinstance(base_runtime, str)
        else None
    )
    require(
        base_runtime_match is not None,
        f"{launch_path}: supervisor base runtime image is not digest-pinned",
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

    sandbox_alias = launch.get("sandbox_client_image_alias")
    require(
        isinstance(sandbox_alias, str)
        and sandbox_alias == sandbox_runtime.rsplit("@", 1)[0] + ":latest"
        and launch.get("sandbox_client_image_alias_id") == sandbox_id,
        f"{launch_path}: sandbox client alias is not bound to the pinned image",
    )

    for launch_field, result_field in (
        ("gateway_sha256_before_execution", "gateway_sha256"),
        ("cli_sha256_before_execution", "cli_sha256"),
        ("conformance_sha256_before_execution", "conformance_sha256"),
        ("supervisor_sha256_before_execution", "supervisor_sha256"),
        (
            "supervisor_dockerfile_sha256_before_execution",
            "supervisor_dockerfile_sha256",
        ),
        ("cli_trace_wrapper_sha256_before_execution", "cli_trace_wrapper_sha256"),
    ):
        require(
            launch.get(launch_field) == result.get(result_field),
            f"{launch_path}: {launch_field} does not bind the staged artifact",
        )
    if external:
        require(
            launch.get("external_driver_sha256_before_execution")
            == result.get("external_driver_sha256"),
            f"{launch_path}: external driver pre-execution hash mismatch",
        )
        gateway_port = launch.get("gateway_port")
        callback_endpoint = f"https://host.containers.internal:{gateway_port}"
        require(
            isinstance(gateway_port, int)
            and 0 < gateway_port <= 65535
            and launch.get("external_driver_grpc_endpoint") == callback_endpoint,
            f"{launch_path}: external driver callback endpoint is not isolated",
        )
        require(
            launch.get("external_driver_host_gateway_ip") == "host-gateway"
            and launch.get("external_driver_userns") is None
            and launch.get("external_driver_spiffe") is False
            and launch.get("external_driver_proxy") is False
            and launch.get("external_driver_app_armor") is False,
            f"{launch_path}: external driver effective configuration is tainted",
        )
        driver_environment = launch.get("external_driver_environment")
        expected_environment_keys = {
            "OPENSHELL_COMPUTE_DRIVER_SOCKET",
            "OPENSHELL_PODMAN_SOCKET",
            "OPENSHELL_SANDBOX_IMAGE",
            "OPENSHELL_SANDBOX_IMAGE_PULL_POLICY",
            "OPENSHELL_HEALTH_CHECK_INTERVAL_SECS",
            "OPENSHELL_GRPC_ENDPOINT",
            "OPENSHELL_GATEWAY_PORT",
            "OPENSHELL_NETWORK_NAME",
            "OPENSHELL_STOP_TIMEOUT",
            "OPENSHELL_SUPERVISOR_IMAGE",
            "OPENSHELL_PODMAN_TLS_CA",
            "OPENSHELL_PODMAN_TLS_CERT",
            "OPENSHELL_PODMAN_TLS_KEY",
            "OPENSHELL_ENABLE_BIND_MOUNTS",
        }
        require(
            isinstance(driver_environment, dict)
            and set(driver_environment) == expected_environment_keys,
            f"{launch_path}: external driver allowlisted environment is incomplete",
        )
        require(
            driver_environment["OPENSHELL_COMPUTE_DRIVER_SOCKET"]
            == podman_config["socket_path"],
            f"{launch_path}: external driver socket differs from gateway TOML",
        )
        podman_socket = driver_environment["OPENSHELL_PODMAN_SOCKET"]
        require(
            isinstance(podman_socket, str)
            and Path(podman_socket).is_absolute()
            and podman_socket != podman_config["socket_path"],
            f"{launch_path}: external driver Podman socket is not isolated",
        )
        require(
            driver_environment["OPENSHELL_SANDBOX_IMAGE"] == sandbox_runtime
            and driver_environment["OPENSHELL_SANDBOX_IMAGE_PULL_POLICY"]
            == expected_policy
            and driver_environment["OPENSHELL_HEALTH_CHECK_INTERVAL_SECS"] == 10
            and driver_environment["OPENSHELL_GRPC_ENDPOINT"] == callback_endpoint
            and driver_environment["OPENSHELL_GATEWAY_PORT"] == gateway_port
            and isinstance(driver_environment["OPENSHELL_NETWORK_NAME"], str)
            and driver_environment["OPENSHELL_NETWORK_NAME"]
            and isinstance(driver_environment["OPENSHELL_STOP_TIMEOUT"], int)
            and driver_environment["OPENSHELL_STOP_TIMEOUT"] >= 0
            and driver_environment["OPENSHELL_SUPERVISOR_IMAGE"] == runtime_image
            and driver_environment["OPENSHELL_ENABLE_BIND_MOUNTS"] is True,
            f"{launch_path}: external driver allowlisted runtime inputs differ",
        )
        tls_paths: set[str] = set()
        for field in (
            "OPENSHELL_PODMAN_TLS_CA",
            "OPENSHELL_PODMAN_TLS_CERT",
            "OPENSHELL_PODMAN_TLS_KEY",
        ):
            tls_input = driver_environment[field]
            require(
                isinstance(tls_input, dict)
                and set(tls_input) == {"path", "sha256"}
                and isinstance(tls_input["path"], str)
                and Path(tls_input["path"]).is_absolute()
                and isinstance(tls_input["sha256"], str)
                and SHA256_RE.fullmatch(tls_input["sha256"]) is not None,
                f"{launch_path}: invalid external driver callback TLS input {field}",
            )
            tls_paths.add(tls_input["path"])
        require(
            len(tls_paths) == 3,
            f"{launch_path}: external driver callback TLS paths are not distinct",
        )
    else:
        require(
            launch.get("external_driver_sha256_before_execution") == "",
            f"{launch_path}: unexpected external driver hash",
        )

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
    require(
        re.search(
            r"gateway preflight connected: .*authentication=authenticated(?:\n|$)",
            raw_log,
        )
        is not None,
        f"{log_path}: authenticated gateway preflight is missing",
    )
    run_ids = re.findall(
        r"^CLI conformance run ID: ([a-z0-9]+)$", raw_log, re.MULTILINE
    )
    require(
        len(run_ids) == 1,
        f"{log_path}: expected exactly one conformance run ID",
    )
    exec_stdout_path = results_dir / f"{variant}.exec.stdout"
    require(
        exec_stdout_path.is_file(),
        f"{exec_stdout_path}: retained exec stdout is missing",
    )
    expected_exec_stdout = f"openshell-conformance-{run_ids[0]}\n".encode()
    require(
        exec_stdout_path.read_bytes() == expected_exec_stdout,
        f"{exec_stdout_path}: callback exec stdout is not the exact marker",
    )
    launch_markers = (
        runtime_image,
        image_id,
        image_digest,
        sandbox_runtime,
        sandbox_id,
        sandbox_digest,
        sandbox_alias,
        launch["sandbox_client_image_alias_id"],
        launch["supervisor_base_image_id"],
        base_digest,
        base_runtime,
        launch["supervisor_package_manifest_sha256"],
    )
    require(
        all(marker in raw_log for marker in launch_markers),
        f"{log_path}: launch provenance is absent from raw output",
    )

    raw_evidence_hashes = {
        result_path.name: sha256(result_path),
        launch_path.name: sha256(launch_path),
        log_path.name: sha256(log_path),
        config_path.name: sha256(config_path),
        exec_stdout_path.name: sha256(exec_stdout_path),
    }
    if external:
        driver_log_path = results_dir / f"{variant}.driver.log"
        require(
            driver_log_path.is_file() and driver_log_path.stat().st_size > 0,
            f"{driver_log_path}: retained external driver log is missing or empty",
        )
        raw_evidence_hashes[driver_log_path.name] = sha256(driver_log_path)

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
        "raw_evidence_sha256": raw_evidence_hashes,
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
    baseline_launch = baseline["launch_attestation"]
    candidate_launch = candidate["launch_attestation"]
    for field, label in (
        ("sandbox_image_id", "sandbox image ID"),
        ("sandbox_image_digest", "sandbox image digest"),
        ("sandbox_runtime_image", "sandbox runtime image"),
        ("supervisor_base_image", "supervisor base image"),
        ("supervisor_base_image_id", "supervisor base-image ID"),
        ("supervisor_base_image_digest", "supervisor base-image digest"),
        ("supervisor_package_manifest_sha256", "supervisor package manifest"),
    ):
        require(
            baseline_launch.get(field) == candidate_launch.get(field),
            f"baseline and candidate {label} differ",
        )
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
        baseline_env = baseline_launch["external_driver_environment"]
        candidate_env = candidate_launch["external_driver_environment"]
        for field, label in (
            ("OPENSHELL_COMPUTE_DRIVER_SOCKET", "compute-driver UDS"),
            ("OPENSHELL_PODMAN_SOCKET", "Podman API UDS"),
            ("OPENSHELL_NETWORK_NAME", "Podman network"),
        ):
            require(
                baseline_env[field] != candidate_env[field],
                f"baseline and candidate reuse the same external {label}",
            )
        for field in (
            "OPENSHELL_PODMAN_TLS_CA",
            "OPENSHELL_PODMAN_TLS_CERT",
            "OPENSHELL_PODMAN_TLS_KEY",
        ):
            require(
                baseline_env[field]["path"] != candidate_env[field]["path"],
                "baseline and candidate reuse the same external callback TLS path",
            )

    return {
        "baseline": baseline,
        "candidate": candidate,
        "comparison_sha256": sha256(comparison_path),
        "classification": "pass",
        "parity": True,
        "accepted": True,
    }


def verify_four_run_provenance(
    in_tree: dict[str, Any], external_uds: dict[str, Any]
) -> None:
    variants = [
        in_tree["baseline"]["launch_attestation"],
        in_tree["candidate"]["launch_attestation"],
        external_uds["baseline"]["launch_attestation"],
        external_uds["candidate"]["launch_attestation"],
    ]
    for fields, label in (
        (
            (
                "sandbox_image_id",
                "sandbox_image_digest",
                "sandbox_runtime_image",
                "sandbox_client_image_alias",
                "sandbox_client_image_alias_id",
            ),
            "sandbox artifact",
        ),
        (
            (
                "supervisor_base_image",
                "supervisor_base_image_id",
                "supervisor_base_image_digest",
                "supervisor_base_runtime_image",
                "supervisor_package_manifest_sha256",
            ),
            "supervisor dependency provenance",
        ),
    ):
        tuples = {tuple(launch.get(field) for field in fields) for launch in variants}
        require(len(tuples) == 1, f"the four runs use different {label}")

    for variant in ("baseline", "candidate"):
        in_tree_artifacts = in_tree[variant]["artifact_sha256"]
        external_artifacts = external_uds[variant]["artifact_sha256"]
        for artifact in (
            "cli",
            "conformance",
            "supervisor",
            "supervisor.Dockerfile",
            "cli-trace-wrapper",
        ):
            require(
                in_tree_artifacts[artifact] == external_artifacts[artifact],
                f"{variant} {artifact} differs across topologies",
            )


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

    in_tree = verify_topology(
        args.in_tree, args.baseline_sha, args.candidate_sha, "smoke"
    )
    external_uds = verify_topology(
        args.external_uds, args.baseline_sha, args.candidate_sha, "external-driver"
    )
    verify_four_run_provenance(in_tree, external_uds)

    report = {
        "manifest_version": 2,
        "baseline_commit": args.baseline_sha,
        "candidate_commit": args.candidate_sha,
        "lane": "local-linux-x86_64-rootless-podman-5.8.2",
        "retained_evidence_bundles": {
            "in_tree": args.in_tree.as_posix(),
            "external_uds": args.external_uds.as_posix(),
        },
        "oracle": {
            "status": True,
            "create": True,
            "ready": True,
            "list_visible": True,
            "callback_exec_exact_marker": True,
            "delete": True,
            "list_empty": True,
        },
        "in_tree": in_tree,
        "external_uds": external_uds,
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
            "authenticated_preflight_verified": True,
            "exact_callback_exec_stdout_verified": True,
            "external_driver_allowlist_verified": True,
            "external_driver_logs_retained": True,
            "external_uds_isolation_verified": True,
            "digest_pinned_supervisor_runtime_verified": True,
            "same_immutable_sandbox_verified": True,
            "supervisor_dependency_provenance_matched": True,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
