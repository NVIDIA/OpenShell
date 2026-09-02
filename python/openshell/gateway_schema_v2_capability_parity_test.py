# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Validate the schema-v2 live capability-parity manifest without a runtime."""

from __future__ import annotations

import tomllib
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "e2e/configs/gateway/schema-v2-capability-parity.toml"

REQUIRED_MANIFEST_FIELDS = {
    "manifest_version",
    "baseline_ref",
    "baseline_schema_version",
    "candidate_ref",
    "candidate_schema_version",
    "capabilities",
}
REQUIRED_CAPABILITY_FIELDS = {
    "id",
    "topics",
    "origin_main_access_paths",
    "schema_v2_access_paths",
    "behavioral_oracle",
    "required_environment",
    "test_lane",
    "status",
}
REQUIRED_TOPICS = {
    "auth_tls_jwt",
    "configuration_producers",
    "credentials",
    "database",
    "docker",
    "external_drivers",
    "inference",
    "interceptors",
    "kubernetes",
    "listeners",
    "middleware",
    "mxc",
    "observability",
    "packaging_upgrades",
    "podman",
    "vm",
}
REQUIRED_CAPABILITY_IDS = {
    "configuration-source-precedence",
    "schema-version-and-strict-layout",
    "gateway-identity-and-logging",
    "primary-health-and-metrics-listeners",
    "database-url-and-persistence-backends",
    "ssh-rate-limit-and-policy-posture",
    "sandbox-service-routing",
    "gateway-listener-tls-and-sni",
    "plaintext-listener-mode",
    "guest-callback-tls-ownership",
    "oidc-bearer-authentication",
    "mtls-user-authentication",
    "unsafe-unauthenticated-user-mode",
    "gateway-minted-sandbox-jwt",
    "otlp-observability",
    "gateway-interceptor-registration",
    "supervisor-middleware-registration",
    "provider-profile-sources",
    "inference-control-plane-configuration",
    "credential-driver-selection-and-kek",
    "credential-driver-backend-tables",
    "docker-image-and-callback-configuration",
    "docker-security-and-provider-configuration",
    "podman-image-and-callback-configuration",
    "podman-runtime-security-and-health",
    "kubernetes-core-placement-and-images",
    "kubernetes-workspace-isolation",
    "kubernetes-supervisor-topology",
    "kubernetes-egress-spiffe-and-security",
    "vm-launch-and-resource-configuration",
    "vm-guest-security-and-spiffe",
    "mxc-windows-driver-configuration",
    "external-compute-driver-socket",
    "helm-configuration-producer",
    "local-launch-script-producers",
    "e2e-fixture-producers",
    "rpm-schema-upgrade",
    "homebrew-debian-and-snap-upgrades",
}
ALLOWED_LANES = {
    "deterministic",
    "e2e-docker",
    "e2e-podman",
    "e2e-kubernetes",
    "e2e-vm",
    "windows-mxc",
    "extension-driver",
    "auth-oidc",
    "observability",
    "packaging",
}
# This inventory plans execution. Live results belong in the execution record,
# not in this baseline manifest, so a PASS cannot be accidentally implied.
ALLOWED_STATUSES = {"not_run", "blocked", "planned"}


def load_manifest() -> dict[str, Any]:
    with MANIFEST_PATH.open("rb") as manifest_file:
        return tomllib.load(manifest_file)


def require_nonempty_string(value: Any, field: str, entry_id: str) -> None:
    assert isinstance(value, str) and value.strip(), (
        f"{entry_id}: {field} is required"
    )


def require_string_list(value: Any, field: str, entry_id: str) -> None:
    assert isinstance(value, list) and value, f"{entry_id}: {field} must be non-empty"
    assert all(isinstance(item, str) and item.strip() for item in value), (
        f"{entry_id}: {field} must contain only non-empty strings"
    )
    assert len(value) == len(set(value)), f"{entry_id}: {field} contains duplicates"


def validate_manifest(manifest: dict[str, Any]) -> None:
    assert set(manifest) == REQUIRED_MANIFEST_FIELDS, (
        "unexpected or missing manifest metadata"
    )
    assert manifest["manifest_version"] == 1
    assert manifest["baseline_ref"] == "origin/main"
    assert manifest["baseline_schema_version"] == 1
    assert manifest["candidate_ref"] == "HEAD"
    assert manifest["candidate_schema_version"] == 2

    capabilities = manifest["capabilities"]
    assert isinstance(capabilities, list) and capabilities, (
        "capabilities must be non-empty"
    )
    ids: list[str] = []
    topics: set[str] = set()
    for capability in capabilities:
        assert isinstance(capability, dict), "each capability must be a TOML table"
        assert set(capability) == REQUIRED_CAPABILITY_FIELDS, (
            "capability has unexpected or missing metadata"
        )
        entry_id = capability["id"]
        require_nonempty_string(entry_id, "id", "capability")
        ids.append(entry_id)
        require_string_list(capability["topics"], "topics", entry_id)
        topics.update(capability["topics"])
        require_string_list(
            capability["origin_main_access_paths"],
            "origin_main_access_paths",
            entry_id,
        )
        require_string_list(
            capability["schema_v2_access_paths"],
            "schema_v2_access_paths",
            entry_id,
        )
        require_nonempty_string(
            capability["behavioral_oracle"], "behavioral_oracle", entry_id
        )
        require_nonempty_string(
            capability["required_environment"], "required_environment", entry_id
        )
        assert capability["test_lane"] in ALLOWED_LANES, (
            f"{entry_id}: unknown test lane {capability['test_lane']!r}"
        )
        assert capability["status"] in ALLOWED_STATUSES, (
            f"{entry_id}: live PASS results are not valid in this planning manifest"
        )

    assert len(ids) == len(set(ids)), "capability IDs must be unique"
    assert set(ids) == REQUIRED_CAPABILITY_IDS, (
        "capability inventory is incomplete or stale"
    )
    assert topics == REQUIRED_TOPICS, (
        "topic inventory is incomplete or contains an unknown topic"
    )


def test_schema_v2_capability_parity_manifest_is_well_formed() -> None:
    validate_manifest(load_manifest())


@pytest.mark.parametrize("field", sorted(REQUIRED_MANIFEST_FIELDS - {"capabilities"}))
def test_manifest_rejects_missing_header_metadata(field: str) -> None:
    manifest = deepcopy(load_manifest())
    del manifest[field]

    with pytest.raises(AssertionError, match="missing manifest metadata"):
        validate_manifest(manifest)


@pytest.mark.parametrize("field", sorted(REQUIRED_CAPABILITY_FIELDS - {"id"}))
def test_manifest_rejects_missing_capability_metadata(field: str) -> None:
    manifest = deepcopy(load_manifest())
    del manifest["capabilities"][0][field]

    with pytest.raises(AssertionError, match="metadata|required|must be"):
        validate_manifest(manifest)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("topics", [], "must be non-empty"),
        ("behavioral_oracle", "", "is required"),
        ("required_environment", "", "is required"),
        ("test_lane", "not-a-lane", "unknown test lane"),
    ],
)
def test_manifest_rejects_malformed_capability_metadata(
    field: str, value: Any, match: str
) -> None:
    manifest = deepcopy(load_manifest())
    manifest["capabilities"][0][field] = value

    with pytest.raises(AssertionError, match=match):
        validate_manifest(manifest)


def test_manifest_rejects_duplicate_capability_id() -> None:
    manifest = deepcopy(load_manifest())
    manifest["capabilities"][1]["id"] = manifest["capabilities"][0]["id"]

    with pytest.raises(AssertionError, match="unique|incomplete"):
        validate_manifest(manifest)


def test_manifest_does_not_claim_live_pass_results() -> None:
    manifest = deepcopy(load_manifest())
    manifest["capabilities"][0]["status"] = "pass"

    with pytest.raises(AssertionError, match="live PASS"):
        validate_manifest(manifest)
