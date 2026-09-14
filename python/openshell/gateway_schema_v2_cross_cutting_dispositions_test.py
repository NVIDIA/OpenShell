# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Validate schema-v2 Step 11 cross-cutting capability dispositions."""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DISPOSITIONS_PATH = (
    REPO_ROOT / "e2e/configs/gateway/schema-v2-cross-cutting-dispositions.toml"
)
CAPABILITY_PATH = REPO_ROOT / "e2e/configs/gateway/schema-v2-capability-parity.toml"
INTENTIONAL_CHANGES_PATH = (
    REPO_ROOT / "e2e/configs/gateway/schema-v2-intentional-changes.toml"
)

STEP_11_CAPABILITY_IDS = {
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
EXPECTED_SUITES = {
    "server-lib": "cargo test -q -p openshell-server --lib",
    "gateway-interceptors": "cargo test -q -p openshell-gateway-interceptors",
    "supervisor-middleware": "cargo test -q -p openshell-supervisor-middleware",
    "otel-test-support": "cargo test -q -p openshell-otel-test-support",
    "multiplex-tls-integration": (
        "cargo test -q -p openshell-server --test multiplex_tls_integration"
    ),
    "edge-tunnel-auth": "cargo test -q -p openshell-server --test edge_tunnel_auth",
}
EXPECTED_CANDIDATE_COMMIT = "363d8540830b2ea294d43198daa2b7a283a2face"
EXPECTED_INTENTIONAL_CHANGES = {
    "gateway-jwt-zero-sentinel-removed": "gateway-minted-sandbox-jwt",
    "middleware-payload-name-normalized": "supervisor-middleware-registration",
}


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as toml_file:
        return tomllib.load(toml_file)


def assert_full_sha(value: object, field: str) -> str:
    assert isinstance(value, str), f"{field} must be a string"
    assert re.fullmatch(r"[0-9a-f]{40}", value), f"{field} must be a full SHA"
    return value


def test_step_11_dispositions_cover_exact_cross_cutting_capabilities() -> None:
    manifest = load_toml(DISPOSITIONS_PATH)

    assert set(manifest) == {
        "manifest_version",
        "baseline_commit",
        "candidate_commit",
        "overall_status",
        "deterministic_preflight",
        "capabilities",
    }
    assert manifest["manifest_version"] == 1
    assert manifest["overall_status"] == "platform_blocked"
    assert (
        assert_full_sha(manifest["baseline_commit"], "baseline_commit")
        == load_toml(CAPABILITY_PATH)["baseline_commit"]
    )
    assert (
        assert_full_sha(manifest["candidate_commit"], "candidate_commit")
        == EXPECTED_CANDIDATE_COMMIT
    )

    capabilities = manifest["capabilities"]
    assert {entry["id"] for entry in capabilities} == STEP_11_CAPABILITY_IDS
    assert len(capabilities) == len(STEP_11_CAPABILITY_IDS)
    for entry in capabilities:
        assert set(entry) == {"id", "status", "owner", "lane", "blocker"}
        assert entry["status"] == "platform_blocked"
        assert all(entry[field].strip() for field in ("owner", "lane"))
        assert len(entry["blocker"]) >= 160


def test_step_11_capability_ids_exist_in_inventory() -> None:
    inventory_ids = {
        entry["id"] for entry in load_toml(CAPABILITY_PATH)["capabilities"]
    }
    assert inventory_ids >= STEP_11_CAPABILITY_IDS


def test_deterministic_preflight_is_not_reported_as_live_parity() -> None:
    manifest = load_toml(DISPOSITIONS_PATH)
    preflight = manifest["deterministic_preflight"]

    assert set(preflight) == {
        "status",
        "baseline_attestation",
        "baseline_attestation_sha256",
        "candidate_attestation",
        "candidate_attestation_sha256",
        "commands",
        "evidence",
    }
    assert preflight["status"] == "pass"
    assert set(preflight["commands"]) == set(EXPECTED_SUITES.values())
    assert len(preflight["commands"]) == len(EXPECTED_SUITES)
    assert len(preflight["evidence"]) >= 4
    assert all(item.strip() for item in preflight["evidence"])

    assert manifest["overall_status"] == "platform_blocked"
    assert all(
        entry["status"] == "platform_blocked" for entry in manifest["capabilities"]
    )

    attestations = {
        "baseline": manifest["baseline_commit"],
        "candidate": manifest["candidate_commit"],
    }
    for variant, source_commit in attestations.items():
        path_field = f"{variant}_attestation"
        digest_field = f"{variant}_attestation_sha256"
        path = REPO_ROOT / preflight[path_field]
        assert path.is_file(), f"missing tracked Step 11 attestation: {path}"
        assert re.fullmatch(r"[0-9a-f]{64}", preflight[digest_field])
        assert hashlib.sha256(path.read_bytes()).hexdigest() == preflight[digest_field]

        attestation = path.read_text(encoding="utf-8")
        assert "schema_v2_step11_deterministic_attestation_version=1\n" in attestation
        assert f"variant={variant}\n" in attestation
        assert f"source_commit={source_commit}\n" in attestation
        assert "source_tree_clean=true\n" in attestation
        assert "cargo_target_scope=checkout-local\n" in attestation
        assert "rustc_wrapper=disabled\n" in attestation
        assert attestation.endswith("\nattestation_complete=true\n")
        suite_sections = {}
        for section in attestation.split("\n=== suite:")[1:]:
            suite, separator, body = section.partition(" ===\n")
            assert separator
            assert suite not in suite_sections
            suite_sections[suite] = body
        assert set(suite_sections) == set(EXPECTED_SUITES)
        for suite, command in EXPECTED_SUITES.items():
            section = suite_sections[suite]
            assert section.startswith(f"command={command} \n--- output ---\n")
            assert section.count("--- exit_status:0 ---") == 1
            assert "--- exit_status:" not in section.replace(
                "--- exit_status:0 ---", ""
            )


def test_step_11_representation_changes_remain_in_intentional_change_ledger() -> None:
    changes = {
        entry["id"]: entry
        for entry in load_toml(INTENTIONAL_CHANGES_PATH)["intentional_changes"]
    }

    for change_id, capability_id in EXPECTED_INTENTIONAL_CHANGES.items():
        assert change_id in changes
        change = changes[change_id]
        assert change["parity_disposition"] == "intentional_change"
        assert capability_id in change["validation_capability_ids"]
