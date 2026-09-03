# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Validate field-level Step 8 Kubernetes parity dispositions."""

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEDGER = (
    ROOT
    / "e2e"
    / "configs"
    / "gateway"
    / "schema-v2-kubernetes-option-dispositions.toml"
)
CAPABILITIES = ROOT / "e2e" / "configs" / "gateway" / "schema-v2-capability-parity.toml"
LIVE_RESULTS = ROOT / "e2e" / "configs" / "gateway" / "schema-v2-live-results.toml"
KUBERNETES_CAPABILITY_IDS = {
    "kubernetes-core-placement-and-images",
    "kubernetes-workspace-isolation",
    "kubernetes-supervisor-topology",
    "kubernetes-egress-spiffe-and-security",
}
FIELD_GROUP = re.compile(
    r"\[openshell\.(?P<table>gateway|drivers\.kubernetes(?:\.(?P<subtable>[a-z_]+))?)\]"
    r"\.\{(?P<fields>[^}]+)\}"
)


def load_ledger() -> dict:
    with LEDGER.open("rb") as handle:
        return tomllib.load(handle)


def manifest_kubernetes_fields() -> set[str]:
    with CAPABILITIES.open("rb") as handle:
        capabilities = tomllib.load(handle)["capabilities"]
    fields: set[str] = set()
    for capability in capabilities:
        if capability["id"] not in KUBERNETES_CAPABILITY_IDS:
            continue
        for access_path in [
            *capability["origin_main_access_paths"],
            *capability["schema_v2_access_paths"],
        ]:
            for match in FIELD_GROUP.finditer(access_path):
                table = match.group("table")
                if table == "gateway" and "inherited by Kubernetes" not in access_path:
                    continue
                prefix = (
                    f"{match.group('subtable')}." if match.group("subtable") else ""
                )
                fields.update(
                    f"{prefix}{field.strip()}"
                    for field in match.group("fields").split(",")
                )
    return fields


def test_kubernetes_ledger_covers_every_manifest_driver_field_once() -> None:
    ledger = load_ledger()
    coverage = ledger["coverage"]
    observed = [field for entry in coverage for field in entry["fields"]]

    assert set(observed) == manifest_kubernetes_fields()
    assert len(observed) == len(set(observed))


def test_kubernetes_core_pass_is_paired_and_qualified_checks_stay_blocked() -> None:
    ledger = load_ledger()
    core = next(entry for entry in ledger["coverage"] if entry["status"] == "pass")

    assert core["id"] == "shared-combined-core"
    assert len(core["evidence"]) >= 3
    assert ledger["baseline_commit"] == "74960ebfaeec4673885089ed995fad902459749f"
    assert len(ledger["validated_candidate_commit"]) == 40

    comparison_path = ROOT / ledger["core_comparison"]
    comparison = json.loads(comparison_path.read_text())
    assert comparison == {
        "accepted": True,
        "baseline_commit": ledger["baseline_commit"],
        "baseline_success": True,
        "candidate_commit": ledger["validated_candidate_commit"],
        "candidate_success": True,
        "classification": "pass",
        "parity": True,
    }
    with LIVE_RESULTS.open("rb") as handle:
        live_results = tomllib.load(handle)["result"]
    live_core = next(
        result
        for result in live_results
        if result["id"] == "kubernetes-core-option-parity"
    )
    assert live_core["status"] == comparison["classification"]
    assert live_core["validated_baseline_commit"] == comparison["baseline_commit"]
    assert live_core["validated_candidate_commit"] == comparison["candidate_commit"]

    blocked = [
        entry
        for entry in [*ledger["coverage"], *ledger["qualified_value"]]
        if entry["status"] == "platform_blocked"
    ]
    assert blocked
    for entry in blocked:
        assert entry["owner"]
        assert entry["lane"]
        assert entry["requirement"]


def test_environment_qualified_security_checks_are_not_claimed_by_core() -> None:
    ledger = load_ledger()
    blocked_fields = {
        field
        for entry in ledger["coverage"]
        if entry["status"] == "platform_blocked"
        for field in entry["fields"]
    }
    qualified = {entry["id"] for entry in ledger["qualified_value"]}

    assert {
        "enable_user_namespaces",
        "https_proxy",
        "proxy_auth_secret_name",
        "provider_spiffe_workload_api_socket_path",
        "sidecar.proxy_uid",
    } <= blocked_fields
    assert {
        "apparmor-enforcement",
        "gpu-resource-combinations",
        "image-volume-sideload",
        "managed-and-operator-workspace-values",
        "runtime-class-isolation",
        "sidecar-topology-value",
    } <= qualified
