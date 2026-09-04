# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Validate the explicit schema-v2 intentional-change ledger."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
LEDGER_PATH = REPO_ROOT / "e2e/configs/gateway/schema-v2-intentional-changes.toml"
CAPABILITY_PATH = REPO_ROOT / "e2e/configs/gateway/schema-v2-capability-parity.toml"

REQUIRED_HEADER_FIELDS = {
    "ledger_version",
    "issue",
    "baseline_commit",
    "candidate_start_commit",
    "intentional_changes",
}
REQUIRED_CHANGE_FIELDS = {
    "id",
    "category",
    "origin_main_contract",
    "schema_v2_contract",
    "migration",
    "rationale",
    "parity_disposition",
    "validation_capability_ids",
}
REQUIRED_CHANGE_IDS = {
    "canonical-image-pull-policy",
    "docker-sandbox-label-rename",
    "driver-table-exclusive-ownership",
    "gateway-jwt-zero-sentinel-removed",
    "guest-tls-centralized",
    "kubernetes-fields-relocated",
    "middleware-payload-name-normalized",
    "package-default-only-auto-migration",
    "podman-health-zero-sentinel-removed",
    "podman-pid-limit-restored",
    "podman-ssh-socket-rename",
    "sandbox-pid-zero-sentinel-removed",
    "schema-version-cutover",
    "singular-compute-driver-selector",
    "vm-grpc-endpoint-rename",
    "vm-sandbox-identity-selection",
}
ALLOWED_CATEGORIES = {
    "bug_fix",
    "cardinality",
    "default_behavior",
    "migration_policy",
    "ownership",
    "relocation",
    "rename",
    "rename_with_alias",
    "schema_cutover",
    "sentinel_removal",
    "type_normalization",
}


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as toml_file:
        return tomllib.load(toml_file)


def require_nonempty_string(value: Any, field: str, change_id: str) -> None:
    assert isinstance(value, str) and value.strip(), f"{change_id}: {field} is required"


def test_intentional_change_ledger_is_complete_and_well_formed() -> None:
    ledger = load_toml(LEDGER_PATH)

    assert set(ledger) == REQUIRED_HEADER_FIELDS
    assert ledger["ledger_version"] == 1
    assert ledger["issue"] == 2792
    assert ledger["baseline_commit"] == "74960ebfaeec4673885089ed995fad902459749f"
    assert ledger["candidate_start_commit"] == (
        "8c868e430e9cd3284d7e274628419ab484ebcee0"
    )

    changes = ledger["intentional_changes"]
    assert isinstance(changes, list) and changes
    ids: list[str] = []
    for change in changes:
        assert set(change) == REQUIRED_CHANGE_FIELDS
        change_id = change["id"]
        require_nonempty_string(change_id, "id", "intentional change")
        ids.append(change_id)
        assert change["category"] in ALLOWED_CATEGORIES
        assert change["parity_disposition"] == "intentional_change"
        for field in (
            "origin_main_contract",
            "schema_v2_contract",
            "migration",
            "rationale",
        ):
            require_nonempty_string(change[field], field, change_id)
        capability_ids = change["validation_capability_ids"]
        assert isinstance(capability_ids, list) and capability_ids
        assert len(capability_ids) == len(set(capability_ids))

    assert len(ids) == len(set(ids))
    assert set(ids) == REQUIRED_CHANGE_IDS


def test_every_intentional_change_links_to_known_capabilities() -> None:
    ledger = load_toml(LEDGER_PATH)
    capabilities = load_toml(CAPABILITY_PATH)["capabilities"]
    known_capability_ids = {capability["id"] for capability in capabilities}

    for change in ledger["intentional_changes"]:
        assert set(change["validation_capability_ids"]) <= known_capability_ids, (
            f"{change['id']}: unknown validation capability"
        )


def test_ledger_does_not_hide_known_unresolved_parity_gaps() -> None:
    ledger = load_toml(LEDGER_PATH)
    change_ids = {change["id"] for change in ledger["intentional_changes"]}

    assert "legacy-environment-selector-upgrade" not in change_ids
    assert "tls-require-client-auth-ignored" not in change_ids
    assert "debian-snap-v1-upgrade" not in change_ids


def test_singular_selector_ledger_preserves_auto_detection() -> None:
    ledger = load_toml(LEDGER_PATH)
    selector = next(
        change
        for change in ledger["intentional_changes"]
        if change["id"] == "singular-compute-driver-selector"
    )

    assert "omission retains built-in auto-detection" in selector["schema_v2_contract"]
    assert "unsupported multi-driver operation" in selector["rationale"]


def test_operator_edited_package_configuration_is_never_auto_rewritten() -> None:
    ledger = load_toml(LEDGER_PATH)
    package_policy = next(
        change
        for change in ledger["intentional_changes"]
        if change["id"] == "package-default-only-auto-migration"
    )

    contract = package_policy["schema_v2_contract"]
    assert "byte-identical package defaults" in contract
    assert "Debian and Snap preserve every legacy file" in contract
    assert "fail closed through read-only package preflight" in contract
    assert "manual-migration guidance" in contract
    assert "no safe provenance marker" in contract
    assert "preserve every edited file" in package_policy["migration"]
    assert "manual schema-v2 conversion" in package_policy["migration"]
