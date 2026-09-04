# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Validate schema-v2 parity-gap dispositions and release blockers."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
GAP_LEDGER_PATH = (
    REPO_ROOT / "e2e/configs/gateway/schema-v2-parity-gap-dispositions.toml"
)
LIVE_RESULTS_PATH = REPO_ROOT / "e2e/configs/gateway/schema-v2-live-results.toml"

REQUIRED_HEADER_FIELDS = {
    "ledger_version",
    "issue",
    "baseline_commit",
    "candidate_start_commit",
    "gaps",
}
REQUIRED_GAP_FIELDS = {
    "id",
    "severity",
    "parity_relation",
    "disposition",
    "origin_main_behavior",
    "candidate_behavior",
    "impact",
    "resolution",
    "validation",
    "owner_step",
}
REQUIRED_GAP_IDS = {
    "debian-snap-v1-upgrade",
    "gateway-owned-guest-tls",
    "generated-e2e-selector-shape",
    "legacy-environment-selector-upgrade",
    "multi-driver-runtime-loss",
    "rpm-exact-default-migration",
    "tls-require-client-auth-ignored",
    "unselected-driver-validation-claim",
}
ALLOWED_SEVERITIES = {"blocker", "major", "minor", "none"}
ALLOWED_RELATIONS = {
    "documentation_gap",
    "non_finding",
    "preexisting_inaccessible_option",
    "regression",
    "upgrade_regression",
}
ALLOWED_DISPOSITIONS = {
    "documentation_fix_required",
    "must_fix_before_parity",
    "must_fix_before_release_gate",
    "must_fix_or_remove_claim",
    "no_action",
    "resolved",
}


def load_ledger() -> dict[str, Any]:
    with GAP_LEDGER_PATH.open("rb") as ledger_file:
        return tomllib.load(ledger_file)


def test_gap_disposition_ledger_is_complete_and_well_formed() -> None:
    ledger = load_ledger()

    assert set(ledger) == REQUIRED_HEADER_FIELDS
    assert ledger["ledger_version"] == 1
    assert ledger["issue"] == 2792
    assert ledger["baseline_commit"] == "74960ebfaeec4673885089ed995fad902459749f"
    assert ledger["candidate_start_commit"] == (
        "8c868e430e9cd3284d7e274628419ab484ebcee0"
    )

    gaps = ledger["gaps"]
    assert isinstance(gaps, list) and gaps
    ids: list[str] = []
    for gap in gaps:
        assert set(gap) == REQUIRED_GAP_FIELDS
        gap_id = gap["id"]
        assert isinstance(gap_id, str) and gap_id.strip()
        ids.append(gap_id)
        assert gap["severity"] in ALLOWED_SEVERITIES
        assert gap["parity_relation"] in ALLOWED_RELATIONS
        assert gap["disposition"] in ALLOWED_DISPOSITIONS
        assert isinstance(gap["owner_step"], int) and 1 <= gap["owner_step"] <= 15
        for field in (
            "origin_main_behavior",
            "candidate_behavior",
            "impact",
            "resolution",
            "validation",
        ):
            assert isinstance(gap[field], str) and gap[field].strip(), (
                f"{gap_id}: {field} is required"
            )

    assert len(ids) == len(set(ids))
    assert set(ids) == REQUIRED_GAP_IDS


def test_every_blocker_has_a_required_fix_and_validation() -> None:
    for gap in load_ledger()["gaps"]:
        if gap["severity"] != "blocker":
            continue

        assert gap["disposition"].startswith("must_fix")
        assert gap["owner_step"] in {6, 12}
        assert len(gap["resolution"]) >= 80
        assert len(gap["validation"]) >= 80


def test_non_findings_do_not_require_product_changes() -> None:
    for gap in load_ledger()["gaps"]:
        if gap["parity_relation"] == "non_finding":
            assert gap["severity"] == "none"
            assert gap["disposition"] == "no_action"


def test_security_sensitive_tls_gap_records_reviewed_resolution() -> None:
    tls_gap = next(
        gap
        for gap in load_ledger()["gaps"]
        if gap["id"] == "tls-require-client-auth-ignored"
    )

    assert tls_gap["parity_relation"] == "preexisting_inaccessible_option"
    assert tls_gap["disposition"] == "resolved"
    assert "Security review" in tls_gap["resolution"]
    assert "rejects require_client_auth" in tls_gap["candidate_behavior"]


def test_step_6_gap_dispositions_are_resolved() -> None:
    step_6_gaps = [gap for gap in load_ledger()["gaps"] if gap["owner_step"] == 6]

    assert {gap["id"] for gap in step_6_gaps} == {
        "legacy-environment-selector-upgrade",
        "tls-require-client-auth-ignored",
        "unselected-driver-validation-claim",
    }
    assert all(gap["severity"] == "none" for gap in step_6_gaps)
    assert all(gap["disposition"] == "resolved" for gap in step_6_gaps)


def test_step_12_product_gaps_are_resolved_without_claiming_live_package_parity() -> (
    None
):
    step_12_gaps = [gap for gap in load_ledger()["gaps"] if gap["owner_step"] == 12]
    assert {gap["id"] for gap in step_12_gaps} == {
        "debian-snap-v1-upgrade",
        "rpm-exact-default-migration",
    }

    debian_snap = next(
        gap for gap in step_12_gaps if gap["id"] == "debian-snap-v1-upgrade"
    )
    assert debian_snap["severity"] == "none"
    assert debian_snap["disposition"] == "resolved"
    assert "source-free, read-only preflight" in debian_snap["candidate_behavior"]
    assert "fail closed" in debian_snap["resolution"]
    assert "manual migration" in debian_snap["resolution"]
    assert "no safe default-provenance marker" in debian_snap["resolution"]
    assert "platform-blocked" in debian_snap["validation"]

    with LIVE_RESULTS_PATH.open("rb") as results_file:
        package_results = {
            result["id"]: result
            for result in tomllib.load(results_file)["result"]
            if result["step"] == 12
        }
    for result_id in (
        "debian-package-upgrade",
        "homebrew-package-upgrade",
        "rpm-package-upgrade",
        "snap-package-refresh",
    ):
        assert package_results[result_id]["status"] == "platform_blocked"


def test_legacy_environment_resolution_preserves_singular_semantics() -> None:
    legacy_gap = next(
        gap
        for gap in load_ledger()["gaps"]
        if gap["id"] == "legacy-environment-selector-upgrade"
    )

    assert "one non-empty OPENSHELL_DRIVERS value" in legacy_gap["resolution"]
    assert "rejects multiple values" in legacy_gap["resolution"]
    assert "conflicting canonical and legacy values" in legacy_gap["resolution"]
