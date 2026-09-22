# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the GB300 Windows ARM64 MXC qualification contract."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict, cast

if TYPE_CHECKING:
    from types import ModuleType


REPO_ROOT = Path(__file__).resolve().parents[1]
QUALIFICATION_DIR = REPO_ROOT / "crates" / "openshell-driver-mxc" / "qualification"


class ContractRow(TypedDict, total=False):
    id: str
    disposition: str
    allow_skip: bool
    architecture: str
    commands: list[str]
    artifact_roles: list[str]
    reason: str


class Contract(TypedDict):
    matrix: list[ContractRow]


class EvidenceArtifact(TypedDict):
    role: str
    path: str
    sha256: str


class EvidenceResult(TypedDict, total=False):
    coverage_id: str
    status: str
    architecture: str
    command: str
    exit_code: int
    skip_count: int
    duration_seconds: float
    artifacts: list[EvidenceArtifact]
    reason: str


class EvidenceRecord(TypedDict):
    schema_version: int
    contract_id: str
    base_sha: str
    head_sha: str
    generated_at: str
    environment: dict[str, object]
    results: list[EvidenceResult]


def _load_validator() -> ModuleType:
    path = QUALIFICATION_DIR / "validate.py"
    spec = importlib.util.spec_from_file_location("gb300_mxc_validator", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VALIDATOR = _load_validator()


def _load_contract() -> Contract:
    return cast("Contract", VALIDATOR.load_json(QUALIFICATION_DIR / "gb300-woa.json"))


def _valid_evidence(contract: Contract, artifact_root: Path) -> EvidenceRecord:
    results: list[EvidenceResult] = []
    for row in contract["matrix"]:
        row_id = row["id"]
        disposition = row["disposition"]
        if disposition == "required":
            artifacts: list[EvidenceArtifact] = []
            for role in row["artifact_roles"]:
                artifact_path = artifact_root / f"{row_id}-{role}.txt"
                artifact_path.write_text(f"evidence for {row_id}\n", encoding="utf-8")
                artifacts.append(
                    {
                        "role": role,
                        "path": artifact_path.name,
                        "sha256": hashlib.sha256(
                            artifact_path.read_bytes()
                        ).hexdigest(),
                    }
                )
            results.append(
                {
                    "coverage_id": row_id,
                    "status": "pass",
                    "architecture": "arm64",
                    "command": row["commands"][0],
                    "exit_code": 0,
                    "skip_count": 0,
                    "duration_seconds": 0.1,
                    "artifacts": artifacts,
                }
            )
        elif disposition == "optional":
            results.append(
                {
                    "coverage_id": row_id,
                    "status": "not_run",
                    "reason": "Not selected for the required qualification gate.",
                    "artifacts": [],
                }
            )
        else:
            results.append(
                {
                    "coverage_id": row_id,
                    "status": "not_applicable",
                    "reason": row["reason"],
                    "artifacts": [],
                }
            )

    return {
        "schema_version": 1,
        "contract_id": "nvbug-6643699-gb300-woa-mxc",
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "generated_at": "2026-09-18T12:00:00Z",
        "environment": {
            "operating_system": "windows",
            "architecture": "arm64",
            "native": True,
            "wsl": False,
            "hardware": "GB300",
        },
        "results": results,
    }


def test_runner_requires_explicit_canonical_source_provenance() -> None:
    source = (QUALIFICATION_DIR / "run-gb300-woa.ps1").read_text(encoding="utf-8")

    assert "ExpectedBaseSha is required" in source
    assert "$ExpectedBaseSha = $fetchedBaseSha" not in source
    assert "https://github.com/nvidia/openshell.git" in source.lower()
    assert "origin must be the canonical NVIDIA/OpenShell" in source


def test_runner_hash_binds_a_versioned_openclaw_package() -> None:
    source = (QUALIFICATION_DIR / "run-gb300-woa.ps1").read_text(encoding="utf-8")

    assert "package.json must declare a non-empty version" in source
    assert "openclaw_package_sha256" in source
    assert "openclaw_package_json_sha256" in source
    assert "Get-ChildItem -LiteralPath $OpenClawInstallDir -Force" in source
    assert "Copy-Item -LiteralPath $_.FullName" in source
    assert "$openClawPreRunSha256 = Get-DirectorySha256 $OpenClawInstallDir" in source
    assert "$openClawPostRunSha256 = Get-DirectorySha256 $OpenClawInstallDir" in source


def test_gb300_gate_invokes_only_required_real_mxc_tests() -> None:
    source = (REPO_ROOT / "tasks" / "scripts" / "windows-msvc.ps1").read_text(
        encoding="utf-8"
    )

    gb300_function = source.split("function Invoke-MxcGb300Tests", 1)[1].split(
        "function Get-Sha256", 1
    )[0]

    assert "$test -- --ignored --exact --test-threads=1 --nocapture" in gb300_function
    assert (
        "--target $RustTarget -- --ignored --test-threads=1 --nocapture"
        not in gb300_function
    )


def test_repository_contract_is_valid() -> None:
    errors = VALIDATOR.validate_contract(_load_contract(), repo_root=REPO_ROOT)
    assert errors == []


def test_required_coverage_cannot_be_skip_safe() -> None:
    contract = copy.deepcopy(_load_contract())
    required = next(
        row for row in contract["matrix"] if row["id"] == "processcontainer-real-mxc"
    )
    required["allow_skip"] = True

    errors = VALIDATOR.validate_contract(contract)

    assert "processcontainer-real-mxc is required and cannot allow skip" in errors


def test_required_coverage_cannot_be_x64_or_nemoclaw() -> None:
    contract = copy.deepcopy(_load_contract())
    required = next(
        row for row in contract["matrix"] if row["id"] == "openclaw-arm64-forward"
    )
    required["architecture"] = "native_x64"
    required["commands"] = ["run-nemoclaw-qualification.ps1"]

    errors = VALIDATOR.validate_contract(contract)

    assert "openclaw-arm64-forward has an invalid required architecture" in errors
    assert "openclaw-arm64-forward cannot use an x64/NemoClaw command" in errors


def test_nemoclaw_exclusion_is_mandatory() -> None:
    contract = copy.deepcopy(_load_contract())
    contract["matrix"] = [
        row for row in contract["matrix"] if row["id"] != "nemoclaw-native-x64"
    ]

    errors = VALIDATOR.validate_contract(contract)

    assert "matrix row is missing: nemoclaw-native-x64" in errors


def test_complete_hash_bound_evidence_passes(tmp_path: Path) -> None:
    contract = _load_contract()
    record = _valid_evidence(contract, tmp_path)

    errors = VALIDATOR.validate_evidence(
        contract,
        record,
        artifact_root=tmp_path,
        expected_base_sha="a" * 40,
    )

    assert errors == []


def test_required_skip_fails_evidence_validation(tmp_path: Path) -> None:
    contract = _load_contract()
    record = _valid_evidence(contract, tmp_path)
    result = next(
        item
        for item in record["results"]
        if item["coverage_id"] == "processcontainer-real-mxc"
    )
    result["status"] = "skip"
    result["skip_count"] = 1

    errors = VALIDATOR.validate_evidence(
        contract,
        record,
        artifact_root=tmp_path,
        expected_base_sha="a" * 40,
    )

    assert "processcontainer-real-mxc: required result must be pass, got skip" in errors
    assert "processcontainer-real-mxc: required skip_count must be 0" in errors


def test_optional_pass_must_carry_declared_arm64_artifacts(tmp_path: Path) -> None:
    contract = _load_contract()
    record = _valid_evidence(contract, tmp_path)
    result = next(
        item
        for item in record["results"]
        if item["coverage_id"] == "local-inference-models"
    )
    result.update(
        {
            "status": "pass",
            "architecture": "native_x64",
            "command": "run-model-evaluation.ps1",
            "exit_code": 0,
            "skip_count": 0,
            "duration_seconds": 1.0,
            "artifacts": [],
        }
    )
    result.pop("reason")

    errors = VALIDATOR.validate_evidence(
        contract,
        record,
        artifact_root=tmp_path,
        expected_base_sha="a" * 40,
    )

    assert "local-inference-models: optional pass evidence must be ARM64" in errors
    assert any("optional artifact roles mismatch" in error for error in errors)


def test_artifact_hash_mismatch_fails_evidence_validation(tmp_path: Path) -> None:
    contract = _load_contract()
    record = _valid_evidence(contract, tmp_path)
    artifact = record["results"][0]["artifacts"][0]
    (tmp_path / artifact["path"]).write_text("tampered\n", encoding="utf-8")

    errors = VALIDATOR.validate_evidence(
        contract,
        record,
        artifact_root=tmp_path,
        expected_base_sha="a" * 40,
    )

    assert any("sha256 does not match" in error for error in errors)
