# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Validate the GB300 Windows ARM64 MXC contract and retained evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

CONTRACT_ID = "nvbug-6643699-gb300-woa-mxc"
DISPOSITIONS = {
    "required",
    "optional",
    "unsupported",
    "architecture_constrained",
}
ARCHITECTURES = {"any", "native_arm64", "native_x64", "none"}
REQUIRED_IDS = {
    "contract-integrity",
    "source-provenance",
    "gb300-arm64-host",
    "arm64-msvc-check",
    "arm64-release-build",
    "arm64-native-tests",
    "arm64-unsupported-driver-contracts",
    "processcontainer-real-mxc",
    "processcontainer-policy-e2e",
    "openclaw-arm64-forward",
}
REQUIRED_REPOSITORY_PATHS = {
    "crates/openshell-driver-mxc/examples/probe-mxc-host.ps1",
    "crates/openshell-driver-mxc/examples/run-mxc-e2e.ps1",
    "crates/openshell-driver-mxc/examples/run-openclaw-forward-test.ps1",
    "crates/openshell-driver-mxc/qualification/gb300-woa.json",
    "tasks/scripts/windows-msvc.ps1",
    "tasks/windows.toml",
}
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def load_json(path: Path) -> dict[str, Any]:
    """Load JSON written by either PowerShell 5.1 or a UTF-8-native tool."""
    with path.open(encoding="utf-8-sig") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _nonempty_strings(value: object) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and item.strip() for item in value)
    )


def validate_contract(
    contract: dict[str, Any], repo_root: Path | None = None
) -> list[str]:
    """Return every static contract violation without stopping at the first."""
    errors: list[str] = []
    if contract.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if contract.get("contract_id") != CONTRACT_ID:
        errors.append(f"contract_id must be {CONTRACT_ID}")
    if contract.get("nvbug") != 6643699:
        errors.append("nvbug must be 6643699")

    target = contract.get("target")
    if not isinstance(target, dict):
        errors.append("target must be an object")
        target = {}
    expected_target = {
        "hardware": "GB300",
        "operating_system": "windows",
        "architecture": "arm64",
        "rust_target": "aarch64-pc-windows-msvc",
        "execution": "native",
        "wsl": False,
        "base_ref": "origin/windows",
    }
    for key, expected in expected_target.items():
        if target.get(key) != expected:
            errors.append(f"target.{key} must be {expected!r}")

    decisions = contract.get("decisions")
    if not isinstance(decisions, dict):
        errors.append("decisions must be an object")
        decisions = {}
    if decisions.get("required_agent_apps") != ["OpenClaw"]:
        errors.append("OpenClaw must be the sole repository-owned required agent app")
    if decisions.get("target_models") != []:
        errors.append("target_models must be empty; model selection is app-owned")
    if decisions.get("model_scope") != "agent_application_owned":
        errors.append("model_scope must remain agent_application_owned")
    if decisions.get("model_release_gate") is not False:
        errors.append("model_release_gate must remain false")
    if decisions.get("required_skip_policy") != "fail":
        errors.append("required_skip_policy must be fail")

    owners = contract.get("owners")
    if not isinstance(owners, dict) or not owners:
        errors.append("owners must be a non-empty object")
        owners = {}
    for owner_id, owner in owners.items():
        if not isinstance(owner, dict):
            errors.append(f"owner {owner_id} must be an object")
            continue
        if not isinstance(owner.get("name"), str) or not owner["name"].strip():
            errors.append(f"owner {owner_id} needs a name")
        if (
            not isinstance(owner.get("responsibility"), str)
            or not owner["responsibility"].strip()
        ):
            errors.append(f"owner {owner_id} needs a responsibility")

    matrix = contract.get("matrix")
    if not isinstance(matrix, list) or not matrix:
        errors.append("matrix must be a non-empty array")
        return errors

    rows: dict[str, dict[str, Any]] = {}
    disposition_counts = dict.fromkeys(DISPOSITIONS, 0)
    for index, row in enumerate(matrix):
        label = f"matrix[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{label} must be an object")
            continue
        row_id = row.get("id")
        if not isinstance(row_id, str) or not row_id.strip():
            errors.append(f"{label}.id must be a non-empty string")
            continue
        label = row_id
        if row_id in rows:
            errors.append(f"duplicate matrix id: {row_id}")
            continue
        rows[row_id] = row

        disposition = row.get("disposition")
        if disposition not in DISPOSITIONS:
            errors.append(f"{label}.disposition is invalid")
        else:
            disposition_counts[disposition] += 1
        if row.get("owner") not in owners:
            errors.append(f"{label}.owner must reference owners")
        if not _nonempty_strings(row.get("prerequisites")):
            errors.append(f"{label}.prerequisites must be non-empty strings")
        if not _nonempty_strings(row.get("pass_criteria")):
            errors.append(f"{label}.pass_criteria must be non-empty strings")
        if not isinstance(row.get("artifact_roles"), list) or not all(
            isinstance(role, str) and role.strip()
            for role in row.get("artifact_roles", [])
        ):
            errors.append(f"{label}.artifact_roles must be a string array")
        if not isinstance(row.get("commands"), list) or not all(
            isinstance(command, str) and command.strip()
            for command in row.get("commands", [])
        ):
            errors.append(f"{label}.commands must be a string array")
        if not isinstance(row.get("hardware_dependent"), bool):
            errors.append(f"{label}.hardware_dependent must be boolean")
        if not isinstance(row.get("credits_gb300_arm64"), bool):
            errors.append(f"{label}.credits_gb300_arm64 must be boolean")
        if not isinstance(row.get("allow_skip"), bool):
            errors.append(f"{label}.allow_skip must be boolean")
        if row.get("architecture") not in ARCHITECTURES:
            errors.append(f"{label}.architecture is invalid")

        if disposition == "required":
            if row.get("allow_skip") is not False:
                errors.append(f"{label} is required and cannot allow skip")
            if row.get("credits_gb300_arm64") is not True:
                errors.append(f"{label} is required and must credit GB300 ARM64")
            if row.get("architecture") not in {"any", "native_arm64"}:
                errors.append(f"{label} has an invalid required architecture")
            if not row.get("commands"):
                errors.append(f"{label} is required and needs a command")
            if not row.get("artifact_roles"):
                errors.append(f"{label} is required and needs artifact roles")
            command_text = " ".join(row.get("commands", [])).lower()
            if "x86_64" in command_text or "nemoclaw" in command_text:
                errors.append(f"{label} cannot use an x64/NemoClaw command")
        elif disposition in {"unsupported", "architecture_constrained"}:
            if row.get("credits_gb300_arm64") is not False:
                errors.append(f"{label} cannot credit GB300 ARM64")
            if not isinstance(row.get("reason"), str) or not row["reason"].strip():
                errors.append(f"{label} needs an explicit reason")
        elif disposition == "optional" and row.get("credits_gb300_arm64") is not False:
            errors.append(f"{label} is optional and cannot credit GB300 ARM64")

    for disposition, count in disposition_counts.items():
        if count == 0:
            errors.append(f"matrix needs at least one {disposition} row")
    actual_required = {
        row_id for row_id, row in rows.items() if row.get("disposition") == "required"
    }
    if actual_required != REQUIRED_IDS:
        missing = sorted(REQUIRED_IDS - actual_required)
        extra = sorted(actual_required - REQUIRED_IDS)
        errors.append(f"required row set mismatch: missing={missing}, extra={extra}")

    _require_row(errors, rows, "wsl", "unsupported", "none", False)
    _require_row(
        errors,
        rows,
        "nemoclaw-native-x64",
        "architecture_constrained",
        "native_x64",
        False,
    )
    _require_row(
        errors,
        rows,
        "node-openclaw-x64-installer",
        "architecture_constrained",
        "native_x64",
        False,
    )
    _require_row(
        errors,
        rows,
        "local-inference-models",
        "optional",
        "native_arm64",
        False,
    )
    openclaw = rows.get("openclaw-arm64-forward", {})
    if not any(
        "run-openclaw-forward-test.ps1" in command
        for command in openclaw.get("commands", [])
    ):
        errors.append("openclaw-arm64-forward must invoke the repository harness")

    if repo_root is not None:
        for relative in sorted(REQUIRED_REPOSITORY_PATHS):
            if not (repo_root / relative).is_file():
                errors.append(f"referenced repository path is missing: {relative}")

    return errors


def _require_row(
    errors: list[str],
    rows: dict[str, dict[str, Any]],
    row_id: str,
    disposition: str,
    architecture: str,
    credit: bool,
) -> None:
    row = rows.get(row_id)
    if row is None:
        errors.append(f"matrix row is missing: {row_id}")
        return
    if row.get("disposition") != disposition:
        errors.append(f"{row_id}.disposition must be {disposition}")
    if row.get("architecture") != architecture:
        errors.append(f"{row_id}.architecture must be {architecture}")
    if row.get("credits_gb300_arm64") is not credit:
        errors.append(f"{row_id}.credits_gb300_arm64 must be {credit}")


def validate_evidence(
    contract: dict[str, Any],
    record: dict[str, Any],
    artifact_root: Path,
    expected_base_sha: str,
) -> list[str]:
    """Validate one retained evidence record against the static matrix."""
    errors = validate_contract(contract, repo_root=None)
    if not SHA_PATTERN.fullmatch(expected_base_sha):
        errors.append("expected base SHA must be 40 lowercase hexadecimal characters")
    if record.get("schema_version") != 1:
        errors.append("evidence schema_version must be 1")
    if record.get("contract_id") != CONTRACT_ID:
        errors.append(f"evidence contract_id must be {CONTRACT_ID}")
    if record.get("base_sha") != expected_base_sha:
        errors.append(
            "evidence base_sha does not match the expected origin/windows SHA"
        )
    if not isinstance(record.get("head_sha"), str) or not SHA_PATTERN.fullmatch(
        record["head_sha"]
    ):
        errors.append("evidence head_sha must be a full lowercase Git SHA")
    if (
        not isinstance(record.get("generated_at"), str)
        or not record["generated_at"].strip()
    ):
        errors.append("evidence generated_at is required")

    environment = record.get("environment")
    if not isinstance(environment, dict):
        errors.append("evidence environment must be an object")
        environment = {}
    expected_environment = {
        "operating_system": "windows",
        "architecture": "arm64",
        "native": True,
        "wsl": False,
        "hardware": "GB300",
    }
    for key, expected in expected_environment.items():
        if environment.get(key) != expected:
            errors.append(f"evidence environment.{key} must be {expected!r}")

    results = record.get("results")
    if not isinstance(results, list):
        errors.append("evidence results must be an array")
        return errors
    by_id: dict[str, dict[str, Any]] = {}
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            errors.append(f"evidence results[{index}] must be an object")
            continue
        coverage_id = result.get("coverage_id")
        if not isinstance(coverage_id, str) or not coverage_id:
            errors.append(f"evidence results[{index}] needs coverage_id")
            continue
        if coverage_id in by_id:
            errors.append(f"duplicate evidence result: {coverage_id}")
            continue
        by_id[coverage_id] = result

    rows = {row["id"]: row for row in contract["matrix"]}
    if set(by_id) != set(rows):
        errors.append(
            "evidence result IDs must exactly match the contract matrix: "
            f"missing={sorted(set(rows) - set(by_id))}, "
            f"extra={sorted(set(by_id) - set(rows))}"
        )

    artifact_root = artifact_root.resolve()
    for row_id, row in rows.items():
        result = by_id.get(row_id)
        if result is None:
            continue
        disposition = row["disposition"]
        status = result.get("status")
        artifacts = result.get("artifacts")
        if not isinstance(artifacts, list):
            errors.append(f"{row_id}: artifacts must be an array")
            artifacts = []

        if disposition == "required":
            if status != "pass":
                errors.append(f"{row_id}: required result must be pass, got {status}")
            if result.get("exit_code") != 0:
                errors.append(f"{row_id}: required exit_code must be 0")
            if result.get("skip_count") != 0:
                errors.append(f"{row_id}: required skip_count must be 0")
            if result.get("architecture") != "arm64":
                errors.append(f"{row_id}: required evidence must be ARM64")
            duration = result.get("duration_seconds")
            if not isinstance(duration, (int, float)) or duration < 0:
                errors.append(f"{row_id}: duration_seconds must be non-negative")
            if (
                not isinstance(result.get("command"), str)
                or not result["command"].strip()
            ):
                errors.append(f"{row_id}: required evidence needs the command")
            actual_roles = {
                item.get("role") for item in artifacts if isinstance(item, dict)
            }
            expected_roles = set(row["artifact_roles"])
            if actual_roles != expected_roles:
                errors.append(
                    f"{row_id}: artifact roles mismatch; "
                    f"expected={sorted(expected_roles)}, actual={sorted(actual_roles)}"
                )
        elif disposition == "optional":
            if status not in {"pass", "not_run"}:
                errors.append(f"{row_id}: optional status must be pass or not_run")
            if status == "not_run" and not _has_reason(result):
                errors.append(f"{row_id}: not_run requires a reason")
            if status == "pass":
                if result.get("exit_code") != 0:
                    errors.append(f"{row_id}: optional pass exit_code must be 0")
                if result.get("skip_count") != 0:
                    errors.append(f"{row_id}: optional pass skip_count must be 0")
                if result.get("architecture") != "arm64":
                    errors.append(f"{row_id}: optional pass evidence must be ARM64")
                duration = result.get("duration_seconds")
                if not isinstance(duration, (int, float)) or duration < 0:
                    errors.append(
                        f"{row_id}: optional pass duration_seconds must be non-negative"
                    )
                if (
                    not isinstance(result.get("command"), str)
                    or not result["command"].strip()
                ):
                    errors.append(f"{row_id}: optional pass needs the command")
                actual_roles = {
                    item.get("role") for item in artifacts if isinstance(item, dict)
                }
                expected_roles = set(row["artifact_roles"])
                if actual_roles != expected_roles:
                    errors.append(
                        f"{row_id}: optional artifact roles mismatch; "
                        f"expected={sorted(expected_roles)}, "
                        f"actual={sorted(actual_roles)}"
                    )
        else:
            if status != "not_applicable":
                errors.append(f"{row_id}: excluded status must be not_applicable")
            if not _has_reason(result):
                errors.append(f"{row_id}: not_applicable requires a reason")
            if artifacts:
                errors.append(f"{row_id}: excluded rows must not claim artifacts")

        if status == "pass":
            errors.extend(_validate_artifacts(row_id, artifacts, artifact_root))

    return errors


def _has_reason(result: dict[str, Any]) -> bool:
    return isinstance(result.get("reason"), str) and bool(result["reason"].strip())


def _validate_artifacts(
    row_id: str, artifacts: list[object], artifact_root: Path
) -> list[str]:
    errors: list[str] = []
    seen_roles: set[str] = set()
    for index, artifact in enumerate(artifacts):
        label = f"{row_id}.artifacts[{index}]"
        if not isinstance(artifact, dict):
            errors.append(f"{label} must be an object")
            continue
        role = artifact.get("role")
        relative = artifact.get("path")
        expected_hash = artifact.get("sha256")
        if not isinstance(role, str) or not role:
            errors.append(f"{label}.role is required")
            continue
        if role in seen_roles:
            errors.append(f"{row_id}: duplicate artifact role {role}")
        seen_roles.add(role)
        if not isinstance(relative, str) or not relative:
            errors.append(f"{label}.path is required")
            continue
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            errors.append(f"{label}.path must stay under the artifact root")
            continue
        path = (artifact_root / relative_path).resolve()
        if not path.is_relative_to(artifact_root):
            errors.append(f"{label}.path resolves outside the artifact root")
            continue
        if not path.is_file() or path.stat().st_size == 0:
            errors.append(f"{label}.path must be a non-empty file: {relative}")
            continue
        if not isinstance(expected_hash, str) or not re.fullmatch(
            r"[0-9a-f]{64}", expected_hash
        ):
            errors.append(f"{label}.sha256 must be lowercase hexadecimal")
            continue
        actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            errors.append(f"{label}.sha256 does not match {relative}")
    return errors


def _print_errors(errors: list[str]) -> int:
    if not errors:
        return 0
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=script_dir / "gb300-woa.json",
        help="Path to the qualification contract",
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)
    subparsers.add_parser("contract", help="Validate the static scope contract")
    evidence = subparsers.add_parser(
        "evidence", help="Validate retained qualification evidence"
    )
    evidence.add_argument("--record", type=Path, required=True)
    evidence.add_argument("--artifact-root", type=Path, required=True)
    evidence.add_argument("--expected-base-sha", required=True)
    args = parser.parse_args(argv)

    try:
        contract = load_json(args.manifest)
        if args.mode == "contract":
            errors = validate_contract(contract, repo_root=repo_root)
        else:
            record = load_json(args.record)
            errors = validate_evidence(
                contract,
                record,
                args.artifact_root,
                args.expected_base_sha,
            )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    if errors:
        return _print_errors(errors)
    if args.mode == "contract":
        print(f"PASS: {CONTRACT_ID} contract is valid")
    else:
        print(f"PASS: {CONTRACT_ID} evidence is complete and hash-bound")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
