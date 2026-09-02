# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATOR = REPO_ROOT / "deploy/rpm/migrate-gateway-config.sh"
CURRENT = REPO_ROOT / "deploy/rpm/gateway.toml.default"
LEGACY = REPO_ROOT / "deploy/rpm/gateway.toml.default.v1"


def run_migrator(
    destination: Path, *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", str(MIGRATOR), str(destination), str(CURRENT), str(LEGACY)],
        check=check,
        text=True,
        capture_output=True,
    )


def test_migrator_seeds_missing_config_and_is_idempotent(tmp_path: Path) -> None:
    destination = tmp_path / "config/openshell/gateway.toml"

    run_migrator(destination)
    assert destination.read_bytes() == CURRENT.read_bytes()

    run_migrator(destination)
    assert destination.read_bytes() == CURRENT.read_bytes()


def test_migrator_replaces_only_exact_legacy_default(tmp_path: Path) -> None:
    destination = tmp_path / "gateway.toml"
    destination.write_bytes(LEGACY.read_bytes())

    run_migrator(destination)

    assert destination.read_bytes() == CURRENT.read_bytes()
    assert destination.stat().st_mode & 0o777 == 0o644


def test_migrator_preserves_edited_legacy_and_current_configs(tmp_path: Path) -> None:
    destination = tmp_path / "gateway.toml"
    edited = LEGACY.read_text(encoding="utf-8") + "# operator edit\n"
    destination.write_text(edited, encoding="utf-8")

    run_migrator(destination)
    assert destination.read_text(encoding="utf-8") == edited

    destination.write_bytes(CURRENT.read_bytes())
    run_migrator(destination)
    assert destination.read_bytes() == CURRENT.read_bytes()


def test_migrator_refuses_symlink_destination(tmp_path: Path) -> None:
    target = tmp_path / "target.toml"
    target.write_text("operator-owned\n", encoding="utf-8")
    destination = tmp_path / "gateway.toml"
    destination.symlink_to(target)

    result = run_migrator(destination, check=False)

    assert result.returncode != 0
    assert "non-regular gateway config" in result.stderr
    assert target.read_text(encoding="utf-8") == "operator-owned\n"
