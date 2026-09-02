# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATOR = REPO_ROOT / "deploy/rpm/migrate-gateway-config.sh"
CURRENT = REPO_ROOT / "deploy/rpm/gateway.toml.default"
LEGACY = REPO_ROOT / "deploy/rpm/gateway.toml.default.v1"
SHIPPED_V1_FIXTURE = b"""# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Default gateway configuration for RPM installs.
#
# This file is seeded to ~/.config/openshell/gateway.toml on first start
# of the openshell-gateway.service systemd user unit. Edit that copy to
# customize. This file is not read directly at runtime.
#
# Configuration precedence (highest to lowest):
#   CLI flag  >  OPENSHELL_* env var  >  TOML file  >  built-in default
#
# To override settings without editing this file, set OPENSHELL_* variables
# in ~/.config/openshell/gateway.env or run:
#   systemctl --user edit openshell-gateway

[openshell]
version = 1

[openshell.gateway]
# Keep the primary listener on the built-in 127.0.0.1:17670 default. The
# Podman driver reports the callback interface it needs, and the gateway
# adds a separate listener scoped to that interface.

# Pin to the Podman compute driver. Without this, the gateway auto-detects
# in order: Kubernetes, Podman, Docker. Pinning prevents unexpected driver
# selection if Docker is also installed on the host.
compute_drivers = ["podman"]
"""


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
    shipped_v1 = SHIPPED_V1_FIXTURE
    assert b'compute_drivers = ["podman"]' in shipped_v1
    assert LEGACY.read_bytes() == shipped_v1
    destination.write_bytes(shipped_v1)

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


def test_shipped_rpm_defaults_have_expected_schema_shapes() -> None:
    import tomllib

    current = tomllib.loads(CURRENT.read_text(encoding="utf-8"))
    legacy = tomllib.loads(LEGACY.read_text(encoding="utf-8"))

    assert current["openshell"]["version"] == 2
    assert current["openshell"]["gateway"]["compute_driver"] == "podman"
    assert "compute_drivers" not in current["openshell"]["gateway"]
    assert current["openshell"]["drivers"]["podman"]["health_check_interval_secs"] == 10
    assert LEGACY.read_bytes() == SHIPPED_V1_FIXTURE
    assert legacy["openshell"]["version"] == 1
    assert legacy["openshell"]["gateway"]["compute_drivers"] == ["podman"]
    assert "compute_driver" not in legacy["openshell"]["gateway"]


def test_migrator_rejects_wrong_argument_count() -> None:
    result = subprocess.run(
        ["sh", str(MIGRATOR)], text=True, capture_output=True, check=False
    )

    assert result.returncode == 2
    assert result.stderr == (
        f"usage: {MIGRATOR} DESTINATION CURRENT_DEFAULT LEGACY_DEFAULT\n"
    )


def test_migrator_seeds_with_mode_0644(tmp_path: Path) -> None:
    destination = tmp_path / "config/openshell/gateway.toml"

    run_migrator(destination)

    assert destination.read_bytes() == CURRENT.read_bytes()
    assert destination.stat().st_mode & 0o777 == 0o644


def test_migrator_preserves_operator_content_and_mode(tmp_path: Path) -> None:
    destination = tmp_path / "gateway.toml"
    edited = LEGACY.read_text(encoding="utf-8") + "# operator edit\\n"
    destination.write_text(edited, encoding="utf-8")
    destination.chmod(0o600)

    run_migrator(destination)

    assert destination.read_text(encoding="utf-8") == edited
    assert destination.stat().st_mode & 0o777 == 0o600

    destination.write_bytes(CURRENT.read_bytes())
    destination.chmod(0o640)
    run_migrator(destination)
    assert destination.read_bytes() == CURRENT.read_bytes()
    assert destination.stat().st_mode & 0o777 == 0o640


def test_migrator_handles_paths_containing_spaces(tmp_path: Path) -> None:
    package = tmp_path / "package defaults"
    package.mkdir()
    current = package / "current default.toml"
    legacy = package / "legacy default.toml"
    current.write_bytes(CURRENT.read_bytes())
    legacy.write_bytes(LEGACY.read_bytes())
    destination = tmp_path / "operator config/gateway config.toml"

    subprocess.run(
        ["sh", str(MIGRATOR), str(destination), str(current), str(legacy)],
        check=True,
    )

    assert destination.read_bytes() == current.read_bytes()
    assert destination.stat().st_mode & 0o777 == 0o644


def test_migrator_rejects_missing_and_nonregular_sources(tmp_path: Path) -> None:
    for source_name in ("current", "legacy"):
        for source_kind in ("missing", "directory", "symlink"):
            current = tmp_path / f"{source_name}-{source_kind}-current.toml"
            legacy = tmp_path / f"{source_name}-{source_kind}-legacy.toml"
            current.write_bytes(CURRENT.read_bytes())
            legacy.write_bytes(LEGACY.read_bytes())
            source = current if source_name == "current" else legacy
            if source_kind == "missing":
                source.unlink()
            elif source_kind == "directory":
                source.unlink()
                source.mkdir()
            else:
                source.unlink()
                source.symlink_to(CURRENT)

            result = subprocess.run(
                [
                    "sh",
                    str(MIGRATOR),
                    str(tmp_path / f"{source_name}-{source_kind}-destination.toml"),
                    str(current),
                    str(legacy),
                ],
                check=False,
                text=True,
                capture_output=True,
            )

            assert result.returncode == 1
            assert (
                f"gateway config migration source is not a regular file: {source}"
                in result.stderr
            )


def test_migrator_refuses_directory_destination(tmp_path: Path) -> None:
    destination = tmp_path / "gateway.toml"
    destination.mkdir()

    result = run_migrator(destination, check=False)

    assert result.returncode == 1
    assert (
        f"refusing to replace non-regular gateway config: {destination}"
        in result.stderr
    )
