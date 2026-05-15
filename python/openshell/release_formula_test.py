# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_generate_homebrew_formula_uses_tagged_macos_driver_asset_without_default_driver(
    tmp_path: Path,
) -> None:
    release_dir = tmp_path / "release"
    release_dir.mkdir()
    (release_dir / "openshell-checksums-sha256.txt").write_text(
        "\n".join(
            [
                "a" * 64 + "  openshell-aarch64-apple-darwin.tar.gz",
                "b" * 64 + "  openshell-driver-vm-aarch64-apple-darwin.tar.gz",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (release_dir / "openshell-gateway-checksums-sha256.txt").write_text(
        "d" * 64 + "  openshell-gateway-aarch64-apple-darwin.tar.gz\n",
        encoding="utf-8",
    )

    repo_root = Path(__file__).resolve().parents[2]
    output = tmp_path / "openshell.rb"
    subprocess.run(
        [
            sys.executable,
            str(repo_root / "tasks/scripts/release.py"),
            "generate-homebrew-formula",
            "--release-tag",
            "v0.0.10",
            "--release-dir",
            str(release_dir),
            "--output",
            str(output),
        ],
        check=True,
    )

    formula = output.read_text(encoding="utf-8")
    assert (
        "https://github.com/NVIDIA/OpenShell/releases/download/"
        "v0.0.10/openshell-driver-vm-aarch64-apple-darwin.tar.gz"
    ) in formula
    assert 'sha256 "' + "b" * 64 + '"' in formula
    assert "OPENSHELL_DRIVERS:" not in formula
    assert "#OPENSHELL_DRIVERS=vm" in formula
    assert 'OPENSHELL_GATEWAY_CONFIG: "#{var}/openshell/gateway.toml"' in formula
    assert 'driver_dir = "#{opt_libexec}"' in formula
    assert 'supervisor_image = "ghcr.io/nvidia/openshell/supervisor:0.0.10"' in formula
    assert 'run opt_libexec/"openshell-gateway-homebrew-service"' in formula
    assert (
        'docker_tls_dir="${OPENSHELL_DOCKER_TLS_DIR:-${HOME}/.local/state/openshell/homebrew/tls}"'
    ) in formula
    assert 'guest_tls_ca = "${docker_tls_dir}/ca.crt"' in formula
    assert 'gateway_env="#{var}/openshell/gateway.env"' in formula
    assert '. "${gateway_env}"' in formula
    assert "OPENSHELL_DRIVER_DIR:" not in formula
    assert "OPENSHELL_DOCKER_SUPERVISOR_IMAGE:" not in formula
    assert 'OPENSHELL_DOCKER_TLS_CA: "#{var}/openshell/tls/ca.crt"' not in formula
    assert "entitlements.atomic_write" in formula
    assert "brew services restart openshell" in formula
