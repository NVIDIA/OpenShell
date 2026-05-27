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
    assert "OPENSHELL_DRIVERS: " not in formula
    assert 'OPENSHELL_GATEWAY_CONFIG: "#{var}/openshell/gateway.toml"' not in formula
    assert "init-gateway-config.sh" not in formula
    assert 'bind_address = "127.0.0.1:17670"' not in formula
    assert '# compute_drivers = ["vm"]' not in formula
    assert 'run opt_libexec/"openshell-gateway-homebrew-service"' in formula
    assert 'xdg_config_home="${XDG_CONFIG_HOME:-${HOME}/.config}"' in formula
    assert 'xdg_gateway_config="${xdg_config_home}/openshell/gateway.toml"' in formula
    assert 'prefix_gateway_config="#{var}/openshell/gateway.toml"' in formula
    assert (
        'if [ -z "${OPENSHELL_GATEWAY_CONFIG:-}" ] && [ ! -f "${xdg_gateway_config}" ] && [ -f "${prefix_gateway_config}" ]; then'
    ) in formula
    assert (
        'exec "#{opt_bin}/openshell-gateway" --config "${prefix_gateway_config}"'
        in formula
    )
    assert 'exec "#{opt_bin}/openshell-gateway"' in formula
    assert "--db-url" not in formula
    assert 'docker_tls_dir="${HOME}/.local/state/openshell/homebrew/tls"' in formula
    assert (
        'export OPENSHELL_LOCAL_TLS_DIR="${OPENSHELL_LOCAL_TLS_DIR:-${docker_tls_dir}}"'
        in formula
    )
    assert '/usr/bin/install -m 0600 "#{var}/openshell/tls/server/tls.key"' in formula
    assert "OPENSHELL_CONFIG_" not in formula
    assert "OPENSHELL_DOCKER_TLS_DIR" not in formula
    assert 'xdg_gateway_env="${xdg_config_home}/openshell/gateway.env"' in formula
    assert 'prefix_gateway_env="#{var}/openshell/gateway.env"' in formula
    assert '. "${xdg_gateway_env}"' in formula
    assert '. "${prefix_gateway_env}"' in formula
    assert 'gateway_env = var/"openshell/gateway.env"' not in formula
    assert "#OPENSHELL_GATEWAY_CONFIG=#{var}/openshell/gateway.toml" not in formula
    assert "environment_variables(" not in formula
    assert "      OPENSHELL_BIND_ADDRESS:" not in formula
    assert "      OPENSHELL_SERVER_PORT:" not in formula
    assert "      OPENSHELL_TLS_CERT:" not in formula
    assert "OPENSHELL_DRIVER_DIR:" not in formula
    assert "OPENSHELL_DOCKER_SUPERVISOR_IMAGE:" not in formula
    assert 'OPENSHELL_DOCKER_TLS_CA: "#{var}/openshell/tls/ca.crt"' not in formula
    assert "entitlements.atomic_write" in formula
    assert "brew services restart openshell" in formula


def test_snap_wrapper_uses_optional_gateway_config_without_generating_toml() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    wrapper = (repo_root / "deploy/snap/bin/openshell-gateway-wrapper").read_text(
        encoding="utf-8"
    )

    assert "init-gateway-config.sh" not in wrapper
    assert (
        'export OPENSHELL_DB_URL="${OPENSHELL_DB_URL:-sqlite:${SNAP_COMMON}/gateway.db?mode=rwc}"'
        in wrapper
    )
    assert 'export OPENSHELL_DISABLE_TLS="${OPENSHELL_DISABLE_TLS:-true}"' in wrapper
    assert (
        'exec "${SNAP}/bin/openshell-gateway" --config "$CANONICAL_CONFIG_FILE" "$@"'
        in wrapper
    )
    assert 'exec "${SNAP}/bin/openshell-gateway" "$@"' in wrapper


def test_rpm_spec_uses_gateway_defaults_without_config_helper() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    spec = (repo_root / "openshell.spec").read_text(encoding="utf-8")

    assert "init-gateway-config.sh" not in spec
    assert "init-pki.sh" not in spec
    assert "Environment=OPENSHELL_LOCAL_TLS_DIR=%%h/.local/state/openshell/tls" in spec
    assert (
        "openshell-gateway generate-certs --output-dir ${OPENSHELL_LOCAL_TLS_DIR}"
        in spec
    )
    assert "EnvironmentFile=-%%E/openshell/gateway.env" in spec
    assert "%%S/openshell/tls" not in spec
    assert "Environment=OPENSHELL_DRIVERS" not in spec
    assert "Environment=OPENSHELL_BIND_ADDRESS" not in spec
    assert "Environment=OPENSHELL_PODMAN_TLS_CA" not in spec
    assert "ExecStart=/usr/bin/openshell-gateway" in spec
    assert "--config" not in spec
    assert "--db-url" not in spec


def test_deb_user_service_uses_gateway_defaults_without_config_helper() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    unit = (repo_root / "deploy/deb/openshell-gateway.service").read_text(
        encoding="utf-8"
    )

    assert "EnvironmentFile=-%E/openshell/gateway.env" in unit
    assert "Environment=OPENSHELL_LOCAL_TLS_DIR=%h/.local/state/openshell/tls" in unit
    assert (
        "openshell-gateway generate-certs --output-dir ${OPENSHELL_LOCAL_TLS_DIR}"
        in unit
    )
    assert "%S/openshell/tls" not in unit
    assert "init-gateway-config.sh" not in unit
    assert "ExecStart=/usr/bin/openshell-gateway" in unit
    assert "--config" not in unit
    assert "--db-url" not in unit
