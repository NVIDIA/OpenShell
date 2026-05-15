# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
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
    assert '(libexec/"init-gateway-config.sh").write' in formula
    assert 'bind_address = "127.0.0.1:17670"' in formula
    assert '# compute_drivers = ["vm"]' in formula
    assert '# compute_drivers = ["docker"]' in formula
    assert "[openshell.gateway.tls]" in formula
    assert 'cert_path = $(toml_string "${pki_dir}/server/tls.crt")' in formula
    assert 'driver_dir = $(toml_string "$driver_dir")' in formula
    assert '"#{opt_libexec}/init-gateway-config.sh" homebrew' in formula
    assert '"ghcr.io/nvidia/openshell/supervisor:0.0.10"' in formula
    assert 'run opt_libexec/"openshell-gateway-homebrew-service"' in formula
    assert 'xdg_config_home="${XDG_CONFIG_HOME:-${HOME}/.config}"' in formula
    assert 'xdg_gateway_config="${xdg_config_home}/openshell/gateway.toml"' in formula
    assert 'prefix_gateway_config="#{var}/openshell/gateway.toml"' in formula
    assert 'elif [ -f "${xdg_gateway_config}" ]; then' in formula
    assert 'gateway_config="${xdg_gateway_config}"' in formula
    assert 'gateway_config="${prefix_gateway_config}"' in formula
    assert (
        'gateway_db_url="${OPENSHELL_DB_URL:-sqlite:#{var}/openshell/gateway/openshell.db}"'
    ) in formula
    assert (
        'exec "#{opt_bin}/openshell-gateway" --config "${gateway_config}" --db-url "${gateway_db_url}"'
    ) in formula
    assert 'docker_tls_dir="${HOME}/.local/state/openshell/homebrew/tls"' in formula
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


def test_gateway_config_helper_ignores_legacy_gateway_environment(
    tmp_path: Path,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    config = tmp_path / "gateway.toml"
    pki_dir = tmp_path / "tls"
    driver_dir = tmp_path / "libexec"
    vm_state_dir = tmp_path / "vm-driver"

    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "OPENSHELL_BIND_ADDRESS": "::1",
        "OPENSHELL_SERVER_PORT": "19090",
        "OPENSHELL_DRIVERS": "vm",
        "OPENSHELL_TLS_CERT": "/legacy/server.crt",
        "OPENSHELL_TLS_KEY": "/legacy/server.key",
        "OPENSHELL_TLS_CLIENT_CA": "/legacy/ca.crt",
    }
    subprocess.run(
        [
            str(repo_root / "deploy/common/init-gateway-config.sh"),
            "deb",
            str(config),
            str(pki_dir),
            str(driver_dir),
            str(vm_state_dir),
        ],
        check=True,
        env=env,
    )

    contents = config.read_text(encoding="utf-8")
    assert '# compute_drivers = ["vm"]' in contents

    data = tomllib.loads(contents)
    openshell = data["openshell"]
    gateway = openshell["gateway"]
    assert gateway["bind_address"] == "127.0.0.1:17670"
    assert "compute_drivers" not in gateway
    assert gateway["tls"]["cert_path"] == str(pki_dir / "server/tls.crt")
    assert gateway["tls"]["key_path"] == str(pki_dir / "server/tls.key")
    assert gateway["tls"]["client_ca_path"] == str(pki_dir / "ca.crt")
    assert openshell["drivers"]["vm"]["driver_dir"] == str(driver_dir)
    assert openshell["drivers"]["vm"]["state_dir"] == str(vm_state_dir)
    assert openshell["drivers"]["vm"]["grpc_endpoint"] == "https://127.0.0.1:17670"


def test_snap_gateway_config_does_not_select_compute_driver(
    tmp_path: Path,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    config = tmp_path / "gateway.toml"
    supervisor_bin = tmp_path / "snap/bin/openshell-sandbox"

    subprocess.run(
        [
            str(repo_root / "deploy/common/init-gateway-config.sh"),
            "snap",
            str(config),
            str(supervisor_bin),
        ],
        check=True,
    )

    contents = config.read_text(encoding="utf-8")
    assert '# compute_drivers = ["docker"]' in contents

    data = tomllib.loads(contents)
    openshell = data["openshell"]
    gateway = openshell["gateway"]
    assert "compute_drivers" not in gateway
    assert gateway["disable_tls"] is True
    assert openshell["drivers"]["docker"]["supervisor_bin"] == str(supervisor_bin)


def test_rpm_gateway_config_does_not_select_compute_driver(
    tmp_path: Path,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    config = tmp_path / "gateway.toml"
    pki_dir = tmp_path / "tls"
    supervisor_image = "ghcr.io/nvidia/openshell/supervisor:test"

    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "OPENSHELL_DRIVERS": "podman",
        "OPENSHELL_BIND_ADDRESS": "0.0.0.0",
        "OPENSHELL_SERVER_PORT": "8080",
    }
    subprocess.run(
        [
            str(repo_root / "deploy/common/init-gateway-config.sh"),
            "rpm",
            str(config),
            str(pki_dir),
            supervisor_image,
        ],
        check=True,
        env=env,
    )

    contents = config.read_text(encoding="utf-8")
    assert '# compute_drivers = ["podman"]' in contents

    data = tomllib.loads(contents)
    openshell = data["openshell"]
    gateway = openshell["gateway"]
    assert gateway["bind_address"] == "127.0.0.1:17670"
    assert "compute_drivers" not in gateway
    assert gateway["supervisor_image"] == supervisor_image
    assert gateway["tls"]["cert_path"] == str(pki_dir / "server/tls.crt")
    assert gateway["guest_tls_ca"] == str(pki_dir / "ca.crt")
    assert openshell["drivers"]["podman"]["image_pull_policy"] == "missing"
    assert openshell["drivers"]["podman"]["network_name"] == "openshell"
    assert openshell["drivers"]["podman"]["stop_timeout_secs"] == 10


def test_rpm_spec_uses_shared_gateway_config_helper_without_generated_env() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    spec = (repo_root / "openshell.spec").read_text(encoding="utf-8")

    assert "init-gateway-env" not in spec
    assert "init-gateway-config.sh rpm" in spec
    assert "EnvironmentFile=-%%E/openshell/gateway.env" in spec
    assert "Environment=OPENSHELL_DRIVERS" not in spec
    assert "Environment=OPENSHELL_BIND_ADDRESS" not in spec
    assert "Environment=OPENSHELL_PODMAN_TLS_CA" not in spec
    assert '--config "$${OPENSHELL_GATEWAY_CONFIG:-%%E/openshell/gateway.toml}"' in spec
    assert '--db-url "$${OPENSHELL_DB_URL:-sqlite://%%S/openshell/gateway.db}"' in spec


def test_deb_user_service_stores_gateway_config_under_xdg_config() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    unit = (repo_root / "deploy/deb/openshell-gateway.service").read_text(
        encoding="utf-8"
    )

    assert "EnvironmentFile=-%E/openshell/gateway.env" in unit
    assert "init-gateway-config.sh deb %E/openshell/gateway.toml" in unit
    assert '--config "$${OPENSHELL_GATEWAY_CONFIG:-%E/openshell/gateway.toml}"' in unit
    assert "%S/openshell/gateway/config.toml" not in unit
