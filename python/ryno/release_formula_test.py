# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


def test_generate_homebrew_formula_uses_channel_urls_and_exact_version(
    tmp_path: Path,
) -> None:
    release_dir = tmp_path / "release"
    release_dir.mkdir()
    (release_dir / "ryno-checksums-sha256.txt").write_text(
        "\n".join(
            [
                "a" * 64 + "  ryno-aarch64-apple-darwin.tar.gz",
                "b" * 64 + "  ryno-driver-vm-aarch64-apple-darwin.tar.gz",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (release_dir / "ryno-gateway-checksums-sha256.txt").write_text(
        "d" * 64 + "  ryno-gateway-aarch64-apple-darwin.tar.gz\n",
        encoding="utf-8",
    )
    (release_dir / "ryno-prover-checksums-sha256.txt").write_text(
        "e" * 64 + "  ryno-prover-aarch64-apple-darwin.tar.gz\n",
        encoding="utf-8",
    )

    repo_root = Path(__file__).resolve().parents[2]
    output = tmp_path / "ryno.rb"
    subprocess.run(
        [
            sys.executable,
            str(repo_root / "tasks/scripts/release.py"),
            "generate-homebrew-formula",
            "--release-tag",
            "v0.1.0-pre.3",
            "--release-dir",
            str(release_dir),
            "--output",
            str(output),
        ],
        check=True,
    )

    formula = output.read_text(encoding="utf-8")
    assert (
        "https://github.com/NVIDIA/Ryno/releases/download/"
        "v0.1.0-pre.3/ryno-driver-vm-aarch64-apple-darwin.tar.gz"
    ) in formula
    assert 'version "0.1.0-pre.3"' in formula
    assert 'sha256 "' + "b" * 64 + '"' in formula
    assert (
        "https://github.com/NVIDIA/Ryno/releases/download/"
        "v0.1.0-pre.3/ryno-prover-aarch64-apple-darwin.tar.gz"
    ) in formula
    assert 'sha256 "' + "e" * 64 + '"' in formula
    assert 'resource("ryno-prover").stage' in formula
    assert 'bin.install "ryno-prover"' in formula
    assert 'bin.install_symlink bin/"ryno" => "openshell"' in formula
    assert "#{bin}/ryno-prover --version" in formula
    assert "RYNO_COMPUTE_DRIVER: " not in formula
    assert 'RYNO_GATEWAY_CONFIG: "#{var}/ryno/gateway.toml"' not in formula
    assert "init-gateway-config.sh" not in formula
    assert 'gateway_config = var/"ryno/gateway.toml"' in formula
    assert "unless gateway_config.exist?" in formula
    generated_config = re.search(
        r"gateway_config_contents = <<~TOML\n(?P<contents>.*?)\n    TOML",
        formula,
        flags=re.DOTALL,
    )
    assert generated_config is not None
    assert "version = 2" in generated_config.group("contents")
    assert "[ryno.gateway]" in generated_config.group("contents")
    assert "bind_address =" not in generated_config.group("contents")

    legacy_empty_config = re.search(
        r"legacy_empty_gateway_config_contents = <<~TOML\n(?P<contents>.*?)\n    TOML",
        formula,
        flags=re.DOTALL,
    )
    assert legacy_empty_config is not None
    assert "version = 1" in legacy_empty_config.group("contents")
    assert "bind_address =" not in legacy_empty_config.group("contents")

    legacy_ipv6_config = re.search(
        r"legacy_ipv6_gateway_config_contents = <<~TOML\n(?P<contents>.*?)\n    TOML",
        formula,
        flags=re.DOTALL,
    )
    assert legacy_ipv6_config is not None
    assert "version = 1" in legacy_ipv6_config.group("contents")
    assert 'bind_address = "[::1]:17670"' in legacy_ipv6_config.group("contents")
    assert "gateway_config.read == legacy_empty_gateway_config_contents ||" in formula
    assert "gateway_config.read == legacy_ipv6_gateway_config_contents" in formula
    assert formula.count("gateway_config.write gateway_config_contents") == 1
    assert "gateway_config.atomic_write gateway_config_contents" in formula
    assert '# compute_driver = "vm"' not in formula
    assert "ryno gateway add https://localhost:17670 --local --name ryno" in formula
    assert 'run opt_libexec/"ryno-gateway-homebrew-service"' in formula
    assert 'xdg_config_home="${XDG_CONFIG_HOME:-${HOME}/.config}"' in formula
    assert 'xdg_gateway_config="${xdg_config_home}/ryno/gateway.toml"' in formula
    assert 'prefix_gateway_config="#{var}/ryno/gateway.toml"' in formula
    assert (
        'if [ -z "${RYNO_GATEWAY_CONFIG:-}" ] && [ ! -f "${xdg_gateway_config}" ] && [ -f "${prefix_gateway_config}" ]; then'
    ) in formula
    assert (
        'exec "#{opt_bin}/ryno-gateway" --config "${prefix_gateway_config}"' in formula
    )
    assert 'exec "#{opt_bin}/ryno-gateway"' in formula
    assert "--db-url" not in formula
    assert 'docker_tls_dir="${HOME}/.local/state/ryno/homebrew/tls"' in formula
    assert (
        'export RYNO_LOCAL_TLS_DIR="${RYNO_LOCAL_TLS_DIR:-${docker_tls_dir}}"'
        in formula
    )
    assert '/usr/bin/install -m 0600 "#{var}/ryno/tls/server/tls.key"' in formula
    assert "RYNO_CONFIG_" not in formula
    assert "RYNO_DOCKER_TLS_DIR" not in formula
    assert 'xdg_gateway_env="${xdg_config_home}/ryno/gateway.env"' in formula
    assert 'prefix_gateway_env="#{var}/ryno/gateway.env"' in formula
    assert '. "${xdg_gateway_env}"' in formula
    assert '. "${prefix_gateway_env}"' in formula
    assert 'gateway_env = var/"ryno/gateway.env"' not in formula
    assert "#RYNO_GATEWAY_CONFIG=#{var}/ryno/gateway.toml" not in formula
    assert "environment_variables(" not in formula
    assert "      RYNO_BIND_ADDRESS:" not in formula
    assert "      RYNO_SERVER_PORT:" not in formula
    assert "      RYNO_TLS_CERT:" not in formula
    assert "RYNO_DRIVER_DIR:" not in formula
    assert "RYNO_DOCKER_SUPERVISOR_IMAGE:" not in formula
    assert 'RYNO_DOCKER_TLS_CA: "#{var}/ryno/tls/ca.crt"' not in formula
    assert "entitlements.atomic_write" in formula
    assert "brew services restart ryno" in formula


def test_snap_wrapper_uses_optional_gateway_config_without_generating_toml() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    wrapper = (repo_root / "tasks/scripts/snap-gateway-wrapper.sh").read_text(
        encoding="utf-8"
    )

    assert "init-gateway-config.sh" not in wrapper
    assert (
        'export RYNO_DB_URL="${RYNO_DB_URL:-sqlite:${SNAP_COMMON}/gateway.db?mode=rwc}"'
        in wrapper
    )
    assert "RYNO_DISABLE_TLS" not in wrapper
    assert (
        'export RYNO_LOCAL_TLS_DIR="${RYNO_LOCAL_TLS_DIR:-${SNAP_COMMON}/tls}"'
        in wrapper
    )
    assert (
        'exec "${SNAP}/bin/ryno-gateway" --config "$CANONICAL_CONFIG_FILE" "$@"'
        in wrapper
    )
    assert 'exec "${SNAP}/bin/ryno-gateway" "$@"' in wrapper


def test_rpm_spec_seeds_and_migrates_gateway_defaults() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    spec = (repo_root / "ryno.spec").read_text(encoding="utf-8")

    assert "init-gateway-config.sh" not in spec
    assert "init-pki.sh" not in spec
    assert "migrate-gateway-config.sh" in spec
    assert "gateway.toml.default.v1" in spec
    assert "%{name}-gateway-migrate-config" in spec
    assert "ExecStartPre=/usr/bin/ryno-gateway config preflight" in spec
    assert "Environment=RYNO_LOCAL_TLS_DIR=%%h/.local/state/ryno/tls" in spec
    assert "ryno-gateway generate-certs --output-dir ${RYNO_LOCAL_TLS_DIR}" in spec
    assert "EnvironmentFile=-%%E/ryno/gateway.env" in spec
    assert "%%S/ryno/tls" not in spec
    assert "Environment=RYNO_COMPUTE_DRIVER" not in spec
    assert "Environment=RYNO_BIND_ADDRESS" not in spec
    assert "Environment=RYNO_PODMAN_TLS_CA" not in spec
    assert "ExecStart=/usr/bin/ryno-gateway" in spec
    assert "--config" not in spec
    assert "--db-url" not in spec


def test_deb_user_service_uses_gateway_defaults_without_config_helper() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    unit = (repo_root / "deploy/deb/ryno-gateway.service").read_text(encoding="utf-8")

    assert "EnvironmentFile=-%E/ryno/gateway.env" in unit
    assert "Environment=RYNO_LOCAL_TLS_DIR=%h/.local/state/ryno/tls" in unit
    assert "ryno-gateway generate-certs --output-dir ${RYNO_LOCAL_TLS_DIR}" in unit
    assert "%S/ryno/tls" not in unit
    assert "init-gateway-config.sh" not in unit
    assert "ExecStart=/usr/bin/ryno-gateway" in unit
    assert "--config" not in unit
    assert "--db-url" not in unit


def test_rpm_exec_start_pre_argument_and_execution_order() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    spec = (repo_root / "ryno.spec").read_text(encoding="utf-8")

    migration = (
        "ExecStartPre=%{_libexecdir}/%{name}-gateway-migrate-config "
        "%%E/ryno/gateway.toml "
        "/usr/share/ryno-gateway/gateway.toml.default "
        "/usr/share/ryno-gateway/gateway.toml.default.v1"
    )
    preflight = "ExecStartPre=/usr/bin/ryno-gateway config preflight"
    certs = "ExecStartPre=/usr/bin/ryno-gateway generate-certs"

    assert migration in spec
    assert preflight in spec
    assert certs in spec
    assert spec.index(migration) < spec.index(preflight) < spec.index(certs)


def test_schema_v2_debian_and_snap_preflight_wiring() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    unit = (repo_root / "deploy/deb/ryno-gateway.service").read_text(encoding="utf-8")
    wrapper = (repo_root / "tasks/scripts/snap-gateway-wrapper.sh").read_text(
        encoding="utf-8"
    )
    package_deb = (repo_root / "tasks/scripts/package-deb.sh").read_text(
        encoding="utf-8"
    )
    preflight = "ExecStartPre=/usr/bin/ryno-gateway config preflight"
    certs = "ExecStartPre=/usr/bin/ryno-gateway generate-certs"
    assert preflight in unit
    assert unit.index(preflight) < unit.index(certs)
    assert "EnvironmentFile=-%E/ryno/gateway.env" in unit
    assert "ExecStart=/usr/bin/ryno-gateway" in unit
    assert "$src_dir/ryno-gateway.service" in package_deb
    assert "$pkgroot/usr/lib/systemd/user/ryno-gateway.service" in package_deb
    assert 'if [ -n "${RYNO_GATEWAY_CONFIG:-}" ]; then' in wrapper
    assert (
        'elif [ -e "$CANONICAL_CONFIG_FILE" ] || [ -L "$CANONICAL_CONFIG_FILE" ]; then'
        in wrapper
    )
    assert wrapper.count('"${SNAP}/bin/ryno-gateway" config preflight') == 4
    assert 'config preflight -- "$@"' in wrapper
    assert 'config preflight -- --config "$CANONICAL_CONFIG_FILE" "$@"' in wrapper
    assert (
        'exec "${SNAP}/bin/ryno-gateway" --config "$CANONICAL_CONFIG_FILE" "$@"'
        in wrapper
    )
    assert wrapper.count('exec "${SNAP}/bin/ryno-gateway" "$@"') == 3
    assert '[ -f "$CANONICAL_CONFIG_FILE" ]' not in wrapper
