#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

SEMVER_TAG_GLOB = "v[0-9]*.[0-9]*.[0-9]*"
SEMVER_TAG_RE = re.compile(r"^v?(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$")


@dataclass(frozen=True)
class Versions:
    python: str
    cargo: str
    docker: str
    deb: str
    snap: str
    rpm_version: str
    rpm_release: str
    git_tag: str
    git_sha: str
    git_distance: int


HOMEBREW_TARGET = "aarch64-apple-darwin"
HOMEBREW_CLI_ASSET = f"openshell-{HOMEBREW_TARGET}.tar.gz"
HOMEBREW_GATEWAY_ASSET = f"openshell-gateway-{HOMEBREW_TARGET}.tar.gz"
HOMEBREW_DRIVER_VM_ASSET = f"openshell-driver-vm-{HOMEBREW_TARGET}.tar.gz"
GITHUB_RELEASE_DOWNLOADS = "https://github.com/NVIDIA/OpenShell/releases/download"
LOCAL_GATEWAY_PORT = 17670
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_RELEASE_TAG_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _run(cmd: list[str], *, env: dict[str, str] | None = None) -> None:
    subprocess.run(cmd, check=True, env=env)


def _git(cmd: list[str]) -> str:
    return (
        subprocess.check_output(["git", *cmd], cwd=_repo_root()).decode("utf-8").strip()
    )


def _parse_semver_tag(tag: str) -> tuple[int, int, int] | None:
    match = SEMVER_TAG_RE.match(tag)
    if match is None:
        return None
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
    )


def _format_semver(version: tuple[int, int, int]) -> str:
    return f"{version[0]}.{version[1]}.{version[2]}"


def _next_patch(version: tuple[int, int, int]) -> tuple[int, int, int]:
    return version[0], version[1], version[2] + 1


def _latest_semver_tag() -> str | None:
    try:
        tag = _git(
            ["describe", "--tags", "--match", SEMVER_TAG_GLOB, "--abbrev=0", "HEAD"]
        )
    except subprocess.CalledProcessError:
        return None

    if _parse_semver_tag(tag) is None:
        raise RuntimeError(f"git describe returned non-semver release tag: {tag}")
    return tag


def _versions_from_parts(
    base_version: tuple[int, int, int],
    git_distance: int,
    git_sha: str,
    git_tag: str,
) -> Versions:
    if git_distance == 0:
        python_version = _format_semver(base_version)
        rpm_version = python_version
        rpm_release = "1"
    else:
        next_version = _format_semver(_next_patch(base_version))
        python_version = f"{next_version}.dev{git_distance}+g{git_sha}"
        rpm_version = next_version
        rpm_release = f"0.dev.{git_distance}.g{git_sha}"

    # Convert PEP 440 to a SemVer-ish string for Cargo:
    # 0.1.0.dev3+gabcdef -> 0.1.0-dev.3+gabcdef
    cargo_version = re.sub(r"\.dev(\d+)", r"-dev.\1", python_version)

    # Docker tags can't contain '+'.
    docker_version = cargo_version.replace("+", "-")

    # Snap versions cannot contain '+' and are limited to 32 characters.
    snap_version = re.sub(r"\.d\d{8}$", "", docker_version)
    if len(snap_version) > 32:
        raise ValueError(f"snap version must be at most 32 characters: {snap_version}")

    # Debian versions use '~' so prereleases sort before the eventual release.
    deb_version = cargo_version
    deb_version = deb_version[1:] if deb_version.startswith("v") else deb_version
    deb_version = deb_version.replace("-dev.", "~dev.", 1)
    deb_version = f"{deb_version}-1"

    return Versions(
        python=python_version,
        cargo=cargo_version,
        docker=docker_version,
        deb=deb_version,
        snap=snap_version,
        rpm_version=rpm_version,
        rpm_release=rpm_release,
        git_tag=git_tag,
        git_sha=git_sha,
        git_distance=git_distance,
    )


def _compute_versions() -> Versions:
    git_tag = _latest_semver_tag()
    git_sha = _git(["rev-parse", "--short=9", "HEAD"])

    if git_tag is None:
        base_version = (0, 0, 0)
        git_distance = int(_git(["rev-list", "--count", "HEAD"]))
        return _versions_from_parts(base_version, git_distance, git_sha, "")

    parsed_tag = _parse_semver_tag(git_tag)
    if parsed_tag is None:
        raise RuntimeError(f"invalid semantic release tag: {git_tag}")

    git_distance = int(_git(["rev-list", f"{git_tag}..HEAD", "--count"]))
    return _versions_from_parts(parsed_tag, git_distance, git_sha, git_tag)


def _print_env(versions: Versions) -> None:
    print(f"VERSION_PY={versions.python}")
    print(f"VERSION_CARGO={versions.cargo}")
    print(f"VERSION_DOCKER={versions.docker}")
    print(f"VERSION_DEB={versions.deb}")
    print(f"VERSION_SNAP={versions.snap}")
    print(f"VERSION_RPM={versions.rpm_version}")
    print(f"VERSION_RPM_RELEASE={versions.rpm_release}")
    print(f"GIT_TAG={versions.git_tag}")
    print(f"GIT_SHA={versions.git_sha}")
    print(f"GIT_DISTANCE={versions.git_distance}")


def get_version(format: str) -> None:
    versions = _compute_versions()
    if format == "python":
        print(versions.python)
    elif format == "cargo":
        print(versions.cargo)
    elif format == "docker":
        print(versions.docker)
    elif format == "deb":
        print(versions.deb)
    elif format == "snap":
        print(versions.snap)
    elif format == "rpm-version":
        print(versions.rpm_version)
    elif format == "rpm-release":
        print(versions.rpm_release)
    elif format == "json":
        print(json.dumps(asdict(versions), sort_keys=True))
    else:
        _print_env(versions)


def _parse_sha256_file(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 2:
            raise ValueError(f"{path}:{line_number}: malformed checksum line")

        digest = parts[0].lower()
        if not _SHA256_RE.fullmatch(digest):
            raise ValueError(f"{path}:{line_number}: invalid SHA-256 digest")

        filename = parts[1].lstrip("*")
        checksums[filename] = digest

    return checksums


def _required_checksum(
    checksums: dict[str, str],
    filename: str,
    checksum_path: Path,
) -> str:
    try:
        return checksums[filename]
    except KeyError as exc:
        raise ValueError(f"{checksum_path}: missing checksum for {filename}") from exc


def _asset_url(release_tag: str, filename: str) -> str:
    return f"{GITHUB_RELEASE_DOWNLOADS}/{release_tag}/{filename}"


def _homebrew_supervisor_image(release_tag: str) -> str:
    image_tag = "dev" if release_tag == "dev" else release_tag.removeprefix("v")
    return f"ghcr.io/nvidia/openshell/supervisor:{image_tag}"


def render_homebrew_formula(
    *,
    release_tag: str,
    cli_sha256: str,
    gateway_sha256: str,
    driver_vm_sha256: str,
) -> str:
    if not _RELEASE_TAG_RE.fullmatch(release_tag):
        raise ValueError(f"release tag contains unsupported characters: {release_tag}")

    version = release_tag.removeprefix("v")
    docker_supervisor_image = _homebrew_supervisor_image(release_tag)
    return f"""# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Generated by tasks/scripts/release.py. Do not edit by hand.

class Openshell < Formula
  desc "Safe, private runtime for autonomous AI agents"
  homepage "https://github.com/NVIDIA/OpenShell"
  url "{_asset_url(release_tag, HOMEBREW_CLI_ASSET)}"
  sha256 "{cli_sha256}"
  version "{version}"
  license "Apache-2.0"

  depends_on macos: :big_sur
  depends_on arch: :arm64

  resource "openshell-gateway" do
    url "{_asset_url(release_tag, HOMEBREW_GATEWAY_ASSET)}"
    sha256 "{gateway_sha256}"
  end

  resource "openshell-driver-vm" do
    url "{_asset_url(release_tag, HOMEBREW_DRIVER_VM_ASSET)}"
    sha256 "{driver_vm_sha256}"
  end

  def install
    odie "OpenShell Homebrew formula currently supports macOS only" unless OS.mac?

    bin.install "openshell"

    resource("openshell-gateway").stage do
      bin.install "openshell-gateway"
    end

    resource("openshell-driver-vm").stage do
      libexec.install "openshell-driver-vm"
    end

    (libexec/"openshell-gateway-homebrew-service").write <<~SH
      #!/bin/sh
      set -eu

      if [ -z "${{HOME:-}}" ]; then
        echo "HOME must be set for Docker TLS bind mounts" >&2
        exit 1
      fi

      docker_tls_dir="${{OPENSHELL_DOCKER_TLS_DIR:-${{HOME}}/.local/state/openshell/homebrew/tls}}"
      mkdir -p "${{docker_tls_dir}}/client"
      chmod 700 "${{docker_tls_dir}}" "${{docker_tls_dir}}/client"
      /usr/bin/install -m 0644 "#{{var}}/openshell/tls/ca.crt" "${{docker_tls_dir}}/ca.crt"
      /usr/bin/install -m 0644 "#{{var}}/openshell/tls/client/tls.crt" "${{docker_tls_dir}}/client/tls.crt"
      /usr/bin/install -m 0600 "#{{var}}/openshell/tls/client/tls.key" "${{docker_tls_dir}}/client/tls.key"

      export OPENSHELL_DOCKER_TLS_CA="${{docker_tls_dir}}/ca.crt"
      export OPENSHELL_DOCKER_TLS_CERT="${{docker_tls_dir}}/client/tls.crt"
      export OPENSHELL_DOCKER_TLS_KEY="${{docker_tls_dir}}/client/tls.key"

      gateway_env="#{{var}}/openshell/gateway.env"
      if [ -f "${{gateway_env}}" ]; then
        set -a
        . "${{gateway_env}}"
        set +a
      fi

      exec "#{{opt_bin}}/openshell-gateway"
    SH
    chmod 0755, libexec/"openshell-gateway-homebrew-service"
  end

  def post_install
    (var/"openshell/gateway").mkpath
    (var/"openshell/vm-driver").mkpath
    (var/"log/openshell").mkpath
    system bin/"openshell-gateway", "generate-certs", "--output-dir", var/"openshell/tls", "--server-san", "host.openshell.internal"

    gateway_env = var/"openshell/gateway.env"
    unless gateway_env.exist?
      gateway_env.atomic_write <<~ENV
        # OpenShell Gateway Environment Configuration
        # Edit freely; this file is not overwritten.
        #
        # Uncomment to force the VM compute driver. Leaving this unset keeps
        # normal Podman/Docker/Kubernetes auto-detection.
        #OPENSHELL_DRIVERS=vm

        # VM driver paths configured by the Homebrew service.
        #OPENSHELL_VM_DRIVER_STATE_DIR=#{{var}}/openshell/vm-driver
        #OPENSHELL_VM_TLS_CA=#{{var}}/openshell/tls/ca.crt
        #OPENSHELL_VM_TLS_CERT=#{{var}}/openshell/tls/client/tls.crt
        #OPENSHELL_VM_TLS_KEY=#{{var}}/openshell/tls/client/tls.key
      ENV
      chmod 0600, gateway_env
    end

    entitlements = var/"openshell/openshell-driver-vm.entitlements.plist"
    entitlements.atomic_write <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0">
      <dict>
          <key>com.apple.security.hypervisor</key>
          <true/>
      </dict>
      </plist>
    XML

    system "/usr/bin/codesign", "--entitlements", entitlements, "--force", "-s", "-", libexec/"openshell-driver-vm"
  end

  service do
    run opt_libexec/"openshell-gateway-homebrew-service"
    environment_variables(
      OPENSHELL_BIND_ADDRESS: "127.0.0.1",
      OPENSHELL_SERVER_PORT: "{LOCAL_GATEWAY_PORT}",
      OPENSHELL_TLS_CERT: "#{{var}}/openshell/tls/server/tls.crt",
      OPENSHELL_TLS_KEY: "#{{var}}/openshell/tls/server/tls.key",
      OPENSHELL_TLS_CLIENT_CA: "#{{var}}/openshell/tls/ca.crt",
      OPENSHELL_DB_URL: "sqlite:#{{var}}/openshell/gateway/openshell.db",
      OPENSHELL_GRPC_ENDPOINT: "https://127.0.0.1:{LOCAL_GATEWAY_PORT}",
      OPENSHELL_SSH_GATEWAY_HOST: "127.0.0.1",
      OPENSHELL_SSH_GATEWAY_PORT: "{LOCAL_GATEWAY_PORT}",
      OPENSHELL_VM_DRIVER_STATE_DIR: "#{{var}}/openshell/vm-driver",
      OPENSHELL_VM_TLS_CA: "#{{var}}/openshell/tls/ca.crt",
      OPENSHELL_VM_TLS_CERT: "#{{var}}/openshell/tls/client/tls.crt",
      OPENSHELL_VM_TLS_KEY: "#{{var}}/openshell/tls/client/tls.key",
      OPENSHELL_DOCKER_SUPERVISOR_IMAGE: "{docker_supervisor_image}",
      OPENSHELL_PODMAN_TLS_CA: "#{{var}}/openshell/tls/ca.crt",
      OPENSHELL_PODMAN_TLS_CERT: "#{{var}}/openshell/tls/client/tls.crt",
      OPENSHELL_PODMAN_TLS_KEY: "#{{var}}/openshell/tls/client/tls.key",
      OPENSHELL_DRIVER_DIR: "#{{opt_libexec}}",
    )
    keep_alive successful_exit: false
    log_path var/"log/openshell/openshell-gateway.out.log"
    error_log_path var/"log/openshell/openshell-gateway.err.log"
  end

  def caveats
    <<~EOS
      Start or restart the local gateway with:
        brew services restart openshell

      Register it with the OpenShell CLI:
        openshell gateway add https://127.0.0.1:{LOCAL_GATEWAY_PORT} --local --name openshell
    EOS
  end

  test do
    assert_match "openshell ", shell_output("#{{bin}}/openshell --version")
  end
end
"""


def generate_homebrew_formula(
    *,
    release_tag: str,
    release_dir: Path,
    output: Path,
) -> None:
    checksums_path = release_dir / "openshell-checksums-sha256.txt"
    gateway_checksums_path = release_dir / "openshell-gateway-checksums-sha256.txt"
    checksums = _parse_sha256_file(checksums_path)
    gateway_checksums = _parse_sha256_file(gateway_checksums_path)

    formula = render_homebrew_formula(
        release_tag=release_tag,
        cli_sha256=_required_checksum(checksums, HOMEBREW_CLI_ASSET, checksums_path),
        gateway_sha256=_required_checksum(
            gateway_checksums,
            HOMEBREW_GATEWAY_ASSET,
            gateway_checksums_path,
        ),
        driver_vm_sha256=_required_checksum(
            checksums,
            HOMEBREW_DRIVER_VM_ASSET,
            checksums_path,
        ),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(formula, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OpenClaw release tooling.")
    sub = parser.add_subparsers(dest="command", required=True)

    get_version_parser = sub.add_parser("get-version", help="Print computed version.")
    get_version_parser.add_argument(
        "--python", action="store_true", help="Print Python version only."
    )
    get_version_parser.add_argument(
        "--cargo", action="store_true", help="Print Cargo version only."
    )
    get_version_parser.add_argument(
        "--docker", action="store_true", help="Print Docker version only."
    )
    get_version_parser.add_argument(
        "--deb", action="store_true", help="Print Debian package version only."
    )
    get_version_parser.add_argument(
        "--snap", action="store_true", help="Print Snap package version only."
    )
    get_version_parser.add_argument(
        "--rpm-version", action="store_true", help="Print RPM Version only."
    )
    get_version_parser.add_argument(
        "--rpm-release", action="store_true", help="Print RPM Release only."
    )
    get_version_parser.add_argument(
        "--json", action="store_true", help="Print all versions as JSON."
    )

    formula_parser = sub.add_parser(
        "generate-homebrew-formula",
        help="Generate the per-release Homebrew formula asset.",
    )
    formula_parser.add_argument(
        "--release-tag",
        required=True,
        help="GitHub release tag that owns the formula assets.",
    )
    formula_parser.add_argument(
        "--release-dir",
        type=Path,
        required=True,
        help="Directory containing release artifacts and checksum files.",
    )
    formula_parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path to write the generated Formula Ruby file.",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "get-version":
        if args.python:
            get_version("python")
        elif args.cargo:
            get_version("cargo")
        elif args.docker:
            get_version("docker")
        elif args.deb:
            get_version("deb")
        elif args.snap:
            get_version("snap")
        elif args.rpm_version:
            get_version("rpm-version")
        elif args.rpm_release:
            get_version("rpm-release")
        elif args.json:
            get_version("json")
        else:
            get_version("all")
    elif args.command == "generate-homebrew-formula":
        generate_homebrew_formula(
            release_tag=args.release_tag,
            release_dir=args.release_dir,
            output=args.output,
        )


if __name__ == "__main__":
    main()
