#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Build and enter the OpenShell development sandbox."""

from __future__ import annotations

import argparse
import json
import os
import platform as host_platform
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "scripts/devbox/dev-sandbox-policy.yaml"
BUILDKIT_DIGESTS = {
    "v0.30.0": "sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f",
}


class UserError(Exception):
    """An actionable configuration or environment error."""


@dataclass(frozen=True, slots=True)
class Config:
    name: str
    image: str
    cpu: str
    memory: str
    platform: str | None
    providers: tuple[str, ...]
    sccache_volume: str
    rebuild_image: bool
    recreate_sandbox: bool
    podman_host: str | None
    podman_connection: str | None


@dataclass(frozen=True, slots=True)
class Buildkit:
    version: str
    image: str
    container: str
    volume: str = "openshell-dev-buildkit"


def parse_config() -> Config:
    parser = argparse.ArgumentParser(
        description="Build and create or reconnect to the OpenShell development sandbox.",
    )
    parser.add_argument(
        "--name", default="openshell-dev", help="sandbox name (default: openshell-dev)"
    )
    parser.add_argument(
        "--image",
        default="localhost/openshell/dev-sandbox:local",
        help="development image name (default: localhost/openshell/dev-sandbox:local)",
    )
    parser.add_argument("--cpu", default="4", help="sandbox CPU limit (default: 4)")
    parser.add_argument(
        "--memory", default="8Gi", help="sandbox memory limit (default: 8Gi)"
    )
    parser.add_argument(
        "--platform",
        help="image platform; defaults to the connected Podman host architecture",
    )
    parser.add_argument(
        "--provider",
        action="append",
        default=[],
        help="provider to attach; may be repeated",
    )
    parser.add_argument(
        "--sccache-volume",
        default="openshell-dev-sccache",
        help="Podman volume used for sccache artifacts (default: openshell-dev-sccache)",
    )
    parser.add_argument(
        "--rebuild-image",
        action="store_true",
        help="rebuild the image and recreate an existing sandbox",
    )
    parser.add_argument(
        "--recreate",
        action="store_true",
        help="delete and recreate an existing sandbox",
    )
    podman_target = parser.add_mutually_exclusive_group()
    podman_target.add_argument(
        "--podman-host",
        help="Podman service URL, including Unix and TCP URLs",
    )
    podman_target.add_argument(
        "--podman-connection",
        help="named Podman system connection",
    )
    arguments = parser.parse_args()
    return Config(
        name=arguments.name,
        image=arguments.image,
        cpu=arguments.cpu,
        memory=arguments.memory,
        platform=arguments.platform,
        providers=tuple(arguments.provider),
        sccache_volume=arguments.sccache_volume,
        rebuild_image=arguments.rebuild_image,
        recreate_sandbox=arguments.recreate or arguments.rebuild_image,
        podman_host=arguments.podman_host,
        podman_connection=arguments.podman_connection,
    )


def require_commands(*commands: str) -> None:
    for command in commands:
        if shutil.which(command) is None:
            raise UserError(f"Required command not found: {command}")


def run(
    command: list[str],
    *,
    capture: bool = False,
    check: bool = True,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    quiet: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE if capture or quiet else None,
    )


def output(
    command: list[str],
    *,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> str:
    return run(command, capture=True, check=check, env=env).stdout.strip()


def sandbox_names() -> set[str]:
    names = output(["openshell", "sandbox", "list", "--names", "--limit", "1000"])
    return set(names.splitlines())


def connect(name: str) -> NoReturn:
    print(f"Connecting to existing sandbox {name}...")
    os.execvp("openshell", ["openshell", "sandbox", "connect", name])


def normalize_unix_url(path: str) -> str:
    return path if path.startswith("unix://") else f"unix://{path}"


def podman_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("CONTAINER_HOST", None)
    environment.pop("CONTAINER_CONNECTION", None)
    return environment


def discover_podman(config: Config) -> Config:
    if config.podman_host or config.podman_connection:
        return config

    system = host_platform.system()
    if system == "Darwin":
        machine = output(
            ["podman", "machine", "info", "--format", "{{.Host.CurrentMachine}}"],
            check=False,
            env=podman_environment(),
        )
        if not machine:
            return config
        socket_path = output(
            [
                "podman",
                "machine",
                "inspect",
                "--format",
                "{{.ConnectionInfo.PodmanSocket.Path}}",
                machine,
            ],
            check=False,
            env=podman_environment(),
        )
        if not socket_path:
            raise UserError(
                f"Could not determine the socket for Podman machine {machine}."
            )
        podman_host = normalize_unix_url(socket_path)
        print(f"Probing Podman machine {machine} at {podman_host}...")
        probe = run(
            ["podman", "--remote", "--url", podman_host, "info"],
            check=False,
            env=podman_environment(),
            quiet=True,
        )
        if probe.returncode:
            raise UserError(
                f"Podman machine {machine} is not accessible at {podman_host}."
            )
        return replace(config, podman_host=podman_host)

    if system == "Linux":
        socket_path = output(
            ["podman", "info", "--format", "{{.Host.RemoteSocket.Path}}"],
            check=False,
            env=podman_environment(),
        )
        if not socket_path:
            raise UserError("Could not determine the local Podman API socket.")
        podman_host = normalize_unix_url(socket_path)
        print(f"Probing the local Podman API at {podman_host}...")
        probe = run(
            ["podman", "--remote", "--url", podman_host, "info"],
            check=False,
            env=podman_environment(),
            quiet=True,
        )
        if probe.returncode:
            raise UserError(f"The local Podman API is not accessible at {podman_host}.")
        return replace(config, podman_host=podman_host)

    return config


def podman_command(config: Config, *arguments: str) -> list[str]:
    command = ["podman"]
    if config.podman_host:
        command += ["--remote", "--url", config.podman_host]
    elif config.podman_connection:
        command += ["--connection", config.podman_connection]
    return command + list(arguments)


def podman(
    config: Config,
    *arguments: str,
    check: bool = True,
    quiet: bool = False,
) -> subprocess.CompletedProcess[str]:
    return run(
        podman_command(config, *arguments),
        check=check,
        quiet=quiet,
        env=podman_environment(),
    )


def podman_output(config: Config, *arguments: str) -> str:
    return output(podman_command(config, *arguments), env=podman_environment())


def buildctl_environment(config: Config) -> dict[str, str]:
    environment = podman_environment()
    if config.podman_host:
        environment["CONTAINER_HOST"] = config.podman_host
        environment.pop("CONTAINER_CONNECTION", None)
    elif config.podman_connection:
        environment["CONTAINER_CONNECTION"] = config.podman_connection
        environment.pop("CONTAINER_HOST", None)
    return environment


def buildctl_command(buildkit: Buildkit, *arguments: str) -> list[str]:
    return [
        "buildctl",
        f"--addr=podman-container://{buildkit.container}",
        *arguments,
    ]


def resolve_buildkit() -> Buildkit:
    fields = output(["buildctl", "--version"]).split()
    version = fields[2] if len(fields) >= 3 else ""
    digest = BUILDKIT_DIGESTS.get(version)
    if digest is None:
        if not version:
            raise UserError("Could not determine the BuildKit version from buildctl.")
        raise UserError(
            f"No pinned daemon image digest is configured for BuildKit {version}.\n"
            "Update the sandbox:dev tool pin and digest mapping together."
        )
    version_slug = version.replace(".", "-")
    return Buildkit(
        version=version,
        image=f"docker.io/moby/buildkit:{version}@{digest}",
        container=f"openshell-dev-buildkit-{version_slug}",
    )


def ensure_buildkit(config: Config, buildkit: Buildkit) -> None:
    if podman(
        config, "volume", "inspect", buildkit.volume, check=False, quiet=True
    ).returncode:
        print(f"Creating BuildKit cache volume {buildkit.volume}...")
        podman(config, "volume", "create", buildkit.volume, quiet=True)

    exists = not podman(
        config, "container", "exists", buildkit.container, check=False, quiet=True
    ).returncode
    if exists:
        running = podman_output(
            config, "inspect", "--format", "{{.State.Running}}", buildkit.container
        )
        if running != "true":
            print(f"Starting BuildKit container {buildkit.container}...")
            podman(config, "start", buildkit.container, quiet=True)
    else:
        print(f"Creating BuildKit container {buildkit.container}...")
        podman(
            config,
            "run",
            "--detach",
            "--name",
            buildkit.container,
            "--privileged",
            "--volume",
            f"{buildkit.volume}:/var/lib/buildkit",
            buildkit.image,
            quiet=True,
        )

    print("Waiting for BuildKit to become ready...")
    environment = buildctl_environment(config)
    for _ in range(30):
        ready = run(
            buildctl_command(buildkit, "debug", "info"),
            env=environment,
            check=False,
            quiet=True,
        )
        if not ready.returncode:
            return
        time.sleep(1)

    print(
        f"BuildKit container {buildkit.container} did not become ready.",
        file=sys.stderr,
    )
    print("BuildKit container logs:", file=sys.stderr)
    podman(config, "logs", buildkit.container, check=False)
    raise UserError("BuildKit startup timed out.")


def build_image(config: Config, buildkit: Buildkit) -> None:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    build_id = f"{timestamp}-{os.getpid()}-{secrets.token_hex(4)}"
    arguments = [
        "build",
        "--frontend",
        "dockerfile.v0",
        "--local",
        f"context={ROOT}",
        "--local",
        f"dockerfile={ROOT}",
        "--opt",
        "filename=scripts/devbox/Dockerfile.dev",
        "--opt",
        f"platform={config.platform}",
        "--opt",
        f"build-arg:AGENT_CLI_BUILD_ID={build_id}",
        "--output",
        f"type=docker,name={config.image},dest=-",
    ]
    if os.environ.get("GITHUB_TOKEN"):
        arguments += [
            "--secret",
            "id=GITHUB_TOKEN,env=GITHUB_TOKEN",
            "--secret",
            "id=MISE_GITHUB_TOKEN,env=GITHUB_TOKEN",
        ]
        print("Using GITHUB_TOKEN as a build secret for GitHub downloads.")

    print(f"Building and loading {config.image} for {config.platform}...")
    error_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix="openshell-dev-podman-load.", delete=False
        ) as load_error:
            error_path = Path(load_error.name)
            builder = subprocess.Popen(
                buildctl_command(buildkit, *arguments),
                env=buildctl_environment(config),
                stdout=subprocess.PIPE,
            )
            assert builder.stdout is not None
            loader = subprocess.Popen(
                podman_command(config, "load", "--quiet"),
                env=podman_environment(),
                stdin=builder.stdout,
                stderr=load_error,
            )
            builder.stdout.close()
            load_status = loader.wait()
            build_status = builder.wait()

        if build_status not in {0, 141, -signal.SIGPIPE}:
            raise subprocess.CalledProcessError(build_status, builder.args)
        if load_status:
            assert error_path is not None
            sys.stderr.write(error_path.read_text())
            raise subprocess.CalledProcessError(load_status, loader.args)
    finally:
        if error_path is not None:
            error_path.unlink(missing_ok=True)


def resolve_platform(config: Config) -> Config:
    if config.podman_host:
        print(f"Checking Podman service at {config.podman_host}...")
    elif config.podman_connection:
        print(f"Checking Podman connection {config.podman_connection}...")
    else:
        print("Checking the active Podman connection...")

    architecture = podman_output(config, "info", "--format", "{{.Host.Arch}}")
    if config.platform:
        return config
    platforms = {
        "arm64": "linux/arm64",
        "aarch64": "linux/arm64",
        "amd64": "linux/amd64",
        "x86_64": "linux/amd64",
    }
    detected = platforms.get(architecture)
    if detected is None:
        raise UserError(
            f"Unsupported Podman host architecture: {architecture}\n"
            "Pass --platform explicitly to continue."
        )
    return replace(config, platform=detected)


def ensure_image(config: Config) -> None:
    image_exists = not podman(
        config, "image", "exists", config.image, check=False, quiet=True
    ).returncode
    build_required = config.rebuild_image or not image_exists
    if config.rebuild_image:
        print(f"Rebuilding {config.image}...")
    elif not image_exists:
        print(f"Image {config.image} is not present in the Podman image store.")
    else:
        image_platform = podman_output(
            config,
            "image",
            "inspect",
            "--format",
            "{{.Os}}/{{.Architecture}}",
            config.image,
        )
        if image_platform != config.platform:
            print(
                f"Existing image platform {image_platform} does not match "
                f"{config.platform}; rebuilding."
            )
            build_required = True

    if build_required:
        buildkit = resolve_buildkit()
        ensure_buildkit(config, buildkit)
        build_image(config, buildkit)
    else:
        print(f"Reusing existing image {config.image} for {config.platform}.")


def ensure_sccache_volume(config: Config) -> None:
    missing = podman(
        config, "volume", "inspect", config.sccache_volume, check=False, quiet=True
    ).returncode
    if missing:
        print(f"Creating sccache volume {config.sccache_volume}...")
        podman(config, "volume", "create", config.sccache_volume, quiet=True)

    # Rootless Podman may map the volume root to a host identity that differs
    # from the sandbox UID. This dedicated cache volume can be world-writable.
    podman(
        config,
        "run",
        "--rm",
        "--user",
        "0",
        "--volume",
        f"{config.sccache_volume}:/sccache",
        config.image,
        "chmod",
        "0777",
        "/sccache",
    )


def delete_sandbox(config: Config) -> None:
    print(f"Deleting existing sandbox {config.name}...")
    run(["openshell", "sandbox", "delete", config.name])
    for _ in range(30):
        if config.name not in sandbox_names():
            return
        time.sleep(1)
    raise UserError(f"Timed out waiting for sandbox {config.name} to be deleted.")


def create_sandbox(config: Config) -> None:
    mounts = {
        "podman": {
            "mounts": [
                {
                    "type": "volume",
                    "source": config.sccache_volume,
                    "target": "/sccache",
                    "read_only": False,
                }
            ]
        }
    }
    command = [
        "openshell",
        "sandbox",
        "create",
        "--name",
        config.name,
        "--from",
        config.image,
        "--cpu",
        config.cpu,
        "--memory",
        config.memory,
        "--policy",
        str(POLICY),
    ]
    for provider in config.providers:
        command += ["--provider", provider]
    command += [
        "--env",
        "CARGO_HOME=/sandbox/.cache/cargo",
        "--env",
        "GOCACHE=/sandbox/.cache/go-build",
        "--env",
        "GOMODCACHE=/sandbox/.cache/go/pkg/mod",
        "--env",
        "GOPATH=/sandbox/.cache/go",
        "--env",
        "HOME=/sandbox",
        "--env",
        "SCCACHE_DIR=/sccache",
        "--env",
        "MISE_TRUSTED_CONFIG_PATHS=/sandbox",
        "--env",
        "RUSTUP_HOME=/usr/local/lib/rustup",
        "--driver-config-json",
        json.dumps(mounts, separators=(",", ":")),
        "--upload",
        ".:/sandbox",
        "--no-tty",
        "--",
        "/bin/true",
    ]
    print(f"Creating {config.name} ({config.cpu} CPU, {config.memory})...")
    run(command, cwd=ROOT)


def initialize_sandbox(config: Config) -> None:
    # Upload filtering intentionally omits Git metadata, so add it separately.
    print("Uploading Git metadata...")
    run(
        [
            "openshell",
            "sandbox",
            "upload",
            "--no-git-ignore",
            config.name,
            str(ROOT / ".git"),
            "/sandbox",
        ]
    )

    # Mise's Rust backend resolves its bin path from the runtime CARGO_HOME.
    print("Initializing the sandbox Cargo home...")
    script = """
set -euo pipefail
mkdir -p /sandbox/.cache/cargo/bin
for tool in /usr/local/lib/rust/bin/*; do
  [[ -e "${tool}" ]] || continue
  ln -sfn "${tool}" "/sandbox/.cache/cargo/bin/$(basename "${tool}")"
done
mise which cargo >/dev/null
""".strip()
    run(
        [
            "openshell",
            "sandbox",
            "exec",
            "--name",
            config.name,
            "--workdir",
            "/sandbox",
            "--",
            "/bin/bash",
            "-c",
            script,
        ]
    )


def main() -> NoReturn:
    config = parse_config()
    require_commands("openshell")

    print("Checking the active OpenShell gateway...")
    run(["openshell", "gateway", "info"], quiet=True)
    existing = config.name in sandbox_names()
    if existing and not config.recreate_sandbox and not config.rebuild_image:
        connect(config.name)

    require_commands("buildctl", "podman")
    config = discover_podman(config)
    config = resolve_platform(config)
    ensure_image(config)
    ensure_sccache_volume(config)

    if existing:
        delete_sandbox(config)

    create_sandbox(config)
    initialize_sandbox(config)
    connect(config.name)


if __name__ == "__main__":
    try:
        main()
    except UserError as error:
        print(f"Error: {error}", file=sys.stderr)
        raise SystemExit(2) from None
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode) from None
