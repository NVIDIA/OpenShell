#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tarfile
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

SEMVER_TAG_RE = re.compile(r"^v?(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$")
PRERELEASE_TAG_RE = re.compile(
    r"^v?(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)-pre\.(?P<sequence>[1-9]\d*)$"
)


@dataclass(frozen=True)
class Versions:
    python: str
    cargo: str
    npm: str
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
HOMEBREW_PROVER_ASSET = f"openshell-prover-{HOMEBREW_TARGET}.tar.gz"
GITHUB_RELEASE_DOWNLOADS = "https://github.com/NVIDIA/OpenShell/releases/download"
LOCAL_GATEWAY_PORT = 17670
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_RELEASE_TAG_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# This inventory describes the standalone core runtime, not every package or SDK
# shipped by a release. Targets include libc because architecture alone cannot
# distinguish the static sandbox from the dynamically linked supervisor.
CORE_ARCHIVES = {
    "cli": ("openshell", "musl", True),
    "gateway": ("openshell-gateway", "gnu", True),
    "sandbox": ("openshell-sandbox", "musl", False),
    "supervisor": ("openshell-supervisor", "gnu", False),
}
IMAGE_COMPONENTS = ("gateway", "sandbox", "supervisor")
IMAGE_REGISTRY = "ghcr.io/nvidia/openshell"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MAX_EXECUTABLE_SIZE = 1024 * 1024 * 1024


def _sha256_stream(stream) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _sha256_path(path: Path) -> str:
    with path.open("rb") as stream:
        return _sha256_stream(stream)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict:
    if path.stat().st_size > 1024 * 1024:
        raise ValueError(f"{path.name}: identity document exceeds 1 MiB")
    value = json.loads(path.read_bytes(), object_pairs_hook=_unique_json_object)
    if not isinstance(value, dict):
        raise ValueError(f"{path.name}: expected a JSON object")
    return value


def _identity_text(value: object, pattern: str, field: str) -> str:
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise ValueError(f"invalid {field}")
    return value


def _source_identity(source_sha: object, run_id: object, run_attempt: object) -> dict:
    """Validate producer identity strings supplied by the CLI or decoded JSON."""
    return {
        "source_sha": _identity_text(source_sha, r"[0-9a-f]{40}", "source SHA"),
        "run_id": _identity_text(run_id, r"[1-9][0-9]*", "workflow run ID"),
        "run_attempt": _identity_text(
            run_attempt, r"[1-9][0-9]*", "workflow run attempt"
        ),
    }


def _image_digest(value: object) -> str:
    return _identity_text(value, r"sha256:[0-9a-f]{64}", "OCI digest")


def _write_identity(output: Path, value: dict) -> None:
    # Validation finishes before publication. Atomic replacement prevents an
    # interrupted writer from leaving a truncated but apparently final document.
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=output.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
        temporary.replace(output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _executable_architecture(header: bytes, target: str) -> None:
    if "linux" in target:
        expected = 62 if target.startswith("x86_64-") else 183
        if (
            len(header) < 20
            or header[:6] != b"\x7fELF\x02\x01"
            or int.from_bytes(header[18:20], "little") != expected
        ):
            raise ValueError(f"executable architecture does not match {target}")
    elif (
        len(header) < 8
        or header[:4] != b"\xcf\xfa\xed\xfe"
        or int.from_bytes(header[4:8], "little") != 0x0100000C
    ):
        raise ValueError(f"executable architecture does not match {target}")


def _archive_executable_sha256(path: Path, binary: str, target: str) -> str:
    # The packaging job creates one executable at the archive root. Never
    # extract a release archive: symlinks, traversal and additional members are
    # invalid inputs even if their compressed bytes have a matching checksum.
    with tarfile.open(path, mode="r|gz") as archive:
        member = archive.next()
        if (
            member is None
            or member.name != binary
            or not member.isfile()
            or not member.mode & 0o111
            or not 0 < member.size <= MAX_EXECUTABLE_SIZE
        ):
            raise ValueError(f"{path.name}: expected one executable named {binary}")
        stream = archive.extractfile(member)
        if stream is None:
            raise ValueError(f"{path.name}: executable is unavailable")
        with stream:
            header = stream.read(64)
            _executable_architecture(header, target)
            digest = hashlib.sha256(header)
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        if archive.next() is not None:
            raise ValueError(f"{path.name}: unexpected additional archive member")
        return digest.hexdigest()


def record_image_identity(
    *,
    component: str,
    source_sha: str,
    run_id: str,
    run_attempt: str,
    metadata_file: Path,
    index_file: Path,
    binary_dir: Path,
    output: Path,
) -> None:
    """Record a producing image job's immutable index and staged binary identity."""
    identity = _source_identity(source_sha, run_id, run_attempt)
    if component not in IMAGE_COMPONENTS:
        raise ValueError("unknown image component")
    metadata = _read_json(metadata_file)
    digest = _image_digest(metadata.get("containerimage.digest"))
    index = _read_json(index_file)
    raw = index_file.read_bytes()
    # Some CLI versions add a display newline. Accept it only when removing
    # that terminator recovers the exact producing build's content digest.
    if digest[7:] not in {
        hashlib.sha256(raw).hexdigest(),
        hashlib.sha256(raw.rstrip(b"\r\n")).hexdigest(),
    }:
        raise ValueError("OCI index bytes do not match producing image digest")
    if index.get("schemaVersion") != 2 or index.get("mediaType") != OCI_INDEX:
        raise ValueError("expected an OCI image index")
    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        raise ValueError("OCI index has no manifest descriptors")
    platforms = {}
    for descriptor in manifests:
        if (
            not isinstance(descriptor, dict)
            or descriptor.get("mediaType") != OCI_MANIFEST
        ):
            raise ValueError("invalid OCI manifest descriptor")
        platform = descriptor.get("platform")
        if not isinstance(platform, dict):
            raise ValueError("OCI descriptor has no platform")
        platform_digest = _image_digest(descriptor.get("digest"))
        annotations = descriptor.get("annotations", {})
        if not isinstance(annotations, dict):
            raise ValueError("invalid OCI descriptor annotations")
        if (
            platform.get("os") == "unknown"
            and platform.get("architecture") == "unknown"
            and annotations.get("vnd.docker.reference.type") == "attestation-manifest"
        ):
            # BuildKit embeds provenance/SBOM manifests in the index. These are
            # evidence, never extra executable platforms available to a client.
            continue
        arch = platform.get("architecture")
        variant = platform.get("variant", "")
        if (
            platform.get("os") != "linux"
            or arch not in ("amd64", "arm64")
            or variant not in ("", "v8")
            or (arch == "amd64" and variant)
            or arch in platforms
        ):
            raise ValueError("unexpected or duplicate executable image platform")
        binary = binary_dir / arch / CORE_ARCHIVES[component][0]
        target_arch = "x86_64" if arch == "amd64" else "aarch64"
        with binary.open("rb") as stream:
            _executable_architecture(stream.read(64), f"{target_arch}-unknown-linux")
        platforms[arch] = {
            "os": "linux",
            "architecture": arch,
            "digest": platform_digest,
            "binary_sha256": _sha256_path(binary),
        }
        if variant:
            platforms[arch]["variant"] = variant
    if set(platforms) != {"amd64", "arm64"}:
        raise ValueError("image must provide Linux amd64 and arm64")
    _write_identity(
        output,
        {
            "schema_version": 1,
            **identity,
            "component": component,
            "repository": f"{IMAGE_REGISTRY}/{component}",
            "index_digest": digest,
            "platforms": [platforms[key] for key in sorted(platforms)],
        },
    )


def _manifest_checksums(path: Path) -> dict[str, str]:
    checksums = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2:
            raise ValueError(f"{path.name}: malformed checksum entry")
        digest, name = parts
        name = name.removeprefix("*")
        _identity_text(digest, r"[0-9a-f]{64}", "archive SHA256")
        if Path(name).name != name or name in checksums:
            raise ValueError(f"{path.name}: unsafe or duplicate archive name")
        checksums[name] = digest
    return checksums


def generate_release_manifest(
    *,
    source_sha: str,
    run_id: str,
    run_attempt: str,
    cargo_version: str,
    release_dir: Path,
    image_dir: Path,
    output: Path,
) -> None:
    """Validate and publish the complete core-runtime inventory of a dev build."""
    identity = _source_identity(source_sha, run_id, run_attempt)
    # A development workflow at an exact stable tag receives a plain version.
    # Otherwise Git's abbreviation can exceed nine characters to remain unique;
    # the suffix must still identify the full source recorded by producing jobs.
    _identity_text(
        cargo_version,
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
        r"(?:-dev\.[1-9][0-9]*\+g[0-9a-f]{9,40})?",
        "development version/source association",
    )
    if "+g" in cargo_version and not source_sha.startswith(
        cargo_version.rsplit("+g", 1)[1]
    ):
        raise ValueError("invalid development version/source association")
    archives = []
    binary_hashes = {}
    for component, (binary, libc, darwin) in CORE_ARCHIVES.items():
        checksums = _manifest_checksums(release_dir / f"{binary}-checksums-sha256.txt")
        targets = [f"x86_64-unknown-linux-{libc}", f"aarch64-unknown-linux-{libc}"]
        if darwin:
            targets.append("aarch64-apple-darwin")
        for target in targets:
            filename = f"{binary}-{target}.tar.gz"
            expected = checksums.get(filename)
            if expected is None:
                raise ValueError(f"missing checksum for {filename}")
            path = release_dir / filename
            actual = _sha256_path(path)
            if actual != expected:
                raise ValueError(f"{filename}: archive checksum mismatch")
            executable_hash = _archive_executable_sha256(path, binary, target)
            binary_hashes[(component, target)] = executable_hash
            archives.append(
                {
                    "component": component,
                    "target": target,
                    "filename": filename,
                    "sha256": actual,
                    "size_bytes": path.stat().st_size,
                    "binary_sha256": executable_hash,
                }
            )
    expected_names = {f"{component}.json" for component in IMAGE_COMPONENTS}
    if {path.name for path in image_dir.iterdir()} != expected_names:
        raise ValueError("expected exactly one identity file for each core image")
    images = []
    for component in IMAGE_COMPONENTS:
        image = _read_json(image_dir / f"{component}.json")
        if (
            type(image.get("schema_version")) is not int
            or image.get("schema_version") != 1
            or set(image)
            != {
                "schema_version",
                "source_sha",
                "run_id",
                "run_attempt",
                "component",
                "repository",
                "index_digest",
                "platforms",
            }
            or image.get("source_sha") != source_sha
            or image.get("run_id") != run_id
            or image.get("component") != component
            or image.get("repository") != f"{IMAGE_REGISTRY}/{component}"
        ):
            raise ValueError(f"{component}: image identity belongs to another build")
        # A successful producing job from an earlier attempt of this same run
        # remains usable when only downstream release assembly is retried.
        _source_identity(source_sha, run_id, image.get("run_attempt"))
        _image_digest(image.get("index_digest"))
        platforms = image.get("platforms")
        if not isinstance(platforms, list) or len(platforms) != 2:
            raise ValueError(f"{component}: expected both executable platforms")
        seen = set()
        for platform in platforms:
            if not isinstance(platform, dict):
                raise ValueError(f"{component}: invalid image platform")
            arch = platform.get("architecture")
            variant = platform.get("variant", "")
            if (
                platform.get("os") != "linux"
                or arch not in ("amd64", "arm64")
                or arch in seen
                or variant not in ("", "v8")
                or (arch == "amd64" and variant)
                or set(platform)
                - {
                    "os",
                    "architecture",
                    "variant",
                    "digest",
                    "binary_sha256",
                }
            ):
                raise ValueError(f"{component}: unexpected or duplicate platform")
            seen.add(arch)
            _image_digest(platform.get("digest"))
            triple_arch = "x86_64" if arch == "amd64" else "aarch64"
            target = f"{triple_arch}-unknown-linux-{CORE_ARCHIVES[component][1]}"
            if platform.get("binary_sha256") != binary_hashes[(component, target)]:
                raise ValueError(
                    f"{component}/{arch}: staged image binary does not match archive"
                )
        images.append(image)
    _write_identity(
        output,
        {
            "schema_version": 1,
            "inventory_scope": "core-runtime",
            **identity,
            "source_repository": "https://github.com/NVIDIA/OpenShell",
            "cargo_version": cargo_version,
            "archive_download_base": f"{GITHUB_RELEASE_DOWNLOADS}/dev",
            "archives": sorted(archives, key=lambda item: item["filename"]),
            "images": images,
        },
    )


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


def _parse_prerelease_tag(tag: str) -> tuple[int, int, int, int] | None:
    match = PRERELEASE_TAG_RE.match(tag)
    if match is None:
        return None
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
        int(match.group("sequence")),
    )


def _format_semver(version: tuple[int, int, int]) -> str:
    return f"{version[0]}.{version[1]}.{version[2]}"


def _next_patch(version: tuple[int, int, int]) -> tuple[int, int, int]:
    return version[0], version[1], version[2] + 1


def _exact_release_tag() -> str | None:
    tags = _git(["tag", "--points-at", "HEAD"]).splitlines()
    stable = [(version, tag) for tag in tags if (version := _parse_semver_tag(tag))]
    if stable:
        return max(stable)[1]

    prereleases = [
        (version, tag) for tag in tags if (version := _parse_prerelease_tag(tag))
    ]
    return max(prereleases)[1] if prereleases else None


def _latest_stable_tag() -> str | None:
    tags = _git(["tag", "--merged", "HEAD", "--list", "v*.*.*"]).splitlines()
    stable = [(version, tag) for tag in tags if (version := _parse_semver_tag(tag))]
    return max(stable)[1] if stable else None


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

    # npm follows SemVer 2.0 like Cargo, but fold the '+g<sha>' build metadata
    # into the prerelease (npm/registries treat build metadata as insignificant
    # for version identity, so each dev build must differ in the prerelease).
    # 0.1.0-dev.3+gabcdef -> 0.1.0-dev.3.gabcdef ; a tagged release stays 0.1.0.
    npm_version = cargo_version.replace("+", ".")

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
        npm=npm_version,
        docker=docker_version,
        deb=deb_version,
        snap=snap_version,
        rpm_version=rpm_version,
        rpm_release=rpm_release,
        git_tag=git_tag,
        git_sha=git_sha,
        git_distance=git_distance,
    )


def _versions_from_prerelease(
    base_version: tuple[int, int, int],
    sequence: int,
    git_sha: str,
    git_tag: str,
) -> Versions:
    version = f"{_format_semver(base_version)}-pre.{sequence}"
    return Versions(
        python=f"{_format_semver(base_version)}rc{sequence}",
        cargo=version,
        npm=version,
        docker=version,
        deb=f"{_format_semver(base_version)}~pre.{sequence}-1",
        snap=version,
        rpm_version=_format_semver(base_version),
        rpm_release=f"0.pre.{sequence}",
        git_tag=git_tag,
        git_sha=git_sha,
        git_distance=0,
    )


def _compute_versions() -> Versions:
    git_sha = _git(["rev-parse", "--short=9", "HEAD"])
    exact_tag = _exact_release_tag()

    if exact_tag is not None:
        stable = _parse_semver_tag(exact_tag)
        if stable is not None:
            return _versions_from_parts(stable, 0, git_sha, exact_tag)

        prerelease = _parse_prerelease_tag(exact_tag)
        if prerelease is None:
            raise RuntimeError(f"invalid semantic release tag: {exact_tag}")
        return _versions_from_prerelease(
            prerelease[:3], prerelease[3], git_sha, exact_tag
        )

    git_tag = _latest_stable_tag()
    if git_tag is None:
        base_version = (0, 0, 0)
        git_distance = int(_git(["rev-list", "--count", "HEAD"]))
        return _versions_from_parts(base_version, git_distance, git_sha, "")

    parsed_tag = _parse_semver_tag(git_tag)
    if parsed_tag is None:
        raise RuntimeError(f"invalid semantic release tag: {git_tag}")

    git_distance = int(_git(["rev-list", f"{git_tag}..HEAD", "--count"]))
    return _versions_from_parts(parsed_tag, git_distance, git_sha, git_tag)


def _compute_dev_versions() -> Versions:
    git_sha = _git(["rev-parse", "--short=9", "HEAD"])
    git_tag = _latest_stable_tag()
    if git_tag is None:
        git_distance = int(_git(["rev-list", "--count", "HEAD"]))
        return _versions_from_parts((0, 0, 0), git_distance, git_sha, "")

    parsed_tag = _parse_semver_tag(git_tag)
    if parsed_tag is None:
        raise RuntimeError(f"invalid semantic release tag: {git_tag}")

    git_distance = int(_git(["rev-list", f"{git_tag}..HEAD", "--count"]))
    return _versions_from_parts(parsed_tag, git_distance, git_sha, git_tag)


def _print_env(versions: Versions) -> None:
    print(f"VERSION_PY={versions.python}")
    print(f"VERSION_CARGO={versions.cargo}")
    print(f"VERSION_NPM={versions.npm}")
    print(f"VERSION_DOCKER={versions.docker}")
    print(f"VERSION_DEB={versions.deb}")
    print(f"VERSION_SNAP={versions.snap}")
    print(f"VERSION_RPM={versions.rpm_version}")
    print(f"VERSION_RPM_RELEASE={versions.rpm_release}")
    print(f"GIT_TAG={versions.git_tag}")
    print(f"GIT_SHA={versions.git_sha}")
    print(f"GIT_DISTANCE={versions.git_distance}")


def get_version(format: str, *, dev: bool = False) -> None:
    versions = _compute_dev_versions() if dev else _compute_versions()
    if format == "python":
        print(versions.python)
    elif format == "cargo":
        print(versions.cargo)
    elif format == "npm":
        print(versions.npm)
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


def render_homebrew_formula(
    *,
    release_tag: str,
    cli_sha256: str,
    gateway_sha256: str,
    driver_vm_sha256: str,
    prover_sha256: str,
) -> str:
    if not _RELEASE_TAG_RE.fullmatch(release_tag):
        raise ValueError(f"release tag contains unsupported characters: {release_tag}")

    version = release_tag.removeprefix("v")
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

  resource "openshell-prover" do
    url "{_asset_url(release_tag, HOMEBREW_PROVER_ASSET)}"
    sha256 "{prover_sha256}"
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

    resource("openshell-prover").stage do
      bin.install "openshell-prover"
    end

    (libexec/"openshell-gateway-homebrew-service").write <<~SH
      #!/bin/sh
      set -eu

      if [ -z "${{HOME:-}}" ]; then
        echo "HOME must be set for Docker TLS bind mounts" >&2
        exit 1
      fi

      xdg_config_home="${{XDG_CONFIG_HOME:-${{HOME}}/.config}}"
      xdg_gateway_env="${{xdg_config_home}}/openshell/gateway.env"
      prefix_gateway_env="#{{var}}/openshell/gateway.env"
      if [ -f "${{xdg_gateway_env}}" ]; then
        set -a
        . "${{xdg_gateway_env}}"
        set +a
      elif [ -f "${{prefix_gateway_env}}" ]; then
        set -a
        . "${{prefix_gateway_env}}"
        set +a
      fi

      docker_tls_dir="${{HOME}}/.local/state/openshell/homebrew/tls"
      mkdir -p "${{docker_tls_dir}}/server"
      mkdir -p "${{docker_tls_dir}}/client"
      mkdir -p "${{docker_tls_dir}}/jwt"
      chmod 700 "${{docker_tls_dir}}" "${{docker_tls_dir}}/server" "${{docker_tls_dir}}/client" "${{docker_tls_dir}}/jwt"
      /usr/bin/install -m 0644 "#{{var}}/openshell/tls/ca.crt" "${{docker_tls_dir}}/ca.crt"
      /usr/bin/install -m 0644 "#{{var}}/openshell/tls/server/tls.crt" "${{docker_tls_dir}}/server/tls.crt"
      /usr/bin/install -m 0600 "#{{var}}/openshell/tls/server/tls.key" "${{docker_tls_dir}}/server/tls.key"
      /usr/bin/install -m 0644 "#{{var}}/openshell/tls/client/tls.crt" "${{docker_tls_dir}}/client/tls.crt"
      /usr/bin/install -m 0600 "#{{var}}/openshell/tls/client/tls.key" "${{docker_tls_dir}}/client/tls.key"
      /usr/bin/install -m 0600 "#{{var}}/openshell/tls/jwt/signing.pem" "${{docker_tls_dir}}/jwt/signing.pem"
      /usr/bin/install -m 0644 "#{{var}}/openshell/tls/jwt/public.pem" "${{docker_tls_dir}}/jwt/public.pem"
      /usr/bin/install -m 0644 "#{{var}}/openshell/tls/jwt/kid" "${{docker_tls_dir}}/jwt/kid"
      export OPENSHELL_LOCAL_TLS_DIR="${{OPENSHELL_LOCAL_TLS_DIR:-${{docker_tls_dir}}}}"

      xdg_gateway_config="${{xdg_config_home}}/openshell/gateway.toml"
      prefix_gateway_config="#{{var}}/openshell/gateway.toml"

      if [ -z "${{OPENSHELL_GATEWAY_CONFIG:-}}" ] && [ ! -f "${{xdg_gateway_config}}" ] && [ -f "${{prefix_gateway_config}}" ]; then
        exec "#{{opt_bin}}/openshell-gateway" --config "${{prefix_gateway_config}}"
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

    gateway_config = var/"openshell/gateway.toml"
    gateway_config_contents = <<~TOML
      [openshell]
      version = 2

      [openshell.gateway]
    TOML
    # These are the only v1 configurations emitted by pre-schema-v2 formulas.
    # Do not migrate a configuration unless it exactly matches one of them.
    legacy_empty_gateway_config_contents = <<~TOML
      [openshell]
      version = 1

      [openshell.gateway]
    TOML
    legacy_ipv6_gateway_config_contents = <<~TOML
      [openshell]
      version = 1

      [openshell.gateway]
      bind_address = "[::1]:{LOCAL_GATEWAY_PORT}"
    TOML
    unless gateway_config.exist?
      gateway_config.write gateway_config_contents
    else
      # Keep any user-edited config untouched.
      if gateway_config.read == legacy_empty_gateway_config_contents ||
         gateway_config.read == legacy_ipv6_gateway_config_contents
        gateway_config.write gateway_config_contents
      end
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
    keep_alive successful_exit: false
    log_path var/"log/openshell/openshell-gateway.out.log"
    error_log_path var/"log/openshell/openshell-gateway.err.log"
  end

  def caveats
    <<~EOS
      Start or restart the local gateway with:
        brew services restart openshell

      Register it with the OpenShell CLI:
        openshell gateway add https://localhost:{LOCAL_GATEWAY_PORT} --local --name openshell
    EOS
  end

  test do
    assert_match "openshell ", shell_output("#{{bin}}/openshell --version")
    assert_match "openshell-prover ", shell_output("#{{bin}}/openshell-prover --version")
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
    prover_checksums_path = release_dir / "openshell-prover-checksums-sha256.txt"
    checksums = _parse_sha256_file(checksums_path)
    gateway_checksums = _parse_sha256_file(gateway_checksums_path)
    prover_checksums = _parse_sha256_file(prover_checksums_path)

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
        prover_sha256=_required_checksum(
            prover_checksums,
            HOMEBREW_PROVER_ASSET,
            prover_checksums_path,
        ),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(formula, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OpenShell release tooling.")
    sub = parser.add_subparsers(dest="command", required=True)

    get_version_parser = sub.add_parser("get-version", help="Print computed version.")
    get_version_parser.add_argument(
        "--dev", action="store_true", help="Ignore exact tags and print a dev version."
    )
    get_version_parser.add_argument(
        "--python", action="store_true", help="Print Python version only."
    )
    get_version_parser.add_argument(
        "--cargo", action="store_true", help="Print Cargo version only."
    )
    get_version_parser.add_argument(
        "--npm", action="store_true", help="Print npm version only."
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

    digest_parser = sub.add_parser(
        "image-build-digest", help="Read the producing Buildx image digest."
    )
    digest_parser.add_argument("--metadata-file", type=Path, required=True)
    image_parser = sub.add_parser(
        "record-image-identity", help="Record an image-producing job's identity."
    )
    manifest_parser = sub.add_parser(
        "generate-release-manifest", help="Validate the complete dev core inventory."
    )
    for identity_parser in (image_parser, manifest_parser):
        identity_parser.add_argument("--source-sha", required=True)
        identity_parser.add_argument("--run-id", required=True)
        identity_parser.add_argument("--run-attempt", required=True)
        identity_parser.add_argument("--output", type=Path, required=True)
    image_parser.add_argument("--component", choices=IMAGE_COMPONENTS, required=True)
    image_parser.add_argument("--metadata-file", type=Path, required=True)
    image_parser.add_argument("--index-file", type=Path, required=True)
    image_parser.add_argument("--binary-dir", type=Path, required=True)
    manifest_parser.add_argument("--cargo-version", required=True)
    manifest_parser.add_argument("--release-dir", type=Path, required=True)
    manifest_parser.add_argument("--image-dir", type=Path, required=True)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "get-version":
        if args.python:
            get_version("python", dev=args.dev)
        elif args.cargo:
            get_version("cargo", dev=args.dev)
        elif args.npm:
            get_version("npm", dev=args.dev)
        elif args.docker:
            get_version("docker", dev=args.dev)
        elif args.deb:
            get_version("deb", dev=args.dev)
        elif args.snap:
            get_version("snap", dev=args.dev)
        elif args.rpm_version:
            get_version("rpm-version", dev=args.dev)
        elif args.rpm_release:
            get_version("rpm-release", dev=args.dev)
        elif args.json:
            get_version("json", dev=args.dev)
        else:
            get_version("all", dev=args.dev)
    elif args.command == "generate-homebrew-formula":
        generate_homebrew_formula(
            release_tag=args.release_tag,
            release_dir=args.release_dir,
            output=args.output,
        )
    elif args.command == "image-build-digest":
        print(
            _image_digest(_read_json(args.metadata_file).get("containerimage.digest"))
        )
    elif args.command == "record-image-identity":
        record_image_identity(
            component=args.component,
            source_sha=args.source_sha,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            metadata_file=args.metadata_file,
            index_file=args.index_file,
            binary_dir=args.binary_dir,
            output=args.output,
        )
    elif args.command == "generate-release-manifest":
        generate_release_manifest(
            source_sha=args.source_sha,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            cargo_version=args.cargo_version,
            release_dir=args.release_dir,
            image_dir=args.image_dir,
            output=args.output,
        )


if __name__ == "__main__":
    main()
