#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2026 Globster. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = 1
SOURCE_REPOSITORY = "globster-monday/OpenShell"
SOURCE_COMMIT = "69f37a7c37253f2b3e3d77b1dd83b67b3f431cd0"
SOURCE_TREE = "a2c4d5b5ce21552efca3276bbb25531f15b1b84c"
OPENSHELL_VERSION = "0.0.116"
CARGO_VERSION = "0.0.116-globster.1"
ARTIFACT_TAG = "0.0.116-globster-69f37a7c"
CHART_VERSION = "0.0.116-globster.1"
GATEWAY_REPOSITORY = "ghcr.io/globster-monday/openshell/gateway"
SUPERVISOR_REPOSITORY = "ghcr.io/globster-monday/openshell/supervisor"
CHART_REPOSITORY = "oci://ghcr.io/globster-monday/openshell/helm-chart"
AGENT_SANDBOX_VERSION = "0.5.3"
AGENT_SANDBOX_MANIFEST_SHA256 = (
    "50f54b0e746376455ae6bb8b90b436bdd8798e1296cff0d72b6267bbeb858e3c"
)
AGENT_SANDBOX_CONTROLLER = (
    "registry.k8s.io/agent-sandbox/agent-sandbox-controller"
    "@sha256:ba381b4e0c86cca597d5c5a31860e38d30ec1c45e0a7a8328bb2799c87d059c0"
)

DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")


class CompatibilityReleaseError(ValueError):
    pass


def _digest(value: str, label: str) -> str:
    if not DIGEST_PATTERN.fullmatch(value):
        raise CompatibilityReleaseError(f"{label} must be an immutable sha256 digest")
    return value


def _replace_once(value: str, old: str, new: str, label: str) -> str:
    if value.count(old) != 1:
        raise CompatibilityReleaseError(f"expected exactly one {label} release marker")
    return value.replace(old, new)


def plan() -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "source": {
            "repository": SOURCE_REPOSITORY,
            "commit": SOURCE_COMMIT,
            "tree": SOURCE_TREE,
        },
        "openshellVersion": OPENSHELL_VERSION,
        "cargoVersion": CARGO_VERSION,
        "artifactTag": ARTIFACT_TAG,
        "chartVersion": CHART_VERSION,
        "platforms": ["linux/amd64", "linux/arm64"],
        "repositories": {
            "gateway": GATEWAY_REPOSITORY,
            "supervisor": SUPERVISOR_REPOSITORY,
            "chart": CHART_REPOSITORY,
        },
        "agentSandbox": {
            "version": AGENT_SANDBOX_VERSION,
            "manifestSha256": AGENT_SANDBOX_MANIFEST_SHA256,
            "controllerImage": AGENT_SANDBOX_CONTROLLER,
        },
    }


def receipt(
    gateway_digest: str,
    supervisor_digest: str,
    chart_digest: str | None = None,
) -> dict[str, Any]:
    gateway_digest = _digest(gateway_digest, "gateway digest")
    supervisor_digest = _digest(supervisor_digest, "supervisor digest")
    if chart_digest is not None:
        chart_digest = _digest(chart_digest, "chart digest")

    result = plan()
    result["artifacts"] = {
        "gateway": {
            "reference": f"{GATEWAY_REPOSITORY}:{ARTIFACT_TAG}@{gateway_digest}",
            "digest": gateway_digest,
            "platforms": ["linux/amd64", "linux/arm64"],
        },
        "supervisor": {
            "reference": f"{SUPERVISOR_REPOSITORY}:{ARTIFACT_TAG}@{supervisor_digest}",
            "digest": supervisor_digest,
            "platforms": ["linux/amd64", "linux/arm64"],
        },
        "chart": {
            "reference": CHART_REPOSITORY,
            "version": CHART_VERSION,
            **({} if chart_digest is None else {"digest": chart_digest}),
        },
    }
    return result


def verify_source(repository: Path) -> None:
    def git(*arguments: str) -> str:
        try:
            return subprocess.check_output(
                ["git", "-C", str(repository), *arguments],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        except (OSError, subprocess.CalledProcessError) as error:
            raise CompatibilityReleaseError(
                "compatibility source could not be verified"
            ) from error

    if git("rev-parse", "HEAD") != SOURCE_COMMIT:
        raise CompatibilityReleaseError(
            "compatibility source commit does not match the reviewed pin"
        )
    if git("rev-parse", "HEAD^{tree}") != SOURCE_TREE:
        raise CompatibilityReleaseError(
            "compatibility source tree does not match the reviewed pin"
        )


def render_chart(
    source: Path,
    destination: Path,
    gateway_digest: str,
    supervisor_digest: str,
) -> None:
    gateway_digest = _digest(gateway_digest, "gateway digest")
    supervisor_digest = _digest(supervisor_digest, "supervisor digest")
    chart_source = source / "deploy/helm/openshell"
    if destination.exists():
        raise CompatibilityReleaseError("chart destination already exists")
    if not chart_source.is_dir():
        raise CompatibilityReleaseError("reviewed chart source is unavailable")
    shutil.copytree(chart_source, destination)

    chart_path = destination / "Chart.yaml"
    chart = chart_path.read_text()
    chart = _replace_once(
        chart,
        'version: 0.0.0\nappVersion: "0.0.0"',
        f"version: {CHART_VERSION}\nappVersion: {ARTIFACT_TAG}",
        "chart version",
    )
    chart = _replace_once(
        chart,
        "type: application\n",
        "type: application\n"
        "annotations:\n"
        f"  globster.ai/source-commit: {SOURCE_COMMIT}\n"
        f"  globster.ai/source-tree: {SOURCE_TREE}\n"
        "  globster.ai/compatibility-receipt: globster-compatibility.json\n",
        "chart annotation",
    )
    chart_path.write_text(chart)

    values_path = destination / "values.yaml"
    values = values_path.read_text()
    values = _replace_once(
        values,
        "image:\n"
        "  # -- Gateway image repository.\n"
        "  repository: ghcr.io/nvidia/openshell/gateway\n"
        "  # -- Gateway image pull policy.\n"
        "  pullPolicy: IfNotPresent\n"
        "  # -- Gateway image tag. Defaults to the chart appVersion when empty.\n"
        '  tag: ""',
        "image:\n"
        "  # -- Gateway image repository.\n"
        f"  repository: {GATEWAY_REPOSITORY}\n"
        "  # -- Gateway image pull policy.\n"
        "  pullPolicy: IfNotPresent\n"
        "  # -- Gateway image tag. Defaults to the chart appVersion when empty.\n"
        f'  tag: "{ARTIFACT_TAG}@{gateway_digest}"',
        "gateway image",
    )
    values = _replace_once(
        values,
        "  image:\n"
        "    # -- Supervisor image repository. Changing it uses the effective gateway image tag unless tag is also set.\n"
        "    repository: ghcr.io/nvidia/openshell/supervisor\n"
        "    # -- Supervisor image pull policy. Defaults to the gateway image pull policy when empty.\n"
        '    pullPolicy: ""\n'
        "    # -- Supervisor image tag override. Empty uses the version pinned into the gateway unless repository is changed.\n"
        '    tag: ""',
        "  image:\n"
        "    # -- Supervisor image repository. Changing it uses the effective gateway image tag unless tag is also set.\n"
        f"    repository: {SUPERVISOR_REPOSITORY}\n"
        "    # -- Supervisor image pull policy. Defaults to the gateway image pull policy when empty.\n"
        '    pullPolicy: ""\n'
        "    # -- Supervisor image tag override. Empty uses the version pinned into the gateway unless repository is changed.\n"
        f'    tag: "{ARTIFACT_TAG}@{supervisor_digest}"',
        "supervisor image",
    )
    values_path.write_text(values)

    (destination / "globster-compatibility.json").write_text(
        json.dumps(receipt(gateway_digest, supervisor_digest), indent=2, sort_keys=True)
        + "\n"
    )


def _safe_archive_members(archive: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    members: dict[str, tarfile.TarInfo] = {}
    for member in archive.getmembers():
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise CompatibilityReleaseError("chart archive contains an unsafe path")
        members[member.name] = member
    return members


def _archive_text(
    archive: tarfile.TarFile, members: dict[str, tarfile.TarInfo], name: str
) -> str:
    member = members.get(name)
    if member is None or not member.isfile():
        raise CompatibilityReleaseError(f"chart archive is missing {name}")
    extracted = archive.extractfile(member)
    if extracted is None:
        raise CompatibilityReleaseError(f"chart archive is missing {name}")
    try:
        return extracted.read().decode("utf-8")
    except UnicodeDecodeError as error:
        raise CompatibilityReleaseError(f"chart archive has invalid {name}") from error


def verify_chart(archive_path: Path) -> dict[str, Any]:
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            members = _safe_archive_members(archive)
            chart = _archive_text(archive, members, "helm-chart/Chart.yaml")
            values = _archive_text(archive, members, "helm-chart/values.yaml")
            encoded_receipt = _archive_text(
                archive, members, "helm-chart/globster-compatibility.json"
            )
    except (OSError, tarfile.TarError) as error:
        raise CompatibilityReleaseError("chart archive could not be read") from error

    try:
        embedded = json.loads(encoded_receipt)
    except json.JSONDecodeError as error:
        raise CompatibilityReleaseError(
            "chart compatibility receipt is invalid"
        ) from error
    if not isinstance(embedded, dict):
        raise CompatibilityReleaseError("chart compatibility receipt is invalid")
    artifacts = embedded.get("artifacts")
    if not isinstance(artifacts, dict):
        raise CompatibilityReleaseError("chart compatibility receipt is invalid")
    gateway = artifacts.get("gateway")
    supervisor = artifacts.get("supervisor")
    if not isinstance(gateway, dict) or not isinstance(supervisor, dict):
        raise CompatibilityReleaseError("chart compatibility receipt is invalid")
    gateway_digest = _digest(str(gateway.get("digest", "")), "gateway digest")
    supervisor_digest = _digest(str(supervisor.get("digest", "")), "supervisor digest")
    expected = receipt(gateway_digest, supervisor_digest)
    if embedded != expected:
        raise CompatibilityReleaseError(
            "chart compatibility receipt does not match the release plan"
        )

    required_chart_values = [
        f"version: {CHART_VERSION}",
        f"appVersion: {ARTIFACT_TAG}",
        f"globster.ai/source-commit: {SOURCE_COMMIT}",
        f"globster.ai/source-tree: {SOURCE_TREE}",
    ]
    required_values = [
        f"repository: {GATEWAY_REPOSITORY}",
        f'tag: "{ARTIFACT_TAG}@{gateway_digest}"',
        f"repository: {SUPERVISOR_REPOSITORY}",
        f'tag: "{ARTIFACT_TAG}@{supervisor_digest}"',
    ]
    if any(value not in chart for value in required_chart_values) or any(
        value not in values for value in required_values
    ):
        raise CompatibilityReleaseError(
            "chart does not pin the reviewed compatibility set"
        )
    return expected


def _write_json(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise CompatibilityReleaseError("receipt output already exists")
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("plan")
    verify_source_parser = subparsers.add_parser("verify-source")
    verify_source_parser.add_argument("--repository", type=Path, required=True)

    render_parser = subparsers.add_parser("render-chart")
    render_parser.add_argument("--source", type=Path, required=True)
    render_parser.add_argument("--destination", type=Path, required=True)
    render_parser.add_argument("--gateway-digest", required=True)
    render_parser.add_argument("--supervisor-digest", required=True)

    verify_parser = subparsers.add_parser("verify-chart")
    verify_parser.add_argument("--archive", type=Path, required=True)

    receipt_parser = subparsers.add_parser("write-receipt")
    receipt_parser.add_argument("--gateway-digest", required=True)
    receipt_parser.add_argument("--supervisor-digest", required=True)
    receipt_parser.add_argument("--chart-digest", required=True)
    receipt_parser.add_argument("--output", type=Path, required=True)

    arguments = parser.parse_args()
    if arguments.command == "plan":
        print(json.dumps(plan(), sort_keys=True))
    elif arguments.command == "verify-source":
        verify_source(arguments.repository)
    elif arguments.command == "render-chart":
        render_chart(
            arguments.source,
            arguments.destination,
            arguments.gateway_digest,
            arguments.supervisor_digest,
        )
    elif arguments.command == "verify-chart":
        print(json.dumps(verify_chart(arguments.archive), sort_keys=True))
    elif arguments.command == "write-receipt":
        _write_json(
            arguments.output,
            receipt(
                arguments.gateway_digest,
                arguments.supervisor_digest,
                arguments.chart_digest,
            ),
        )


if __name__ == "__main__":
    try:
        main()
    except CompatibilityReleaseError as error:
        raise SystemExit(str(error)) from None
