# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run with uv run --no-project --with pytest --with pyyaml pytest tasks/scripts/oci_signing_test.py."""

import hashlib
import os
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
IMAGES = ("gateway", "sandbox", "supervisor")
CHARTS = ("helm-chart", "openshell-workspace")


@pytest.mark.parametrize(
    ("workflow", "version"),
    [
        ("release-publish.yml", "1.2.3"),
        ("release-publish.yml", "1.2.3-pre.1"),
        ("release-dev.yml", "a" * 40),
    ],
)
@pytest.mark.parametrize("failure", ["", "docker", "cosign"])
def test_sign_published_digests(tmp_path, workflow, version, failure):
    job = yaml.safe_load((WORKFLOWS / workflow).read_text())["jobs"]["release-helm"]
    assert job["permissions"]["id-token"] == "write"
    assert job["permissions"]["packages"] == "write"
    step = next(s for s in job["steps"] if s.get("name") == "Sign OCI artifacts")
    # Retained artifacts must also be signed when publication is retried.
    assert "if" not in step

    refs = [f"{name}:{version}" for name in IMAGES]
    chart_versions = (
        ["0.0.0-dev", f"0.0.0-dev.{version}"]
        if workflow == "release-dev.yml"
        else [version]
    )
    refs += [f"{name}:{tag}" for tag in chart_versions for name in CHARTS]
    refs = [f"ghcr.io/nvidia/openshell/{ref}" for ref in refs]
    signatures = tmp_path / "signatures"
    lookups = tmp_path / "lookups"
    for command, script in {
        "docker": """printf '%s\\n' "$4" >> "$LOOKUPS"
test "$FAILURE" != docker || exit 1
printf 'sha256:%s\\n' "$(printf '%s' "$4" | sha256sum | cut -d' ' -f1)"
""",
        "cosign": """printf '%s\\n' "$*" >> "$SIGNATURES"
test "$FAILURE" != cosign
""",
    }.items():
        executable = tmp_path / command
        executable.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + script)
        executable.chmod(0o755)

    values = {"${{ inputs.semver }}": version, "${{ github.sha }}": version}
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", step["run"]],
        env={
            **os.environ,
            **{key: values[value] for key, value in step["env"].items()},
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "LOOKUPS": str(lookups),
            "SIGNATURES": str(signatures),
            "FAILURE": failure,
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) == (not failure), result.stderr
    assert lookups.read_text().splitlines() == (refs[:1] if failure else refs)
    signed = signatures.read_text().splitlines() if signatures.exists() else []
    expected_refs = [] if failure == "docker" else refs[:1] if failure else refs
    assert signed == [
        f"sign --yes {ref.rsplit(':', 1)[0]}@sha256:{hashlib.sha256(ref.encode()).hexdigest()}"
        for ref in expected_refs
    ]
