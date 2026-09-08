# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name("check-cargo-lockfiles.sh")


@pytest.fixture
def repo(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    return tmp_path


def workspace(repo, directory=".", *, manifest=True, tracked=True):
    root = repo / directory
    root.mkdir(parents=True, exist_ok=True)
    lockfile = root / "Cargo.lock"
    lockfile.touch()
    if manifest:
        (root / "Cargo.toml").touch()
    if tracked:
        subprocess.run(["git", "add", str(lockfile)], cwd=repo, check=True)


def run_check(repo, *, failing_manifest="", cwd=None):
    bin_dir = repo / "bin"
    bin_dir.mkdir()
    cargo = bin_dir / "cargo"
    cargo.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        '[[ "$#" -eq 6 && "$1" == metadata && "$2" == --locked && '
        '"$3" == --format-version && "$4" == 1 && "$5" == --manifest-path ]]\n'
        'printf "%s\\0" "$6" >> "$CALL_LOG"\n'
        'if [[ "$6" == "$FAILING_MANIFEST" ]]; then\n'
        '  echo "registry unavailable" >&2\n'
        "  exit 1\n"
        "fi\n"
        'echo "metadata output"\n'
    )
    cargo.chmod(0o755)
    log = repo / "calls"
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=cwd or repo,
        env={
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "CALL_LOG": str(log),
            "FAILING_MANIFEST": failing_manifest,
        },
        capture_output=True,
        text=True,
    )
    calls = log.read_bytes().split(b"\0")[:-1] if log.exists() else []
    return result, [entry.decode() for entry in calls]


def test_no_tracked_lockfiles(repo):
    workspace(repo, tracked=False)
    result, calls = run_check(repo)
    assert result.returncode == 1
    assert "no tracked Cargo.lock files found" in result.stderr
    assert calls == []


def test_missing_manifest_does_not_stop_later_checks(repo):
    workspace(repo, "a-missing", manifest=False)
    workspace(repo, "z-valid")
    result, calls = run_check(repo)
    assert result.returncode == 1
    assert "a-missing/Cargo.lock has no adjacent Cargo.toml" in result.stderr
    assert calls == ["z-valid/Cargo.toml"]


@pytest.mark.parametrize("directory", ["nested workspace", "nested\nworkspace"])
def test_success_from_subdirectory_with_unusual_path(repo, directory):
    workspace(repo)
    workspace(repo, directory)
    workspace(repo, "untracked", tracked=False)
    result, calls = run_check(repo, cwd=repo / directory)
    assert result.returncode == 0, result.stderr
    assert calls == ["Cargo.toml", f"{directory}/Cargo.toml"]
    assert "metadata output" not in result.stdout


def test_cargo_failure_preserves_diagnostic_and_continues(repo):
    workspace(repo, "a-failing")
    workspace(repo, "z-valid")
    result, calls = run_check(repo, failing_manifest="a-failing/Cargo.toml")
    assert result.returncode == 1
    assert calls == ["a-failing/Cargo.toml", "z-valid/Cargo.toml"]
    assert "registry unavailable" in result.stderr
    assert "validation failed for a-failing/Cargo.lock" in result.stderr
    assert "out of sync" not in result.stderr
    assert "If a lockfile needs updating" in result.stderr
