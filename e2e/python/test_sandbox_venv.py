# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the writable sandbox venv, PATH, and package installation.

Verifies that:
- /sandbox/.venv/bin is in PATH for both interactive and non-interactive sessions
- pip install works inside the sandbox with an explicit PyPI policy
- uv pip install works (validates Landlock V2 cross-directory rename support)
- uv run --with works for ephemeral dependency injection
- Installed packages are importable after installation

Package-install tests pass their policy explicitly. In the split sandbox and
supervisor topology, trusted policy evaluation no longer discovers policy from
the untrusted workload image filesystem.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from openshell._proto import datamodel_pb2, sandbox_pb2

if TYPE_CHECKING:
    from collections.abc import Callable

    from openshell import Sandbox


def _pypi_spec() -> datamodel_pb2.SandboxSpec:
    endpoints = [
        "pypi.org",
        "files.pythonhosted.org",
        "github.com",
        "objects.githubusercontent.com",
        "api.github.com",
        "downloads.python.org",
    ]
    return datamodel_pb2.SandboxSpec(
        policy=sandbox_pb2.SandboxPolicy(
            version=1,
            filesystem=sandbox_pb2.FilesystemPolicy(
                include_workdir=True,
                read_only=["/usr", "/lib", "/etc", "/app", "/proc"],
                read_write=["/sandbox", "/tmp"],
            ),
            landlock=sandbox_pb2.LandlockPolicy(compatibility="best_effort"),
            process=sandbox_pb2.ProcessPolicy(
                run_as_user="sandbox", run_as_group="sandbox"
            ),
            network_policies={
                "pypi": sandbox_pb2.NetworkPolicyRule(
                    name="pypi",
                    endpoints=[
                        sandbox_pb2.NetworkEndpoint(host=host, port=443)
                        for host in endpoints
                    ],
                    binaries=[sandbox_pb2.NetworkBinary(path="/**")],
                )
            },
        )
    )


def test_sandbox_venv_in_path(
    sandbox: Callable[..., Sandbox],
) -> None:
    """Non-interactive exec sees /sandbox/.venv/bin in PATH."""
    with sandbox(spec=_pypi_spec(), delete_on_exit=True) as sb:
        result = sb.exec(["bash", "-c", "echo $PATH"], timeout_seconds=20)
        assert result.exit_code == 0, result.stderr
        path_dirs = result.stdout.strip().split(":")
        assert "/sandbox/.venv/bin" in path_dirs, (
            f"Expected /sandbox/.venv/bin in PATH, got: {result.stdout.strip()}"
        )


def test_pip_install_in_sandbox(
    sandbox: Callable[..., Sandbox],
) -> None:
    """pip install works inside the sandbox and installed packages are importable."""
    with sandbox(spec=_pypi_spec(), delete_on_exit=True) as sb:
        install = sb.exec(
            ["pip", "install", "--quiet", "cowsay"],
            timeout_seconds=60,
        )
        assert install.exit_code == 0, (
            f"pip install failed:\nstdout: {install.stdout}\nstderr: {install.stderr}"
        )

        # Verify the package is importable
        verify = sb.exec(
            ["python", "-c", "import cowsay; print(cowsay.char_names[0])"],
            timeout_seconds=20,
        )
        assert verify.exit_code == 0, (
            f"import failed:\nstdout: {verify.stdout}\nstderr: {verify.stderr}"
        )
        assert verify.stdout.strip(), "Expected non-empty output from cowsay"


def test_uv_pip_install_in_sandbox(
    sandbox: Callable[..., Sandbox],
) -> None:
    """uv pip install works inside the sandbox (validates Landlock V2 REFER support).

    Under Landlock V1 this would fail with EXDEV (cross-device link, os error 18)
    because uv uses cross-directory rename() for cache population and installation.
    Landlock V2 adds the REFER right which permits this.
    """
    with sandbox(spec=_pypi_spec(), delete_on_exit=True) as sb:
        install = sb.exec(
            [
                "uv",
                "pip",
                "install",
                "--python",
                "/sandbox/.venv/bin/python",
                "--quiet",
                "cowsay",
            ],
            timeout_seconds=60,
        )
        assert install.exit_code == 0, (
            f"uv pip install failed:\nstdout: {install.stdout}\nstderr: {install.stderr}"
        )

        # Verify the package is importable
        verify = sb.exec(
            ["python", "-c", "import cowsay; print(cowsay.char_names[0])"],
            timeout_seconds=20,
        )
        assert verify.exit_code == 0, (
            f"import failed after uv install:\n"
            f"stdout: {verify.stdout}\nstderr: {verify.stderr}"
        )
        assert verify.stdout.strip(), "Expected non-empty output from cowsay"


def test_uv_run_with_ephemeral_dependency(
    sandbox: Callable[..., Sandbox],
) -> None:
    """uv run --with installs a dependency on-the-fly and runs a script using it."""
    with sandbox(spec=_pypi_spec(), delete_on_exit=True) as sb:
        result = sb.exec(
            [
                "uv",
                "run",
                "--python",
                "/sandbox/.venv/bin/python",
                "--with",
                "cowsay",
                "python",
                "-c",
                "import cowsay; print(cowsay.char_names[0])",
            ],
            timeout_seconds=60,
        )
        assert result.exit_code == 0, (
            f"uv run --with failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
        assert result.stdout.strip(), "Expected non-empty output from uv run"
