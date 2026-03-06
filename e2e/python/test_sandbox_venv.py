# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the writable sandbox venv, PATH, and package installation.

Verifies that:
- /sandbox/.venv/bin is in PATH for both interactive and non-interactive sessions
- pip install works inside the sandbox (pypi network policy)
- uv pip install works (validates Landlock V2 cross-directory rename support)
- uv run --with works for ephemeral dependency injection
- Installed packages are importable after installation

The PATH test uses the default (no-network) policy.  Package installation
tests supply an explicit pypi network policy so the proxy allows egress to
pypi.org and files.pythonhosted.org.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from navigator._proto import datamodel_pb2, sandbox_pb2

if TYPE_CHECKING:
    from collections.abc import Callable

    from navigator import Sandbox


# ---------------------------------------------------------------------------
# Policy helpers
# ---------------------------------------------------------------------------

_BASE_FILESYSTEM = sandbox_pb2.FilesystemPolicy(
    include_workdir=True,
    read_only=["/usr", "/lib", "/proc", "/dev/urandom", "/app", "/etc", "/var/log"],
    read_write=["/sandbox", "/tmp", "/dev/null"],
)
_BASE_LANDLOCK = sandbox_pb2.LandlockPolicy(compatibility="best_effort")
_BASE_PROCESS = sandbox_pb2.ProcessPolicy(run_as_user="sandbox", run_as_group="sandbox")

_PYPI_NETWORK_POLICY = sandbox_pb2.NetworkPolicyRule(
    name="pypi",
    endpoints=[
        sandbox_pb2.NetworkEndpoint(host="pypi.org", port=443),
        sandbox_pb2.NetworkEndpoint(host="files.pythonhosted.org", port=443),
    ],
    binaries=[
        sandbox_pb2.NetworkBinary(path="/sandbox/.venv/bin/python"),
        sandbox_pb2.NetworkBinary(path="/sandbox/.venv/bin/python3"),
        sandbox_pb2.NetworkBinary(path="/sandbox/.venv/bin/pip"),
        sandbox_pb2.NetworkBinary(path="/app/.venv/bin/python"),
        sandbox_pb2.NetworkBinary(path="/app/.venv/bin/python3"),
        sandbox_pb2.NetworkBinary(path="/app/.venv/bin/pip"),
        sandbox_pb2.NetworkBinary(path="/usr/local/bin/uv"),
        sandbox_pb2.NetworkBinary(path="/sandbox/.uv/python/**"),
    ],
)


def _pypi_spec() -> datamodel_pb2.SandboxSpec:
    """Sandbox spec that allows pip/uv to install packages from PyPI."""
    return datamodel_pb2.SandboxSpec(
        policy=sandbox_pb2.SandboxPolicy(
            version=1,
            filesystem=_BASE_FILESYSTEM,
            landlock=_BASE_LANDLOCK,
            process=_BASE_PROCESS,
            network_policies={"pypi": _PYPI_NETWORK_POLICY},
            inference=sandbox_pb2.InferencePolicy(allowed_routes=["local"]),
        ),
    )


def test_sandbox_venv_in_path(
    sandbox: Callable[..., Sandbox],
) -> None:
    """Non-interactive exec sees /sandbox/.venv/bin in PATH."""
    with sandbox(delete_on_exit=True) as sb:
        result = sb.exec(["bash", "-c", "echo $PATH"], timeout_seconds=20)
        assert result.exit_code == 0, result.stderr
        path_dirs = result.stdout.strip().split(":")
        assert "/sandbox/.venv/bin" in path_dirs, (
            f"Expected /sandbox/.venv/bin in PATH, got: {result.stdout.strip()}"
        )
        # /sandbox/.venv/bin must come before /app/.venv/bin
        sandbox_idx = path_dirs.index("/sandbox/.venv/bin")
        app_idx = path_dirs.index("/app/.venv/bin")
        assert sandbox_idx < app_idx, (
            "/sandbox/.venv/bin must precede /app/.venv/bin in PATH"
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
