# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the writable sandbox venv, PATH, and package installation.

Verifies that:
- /sandbox/.venv/bin is in PATH for both interactive and non-interactive sessions
- pip install works inside the sandbox (pypi policy in dev-sandbox-policy.yaml)
- uv pip install works (validates Landlock V2 cross-directory rename support)
- uv run --with works for ephemeral dependency injection
- Installed packages are importable after installation

All tests use the default dev sandbox policy -- no custom policy overrides.
The SDK omits the policy field from the spec so the sandbox container discovers
its policy from /etc/openshell/policy.yaml (the dev-sandbox-policy.yaml baked
into the image), which already includes the pypi network policy.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from openshell import Sandbox


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


def test_pip_install_in_sandbox(
    sandbox: Callable[..., Sandbox],
) -> None:
    """pip install works inside the sandbox and installed packages are importable."""
    with sandbox(delete_on_exit=True) as sb:
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
    with sandbox(delete_on_exit=True) as sb:
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
    with sandbox(delete_on_exit=True) as sb:
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
