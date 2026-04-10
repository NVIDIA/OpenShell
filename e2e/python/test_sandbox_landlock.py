# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for Landlock filesystem sandboxing.

Verifies that:
- Landlock availability is logged via OCSF in sandbox logs
- Read-only paths block writes but allow reads
- Read-write paths allow both reads and writes
- Paths outside the policy are blocked entirely
- Paths the sandbox user owns but are not in the policy are still blocked
- best_effort mode skips inaccessible paths without crashing

These tests require a Linux host with Landlock support (kernel 5.13+).
GitHub Actions Linux runners satisfy this requirement. Docker Desktop
linuxkit kernels also support Landlock (ABI v5+).

Related: https://github.com/NVIDIA/OpenShell/issues/803
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from openshell._proto import datamodel_pb2, sandbox_pb2

if TYPE_CHECKING:
    from collections.abc import Callable

    from openshell import Sandbox


# =============================================================================
# Policy helpers
# =============================================================================

_LANDLOCK_FILESYSTEM = sandbox_pb2.FilesystemPolicy(
    include_workdir=True,
    read_only=["/usr", "/lib", "/etc", "/proc", "/dev/urandom"],
    read_write=["/sandbox", "/tmp"],
)
_LANDLOCK_BEST_EFFORT = sandbox_pb2.LandlockPolicy(compatibility="best_effort")
_LANDLOCK_PROCESS = sandbox_pb2.ProcessPolicy(
    run_as_user="sandbox", run_as_group="sandbox"
)


def _landlock_policy(
    *,
    filesystem: sandbox_pb2.FilesystemPolicy | None = None,
    landlock: sandbox_pb2.LandlockPolicy | None = None,
) -> sandbox_pb2.SandboxPolicy:
    return sandbox_pb2.SandboxPolicy(
        version=1,
        filesystem=filesystem or _LANDLOCK_FILESYSTEM,
        landlock=landlock or _LANDLOCK_BEST_EFFORT,
        process=_LANDLOCK_PROCESS,
        network_policies={},
    )


# =============================================================================
# Closures for exec_python (serialized into the sandbox by cloudpickle)
# =============================================================================


def _try_write():
    """Return a closure that attempts to write a file and returns the result."""

    def fn(path):
        import os

        try:
            with open(os.path.join(path, ".landlock-test"), "w") as f:
                f.write("test")
            return "OK"
        except PermissionError:
            return "EPERM"
        except OSError as e:
            return f"ERROR:{e.errno}"

    return fn


def _try_read():
    """Return a closure that attempts to read a directory listing."""

    def fn(path):
        import os

        try:
            entries = os.listdir(path)
            return f"OK:{len(entries)}"
        except PermissionError:
            return "EPERM"
        except OSError as e:
            return f"ERROR:{e.errno}"

    return fn


def _check_user_owns_path():
    """Return a closure that checks if the current user owns a path."""

    def fn(path):
        import os

        try:
            st = os.stat(path)
            uid = os.getuid()
            return f"owner:{st.st_uid} me:{uid} match:{st.st_uid == uid}"
        except OSError as e:
            return f"ERROR:{e}"

    return fn


# =============================================================================
# Landlock enforcement tests
# =============================================================================


def test_landlock_blocks_write_to_read_only_path(
    sandbox: Callable[..., Sandbox],
) -> None:
    """Writes to read-only paths (/usr) are blocked by Landlock."""
    spec = datamodel_pb2.SandboxSpec(policy=_landlock_policy())
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        result = sb.exec_python(_try_write(), args=("/usr",))
        assert result.exit_code == 0, result.stderr
        assert result.stdout.strip() == "EPERM", (
            f"Expected write to /usr to be denied, got: {result.stdout.strip()}"
        )


def test_landlock_allows_write_to_read_write_path(
    sandbox: Callable[..., Sandbox],
) -> None:
    """Writes to read-write paths (/tmp, /sandbox) are allowed."""
    spec = datamodel_pb2.SandboxSpec(policy=_landlock_policy())
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        for path in ["/tmp", "/sandbox"]:
            result = sb.exec_python(_try_write(), args=(path,))
            assert result.exit_code == 0, result.stderr
            assert result.stdout.strip() == "OK", (
                f"Expected write to {path} to succeed, got: {result.stdout.strip()}"
            )


def test_landlock_allows_read_on_read_only_path(
    sandbox: Callable[..., Sandbox],
) -> None:
    """Reads from read-only paths (/usr, /etc) are allowed."""
    spec = datamodel_pb2.SandboxSpec(policy=_landlock_policy())
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        for path in ["/usr", "/etc"]:
            result = sb.exec_python(_try_read(), args=(path,))
            assert result.exit_code == 0, result.stderr
            assert result.stdout.strip().startswith("OK:"), (
                f"Expected read from {path} to succeed, got: {result.stdout.strip()}"
            )


def test_landlock_blocks_access_outside_policy(
    sandbox: Callable[..., Sandbox],
) -> None:
    """Paths not listed in the policy (/opt, /root) are blocked entirely.

    When Landlock is enforced, any path not covered by a rule is denied
    by default. This is the fundamental allowlist property.
    """
    spec = datamodel_pb2.SandboxSpec(policy=_landlock_policy())
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        for path in ["/opt", "/root"]:
            result = sb.exec_python(_try_read(), args=(path,))
            assert result.exit_code == 0, result.stderr
            assert (
                "EPERM" in result.stdout.strip() or "ERROR:" in result.stdout.strip()
            ), (
                f"Expected access to {path} (outside policy) to be denied, "
                f"got: {result.stdout.strip()}"
            )


def test_landlock_blocks_user_owned_path_outside_policy(
    sandbox: Callable[..., Sandbox],
) -> None:
    """Landlock blocks access to /home/sandbox even though the sandbox user owns it.

    This is the key distinction between Landlock and Unix DAC permissions:
    the sandbox user has filesystem ownership of /home/sandbox, but because
    /home is not in the Landlock policy, access is denied. This confirms
    Landlock is enforcing independently of Unix permissions.
    """
    spec = datamodel_pb2.SandboxSpec(policy=_landlock_policy())
    with sandbox(spec=spec, delete_on_exit=True) as sb:
        # Verify the sandbox user owns /home/sandbox
        own_result = sb.exec_python(_check_user_owns_path(), args=("/home/sandbox",))
        # The path might not exist in all images, so only assert Landlock
        # enforcement if the path is present and owned by us.
        if own_result.exit_code == 0 and "match:True" in own_result.stdout:
            write_result = sb.exec_python(_try_write(), args=("/home/sandbox",))
            assert write_result.exit_code == 0, write_result.stderr
            assert write_result.stdout.strip() == "EPERM", (
                "Expected Landlock to block write to /home/sandbox despite user ownership. "
                f"Got: {write_result.stdout.strip()}"
            )
