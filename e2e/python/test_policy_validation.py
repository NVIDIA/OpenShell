# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""E2E tests for server-side policy safety validation.

These tests verify that the gRPC server rejects sandbox creation and policy
updates that contain unsafe content (root process identity, path traversal,
overly broad filesystem paths).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import grpc
import pytest

from navigator._proto import datamodel_pb2, navigator_pb2, sandbox_pb2

if TYPE_CHECKING:
    from collections.abc import Callable

    from navigator import Sandbox, SandboxClient


# =============================================================================
# Policy helpers
# =============================================================================

_SAFE_FILESYSTEM = sandbox_pb2.FilesystemPolicy(
    include_workdir=True,
    read_only=["/usr", "/lib", "/etc", "/app", "/var/log"],
    read_write=["/sandbox", "/tmp"],
)
_SAFE_LANDLOCK = sandbox_pb2.LandlockPolicy(compatibility="best_effort")
_SAFE_PROCESS = sandbox_pb2.ProcessPolicy(run_as_user="sandbox", run_as_group="sandbox")


def _safe_policy() -> sandbox_pb2.SandboxPolicy:
    """Build a safe baseline policy for testing."""
    return sandbox_pb2.SandboxPolicy(
        version=1,
        filesystem=_SAFE_FILESYSTEM,
        landlock=_SAFE_LANDLOCK,
        process=_SAFE_PROCESS,
    )


# =============================================================================
# Tests
# =============================================================================


def test_create_sandbox_rejects_root_user(
    sandbox_client: SandboxClient,
) -> None:
    """Server rejects CreateSandbox with run_as_user='root'."""
    policy = sandbox_pb2.SandboxPolicy(
        version=1,
        filesystem=_SAFE_FILESYSTEM,
        landlock=_SAFE_LANDLOCK,
        process=sandbox_pb2.ProcessPolicy(
            run_as_user="root",
            run_as_group="sandbox",
        ),
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)

    stub = sandbox_client._stub
    with pytest.raises(grpc.RpcError) as exc_info:
        stub.CreateSandbox(navigator_pb2.CreateSandboxRequest(name="", spec=spec))

    assert exc_info.value.code() == grpc.StatusCode.INVALID_ARGUMENT
    assert "root" in exc_info.value.details().lower()


def test_create_sandbox_rejects_path_traversal(
    sandbox_client: SandboxClient,
) -> None:
    """Server rejects CreateSandbox with '..' in filesystem paths."""
    policy = sandbox_pb2.SandboxPolicy(
        version=1,
        filesystem=sandbox_pb2.FilesystemPolicy(
            include_workdir=True,
            read_only=["/usr/../etc/shadow"],
            read_write=["/tmp"],
        ),
        landlock=_SAFE_LANDLOCK,
        process=_SAFE_PROCESS,
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)

    stub = sandbox_client._stub
    with pytest.raises(grpc.RpcError) as exc_info:
        stub.CreateSandbox(navigator_pb2.CreateSandboxRequest(name="", spec=spec))

    assert exc_info.value.code() == grpc.StatusCode.INVALID_ARGUMENT
    assert "traversal" in exc_info.value.details().lower()


def test_create_sandbox_rejects_overly_broad_paths(
    sandbox_client: SandboxClient,
) -> None:
    """Server rejects CreateSandbox with read_write=['/']."""
    policy = sandbox_pb2.SandboxPolicy(
        version=1,
        filesystem=sandbox_pb2.FilesystemPolicy(
            include_workdir=True,
            read_only=["/usr"],
            read_write=["/"],
        ),
        landlock=_SAFE_LANDLOCK,
        process=_SAFE_PROCESS,
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)

    stub = sandbox_client._stub
    with pytest.raises(grpc.RpcError) as exc_info:
        stub.CreateSandbox(navigator_pb2.CreateSandboxRequest(name="", spec=spec))

    assert exc_info.value.code() == grpc.StatusCode.INVALID_ARGUMENT
    assert "broad" in exc_info.value.details().lower()


def test_update_policy_rejects_immutable_fields(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """UpdateSandboxPolicy rejects removal of filesystem paths on a live sandbox.

    Filesystem paths are enforced by Landlock at sandbox startup and cannot be
    removed after the fact. This test verifies that the server rejects updates
    that remove existing read_only paths, which also prevents unsafe content
    from being introduced via policy updates.
    """
    safe_policy = _safe_policy()
    spec = datamodel_pb2.SandboxSpec(policy=safe_policy)

    with sandbox(spec=spec, delete_on_exit=True) as sb:
        sandbox_name = sb.sandbox.name
        stub = sandbox_client._stub

        # Try to update with a modified filesystem policy (immutable field)
        unsafe_policy = sandbox_pb2.SandboxPolicy(
            version=1,
            filesystem=sandbox_pb2.FilesystemPolicy(
                include_workdir=True,
                read_only=["/usr/../etc/shadow"],
                read_write=["/tmp"],
            ),
            landlock=_SAFE_LANDLOCK,
            process=_SAFE_PROCESS,
        )

        with pytest.raises(grpc.RpcError) as exc_info:
            stub.UpdateSandboxPolicy(
                navigator_pb2.UpdateSandboxPolicyRequest(
                    name=sandbox_name,
                    policy=unsafe_policy,
                )
            )

        assert exc_info.value.code() == grpc.StatusCode.INVALID_ARGUMENT
        assert "cannot be removed" in exc_info.value.details().lower()
