# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Python SDK policy integration tests.

Transparent network interception is exercised by the Rust E2E suites, which
cover TCP, DNS, L7, SSRF, policy reload, and credential rewriting without a
workload-visible forward-proxy endpoint. This module keeps the SDK-level
policy checks that do not depend on the retired ``10.200.0.1:3128`` contract.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import grpc
import pytest

from openshell._proto import datamodel_pb2, sandbox_pb2

if TYPE_CHECKING:
    from collections.abc import Callable

    from openshell import Sandbox


_BASE_FILESYSTEM = sandbox_pb2.FilesystemPolicy(
    include_workdir=True,
    read_only=["/usr", "/lib", "/etc", "/app", "/var/log", "/proc", "/dev/urandom"],
    read_write=["/sandbox", "/tmp"],
)
_BASE_LANDLOCK = sandbox_pb2.LandlockPolicy(compatibility="best_effort")
_BASE_PROCESS = sandbox_pb2.ProcessPolicy(
    run_as_user="sandbox", run_as_group="sandbox"
)


def _base_policy(
    network_policies: dict[str, sandbox_pb2.NetworkPolicyRule] | None = None,
) -> sandbox_pb2.SandboxPolicy:
    return sandbox_pb2.SandboxPolicy(
        version=1,
        filesystem=_BASE_FILESYSTEM,
        landlock=_BASE_LANDLOCK,
        process=_BASE_PROCESS,
        network_policies=network_policies or {},
    )


def test_policy_applies_to_exec_commands(
    sandbox: Callable[..., Sandbox],
) -> None:
    def current_user() -> str:
        import os
        import pwd

        return pwd.getpwuid(os.getuid()).pw_name

    def write_allowed_files() -> str:
        from pathlib import Path

        Path("/sandbox/allowed.txt").write_text("ok")
        Path("/tmp/allowed.txt").write_text("ok")
        return "ok"

    spec = datamodel_pb2.SandboxSpec(policy=_base_policy())
    with sandbox(spec=spec, delete_on_exit=True) as policy_sandbox:
        user_result = policy_sandbox.exec_python(current_user)
        assert user_result.exit_code == 0, user_result.stderr
        assert user_result.stdout.strip() == "sandbox"

        file_result = policy_sandbox.exec_python(write_allowed_files)
        assert file_result.exit_code == 0, file_result.stderr
        assert file_result.stdout.strip() == "ok"


def test_conflicting_destination_metadata_is_rejected(
    sandbox: Callable[..., Sandbox],
) -> None:
    """The gateway rejects ambiguous endpoint pinning before launch."""
    target = "10.200.0.2"
    port = 19876
    policy = _base_policy(
        network_policies={
            "user_rule": sandbox_pb2.NetworkPolicyRule(
                name="user_rule",
                endpoints=[sandbox_pb2.NetworkEndpoint(host=target, port=port)],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
            "approved_rule": sandbox_pb2.NetworkPolicyRule(
                name="approved_rule",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(
                        host=target,
                        port=port,
                        allowed_ips=["10.200.0.0/24"],
                    )
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            ),
        }
    )
    spec = datamodel_pb2.SandboxSpec(policy=policy)
    with (
        pytest.raises(grpc.RpcError) as exc_info,
        sandbox(spec=spec, delete_on_exit=True),
    ):
        pytest.fail("ambiguous policy unexpectedly created a sandbox")

    assert exc_info.value.code() == grpc.StatusCode.FAILED_PRECONDITION
    details = exc_info.value.details() or ""
    assert "network endpoint ambiguity validation failed" in details
    assert "allowed_ips" in details
