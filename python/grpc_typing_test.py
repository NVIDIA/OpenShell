# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Check the consumer-facing types of generated sync and async RPCs."""

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_generated_rpc_types(tmp_path: Path, asynchronous: bool) -> None:
    channel = "grpc.aio.Channel" if asynchronous else "grpc.Channel"
    function = "async def" if asynchronous else "def"
    await_call = "await " if asynchronous else ""
    iterate = "async for" if asynchronous else "for"
    source = f"""
from typing import assert_type
import grpc
import grpc.aio
from openshell._proto import credential_driver_pb2 as credentials
from openshell._proto import credential_driver_pb2_grpc as driver
from openshell._proto import openshell_pb2 as pb
from openshell._proto import openshell_pb2_grpc as rpc

{function} check(channel: {channel}) -> None:
    stub = rpc.OpenShellStub(channel)
    assert_type({await_call}stub.GetProvider(pb.GetProviderRequest()), pb.ProviderResponse)
    assert_type({await_call}stub.CreateProvider(pb.CreateProviderRequest()), pb.ProviderResponse)
    assert_type({await_call}stub.UpdateProvider(pb.UpdateProviderRequest()), pb.ProviderResponse)
    assert_type({await_call}stub.DeleteProvider(pb.DeleteProviderRequest()), pb.DeleteProviderResponse)
    assert_type({await_call}stub.ListProviders(pb.ListProvidersRequest()), pb.ListProvidersResponse)
    assert_type({await_call}stub.GetProviderProfile(pb.GetProviderProfileRequest()), pb.ProviderProfileResponse)
    assert_type({await_call}stub.GetSandbox(pb.GetSandboxRequest()), pb.SandboxResponse)
    assert_type({await_call}stub.DetachSandboxProvider(pb.DetachSandboxProviderRequest()), pb.DetachSandboxProviderResponse)
    {iterate} event in stub.ExecSandbox(pb.ExecSandboxRequest()):
        assert_type(event, pb.ExecSandboxEvent)
    {iterate} frame in stub.ForwardTcp(iter([pb.TcpForwardFrame()])):
        assert_type(frame, pb.TcpForwardFrame)
    credential_stub = driver.CredentialDriverStub(channel)
    assert_type({await_call}credential_stub.StoreCredential(credentials.StoreCredentialRequest()), credentials.StoreCredentialResponse)
"""
    path = tmp_path / "consumer.py"
    path.write_text(source)
    result = _check_types(path)
    assert result.returncode == 0, result.stdout + result.stderr

    # A missing import or Any-typed callable must not make this test pass.
    path.write_text(
        source.replace(
            "stub.GetProvider(pb.GetProviderRequest())",
            "stub.GetProvider(pb.DeleteProviderRequest())",
        )
    )
    result = _check_types(path)
    assert result.returncode != 0
    assert "invalid-argument-type" in result.stdout
    assert "GetProviderRequest" in result.stdout
    assert "DeleteProviderRequest" in result.stdout


def _check_types(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "ty",
            "check",
            "--python",
            sys.executable,
            "--output-format",
            "concise",
            str(path),
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )
