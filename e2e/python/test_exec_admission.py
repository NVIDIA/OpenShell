# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import threading
import time
import uuid
from typing import TYPE_CHECKING

import grpc
import pytest
from google.protobuf import duration_pb2

from openshell._proto import datamodel_pb2, openshell_pb2
from openshell.errors import from_grpc_error

if TYPE_CHECKING:
    from collections.abc import Callable

    from openshell import Sandbox, SandboxClient


def assert_blocked(stream, reason: str) -> None:
    with pytest.raises(grpc.RpcError) as caught:
        list(stream)
    error = from_grpc_error(caught.value)
    assert error.code() == grpc.StatusCode.FAILED_PRECONDITION
    assert error.error_info is not None
    assert error.error_info.reason == reason


@pytest.mark.parametrize("interactive", [False, True])
def test_exec_request_id_never_relaunches_or_replays_output(
    sandbox: Callable[..., Sandbox], sandbox_client: SandboxClient, interactive: bool
) -> None:
    with sandbox(delete_on_exit=True) as sb:
        path = f"/sandbox/exec-admission-{uuid.uuid4().hex}"
        request = openshell_pb2.ExecSandboxRequest(
            sandbox=sb.sandbox.name,
            workspace_scope=datamodel_pb2.WorkspaceSelector(workspace="default"),
            command=[
                "/bin/sh",
                "-c",
                f"printf x >> {path}; printf started; "
                f"while [ ! -e {path}.release ]; do sleep 0.1; done; "
                "printf finished; exit 7",
            ],
            request_id=str(uuid.uuid4()),
        )
        done = threading.Event()

        def invoke(value):
            if not interactive:
                return sandbox_client._stub.ExecSandbox(value, timeout=30)

            def inputs():
                yield openshell_pb2.ExecSandboxInput(start=value)
                done.wait(timeout=30)

            return sandbox_client._stub.ExecSandboxInteractive(inputs(), timeout=30)

        stream = invoke(request)
        try:
            first = next(stream)
            assert first.WhichOneof("payload") == "stdout"
            assert b"started" in first.stdout.data
            assert_blocked(invoke(request), "REQUEST_OUTCOME_UNCERTAIN")
            changed = openshell_pb2.ExecSandboxRequest()
            changed.CopyFrom(request)
            changed.command.append("changed-payload")
            assert_blocked(invoke(changed), "REQUEST_ID_PAYLOAD_MISMATCH")
            assert sb.exec(["touch", f"{path}.release"]).exit_code == 0
            events = list(stream)
            assert events[-1].WhichOneof("payload") == "exit"
            assert events[-1].exit.exit_code == 7
            assert_blocked(invoke(request), "REQUEST_STREAM_UNAVAILABLE")
            result = sb.exec(["cat", path])
            assert result.exit_code == 0
            assert result.stdout == "x"
        finally:
            done.set()
            stream.cancel()


@pytest.mark.parametrize("interactive", [False, True])
def test_exec_request_timeout_keeps_launch_unresolved(
    sandbox: Callable[..., Sandbox], sandbox_client: SandboxClient, interactive: bool
) -> None:
    with sandbox(delete_on_exit=True) as sb:
        path = f"/sandbox/exec-timeout-{uuid.uuid4().hex}"
        request = openshell_pb2.ExecSandboxRequest(
            sandbox=sb.sandbox.name,
            workspace_scope=datamodel_pb2.WorkspaceSelector(workspace="default"),
            command=["/bin/sh", "-c", f"printf x >> {path}; sleep 5"],
            execution_timeout=duration_pb2.Duration(seconds=1),
            request_id=str(uuid.uuid4()),
        )
        done = threading.Event()

        def invoke():
            if not interactive:
                return sandbox_client._stub.ExecSandbox(request, timeout=30)

            def inputs():
                yield openshell_pb2.ExecSandboxInput(start=request)
                done.wait(timeout=30)

            return sandbox_client._stub.ExecSandboxInteractive(inputs(), timeout=30)

        stream = invoke()
        try:
            events = []
            for event in stream:
                events.append(event)
                if event.WhichOneof("payload") == "exit":
                    # A synthetic timeout leaves the interactive input task
                    # alive until the client closes its side of the stream.
                    done.set()
            assert events[-1].exit.exit_code == 124
            assert_blocked(invoke(), "REQUEST_OUTCOME_UNCERTAIN")
            assert sb.exec(["cat", path]).stdout == "x"
        finally:
            done.set()
            stream.cancel()


def test_exec_client_cancellation_does_not_clear_launch_admission(
    sandbox: Callable[..., Sandbox], sandbox_client: SandboxClient
) -> None:
    with sandbox(delete_on_exit=True) as sb:
        path = f"/sandbox/exec-cancel-{uuid.uuid4().hex}"
        request = openshell_pb2.ExecSandboxRequest(
            sandbox=sb.sandbox.name,
            workspace_scope=datamodel_pb2.WorkspaceSelector(workspace="default"),
            command=[
                "/bin/sh",
                "-c",
                f"printf x >> {path}; printf started; sleep 1; printf finished",
            ],
            request_id=str(uuid.uuid4()),
        )
        stream = sandbox_client._stub.ExecSandbox(request, timeout=30)
        assert b"started" in next(stream).stdout.data
        stream.cancel()
        deadline = time.monotonic() + 15
        while True:
            with pytest.raises(grpc.RpcError) as caught:
                list(sandbox_client._stub.ExecSandbox(request, timeout=30))
            error = from_grpc_error(caught.value)
            assert error.error_info is not None
            if error.error_info.reason == "REQUEST_STREAM_UNAVAILABLE":
                break
            assert error.error_info.reason == "REQUEST_OUTCOME_UNCERTAIN"
            assert time.monotonic() < deadline
            time.sleep(0.1)
        assert sb.exec(["cat", path]).stdout == "x"
