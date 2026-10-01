# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Cleanup status handling through the curated client's real gRPC interceptor."""

from concurrent import futures
from contextlib import nullcontext
from types import SimpleNamespace

import grpc
import pytest

from openshell._proto import openshell_pb2
from openshell.errors import GatewayError
from openshell.sandbox import Sandbox, SandboxClient


@pytest.fixture
def cleanup_client():
    state = SimpleNamespace(
        exists=False,
        code=grpc.StatusCode.NOT_FOUND,
        calls=[],
        closed=[],
    )

    def fail(context):
        context.set_trailing_metadata((("request-id", "cleanup-regression"),))
        context.abort(state.code, "cleanup status")

    def get(request, context):
        state.calls.append("GetSandbox")
        assert request.name == "cleanup-test"
        assert request.workspace_scope.workspace == "default"
        if not state.exists:
            fail(context)
        response = openshell_pb2.SandboxResponse()
        response.sandbox.metadata.id = "sandbox-1"
        response.sandbox.metadata.name = request.name
        response.sandbox.metadata.workspace = "default"
        response.sandbox.status.phase = openshell_pb2.SANDBOX_PHASE_READY
        return response

    def delete(request, context):
        state.calls.append("DeleteSandbox")
        assert request.name == "cleanup-test"
        assert request.workspace_scope.workspace == "default"
        assert request.allow_missing
        if state.code == grpc.StatusCode.NOT_FOUND:
            return openshell_pb2.DeleteSandboxResponse(
                outcome=openshell_pb2.DELETION_OUTCOME_ALREADY_ABSENT
            )
        fail(context)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    server.add_generic_rpc_handlers(
        (
            grpc.method_handlers_generic_handler(
                "openshell.v1.OpenShell",
                {
                    "GetSandbox": grpc.unary_unary_rpc_method_handler(
                        get,
                        request_deserializer=openshell_pb2.GetSandboxRequest.FromString,
                        response_serializer=openshell_pb2.SandboxResponse.SerializeToString,
                    ),
                    "DeleteSandbox": grpc.unary_unary_rpc_method_handler(
                        delete,
                        request_deserializer=openshell_pb2.DeleteSandboxRequest.FromString,
                        response_serializer=openshell_pb2.DeleteSandboxResponse.SerializeToString,
                    ),
                },
            ),
        )
    )
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    client = SandboxClient(
        f"127.0.0.1:{port}",
        timeout=5,
        _bearer_close=lambda: state.closed.append(True),
    )
    try:
        yield client, state
    finally:
        client.close()
        server.stop(0).wait()


def assert_original_call(error, code):
    assert isinstance(error, GatewayError)
    assert isinstance(error.raw_error, grpc.Call)
    assert error.code() == error.raw_error.code() == code
    assert error.details() == "cleanup status"
    assert ("request-id", "cleanup-regression") in error.trailing_metadata()


@pytest.mark.parametrize(
    "code",
    [
        grpc.StatusCode.NOT_FOUND,
        grpc.StatusCode.PERMISSION_DENIED,
        grpc.StatusCode.UNAVAILABLE,
    ],
)
def test_wait_deleted_handles_intercepted_status(cleanup_client, code):
    client, state = cleanup_client
    state.code = code
    # Prove this is the curated intercepted stub, not a fake raw exception.
    with pytest.raises(GatewayError) as observed:
        client.get("cleanup-test", workspace="default")
    assert_original_call(observed.value, code)

    expected = (
        nullcontext()
        if code == grpc.StatusCode.NOT_FOUND
        else pytest.raises(GatewayError)
    )
    with expected as caught:
        client.wait_deleted("cleanup-test", workspace="default", timeout_seconds=5)
    if caught is not None:
        assert_original_call(caught.value, code)
    assert state.calls == ["GetSandbox", "GetSandbox"]


@pytest.mark.parametrize(
    "code",
    [
        grpc.StatusCode.NOT_FOUND,
        grpc.StatusCode.PERMISSION_DENIED,
        grpc.StatusCode.UNAVAILABLE,
    ],
)
def test_context_cleanup_handles_absence_and_intercepted_errors(
    cleanup_client, monkeypatch, code
):
    client, state = cleanup_client
    state.code = code
    state.exists = True
    monkeypatch.setattr(
        SandboxClient,
        "from_active_cluster",
        classmethod(lambda _cls, **_kwargs: client),
    )

    managed = Sandbox(workspace="default", sandbox="cleanup-test")
    expected = (
        nullcontext()
        if code == grpc.StatusCode.NOT_FOUND
        else pytest.raises(GatewayError)
    )
    with expected as caught, managed:
        state.exists = False
    if caught is not None:
        assert_original_call(caught.value, code)
    assert state.calls == ["GetSandbox", "GetSandbox", "DeleteSandbox"]
    assert state.closed == [True]
    assert managed._client is None
    assert managed._session is None
