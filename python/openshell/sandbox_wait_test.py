# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from concurrent import futures
from types import SimpleNamespace

import grpc
import pytest

import openshell.sandbox as sandbox_module
from openshell._proto import openshell_pb2
from openshell.sandbox import SandboxClient, SandboxError


class Clock:
    def __init__(self) -> None:
        self.elapsed = 0.0
        self.wall_offset = 0.0

    def monotonic(self) -> float:
        return self.elapsed

    def time(self) -> float:
        return self.elapsed + self.wall_offset

    def sleep(self, seconds: float) -> None:
        assert seconds >= 0
        self.elapsed += seconds


@pytest.mark.parametrize("method", ["wait_ready", "wait_stopped", "wait_deleted"])
@pytest.mark.parametrize("timeout_seconds", [0, -1])
def test_expired_wait_does_not_poll(monkeypatch, method, timeout_seconds):
    def get(_request, timeout):
        pytest.fail(f"unexpected lookup with timeout {timeout}")

    with SandboxClient("localhost:1") as client:
        monkeypatch.setattr(client, "_stub", SimpleNamespace(GetSandbox=get))
        with pytest.raises(SandboxError, match="within timeout"):
            getattr(client, method)(
                "job", workspace="team", timeout_seconds=timeout_seconds
            )


@pytest.mark.parametrize("method", ["wait_ready", "wait_stopped", "wait_deleted"])
@pytest.mark.parametrize(
    "code", [grpc.StatusCode.DEADLINE_EXCEEDED, grpc.StatusCode.PERMISSION_DENIED]
)
def test_wait_preserves_lookup_errors_before_deadline(monkeypatch, method, code):
    class LookupError(grpc.RpcError):
        def code(self):
            return code

    error = LookupError()

    def get(_request, timeout):
        assert 0 < timeout <= 0.1
        raise error

    with SandboxClient("localhost:1", timeout=0.1) as client:
        monkeypatch.setattr(client, "_stub", SimpleNamespace(GetSandbox=get))
        with pytest.raises(LookupError) as caught:
            getattr(client, method)("job", workspace="team", timeout_seconds=10)
        assert caught.value is error


@pytest.mark.parametrize("method", ["wait_ready", "wait_stopped", "wait_deleted"])
@pytest.mark.parametrize("client_timeout", [0.1, 30.0])
def test_wait_bounds_rpc_and_sleep(monkeypatch, method, client_timeout):
    clock = Clock()
    monkeypatch.setattr(sandbox_module, "time", clock)
    timeouts = []

    def get(request, timeout):
        assert request.name == "job"
        assert request.workspace_scope.workspace == "team"
        timeouts.append(timeout)
        clock.elapsed += 0.05
        return openshell_pb2.SandboxResponse()

    with SandboxClient("localhost:1", timeout=client_timeout) as client:
        monkeypatch.setattr(client, "_stub", SimpleNamespace(GetSandbox=get))
        with pytest.raises(SandboxError, match="within timeout"):
            getattr(client, method)("job", workspace="team", timeout_seconds=1.25)

    assert timeouts == pytest.approx(
        [min(client_timeout, 1.25), min(client_timeout, 0.2)]
    )
    assert clock.elapsed == pytest.approx(1.25)


@pytest.mark.parametrize(
    ("method", "phase"),
    [
        ("wait_ready", openshell_pb2.SANDBOX_PHASE_READY),
        ("wait_stopped", openshell_pb2.SANDBOX_PHASE_STOPPED),
        ("wait_deleted", openshell_pb2.SANDBOX_PHASE_READY),
    ],
)
def test_wait_ignores_wall_clock_changes(monkeypatch, method, phase):
    clock = Clock()
    monkeypatch.setattr(sandbox_module, "time", clock)
    calls = 0

    def get(_request, timeout):
        nonlocal calls
        assert timeout > 0
        calls += 1
        clock.wall_offset += 1000
        response = openshell_pb2.SandboxResponse()
        response.sandbox.metadata.id = "original" if calls == 1 else "replacement"
        if calls == 2:
            response.sandbox.status.phase = phase
        return response

    with SandboxClient("localhost:1") as client:
        monkeypatch.setattr(client, "_stub", SimpleNamespace(GetSandbox=get))
        options = (
            {"expected_sandbox_id": "original"} if method == "wait_deleted" else {}
        )
        getattr(client, method)("job", workspace="team", timeout_seconds=2, **options)

    assert calls == 2
    assert clock.elapsed == 1


@pytest.mark.parametrize("method", ["wait_ready", "wait_stopped", "wait_deleted"])
def test_wait_cancels_stalled_lookup_at_deadline(method):
    import threading
    import time

    def get(_request, context):
        cancelled = threading.Event()
        context.add_callback(cancelled.set)
        cancelled.wait(5)
        return openshell_pb2.SandboxResponse()

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
                },
            ),
        )
    )
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    try:
        with SandboxClient(f"127.0.0.1:{port}", timeout=2) as client:
            started = time.monotonic()
            with pytest.raises(SandboxError, match="within timeout"):
                getattr(client, method)("job", workspace="team", timeout_seconds=0.1)
            assert time.monotonic() - started < 1
    finally:
        server.stop(0).wait()
