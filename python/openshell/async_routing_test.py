# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Native async exec preserves replica affinity and the pre-response fallback."""

from contextlib import asynccontextmanager

import grpc
import grpc.aio
import pytest

from openshell import AsyncSandboxClient, ExecChunk, GatewayError
from openshell._proto import openshell_pb2 as pb
from openshell._proto import openshell_pb2_grpc as rpc


class Gateway(rpc.OpenShellServicer):
    def __init__(self):
        self.owner = ""
        self.reject_route = None
        self.fail_after_output = False
        self.exec_deadlines = []
        self.requests = []

    async def GetSandbox(self, request, context):
        self.requests.append((request, context.invocation_metadata()))
        if self.owner:
            await context.send_initial_metadata((("x-openshell-owner", self.owner),))
        return pb.SandboxResponse()

    async def ExecSandbox(self, request, context):
        self.requests.append((request, context.invocation_metadata()))
        self.exec_deadlines.append(context.time_remaining())
        if (
            dict(context.invocation_metadata()).get("x-openshell-replica")
            and self.reject_route is not None
        ):
            await context.abort(grpc.StatusCode.UNAVAILABLE, self.reject_route)
        event = pb.ExecSandboxEvent()
        event.stdout.data = b"hello"
        yield event
        if self.fail_after_output:
            await context.abort(grpc.StatusCode.UNAVAILABLE, "no healthy upstream")
        event = pb.ExecSandboxEvent()
        event.exit.exit_code = 0
        yield event


@asynccontextmanager
async def gateway():
    service = Gateway()
    server = grpc.aio.server()
    rpc.add_OpenShellServicer_to_server(service, server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    try:
        yield service, f"127.0.0.1:{port}"
    finally:
        await server.stop(0)


async def test_async_exec_owner_cache_and_narrow_unrouted_retry():
    async with gateway() as (service, target), AsyncSandboxClient(target) as client:
        service.owner = "openshell-1"
        for _ in range(2):
            assert (
                await client.exec("worker", ["echo"], workspace="team")
            ).stdout == "hello"
        lookups = [
            request
            for request, _ in service.requests
            if isinstance(request, pb.GetSandboxRequest)
        ]
        assert len(lookups) == 1
        service.reject_route = "no healthy upstream"
        assert (
            await client.exec("worker", ["echo"], workspace="team")
        ).stdout == "hello"
        routes = [
            dict(metadata).get("x-openshell-replica", "")
            for request, metadata in service.requests
            if isinstance(request, pb.ExecSandboxRequest)
        ]
        assert routes == ["openshell-1", "openshell-1", "openshell-1", ""]
        service.reject_route = "gateway denied exec"
        with pytest.raises(GatewayError):
            await client.exec("worker", ["echo"], workspace="team")
        assert dict(service.requests[-1][1])["x-openshell-replica"] == "openshell-1"


async def test_async_exec_never_replays_after_output_and_preserves_deadlines():
    async with gateway() as (service, target), AsyncSandboxClient(target) as client:
        service.owner = "openshell-1"
        await client.exec("worker", ["echo"], workspace="team", timeout_seconds=60)
        assert 60 < service.exec_deadlines[-1] <= 70
        async for _ in client.exec_stream(
            "worker", ["echo"], workspace="team", timeout_seconds=60, timeout=0.5
        ):
            pass
        assert 0 < service.exec_deadlines[-1] <= 0.6
        service.fail_after_output = True
        before = len(service.exec_deadlines)
        stream = client.exec_stream("worker", ["echo"], workspace="team")
        assert isinstance(await anext(stream), ExecChunk)
        with pytest.raises(GatewayError):
            await anext(stream)
        assert len(service.exec_deadlines) == before + 1
