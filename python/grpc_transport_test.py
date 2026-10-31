# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generated async stubs retain native gRPC transport behavior."""

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import grpc
import grpc.aio
import pytest

from openshell._proto import datamodel_pb2 as dm
from openshell._proto import openshell_pb2 as pb
from openshell._proto import openshell_pb2_grpc as rpc


class Gateway(rpc.OpenShellServicer):
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()

    async def GetProvider(
        self, request: pb.GetProviderRequest, context: grpc.aio.ServicerContext
    ) -> pb.ProviderResponse:
        assert ("authorization", "Bearer test-token") in (
            context.invocation_metadata() or ()
        )
        if request.name == "missing":
            await context.abort(grpc.StatusCode.NOT_FOUND, "No provider")
        if request.name == "blocked":
            self.started.set()
            try:
                await asyncio.Future()
            finally:
                self.cancelled.set()
        return pb.ProviderResponse(
            provider=dm.Provider(metadata=dm.ObjectMeta(name=request.name))
        )


@asynccontextmanager
async def gateway() -> AsyncGenerator[tuple[Gateway, grpc.aio.Channel]]:
    service = Gateway()
    server = grpc.aio.server()
    rpc.add_OpenShellServicer_to_server(service, server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{port}") as channel:
            yield service, channel
    finally:
        await server.stop(0)


_METADATA = (("authorization", "Bearer test-token"),)


async def test_concurrent_calls_and_task_cancellation() -> None:
    async with gateway() as (service, channel):
        stub = rpc.OpenShellStub(channel)

        async def blocked_call() -> pb.ProviderResponse:
            return await stub.GetProvider(
                pb.GetProviderRequest(name="blocked"), timeout=5, metadata=_METADATA
            )

        pending = asyncio.create_task(blocked_call())
        try:
            await asyncio.wait_for(service.started.wait(), timeout=5)
            response = await stub.GetProvider(
                pb.GetProviderRequest(name="ready"), timeout=5, metadata=_METADATA
            )
            assert response.provider.metadata.name == "ready"
        finally:
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
        await asyncio.wait_for(service.cancelled.wait(), timeout=5)
        response = await stub.GetProvider(
            pb.GetProviderRequest(name="still-ready"), timeout=5, metadata=_METADATA
        )
        assert response.provider.metadata.name == "still-ready"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("missing", grpc.StatusCode.NOT_FOUND),
        ("blocked", grpc.StatusCode.DEADLINE_EXCEEDED),
    ],
)
async def test_status_and_deadline(name: str, expected: grpc.StatusCode) -> None:
    async with gateway() as (_, channel):
        stub = rpc.OpenShellStub(channel)
        with pytest.raises(grpc.aio.AioRpcError) as error:
            await stub.GetProvider(
                pb.GetProviderRequest(name=name), timeout=0.2, metadata=_METADATA
            )
        assert error.value.code() == expected
