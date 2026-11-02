# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Consumer contracts exercised over a real loopback aio transport."""

import asyncio
import inspect
import threading
from contextlib import asynccontextmanager

import grpc
import grpc.aio
import pytest

from openshell import (
    AsyncPager,
    AsyncSandboxClient,
    ExecChunk,
    GatewayError,
    Page,
    SandboxError,
)
from openshell._proto import datamodel_pb2 as dm
from openshell._proto import openshell_pb2 as pb
from openshell._proto import openshell_pb2_grpc as rpc


class Gateway(rpc.OpenShellServicer):
    def __init__(self):
        self.requests = []
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()

    async def GetSandbox(self, request, context):
        self.requests.append((request, context.invocation_metadata()))
        if request.name == "missing":
            await context.abort(grpc.StatusCode.NOT_FOUND, "missing sandbox")
        if request.name == "blocked":
            self.started.set()
            try:
                await asyncio.Future()
            finally:
                self.cancelled.set()
        return pb.SandboxResponse(
            sandbox=pb.Sandbox(
                metadata=dm.ObjectMeta(
                    id="identity",
                    name=request.name,
                    workspace=request.workspace_scope.workspace,
                ),
                status=pb.SandboxStatus(phase=pb.SANDBOX_PHASE_READY, exit_code=0),
            )
        )

    async def CreateSandbox(self, request, context):
        self.requests.append((request, context.invocation_metadata()))
        return pb.SandboxResponse(
            sandbox=pb.Sandbox(metadata=dm.ObjectMeta(id="created", name=request.name))
        )

    async def ListSandboxes(self, request, context):
        self.requests.append((request, context.invocation_metadata()))
        return pb.ListSandboxesResponse(
            sandboxes=[
                pb.Sandbox(metadata=dm.ObjectMeta(name=request.page_token or "first"))
            ],
            next_page_token="second" if not request.page_token else "",
        )

    async def ExecSandbox(self, request, context):
        self.requests.append((request, context.invocation_metadata()))
        event = pb.ExecSandboxEvent()
        event.stdout.data = b"hello"
        yield event
        if request.command == ["blocked"]:
            self.started.set()
            try:
                await asyncio.Future()
            finally:
                self.cancelled.set()
        event = pb.ExecSandboxEvent()
        event.exit.exit_code = 0
        yield event

    async def ExposeService(self, request, context):
        self.requests.append((request, context.invocation_metadata()))
        return pb.ServiceEndpointResponse(
            endpoint=pb.ServiceEndpoint(
                name=request.name,
                sandbox=request.sandbox,
                target_port=request.target_port,
                authorization_mode=request.authorization_mode,
            ),
            url="https://service.example/",
        )

    async def GetService(self, request, context):
        self.requests.append((request, context.invocation_metadata()))
        return pb.ServiceEndpointResponse(
            endpoint=pb.ServiceEndpoint(name=request.name),
            url="https://service.example/",
        )

    async def ListServices(self, request, context):
        self.requests.append((request, context.invocation_metadata()))
        return pb.ListServicesResponse(
            services=[
                pb.ServiceEndpointResponse(
                    endpoint=pb.ServiceEndpoint(name=request.page_token or "first")
                )
            ],
            next_page_token="second" if not request.page_token else "",
        )

    async def DeleteService(self, request, context):
        self.requests.append((request, context.invocation_metadata()))
        return pb.DeleteServiceResponse(outcome=pb.DELETION_OUTCOME_ALREADY_ABSENT)

    async def GetSandboxLogs(self, request, context):
        self.requests.append((request, context.invocation_metadata()))
        return pb.GetSandboxLogsResponse(
            logs=[
                pb.SandboxLogLine(
                    message="denied", fields={"action": "deny"}, source="sandbox"
                )
            ],
            buffer_total=42,
        )


@asynccontextmanager
async def gateway():
    service = Gateway()
    server = grpc.aio.server()
    rpc.add_OpenShellServicer_to_server(service, server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    try:
        yield (service, f"127.0.0.1:{port}")
    finally:
        await server.stop(0)


async def test_async_lifecycle_pagination_exec_and_auth():
    async with (
        gateway() as (service, target),
        AsyncSandboxClient(target, bearer_token="test-token") as client,
    ):
        sandbox = await client.get("worker", workspace="team")
        assert sandbox.workspace == "team"
        assert sandbox.status.exit_code == 0
        created = await client.create(
            name="new", workspace="team", request_id="request-1"
        )
        assert created.id == "created"
        assert service.requests[-1][0].request_id == "request-1"
        pages = client.list(workspace="team", label_selector="owner=helix")
        assert isinstance(pages, AsyncPager)
        assert [item.name for item in await pages.all()] == ["first", "second"]
        result = await client.exec("worker", ["echo"], workspace="team")
        assert result.stdout == "hello"
        assert result.exit_code == 0
        for _, metadata in service.requests:
            assert ("authorization", "Bearer test-token") in metadata


async def test_errors_deadlines_and_cancellation():
    async with gateway() as (service, target), AsyncSandboxClient(target) as client:
        with pytest.raises(GatewayError) as failure:
            await client.get("missing", workspace="team")
        assert failure.value.code() == grpc.StatusCode.NOT_FOUND
        with pytest.raises(GatewayError) as failure:
            await client.get("blocked", workspace="team", timeout=0.05)
        assert failure.value.code() == grpc.StatusCode.DEADLINE_EXCEEDED
        await asyncio.wait_for(service.cancelled.wait(), 2)
        service.started.clear()
        service.cancelled.clear()
        task = asyncio.create_task(client.get("blocked", workspace="team"))
        await asyncio.wait_for(service.started.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(service.cancelled.wait(), 2)
        assert (await client.get("healthy", workspace="team")).name == "healthy"


async def test_stream_close_cancels_rpc():
    async with (
        gateway() as (service, target),
        AsyncSandboxClient(target, bearer_token="stream-token") as client,
    ):
        stream = client.exec_stream("worker", ["blocked"], workspace="team")
        chunk = await anext(stream)
        assert isinstance(chunk, ExecChunk)
        assert chunk.data == b"hello"
        await asyncio.wait_for(service.started.wait(), 2)
        await stream.aclose()
        await asyncio.wait_for(service.cancelled.wait(), 2)


async def test_borrowed_channel_remains_open():
    async with gateway() as (_, target), grpc.aio.insecure_channel(target) as channel:
        async with AsyncSandboxClient.from_channel(channel) as client:
            assert (await client.get("worker", workspace="team")).name == "worker"
        response = await rpc.OpenShellStub(channel).GetSandbox(
            pb.GetSandboxRequest(name="after-close")
        )
        assert response.sandbox.metadata.name == "after-close"


async def test_blocking_token_provider_does_not_block_loop():
    entered = threading.Event()
    release = threading.Event()

    def token():
        entered.set()
        assert release.wait(5)
        return "refreshed"

    async with (
        gateway() as (service, target),
        AsyncSandboxClient(target, bearer_token=token) as client,
    ):
        pending = asyncio.create_task(client.get("worker", workspace="team"))
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            await asyncio.wait_for(asyncio.sleep(0), 0.5)
        finally:
            release.set()
        await pending
        assert ("authorization", "Bearer refreshed") in service.requests[0][1]


async def test_pager_rejects_repeated_tokens():
    async def fetch(token):
        return Page([token], "again")

    pager = AsyncPager(fetch)
    await anext(pager)
    with pytest.raises(SandboxError, match="repeated"):
        await anext(pager)


def test_async_methods_are_real_coroutines():
    from unittest.mock import AsyncMock, create_autospec

    assert inspect.iscoroutinefunction(AsyncSandboxClient.create)
    assert not inspect.iscoroutinefunction(AsyncSandboxClient.list)
    client = create_autospec(AsyncSandboxClient, instance=True)
    assert isinstance(client.create, AsyncMock)


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_services_logs_and_session_scope(asynchronous):
    from datetime import UTC, datetime

    from openshell import DeletionOutcome, SandboxClient, ServiceAuthorizationMode

    async with gateway() as (service, target):
        client = AsyncSandboxClient(target) if asynchronous else SandboxClient(target)

        async def invoke(method, *args, **kwargs):
            if asynchronous:
                return await method(*args, **kwargs)
            return await asyncio.to_thread(method, *args, **kwargs)

        try:
            session = await invoke(client.get_session, "worker", workspace="team")
            endpoint = await invoke(
                session.expose_service,
                name="api",
                target_port=8080,
                authorization_mode=ServiceAuthorizationMode.BEARER_PASSTHROUGH,
                request_id="expose-1",
            )
            assert endpoint.url == "https://service.example/"
            request = service.requests[-1][0]
            assert request.workspace_scope.workspace == "team"
            assert request.sandbox == "worker"
            assert request.request_id == "expose-1"
            assert (
                endpoint.endpoint.authorization_mode
                == pb.SERVICE_AUTHORIZATION_MODE_BEARER_PASSTHROUGH
            )
            assert (
                await invoke(session.get_service, name="api")
            ).endpoint.name == "api"
            endpoints = await invoke(session.list_all_services)
            assert [item.endpoint.name for item in endpoints] == ["first", "second"]
            result = await invoke(
                session.delete_service,
                name="api",
                allow_missing=True,
                request_id="delete-1",
            )
            assert result.outcome == DeletionOutcome.ALREADY_ABSENT
            since = datetime(2026, 1, 1, tzinfo=UTC)
            logs = await invoke(
                session.get_logs,
                lines=10,
                since=since,
                sources=["sandbox"],
                min_level="WARN",
            )
            assert logs.buffer_total == 42
            assert logs.logs[0].fields["action"] == "deny"
            assert service.requests[-1][0].since_time.ToDatetime(tzinfo=UTC) == since
            with pytest.raises(ValueError, match="timezone-aware"):
                await invoke(session.get_logs, since=datetime(2026, 1, 1))
        finally:
            await invoke(client.close)
