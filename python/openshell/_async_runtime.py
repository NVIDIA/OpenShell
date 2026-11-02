# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Native asyncio transport and iteration for the generated async clients."""

from __future__ import annotations

import asyncio
import contextlib
import time
from typing import TYPE_CHECKING, Generic, Self, TypeVar

import grpc
import grpc.aio

from ._proto import openshell_pb2, openshell_pb2_grpc
from .errors import from_grpc_error
from .sandbox import (
    _OWNER_REPLICA_HEADER,
    _OWNER_REQUEST_HEADER,
    _ROUTE_REPLICA_HEADER,
    ClientCredentialsAuth,
    Page,
    Pager,
    SandboxError,
    TlsConfig,
    _get_sandbox_request,
    _is_local_grpc_endpoint,
    _normalize_bearer,
    _OwnerCache,
    _retry_unrouted,
)

T = TypeVar("T")

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


async def _await_rpc(call: Awaitable[T]) -> T:
    try:
        return await call
    except grpc.RpcError as error:
        raise from_grpc_error(error) from error


class AsyncPager(Generic[T]):
    """Lazy, single-pass async pages with the same token guards as ``Pager``.

    A pager must have only one consumer. Cancellation leaves the current token
    available for an explicit retry; no page is prefetched or retried implicitly.
    """

    def __init__(
        self, fetch: Callable[[str], Awaitable[Page[T]]], page_token: str = ""
    ) -> None:
        self._fetch = fetch
        # Reuse the sync pager's bounded token accounting, not its I/O.
        self._state: Pager[T] = Pager(lambda _: Page([], ""), page_token)
        self._busy = False

    def __aiter__(self) -> AsyncPager[T]:
        return self

    async def __anext__(self) -> Page[T]:
        if self._busy:
            raise RuntimeError("an AsyncPager cannot have concurrent consumers")
        state = self._state
        if state._page_token is None:
            raise StopAsyncIteration
        token = state._page_token
        token_bytes = state._validate_page_token_budget(token)
        self._busy = True
        try:
            page = await self._fetch(token)
            if token:
                state._consumed_page_tokens.add(token)
                state._consumed_page_token_bytes += token_bytes
            if (
                page.next_page_token
                and page.next_page_token in state._consumed_page_tokens
            ):
                raise SandboxError("pager received a repeated continuation token")
            state._page_token = page.next_page_token or None
            return page
        finally:
            self._busy = False

    async def all(self) -> list[T]:
        """Collect every remaining page into memory."""
        return [item async for page in self for item in page.items]


class _AsyncBearer:
    """Run the existing locked refresh providers off the event loop.

    Keep worker tasks alive across caller cancellation so close can wait before
    disposing an owned refresher. Providers retain their existing single-flight
    refresh and cross-process rotated-token persistence semantics.
    """

    def __init__(self, provider: Callable[[], str]) -> None:
        self._provider = provider
        self._pending: set[asyncio.Task[str]] = set()

    async def details(self, details: grpc.aio.ClientCallDetails):
        start = time.monotonic()
        task = asyncio.create_task(asyncio.to_thread(self._provider))
        self._pending.add(task)
        task.add_done_callback(self._finished)
        try:
            token = await asyncio.wait_for(asyncio.shield(task), details.timeout)
        except TimeoutError as error:
            raise grpc.aio.AioRpcError(
                grpc.StatusCode.DEADLINE_EXCEEDED,
                grpc.aio.Metadata(),
                grpc.aio.Metadata(),
                "deadline exceeded while obtaining bearer credentials",
            ) from error
        timeout = details.timeout
        if timeout is not None:
            timeout = max(0.0, timeout - (time.monotonic() - start))
        return grpc.aio.ClientCallDetails(
            details.method,
            timeout,
            grpc.aio.Metadata(
                *tuple(details.metadata or ()), ("authorization", f"Bearer {token}")
            ),
            details.credentials,
            details.wait_for_ready,
        )

    def _finished(self, task: asyncio.Task[str]) -> None:
        self._pending.discard(task)
        if not task.cancelled():
            task.exception()  # Retrieve failures when the requesting task was cancelled.

    async def drain(self) -> None:
        if self._pending:
            await asyncio.gather(*self._pending, return_exceptions=True)


class _UnaryAuth(grpc.aio.UnaryUnaryClientInterceptor):
    def __init__(self, auth: _AsyncBearer) -> None:
        self._auth = auth

    async def intercept_unary_unary(self, continuation, client_call_details, request):
        return await continuation(
            await self._auth.details(client_call_details), request
        )


class _StreamAuth(grpc.aio.UnaryStreamClientInterceptor):
    def __init__(self, auth: _AsyncBearer) -> None:
        self._auth = auth

    async def intercept_unary_stream(self, continuation, client_call_details, request):
        return await continuation(
            await self._auth.details(client_call_details), request
        )


class _BidiAuth(grpc.aio.StreamStreamClientInterceptor):
    def __init__(self, auth: _AsyncBearer) -> None:
        self._auth = auth

    async def intercept_stream_stream(
        self, continuation, client_call_details, request_iterator
    ):
        return await continuation(
            await self._auth.details(client_call_details), request_iterator
        )


class AsyncTransport:
    """Transport owned by AsyncSandboxClient; construct on its event loop."""

    def __init__(
        self,
        endpoint: str,
        *,
        tls: TlsConfig | None = None,
        bearer_token: str | Callable[[], str] | None = None,
        client_credentials: ClientCredentialsAuth | None = None,
        timeout: float = 30.0,
        cluster_name: str | None = None,
        _bearer_close: Callable[[], None] | None = None,
    ) -> None:
        if bearer_token is not None and client_credentials is not None:
            raise SandboxError(
                "bearer_token and client_credentials are mutually exclusive"
            )
        if (
            client_credentials is not None
            and tls is None
            and not _is_local_grpc_endpoint(endpoint)
        ):
            raise SandboxError(
                "OAuth client credentials require TLS for non-loopback gateway endpoints"
            )
        self._timeout = timeout
        self._endpoint = endpoint
        self._cluster_name = cluster_name
        self._bearer_close = _bearer_close
        self._owns_channel = True
        self._close_task: asyncio.Task[None] | None = None
        provider = _normalize_bearer(client_credentials or bearer_token)
        self._auth = _AsyncBearer(provider) if provider is not None else None
        # aio registers multi-interface interceptors under only their first
        # matching interface, so use a separate object for each RPC shape.
        interceptors = (
            [_UnaryAuth(self._auth), _StreamAuth(self._auth), _BidiAuth(self._auth)]
            if self._auth is not None
            else []
        )
        if tls is None:
            self._channel = grpc.aio.insecure_channel(
                endpoint, interceptors=interceptors
            )
        else:
            credentials = grpc.ssl_channel_credentials(
                root_certificates=tls.ca_path.read_bytes() if tls.ca_path else None,
                private_key=tls.key_path.read_bytes() if tls.key_path else None,
                certificate_chain=tls.cert_path.read_bytes() if tls.cert_path else None,
            )
            self._channel = grpc.aio.secure_channel(
                endpoint, credentials, interceptors=interceptors
            )
        self._stub = openshell_pb2_grpc.OpenShellStub(self._channel)
        self._owners = _OwnerCache()

    @classmethod
    def from_channel(cls, channel: grpc.aio.Channel, *, timeout: float = 30.0) -> Self:
        """Borrow a caller-configured channel; closing the client leaves it open."""
        client = cls.__new__(cls)
        client._channel = channel
        client._stub = openshell_pb2_grpc.OpenShellStub(channel)
        client._timeout = timeout
        client._owns_channel = False
        client._bearer_close = None
        client._auth = None
        client._close_task = None
        client._owners = _OwnerCache()
        return client

    async def _owner_of(self, workspace: str, sandbox: str, timeout: float) -> str:
        owner = self._owners.get(workspace, sandbox)
        if owner is not None:
            return owner
        call = self._stub.GetSandbox(
            _get_sandbox_request(sandbox, workspace),
            timeout=timeout,
            metadata=((_OWNER_REQUEST_HEADER, "1"),),
        )
        try:
            await call
            metadata = await call.initial_metadata()
        except grpc.RpcError:
            return ""
        value = dict(tuple(metadata or ())).get(_OWNER_REPLICA_HEADER)
        owner = value if isinstance(value, str) else ""
        self._owners.put(workspace, sandbox, owner)
        return owner

    async def _open_exec(
        self, request: openshell_pb2.ExecSandboxRequest, workspace: str, timeout: float
    ):
        deadline = time.monotonic() + timeout
        owner = await self._owner_of(workspace, request.sandbox, timeout)
        if owner:
            events = self._stub.ExecSandbox(
                request,
                timeout=max(0.0, deadline - time.monotonic()),
                metadata=((_ROUTE_REPLICA_HEADER, owner),),
            )
            try:
                try:
                    first = await anext(events.__aiter__(), None)
                except grpc.RpcError as error:
                    if not _retry_unrouted(error):
                        raise
                    self._owners.forget(workspace, request.sandbox)
                else:
                    if first is not None:
                        yield first
                    async for event in events:
                        yield event
                    return
            finally:
                events.cancel()
        events = self._stub.ExecSandbox(
            request, timeout=max(0.0, deadline - time.monotonic())
        )
        try:
            async for event in events:
                yield event
        finally:
            events.cancel()

    async def _close(self) -> None:
        if self._owns_channel:
            await self._channel.close()
        if self._auth is not None:
            await self._auth.drain()
        if self._bearer_close is not None:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(self._bearer_close)
            self._bearer_close = None

    async def close(self) -> None:
        """Close owned resources once, even if the caller is cancelled."""
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close())
        await asyncio.shield(self._close_task)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()
