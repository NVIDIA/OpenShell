# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import grpc
import grpc.aio
import pytest

if TYPE_CHECKING:
    from pathlib import Path

from openshell._proto import datamodel_pb2, openshell_pb2
from openshell.sandbox import (
    _PYTHON_CLOUDPICKLE_BOOTSTRAP,
    _SANDBOX_PYTHON_BIN,
    AsyncInferenceRouteClient,
    AsyncSandbox,
    AsyncSandboxClient,
    AsyncSandboxSession,
    AsyncWorkspaceClient,
    ExecResult,
    SandboxError,
    SandboxRef,
    SandboxStatusRef,
    _AsyncBearerUnaryStreamInterceptor,
    _AsyncBearerUnaryUnaryInterceptor,
)


async def _aiter(items: list[Any]) -> Any:
    for item in items:
        yield item


def _async_client_with_fake_stub(stub: object) -> AsyncSandboxClient:
    client = cast("AsyncSandboxClient", object.__new__(AsyncSandboxClient))
    client._timeout = 30.0
    client._stub = cast("Any", stub)
    return client


def _make_sandbox_proto(
    id_: str,
    name: str,
    labels: dict[str, str] | None = None,
    phase: openshell_pb2.SandboxPhase = openshell_pb2.SANDBOX_PHASE_READY,
    version: int = 0,
    workspace: str = "default",
) -> openshell_pb2.Sandbox:
    sandbox = openshell_pb2.Sandbox()
    sandbox.metadata.id = id_
    sandbox.metadata.name = name
    sandbox.metadata.workspace = workspace
    for key, value in (labels or {}).items():
        sandbox.metadata.labels[key] = value
    sandbox.status.phase = phase
    sandbox.status.current_policy_version = version
    return sandbox


class _FakeAsyncExecStub:
    def __init__(self, events: list[openshell_pb2.ExecSandboxEvent] | None = None):
        self.request: openshell_pb2.ExecSandboxRequest | None = None
        self._events = events or [
            openshell_pb2.ExecSandboxEvent(
                exit=openshell_pb2.ExecSandboxExit(exit_code=0)
            )
        ]

    def ExecSandbox(
        self,
        request: openshell_pb2.ExecSandboxRequest,
        timeout: float | None = None,
    ) -> Any:
        self.request = request
        _ = timeout
        return _aiter(list(self._events))


class _FakeAsyncInferenceStub:
    def __init__(self) -> None:
        self.request: Any = None

    async def SetInferenceRoute(
        self, request: Any, timeout: float | None = None
    ) -> Any:
        self.request = request
        _ = timeout
        return SimpleNamespace(
            provider_name=request.provider_name,
            model_id=request.model_id,
            version=1,
        )

    async def GetInferenceRoute(
        self, request: Any, timeout: float | None = None
    ) -> Any:
        self.request = request
        _ = timeout
        return SimpleNamespace(
            provider_name="openai-dev",
            model_id="gpt-4.1",
            version=2,
        )

    async def DeleteInferenceRoute(
        self, request: Any, timeout: float | None = None
    ) -> Any:
        self.request = request
        _ = timeout
        return SimpleNamespace(deleted=True)


class _FakeAsyncSandboxStub:
    def __init__(self, listed: list[openshell_pb2.Sandbox] | None = None) -> None:
        self.create_request: openshell_pb2.CreateSandboxRequest | None = None
        self.list_request: openshell_pb2.ListSandboxesRequest | None = None
        self.delete_request: openshell_pb2.DeleteSandboxRequest | None = None
        self.health_calls = 0
        self._listed = listed or []

    async def CreateSandbox(
        self,
        request: openshell_pb2.CreateSandboxRequest,
        timeout: float | None = None,
    ) -> Any:
        self.create_request = request
        _ = timeout
        return SimpleNamespace(
            sandbox=_make_sandbox_proto(
                "sandbox-1",
                request.name or "generated",
                dict(request.labels),
                workspace=request.workspace,
            )
        )

    async def ListSandboxes(
        self,
        request: openshell_pb2.ListSandboxesRequest,
        timeout: float | None = None,
    ) -> Any:
        self.list_request = request
        _ = timeout
        return SimpleNamespace(sandboxes=list(self._listed))

    async def DeleteSandbox(
        self,
        request: openshell_pb2.DeleteSandboxRequest,
        timeout: float | None = None,
    ) -> Any:
        self.delete_request = request
        _ = timeout
        return SimpleNamespace(deleted=True)

    async def Health(self, request: Any, timeout: float | None = None) -> Any:
        self.health_calls += 1
        _ = (request, timeout)
        return openshell_pb2.HealthResponse()


class _FakeAsyncWorkspaceStub:
    def __init__(self) -> None:
        self.request: Any = None

    @staticmethod
    def _workspace(name: str, labels: dict[str, str] | None = None) -> Any:
        workspace = datamodel_pb2.Workspace()
        workspace.metadata.name = name
        workspace.metadata.labels.update(labels or {})
        workspace.status.phase = datamodel_pb2.WORKSPACE_PHASE_ACTIVE
        return workspace

    async def CreateWorkspace(self, request: Any, timeout: float | None = None) -> Any:
        self.request = request
        _ = timeout
        return SimpleNamespace(
            workspace=self._workspace(request.name, dict(request.labels))
        )

    async def ListWorkspaces(self, request: Any, timeout: float | None = None) -> Any:
        self.request = request
        _ = timeout
        return SimpleNamespace(workspaces=[self._workspace("staging")])

    async def DeleteWorkspace(self, request: Any, timeout: float | None = None) -> Any:
        self.request = request
        _ = timeout
        return SimpleNamespace(deleted=True)


# ---------------------------------------------------------------------------
# exec / exec_python
# ---------------------------------------------------------------------------


async def test_async_exec_sends_stdin_payload() -> None:
    stub = _FakeAsyncExecStub()
    client = _async_client_with_fake_stub(stub)

    result = await client.exec(
        "sandbox-1", ["python", "-c", "print('ok')"], stdin=b"payload"
    )

    assert result.exit_code == 0
    assert stub.request is not None
    assert stub.request.stdin == b"payload"


async def test_async_exec_python_serializes_callable_payload() -> None:
    stub = _FakeAsyncExecStub()
    client = _async_client_with_fake_stub(stub)

    def add(a: int, b: int) -> int:
        return a + b

    result = await client.exec_python("sandbox-1", add, args=(2, 3))

    assert result.exit_code == 0
    assert stub.request is not None
    assert stub.request.command == [
        _SANDBOX_PYTHON_BIN,
        "-c",
        _PYTHON_CLOUDPICKLE_BOOTSTRAP,
    ]
    assert stub.request.environment["OPENSHELL_PYFUNC_B64"]
    assert stub.request.stdin == b""


async def test_async_exec_stream_yields_chunks_then_result() -> None:
    stub = _FakeAsyncExecStub(
        events=[
            openshell_pb2.ExecSandboxEvent(
                stdout=openshell_pb2.ExecSandboxStdout(data=b"out")
            ),
            openshell_pb2.ExecSandboxEvent(
                stderr=openshell_pb2.ExecSandboxStderr(data=b"err")
            ),
            openshell_pb2.ExecSandboxEvent(
                exit=openshell_pb2.ExecSandboxExit(exit_code=7)
            ),
        ]
    )
    client = _async_client_with_fake_stub(stub)

    items = [item async for item in client.exec_stream("sandbox-1", ["ls"])]

    result = items[-1]
    assert isinstance(result, ExecResult)
    assert result.exit_code == 7
    assert result.stdout == "out"
    assert result.stderr == "err"


async def test_async_exec_stream_rejects_empty_command() -> None:
    client = _async_client_with_fake_stub(_FakeAsyncExecStub())

    with pytest.raises(SandboxError, match="command must not be empty"):
        [item async for item in client.exec_stream("sandbox-1", [])]


# ---------------------------------------------------------------------------
# Bearer auth interceptor (async twin)
# ---------------------------------------------------------------------------


def test_async_bearer_interceptor_attaches_authorization_header() -> None:
    interceptor = _AsyncBearerUnaryUnaryInterceptor(lambda: "secret-token")
    details = grpc.aio.ClientCallDetails(
        method="/Test/Method",
        timeout=None,
        metadata=grpc.aio.Metadata(("x-existing", "yes")),
        credentials=None,
        wait_for_ready=None,
    )

    new_details = interceptor._attach(details)
    assert new_details.metadata is not None
    md = list(new_details.metadata)

    assert ("x-existing", "yes") in md
    assert ("authorization", "Bearer secret-token") in md


def test_async_bearer_interceptor_handles_empty_metadata() -> None:
    interceptor = _AsyncBearerUnaryStreamInterceptor(lambda: "t")
    details = grpc.aio.ClientCallDetails(
        method="/Test/Method",
        timeout=None,
        metadata=None,
        credentials=None,
        wait_for_ready=None,
    )

    new_details = interceptor._attach(details)

    assert new_details.metadata is not None
    assert list(new_details.metadata) == [("authorization", "Bearer t")]


async def test_async_bearer_interceptor_awaits_continuation() -> None:
    interceptor = _AsyncBearerUnaryUnaryInterceptor(lambda: "tok")
    captured: dict[str, Any] = {}

    async def continuation(details: Any, request: Any) -> str:
        captured["details"] = details
        captured["request"] = request
        return "result"

    details = grpc.aio.ClientCallDetails(
        method="/Test/Method",
        timeout=None,
        metadata=None,
        credentials=None,
        wait_for_ready=None,
    )
    result = await interceptor.intercept_unary_unary(continuation, details, "payload")

    assert result == "result"
    assert ("authorization", "Bearer tok") in list(captured["details"].metadata)
    assert captured["request"] == "payload"


def test_async_bearer_interceptor_calls_provider_per_request() -> None:
    tokens = iter(["t1", "t2", "t3"])
    interceptor = _AsyncBearerUnaryUnaryInterceptor(lambda: next(tokens))
    seen: list[str] = []

    for _ in range(3):
        details = grpc.aio.ClientCallDetails(
            method="/m",
            timeout=None,
            metadata=None,
            credentials=None,
            wait_for_ready=None,
        )
        attached = interceptor._attach(details)
        assert attached.metadata is not None
        for key, value in attached.metadata:
            if key == "authorization":
                assert isinstance(value, str)
                seen.append(value)

    assert seen == ["Bearer t1", "Bearer t2", "Bearer t3"]


# ---------------------------------------------------------------------------
# from_active_cluster: gateway resolution shared with the sync client
# ---------------------------------------------------------------------------


def _setup_gateway_dir(
    tmp_path: Path,
    monkeypatch: Any,
    *,
    name: str = "g",
    endpoint: str = "http://127.0.0.1:8080",
    auth_mode: str | None = None,
    mtls_files: dict[str, str] | None = None,
    oidc_bundle: dict | None = None,
) -> Path:
    gateway_dir = tmp_path / "openshell" / "gateways" / name
    gateway_dir.mkdir(parents=True)
    (tmp_path / "openshell" / "active_gateway").write_text(name)
    meta: dict[str, Any] = {"gateway_endpoint": endpoint}
    if auth_mode is not None:
        meta["auth_mode"] = auth_mode
    (gateway_dir / "metadata.json").write_text(json.dumps(meta))
    if mtls_files:
        mtls_dir = gateway_dir / "mtls"
        mtls_dir.mkdir()
        for fname, body in mtls_files.items():
            (mtls_dir / fname).write_text(body)
    if oidc_bundle is not None:
        (gateway_dir / "oidc_token.json").write_text(json.dumps(oidc_bundle))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("OPENSHELL_GATEWAY", raising=False)
    return gateway_dir


def _bearer_interceptor_count(channel: Any) -> int:
    """Count bearer interceptors across all four grpc.aio call categories.

    grpc.aio sorts interceptors into per-call-type buckets, so an OIDC
    client should register exactly one interceptor in each of the four."""
    total = 0
    for attr in (
        "_unary_unary_interceptors",
        "_unary_stream_interceptors",
        "_stream_unary_interceptors",
        "_stream_stream_interceptors",
    ):
        total += len(getattr(channel, attr, []))
    return total


async def test_async_from_active_cluster_reads_gateway_metadata_layout(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    gateway_name = "test-gateway"
    gateway_dir = tmp_path / "openshell" / "gateways" / gateway_name
    mtls_dir = gateway_dir / "mtls"
    mtls_dir.mkdir(parents=True)
    (tmp_path / "openshell" / "active_gateway").write_text(gateway_name)
    (gateway_dir / "metadata.json").write_text(
        json.dumps({"gateway_endpoint": "https://127.0.0.1:8443"})
    )
    (mtls_dir / "ca.crt").write_text("ca")
    (mtls_dir / "tls.crt").write_text("cert")
    (mtls_dir / "tls.key").write_text("key")

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("OPENSHELL_GATEWAY", raising=False)

    client = AsyncSandboxClient.from_active_cluster()
    try:
        assert client._cluster_name == gateway_name
        assert client._endpoint == "127.0.0.1:8443"
    finally:
        await client.close()


async def test_async_from_active_cluster_prefers_openshell_gateway_env(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    gateway_name = "env-gateway"
    gateway_dir = tmp_path / "openshell" / "gateways" / gateway_name
    mtls_dir = gateway_dir / "mtls"
    mtls_dir.mkdir(parents=True)
    (gateway_dir / "metadata.json").write_text(
        json.dumps({"gateway_endpoint": "https://127.0.0.1:8443"})
    )
    (mtls_dir / "ca.crt").write_text("ca")
    (mtls_dir / "tls.crt").write_text("cert")
    (mtls_dir / "tls.key").write_text("key")

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("OPENSHELL_GATEWAY", gateway_name)

    client = AsyncSandboxClient.from_active_cluster()
    try:
        assert client._cluster_name == gateway_name
    finally:
        await client.close()


async def test_async_from_active_cluster_loads_bearer_when_auth_mode_is_oidc(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    _setup_gateway_dir(
        tmp_path,
        monkeypatch,
        auth_mode="oidc",
        oidc_bundle={"access_token": "from-disk"},
    )
    client = AsyncSandboxClient.from_active_cluster()
    try:
        # One bearer interceptor per call category so streaming exec is
        # authenticated too.
        assert _bearer_interceptor_count(client._channel) == 4
    finally:
        await client.close()


async def test_async_from_active_cluster_ignores_stale_token_when_not_oidc(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    _setup_gateway_dir(
        tmp_path,
        monkeypatch,
        oidc_bundle={"access_token": "stale-from-disk"},
    )
    client = AsyncSandboxClient.from_active_cluster()
    try:
        assert _bearer_interceptor_count(client._channel) == 0
    finally:
        await client.close()


async def test_async_from_active_cluster_https_oidc_without_mtls_uses_tls(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    _setup_gateway_dir(
        tmp_path,
        monkeypatch,
        endpoint="https://gateway.example:443",
        auth_mode="oidc",
        oidc_bundle={"access_token": "t"},
    )
    client = AsyncSandboxClient.from_active_cluster()
    try:
        assert client._endpoint == "gateway.example:443"
        assert _bearer_interceptor_count(client._channel) == 4
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# CRUD surface: create / list / delete / health
# ---------------------------------------------------------------------------


async def test_async_create_forwards_name_and_labels() -> None:
    stub = _FakeAsyncSandboxStub()
    client = _async_client_with_fake_stub(stub)

    ref = await client.create(
        workspace="default",
        name="job-1",
        labels={"aiq": "deep-research"},
    )

    assert stub.create_request is not None
    assert stub.create_request.name == "job-1"
    assert stub.create_request.workspace == "default"
    assert dict(stub.create_request.labels) == {"aiq": "deep-research"}
    assert dict(ref.labels) == {"aiq": "deep-research"}


async def test_async_create_without_args_sends_empty_metadata() -> None:
    stub = _FakeAsyncSandboxStub()
    client = _async_client_with_fake_stub(stub)

    await client.create(workspace="default")

    assert stub.create_request is not None
    assert stub.create_request.name == ""
    assert dict(stub.create_request.labels) == {}


async def test_async_create_copies_caller_labels() -> None:
    stub = _FakeAsyncSandboxStub()
    client = _async_client_with_fake_stub(stub)

    caller_labels = {"aiq": "deep-research"}
    await client.create(workspace="default", labels=caller_labels)
    caller_labels["aiq"] = "mutated"

    assert stub.create_request is not None
    assert dict(stub.create_request.labels) == {"aiq": "deep-research"}


async def test_async_create_session_forwards_name_and_labels() -> None:
    stub = _FakeAsyncSandboxStub()
    client = _async_client_with_fake_stub(stub)

    session = await client.create_session(
        workspace="default", name="job-2", labels={"team": "aiq"}
    )

    assert isinstance(session, AsyncSandboxSession)
    assert stub.create_request is not None
    assert stub.create_request.name == "job-2"
    assert dict(stub.create_request.labels) == {"team": "aiq"}
    assert session.sandbox.name == "job-2"


async def test_async_session_delete_preserves_workspace() -> None:
    stub = _FakeAsyncSandboxStub()
    client = _async_client_with_fake_stub(stub)
    session = await client.create_session(workspace="staging", name="job-2")

    assert await session.delete() is True
    assert stub.delete_request is not None
    assert stub.delete_request.workspace == "staging"


async def test_async_list_forwards_label_selector() -> None:
    stub = _FakeAsyncSandboxStub()
    client = _async_client_with_fake_stub(stub)

    await client.list(workspace="default", label_selector="aiq=deep-research")

    assert stub.list_request is not None
    assert stub.list_request.workspace == "default"
    assert stub.list_request.label_selector == "aiq=deep-research"


async def test_async_list_without_selector_sends_empty_string() -> None:
    stub = _FakeAsyncSandboxStub()
    client = _async_client_with_fake_stub(stub)

    await client.list(workspace="default")

    assert stub.list_request is not None
    assert stub.list_request.label_selector == ""


async def test_async_list_for_all_workspaces_sets_flag() -> None:
    stub = _FakeAsyncSandboxStub()
    client = _async_client_with_fake_stub(stub)

    await client.list_for_all_workspaces()

    assert stub.list_request is not None
    assert stub.list_request.all_workspaces is True
    assert stub.list_request.workspace == ""


async def test_async_list_ids_forwards_label_selector() -> None:
    stub = _FakeAsyncSandboxStub(listed=[_make_sandbox_proto("sandbox-1", "job-1")])
    client = _async_client_with_fake_stub(stub)

    ids = await client.list_ids(workspace="default", label_selector="aiq=deep-research")

    assert stub.list_request is not None
    assert stub.list_request.label_selector == "aiq=deep-research"
    assert ids == ["sandbox-1"]


async def test_async_delete_returns_bool() -> None:
    stub = _FakeAsyncSandboxStub()
    client = _async_client_with_fake_stub(stub)

    assert await client.delete("job-1", workspace="default") is True
    assert stub.delete_request is not None
    assert stub.delete_request.name == "job-1"
    assert stub.delete_request.workspace == "default"


async def test_async_health_calls_stub() -> None:
    stub = _FakeAsyncSandboxStub()
    client = _async_client_with_fake_stub(stub)

    await client.health()

    assert stub.health_calls == 1


# ---------------------------------------------------------------------------
# wait_ready / wait_deleted
# ---------------------------------------------------------------------------


class _ReadyStub:
    def __init__(self, phase: openshell_pb2.SandboxPhase) -> None:
        self._phase = phase

    async def GetSandbox(self, request: Any, timeout: float | None = None) -> Any:
        _ = timeout
        return SimpleNamespace(
            sandbox=_make_sandbox_proto("sandbox-1", request.name, phase=self._phase)
        )


async def test_async_wait_ready_returns_when_ready() -> None:
    client = _async_client_with_fake_stub(_ReadyStub(openshell_pb2.SANDBOX_PHASE_READY))

    ref = await client.wait_ready("job-1", workspace="default", timeout_seconds=5)

    assert ref.status.phase == openshell_pb2.SANDBOX_PHASE_READY


async def test_async_wait_ready_raises_on_error_phase() -> None:
    client = _async_client_with_fake_stub(_ReadyStub(openshell_pb2.SANDBOX_PHASE_ERROR))

    with pytest.raises(SandboxError, match="error phase"):
        await client.wait_ready("job-1", workspace="default", timeout_seconds=5)


class _NotFoundStub:
    async def GetSandbox(self, request: Any, timeout: float | None = None) -> Any:
        _ = (request, timeout)
        raise grpc.aio.AioRpcError(
            grpc.StatusCode.NOT_FOUND,
            grpc.aio.Metadata(),
            grpc.aio.Metadata(),
            details="not found",
        )


async def test_async_wait_deleted_returns_on_not_found() -> None:
    client = _async_client_with_fake_stub(_NotFoundStub())

    # Should return promptly (no timeout) when the sandbox is already gone.
    await client.wait_deleted("job-1", workspace="default", timeout_seconds=5)


# ---------------------------------------------------------------------------
# Inference route client (async twin)
# ---------------------------------------------------------------------------


async def test_async_inference_set_route_forwards_workspace_and_no_verify() -> None:
    stub = _FakeAsyncInferenceStub()
    client = cast(
        "AsyncInferenceRouteClient", object.__new__(AsyncInferenceRouteClient)
    )
    client._timeout = 30.0
    client._stub = cast("Any", stub)

    await client.set_route(
        workspace="staging",
        provider_name="openai-dev",
        model_id="gpt-4.1",
        no_verify=True,
    )

    assert stub.request is not None
    assert stub.request.workspace == "staging"
    assert stub.request.no_verify is True


async def test_async_inference_get_and_delete_route_forward_workspace() -> None:
    stub = _FakeAsyncInferenceStub()
    client = cast(
        "AsyncInferenceRouteClient", object.__new__(AsyncInferenceRouteClient)
    )
    client._timeout = 30.0
    client._stub = cast("Any", stub)

    route = await client.get_route(workspace="staging")
    assert route.version == 2
    assert stub.request.workspace == "staging"

    assert await client.delete_route(workspace="staging", route_name="primary")
    assert stub.request.workspace == "staging"
    assert stub.request.route_name == "primary"


async def test_async_workspace_client_mirrors_lifecycle_operations() -> None:
    stub = _FakeAsyncWorkspaceStub()
    client = cast("AsyncWorkspaceClient", object.__new__(AsyncWorkspaceClient))
    client._timeout = 30.0
    client._stub = cast("Any", stub)

    created = await client.create("staging", labels={"team": "agents"})
    assert created.name == "staging"
    assert created.labels == {"team": "agents"}

    listed = await client.list(label_selector="team=agents")
    assert [workspace.name for workspace in listed] == ["staging"]
    assert stub.request.label_selector == "team=agents"

    assert await client.delete("staging") is True
    assert stub.request.name == "staging"


# ---------------------------------------------------------------------------
# Lifecycle: context manager, close, bearer_close
# ---------------------------------------------------------------------------


async def test_async_client_context_manager_returns_self() -> None:
    async with AsyncSandboxClient("localhost:8080") as client:
        assert isinstance(client, AsyncSandboxClient)


async def test_async_client_close_invokes_bearer_close() -> None:
    closed = [0]

    def bearer_close() -> None:
        closed[0] += 1

    client = AsyncSandboxClient(
        "localhost:8080",
        bearer_token="tok",
        _bearer_close=bearer_close,
    )
    await client.close()
    assert closed[0] == 1
    # close() is idempotent — re-invoking does not double-call.
    await client.close()
    assert closed[0] == 1


# ---------------------------------------------------------------------------
# High-level AsyncSandbox context manager
# ---------------------------------------------------------------------------


class _RecordingAsyncClient:
    def __init__(self) -> None:
        self.create_kwargs: dict[str, Any] | None = None
        self.closed = False

    async def create_session(
        self,
        *,
        workspace: str,
        spec: Any = None,
        name: str | None = None,
        labels: Any = None,
    ) -> Any:
        self.create_kwargs = {
            "workspace": workspace,
            "spec": spec,
            "name": name,
            "labels": labels,
        }
        return SimpleNamespace(
            sandbox=SimpleNamespace(name=name or "generated"),
            _workspace=workspace,
        )

    async def wait_ready(
        self,
        name: str,
        *,
        workspace: str,
        timeout_seconds: float = 300.0,
    ) -> SandboxRef:
        _ = timeout_seconds
        return SandboxRef(
            id="sandbox-1",
            name=name,
            workspace=workspace,
            status=SandboxStatusRef(phase=2, current_policy_version=0),
        )

    async def close(self) -> None:
        self.closed = True


async def test_async_sandbox_wrapper_forwards_auth_kwargs(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    class _Sentinel(Exception):
        pass

    def fake_from_active_cluster(**kwargs: Any) -> Any:
        captured.update(kwargs)
        raise _Sentinel

    monkeypatch.setattr(
        AsyncSandboxClient,
        "from_active_cluster",
        staticmethod(fake_from_active_cluster),
    )

    sandbox = AsyncSandbox(
        workspace="default",
        cluster="my-gw",
        timeout=42.0,
        auto_refresh=False,
        write_back=False,
        insecure=True,
    )

    with pytest.raises(_Sentinel):
        await sandbox.__aenter__()

    assert captured["cluster"] == "my-gw"
    assert captured["timeout"] == 42.0
    assert captured["auto_refresh"] is False
    assert captured["write_back"] is False
    assert captured["insecure"] is True


async def test_async_sandbox_wrapper_defaults_match(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    class _Sentinel(Exception):
        pass

    def fake_from_active_cluster(**kwargs: Any) -> Any:
        captured.update(kwargs)
        raise _Sentinel

    monkeypatch.setattr(
        AsyncSandboxClient,
        "from_active_cluster",
        staticmethod(fake_from_active_cluster),
    )

    with pytest.raises(_Sentinel):
        await AsyncSandbox(workspace="default").__aenter__()

    assert captured["auto_refresh"] is True
    assert captured["write_back"] is True
    assert captured["insecure"] is False


async def test_async_high_level_creation_forwards_name_and_labels(
    monkeypatch: Any,
) -> None:
    recording = _RecordingAsyncClient()
    monkeypatch.setattr(
        AsyncSandboxClient,
        "from_active_cluster",
        staticmethod(lambda **_kwargs: recording),
    )

    sandbox = AsyncSandbox(
        workspace="staging",
        name="job-1",
        labels={"aiq": "deep-research"},
        delete_on_exit=False,
    )
    await sandbox.__aenter__()
    try:
        assert recording.create_kwargs == {
            "workspace": "staging",
            "spec": None,
            "name": "job-1",
            "labels": {"aiq": "deep-research"},
        }
    finally:
        await sandbox.__aexit__(None, None, None)
    assert recording.closed is True


async def test_async_high_level_attach_rejects_name() -> None:
    sandbox = AsyncSandbox(
        workspace="default", sandbox="existing-sandbox", name="job-1"
    )

    with pytest.raises(SandboxError):
        await sandbox.__aenter__()


async def test_async_high_level_attach_rejects_labels() -> None:
    ref = SandboxRef(
        id="sandbox-1",
        name="existing",
        workspace="default",
        status=SandboxStatusRef(phase=2, current_policy_version=0),
    )
    sandbox = AsyncSandbox(
        workspace="default", sandbox=ref, labels={"aiq": "deep-research"}
    )

    with pytest.raises(SandboxError):
        await sandbox.__aenter__()
