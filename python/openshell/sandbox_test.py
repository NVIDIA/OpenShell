# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

from openshell._proto import inference_pb2, openshell_pb2
from openshell.sandbox import (
    _PYTHON_CLOUDPICKLE_BOOTSTRAP,
    _SANDBOX_PYTHON_BIN,
    InferenceRouteClient,
    SandboxClient,
)

if TYPE_CHECKING:
    from pathlib import Path


class _FakeStub:
    def __init__(self) -> None:
        self.request: openshell_pb2.ExecSandboxRequest | None = None

    def ExecSandbox(
        self,
        request: openshell_pb2.ExecSandboxRequest,
        timeout: float | None = None,
    ):
        self.request = request
        _ = timeout
        yield openshell_pb2.ExecSandboxEvent(
            exit=openshell_pb2.ExecSandboxExit(exit_code=0)
        )


class _FakeInferenceStub:
    def __init__(self) -> None:
        self.request = None
        self.sandbox_request = None
        self.get_sandbox_request = None
        self.clear_sandbox_request = None

    def SetClusterInference(self, request: Any, timeout: float | None = None) -> Any:
        self.request = request
        _ = timeout

        class _Response:
            provider_name = request.provider_name
            model_id = request.model_id
            version = 1
            route_name = request.route_name or "inference.local"
            timeout_secs = request.timeout_secs
            validation_performed = True
            validated_endpoints = (
                inference_pb2.ValidatedEndpoint(
                    url="mock://cluster",
                    protocol="openai_chat_completions",
                ),
            )

        return _Response()

    def SetSandboxInference(self, request: Any, timeout: float | None = None) -> Any:
        self.sandbox_request = request
        _ = timeout
        return inference_pb2.SetSandboxInferenceResponse(
            sandbox_id=request.sandbox_id,
            provider_name=request.provider_name,
            model_id=request.model_id,
            version=1,
            timeout_secs=request.timeout_secs,
            validation_performed=True,
            validated_endpoints=[
                inference_pb2.ValidatedEndpoint(
                    url="mock://sandbox",
                    protocol="openai_chat_completions",
                )
            ],
        )

    def GetSandboxInference(self, request: Any, timeout: float | None = None) -> Any:
        self.get_sandbox_request = request
        _ = timeout
        return inference_pb2.GetSandboxInferenceResponse(
            sandbox_id=request.sandbox_id,
            provider_name="openai-dev",
            model_id="gpt-4.1",
            version=2,
            timeout_secs=90,
        )

    def ClearSandboxInference(self, request: Any, timeout: float | None = None) -> Any:
        self.clear_sandbox_request = request
        _ = timeout
        return inference_pb2.ClearSandboxInferenceResponse(
            sandbox_id=request.sandbox_id,
            cleared=True,
        )


def _client_with_fake_stub(stub: _FakeStub) -> SandboxClient:
    client = cast("SandboxClient", object.__new__(SandboxClient))
    client._timeout = 30.0
    client._stub = cast("Any", stub)
    return client


def test_exec_sends_stdin_payload() -> None:
    stub = _FakeStub()
    client = _client_with_fake_stub(stub)

    result = client.exec("sandbox-1", ["python", "-c", "print('ok')"], stdin=b"payload")

    assert result.exit_code == 0
    assert stub.request is not None
    assert stub.request.stdin == b"payload"


def test_exec_python_serializes_callable_payload() -> None:
    stub = _FakeStub()
    client = _client_with_fake_stub(stub)

    def add(a: int, b: int) -> int:
        return a + b

    result = client.exec_python("sandbox-1", add, args=(2, 3))

    assert result.exit_code == 0
    assert stub.request is not None
    assert stub.request.command == [
        _SANDBOX_PYTHON_BIN,
        "-c",
        _PYTHON_CLOUDPICKLE_BOOTSTRAP,
    ]
    assert stub.request.environment["OPENSHELL_PYFUNC_B64"]
    assert stub.request.stdin == b""


def test_from_active_cluster_reads_gateway_metadata_layout(
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

    client = SandboxClient.from_active_cluster()
    try:
        assert client._cluster_name == gateway_name
    finally:
        client.close()


def test_from_active_cluster_prefers_openshell_gateway_env(
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

    client = SandboxClient.from_active_cluster()
    try:
        assert client._cluster_name == gateway_name
    finally:
        client.close()


def test_inference_set_cluster_forwards_no_verify_flag() -> None:
    stub = _FakeInferenceStub()
    client = cast("InferenceRouteClient", object.__new__(InferenceRouteClient))
    client._timeout = 30.0
    client._stub = cast("Any", stub)

    config = client.set_cluster(
        provider_name="openai-dev",
        model_id="gpt-4.1",
        no_verify=True,
        timeout_secs=120,
    )

    assert stub.request is not None
    assert stub.request.no_verify is True
    assert config.timeout_secs == 120
    assert config.validation_performed is True
    assert config.validated_endpoints[0].url == "mock://cluster"


def test_inference_set_sandbox_forwards_override_request() -> None:
    stub = _FakeInferenceStub()
    client = cast("InferenceRouteClient", object.__new__(InferenceRouteClient))
    client._timeout = 30.0
    client._stub = cast("Any", stub)

    config = client.set_sandbox(
        "sandbox-1",
        provider_name="openai-dev",
        model_id="gpt-4.1",
        no_verify=True,
        timeout_secs=120,
    )

    assert stub.sandbox_request is not None
    assert stub.sandbox_request.sandbox_id == "sandbox-1"
    assert stub.sandbox_request.provider_name == "openai-dev"
    assert stub.sandbox_request.model_id == "gpt-4.1"
    assert stub.sandbox_request.no_verify is True
    assert config.sandbox_id == "sandbox-1"
    assert config.provider_name == "openai-dev"
    assert config.model_id == "gpt-4.1"
    assert config.timeout_secs == 120
    assert config.validation_performed is True
    assert config.validated_endpoints[0].url == "mock://sandbox"


def test_inference_get_sandbox_forwards_override_request() -> None:
    stub = _FakeInferenceStub()
    client = cast("InferenceRouteClient", object.__new__(InferenceRouteClient))
    client._timeout = 30.0
    client._stub = cast("Any", stub)

    config = client.get_sandbox("sandbox-1")

    assert stub.get_sandbox_request is not None
    assert stub.get_sandbox_request.sandbox_id == "sandbox-1"
    assert config.sandbox_id == "sandbox-1"
    assert config.provider_name == "openai-dev"
    assert config.model_id == "gpt-4.1"
    assert config.version == 2
    assert config.timeout_secs == 90


def test_inference_clear_sandbox_forwards_override_request() -> None:
    stub = _FakeInferenceStub()
    client = cast("InferenceRouteClient", object.__new__(InferenceRouteClient))
    client._timeout = 30.0
    client._stub = cast("Any", stub)

    cleared = client.clear_sandbox("sandbox-1")

    assert stub.clear_sandbox_request is not None
    assert stub.clear_sandbox_request.sandbox_id == "sandbox-1"
    assert cleared is True
