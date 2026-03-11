# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

from openshell._proto import navigator_pb2
from openshell.sandbox import (
    _PYTHON_CLOUDPICKLE_BOOTSTRAP,
    _SANDBOX_PYTHON_BIN,
    SandboxClient,
)

if TYPE_CHECKING:
    from pathlib import Path


class _FakeStub:
    def __init__(self) -> None:
        self.request: navigator_pb2.ExecSandboxRequest | None = None

    def ExecSandbox(
        self,
        request: navigator_pb2.ExecSandboxRequest,
        timeout: float | None = None,
    ):
        self.request = request
        _ = timeout
        yield navigator_pb2.ExecSandboxEvent(
            exit=navigator_pb2.ExecSandboxExit(exit_code=0)
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
