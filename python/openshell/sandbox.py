# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import json
import os
import pathlib
import sys
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import grpc

from ._proto import (
    datamodel_pb2,
    inference_pb2,
    inference_pb2_grpc,
    openshell_pb2,
    openshell_pb2_grpc,
)

if TYPE_CHECKING:
    import builtins
    from collections.abc import Callable, Iterator, Mapping, Sequence


@dataclass(frozen=True)
class TlsConfig:
    ca_path: pathlib.Path
    cert_path: pathlib.Path
    key_path: pathlib.Path


@dataclass(frozen=True)
class SandboxRef:
    id: str
    name: str
    namespace: str
    phase: int


@dataclass(frozen=True)
class ExecChunk:
    stream: str
    data: bytes


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str


class SandboxError(RuntimeError):
    pass


class SandboxSession:
    def __init__(self, client: SandboxClient, sandbox: SandboxRef) -> None:
        self._client = client
        self.sandbox = sandbox

    @property
    def id(self) -> str:
        return self.sandbox.id

    def exec(
        self,
        command: Sequence[str],
        *,
        stream_output: bool = False,
        workdir: str | None = None,
        env: Mapping[str, str] | None = None,
        stdin: bytes | None = None,
        timeout_seconds: int | None = None,
    ) -> ExecResult:
        return self._client.exec(
            self.sandbox.id,
            command,
            stream_output=stream_output,
            workdir=workdir,
            env=env,
            stdin=stdin,
            timeout_seconds=timeout_seconds,
        )

    def exec_python(
        self,
        function: Callable[..., object],
        *,
        args: Sequence[object] = (),
        kwargs: Mapping[str, object] | None = None,
        stream_output: bool = False,
        workdir: str | None = None,
        env: Mapping[str, str] | None = None,
        timeout_seconds: int | None = None,
    ) -> ExecResult:
        return self._client.exec_python(
            self.sandbox.id,
            function,
            args=args,
            kwargs=kwargs,
            stream_output=stream_output,
            workdir=workdir,
            env=env,
            timeout_seconds=timeout_seconds,
        )

    def delete(self) -> bool:
        return self._client.delete(self.sandbox.name)


class SandboxClient:
    """gRPC client for sandbox CRUD and command execution."""

    def __init__(
        self,
        endpoint: str,
        *,
        tls: TlsConfig | None = None,
        timeout: float = 30.0,
        cluster_name: str | None = None,
    ) -> None:
        self._endpoint = endpoint
        self._timeout = timeout
        self._cluster_name = cluster_name
        if tls is None:
            self._channel = grpc.insecure_channel(endpoint)
        else:
            credentials = grpc.ssl_channel_credentials(
                root_certificates=tls.ca_path.read_bytes(),
                private_key=tls.key_path.read_bytes(),
                certificate_chain=tls.cert_path.read_bytes(),
            )
            self._channel = grpc.secure_channel(endpoint, credentials)
        self._stub = openshell_pb2_grpc.OpenShellStub(self._channel)

    @classmethod
    def from_active_cluster(
        cls,
        *,
        cluster: str | None = None,
        timeout: float = 30.0,
    ) -> SandboxClient:
        cluster_name = cluster or _resolve_active_cluster()
        metadata_path = (
            _xdg_config_home()
            / "openshell"
            / "gateways"
            / cluster_name
            / "metadata.json"
        )
        metadata = json.loads(metadata_path.read_text())
        parsed = urlparse(metadata["gateway_endpoint"])
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        endpoint = f"{host}:{port}"
        if parsed.scheme == "https":
            mtls_dir = (
                _xdg_config_home() / "openshell" / "gateways" / cluster_name / "mtls"
            )
            tls = TlsConfig(
                ca_path=mtls_dir / "ca.crt",
                cert_path=mtls_dir / "tls.crt",
                key_path=mtls_dir / "tls.key",
            )
            return cls(endpoint, tls=tls, timeout=timeout, cluster_name=cluster_name)
        return cls(endpoint, timeout=timeout, cluster_name=cluster_name)

    def close(self) -> None:
        self._channel.close()

    def __enter__(self) -> SandboxClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def health(self) -> openshell_pb2.HealthResponse:
        return self._stub.Health(openshell_pb2.HealthRequest(), timeout=self._timeout)

    def create(
        self,
        *,
        spec: datamodel_pb2.SandboxSpec | None = None,
    ) -> SandboxRef:
        request_spec = spec if spec is not None else _default_spec()
        response = self._stub.CreateSandbox(
            openshell_pb2.CreateSandboxRequest(spec=request_spec),
            timeout=self._timeout,
        )
        if response.sandbox.id == "":
            raise SandboxError("CreateSandbox returned empty sandbox id")
        return _sandbox_ref(response.sandbox)

    def create_session(
        self,
        *,
        spec: datamodel_pb2.SandboxSpec | None = None,
    ) -> SandboxSession:
        return SandboxSession(self, self.create(spec=spec))

    def get(self, sandbox_name: str) -> SandboxRef:
        response = self._stub.GetSandbox(
            openshell_pb2.GetSandboxRequest(name=sandbox_name),
            timeout=self._timeout,
        )
        return _sandbox_ref(response.sandbox)

    def get_session(self, sandbox_name: str) -> SandboxSession:
        return SandboxSession(self, self.get(sandbox_name))

    def list(self, *, limit: int = 100, offset: int = 0) -> builtins.list[SandboxRef]:
        response = self._stub.ListSandboxes(
            openshell_pb2.ListSandboxesRequest(limit=limit, offset=offset),
            timeout=self._timeout,
        )
        return [_sandbox_ref(item) for item in response.sandboxes]

    def list_ids(self, *, limit: int = 100, offset: int = 0) -> builtins.list[str]:
        return [item.id for item in self.list(limit=limit, offset=offset)]

    def delete(self, sandbox_name: str) -> bool:
        response = self._stub.DeleteSandbox(
            openshell_pb2.DeleteSandboxRequest(name=sandbox_name),
            timeout=self._timeout,
        )
        return bool(response.deleted)

    def wait_deleted(self, sandbox_name: str, *, timeout_seconds: float = 60.0) -> None:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            try:
                self.get(sandbox_name)
            except grpc.RpcError as exc:
                if (
                    isinstance(exc, grpc.Call)
                    and exc.code() == grpc.StatusCode.NOT_FOUND
                ):
                    return
                raise
            time.sleep(1)
        raise SandboxError(f"sandbox {sandbox_name} was not deleted within timeout")

    def wait_ready(
        self, sandbox_name: str, *, timeout_seconds: float = 300.0
    ) -> SandboxRef:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            sandbox = self.get(sandbox_name)
            if sandbox.phase == datamodel_pb2.SANDBOX_PHASE_READY:
                return sandbox
            if sandbox.phase == datamodel_pb2.SANDBOX_PHASE_ERROR:
                raise SandboxError(f"sandbox {sandbox_name} entered error phase")
            time.sleep(1)
        raise SandboxError(f"sandbox {sandbox_name} was not ready within timeout")

    def exec_stream(
        self,
        sandbox_id: str,
        command: Sequence[str],
        *,
        workdir: str | None = None,
        env: Mapping[str, str] | None = None,
        stdin: bytes | None = None,
        timeout_seconds: int | None = None,
    ) -> Iterator[ExecChunk | ExecResult]:
        if not command:
            raise SandboxError("command must not be empty")

        request = openshell_pb2.ExecSandboxRequest(
            sandbox_id=sandbox_id,
            command=list(command),
            workdir=workdir or "",
            environment=dict(env or {}),
            timeout_seconds=timeout_seconds or 0,
            stdin=stdin or b"",
        )
        # Use whichever is larger: the default client timeout or the command
        # timeout plus headroom for SSH setup / teardown overhead.
        grpc_deadline = self._timeout
        if timeout_seconds and timeout_seconds + 10 > grpc_deadline:
            grpc_deadline = timeout_seconds + 10
        stream = self._stub.ExecSandbox(request, timeout=grpc_deadline)

        stdout_parts: list[bytes] = []
        stderr_parts: list[bytes] = []
        exit_code: int | None = None

        for event in stream:
            payload = event.WhichOneof("payload")
            if payload == "stdout":
                data = bytes(event.stdout.data)
                stdout_parts.append(data)
                yield ExecChunk(stream="stdout", data=data)
            elif payload == "stderr":
                data = bytes(event.stderr.data)
                stderr_parts.append(data)
                yield ExecChunk(stream="stderr", data=data)
            elif payload == "exit":
                exit_code = int(event.exit.exit_code)

        if exit_code is None:
            raise SandboxError("ExecSandbox stream ended without an exit event")

        yield ExecResult(
            exit_code=exit_code,
            stdout=b"".join(stdout_parts).decode("utf-8", errors="replace"),
            stderr=b"".join(stderr_parts).decode("utf-8", errors="replace"),
        )

    def exec(
        self,
        sandbox_id: str,
        command: Sequence[str],
        *,
        stream_output: bool = False,
        workdir: str | None = None,
        env: Mapping[str, str] | None = None,
        stdin: bytes | None = None,
        timeout_seconds: int | None = None,
    ) -> ExecResult:
        result: ExecResult | None = None
        for item in self.exec_stream(
            sandbox_id,
            command,
            workdir=workdir,
            env=env,
            stdin=stdin,
            timeout_seconds=timeout_seconds,
        ):
            if stream_output and isinstance(item, ExecChunk):
                if item.stream == "stdout":
                    sys.stdout.buffer.write(item.data)
                    sys.stdout.flush()
                else:
                    sys.stderr.buffer.write(item.data)
                    sys.stderr.flush()
            if isinstance(item, ExecResult):
                result = item
        if result is None:
            raise SandboxError("ExecSandbox did not return a result")
        return result

    def exec_python(
        self,
        sandbox_id: str,
        function: Callable[..., object],
        *,
        args: Sequence[object] = (),
        kwargs: Mapping[str, object] | None = None,
        stream_output: bool = False,
        workdir: str | None = None,
        env: Mapping[str, str] | None = None,
        timeout_seconds: int | None = None,
    ) -> ExecResult:
        exec_env = dict(env or {})
        exec_env["OPENSHELL_PYFUNC_B64"] = _serialize_python_callable(
            function,
            args=args,
            kwargs=kwargs,
        )
        return self.exec(
            sandbox_id,
            [_SANDBOX_PYTHON_BIN, "-c", _PYTHON_CLOUDPICKLE_BOOTSTRAP],
            stream_output=stream_output,
            workdir=workdir,
            env=exec_env,
            timeout_seconds=timeout_seconds,
        )


@dataclass(frozen=True)
class ClusterInferenceConfig:
    provider_name: str
    model_id: str
    version: int


class InferenceRouteClient:
    """gRPC client for cluster-level inference configuration."""

    def __init__(self, channel: grpc.Channel, *, timeout: float = 30.0) -> None:
        self._stub = inference_pb2_grpc.InferenceStub(channel)
        self._timeout = timeout

    @classmethod
    def from_sandbox_client(cls, client: SandboxClient) -> InferenceRouteClient:
        return cls(client._channel, timeout=client._timeout)

    def set_cluster(
        self,
        *,
        provider_name: str,
        model_id: str,
        no_verify: bool = False,
    ) -> ClusterInferenceConfig:
        response = self._stub.SetClusterInference(
            inference_pb2.SetClusterInferenceRequest(
                provider_name=provider_name,
                model_id=model_id,
                no_verify=no_verify,
            ),
            timeout=self._timeout,
        )
        return ClusterInferenceConfig(
            provider_name=response.provider_name,
            model_id=response.model_id,
            version=response.version,
        )

    def get_cluster(self) -> ClusterInferenceConfig:
        response = self._stub.GetClusterInference(
            inference_pb2.GetClusterInferenceRequest(),
            timeout=self._timeout,
        )
        return ClusterInferenceConfig(
            provider_name=response.provider_name,
            model_id=response.model_id,
            version=response.version,
        )


class Sandbox:
    """Context-managed sandbox session bound to one sandbox id."""

    def __init__(
        self,
        *,
        cluster: str | None = None,
        sandbox: str | SandboxRef | None = None,
        delete_on_exit: bool = True,
        spec: datamodel_pb2.SandboxSpec | None = None,
        timeout: float = 30.0,
        ready_timeout_seconds: float = 120.0,
    ) -> None:
        self._cluster = cluster
        self._sandbox_input = sandbox
        self._delete_on_exit = delete_on_exit
        self._spec = spec
        self._timeout = timeout
        self._ready_timeout_seconds = ready_timeout_seconds
        self._client: SandboxClient | None = None
        self._session: SandboxSession | None = None

    @property
    def id(self) -> str:
        if self._session is None:
            raise SandboxError("sandbox context has not been entered")
        return self._session.id

    @property
    def sandbox(self) -> SandboxRef:
        if self._session is None:
            raise SandboxError("sandbox context has not been entered")
        return self._session.sandbox

    def __enter__(self) -> Sandbox:
        client = SandboxClient.from_active_cluster(
            cluster=self._cluster,
            timeout=self._timeout,
        )
        self._client = client

        if self._sandbox_input is None:
            self._session = client.create_session(spec=self._spec)
        elif isinstance(self._sandbox_input, SandboxRef):
            self._session = SandboxSession(client, self._sandbox_input)
        else:
            self._session = client.get_session(self._sandbox_input)

        ready = client.wait_ready(
            self._session.sandbox.name,
            timeout_seconds=self._ready_timeout_seconds,
        )
        self._session = SandboxSession(client, ready)

        return self

    def __exit__(self, *args: object) -> None:
        try:
            if (
                self._delete_on_exit
                and self._session is not None
                and self._client is not None
            ):
                try:
                    deleted = self._session.delete()
                    if deleted:
                        self._client.wait_deleted(self._session.sandbox.name)
                except grpc.RpcError as exc:
                    if (
                        not isinstance(exc, grpc.Call)
                        or exc.code() != grpc.StatusCode.NOT_FOUND
                    ):
                        raise
        finally:
            if self._client is not None:
                self._client.close()
            self._session = None
            self._client = None

    def exec(
        self,
        command: Sequence[str],
        *,
        stream_output: bool = False,
        workdir: str | None = None,
        env: Mapping[str, str] | None = None,
        stdin: bytes | None = None,
        timeout_seconds: int | None = None,
    ) -> ExecResult:
        if self._session is None:
            raise SandboxError("sandbox context has not been entered")
        return self._session.exec(
            command,
            stream_output=stream_output,
            workdir=workdir,
            env=env,
            stdin=stdin,
            timeout_seconds=timeout_seconds,
        )

    def exec_python(
        self,
        function: Callable[..., object],
        *,
        args: Sequence[object] = (),
        kwargs: Mapping[str, object] | None = None,
        stream_output: bool = False,
        workdir: str | None = None,
        env: Mapping[str, str] | None = None,
        timeout_seconds: int | None = None,
    ) -> ExecResult:
        if self._session is None:
            raise SandboxError("sandbox context has not been entered")
        return self._session.exec_python(
            function,
            args=args,
            kwargs=kwargs,
            stream_output=stream_output,
            workdir=workdir,
            env=env,
            timeout_seconds=timeout_seconds,
        )


_PYTHON_CLOUDPICKLE_BOOTSTRAP = (
    "import base64,cloudpickle,os;"
    "payload=base64.b64decode(os.environ['OPENSHELL_PYFUNC_B64']);"
    "func,args,kwargs=cloudpickle.loads(payload);"
    "result=func(*args,**kwargs);"
    "print(result) if result is not None else None"
)

_SANDBOX_PYTHON_BIN = "python"


def _serialize_python_callable(
    function: Callable[..., object],
    *,
    args: Sequence[object],
    kwargs: Mapping[str, object] | None,
) -> str:
    try:
        import cloudpickle
    except ImportError as exc:  # pragma: no cover - import error path
        raise SandboxError("cloudpickle is required for exec_python") from exc

    payload = cloudpickle.dumps((function, tuple(args), dict(kwargs or {})))
    return base64.b64encode(payload).decode("ascii")


def _sandbox_ref(sandbox: datamodel_pb2.Sandbox) -> SandboxRef:
    return SandboxRef(
        id=sandbox.id,
        name=sandbox.name,
        namespace=sandbox.namespace,
        phase=sandbox.phase,
    )


def _default_spec() -> datamodel_pb2.SandboxSpec:
    # Omit the policy field so the sandbox container discovers its policy
    # from /etc/openshell/policy.yaml (baked into the image at build time).
    # This avoids duplicating policy defaults between the SDK and the
    # container image and ensures sandboxes get the full dev-sandbox-policy
    # (including network_policies) out of the box.
    return datamodel_pb2.SandboxSpec()


def _xdg_config_home() -> pathlib.Path:
    configured = os.environ.get("XDG_CONFIG_HOME")
    if configured:
        return pathlib.Path(configured)
    return pathlib.Path.home() / ".config"


def _resolve_active_cluster() -> str:
    env_gateway = os.environ.get("OPENSHELL_GATEWAY")
    if env_gateway:
        return env_gateway
    active_file = _xdg_config_home() / "openshell" / "active_gateway"
    value = active_file.read_text().strip()
    if value == "":
        raise SandboxError("no active gateway configured")
    return value
