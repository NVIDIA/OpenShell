# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import contextlib
import json
import os
import pathlib
import sys
import tempfile
import threading
import time
from collections import namedtuple
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast
from urllib.parse import urlparse

import grpc
import httpx

from ._proto import (
    inference_pb2,
    inference_pb2_grpc,
    openshell_pb2,
    openshell_pb2_grpc,
)

_ClientCallDetailsBase = namedtuple(
    "_ClientCallDetailsBase",
    ("method", "timeout", "metadata", "credentials", "wait_for_ready", "compression"),
)


class _ClientCallDetails(_ClientCallDetailsBase, grpc.ClientCallDetails):
    pass


if TYPE_CHECKING:
    import builtins
    from collections.abc import Callable, Iterator, Mapping, Sequence


@dataclass(frozen=True)
class TlsConfig:
    """Channel TLS material.

    All three fields are optional so callers can pick the trust profile:

    - Full mTLS: pass all three (server trusts client identity).
    - CA-only: pass `ca_path` (custom CA, no client identity).
    - System roots: pass no fields (`TlsConfig()`) — uses the OS trust
      store. Useful for OIDC gateways behind a public CA.

    `cert_path` and `key_path` must be set together or not at all.
    """

    ca_path: pathlib.Path | None = None
    cert_path: pathlib.Path | None = None
    key_path: pathlib.Path | None = None

    def __post_init__(self) -> None:
        if (self.cert_path is None) != (self.key_path is None):
            raise ValueError("TlsConfig: cert_path and key_path must be set together")


class _BearerAuthInterceptor(
    grpc.UnaryUnaryClientInterceptor,
    grpc.UnaryStreamClientInterceptor,
    grpc.StreamUnaryClientInterceptor,
    grpc.StreamStreamClientInterceptor,
):
    """Add `authorization: Bearer <token>` to every outgoing RPC.

    Implemented as an interceptor (not call credentials) so it works on
    both plaintext and TLS channels without needing
    `grpc.composite_channel_credentials`. The token provider is invoked
    per call, so callers can swap tokens at runtime by mutating shared
    state or returning a fresh value from the callable.
    """

    def __init__(self, token_provider: Callable[[], str]) -> None:
        self._token_provider = token_provider

    def _attach(self, details: grpc.ClientCallDetails) -> grpc.ClientCallDetails:
        original_metadata = getattr(details, "metadata", None)
        metadata = list(original_metadata) if original_metadata else []
        metadata.append(("authorization", f"Bearer {self._token_provider()}"))
        return _ClientCallDetails(
            getattr(details, "method", None),
            getattr(details, "timeout", None),
            metadata,
            getattr(details, "credentials", None),
            getattr(details, "wait_for_ready", None),
            getattr(details, "compression", None),
        )

    def intercept_unary_unary(self, continuation, client_call_details, request):
        return continuation(self._attach(client_call_details), request)

    def intercept_unary_stream(self, continuation, client_call_details, request):
        return continuation(self._attach(client_call_details), request)

    def intercept_stream_unary(
        self, continuation, client_call_details, request_iterator
    ):
        return continuation(self._attach(client_call_details), request_iterator)

    def intercept_stream_stream(
        self, continuation, client_call_details, request_iterator
    ):
        return continuation(self._attach(client_call_details), request_iterator)


def _normalize_bearer(
    bearer: str | Callable[[], str] | None,
) -> Callable[[], str] | None:
    if bearer is None:
        return None
    if callable(bearer):
        return cast("Callable[[], str]", bearer)
    token = bearer
    return lambda: token


@dataclass(frozen=True)
class SandboxStatusRef:
    phase: int
    current_policy_version: int


@dataclass(frozen=True)
class SandboxRef:
    id: str
    name: str
    status: SandboxStatusRef

    @property
    def phase(self) -> int:
        return self.status.phase

    @property
    def current_policy_version(self) -> int:
        return self.status.current_policy_version


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
        bearer_token: str | Callable[[], str] | None = None,
        timeout: float = 30.0,
        cluster_name: str | None = None,
        _bearer_close: Callable[[], None] | None = None,
    ) -> None:
        """Create a SandboxClient.

        Args:
            endpoint: host:port for the gateway gRPC service.
            tls: mTLS material. None for a plaintext channel.
            bearer_token: OIDC access token, or a zero-arg callable
                returning the current token (called per RPC; supports
                runtime refresh). Combines with `tls` — pass both when
                the gateway uses mTLS for transport identity and OIDC
                for user identity.
            timeout: default per-call timeout in seconds.
            cluster_name: optional friendly name for error messages.
            _bearer_close: internal — wired by `from_active_cluster`
                when an `_OidcRefresher` owns the bearer callable, so
                `close()` can release the refresher's HTTP client.
                Public callers should not pass this; they own the
                lifecycle of any callable they supplied as
                `bearer_token`.
        """
        self._endpoint = endpoint
        self._timeout = timeout
        self._cluster_name = cluster_name
        self._bearer_close = _bearer_close
        if tls is None:
            self._channel = grpc.insecure_channel(endpoint)
        else:
            # Build credentials from whatever subset of mTLS material the
            # caller supplied. None for `root_certificates` makes gRPC use
            # the system trust store, which is what we want for OIDC
            # gateways behind a public CA.
            credentials = grpc.ssl_channel_credentials(
                root_certificates=(tls.ca_path.read_bytes() if tls.ca_path else None),
                private_key=(tls.key_path.read_bytes() if tls.key_path else None),
                certificate_chain=(
                    tls.cert_path.read_bytes() if tls.cert_path else None
                ),
            )
            self._channel = grpc.secure_channel(endpoint, credentials)
        provider = _normalize_bearer(bearer_token)
        if provider is not None:
            self._channel = grpc.intercept_channel(
                self._channel,
                _BearerAuthInterceptor(provider),
            )
        self._stub = openshell_pb2_grpc.OpenShellStub(self._channel)

    @classmethod
    def from_active_cluster(
        cls,
        *,
        cluster: str | None = None,
        timeout: float = 30.0,
        auto_refresh: bool = True,
        write_back: bool = True,
        insecure: bool = False,
    ) -> SandboxClient:
        """Construct a `SandboxClient` from the active gateway's on-disk state.

        Args:
            cluster: explicit gateway name; otherwise reads
                `$OPENSHELL_GATEWAY` or `~/.config/openshell/active_gateway`.
            timeout: per-call gRPC timeout in seconds.
            auto_refresh: when True (default) and the gateway uses OIDC,
                lazily refresh the access token via the IdP's token endpoint
                if the cached `oidc_token.json` is near expiry. Matches the
                lazy-refresh patterns used by `google-auth` and `botocore`.
                Set False to keep the SDK as a read-only consumer of the
                CLI's cache (fail closed on expiry).
            write_back: when True (default, and `auto_refresh=True`),
                atomically persist refreshed bundles back to
                `oidc_token.json` so other processes — including the
                Rust CLI — see the rotation. Required for IdPs with
                refresh-token rotation enabled (Keycloak, Entra in
                strict mode): an in-memory-only refresh would leave the
                on-disk `refresh_token` pointing at an invalidated
                value, and any other process starting from that disk
                state would fail on its first refresh. Set False only
                when you know the SDK is the sole consumer of this
                gateway directory.
            insecure: when True, disables TLS certificate verification
                for OIDC discovery and refresh calls. Mirrors the Rust
                CLI's `--insecure` flag for issuers behind self-signed
                certs. Off by default.
        """
        cluster_name = cluster or _resolve_active_cluster()
        gateway_dir = _xdg_config_home() / "openshell" / "gateways" / cluster_name
        metadata_path = gateway_dir / "metadata.json"
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise SandboxError(f"gateway '{cluster_name}' not found") from None
        if "gateway_endpoint" not in metadata:
            raise SandboxError(f"gateway '{cluster_name}' metadata missing endpoint")
        parsed = urlparse(metadata["gateway_endpoint"])
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        endpoint = f"{host}:{port}"

        # TLS transport. Mirror crates/openshell-tui/src/lib.rs
        # `build_oidc_channel` — for an https gateway, always build a
        # secure channel and pick the strongest available trust profile.
        tls: TlsConfig | None = None
        if parsed.scheme == "https":
            mtls_dir = gateway_dir / "mtls"
            ca = mtls_dir / "ca.crt" if (mtls_dir / "ca.crt").exists() else None
            cert = mtls_dir / "tls.crt" if (mtls_dir / "tls.crt").exists() else None
            key = mtls_dir / "tls.key" if (mtls_dir / "tls.key").exists() else None
            if ca is not None and cert is not None and key is not None:
                # Full mTLS.
                tls = TlsConfig(ca_path=ca, cert_path=cert, key_path=key)
            elif ca is not None:
                # CA-only trust (no client identity).
                tls = TlsConfig(ca_path=ca)
            else:
                # System roots (e.g. OIDC gateway behind a public CA).
                tls = TlsConfig()

        # OIDC bearer. Mirror the Rust CLI/TUI: the gateway metadata's
        # `auth_mode` is authoritative — a stale oidc_token.json next to
        # a non-OIDC gateway should NOT cause us to attach a bearer.
        bearer_token: Callable[[], str] | None = None
        bearer_close: Callable[[], None] | None = None
        if metadata.get("auth_mode") == "oidc":
            bearer_token, bearer_close = _make_cluster_bearer_provider(
                gateway_dir,
                cluster_name,
                auto_refresh=auto_refresh,
                write_back=write_back,
                insecure=insecure,
            )

        return cls(
            endpoint,
            tls=tls,
            bearer_token=bearer_token,
            timeout=timeout,
            cluster_name=cluster_name,
            _bearer_close=bearer_close,
        )

    def close(self) -> None:
        """Release the gRPC channel and any bearer-auth resources.

        Idempotent. If `from_active_cluster` wired up an OIDC refresher
        for this client, the refresher's underlying httpx.Client is
        closed here too — otherwise long-lived services that churn
        clients would leak sockets / file descriptors until GC.
        """
        self._channel.close()
        if self._bearer_close is not None:
            with contextlib.suppress(Exception):
                self._bearer_close()
            self._bearer_close = None

    def __enter__(self) -> SandboxClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def health(self) -> openshell_pb2.HealthResponse:
        return self._stub.Health(openshell_pb2.HealthRequest(), timeout=self._timeout)

    def create(
        self,
        *,
        spec: openshell_pb2.SandboxSpec | None = None,
    ) -> SandboxRef:
        request_spec = spec if spec is not None else _default_spec()
        response = self._stub.CreateSandbox(
            openshell_pb2.CreateSandboxRequest(spec=request_spec),
            timeout=self._timeout,
        )
        sandbox_ref = _sandbox_ref(response.sandbox)
        if sandbox_ref.id == "":
            raise SandboxError("CreateSandbox returned empty sandbox id")
        return sandbox_ref

    def create_session(
        self,
        *,
        spec: openshell_pb2.SandboxSpec | None = None,
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
            if sandbox.status.phase == openshell_pb2.SANDBOX_PHASE_READY:
                return sandbox
            if sandbox.status.phase == openshell_pb2.SANDBOX_PHASE_ERROR:
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
        spec: openshell_pb2.SandboxSpec | None = None,
        timeout: float = 30.0,
        ready_timeout_seconds: float = 120.0,
        auto_refresh: bool = True,
        write_back: bool = True,
        insecure: bool = False,
    ) -> None:
        """Bind a Sandbox context to the active gateway.

        OIDC kwargs (`auto_refresh`, `write_back`, `insecure`) forward
        directly to `SandboxClient.from_active_cluster` and have the
        same semantics. They're surfaced on `Sandbox` so callers using
        the higher-level wrapper get parity with `SandboxClient` for
        OIDC-protected gateways (e.g. passing `insecure=True` for a
        self-signed dev IdP). Non-OIDC gateways ignore them.
        """
        self._cluster = cluster
        self._sandbox_input = sandbox
        self._delete_on_exit = delete_on_exit
        self._spec = spec
        self._timeout = timeout
        self._ready_timeout_seconds = ready_timeout_seconds
        self._auto_refresh = auto_refresh
        self._write_back = write_back
        self._insecure = insecure
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
            auto_refresh=self._auto_refresh,
            write_back=self._write_back,
            insecure=self._insecure,
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


def _sandbox_ref(sandbox: openshell_pb2.Sandbox) -> SandboxRef:
    status = sandbox.status if sandbox.HasField("status") else None
    return SandboxRef(
        id=sandbox.metadata.id if sandbox.metadata else "",
        name=sandbox.metadata.name if sandbox.metadata else "",
        status=SandboxStatusRef(
            phase=status.phase if status else 0,
            current_policy_version=status.current_policy_version if status else 0,
        ),
    )


def _default_spec() -> openshell_pb2.SandboxSpec:
    # Omit the policy field so the sandbox container discovers its policy
    # from /etc/openshell/policy.yaml (baked into the image at build time).
    # This avoids duplicating policy defaults between the SDK and the
    # container image and ensures sandboxes get the full dev-sandbox-policy
    # (including network_policies) out of the box.
    return openshell_pb2.SandboxSpec()


def _xdg_config_home() -> pathlib.Path:
    configured = os.environ.get("XDG_CONFIG_HOME")
    if configured:
        return pathlib.Path(configured)
    return pathlib.Path.home() / ".config"


# Re-check the cached token roughly 30 seconds before the issuer's
# stated expiry, to leave room for in-flight RPCs and clock skew. This
# matches `openshell-bootstrap::oidc_token::is_token_expired`.
_OIDC_TOKEN_EXPIRY_GRACE_SECONDS = 30


def _read_oidc_token_bundle(gateway_dir: pathlib.Path) -> dict | None:
    """Read and parse `oidc_token.json` for a gateway.

    Returns the parsed dict, or `None` if the file is absent or unreadable.
    See `openshell-bootstrap::oidc_token::store_oidc_token` for the writer.
    """
    token_path = gateway_dir / "oidc_token.json"
    try:
        return json.loads(token_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _normalize_issuer(bundle: dict) -> str | None:
    """Return the bundle's issuer with a trailing slash stripped.

    Used to detect whether the issuer changed when adopting a bundle
    re-read from disk, so a cached token endpoint computed for the old
    issuer can be invalidated. Trailing-slash differences are treated as
    equal, matching `_discover_token_endpoint`'s normalization.
    """
    issuer = bundle.get("issuer")
    return issuer.rstrip("/") if isinstance(issuer, str) else None


def _load_cluster_bearer_token(gateway_dir: pathlib.Path) -> str | None:
    """Read a single (possibly expired) access token from disk.

    Lower-level helper used by both the legacy single-shot path and the
    refreshing provider. Returns the raw access_token string or None.
    """
    bundle = _read_oidc_token_bundle(gateway_dir)
    if bundle is None:
        return None
    access_token = bundle.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        return None
    return access_token


def _make_fail_closed_bearer_provider(
    gateway_dir: pathlib.Path,
    cluster_name: str,
) -> Callable[[], str]:
    """Per-RPC provider that re-reads `oidc_token.json` but does NOT refresh.

    Raises `SandboxError` when the token is missing or expired. Available as
    an opt-out from the default `_OidcRefresher` for callers (e.g. tests)
    that want to assert expiry behavior or that don't want the SDK to make
    outbound HTTP calls to the IdP.
    """

    def provider() -> str:
        bundle = _read_oidc_token_bundle(gateway_dir)
        if bundle is None:
            raise SandboxError(
                f"OIDC token for gateway '{cluster_name}' is missing or "
                f"unreadable. Re-authenticate with: openshell gateway login"
            )
        access_token = bundle.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise SandboxError(
                f"OIDC token for gateway '{cluster_name}' has no access "
                f"token. Re-authenticate with: openshell gateway login"
            )
        expires_at = bundle.get("expires_at")
        if isinstance(expires_at, int):
            now = int(time.time())
            if now + _OIDC_TOKEN_EXPIRY_GRACE_SECONDS >= expires_at:
                raise SandboxError(
                    f"OIDC token for gateway '{cluster_name}' has expired. "
                    f"Re-authenticate with: openshell gateway login"
                )
        return access_token

    return provider


class _InvalidGrantError(SandboxError):
    """Refresh failed with OAuth2 `invalid_grant` (RFC 6749 §5.2).

    The refresh_token was rejected — expired, revoked, or rotated out by
    a concurrent refresh in another process. Subclass of `SandboxError`
    so an uncaught instance still surfaces the standard re-authenticate
    hint; `current_access_token` catches it to retry once with a
    peer-rotated bundle before giving up.
    """


class _OidcRefresher:
    """Thread-safe in-process OAuth2 refresh for a gateway's `oidc_token.json`.

    Mirrors the lazy-refresh pattern used by `google-auth`'s `Credentials`
    and `botocore`'s `SSOTokenProvider`. Uses `httpx` for transport so
    we can pin `follow_redirects=False` and the TLS verification policy
    explicitly — same posture as the Rust CLI's use of `reqwest` with
    `Policy::none()` and an opt-in `danger_accept_invalid_certs` (see
    `crates/openshell-cli/src/oidc_auth.rs::http_client`). The OAuth2
    refresh-token grant itself (RFC 6749 §6) is a single form-encoded
    POST, handled inline rather than via an OAuth2 library.

    Properties:

    - **Lazy**: check expiry on every RPC; refresh only when stale.
    - **Lock-coordinated**: concurrent RPCs share a single refresh, not
      one per call. Plain `threading.Lock` (no separate worker thread,
      unlike `google-auth`'s `RefreshThreadManager` — sufficient for
      our use case).
    - **Disk-aware**: before refreshing, re-read `oidc_token.json` —
      the CLI or another process may have already rotated the bundle.
    - **Discovery-validated**: fetches the OIDC discovery document
      from `<issuer>/.well-known/openid-configuration`, rejects
      responses whose `issuer` field doesn't match the configured one
      (preventing SSRF / misdirection of the refresh_token to an
      attacker-controlled endpoint). Mirrors the Rust CLI's
      `discover()` function.
    - **Redirect-hardened**: `follow_redirects=False` on the underlying
      `httpx.Client` so a 3xx during discovery or refresh is treated
      as a failure rather than silently chasing the redirect to an
      arbitrary host.
    - **Write-back by default**: when `auto_refresh=True`, refreshed
      bundles are atomically persisted to `oidc_token.json` at mode
      0600 so other processes (Rust CLI, TUI, other Python clients)
      see the rotated `refresh_token`. Required for IdPs that
      invalidate the old `refresh_token` on rotation (Keycloak with
      rotation enabled, Entra in strict mode); without write-back, a
      second process would `invalid_grant` on next refresh.
    - **`insecure=True` flag** disables TLS certificate verification
      for the discovery and refresh calls. Matches the Rust CLI's
      `--insecure` plumbing for OIDC issuers behind self-signed certs.
    - **Refresh failures** surface as `SandboxError` with a
      "re-authenticate with: openshell gateway login" hint.
    """

    def __init__(
        self,
        gateway_dir: pathlib.Path,
        cluster_name: str,
        *,
        write_back: bool = True,
        insecure: bool = False,
    ) -> None:
        self._gateway_dir = gateway_dir
        self._cluster_name = cluster_name
        self._write_back = write_back
        self._lock = threading.Lock()
        self._bundle: dict | None = None
        self._token_endpoint: str | None = None
        # Single httpx.Client serves both discovery (unauthenticated
        # GET) and refresh (POST with form-encoded body) — they share
        # the same security posture.
        #
        # - follow_redirects=False: a 3xx during discovery would
        #   otherwise steer us to an attacker-controlled token
        #   endpoint. Matches `reqwest::redirect::Policy::none()` in
        #   the Rust CLI's `oidc_auth.rs::http_client`.
        # - verify=not insecure: opt-in TLS-verification disable for
        #   self-signed issuers. Matches the Rust CLI's `--insecure`
        #   flag plumbing.
        #
        # We don't use authlib's `OAuth2Client` here because it
        # auto-injects an Authorization header on every request from
        # its stored token, which would break the unauthenticated
        # discovery GET. The refresh_token grant for a public client
        # is a single form-encoded POST — small enough to spell out
        # directly with httpx, and easier to test.
        self._http = httpx.Client(
            follow_redirects=False,
            verify=not insecure,
            timeout=15.0,
        )

    def close(self) -> None:
        self._http.close()

    def __del__(self) -> None:
        # Best-effort cleanup; tests + short-lived callers may not call
        # close() explicitly.
        with contextlib.suppress(Exception):
            self._http.close()

    def current_access_token(self) -> str:
        """Return a non-expired access token, refreshing if needed."""
        with self._lock:
            if self._bundle is None:
                self._bundle = _read_oidc_token_bundle(self._gateway_dir)
                if self._bundle is None:
                    raise SandboxError(
                        f"OIDC token for gateway '{self._cluster_name}' is "
                        f"missing or unreadable. Re-authenticate with: "
                        f"openshell gateway login"
                    )
            if self._is_fresh(self._bundle):
                return self._bundle["access_token"]
            # Cached bundle is stale. Before refreshing, re-read disk —
            # another process (CLI, TUI, another SDK client) may have
            # rotated the bundle while we were idle. Adopt the disk
            # bundle when it was refreshed more recently than ours, EVEN
            # WHEN its access token is also stale: otherwise we'd refresh
            # with our in-memory refresh_token, which a rotating IdP may
            # have already invalidated when the other process refreshed
            # (Keycloak with rotation, Entra in strict mode).
            #
            # "More recently" is judged by `expires_at`: a refresh issues
            # a new access token with a forward expiry alongside the
            # (possibly rotated) refresh_token, so the bundle with the
            # later expiry carries the newest refresh_token. This also
            # preserves the write_back=False case, where our in-memory
            # bundle has already rotated past the on-disk one and must
            # NOT be clobbered by the older disk copy.
            disk = _read_oidc_token_bundle(self._gateway_dir)
            if disk is not None and self._expiry(disk) > self._expiry(self._bundle):
                # If the issuer changed under us, the cached token
                # endpoint no longer applies — force re-discovery.
                if _normalize_issuer(disk) != _normalize_issuer(self._bundle):
                    self._token_endpoint = None
                self._bundle = disk
                if self._is_fresh(disk):
                    return disk["access_token"]
            # Truly stale; refresh against the IdP using the freshest
            # bundle we have (disk if it was newer, else in-memory).
            try:
                self._bundle = self._refresh(self._bundle)
            except _InvalidGrantError as exc:
                # We lost a cross-process rotation race: between our disk
                # re-read above and our refresh POST, a peer (CLI, TUI,
                # another SDK client) rotated the refresh_token and the
                # IdP invalidated ours. This is the residual window that
                # neither google-auth nor botocore close without an OS
                # file lock. Rather than lock, recover: re-read disk once
                # and, if a peer wrote a *different* refresh_token, retry
                # with it before surfacing a re-authenticate error.
                self._bundle = self._recover_from_invalid_grant(self._bundle, exc)
            if self._write_back:
                self._write_to_disk(self._bundle)
            return self._bundle["access_token"]

    def _recover_from_invalid_grant(
        self, attempted: dict, exc: _InvalidGrantError
    ) -> dict:
        """Re-read disk after an `invalid_grant` and retry once if a peer
        rotated the refresh_token.

        `attempted` is the bundle whose refresh_token the IdP just
        rejected. If disk now holds a different refresh_token, a
        concurrent process won the rotation race — adopt and reuse it
        (returning early if it is already fresh, otherwise refreshing
        with it). If disk offers nothing new, the rejection is genuine:
        re-raise so the caller sees the re-authenticate hint.
        """
        disk = _read_oidc_token_bundle(self._gateway_dir)
        if disk is None or disk.get("refresh_token") == attempted.get("refresh_token"):
            # No peer rotation — the refresh_token really is dead.
            raise exc
        if _normalize_issuer(disk) != _normalize_issuer(attempted):
            self._token_endpoint = None
        if self._is_fresh(disk):
            return disk
        # Single retry with the peer's rotated token; a second
        # _InvalidGrantError here propagates (no further retry).
        return self._refresh(disk)

    @staticmethod
    def _is_fresh(bundle: dict) -> bool:
        access_token = bundle.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            return False
        exp = bundle.get("expires_at")
        if not isinstance(exp, int):
            # No expiry info — treat as fresh (matches the
            # `is_token_expired` semantics in the Rust CLI).
            return True
        return int(time.time()) + _OIDC_TOKEN_EXPIRY_GRACE_SECONDS < exp

    @staticmethod
    def _expiry(bundle: dict) -> float:
        """Access-token expiry as a comparable number.

        A bundle without an `expires_at` is treated as non-expiring
        (`+inf`) — consistent with `_is_fresh`, which treats a missing
        expiry as always fresh. Used to decide which of two stale
        bundles (in-memory vs. on-disk) was refreshed more recently and
        therefore holds the newest refresh_token.
        """
        exp = bundle.get("expires_at")
        return float(exp) if isinstance(exp, int) else float("inf")

    def _discover_token_endpoint(self, bundle: dict) -> str:
        if self._token_endpoint is not None:
            return self._token_endpoint
        issuer = bundle.get("issuer")
        if not isinstance(issuer, str) or not issuer:
            raise SandboxError(
                f"OIDC bundle for gateway '{self._cluster_name}' has no "
                f"`issuer`; cannot refresh. Re-authenticate with: openshell "
                f"gateway login"
            )
        normalized_issuer = issuer.rstrip("/")
        discovery_url = f"{normalized_issuer}/.well-known/openid-configuration"
        try:
            resp = self._http.get(discovery_url)
        except httpx.HTTPError as e:
            raise SandboxError(
                f"OIDC discovery failed for gateway "
                f"'{self._cluster_name}': {e}. Re-authenticate with: "
                f"openshell gateway login"
            ) from e
        # follow_redirects=False means a 3xx surfaces as a non-2xx
        # status; treat any non-success as a discovery failure rather
        # than silently following.
        if not 200 <= resp.status_code < 300:
            raise SandboxError(
                f"OIDC discovery failed for gateway "
                f"'{self._cluster_name}': HTTP {resp.status_code} "
                f"from {discovery_url}. Re-authenticate with: openshell "
                f"gateway login"
            )
        try:
            disco = resp.json()
        except ValueError as e:
            raise SandboxError(
                f"OIDC discovery returned invalid JSON for gateway "
                f"'{self._cluster_name}': {e}"
            ) from e
        # Critical: validate that the discovery document's `issuer`
        # matches the configured one. Without this, a misdirected or
        # malicious discovery response could steer the refresh_token
        # POST to an attacker-controlled endpoint.
        discovered_issuer = disco.get("issuer", "")
        if not isinstance(discovered_issuer, str) or (
            discovered_issuer.rstrip("/") != normalized_issuer
        ):
            raise SandboxError(
                f"OIDC discovery issuer mismatch for gateway "
                f"'{self._cluster_name}': expected '{normalized_issuer}', "
                f"got '{discovered_issuer}'."
            )
        endpoint = disco.get("token_endpoint")
        if not isinstance(endpoint, str) or not endpoint:
            raise SandboxError(
                f"OIDC discovery for gateway '{self._cluster_name}' did "
                f"not include a token_endpoint."
            )
        self._token_endpoint = endpoint
        return endpoint

    def _refresh(self, bundle: dict) -> dict:
        refresh_token = bundle.get("refresh_token")
        if not isinstance(refresh_token, str) or not refresh_token:
            raise SandboxError(
                f"OIDC token for gateway '{self._cluster_name}' has no "
                f"refresh token. Re-authenticate with: openshell gateway "
                f"login"
            )
        token_endpoint = self._discover_token_endpoint(bundle)
        client_id = bundle.get("client_id", "openshell-cli")

        # RFC 6749 §6: refresh_token grant. Form-encoded POST with
        # grant_type, refresh_token, and (for a public client) client_id.
        # No Authorization header (token_endpoint_auth_method="none").
        try:
            resp = self._http.post(
                token_endpoint,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": client_id,
                },
            )
        except httpx.HTTPError as e:
            raise SandboxError(
                f"OIDC token refresh failed for gateway "
                f"'{self._cluster_name}': {type(e).__name__}: {e}. "
                f"Re-authenticate with: openshell gateway login"
            ) from e
        if resp.status_code != 200:
            # Include the IdP's error body for diagnostics — RFC 6749
            # mandates a JSON body like {"error":"invalid_grant", ...}
            # on failure, which is the most useful signal to surface.
            error_code = None
            with contextlib.suppress(Exception):
                body = resp.json()
                if isinstance(body, dict):
                    error_code = body.get("error")
            detail = ""
            with contextlib.suppress(Exception):
                detail = f": {resp.text[:200]}"
            message = (
                f"OIDC token refresh failed for gateway "
                f"'{self._cluster_name}': HTTP {resp.status_code}"
                f"{detail}. Re-authenticate with: openshell gateway "
                f"login"
            )
            # `invalid_grant` specifically means the refresh_token was
            # rejected — distinguished from transport/5xx errors so the
            # caller can retry once with a peer-rotated bundle (a lost
            # cross-process rotation race) before surfacing the failure.
            if error_code == "invalid_grant":
                raise _InvalidGrantError(message)
            raise SandboxError(message)
        try:
            token = resp.json()
        except ValueError as e:
            raise SandboxError(
                f"OIDC refresh response for gateway '{self._cluster_name}' "
                f"is not JSON: {e}"
            ) from e

        access_token = token.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise SandboxError(
                f"OIDC refresh response for gateway '{self._cluster_name}' "
                f"is missing access_token."
            )
        expires_at = token.get("expires_at")
        if expires_at is None:
            expires_in = token.get("expires_in")
            if isinstance(expires_in, (int, float)):
                expires_at = int(time.time()) + int(expires_in)
        return {
            "access_token": access_token,
            # Refresh-token rotation: some IdPs (Keycloak with rotation
            # enabled, Entra in strict mode) reissue and invalidate the
            # old one. Honor the new value when present.
            "refresh_token": token.get("refresh_token", refresh_token),
            "expires_at": int(expires_at) if expires_at is not None else None,
            "issuer": bundle.get("issuer", ""),
            "client_id": client_id,
        }

    def _write_to_disk(self, bundle: dict) -> None:
        """Atomic-replace `oidc_token.json` with the refreshed bundle.

        Strips `None` values to match the Rust writer's
        `skip_serializing_if = "Option::is_none"` behavior so a Python-
        written file is byte-identical in shape to what the CLI writes.

        Uses `tempfile.mkstemp` (PID + random suffix) so two writers
        racing on the same gateway directory don't share a tmp file
        and trample each other's content. Each writer gets a unique
        path; `.replace()` is atomic per-writer, and POSIX rename
        semantics ensure the final `oidc_token.json` is always
        complete-and-readable to anyone observing.
        """
        path = self._gateway_dir / "oidc_token.json"
        serializable = {k: v for k, v in bundle.items() if v is not None}
        payload = json.dumps(serializable, indent=2)

        # mkstemp creates the file with mode 0600 already on POSIX
        # (it uses O_CREAT | O_EXCL with restrictive umask), so chmod
        # is a belt-and-braces step for filesystems that don't honor
        # the initial mode.
        fd, tmp_name = tempfile.mkstemp(
            prefix=".oidc_token.",
            suffix=".tmp",
            dir=str(self._gateway_dir),
        )
        tmp_path = pathlib.Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(payload)
            with contextlib.suppress(OSError):
                tmp_path.chmod(0o600)
            tmp_path.replace(path)
        except BaseException:
            # Clean up our tmp on failure so we don't leave orphaned
            # `.oidc_token.<rand>.tmp` files lying around. The replace
            # already moved the file on the success path.
            with contextlib.suppress(OSError):
                tmp_path.unlink()
            raise


def _make_cluster_bearer_provider(
    gateway_dir: pathlib.Path,
    cluster_name: str,
    *,
    auto_refresh: bool = True,
    write_back: bool = True,
    insecure: bool = False,
) -> tuple[Callable[[], str], Callable[[], None] | None]:
    """Build a per-RPC token provider for a gateway directory.

    Returns `(token_provider, close_fn_or_none)`. `close_fn` is non-None
    only when an `_OidcRefresher` was constructed; callers that own the
    provider's lifecycle (e.g. `SandboxClient.close()`) should invoke
    it during teardown so the underlying httpx.Client is released
    rather than relying on `__del__`.

    With `auto_refresh=True` (the default), returns an `_OidcRefresher`-
    backed callable that lazily refreshes against the IdP's token endpoint
    when the cached bundle is stale. This mirrors the lazy-refresh pattern
    used by `google.oauth2.credentials.Credentials` and
    `botocore.tokens.SSOTokenProvider` and lets long-running scripts
    survive token rotation without intervention.

    With `auto_refresh=False`, falls back to the read-only / fail-closed
    behavior: the SDK consumes whatever the CLI most recently wrote and
    raises `SandboxError` when the token expires. Useful for tests or
    callers that don't want the SDK to make outbound HTTP calls to the
    IdP. No close_fn is returned in this case.

    `write_back=True` (only meaningful when `auto_refresh=True`) makes the
    refresher atomically persist the rotated bundle back to
    `oidc_token.json` so other processes — including the Rust CLI — see
    the new token. Defaults to True because OIDC providers with
    refresh-token rotation (Keycloak, Entra) invalidate the old
    refresh_token on rotation; an in-memory-only refresh would leave the
    on-disk bundle pointing at an invalidated value, and any other
    process starting from that disk state would fail on its first
    refresh.

    `insecure=True` disables TLS certificate verification for both the
    OIDC discovery document fetch and the refresh-token POST. Mirrors
    the Rust CLI's `--insecure` flag for OIDC issuers behind self-signed
    certs.
    """
    if not auto_refresh:
        return _make_fail_closed_bearer_provider(gateway_dir, cluster_name), None
    refresher = _OidcRefresher(
        gateway_dir,
        cluster_name,
        write_back=write_back,
        insecure=insecure,
    )
    return refresher.current_access_token, refresher.close


def _resolve_active_cluster() -> str:
    env_gateway = os.environ.get("OPENSHELL_GATEWAY")
    if env_gateway:
        return env_gateway
    active_file = _xdg_config_home() / "openshell" / "active_gateway"
    try:
        value = active_file.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        raise SandboxError("no active gateway configured") from None
    if value == "":
        raise SandboxError("no active gateway configured")
    return value
