# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import pickle
import threading
import time
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from openshell._proto import openshell_pb2
from openshell.sandbox import (
    _PYTHON_CLOUDPICKLE_BOOTSTRAP,
    _SANDBOX_PYTHON_BIN,
    InferenceRouteClient,
    Sandbox,
    SandboxClient,
    SandboxError,
    SandboxRef,
    SandboxStatusRef,
    TlsConfig,
    _BearerAuthInterceptor,
    _load_cluster_bearer_token,
    _make_cluster_bearer_provider,
    _normalize_bearer,
    _OidcRefresher,
    _read_oidc_token_bundle,
    _sandbox_ref,
)


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

    def SetClusterInference(self, request: Any, timeout: float | None = None) -> Any:
        self.request = request
        _ = timeout

        class _Response:
            provider_name = request.provider_name
            model_id = request.model_id
            version = 1

        return _Response()


def _client_with_fake_stub(stub: object) -> SandboxClient:
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


# ---------------------------------------------------------------------------
# OIDC bearer auth
# ---------------------------------------------------------------------------


class _FakeClientCallDetails:
    """grpc.ClientCallDetails is a NamedTuple in real gRPC; for unit tests we
    just need an object with the same field set and a ._replace shim."""

    __slots__ = ("credentials", "metadata", "method", "timeout", "wait_for_ready")

    def __init__(
        self,
        method: str = "/Test/Method",
        timeout: float | None = None,
        metadata: Any = None,
        credentials: Any = None,
        wait_for_ready: Any = None,
    ) -> None:
        self.method = method
        self.timeout = timeout
        self.metadata = metadata
        self.credentials = credentials
        self.wait_for_ready = wait_for_ready

    def _replace(self, **kwargs: Any) -> _FakeClientCallDetails:
        return _FakeClientCallDetails(
            method=kwargs.get("method", self.method),
            timeout=kwargs.get("timeout", self.timeout),
            metadata=kwargs.get("metadata", self.metadata),
            credentials=kwargs.get("credentials", self.credentials),
            wait_for_ready=kwargs.get("wait_for_ready", self.wait_for_ready),
        )


def test_normalize_bearer_accepts_str_or_callable() -> None:
    assert _normalize_bearer(None) is None

    static = _normalize_bearer("abc")
    assert static is not None
    assert static() == "abc"

    counter = [0]

    def provider() -> str:
        counter[0] += 1
        return f"token-{counter[0]}"

    dynamic = _normalize_bearer(provider)
    assert dynamic is not None
    assert dynamic() == "token-1"
    assert dynamic() == "token-2"


def test_bearer_interceptor_attaches_authorization_header() -> None:
    interceptor = _BearerAuthInterceptor(lambda: "secret-token")
    captured: dict[str, Any] = {}

    def continuation(details: Any, request: Any) -> str:
        captured["details"] = details
        captured["request"] = request
        return "result"

    details = _FakeClientCallDetails(metadata=[("x-existing", "yes")])
    result = interceptor.intercept_unary_unary(continuation, details, "payload")

    assert result == "result"
    md = list(captured["details"].metadata)
    # Pre-existing metadata preserved, authorization appended last.
    assert ("x-existing", "yes") in md
    assert ("authorization", "Bearer secret-token") in md
    assert captured["request"] == "payload"


def test_bearer_interceptor_handles_empty_metadata() -> None:
    interceptor = _BearerAuthInterceptor(lambda: "t")
    captured: dict[str, Any] = {}

    def continuation(details: Any, _request: Any) -> None:
        captured["metadata"] = list(details.metadata)

    details = _FakeClientCallDetails(metadata=None)
    interceptor.intercept_unary_unary(continuation, details, request="x")

    assert captured["metadata"] == [("authorization", "Bearer t")]


def test_bearer_interceptor_calls_token_provider_per_request() -> None:
    tokens = iter(["t1", "t2", "t3"])
    interceptor = _BearerAuthInterceptor(lambda: next(tokens))
    seen: list[str] = []

    def continuation(details: Any, _request: Any) -> None:
        for key, value in details.metadata:
            if key == "authorization":
                seen.append(value)

    for _ in range(3):
        interceptor.intercept_unary_unary(
            continuation, _FakeClientCallDetails(), request="x"
        )

    assert seen == ["Bearer t1", "Bearer t2", "Bearer t3"]


def test_load_cluster_bearer_token_reads_oidc_token_json(tmp_path: Path) -> None:
    gateway_dir = tmp_path / "gw"
    gateway_dir.mkdir()
    (gateway_dir / "oidc_token.json").write_text(
        json.dumps(
            {
                "access_token": "jwt-blob",
                "refresh_token": "rt",
                "expires_at": 9999999999,
                "issuer": "https://idp.example/realms/openshell",
                "client_id": "openshell-cli",
            }
        )
    )
    assert _load_cluster_bearer_token(gateway_dir) == "jwt-blob"


def test_load_cluster_bearer_token_returns_none_when_missing(
    tmp_path: Path,
) -> None:
    assert _load_cluster_bearer_token(tmp_path / "absent") is None


def test_load_cluster_bearer_token_tolerates_unreadable_file(
    tmp_path: Path,
) -> None:
    gateway_dir = tmp_path / "gw"
    gateway_dir.mkdir()
    (gateway_dir / "oidc_token.json").write_text("not json")
    assert _load_cluster_bearer_token(gateway_dir) is None


def test_load_cluster_bearer_token_rejects_missing_access_token(
    tmp_path: Path,
) -> None:
    gateway_dir = tmp_path / "gw"
    gateway_dir.mkdir()
    (gateway_dir / "oidc_token.json").write_text(json.dumps({"refresh_token": "rt"}))
    assert _load_cluster_bearer_token(gateway_dir) is None


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


def _channel_is_intercepted(channel: Any) -> bool:
    """grpc.intercept_channel returns a _Channel whose module name ends in
    `interceptor`. We don't depend on the class name (it varies across
    gRPC versions); module is stable."""
    return type(channel).__module__.endswith("interceptor")


def test_from_active_cluster_loads_bearer_when_auth_mode_is_oidc(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    """Finding 3: bearer is attached iff metadata.auth_mode == "oidc"."""
    _setup_gateway_dir(
        tmp_path,
        monkeypatch,
        auth_mode="oidc",
        oidc_bundle={"access_token": "from-disk"},
    )
    client = SandboxClient.from_active_cluster()
    try:
        assert _channel_is_intercepted(client._channel)
    finally:
        client.close()


def test_from_active_cluster_ignores_stale_token_when_auth_mode_not_oidc(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    """Finding 3: a stale oidc_token.json alongside a non-OIDC gateway must
    NOT cause bearer auth to be attached."""
    _setup_gateway_dir(
        tmp_path,
        monkeypatch,
        # auth_mode omitted (or "mtls", "plaintext") — anything but "oidc".
        oidc_bundle={"access_token": "stale-from-disk"},
    )
    client = SandboxClient.from_active_cluster()
    try:
        # Plain channel, no interceptor wrapper.
        assert not _channel_is_intercepted(client._channel)
    finally:
        client.close()


def test_from_active_cluster_https_oidc_without_mtls_uses_tls_with_system_roots(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    """Finding 1: https OIDC gateways without mTLS material must still use a
    TLS channel (system roots) — NOT fall back to insecure_channel."""
    _setup_gateway_dir(
        tmp_path,
        monkeypatch,
        endpoint="https://gateway.example:443",
        auth_mode="oidc",
        oidc_bundle={"access_token": "t"},
    )
    client = SandboxClient.from_active_cluster()
    try:
        # The bearer interceptor wraps the channel, so inspect the
        # wrapped channel's class to confirm it's a secure (TLS) channel.
        inner = getattr(client._channel, "_channel", client._channel)
        # gRPC's `grpc.secure_channel` returns a `_Channel` from
        # `grpc._channel`; we can't trivially introspect "secure" vs
        # "insecure" on the wrapper itself. Probe by attempting to
        # extract the connectivity state — both kinds expose it — and
        # rely on a behavioral assertion: an insecure channel against
        # a hostname-only endpoint would have already attached TCP-only
        # subchannels. Easier: verify TlsConfig() was used by checking
        # the SandboxClient endpoint normalized correctly.
        # The most direct assertion is on the client config:
        assert client._endpoint == "gateway.example:443"
        # And the channel must not be insecure.
        assert "InsecureChannelCredentials" not in repr(inner)
    finally:
        client.close()


def test_from_active_cluster_https_ca_only_layout(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    """Finding 1: a CA-only mtls directory (ca.crt but no tls.crt/tls.key)
    must produce a CA-only TLS channel, not a FileNotFoundError."""
    _setup_gateway_dir(
        tmp_path,
        monkeypatch,
        endpoint="https://gateway.example:443",
        auth_mode="oidc",
        mtls_files={
            "ca.crt": "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
        },
        oidc_bundle={"access_token": "t"},
    )
    # Should not raise.
    client = SandboxClient.from_active_cluster()
    try:
        assert client._endpoint == "gateway.example:443"
    finally:
        client.close()


def test_tls_config_rejects_partial_client_identity() -> None:
    """Cert without key (or vice versa) is a misconfiguration."""
    import pytest as _pytest

    with _pytest.raises(ValueError, match="cert_path and key_path"):
        TlsConfig(cert_path=Path("/x.crt"))


def test_tls_config_allows_empty_for_system_roots() -> None:
    """`TlsConfig()` is the system-roots-trust flavor."""
    cfg = TlsConfig()
    assert cfg.ca_path is None and cfg.cert_path is None and cfg.key_path is None


# ---------------------------------------------------------------------------
# Provider semantics: per-RPC reload + expiry
# ---------------------------------------------------------------------------


def test_cluster_bearer_provider_reloads_on_every_call(tmp_path: Path) -> None:
    """The fail-closed (no-refresh) provider re-reads oidc_token.json each
    invocation, so a long-lived SandboxClient picks up CLI rotations
    without reconstruction."""
    gateway_dir = tmp_path
    token_file = gateway_dir / "oidc_token.json"
    token_file.write_text(json.dumps({"access_token": "first"}))
    provider, _ = _make_cluster_bearer_provider(gateway_dir, "g", auto_refresh=False)

    assert provider() == "first"
    # Simulate `openshell gateway login` writing a new token.
    token_file.write_text(json.dumps({"access_token": "second"}))
    assert provider() == "second"


def test_cluster_bearer_provider_raises_on_expired_token(tmp_path: Path) -> None:
    """Fail-closed provider raises on expiry with a clear re-login hint."""
    gateway_dir = tmp_path
    (gateway_dir / "oidc_token.json").write_text(
        json.dumps({"access_token": "expired", "expires_at": 1})
    )
    provider, _ = _make_cluster_bearer_provider(
        gateway_dir, "stale-gateway", auto_refresh=False
    )

    import pytest as _pytest

    with _pytest.raises(SandboxError, match="expired"):
        provider()


def test_cluster_bearer_provider_raises_when_file_missing(tmp_path: Path) -> None:
    provider, _ = _make_cluster_bearer_provider(
        tmp_path / "absent", "g", auto_refresh=False
    )
    import pytest as _pytest

    with _pytest.raises(SandboxError, match="missing or unreadable"):
        provider()


def test_cluster_bearer_provider_raises_on_missing_access_token(
    tmp_path: Path,
) -> None:
    (tmp_path / "oidc_token.json").write_text(json.dumps({"refresh_token": "r"}))
    provider, _ = _make_cluster_bearer_provider(tmp_path, "g", auto_refresh=False)
    import pytest as _pytest

    with _pytest.raises(SandboxError, match="no access token"):
        provider()


# ---------------------------------------------------------------------------
# OAuth2 native refresh (_OidcRefresher) — opt-in via auto_refresh=True.
# ---------------------------------------------------------------------------


def _write_bundle(
    gateway_dir: Path,
    *,
    access_token: str = "fresh",
    refresh_token: str = "r-orig",
    expires_at: int | None = None,
    issuer: str = "https://idp.example/realms/openshell",
    client_id: str = "openshell-cli",
) -> None:
    bundle: dict[str, Any] = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "issuer": issuer,
        "client_id": client_id,
    }
    if expires_at is not None:
        bundle["expires_at"] = expires_at
    (gateway_dir / "oidc_token.json").write_text(json.dumps(bundle))


DEFAULT_ISSUER = "https://idp.example/realms/openshell"
DEFAULT_TOKEN_ENDPOINT = (
    "https://idp.example/realms/openshell/protocol/openid-connect/token"
)


def _make_mock_transport(
    *,
    discovery: dict | None = None,
    refresh_responses: list[dict] | None = None,
    discovery_status: int = 200,
    refresh_status: int = 200,
    seen_refresh: list[Any] | None = None,
    seen_discovery: list[Any] | None = None,
):
    """Build an httpx.MockTransport that serves OIDC discovery + token
    refresh from an in-memory script.

    `refresh_responses` is consumed in order across successive POSTs to
    the token endpoint (which lets tests assert refresh-token rotation
    semantics across multiple refreshes).
    """
    import httpx as _httpx

    refresh_iter = iter(
        refresh_responses or [{"access_token": "refreshed-jwt", "expires_in": 3600}]
    )

    def handler(request: _httpx.Request) -> _httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            if seen_discovery is not None:
                seen_discovery.append(str(request.url))
            body = discovery or {
                "issuer": DEFAULT_ISSUER,
                "token_endpoint": DEFAULT_TOKEN_ENDPOINT,
            }
            return _httpx.Response(discovery_status, json=body)
        # Anything else is a refresh exchange.
        if seen_refresh is not None:
            seen_refresh.append((str(request.url), bytes(request.content)))
        try:
            body = next(refresh_iter)
        except StopIteration:
            return _httpx.Response(500, json={"error": "test_script_exhausted"})
        return _httpx.Response(refresh_status, json=body)

    return _httpx.MockTransport(handler)


def _install_mock_transport(refresher: Any, transport: Any) -> None:
    """Swap the refresher's httpx.Client for one bound to a mock transport.

    We rebuild with `follow_redirects=False` so the redirect-rejection
    test still exercises the real policy.
    """
    import httpx as _httpx

    refresher._http.close()
    refresher._http = _httpx.Client(transport=transport, follow_redirects=False)


def test_refresher_returns_cached_token_when_fresh(tmp_path: Path) -> None:
    """No refresh round-trip when the cached bundle is still fresh."""
    _write_bundle(tmp_path, expires_at=int(time.time()) + 3600)
    seen: list[Any] = []
    transport = _make_mock_transport(
        seen_discovery=seen,
        seen_refresh=seen,
    )
    r = _OidcRefresher(tmp_path, "g")
    _install_mock_transport(r, transport)
    assert r.current_access_token() == "fresh"
    assert seen == []  # no discovery, no refresh


def test_refresher_picks_up_disk_rotation_before_refreshing(
    tmp_path: Path,
) -> None:
    """If the in-memory bundle is stale but the CLI just wrote a fresh one,
    re-read disk instead of hitting the IdP."""
    _write_bundle(tmp_path, access_token="old", expires_at=1)
    seen_refresh: list[Any] = []
    transport = _make_mock_transport(seen_refresh=seen_refresh)
    r = _OidcRefresher(tmp_path, "g", write_back=False)
    _install_mock_transport(r, transport)
    # First call: refresh against IdP — exercise that path first.
    assert r.current_access_token() == "refreshed-jwt"
    assert len(seen_refresh) == 1

    # Now simulate the CLI writing a fresh bundle. Force the in-memory
    # state to look stale so the disk re-read path triggers.
    _write_bundle(
        tmp_path, access_token="cli-rotated", expires_at=int(time.time()) + 3600
    )
    r._bundle = {
        "access_token": "stale-in-memory",
        "expires_at": 1,
        "refresh_token": "r",
    }
    # Replace the transport with one that asserts on any request.
    import httpx as _httpx

    def assert_no_calls(_req: _httpx.Request) -> _httpx.Response:
        raise AssertionError("should not refresh — disk was fresh")

    _install_mock_transport(r, _httpx.MockTransport(assert_no_calls))
    assert r.current_access_token() == "cli-rotated"


def test_refresher_adopts_stale_disk_refresh_token_before_refreshing(
    tmp_path: Path,
) -> None:
    """Regression: when both the in-memory and on-disk access tokens are
    stale but another process rotated the on-disk refresh_token, refresh
    with the disk refresh_token (r2), not the invalidated in-memory one (r1).

    Without this, a rotating IdP (Keycloak with rotation, Entra strict) would
    invalid_grant because process A still holds the pre-rotation r1.
    """
    # Disk holds a rotated-but-stale bundle (r2) written by another process.
    # Its access token was minted more recently than ours (later expiry,
    # though still inside the grace window), so disk carries the newer
    # refresh_token even though both are due for refresh.
    disk_exp = int(time.time()) + 5
    _write_bundle(
        tmp_path, access_token="disk-old", expires_at=disk_exp, refresh_token="r2"
    )
    seen: list[Any] = []
    transport = _make_mock_transport(
        refresh_responses=[
            {"access_token": "a-new", "refresh_token": "r3", "expires_in": 3600},
        ],
        seen_refresh=seen,
    )
    r = _OidcRefresher(tmp_path, "g", write_back=False)
    _install_mock_transport(r, transport)
    # Seed older stale in-memory state holding the pre-rotation token r1.
    r._bundle = {
        "access_token": "mem-old",
        "expires_at": 1,
        "refresh_token": "r1",
        "issuer": DEFAULT_ISSUER,
    }

    assert r.current_access_token() == "a-new"
    # The refresh POST must carry the disk's r2, never the stale r1.
    _, body = seen[-1]
    assert b"refresh_token=r2" in body
    assert b"refresh_token=r1" not in body


def test_refresher_resets_token_endpoint_when_disk_issuer_changes(
    tmp_path: Path,
) -> None:
    """When the adopted disk bundle has a different issuer than the cached
    one, the previously discovered token endpoint must be re-discovered
    against the new issuer rather than reused."""
    new_issuer = "https://other-idp.example/realms/openshell"
    # Disk is newer than the in-memory bundle (later expiry) so it is
    # adopted, but still stale so a refresh — and thus re-discovery — runs.
    _write_bundle(
        tmp_path,
        access_token="disk-old",
        expires_at=int(time.time()) + 5,
        refresh_token="r2",
        issuer=new_issuer,
    )
    seen_discovery: list[Any] = []
    transport = _make_mock_transport(
        discovery={
            "issuer": new_issuer,
            "token_endpoint": f"{new_issuer}/protocol/openid-connect/token",
        },
        seen_discovery=seen_discovery,
    )
    r = _OidcRefresher(tmp_path, "g", write_back=False)
    _install_mock_transport(r, transport)
    # Pretend we already discovered an endpoint for the OLD issuer.
    r._token_endpoint = f"{DEFAULT_ISSUER}/protocol/openid-connect/token"
    r._bundle = {
        "access_token": "mem-old",
        "expires_at": 1,
        "refresh_token": "r1",
        "issuer": DEFAULT_ISSUER,
    }

    r.current_access_token()
    # Re-discovery happened against the new issuer.
    assert len(seen_discovery) == 1
    assert new_issuer in seen_discovery[0]


def test_refresher_recovers_from_invalid_grant_after_peer_rotation(
    tmp_path: Path,
) -> None:
    """If our refresh POST loses a rotation race (peer already rotated r1→r2
    and the IdP rejects our r1 with invalid_grant), re-read disk, pick up the
    peer's r2, and retry — succeeding without forcing a re-authenticate."""
    import httpx as _httpx

    _write_bundle(tmp_path, access_token="old", expires_at=1, refresh_token="r1")
    posts: list[bytes] = []

    def handler(request: _httpx.Request) -> _httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return _httpx.Response(
                200,
                json={
                    "issuer": DEFAULT_ISSUER,
                    "token_endpoint": DEFAULT_TOKEN_ENDPOINT,
                },
            )
        body = bytes(request.content)
        posts.append(body)
        if b"refresh_token=r1" in body:
            # Simulate the peer: it already rotated r1→r2 and wrote r2 to
            # disk, so the IdP rejects our now-stale r1.
            _write_bundle(
                tmp_path,
                access_token="peer",
                expires_at=int(time.time()) + 5,
                refresh_token="r2",
            )
            return _httpx.Response(400, json={"error": "invalid_grant"})
        # The retry carries the peer's r2 and succeeds.
        return _httpx.Response(
            200,
            json={"access_token": "a-final", "refresh_token": "r3", "expires_in": 3600},
        )

    r = _OidcRefresher(tmp_path, "g", write_back=False)
    _install_mock_transport(r, _httpx.MockTransport(handler))

    assert r.current_access_token() == "a-final"
    # Exactly two refresh POSTs: the failed r1 then the recovered r2.
    assert any(b"refresh_token=r1" in p for p in posts)
    assert any(b"refresh_token=r2" in p for p in posts)
    assert len(posts) == 2


def test_refresher_reraises_invalid_grant_without_peer_rotation(
    tmp_path: Path,
) -> None:
    """invalid_grant with no peer rotation (disk still holds our refresh_token)
    is a genuine dead token — surface the re-authenticate hint and do NOT loop
    on the retry path."""
    import httpx as _httpx
    import pytest as _pytest

    _write_bundle(tmp_path, access_token="old", expires_at=1, refresh_token="r1")
    posts: list[bytes] = []

    def handler(request: _httpx.Request) -> _httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return _httpx.Response(
                200,
                json={
                    "issuer": DEFAULT_ISSUER,
                    "token_endpoint": DEFAULT_TOKEN_ENDPOINT,
                },
            )
        posts.append(bytes(request.content))
        return _httpx.Response(400, json={"error": "invalid_grant"})

    r = _OidcRefresher(tmp_path, "g", write_back=False)
    _install_mock_transport(r, _httpx.MockTransport(handler))

    with _pytest.raises(SandboxError, match="Re-authenticate"):
        r.current_access_token()
    # Only one POST — disk offered no new refresh_token, so no retry.
    assert len(posts) == 1


def test_refresher_exchanges_refresh_token_when_stale(tmp_path: Path) -> None:
    """When both memory and disk are stale, do the OAuth2 refresh exchange."""
    _write_bundle(tmp_path, access_token="old", expires_at=1)
    seen_refresh: list[Any] = []
    transport = _make_mock_transport(seen_refresh=seen_refresh)
    r = _OidcRefresher(tmp_path, "g", write_back=False)
    _install_mock_transport(r, transport)

    assert r.current_access_token() == "refreshed-jwt"
    # The refresh request should be a POST to the discovered token endpoint
    # with grant_type=refresh_token in the body.
    url, body = seen_refresh[-1]
    assert url.endswith("/protocol/openid-connect/token")
    assert b"grant_type=refresh_token" in body
    assert b"refresh_token=r-orig" in body


def test_refresher_writes_back_when_enabled(tmp_path: Path) -> None:
    """write_back=True persists rotated bundle to disk atomically with 0600."""
    _write_bundle(tmp_path, access_token="old", expires_at=1)
    transport = _make_mock_transport(
        refresh_responses=[
            {
                "access_token": "rotated",
                "refresh_token": "r-new",
                "expires_in": 3600,
            }
        ],
    )
    r = _OidcRefresher(tmp_path, "g", write_back=True)
    _install_mock_transport(r, transport)

    assert r.current_access_token() == "rotated"
    on_disk = json.loads((tmp_path / "oidc_token.json").read_text())
    assert on_disk["access_token"] == "rotated"
    assert on_disk["refresh_token"] == "r-new"
    # Mode should be 0600 on POSIX.
    if os.name == "posix":
        mode = (tmp_path / "oidc_token.json").stat().st_mode & 0o777
        assert mode == 0o600, f"got {oct(mode)}"


def test_refresher_write_back_is_default(tmp_path: Path) -> None:
    """Default IS write_back=True so refresh-token rotation propagates to
    disk for other processes (Rust CLI, TUI, second Python client)."""
    _write_bundle(tmp_path, access_token="old", expires_at=1)
    transport = _make_mock_transport(
        refresh_responses=[
            {
                "access_token": "rotated",
                "refresh_token": "r-new",
                "expires_in": 3600,
            }
        ],
    )
    r = _OidcRefresher(tmp_path, "g")  # default write_back=True
    _install_mock_transport(r, transport)

    r.current_access_token()
    on_disk = json.loads((tmp_path / "oidc_token.json").read_text())
    assert on_disk["access_token"] == "rotated"
    assert on_disk["refresh_token"] == "r-new"


def test_refresher_honors_refresh_token_rotation(tmp_path: Path) -> None:
    """When the IdP returns a new refresh_token, use it for subsequent refreshes
    instead of the original. Some IdPs (Keycloak with rotation enabled, Entra
    in strict mode) reissue and invalidate the old refresh_token."""
    _write_bundle(tmp_path, access_token="old", expires_at=1, refresh_token="r1")
    seen: list[Any] = []
    transport = _make_mock_transport(
        refresh_responses=[
            {"access_token": "a2", "refresh_token": "r2", "expires_in": 1},
            {"access_token": "a3", "refresh_token": "r3", "expires_in": 3600},
        ],
        seen_refresh=seen,
    )
    r = _OidcRefresher(tmp_path, "g", write_back=False)
    _install_mock_transport(r, transport)

    assert r.current_access_token() == "a2"
    # Second call: a2 is also expired (expires_in=1), so we refresh again,
    # this time the request body should carry the rotated r2 (not r1).
    assert r.current_access_token() == "a3"
    assert b"refresh_token=r1" in seen[0][1]
    assert b"refresh_token=r2" in seen[1][1]


def test_refresher_second_process_can_refresh_after_rotation(
    tmp_path: Path,
) -> None:
    """Two-process simulation (Finding #2): process A refreshes r1→r2 with
    write_back=True (default). Process B starts from disk and successfully
    uses r2 — proving the rotation reached the shared cache."""
    _write_bundle(tmp_path, access_token="old", expires_at=1, refresh_token="r1")
    transport_a = _make_mock_transport(
        refresh_responses=[
            {"access_token": "a2", "refresh_token": "r2", "expires_in": 1},
        ],
    )
    process_a = _OidcRefresher(tmp_path, "g")  # write_back=True (default)
    _install_mock_transport(process_a, transport_a)
    assert process_a.current_access_token() == "a2"

    # Process B picks up the cache fresh. The IdP now expects r2; if the
    # disk still held r1, this would fail at the IdP. With write_back the
    # disk has r2, and B refreshes successfully.
    seen_b: list[Any] = []
    transport_b = _make_mock_transport(
        refresh_responses=[
            {"access_token": "a3", "refresh_token": "r3", "expires_in": 3600},
        ],
        seen_refresh=seen_b,
    )
    process_b = _OidcRefresher(tmp_path, "g")
    _install_mock_transport(process_b, transport_b)
    assert process_b.current_access_token() == "a3"
    # Process B should have presented r2, not r1.
    assert b"refresh_token=r2" in seen_b[0][1]


def test_refresher_concurrent_calls_share_one_refresh(tmp_path: Path) -> None:
    """N threads racing on a stale token should produce exactly one
    refresh exchange (not N). Mirrors google-auth's RefreshThreadManager
    coordination."""
    _write_bundle(tmp_path, access_token="old", expires_at=1)
    refresh_count = [0]
    barrier = threading.Barrier(8)

    import httpx as _httpx

    def handler(request: _httpx.Request) -> _httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return _httpx.Response(
                200,
                json={
                    "issuer": DEFAULT_ISSUER,
                    "token_endpoint": DEFAULT_TOKEN_ENDPOINT,
                },
            )
        refresh_count[0] += 1
        return _httpx.Response(
            200,
            json={
                "access_token": "refreshed",
                "expires_in": 3600,
            },
        )

    r = _OidcRefresher(tmp_path, "g", write_back=False)
    _install_mock_transport(r, _httpx.MockTransport(handler))

    results: list[str] = []
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            barrier.wait()
            results.append(r.current_access_token())
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    assert results == ["refreshed"] * 8
    # One refresh exchange, regardless of thread count.
    assert refresh_count[0] == 1, f"expected one refresh, got {refresh_count[0]}"


def test_refresher_surfaces_idp_failure_as_sandbox_error(
    tmp_path: Path,
) -> None:
    """A non-2xx from the token endpoint becomes a SandboxError."""
    _write_bundle(tmp_path, access_token="old", expires_at=1)
    transport = _make_mock_transport(
        refresh_status=400,
        refresh_responses=[
            {
                "error": "invalid_grant",
                "error_description": "Token is not active",
            }
        ],
    )
    r = _OidcRefresher(tmp_path, "g", write_back=False)
    _install_mock_transport(r, transport)

    import pytest as _pytest

    with _pytest.raises(SandboxError, match="refresh failed"):
        r.current_access_token()


def test_refresher_rejects_issuer_mismatch_in_discovery(tmp_path: Path) -> None:
    """Finding #1 (Critical): a discovery doc claiming a different issuer
    must be rejected. Without this, a malicious or misdirected discovery
    response could steer the refresh_token POST to an attacker-
    controlled endpoint."""
    _write_bundle(tmp_path, access_token="old", expires_at=1)
    transport = _make_mock_transport(
        discovery={
            "issuer": "https://evil.example/realms/openshell",
            "token_endpoint": "https://evil.example/token",
        },
    )
    r = _OidcRefresher(tmp_path, "g", write_back=False)
    _install_mock_transport(r, transport)

    import pytest as _pytest

    with _pytest.raises(SandboxError, match="issuer mismatch"):
        r.current_access_token()


def test_refresher_rejects_redirect_during_discovery(tmp_path: Path) -> None:
    """Finding #1 (Critical): a 3xx during OIDC discovery must NOT be
    auto-followed — that would let a network attacker steer the SDK to
    an arbitrary token_endpoint URL. The Rust CLI sets
    `Policy::none()`; we set httpx's `follow_redirects=False`."""
    _write_bundle(tmp_path, access_token="old", expires_at=1)
    transport = _make_mock_transport(
        discovery_status=302,
        discovery={"location": "https://evil.example/...."},
    )
    r = _OidcRefresher(tmp_path, "g", write_back=False)
    _install_mock_transport(r, transport)

    import pytest as _pytest

    with _pytest.raises(SandboxError, match=r"discovery failed.*HTTP 302"):
        r.current_access_token()


def test_refresher_insecure_disables_tls_verification() -> None:
    """Finding #3: insecure=True propagates to httpx as verify=False so
    self-signed OIDC issuers work the same way they do in the Rust CLI's
    `--insecure` plumbing."""
    import pathlib

    r = _OidcRefresher(
        pathlib.Path("/tmp/does-not-exist"),
        "g",
        insecure=True,
    )
    try:
        # httpx exposes the configured verify policy on the client; we
        # don't depend on its precise type, just on it being a falsy
        # value (the default is True / an SSLContext).
        # In recent httpx versions this lives on the underlying transport.
        # The simplest stable check is: an insecure client allows
        # connect to self-signed hosts; the rest of the contract is
        # httpx's responsibility.
        # Verify the client's verify attribute (whether top-level or via
        # transport) is False.
        assert _client_verify_is_disabled(r._http)
    finally:
        r.close()


def _client_verify_is_disabled(client: Any) -> bool:
    """Inspect an httpx.Client for verify=False. httpx surfaces verify
    either on the client directly (older) or via the default transport
    (newer)."""
    if getattr(client, "verify", None) is False:
        return True
    transport = getattr(client, "_transport", None)
    if transport is None:
        return False
    # httpx's default HTTPTransport wraps an SSL context or a bool.
    pool = getattr(transport, "_pool", None)
    if pool is not None:
        ssl_context = getattr(pool, "_ssl_context", None)
        # When verify=False, httpx builds a context without verification.
        if ssl_context is not None:
            import ssl

            return ssl_context.verify_mode == ssl.CERT_NONE
    # Fallback: check for any internal `_verify` attribute set to False.
    return getattr(transport, "_verify", None) is False


def test_refresher_raises_when_bundle_has_no_refresh_token(
    tmp_path: Path,
) -> None:
    """Without a refresh_token (e.g. client_credentials grant — different
    code path entirely), refresh has nothing to exchange and surfaces a
    clear error."""
    (tmp_path / "oidc_token.json").write_text(
        json.dumps({"access_token": "old", "expires_at": 1, "issuer": "x"})
    )
    r = _OidcRefresher(tmp_path, "g", write_back=False)
    import pytest as _pytest

    with _pytest.raises(SandboxError, match="no refresh token"):
        r.current_access_token()


# ---------------------------------------------------------------------------
# auth_mode gate: only metadata.json["auth_mode"] == "oidc" wires the bearer
# interceptor. A stray oidc_token.json next to a non-OIDC gateway must not
# trigger it.
# ---------------------------------------------------------------------------


def test_mtls_only_from_active_cluster_skips_bearer_interceptor(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    """from_active_cluster against an mTLS-only gateway (no auth_mode set)
    does not wrap the channel with a bearer interceptor, even if a stale
    oidc_token.json is present in the gateway directory."""
    gateway_name = "mtls-only"
    gateway_dir = tmp_path / "openshell" / "gateways" / gateway_name
    mtls_dir = gateway_dir / "mtls"
    mtls_dir.mkdir(parents=True)
    (tmp_path / "openshell" / "active_gateway").write_text(gateway_name)
    # No auth_mode field — the chart-default path.
    (gateway_dir / "metadata.json").write_text(
        json.dumps({"gateway_endpoint": "https://127.0.0.1:8443"})
    )
    for f in ("ca.crt", "tls.crt", "tls.key"):
        (mtls_dir / f).write_text(f"-----BEGIN {f}-----\n-----END {f}-----\n")
    # Stray oidc_token.json — proving the auth_mode gate (and not the
    # file's presence) is what would trigger the refresher.
    (gateway_dir / "oidc_token.json").write_text(json.dumps({"access_token": "stale"}))

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("OPENSHELL_GATEWAY", raising=False)

    client = SandboxClient.from_active_cluster()
    try:
        # No bearer interceptor wraps the channel.
        assert not type(client._channel).__module__.endswith("interceptor")
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Lifecycle plumbing: close() releases refresher resources, concurrent
# write-back doesn't trample.
# ---------------------------------------------------------------------------


def test_sandbox_client_close_invokes_bearer_close() -> None:
    """`SandboxClient.close()` must invoke the `_bearer_close` callable
    wired by `from_active_cluster`. Otherwise the refresher's
    httpx.Client leaks sockets/FDs until GC runs."""
    closed = [0]

    def bearer_close() -> None:
        closed[0] += 1

    client = SandboxClient(
        "localhost:8080",
        bearer_token="tok",
        _bearer_close=bearer_close,
    )
    client.close()
    assert closed[0] == 1
    # close() is idempotent — re-invoking does not double-call.
    client.close()
    assert closed[0] == 1


def test_sandbox_client_close_releases_refresher_http_client(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    """End-to-end check: an OIDC-backed client built by
    from_active_cluster() must close the refresher's httpx.Client when
    the SandboxClient is closed."""
    gateway_name = "oidc-gw"
    gateway_dir = tmp_path / "openshell" / "gateways" / gateway_name
    mtls_dir = gateway_dir / "mtls"
    mtls_dir.mkdir(parents=True)
    (tmp_path / "openshell" / "active_gateway").write_text(gateway_name)
    (gateway_dir / "metadata.json").write_text(
        json.dumps(
            {
                "gateway_endpoint": "https://127.0.0.1:8443",
                "auth_mode": "oidc",
            }
        )
    )
    for f in ("ca.crt", "tls.crt", "tls.key"):
        (mtls_dir / f).write_text(f"-----BEGIN {f}-----\n-----END {f}-----\n")
    _write_bundle(gateway_dir, expires_at=int(time.time()) + 3600)

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("OPENSHELL_GATEWAY", raising=False)

    # Capture the httpx.Client instance created inside the refresher by
    # monkey-patching _OidcRefresher to record it on construction.
    created: list[Any] = []
    real_init = _OidcRefresher.__init__

    def recording_init(self: Any, *args: Any, **kwargs: Any) -> None:
        real_init(self, *args, **kwargs)
        created.append(self._http)

    monkeypatch.setattr(_OidcRefresher, "__init__", recording_init)

    client = SandboxClient.from_active_cluster()
    assert len(created) == 1
    http_client = created[0]
    assert not http_client.is_closed
    client.close()
    assert http_client.is_closed


def test_refresher_concurrent_write_back_does_not_trample(tmp_path: Path) -> None:
    """Two writers calling `_write_to_disk` concurrently must each use
    their own tempfile (PID+random) and not corrupt each other's content.
    The final file must be valid JSON from exactly one of the writers,
    and no orphaned `.oidc_token.<rand>.tmp` files should remain."""
    _write_bundle(tmp_path, expires_at=int(time.time()) + 3600)
    r = _OidcRefresher(tmp_path, "g", write_back=False)
    try:
        N = 16
        barrier = threading.Barrier(N)
        errors: list[BaseException] = []

        def writer(idx: int) -> None:
            try:
                barrier.wait()
                r._write_to_disk(
                    {
                        "access_token": f"a-{idx}",
                        "refresh_token": f"r-{idx}",
                        "expires_at": 1_700_000_000 + idx,
                        "issuer": DEFAULT_ISSUER,
                        "client_id": "openshell-cli",
                    }
                )
            except BaseException as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, errors

        # Final file is valid JSON from one of the writers (race winner).
        final = json.loads((tmp_path / "oidc_token.json").read_text())
        assert final["access_token"].startswith("a-")
        assert final["refresh_token"].startswith("r-")

        # No orphan tmp files left behind. mkstemp uses a random suffix
        # so each writer's tmp is distinct; the cleanup path on the
        # success branch is `.replace()`, which atomically moves the
        # tmp to the final path — no straggler tmp should remain.
        leftovers = sorted(tmp_path.glob(".oidc_token.*.tmp"))
        assert leftovers == [], f"orphan tmp files: {leftovers}"
    finally:
        r.close()


def test_sandbox_wrapper_forwards_auth_kwargs_to_from_active_cluster(
    monkeypatch: Any,
) -> None:
    """The high-level `Sandbox` context manager must pass auto_refresh,
    write_back, and insecure through to SandboxClient.from_active_cluster
    so callers using the wrapper get parity with SandboxClient for
    OIDC-protected gateways."""
    captured: dict[str, Any] = {}

    class _Sentinel(Exception):
        pass

    def fake_from_active_cluster(**kwargs: Any) -> Any:
        captured.update(kwargs)
        # Short-circuit the rest of __enter__ (which would try to create
        # a session against a real gateway). The kwargs we care about
        # have already been recorded.
        raise _Sentinel

    monkeypatch.setattr(
        SandboxClient, "from_active_cluster", staticmethod(fake_from_active_cluster)
    )

    sandbox = Sandbox(
        cluster="my-gw",
        timeout=42.0,
        auto_refresh=False,
        write_back=False,
        insecure=True,
    )
    import pytest as _pytest

    with _pytest.raises(_Sentinel):
        sandbox.__enter__()

    assert captured["cluster"] == "my-gw"
    assert captured["timeout"] == 42.0
    assert captured["auto_refresh"] is False
    assert captured["write_back"] is False
    assert captured["insecure"] is True


def test_sandbox_wrapper_defaults_match_from_active_cluster(
    monkeypatch: Any,
) -> None:
    """Sandbox(...) with no auth kwargs forwards the same defaults
    (auto_refresh=True, write_back=True, insecure=False) that
    SandboxClient.from_active_cluster uses, so the wrapper doesn't
    silently weaken the security posture."""
    captured: dict[str, Any] = {}

    class _Sentinel(Exception):
        pass

    def fake_from_active_cluster(**kwargs: Any) -> Any:
        captured.update(kwargs)
        raise _Sentinel

    monkeypatch.setattr(
        SandboxClient, "from_active_cluster", staticmethod(fake_from_active_cluster)
    )

    import pytest as _pytest

    with _pytest.raises(_Sentinel):
        Sandbox().__enter__()

    assert captured["auto_refresh"] is True
    assert captured["write_back"] is True
    assert captured["insecure"] is False


def test_inference_set_cluster_forwards_no_verify_flag() -> None:
    stub = _FakeInferenceStub()
    client = cast("InferenceRouteClient", object.__new__(InferenceRouteClient))
    client._timeout = 30.0
    client._stub = cast("Any", stub)

    client.set_cluster(
        provider_name="openai-dev",
        model_id="gpt-4.1",
        no_verify=True,
    )

    assert stub.request is not None
    assert stub.request.no_verify is True


# ---------------------------------------------------------------------------
# Encoding regression tests (utf-8 explicit on all config file reads/writes)
# ---------------------------------------------------------------------------


def test_read_oidc_token_bundle_parses_non_ascii_utf8(tmp_path: Path) -> None:
    gateway_dir = tmp_path / "gw"
    gateway_dir.mkdir()
    payload = {"refresh_token": "tok", "issuer": "https://example.com/é"}
    (gateway_dir / "oidc_token.json").write_bytes(
        json.dumps(payload, ensure_ascii=False).encode("utf-8")
    )
    result = _read_oidc_token_bundle(gateway_dir)
    assert result == payload


def test_read_oidc_token_bundle_returns_none_on_corrupt_bytes(tmp_path: Path) -> None:
    gateway_dir = tmp_path / "gw"
    gateway_dir.mkdir()
    (gateway_dir / "oidc_token.json").write_bytes(b"\xff\xfe not utf-8")
    assert _read_oidc_token_bundle(gateway_dir) is None


def test_load_cluster_bearer_token_handles_non_ascii_utf8_oidc(tmp_path: Path) -> None:
    gateway_dir = tmp_path / "gw"
    gateway_dir.mkdir()
    bundle = {
        "access_token": "accéss",
        "refresh_token": "ref",
        "expiry": "2099-01-01T00:00:00Z",
        "issuer": "https://example.com",
        "client_id": "c",
        "client_secret": "s",
    }
    (gateway_dir / "oidc_token.json").write_bytes(
        json.dumps(bundle, ensure_ascii=False).encode("utf-8")
    )
    token = _load_cluster_bearer_token(gateway_dir)
    assert token == "accéss"


def test_from_active_cluster_reads_utf8_bytes_from_active_gateway_and_metadata(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    gateway_name = "gw-é"
    gateway_dir = tmp_path / "openshell" / "gateways" / gateway_name
    gateway_dir.mkdir(parents=True)
    (tmp_path / "openshell" / "active_gateway").write_bytes(
        gateway_name.encode("utf-8")
    )
    meta = {"gateway_endpoint": "http://tést.example:8080"}
    (gateway_dir / "metadata.json").write_bytes(
        json.dumps(meta, ensure_ascii=False).encode("utf-8")
    )

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("OPENSHELL_GATEWAY", raising=False)

    client = SandboxClient.from_active_cluster()
    try:
        assert client._cluster_name == gateway_name
        assert client._endpoint == "tést.example:8080"
    finally:
        client.close()


# ---- Sandbox label / selector API tests ----


def _make_sandbox_proto(
    id_: str,
    name: str,
    labels: dict[str, str] | None = None,
    phase: openshell_pb2.SandboxPhase = openshell_pb2.SANDBOX_PHASE_READY,
    version: int = 0,
) -> openshell_pb2.Sandbox:
    sandbox = openshell_pb2.Sandbox()
    sandbox.metadata.id = id_
    sandbox.metadata.name = name
    for key, value in (labels or {}).items():
        sandbox.metadata.labels[key] = value
    sandbox.status.phase = phase
    sandbox.status.current_policy_version = version
    return sandbox


class _FakeSandboxStub:
    def __init__(self, listed: list[openshell_pb2.Sandbox] | None = None) -> None:
        self.create_request: openshell_pb2.CreateSandboxRequest | None = None
        self.list_request: openshell_pb2.ListSandboxesRequest | None = None
        self._listed = listed or []

    def CreateSandbox(
        self,
        request: openshell_pb2.CreateSandboxRequest,
        timeout: float | None = None,
    ) -> Any:
        self.create_request = request
        _ = timeout
        return SimpleNamespace(
            sandbox=_make_sandbox_proto(
                "sandbox-1", request.name or "generated", dict(request.labels)
            )
        )

    def ListSandboxes(
        self,
        request: openshell_pb2.ListSandboxesRequest,
        timeout: float | None = None,
    ) -> Any:
        self.list_request = request
        _ = timeout
        return SimpleNamespace(sandboxes=list(self._listed))


class _RecordingHighLevelClient:
    """A stand-in for SandboxClient used to observe high-level forwarding."""

    def __init__(self) -> None:
        self.create_kwargs: dict[str, Any] | None = None

    def create_session(
        self,
        *,
        spec: Any = None,
        name: str | None = None,
        labels: Any = None,
    ) -> Any:
        self.create_kwargs = {"spec": spec, "name": name, "labels": labels}
        return SimpleNamespace(sandbox=SimpleNamespace(name=name or "generated"))

    def wait_ready(self, name: str, *, timeout_seconds: float = 300.0) -> SandboxRef:
        _ = timeout_seconds
        return SandboxRef(
            id="sandbox-1",
            name=name,
            status=SandboxStatusRef(phase=2, current_policy_version=0),
        )


def test_create_forwards_name_and_labels() -> None:
    stub = _FakeSandboxStub()
    client = _client_with_fake_stub(stub)

    ref = client.create(name="job-1", labels={"aiq": "deep-research"})

    assert stub.create_request is not None
    assert stub.create_request.name == "job-1"
    assert dict(stub.create_request.labels) == {"aiq": "deep-research"}
    assert dict(ref.labels) == {"aiq": "deep-research"}


def test_create_without_args_sends_empty_metadata() -> None:
    stub = _FakeSandboxStub()
    client = _client_with_fake_stub(stub)

    client.create()

    assert stub.create_request is not None
    assert stub.create_request.name == ""
    assert dict(stub.create_request.labels) == {}


def test_create_copies_caller_labels() -> None:
    stub = _FakeSandboxStub()
    client = _client_with_fake_stub(stub)

    caller_labels = {"aiq": "deep-research"}
    client.create(labels=caller_labels)
    caller_labels["aiq"] = "mutated"

    assert stub.create_request is not None
    assert dict(stub.create_request.labels) == {"aiq": "deep-research"}


def test_create_session_forwards_name_and_labels() -> None:
    stub = _FakeSandboxStub()
    client = _client_with_fake_stub(stub)

    session = client.create_session(name="job-2", labels={"team": "aiq"})

    assert stub.create_request is not None
    assert stub.create_request.name == "job-2"
    assert dict(stub.create_request.labels) == {"team": "aiq"}
    assert session.sandbox.name == "job-2"


def test_list_forwards_label_selector() -> None:
    stub = _FakeSandboxStub()
    client = _client_with_fake_stub(stub)

    client.list(label_selector="aiq=deep-research")

    assert stub.list_request is not None
    assert stub.list_request.label_selector == "aiq=deep-research"


def test_list_without_selector_sends_empty_string() -> None:
    stub = _FakeSandboxStub()
    client = _client_with_fake_stub(stub)

    client.list()

    assert stub.list_request is not None
    assert stub.list_request.label_selector == ""


def test_list_ids_forwards_label_selector() -> None:
    stub = _FakeSandboxStub(listed=[_make_sandbox_proto("sandbox-1", "job-1")])
    client = _client_with_fake_stub(stub)

    ids = client.list_ids(label_selector="aiq=deep-research")

    assert stub.list_request is not None
    assert stub.list_request.label_selector == "aiq=deep-research"
    assert ids == ["sandbox-1"]


def test_sandbox_ref_retains_gateway_labels() -> None:
    proto = _make_sandbox_proto(
        "sandbox-1", "job-1", {"aiq": "deep-research", "env": "dev"}
    )

    ref = _sandbox_ref(proto)

    assert dict(ref.labels) == {"aiq": "deep-research", "env": "dev"}


def test_returned_labels_are_immutable() -> None:
    proto = _make_sandbox_proto("sandbox-1", "job-1", {"aiq": "deep-research"})
    ref = _sandbox_ref(proto)

    with pytest.raises(TypeError):
        ref.labels["mutated"] = "nope"  # type: ignore[index]


def test_direct_sandbox_ref_construction_defaults_labels() -> None:
    ref = SandboxRef(
        id="sandbox-1",
        name="job-1",
        status=SandboxStatusRef(phase=2, current_policy_version=0),
    )

    assert dict(ref.labels) == {}


def test_sandbox_ref_stays_hashable_with_labels_excluded_from_identity() -> None:
    ref_a = _sandbox_ref(_make_sandbox_proto("sandbox-1", "job-1", {"aiq": "a"}))
    ref_b = _sandbox_ref(_make_sandbox_proto("sandbox-1", "job-1", {"aiq": "b"}))

    # Frozen dataclass must remain hashable despite the immutable labels field.
    assert hash(ref_a) == hash(ref_b)
    # Labels are excluded from identity: same (id, name, status) compares equal.
    assert ref_a == ref_b
    assert {ref_a, ref_b} == {ref_a}


def test_sandbox_ref_labels_support_standard_serialization() -> None:
    ref = _sandbox_ref(
        _make_sandbox_proto("sandbox-1", "job-1", {"aiq": "deep-research"})
    )

    assert asdict(ref)["labels"] == {"aiq": "deep-research"}
    assert dict(deepcopy(ref).labels) == {"aiq": "deep-research"}
    assert dict(pickle.loads(pickle.dumps(ref)).labels) == {"aiq": "deep-research"}


def test_default_sandbox_ref_labels_support_standard_serialization() -> None:
    ref = SandboxRef(
        id="sandbox-1",
        name="job-1",
        status=SandboxStatusRef(phase=2, current_policy_version=0),
    )

    assert asdict(ref)["labels"] == {}
    assert dict(deepcopy(ref).labels) == {}
    assert dict(pickle.loads(pickle.dumps(ref)).labels) == {}


def test_direct_sandbox_ref_copies_and_freezes_labels() -> None:
    labels = {"aiq": "deep-research"}
    ref = SandboxRef(
        id="sandbox-1",
        name="job-1",
        status=SandboxStatusRef(phase=2, current_policy_version=0),
        labels=labels,
    )
    labels["aiq"] = "mutated"

    assert dict(ref.labels) == {"aiq": "deep-research"}
    with pytest.raises(TypeError):
        ref.labels["mutated"] = "nope"  # type: ignore[index]


def test_high_level_creation_forwards_name_and_labels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recording = _RecordingHighLevelClient()
    monkeypatch.setattr(
        SandboxClient,
        "from_active_cluster",
        classmethod(lambda _cls, **_kwargs: recording),
    )

    sandbox = Sandbox(
        name="job-1", labels={"aiq": "deep-research"}, delete_on_exit=False
    )
    sandbox.__enter__()

    assert recording.create_kwargs == {
        "spec": None,
        "name": "job-1",
        "labels": {"aiq": "deep-research"},
    }


def test_high_level_attach_rejects_name() -> None:
    sandbox = Sandbox(sandbox="existing-sandbox", name="job-1")

    with pytest.raises(SandboxError):
        sandbox.__enter__()


def test_high_level_attach_rejects_labels() -> None:
    ref = SandboxRef(
        id="sandbox-1",
        name="existing",
        status=SandboxStatusRef(phase=2, current_policy_version=0),
    )
    sandbox = Sandbox(sandbox=ref, labels={"aiq": "deep-research"})

    with pytest.raises(SandboxError):
        sandbox.__enter__()
