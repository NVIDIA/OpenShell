# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""End-to-end tests for OIDC authentication, RBAC, and scope enforcement.

These tests require:
- A running K3s cluster with OIDC enabled (OPENSHELL_OIDC_ISSUER set)
- A running Keycloak instance with the openshell realm
- The cluster started with OPENSHELL_OIDC_SCOPES_CLAIM=scope

Skip condition: set OPENSHELL_E2E_OIDC=1 to enable these tests.
"""

from __future__ import annotations

import contextlib
import json
import os
import urllib.parse
import urllib.request
from pathlib import Path

import grpc
import pytest

from openshell._proto import datamodel_pb2, openshell_pb2, openshell_pb2_grpc

KEYCLOAK_REALM = "openshell"


def _xdg_config_home() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))


def _keycloak_url() -> str:
    """Derive the Keycloak URL from the gateway's stored OIDC issuer.

    The server validates the issuer claim in JWTs, so the token must be
    requested from the same base URL the server was configured with
    (typically the host IP, not localhost).
    """
    if url := os.environ.get("OPENSHELL_KEYCLOAK_URL"):
        return url
    cluster_name = os.environ.get("OPENSHELL_GATEWAY", "openshell")
    metadata_path = (
        _xdg_config_home() / "openshell" / "gateways" / cluster_name / "metadata.json"
    )
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text())
        issuer = metadata.get("oidc_issuer", "")
        if issuer:
            # issuer is like "http://192.168.4.172:8180/realms/openshell"
            # extract base URL before /realms/
            idx = issuer.find("/realms/")
            if idx > 0:
                return issuer[:idx]
    return "http://localhost:8180"


TOKEN_ENDPOINT = (
    f"{_keycloak_url()}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
)

pytestmark = pytest.mark.skipif(
    os.environ.get("OPENSHELL_E2E_OIDC") != "1",
    reason="OIDC e2e tests disabled (set OPENSHELL_E2E_OIDC=1)",
)


def _gateway_endpoint() -> tuple[str, bool]:
    """Read the active gateway endpoint from metadata."""
    cluster_name = os.environ.get("OPENSHELL_GATEWAY", "openshell")
    metadata_path = (
        _xdg_config_home() / "openshell" / "gateways" / cluster_name / "metadata.json"
    )
    metadata = json.loads(metadata_path.read_text())
    endpoint = metadata["gateway_endpoint"]
    is_tls = endpoint.startswith("https://")
    return endpoint, is_tls


def _mtls_dir() -> Path:
    cluster_name = os.environ.get("OPENSHELL_GATEWAY", "openshell")
    return _xdg_config_home() / "openshell" / "gateways" / cluster_name / "mtls"


def _token_request(data: dict[str, str]) -> str:
    """POST to the Keycloak token endpoint and return the access token."""
    encoded = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(TOKEN_ENDPOINT, data=encoded)
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = json.loads(resp.read())
    return body["access_token"]


def _get_token(
    username: str,
    password: str,
    *,
    client_id: str = "openshell-cli",
    scopes: str | None = None,
) -> str:
    """Get an access token from Keycloak via password grant."""
    data = {
        "grant_type": "password",
        "client_id": client_id,
        "username": username,
        "password": password,
    }
    if scopes:
        data["scope"] = scopes
    return _token_request(data)


def _get_ci_token(
    *,
    client_id: str = "openshell-ci",
    client_secret: str = "ci-test-secret",
) -> str:
    """Get an access token via client credentials grant."""
    return _token_request(
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
    )


def _grpc_channel() -> grpc.Channel:
    """Create a gRPC channel to the gateway with mTLS transport."""
    endpoint, is_tls = _gateway_endpoint()
    parsed = urllib.parse.urlparse(endpoint)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if is_tls else 80)
    target = f"{host}:{port}"

    if is_tls:
        mtls = _mtls_dir()
        ca_cert = (mtls / "ca.crt").read_bytes()
        client_cert = (mtls / "tls.crt").read_bytes()
        client_key = (mtls / "tls.key").read_bytes()
        creds = grpc.ssl_channel_credentials(
            root_certificates=ca_cert,
            private_key=client_key,
            certificate_chain=client_cert,
        )
        return grpc.secure_channel(target, creds)
    return grpc.insecure_channel(target)


def _stub_with_token(token: str) -> openshell_pb2_grpc.OpenShellStub:
    """Create a gRPC stub that injects a Bearer token."""
    channel = _grpc_channel()
    return openshell_pb2_grpc.OpenShellStub(channel), [
        ("authorization", f"Bearer {token}")
    ]


# ── RBAC Tests ────────────────────────────────────────────────────────


class TestRbac:
    """Test role-based access control."""

    def test_admin_can_create_provider(self) -> None:
        token = _get_token("admin@test", "admin", scopes="openid openshell:all")
        stub, metadata = _stub_with_token(token)
        req = openshell_pb2.CreateProviderRequest(
            provider=datamodel_pb2.Provider(
                name="e2e-oidc-admin-test",
                type="claude",
                credentials={"API_KEY": "test-value"},
            )
        )
        try:
            stub.CreateProvider(req, metadata=metadata)
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.ALREADY_EXISTS:
                pass  # fine, provider exists from a previous run
            else:
                raise
        finally:
            with contextlib.suppress(grpc.RpcError):
                stub.DeleteProvider(
                    openshell_pb2.DeleteProviderRequest(name="e2e-oidc-admin-test"),
                    metadata=metadata,
                )

    def test_user_cannot_create_provider(self) -> None:
        token = _get_token("user@test", "user", scopes="openid openshell:all")
        stub, metadata = _stub_with_token(token)
        req = openshell_pb2.CreateProviderRequest(
            provider=datamodel_pb2.Provider(
                name="e2e-oidc-user-blocked",
                type="claude",
                credentials={"API_KEY": "test-value"},
            )
        )
        with pytest.raises(grpc.RpcError) as exc_info:
            stub.CreateProvider(req, metadata=metadata)
        assert exc_info.value.code() == grpc.StatusCode.PERMISSION_DENIED
        assert "openshell-admin" in exc_info.value.details()

    def test_user_can_list_sandboxes(self) -> None:
        token = _get_token("user@test", "user", scopes="openid openshell:all")
        stub, metadata = _stub_with_token(token)
        stub.ListSandboxes(openshell_pb2.ListSandboxesRequest(), metadata=metadata)

    def test_unauthenticated_request_rejected(self) -> None:
        channel = _grpc_channel()
        stub = openshell_pb2_grpc.OpenShellStub(channel)
        with pytest.raises(grpc.RpcError) as exc_info:
            stub.ListSandboxes(openshell_pb2.ListSandboxesRequest())
        assert exc_info.value.code() == grpc.StatusCode.UNAUTHENTICATED

    def test_health_does_not_require_auth(self) -> None:
        channel = _grpc_channel()
        stub = openshell_pb2_grpc.OpenShellStub(channel)
        resp = stub.Health(openshell_pb2.HealthRequest())
        assert resp.status == openshell_pb2.SERVICE_STATUS_HEALTHY


# ── Scope Enforcement Tests ──────────────────────────────────────────


class TestScopes:
    """Test scope-based fine-grained permissions.

    These tests require the server to be started with
    OPENSHELL_OIDC_SCOPES_CLAIM=scope.
    """

    pytestmark = pytest.mark.skipif(
        os.environ.get("OPENSHELL_E2E_OIDC_SCOPES") != "1",
        reason="Scope e2e tests disabled (set OPENSHELL_E2E_OIDC_SCOPES=1)",
    )

    def test_sandbox_scoped_token_can_list_sandboxes(self) -> None:
        token = _get_token(
            "admin@test", "admin", scopes="openid sandbox:read sandbox:write"
        )
        stub, metadata = _stub_with_token(token)
        stub.ListSandboxes(openshell_pb2.ListSandboxesRequest(), metadata=metadata)

    def test_sandbox_scoped_token_cannot_list_providers(self) -> None:
        token = _get_token(
            "admin@test", "admin", scopes="openid sandbox:read sandbox:write"
        )
        stub, metadata = _stub_with_token(token)
        with pytest.raises(grpc.RpcError) as exc_info:
            stub.ListProviders(openshell_pb2.ListProvidersRequest(), metadata=metadata)
        assert exc_info.value.code() == grpc.StatusCode.PERMISSION_DENIED
        assert "provider:read" in exc_info.value.details()

    def test_openshell_all_grants_full_access(self) -> None:
        token = _get_token("admin@test", "admin", scopes="openid openshell:all")
        stub, metadata = _stub_with_token(token)
        stub.ListSandboxes(openshell_pb2.ListSandboxesRequest(), metadata=metadata)
        stub.ListProviders(openshell_pb2.ListProvidersRequest(), metadata=metadata)

    def test_no_openshell_scopes_denied(self) -> None:
        token = _get_token("admin@test", "admin")
        stub, metadata = _stub_with_token(token)
        with pytest.raises(grpc.RpcError) as exc_info:
            stub.ListSandboxes(openshell_pb2.ListSandboxesRequest(), metadata=metadata)
        assert exc_info.value.code() == grpc.StatusCode.PERMISSION_DENIED


# ── Client Credentials Tests ─────────────────────────────────────────


class TestClientCredentials:
    """Test CI/automation client credentials flow."""

    def test_ci_token_can_list_sandboxes(self) -> None:
        token = _get_ci_token()
        stub, metadata = _stub_with_token(token)
        stub.ListSandboxes(openshell_pb2.ListSandboxesRequest(), metadata=metadata)
