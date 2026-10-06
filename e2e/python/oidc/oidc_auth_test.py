# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""End-to-end tests for OIDC authentication, RBAC, and scope enforcement.

These tests require:
- A running K3s cluster with OIDC enabled (RYNO_OIDC_ISSUER set)
- A running Keycloak instance with the ryno realm
- The cluster started with RYNO_OIDC_SCOPES_CLAIM=scope

Skip condition: set RYNO_E2E_OIDC=1 to enable these tests.
"""

from __future__ import annotations

import contextlib
import os
import urllib.parse
from pathlib import Path

import grpc
import pytest

from ryno import ClientCredentialsAuth, SandboxClient, TlsConfig
from ryno._proto import datamodel_pb2, ryno_pb2, ryno_pb2_grpc

from .helpers import (
    KEYCLOAK_REALM,
    _gateway_endpoint,
    _mtls_dir,
    extract_sub,
    get_token,
    grpc_channel,
    keycloak_url,
    stub_with_token,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("RYNO_E2E_OIDC") != "1",
    reason="OIDC e2e tests disabled (set RYNO_E2E_OIDC=1)",
)


# ── RBAC Tests ────────────────────────────────────────────────────────


class TestRbac:
    """Test role-based access control."""

    def test_admin_can_create_provider(self) -> None:
        token = get_token("admin@test", "admin", scopes="openid ryno:all")
        stub, metadata = stub_with_token(token)
        req = ryno_pb2.CreateProviderRequest(
            workspace_scope=datamodel_pb2.WorkspaceSelector(workspace="default"),
            provider=datamodel_pb2.Provider(
                metadata=datamodel_pb2.ObjectMeta(name="e2e-oidc-admin-test"),
                type="claude-code",
                credentials={"ANTHROPIC_API_KEY": "test-value"},
            ),
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
                    ryno_pb2.DeleteProviderRequest(
                        workspace_scope=datamodel_pb2.WorkspaceSelector(
                            workspace="default"
                        ),
                        name="e2e-oidc-admin-test",
                    ),
                    metadata=metadata,
                )

    def test_user_cannot_create_provider(self) -> None:
        token = get_token("user@test", "user", scopes="openid ryno:all")
        stub, metadata = stub_with_token(token)
        req = ryno_pb2.CreateProviderRequest(
            workspace_scope=datamodel_pb2.WorkspaceSelector(workspace="default"),
            provider=datamodel_pb2.Provider(
                metadata=datamodel_pb2.ObjectMeta(name="e2e-oidc-user-blocked"),
                type="claude-code",
                credentials={"ANTHROPIC_API_KEY": "test-value"},
            ),
        )
        with pytest.raises(grpc.RpcError) as exc_info:
            stub.CreateProvider(req, metadata=metadata)
        assert exc_info.value.code() == grpc.StatusCode.PERMISSION_DENIED

    def test_user_can_list_sandboxes(self) -> None:
        admin_token = get_token("admin@test", "admin", scopes="openid ryno:all")
        admin_stub, admin_md = stub_with_token(admin_token)
        user_token = get_token("user@test", "user", scopes="openid ryno:all")
        user_sub = extract_sub(user_token)
        user_stub, user_md = stub_with_token(user_token)

        with contextlib.suppress(grpc.RpcError):
            admin_stub.AddWorkspaceMember(
                ryno_pb2.AddWorkspaceMemberRequest(
                    workspace_scope=datamodel_pb2.WorkspaceSelector(
                        workspace="default"
                    ),
                    principal_subject=user_sub,
                    role=ryno_pb2.WORKSPACE_ROLE_USER,
                ),
                metadata=admin_md,
            )
        try:
            user_stub.ListSandboxes(
                ryno_pb2.ListSandboxesRequest(
                    workspace_scope=datamodel_pb2.WorkspaceSelector(workspace="default")
                ),
                metadata=user_md,
            )
        finally:
            with contextlib.suppress(grpc.RpcError):
                admin_stub.RemoveWorkspaceMember(
                    ryno_pb2.RemoveWorkspaceMemberRequest(
                        workspace_scope=datamodel_pb2.WorkspaceSelector(
                            workspace="default"
                        ),
                        principal_subject=user_sub,
                    ),
                    metadata=admin_md,
                )

    def test_request_without_bearer_token_rejected(self) -> None:
        channel = grpc_channel()
        stub = ryno_pb2_grpc.RynoStub(channel)
        with pytest.raises(grpc.RpcError) as exc_info:
            stub.ListSandboxes(
                ryno_pb2.ListSandboxesRequest(
                    workspace_scope=datamodel_pb2.WorkspaceSelector(workspace="default")
                )
            )
        assert exc_info.value.code() in (
            grpc.StatusCode.UNAUTHENTICATED,
            grpc.StatusCode.PERMISSION_DENIED,
        )

    def test_health_does_not_require_auth(self) -> None:
        channel = grpc_channel()
        stub = ryno_pb2_grpc.RynoStub(channel)
        resp = stub.Health(ryno_pb2.HealthRequest())
        assert resp.status == ryno_pb2.SERVICE_STATUS_HEALTHY


# ── Scope Enforcement Tests ──────────────────────────────────────────


class TestScopes:
    """Test scope-based fine-grained permissions.

    These tests require the server to be started with
    RYNO_OIDC_SCOPES_CLAIM=scope.
    """

    pytestmark = pytest.mark.skipif(
        os.environ.get("RYNO_E2E_OIDC_SCOPES") != "1",
        reason="Scope e2e tests disabled (set RYNO_E2E_OIDC_SCOPES=1)",
    )

    def test_sandbox_scoped_token_can_list_sandboxes(self) -> None:
        token = get_token(
            "admin@test", "admin", scopes="openid sandbox:read sandbox:write"
        )
        stub, metadata = stub_with_token(token)
        stub.ListSandboxes(
            ryno_pb2.ListSandboxesRequest(
                workspace_scope=datamodel_pb2.WorkspaceSelector(workspace="default")
            ),
            metadata=metadata,
        )

    def test_sandbox_scoped_token_cannot_list_providers(self) -> None:
        token = get_token(
            "admin@test", "admin", scopes="openid sandbox:read sandbox:write"
        )
        stub, metadata = stub_with_token(token)
        with pytest.raises(grpc.RpcError) as exc_info:
            stub.ListProviders(
                ryno_pb2.ListProvidersRequest(
                    workspace_scope=datamodel_pb2.WorkspaceSelector(workspace="default")
                ),
                metadata=metadata,
            )
        assert exc_info.value.code() == grpc.StatusCode.PERMISSION_DENIED
        assert "provider:read" in exc_info.value.details()

    def test_ryno_all_grants_full_access(self) -> None:
        token = get_token("admin@test", "admin", scopes="openid ryno:all")
        stub, metadata = stub_with_token(token)
        stub.ListSandboxes(
            ryno_pb2.ListSandboxesRequest(
                workspace_scope=datamodel_pb2.WorkspaceSelector(workspace="default")
            ),
            metadata=metadata,
        )
        stub.ListProviders(
            ryno_pb2.ListProvidersRequest(
                workspace_scope=datamodel_pb2.WorkspaceSelector(workspace="default")
            ),
            metadata=metadata,
        )

    def test_no_ryno_scopes_denied(self) -> None:
        token = get_token("admin@test", "admin")
        stub, metadata = stub_with_token(token)
        with pytest.raises(grpc.RpcError) as exc_info:
            stub.ListSandboxes(
                ryno_pb2.ListSandboxesRequest(
                    workspace_scope=datamodel_pb2.WorkspaceSelector(workspace="default")
                ),
                metadata=metadata,
            )
        assert exc_info.value.code() == grpc.StatusCode.PERMISSION_DENIED


# ── Client Credentials Tests ─────────────────────────────────────────


class TestClientCredentials:
    """Test CI/automation client credentials flow."""

    def test_ci_token_can_list_sandboxes(self) -> None:
        admin_token = get_token("admin@test", "admin", scopes="openid ryno:all")
        admin_stub, admin_md = stub_with_token(admin_token)
        auth = ClientCredentialsAuth(
            issuer=f"{keycloak_url()}/realms/{KEYCLOAK_REALM}",
            client_id="ryno-ci",
            client_secret="ci-test-secret",
        )
        ci_token = auth()
        ci_sub = extract_sub(ci_token)
        gateway_endpoint, is_tls = _gateway_endpoint()
        parsed = urllib.parse.urlparse(gateway_endpoint)
        target = f"{parsed.hostname}:{parsed.port or (443 if is_tls else 80)}"
        tls = None
        if is_tls:
            if ca_path := os.environ.get("RYNO_E2E_GATEWAY_CA_CERT"):
                tls = TlsConfig(ca_path=Path(ca_path))
            else:
                mtls = _mtls_dir()
                tls = TlsConfig(
                    ca_path=mtls / "ca.crt",
                    cert_path=mtls / "tls.crt",
                    key_path=mtls / "tls.key",
                )
        ci_client = SandboxClient(target, tls=tls, client_credentials=auth)

        with contextlib.suppress(grpc.RpcError):
            admin_stub.AddWorkspaceMember(
                ryno_pb2.AddWorkspaceMemberRequest(
                    workspace_scope=datamodel_pb2.WorkspaceSelector(
                        workspace="default"
                    ),
                    principal_subject=ci_sub,
                    role=ryno_pb2.WORKSPACE_ROLE_USER,
                ),
                metadata=admin_md,
            )
        try:
            ci_client.list_all(workspace="default")
        finally:
            ci_client.close()
            with contextlib.suppress(grpc.RpcError):
                admin_stub.RemoveWorkspaceMember(
                    ryno_pb2.RemoveWorkspaceMemberRequest(
                        workspace_scope=datamodel_pb2.WorkspaceSelector(
                            workspace="default"
                        ),
                        principal_subject=ci_sub,
                    ),
                    metadata=admin_md,
                )
