# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""End-to-end tests for workspace-scoped authorization enforcement.

Validates that every workspace-scoped RPC enforces membership and role
checks when OIDC is configured. Uses two Keycloak users:

- admin@test  — openshell-admin role → Platform Admin (bypasses membership)
- user@test   — openshell-user role  → must be an explicit workspace member

Skip condition: set OPENSHELL_E2E_OIDC=1 to enable these tests.
"""

from __future__ import annotations

import contextlib
import os
from typing import TYPE_CHECKING, Any

import grpc
import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

from openshell._proto import (
    datamodel_pb2,
    inference_pb2,
    inference_pb2_grpc,
    openshell_pb2,
    openshell_pb2_grpc,
)

from .helpers import extract_sub, get_token, grpc_channel, stub_with_token

WS = "e2e-authz-test"

pytestmark = pytest.mark.skipif(
    os.environ.get("OPENSHELL_E2E_OIDC") != "1",
    reason="OIDC e2e tests disabled (set OPENSHELL_E2E_OIDC=1)",
)


# ── Helpers ──────────────────────────────────────────────────────────────


def _admin_token() -> str:
    return get_token("admin@test", "admin", scopes="openid openshell:all")


def _user_token() -> str:
    return get_token("user@test", "user", scopes="openid openshell:all")


def _add_member(
    stub: openshell_pb2_grpc.OpenShellStub,
    metadata: list[tuple[str, str]],
    workspace: str,
    subject: str,
    role: int,
) -> None:
    stub.AddWorkspaceMember(
        openshell_pb2.AddWorkspaceMemberRequest(
            workspace=workspace,
            principal_subject=subject,
            role=role,
        ),
        metadata=metadata,
    )


def _remove_member(
    stub: openshell_pb2_grpc.OpenShellStub,
    metadata: list[tuple[str, str]],
    workspace: str,
    subject: str,
) -> None:
    with contextlib.suppress(grpc.RpcError):
        stub.RemoveWorkspaceMember(
            openshell_pb2.RemoveWorkspaceMemberRequest(
                workspace=workspace,
                principal_subject=subject,
            ),
            metadata=metadata,
        )


# ── RPC call builders for parametrized non-member rejection tests ────────
#
# Each entry is (test_id, callable(stub, metadata) -> response).
# The callable constructs a minimal valid request for the given RPC.


def _assert_non_member_denial(
    error: grpc.RpcError,
    workspace: str,
    subject: str,
    rpc_name: str,
) -> None:
    assert error.code() == grpc.StatusCode.PERMISSION_DENIED, (
        f"{rpc_name}: expected PERMISSION_DENIED, got {error.code()}"
    )
    details = error.details()
    assert f"not a member of workspace '{workspace}'" in details, (
        f"{rpc_name}: denial came from the wrong authorization layer: {details}"
    )
    command = (
        "openshell workspace member add "
        f"--workspace '{workspace}' --subject '{subject}' --role user"
    )
    assert command in details, (
        f"{rpc_name}: denial omitted the actionable membership command: {details}"
    )


def _assert_workspace_admin_denial(
    error: grpc.RpcError,
    workspace: str,
    subject: str,
    rpc_name: str,
) -> None:
    assert error.code() == grpc.StatusCode.PERMISSION_DENIED, (
        f"{rpc_name}: expected PERMISSION_DENIED, got {error.code()}"
    )
    details = error.details()
    assert f"workspace role 'admin' required in workspace '{workspace}'" in details, (
        f"{rpc_name}: denial came from the wrong authorization layer: {details}"
    )
    command = (
        "openshell workspace member add "
        f"--workspace '{workspace}' --subject '{subject}' --role admin"
    )
    assert command in details, (
        f"{rpc_name}: denial omitted the admin remediation command: {details}"
    )


def _workspace_rpcs() -> list[tuple[str, Callable]]:
    """All workspace-scoped RPCs that accept a workspace field."""
    return [
        # ── Workspace domain ──
        (
            "GetWorkspace",
            lambda s, m: s.GetWorkspace(
                openshell_pb2.GetWorkspaceRequest(name=WS), metadata=m
            ),
        ),
        (
            "ListWorkspaceMembers",
            lambda s, m: s.ListWorkspaceMembers(
                openshell_pb2.ListWorkspaceMembersRequest(workspace=WS), metadata=m
            ),
        ),
        (
            "AddWorkspaceMember",
            lambda s, m: s.AddWorkspaceMember(
                openshell_pb2.AddWorkspaceMemberRequest(
                    workspace=WS,
                    principal_subject="fake",
                    role=openshell_pb2.WORKSPACE_ROLE_USER,
                ),
                metadata=m,
            ),
        ),
        (
            "RemoveWorkspaceMember",
            lambda s, m: s.RemoveWorkspaceMember(
                openshell_pb2.RemoveWorkspaceMemberRequest(
                    workspace=WS,
                    principal_subject="fake",
                ),
                metadata=m,
            ),
        ),
        # ── Sandbox domain ──
        (
            "CreateSandbox",
            lambda s, m: s.CreateSandbox(
                openshell_pb2.CreateSandboxRequest(
                    workspace=WS,
                    spec=openshell_pb2.SandboxSpec(
                        template=openshell_pb2.SandboxTemplate(image="ubuntu:24.04")
                    ),
                ),
                metadata=m,
            ),
        ),
        (
            "GetSandbox",
            lambda s, m: s.GetSandbox(
                openshell_pb2.GetSandboxRequest(name="nonexistent", workspace=WS),
                metadata=m,
            ),
        ),
        (
            "ListSandboxes",
            lambda s, m: s.ListSandboxes(
                openshell_pb2.ListSandboxesRequest(workspace=WS), metadata=m
            ),
        ),
        (
            "DeleteSandbox",
            lambda s, m: s.DeleteSandbox(
                openshell_pb2.DeleteSandboxRequest(name="nonexistent", workspace=WS),
                metadata=m,
            ),
        ),
        (
            "ListSandboxProviders",
            lambda s, m: s.ListSandboxProviders(
                openshell_pb2.ListSandboxProvidersRequest(
                    sandbox_name="nonexistent", workspace=WS
                ),
                metadata=m,
            ),
        ),
        (
            "AttachSandboxProvider",
            lambda s, m: s.AttachSandboxProvider(
                openshell_pb2.AttachSandboxProviderRequest(
                    sandbox_name="nonexistent",
                    provider_name="nonexistent",
                    workspace=WS,
                ),
                metadata=m,
            ),
        ),
        (
            "DetachSandboxProvider",
            lambda s, m: s.DetachSandboxProvider(
                openshell_pb2.DetachSandboxProviderRequest(
                    sandbox_name="nonexistent",
                    provider_name="nonexistent",
                    workspace=WS,
                ),
                metadata=m,
            ),
        ),
        # ── Provider domain ──
        (
            "CreateProvider",
            lambda s, m: s.CreateProvider(
                openshell_pb2.CreateProviderRequest(
                    workspace=WS,
                    provider=datamodel_pb2.Provider(
                        metadata=datamodel_pb2.ObjectMeta(
                            name="authz-test", workspace=WS
                        ),
                        type="claude",
                        credentials={"ANTHROPIC_API_KEY": "v"},
                    ),
                ),
                metadata=m,
            ),
        ),
        (
            "GetProvider",
            lambda s, m: s.GetProvider(
                openshell_pb2.GetProviderRequest(name="nonexistent", workspace=WS),
                metadata=m,
            ),
        ),
        (
            "ListProviders",
            lambda s, m: s.ListProviders(
                openshell_pb2.ListProvidersRequest(workspace=WS), metadata=m
            ),
        ),
        (
            "UpdateProvider",
            lambda s, m: s.UpdateProvider(
                openshell_pb2.UpdateProviderRequest(
                    workspace=WS,
                    provider=datamodel_pb2.Provider(
                        metadata=datamodel_pb2.ObjectMeta(
                            name="nonexistent", workspace=WS
                        ),
                        type="claude",
                        credentials={"ANTHROPIC_API_KEY": "v"},
                    ),
                ),
                metadata=m,
            ),
        ),
        (
            "DeleteProvider",
            lambda s, m: s.DeleteProvider(
                openshell_pb2.DeleteProviderRequest(name="nonexistent", workspace=WS),
                metadata=m,
            ),
        ),
        (
            "ListProviderProfiles",
            lambda s, m: s.ListProviderProfiles(
                openshell_pb2.ListProviderProfilesRequest(workspace=WS), metadata=m
            ),
        ),
        (
            "GetProviderProfile",
            lambda s, m: s.GetProviderProfile(
                openshell_pb2.GetProviderProfileRequest(id="nonexistent", workspace=WS),
                metadata=m,
            ),
        ),
        (
            "ImportProviderProfiles",
            lambda s, m: s.ImportProviderProfiles(
                openshell_pb2.ImportProviderProfilesRequest(workspace=WS, profiles=[]),
                metadata=m,
            ),
        ),
        (
            "UpdateProviderProfiles",
            lambda s, m: s.UpdateProviderProfiles(
                openshell_pb2.UpdateProviderProfilesRequest(
                    workspace=WS, id="nonexistent"
                ),
                metadata=m,
            ),
        ),
        (
            "LintProviderProfiles",
            lambda s, m: s.LintProviderProfiles(
                openshell_pb2.LintProviderProfilesRequest(workspace=WS, profiles=[]),
                metadata=m,
            ),
        ),
        (
            "DeleteProviderProfile",
            lambda s, m: s.DeleteProviderProfile(
                openshell_pb2.DeleteProviderProfileRequest(
                    id="nonexistent", workspace=WS
                ),
                metadata=m,
            ),
        ),
        (
            "GetProviderRefreshStatus",
            lambda s, m: s.GetProviderRefreshStatus(
                openshell_pb2.GetProviderRefreshStatusRequest(
                    provider="nonexistent", workspace=WS
                ),
                metadata=m,
            ),
        ),
        (
            "ConfigureProviderRefresh",
            lambda s, m: s.ConfigureProviderRefresh(
                openshell_pb2.ConfigureProviderRefreshRequest(
                    provider="nonexistent",
                    credential_key="k",
                    strategy=openshell_pb2.PROVIDER_CREDENTIAL_REFRESH_STRATEGY_STATIC,
                    workspace=WS,
                ),
                metadata=m,
            ),
        ),
        (
            "RotateProviderCredential",
            lambda s, m: s.RotateProviderCredential(
                openshell_pb2.RotateProviderCredentialRequest(
                    provider="nonexistent",
                    credential_key="k",
                    workspace=WS,
                ),
                metadata=m,
            ),
        ),
        (
            "DeleteProviderRefresh",
            lambda s, m: s.DeleteProviderRefresh(
                openshell_pb2.DeleteProviderRefreshRequest(
                    provider="nonexistent",
                    credential_key="k",
                    workspace=WS,
                ),
                metadata=m,
            ),
        ),
        # ── Service domain ──
        (
            "ExposeService",
            lambda s, m: s.ExposeService(
                openshell_pb2.ExposeServiceRequest(
                    sandbox="nonexistent",
                    service="svc",
                    target_port=8080,
                    workspace=WS,
                ),
                metadata=m,
            ),
        ),
        (
            "GetService",
            lambda s, m: s.GetService(
                openshell_pb2.GetServiceRequest(
                    sandbox="nonexistent", service="svc", workspace=WS
                ),
                metadata=m,
            ),
        ),
        (
            "ListServices",
            lambda s, m: s.ListServices(
                openshell_pb2.ListServicesRequest(workspace=WS), metadata=m
            ),
        ),
        (
            "DeleteService",
            lambda s, m: s.DeleteService(
                openshell_pb2.DeleteServiceRequest(
                    sandbox="nonexistent", service="svc", workspace=WS
                ),
                metadata=m,
            ),
        ),
        # ── Policy domain ──
        (
            "GetSandboxPolicyStatus",
            lambda s, m: s.GetSandboxPolicyStatus(
                openshell_pb2.GetSandboxPolicyStatusRequest(
                    name="nonexistent", workspace=WS
                ),
                metadata=m,
            ),
        ),
        (
            "ListSandboxPolicies",
            lambda s, m: s.ListSandboxPolicies(
                openshell_pb2.ListSandboxPoliciesRequest(
                    name="nonexistent", workspace=WS
                ),
                metadata=m,
            ),
        ),
        (
            "GetDraftPolicy",
            lambda s, m: s.GetDraftPolicy(
                openshell_pb2.GetDraftPolicyRequest(name="nonexistent", workspace=WS),
                metadata=m,
            ),
        ),
        (
            "ApproveDraftChunk",
            lambda s, m: s.ApproveDraftChunk(
                openshell_pb2.ApproveDraftChunkRequest(
                    name="nonexistent", chunk_id="x", workspace=WS
                ),
                metadata=m,
            ),
        ),
        (
            "RejectDraftChunk",
            lambda s, m: s.RejectDraftChunk(
                openshell_pb2.RejectDraftChunkRequest(
                    name="nonexistent", chunk_id="x", workspace=WS
                ),
                metadata=m,
            ),
        ),
        (
            "ApproveAllDraftChunks",
            lambda s, m: s.ApproveAllDraftChunks(
                openshell_pb2.ApproveAllDraftChunksRequest(
                    name="nonexistent", workspace=WS
                ),
                metadata=m,
            ),
        ),
        (
            "EditDraftChunk",
            lambda s, m: s.EditDraftChunk(
                openshell_pb2.EditDraftChunkRequest(
                    name="nonexistent", chunk_id="x", workspace=WS
                ),
                metadata=m,
            ),
        ),
        (
            "UndoDraftChunk",
            lambda s, m: s.UndoDraftChunk(
                openshell_pb2.UndoDraftChunkRequest(
                    name="nonexistent", chunk_id="x", workspace=WS
                ),
                metadata=m,
            ),
        ),
        (
            "ClearDraftChunks",
            lambda s, m: s.ClearDraftChunks(
                openshell_pb2.ClearDraftChunksRequest(name="nonexistent", workspace=WS),
                metadata=m,
            ),
        ),
        (
            "GetDraftHistory",
            lambda s, m: s.GetDraftHistory(
                openshell_pb2.GetDraftHistoryRequest(name="nonexistent", workspace=WS),
                metadata=m,
            ),
        ),
        # ── Inference domain ──
        (
            "SetInferenceRoute",
            lambda _s, m: _inference_stub().SetInferenceRoute(
                inference_pb2.SetInferenceRouteRequest(
                    provider_name="nonexistent", workspace=WS
                ),
                metadata=m,
            ),
        ),
        (
            "GetInferenceRoute",
            lambda _s, m: _inference_stub().GetInferenceRoute(
                inference_pb2.GetInferenceRouteRequest(workspace=WS), metadata=m
            ),
        ),
        (
            "DeleteInferenceRoute",
            lambda _s, m: _inference_stub().DeleteInferenceRoute(
                inference_pb2.DeleteInferenceRouteRequest(workspace=WS), metadata=m
            ),
        ),
    ]


def _platform_profile_rpcs() -> list[tuple[str, Callable]]:
    """Provider-profile RPCs targeting the explicit platform scope."""
    return [
        (
            "ListProviderProfiles",
            lambda s, m: s.ListProviderProfiles(
                openshell_pb2.ListProviderProfilesRequest(workspace=""), metadata=m
            ),
        ),
        (
            "GetProviderProfile",
            lambda s, m: s.GetProviderProfile(
                openshell_pb2.GetProviderProfileRequest(id="nonexistent", workspace=""),
                metadata=m,
            ),
        ),
        (
            "ImportProviderProfiles",
            lambda s, m: s.ImportProviderProfiles(
                openshell_pb2.ImportProviderProfilesRequest(workspace="", profiles=[]),
                metadata=m,
            ),
        ),
        (
            "UpdateProviderProfiles",
            lambda s, m: s.UpdateProviderProfiles(
                openshell_pb2.UpdateProviderProfilesRequest(
                    id="nonexistent", workspace=""
                ),
                metadata=m,
            ),
        ),
        (
            "LintProviderProfiles",
            lambda s, m: s.LintProviderProfiles(
                openshell_pb2.LintProviderProfilesRequest(workspace="", profiles=[]),
                metadata=m,
            ),
        ),
        (
            "DeleteProviderProfile",
            lambda s, m: s.DeleteProviderProfile(
                openshell_pb2.DeleteProviderProfileRequest(
                    id="nonexistent", workspace=""
                ),
                metadata=m,
            ),
        ),
    ]


def _global_policy_read_rpcs() -> list[tuple[str, Callable]]:
    """Policy history reads targeting the explicit global scope."""
    return [
        (
            "GetSandboxPolicyStatus",
            lambda s, m: s.GetSandboxPolicyStatus(
                openshell_pb2.GetSandboxPolicyStatusRequest(
                    workspace="", **{"global": True}
                ),
                metadata=m,
            ),
        ),
        (
            "ListSandboxPolicies",
            lambda s, m: s.ListSandboxPolicies(
                openshell_pb2.ListSandboxPoliciesRequest(
                    workspace="", **{"global": True}
                ),
                metadata=m,
            ),
        ),
    ]


_cached_inference_stub: inference_pb2_grpc.InferenceStub | None = None


def _inference_stub() -> inference_pb2_grpc.InferenceStub:
    global _cached_inference_stub
    if _cached_inference_stub is None:
        _cached_inference_stub = inference_pb2_grpc.InferenceStub(grpc_channel())
    return _cached_inference_stub


# ── Test class ───────────────────────────────────────────────────────────


class TestWorkspaceAuthorization:
    """Workspace-scoped authorization enforcement tests."""

    @pytest.fixture(autouse=True, scope="class")
    def workspace(self) -> Any:
        """Create a test workspace and tear it down after all tests."""
        token = _admin_token()
        stub, metadata = stub_with_token(token)

        with contextlib.suppress(grpc.RpcError):
            stub.CreateWorkspace(
                openshell_pb2.CreateWorkspaceRequest(name=WS),
                metadata=metadata,
            )

        yield WS

        with contextlib.suppress(grpc.RpcError):
            stub.DeleteWorkspace(
                openshell_pb2.DeleteWorkspaceRequest(name=WS),
                metadata=metadata,
            )

    @pytest.fixture(scope="class")
    def admin_ctx(
        self,
    ) -> tuple[openshell_pb2_grpc.OpenShellStub, list[tuple[str, str]]]:
        token = _admin_token()
        return stub_with_token(token)

    @pytest.fixture(scope="class")
    def user_ctx(
        self,
    ) -> tuple[openshell_pb2_grpc.OpenShellStub, list[tuple[str, str]], str]:
        token = _user_token()
        stub, metadata = stub_with_token(token)
        sub = extract_sub(token)
        return stub, metadata, sub

    @pytest.fixture(scope="class")
    def seed_provider(self, admin_ctx: Any, workspace: str) -> Any:
        """Create a provider so read RPCs have data to return."""
        stub, metadata = admin_ctx
        prov_name = "e2e-authz-provider"
        with contextlib.suppress(grpc.RpcError):
            stub.CreateProvider(
                openshell_pb2.CreateProviderRequest(
                    workspace=workspace,
                    provider=datamodel_pb2.Provider(
                        metadata=datamodel_pb2.ObjectMeta(
                            name=prov_name, workspace=workspace
                        ),
                        type="claude",
                        credentials={"ANTHROPIC_API_KEY": "test"},
                    ),
                ),
                metadata=metadata,
            )
        yield prov_name
        with contextlib.suppress(grpc.RpcError):
            stub.DeleteProvider(
                openshell_pb2.DeleteProviderRequest(
                    name=prov_name, workspace=workspace
                ),
                metadata=metadata,
            )

    # ── Test 1: Non-member rejection — workspace-field RPCs ──────────

    @pytest.mark.parametrize(
        "rpc_name,call",
        _workspace_rpcs(),
        ids=[r[0] for r in _workspace_rpcs()],
    )
    def test_non_member_rejected(
        self,
        rpc_name: str,
        call: Callable,
        user_ctx: Any,
    ) -> None:
        stub, metadata, user_sub = user_ctx
        with pytest.raises(grpc.RpcError) as exc_info:
            call(stub, metadata)
        _assert_non_member_denial(exc_info.value, WS, user_sub, rpc_name)

    # ── Test 2: Non-member rejection — dual-mode RPCs ────────────────

    def test_non_member_rejected_update_config(
        self,
        user_ctx: Any,
    ) -> None:
        stub, metadata, user_sub = user_ctx
        with pytest.raises(grpc.RpcError) as exc_info:
            stub.UpdateConfig(
                openshell_pb2.UpdateConfigRequest(name="nonexistent", workspace=WS),
                metadata=metadata,
            )
        _assert_non_member_denial(
            exc_info.value,
            WS,
            user_sub,
            "UpdateConfig",
        )

    # ── Test 3: Sandbox log authorization uses persisted workspace ───

    def test_get_sandbox_logs_rejects_spoofed_workspace(
        self,
        admin_ctx: Any,
        user_ctx: Any,
    ) -> None:
        admin_stub, admin_md = admin_ctx
        user_stub, user_md, user_sub = user_ctx
        other_workspace = "e2e-authz-log-b"
        sandbox_name = "e2e-log-target"

        with contextlib.suppress(grpc.RpcError):
            admin_stub.DeleteWorkspace(
                openshell_pb2.DeleteWorkspaceRequest(name=other_workspace),
                metadata=admin_md,
            )
        admin_stub.CreateWorkspace(
            openshell_pb2.CreateWorkspaceRequest(name=other_workspace),
            metadata=admin_md,
        )
        _add_member(
            admin_stub, admin_md, WS, user_sub, openshell_pb2.WORKSPACE_ROLE_USER
        )

        sandbox_id = ""
        try:
            response = admin_stub.CreateSandbox(
                openshell_pb2.CreateSandboxRequest(
                    name=sandbox_name,
                    workspace=other_workspace,
                    spec=openshell_pb2.SandboxSpec(),
                ),
                metadata=admin_md,
            )
            sandbox_id = response.sandbox.metadata.id

            with pytest.raises(grpc.RpcError) as exc_info:
                user_stub.GetSandboxLogs(
                    openshell_pb2.GetSandboxLogsRequest(
                        sandbox_id=sandbox_id,
                        workspace=WS,
                    ),
                    metadata=user_md,
                )
            # ID-based handlers normalize unauthorized responses to NOT_FOUND
            # so cross-workspace sandbox existence cannot be inferred (CWE-203).
            assert exc_info.value.code() == grpc.StatusCode.NOT_FOUND, (
                "GetSandboxLogs: expected NOT_FOUND for cross-workspace sandbox, "
                f"got {exc_info.value.code()}"
            )
        finally:
            if sandbox_id:
                with contextlib.suppress(grpc.RpcError):
                    admin_stub.DeleteSandbox(
                        openshell_pb2.DeleteSandboxRequest(
                            name=sandbox_name,
                            workspace=other_workspace,
                        ),
                        metadata=admin_md,
                    )
            _remove_member(admin_stub, admin_md, WS, user_sub)
            with contextlib.suppress(grpc.RpcError):
                admin_stub.DeleteWorkspace(
                    openshell_pb2.DeleteWorkspaceRequest(name=other_workspace),
                    metadata=admin_md,
                )

    # ── Test 4: Global config requires Platform Admin ────────────────

    def test_global_update_rejected_for_default_workspace_admin(
        self,
        admin_ctx: Any,
        user_ctx: Any,
    ) -> None:
        admin_stub, admin_md = admin_ctx
        user_stub, user_md, user_sub = user_ctx

        _remove_member(admin_stub, admin_md, "default", user_sub)
        _add_member(
            admin_stub,
            admin_md,
            "default",
            user_sub,
            openshell_pb2.WORKSPACE_ROLE_ADMIN,
        )
        try:
            with pytest.raises(grpc.RpcError) as exc_info:
                user_stub.UpdateConfig(
                    openshell_pb2.UpdateConfigRequest(
                        workspace="",
                        setting_key="log_level",
                        delete_setting=True,
                        **{"global": True},
                    ),
                    metadata=user_md,
                )
            assert exc_info.value.code() == grpc.StatusCode.PERMISSION_DENIED
            assert "platform admin role required" in exc_info.value.details(), (
                "UpdateConfig: denial came from the wrong authorization layer: "
                f"{exc_info.value.details()}"
            )
        finally:
            _remove_member(admin_stub, admin_md, "default", user_sub)

    # ── Test 5: Non-member ListWorkspaces returns filtered results ───

    def test_non_member_list_workspaces_filtered(
        self,
        user_ctx: Any,
    ) -> None:
        stub, metadata, _ = user_ctx
        resp = stub.ListWorkspaces(
            openshell_pb2.ListWorkspacesRequest(),
            metadata=metadata,
        )
        ws_names = [w.metadata.name for w in resp.workspaces]
        assert WS not in ws_names, (
            f"non-member should not see workspace {WS} in ListWorkspaces"
        )

    # ── Test 6: Platform Admin bypass ────────────────────────────────

    @pytest.mark.usefixtures("seed_provider")
    def test_platform_admin_get_workspace(
        self,
        admin_ctx: Any,
    ) -> None:
        stub, metadata = admin_ctx
        resp = stub.GetWorkspace(
            openshell_pb2.GetWorkspaceRequest(name=WS),
            metadata=metadata,
        )
        assert resp.workspace.metadata.name == WS

    def test_platform_admin_list_sandboxes(
        self,
        admin_ctx: Any,
    ) -> None:
        stub, metadata = admin_ctx
        stub.ListSandboxes(
            openshell_pb2.ListSandboxesRequest(workspace=WS),
            metadata=metadata,
        )

    def test_platform_admin_get_provider(
        self,
        admin_ctx: Any,
        seed_provider: str,
    ) -> None:
        stub, metadata = admin_ctx
        resp = stub.GetProvider(
            openshell_pb2.GetProviderRequest(name=seed_provider, workspace=WS),
            metadata=metadata,
        )
        assert resp.provider.metadata.name == seed_provider

    def test_platform_admin_list_services(
        self,
        admin_ctx: Any,
    ) -> None:
        stub, metadata = admin_ctx
        stub.ListServices(
            openshell_pb2.ListServicesRequest(workspace=WS),
            metadata=metadata,
        )

    def test_platform_admin_get_draft_history(
        self,
        admin_ctx: Any,
    ) -> None:
        stub, metadata = admin_ctx
        # May fail with NOT_FOUND for the sandbox name, but should not fail with PERMISSION_DENIED
        try:
            stub.GetDraftHistory(
                openshell_pb2.GetDraftHistoryRequest(name="nonexistent", workspace=WS),
                metadata=metadata,
            )
        except grpc.RpcError as e:
            assert e.code() != grpc.StatusCode.PERMISSION_DENIED

    # ── Test 7: User member — read operations succeed ────────────────

    def test_user_member_read_operations(
        self,
        admin_ctx: Any,
        user_ctx: Any,
        seed_provider: str,
    ) -> None:
        admin_stub, admin_md = admin_ctx
        user_stub, user_md, user_sub = user_ctx

        _add_member(
            admin_stub, admin_md, WS, user_sub, openshell_pb2.WORKSPACE_ROLE_USER
        )
        try:
            # GetWorkspace
            resp = user_stub.GetWorkspace(
                openshell_pb2.GetWorkspaceRequest(name=WS),
                metadata=user_md,
            )
            assert resp.workspace.metadata.name == WS

            # ListSandboxes
            user_stub.ListSandboxes(
                openshell_pb2.ListSandboxesRequest(workspace=WS),
                metadata=user_md,
            )

            # GetProvider
            resp = user_stub.GetProvider(
                openshell_pb2.GetProviderRequest(name=seed_provider, workspace=WS),
                metadata=user_md,
            )
            assert resp.provider.metadata.name == seed_provider

            # ListProviders
            user_stub.ListProviders(
                openshell_pb2.ListProvidersRequest(workspace=WS),
                metadata=user_md,
            )

            # ListServices
            user_stub.ListServices(
                openshell_pb2.ListServicesRequest(workspace=WS),
                metadata=user_md,
            )

            # ListWorkspaceMembers
            user_stub.ListWorkspaceMembers(
                openshell_pb2.ListWorkspaceMembersRequest(workspace=WS),
                metadata=user_md,
            )
        finally:
            _remove_member(admin_stub, admin_md, WS, user_sub)

    # ── Test 8: User member — admin operations denied ────────────────

    def test_user_member_admin_operations_denied(
        self,
        admin_ctx: Any,
        user_ctx: Any,
    ) -> None:
        admin_stub, admin_md = admin_ctx
        user_stub, user_md, user_sub = user_ctx

        _add_member(
            admin_stub, admin_md, WS, user_sub, openshell_pb2.WORKSPACE_ROLE_USER
        )
        try:
            # CreateProvider requires workspace admin
            with pytest.raises(grpc.RpcError) as exc_info:
                user_stub.CreateProvider(
                    openshell_pb2.CreateProviderRequest(
                        workspace=WS,
                        provider=datamodel_pb2.Provider(
                            metadata=datamodel_pb2.ObjectMeta(
                                name="user-blocked", workspace=WS
                            ),
                            type="claude",
                            credentials={"ANTHROPIC_API_KEY": "v"},
                        ),
                    ),
                    metadata=user_md,
                )
            _assert_workspace_admin_denial(
                exc_info.value,
                WS,
                user_sub,
                "CreateProvider",
            )

            # AddWorkspaceMember requires workspace admin
            with pytest.raises(grpc.RpcError) as exc_info:
                user_stub.AddWorkspaceMember(
                    openshell_pb2.AddWorkspaceMemberRequest(
                        workspace=WS,
                        principal_subject="fake-subject",
                        role=openshell_pb2.WORKSPACE_ROLE_USER,
                    ),
                    metadata=user_md,
                )
            _assert_workspace_admin_denial(
                exc_info.value,
                WS,
                user_sub,
                "AddWorkspaceMember",
            )

            # ApproveDraftChunk requires workspace admin
            with pytest.raises(grpc.RpcError) as exc_info:
                user_stub.ApproveDraftChunk(
                    openshell_pb2.ApproveDraftChunkRequest(
                        name="nonexistent",
                        chunk_id="x",
                        workspace=WS,
                    ),
                    metadata=user_md,
                )
            _assert_workspace_admin_denial(
                exc_info.value,
                WS,
                user_sub,
                "ApproveDraftChunk",
            )
        finally:
            _remove_member(admin_stub, admin_md, WS, user_sub)

    # ── Test 9: Workspace Admin — admin operations succeed ───────────

    def test_workspace_admin_can_create_provider(
        self,
        admin_ctx: Any,
        user_ctx: Any,
    ) -> None:
        admin_stub, admin_md = admin_ctx
        user_stub, user_md, user_sub = user_ctx

        _add_member(
            admin_stub, admin_md, WS, user_sub, openshell_pb2.WORKSPACE_ROLE_ADMIN
        )
        prov_name = "e2e-authz-ws-admin-prov"
        try:
            user_stub.CreateProvider(
                openshell_pb2.CreateProviderRequest(
                    workspace=WS,
                    provider=datamodel_pb2.Provider(
                        metadata=datamodel_pb2.ObjectMeta(name=prov_name, workspace=WS),
                        type="claude",
                        credentials={"ANTHROPIC_API_KEY": "v"},
                    ),
                ),
                metadata=user_md,
            )

            # Also test AddWorkspaceMember with User role
            user_stub.AddWorkspaceMember(
                openshell_pb2.AddWorkspaceMemberRequest(
                    workspace=WS,
                    principal_subject="fake-member-subject",
                    role=openshell_pb2.WORKSPACE_ROLE_USER,
                ),
                metadata=user_md,
            )
            _remove_member(admin_stub, admin_md, WS, "fake-member-subject")
        finally:
            with contextlib.suppress(grpc.RpcError):
                admin_stub.DeleteProvider(
                    openshell_pb2.DeleteProviderRequest(name=prov_name, workspace=WS),
                    metadata=admin_md,
                )
            _remove_member(admin_stub, admin_md, WS, user_sub)

    # ── Test 10: all_workspaces rejected for non-Platform-Admin ──────

    def test_all_workspaces_rejected_for_workspace_admin(
        self,
        admin_ctx: Any,
        user_ctx: Any,
    ) -> None:
        admin_stub, admin_md = admin_ctx
        user_stub, user_md, user_sub = user_ctx

        _add_member(
            admin_stub, admin_md, WS, user_sub, openshell_pb2.WORKSPACE_ROLE_ADMIN
        )
        try:
            with pytest.raises(grpc.RpcError) as exc_info:
                user_stub.ListSandboxes(
                    openshell_pb2.ListSandboxesRequest(all_workspaces=True),
                    metadata=user_md,
                )
            assert exc_info.value.code() == grpc.StatusCode.PERMISSION_DENIED

            with pytest.raises(grpc.RpcError) as exc_info:
                user_stub.ListProviders(
                    openshell_pb2.ListProvidersRequest(all_workspaces=True),
                    metadata=user_md,
                )
            assert exc_info.value.code() == grpc.StatusCode.PERMISSION_DENIED

            with pytest.raises(grpc.RpcError) as exc_info:
                user_stub.ListServices(
                    openshell_pb2.ListServicesRequest(all_workspaces=True),
                    metadata=user_md,
                )
            assert exc_info.value.code() == grpc.StatusCode.PERMISSION_DENIED
        finally:
            _remove_member(admin_stub, admin_md, WS, user_sub)

    # ── Test 11: Workspace Admin cannot assign Admin role ────────────

    def test_workspace_admin_cannot_assign_admin_role(
        self,
        admin_ctx: Any,
        user_ctx: Any,
    ) -> None:
        admin_stub, admin_md = admin_ctx
        user_stub, user_md, user_sub = user_ctx

        _add_member(
            admin_stub, admin_md, WS, user_sub, openshell_pb2.WORKSPACE_ROLE_ADMIN
        )
        try:
            # Workspace Admin cannot assign Admin role
            with pytest.raises(grpc.RpcError) as exc_info:
                user_stub.AddWorkspaceMember(
                    openshell_pb2.AddWorkspaceMemberRequest(
                        workspace=WS,
                        principal_subject="another-subject",
                        role=openshell_pb2.WORKSPACE_ROLE_ADMIN,
                    ),
                    metadata=user_md,
                )
            assert exc_info.value.code() == grpc.StatusCode.PERMISSION_DENIED

            # But User role assignment succeeds
            user_stub.AddWorkspaceMember(
                openshell_pb2.AddWorkspaceMemberRequest(
                    workspace=WS,
                    principal_subject="another-subject",
                    role=openshell_pb2.WORKSPACE_ROLE_USER,
                ),
                metadata=user_md,
            )
            _remove_member(admin_stub, admin_md, WS, "another-subject")
        finally:
            _remove_member(admin_stub, admin_md, WS, user_sub)

    # ── Test 12: ListWorkspaces filtered by membership ───────────────

    def test_list_workspaces_filtered_by_membership(
        self,
        admin_ctx: Any,
        user_ctx: Any,
    ) -> None:
        admin_stub, admin_md = admin_ctx
        user_stub, user_md, user_sub = user_ctx

        ws2 = "e2e-authz-test-2"
        with contextlib.suppress(grpc.RpcError):
            admin_stub.CreateWorkspace(
                openshell_pb2.CreateWorkspaceRequest(name=ws2),
                metadata=admin_md,
            )

        _add_member(
            admin_stub, admin_md, WS, user_sub, openshell_pb2.WORKSPACE_ROLE_USER
        )
        try:
            resp = user_stub.ListWorkspaces(
                openshell_pb2.ListWorkspacesRequest(),
                metadata=user_md,
            )
            ws_names = [w.metadata.name for w in resp.workspaces]
            assert WS in ws_names, f"member should see {WS}"
            assert ws2 not in ws_names, f"non-member should not see {ws2}"
            assert "default" not in ws_names, "non-member should not see default"
        finally:
            _remove_member(admin_stub, admin_md, WS, user_sub)
            with contextlib.suppress(grpc.RpcError):
                admin_stub.DeleteWorkspace(
                    openshell_pb2.DeleteWorkspaceRequest(name=ws2),
                    metadata=admin_md,
                )

    # ── Test 13: Platform provider profiles require Platform Admin ───

    @pytest.mark.parametrize(
        "rpc_name,call",
        _platform_profile_rpcs(),
        ids=[r[0] for r in _platform_profile_rpcs()],
    )
    def test_platform_provider_profile_operations_require_platform_admin(
        self,
        rpc_name: str,
        call: Callable,
        user_ctx: Any,
    ) -> None:
        stub, metadata, _ = user_ctx

        with pytest.raises(grpc.RpcError) as exc_info:
            call(stub, metadata)

        assert exc_info.value.code() == grpc.StatusCode.PERMISSION_DENIED, (
            f"{rpc_name}: expected PERMISSION_DENIED, got {exc_info.value.code()}"
        )
        assert "platform admin role required" in exc_info.value.details(), (
            f"{rpc_name}: denial came from the wrong authorization layer: "
            f"{exc_info.value.details()}"
        )

    @pytest.mark.parametrize(
        "rpc_name,call",
        _platform_profile_rpcs(),
        ids=[r[0] for r in _platform_profile_rpcs()],
    )
    def test_platform_admin_can_access_platform_provider_profile_operations(
        self,
        rpc_name: str,
        call: Callable,
        admin_ctx: Any,
    ) -> None:
        stub, metadata = admin_ctx

        try:
            call(stub, metadata)
        except grpc.RpcError as error:
            assert error.code() != grpc.StatusCode.PERMISSION_DENIED, (
                f"{rpc_name}: Platform Admin was denied: {error.details()}"
            )

    # ── Test 14: Global policy reads require Platform Admin ──────────

    @pytest.mark.parametrize(
        "rpc_name,call",
        _global_policy_read_rpcs(),
        ids=[r[0] for r in _global_policy_read_rpcs()],
    )
    def test_global_policy_reads_require_platform_admin(
        self,
        rpc_name: str,
        call: Callable,
        user_ctx: Any,
    ) -> None:
        stub, metadata, _ = user_ctx

        with pytest.raises(grpc.RpcError) as exc_info:
            call(stub, metadata)

        assert exc_info.value.code() == grpc.StatusCode.PERMISSION_DENIED, (
            f"{rpc_name}: expected PERMISSION_DENIED, got {exc_info.value.code()}"
        )
        assert "platform admin role required" in exc_info.value.details(), (
            f"{rpc_name}: denial came from the wrong authorization layer: "
            f"{exc_info.value.details()}"
        )

    @pytest.mark.parametrize(
        "rpc_name,call",
        _global_policy_read_rpcs(),
        ids=[r[0] for r in _global_policy_read_rpcs()],
    )
    def test_platform_admin_can_access_global_policy_reads(
        self,
        rpc_name: str,
        call: Callable,
        admin_ctx: Any,
    ) -> None:
        stub, metadata = admin_ctx

        try:
            call(stub, metadata)
        except grpc.RpcError as error:
            assert error.code() != grpc.StatusCode.PERMISSION_DENIED, (
                f"{rpc_name}: Platform Admin was denied: {error.details()}"
            )
