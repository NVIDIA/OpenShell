// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "linux")]

//! OIDC authentication and workspace authorization on a live gateway, with
//! access tokens Keycloak issues for the fixture realm.
//!
//! `oidc_pkce` covers interactive login through the CLI. These tests get
//! tokens with password and client-credentials grants and call the gateway's
//! gRPC API directly, so they can check every workspace-scoped RPC: the
//! gateway validates the real token, the authorization middleware lets a
//! member-less user through, and the handler's membership check refuses it
//! with the remediation the CLI shows.
//!
//! Ported from `e2e/python/oidc/oidc_auth_test.py` and
//! `e2e/python/oidc/workspace_authz_test.py`. Run with
//! `mise run e2e:oidc-pkce:docker`, which starts Keycloak and a gateway that
//! trusts it.

use std::process::Stdio;

use base64::Engine as _;
use openshell_sdk::raw::{AuthedGrpcClient, proto};
use openshell_sdk::{AuthConfig, ClientConfig, OpenShellClient};
use serial_test::serial;
use tokio::process::Command;
use tonic::{Code, Status};

const USER_ROLE: i32 = proto::WorkspaceRole::User as i32;
const ADMIN_ROLE: i32 = proto::WorkspaceRole::Admin as i32;
const ALL_SCOPES: &str = "openid openshell:all";
/// A sandbox name no test creates, for RPCs that name one.
const MISSING: &str = "nonexistent";

// ── Tokens and clients ─────────────────────────────────────────────────

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("OIDC authz E2E requires {name}"))
}

/// Request an access token from the realm's token endpoint.
async fn token(form: &[(&str, &str)]) -> String {
    let endpoint = format!(
        "{}/protocol/openid-connect/token",
        env("OPENSHELL_E2E_OIDC_ISSUER")
    );
    let mut command = Command::new("curl");
    command.args(["-sS", "--fail-with-body", "--max-time", "20"]);
    for (key, value) in form {
        command
            .arg("--data-urlencode")
            .arg(format!("{key}={value}"));
    }
    let output = command
        .arg(&endpoint)
        .stdin(Stdio::null())
        .output()
        .await
        .expect("run curl");
    let body = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "token request to {endpoint} failed: {body} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value = serde_json::from_str(&body).expect("token response JSON");
    response["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("token response has no access_token: {body}"))
        .to_string()
}

/// A password-grant token for a fixture user through the CLI's client.
async fn password_token(username: &str, password: &str, scope: Option<&str>) -> String {
    let mut form = vec![
        ("grant_type", "password"),
        ("client_id", "openshell-cli"),
        ("username", username),
        ("password", password),
    ];
    if let Some(scope) = scope {
        form.push(("scope", scope));
    }
    token(&form).await
}

/// The `sub` claim of an access token, which workspace membership names.
fn subject(token: &str) -> String {
    let payload = token.split('.').nth(1).expect("JWT payload");
    let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .expect("JWT payload base64");
    let claims: serde_json::Value = serde_json::from_slice(&claims).expect("JWT claims JSON");
    claims["sub"].as_str().expect("JWT sub").to_string()
}

/// A gateway client that sends `token` as its bearer, or no token.
async fn client(token: Option<&str>) -> AuthedGrpcClient {
    let mut config = ClientConfig::new(env("OPENSHELL_E2E_OIDC_GATEWAY_ENDPOINT"));
    if let Ok(ca) = std::env::var("OPENSHELL_E2E_GATEWAY_CA_CERT") {
        config.ca_cert = Some(std::fs::read(&ca).expect("read the gateway CA"));
    }
    config.auth = token.map(AuthConfig::oidc);
    OpenShellClient::connect(config)
        .await
        .expect("connect to the OIDC gateway")
        .raw_grpc()
}

struct Identity {
    client: AuthedGrpcClient,
    sub: String,
}

async fn identity(username: &str, password: &str) -> Identity {
    let token = password_token(username, password, Some(ALL_SCOPES)).await;
    Identity {
        sub: subject(&token),
        client: client(Some(&token)).await,
    }
}

async fn admin() -> Identity {
    identity("admin@test", "admin").await
}

async fn user() -> Identity {
    identity("user@test", "user").await
}

/// A workspace name unique to this run. Workspace names are at most 19
/// characters, so `label` is at most five.
fn unique_workspace(label: &str) -> String {
    assert!(label.len() <= 5, "workspace label {label:?} is too long");
    let suffix: u32 = rand::random();
    format!("az-{label}-{suffix:08x}")
}

// ── Workspace fixture ──────────────────────────────────────────────────

/// A workspace the Platform Admin creates, with a seeded provider so reads
/// have something to return. Call [`Workspace::delete`] at the end.
struct Workspace {
    name: String,
    provider: String,
}

impl Workspace {
    async fn create(admin: &mut Identity, label: &str) -> Self {
        let name = unique_workspace(label);
        admin
            .client
            .create_workspace(proto::CreateWorkspaceRequest {
                name: name.clone(),
                ..Default::default()
            })
            .await
            .unwrap_or_else(|status| panic!("create workspace {name}: {status}"));
        let provider = "e2e-authz-provider".to_string();
        admin
            .client
            .create_provider(provider_request(&name, &provider))
            .await
            .unwrap_or_else(|status| panic!("seed provider in {name}: {status}"));
        Self { name, provider }
    }

    async fn delete(self, admin: &mut Identity) {
        let _ = admin
            .client
            .delete_provider(proto::DeleteProviderRequest {
                name: self.provider.clone(),
                workspace_scope: Some(proto::workspace_selector(&self.name)),
                ..Default::default()
            })
            .await;
        if let Err(status) = admin
            .client
            .delete_workspace(proto::DeleteWorkspaceRequest {
                name: self.name.clone(),
                ..Default::default()
            })
            .await
        {
            eprintln!("warning: delete workspace {}: {status}", self.name);
        }
    }
}

async fn add_member(admin: &mut Identity, workspace: &str, subject: &str, role: i32) {
    admin
        .client
        .add_workspace_member(proto::AddWorkspaceMemberRequest {
            workspace_scope: Some(proto::workspace_selector(workspace)),
            principal_subject: subject.to_string(),
            role,
            ..Default::default()
        })
        .await
        .unwrap_or_else(|status| panic!("add {subject} to {workspace}: {status}"));
}

async fn remove_member(admin: &mut Identity, workspace: &str, subject: &str) {
    let _ = admin
        .client
        .remove_workspace_member(proto::RemoveWorkspaceMemberRequest {
            workspace_scope: Some(proto::workspace_selector(workspace)),
            principal_subject: subject.to_string(),
            ..Default::default()
        })
        .await;
}

fn provider_request(workspace: &str, name: &str) -> proto::CreateProviderRequest {
    proto::CreateProviderRequest {
        workspace_scope: Some(proto::workspace_selector(workspace)),
        provider: Some(proto::Provider {
            metadata: Some(proto::ObjectMeta {
                name: name.to_string(),
                workspace: workspace.to_string(),
                ..Default::default()
            }),
            r#type: "claude-code".to_string(),
            credentials: [("ANTHROPIC_API_KEY".to_string(), "v".to_string())].into(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

// ── The RPCs under test ────────────────────────────────────────────────

/// Workspace-scoped RPCs, each called with a minimal request against a
/// workspace. RPCs that name a sandbox name one that doesn't exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rpc {
    GetWorkspace,
    ListWorkspaceMembers,
    AddWorkspaceMember,
    RemoveWorkspaceMember,
    CreateSandbox,
    GetSandbox,
    ListSandboxes,
    DeleteSandbox,
    ListSandboxProviders,
    AttachSandboxProvider,
    DetachSandboxProvider,
    CreateProvider,
    GetProvider,
    ListProviders,
    UpdateProvider,
    DeleteProvider,
    ListProviderProfiles,
    GetProviderProfile,
    ImportProviderProfiles,
    UpdateProviderProfiles,
    LintProviderProfiles,
    DeleteProviderProfile,
    GetProviderRefreshStatus,
    ConfigureProviderRefresh,
    RotateProviderCredential,
    DeleteProviderRefresh,
    ExposeService,
    GetService,
    ListServices,
    DeleteService,
    GetSandboxPolicyStatus,
    ListSandboxPolicies,
    GetDraftPolicy,
    ApproveDraftChunk,
    RejectDraftChunk,
    ApproveAllDraftChunks,
    EditDraftChunk,
    UndoDraftChunk,
    ClearDraftChunks,
    GetDraftHistory,
    UpdateConfig,
}

impl Rpc {
    const ALL: [Self; 41] = [
        Self::GetWorkspace,
        Self::ListWorkspaceMembers,
        Self::AddWorkspaceMember,
        Self::RemoveWorkspaceMember,
        Self::CreateSandbox,
        Self::GetSandbox,
        Self::ListSandboxes,
        Self::DeleteSandbox,
        Self::ListSandboxProviders,
        Self::AttachSandboxProvider,
        Self::DetachSandboxProvider,
        Self::CreateProvider,
        Self::GetProvider,
        Self::ListProviders,
        Self::UpdateProvider,
        Self::DeleteProvider,
        Self::ListProviderProfiles,
        Self::GetProviderProfile,
        Self::ImportProviderProfiles,
        Self::UpdateProviderProfiles,
        Self::LintProviderProfiles,
        Self::DeleteProviderProfile,
        Self::GetProviderRefreshStatus,
        Self::ConfigureProviderRefresh,
        Self::RotateProviderCredential,
        Self::DeleteProviderRefresh,
        Self::ExposeService,
        Self::GetService,
        Self::ListServices,
        Self::DeleteService,
        Self::GetSandboxPolicyStatus,
        Self::ListSandboxPolicies,
        Self::GetDraftPolicy,
        Self::ApproveDraftChunk,
        Self::RejectDraftChunk,
        Self::ApproveAllDraftChunks,
        Self::EditDraftChunk,
        Self::UndoDraftChunk,
        Self::ClearDraftChunks,
        Self::GetDraftHistory,
        Self::UpdateConfig,
    ];

    /// Whether the RPC looks up a sandbox by name first. Those answer a
    /// caller who can't see the sandbox with `NOT_FOUND`, so its existence in
    /// another workspace doesn't leak.
    fn names_sandbox(self) -> bool {
        matches!(
            self,
            Self::GetSandbox
                | Self::DeleteSandbox
                | Self::ListSandboxProviders
                | Self::AttachSandboxProvider
                | Self::DetachSandboxProvider
                | Self::ExposeService
                | Self::GetService
                | Self::DeleteService
                | Self::GetSandboxPolicyStatus
                | Self::ListSandboxPolicies
                | Self::GetDraftPolicy
                | Self::ApproveDraftChunk
                | Self::RejectDraftChunk
                | Self::ApproveAllDraftChunks
                | Self::EditDraftChunk
                | Self::UndoDraftChunk
                | Self::ClearDraftChunks
                | Self::GetDraftHistory
                | Self::UpdateConfig
        )
    }

    /// Call the RPC against workspace `ws`.
    #[allow(clippy::too_many_lines)]
    async fn call(self, c: &mut AuthedGrpcClient, ws: &str) -> Result<(), Status> {
        let scope = Some(proto::workspace_selector(ws));
        let sandbox = MISSING.to_string();
        match self {
            Self::GetWorkspace => c
                .get_workspace(proto::GetWorkspaceRequest {
                    name: ws.to_string(),
                })
                .await
                .map(drop),
            Self::ListWorkspaceMembers => c
                .list_workspace_members(proto::ListWorkspaceMembersRequest {
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::AddWorkspaceMember => c
                .add_workspace_member(proto::AddWorkspaceMemberRequest {
                    workspace_scope: scope,
                    principal_subject: "fake".to_string(),
                    role: USER_ROLE,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::RemoveWorkspaceMember => c
                .remove_workspace_member(proto::RemoveWorkspaceMemberRequest {
                    workspace_scope: scope,
                    principal_subject: "fake".to_string(),
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::CreateSandbox => c
                .create_sandbox(proto::CreateSandboxRequest {
                    workspace_scope: scope,
                    spec: Some(proto::SandboxSpec {
                        template: Some(proto::SandboxTemplate {
                            image: "ubuntu:24.04".to_string(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::GetSandbox => c
                .get_sandbox(proto::GetSandboxRequest {
                    name: sandbox,
                    workspace_scope: scope,
                })
                .await
                .map(drop),
            Self::ListSandboxes => c
                .list_sandboxes(proto::ListSandboxesRequest {
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::DeleteSandbox => c
                .delete_sandbox(proto::DeleteSandboxRequest {
                    name: sandbox,
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::ListSandboxProviders => c
                .list_sandbox_providers(proto::ListSandboxProvidersRequest {
                    sandbox,
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::AttachSandboxProvider => c
                .attach_sandbox_provider(proto::AttachSandboxProviderRequest {
                    sandbox,
                    provider: MISSING.to_string(),
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::DetachSandboxProvider => c
                .detach_sandbox_provider(proto::DetachSandboxProviderRequest {
                    sandbox,
                    provider: MISSING.to_string(),
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::CreateProvider => c
                .create_provider(provider_request(ws, "authz-test"))
                .await
                .map(drop),
            Self::GetProvider => c
                .get_provider(proto::GetProviderRequest {
                    name: MISSING.to_string(),
                    workspace_scope: scope,
                })
                .await
                .map(drop),
            Self::ListProviders => c
                .list_providers(proto::ListProvidersRequest {
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::UpdateProvider => {
                let created = provider_request(ws, MISSING);
                c.update_provider(proto::UpdateProviderRequest {
                    workspace_scope: scope,
                    provider: created.provider,
                    ..Default::default()
                })
                .await
                .map(drop)
            }
            Self::DeleteProvider => c
                .delete_provider(proto::DeleteProviderRequest {
                    name: MISSING.to_string(),
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::ListProviderProfiles => c
                .list_provider_profiles(proto::ListProviderProfilesRequest {
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::GetProviderProfile => c
                .get_provider_profile(proto::GetProviderProfileRequest {
                    id: MISSING.to_string(),
                    workspace_scope: scope,
                })
                .await
                .map(drop),
            Self::ImportProviderProfiles => c
                .import_provider_profiles(proto::ImportProviderProfilesRequest {
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::UpdateProviderProfiles => c
                .update_provider_profiles(proto::UpdateProviderProfilesRequest {
                    workspace_scope: scope,
                    id: MISSING.to_string(),
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::LintProviderProfiles => c
                .lint_provider_profiles(proto::LintProviderProfilesRequest {
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::DeleteProviderProfile => c
                .delete_provider_profile(proto::DeleteProviderProfileRequest {
                    id: MISSING.to_string(),
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::GetProviderRefreshStatus => c
                .get_provider_refresh_status(proto::GetProviderRefreshStatusRequest {
                    provider: MISSING.to_string(),
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::ConfigureProviderRefresh => c
                .configure_provider_refresh(proto::ConfigureProviderRefreshRequest {
                    provider: MISSING.to_string(),
                    credential_key: "k".to_string(),
                    strategy: proto::ProviderCredentialRefreshStrategy::Static as i32,
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::RotateProviderCredential => c
                .rotate_provider_credential(proto::RotateProviderCredentialRequest {
                    provider: MISSING.to_string(),
                    credential_key: "k".to_string(),
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::DeleteProviderRefresh => c
                .delete_provider_refresh(proto::DeleteProviderRefreshRequest {
                    provider: MISSING.to_string(),
                    credential_key: "k".to_string(),
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::ExposeService => c
                .expose_service(proto::ExposeServiceRequest {
                    sandbox,
                    name: "svc".to_string(),
                    target_port: 8080,
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::GetService => c
                .get_service(proto::GetServiceRequest {
                    sandbox,
                    name: "svc".to_string(),
                    workspace_scope: scope,
                })
                .await
                .map(drop),
            Self::ListServices => c
                .list_services(proto::ListServicesRequest {
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::DeleteService => c
                .delete_service(proto::DeleteServiceRequest {
                    sandbox,
                    name: "svc".to_string(),
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::GetSandboxPolicyStatus => c
                .get_sandbox_policy_status(proto::GetSandboxPolicyStatusRequest {
                    sandbox,
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::ListSandboxPolicies => c
                .list_sandbox_policies(proto::ListSandboxPoliciesRequest {
                    sandbox,
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::GetDraftPolicy => c
                .get_draft_policy(proto::GetDraftPolicyRequest {
                    sandbox,
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::ApproveDraftChunk => c
                .approve_draft_chunk(proto::ApproveDraftChunkRequest {
                    sandbox,
                    chunk_id: "x".to_string(),
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::RejectDraftChunk => c
                .reject_draft_chunk(proto::RejectDraftChunkRequest {
                    sandbox,
                    chunk_id: "x".to_string(),
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::ApproveAllDraftChunks => c
                .approve_all_draft_chunks(proto::ApproveAllDraftChunksRequest {
                    sandbox,
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::EditDraftChunk => c
                .edit_draft_chunk(proto::EditDraftChunkRequest {
                    sandbox,
                    chunk_id: "x".to_string(),
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::UndoDraftChunk => c
                .undo_draft_chunk(proto::UndoDraftChunkRequest {
                    sandbox,
                    chunk_id: "x".to_string(),
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::ClearDraftChunks => c
                .clear_draft_chunks(proto::ClearDraftChunksRequest {
                    sandbox,
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::GetDraftHistory => c
                .get_draft_history(proto::GetDraftHistoryRequest {
                    sandbox,
                    workspace_scope: scope,
                })
                .await
                .map(drop),
            Self::UpdateConfig => c
                .update_config(proto::UpdateConfigRequest {
                    sandbox,
                    workspace_scope: scope,
                    ..Default::default()
                })
                .await
                .map(drop),
        }
    }
}

/// Platform-scoped RPCs: provider profiles without a workspace and global
/// policy reads.
#[derive(Clone, Copy, Debug)]
enum PlatformRpc {
    ListProviderProfiles,
    GetProviderProfile,
    ImportProviderProfiles,
    UpdateProviderProfiles,
    LintProviderProfiles,
    DeleteProviderProfile,
    GetGlobalPolicyStatus,
    ListGlobalPolicies,
}

impl PlatformRpc {
    const ALL: [Self; 8] = [
        Self::ListProviderProfiles,
        Self::GetProviderProfile,
        Self::ImportProviderProfiles,
        Self::UpdateProviderProfiles,
        Self::LintProviderProfiles,
        Self::DeleteProviderProfile,
        Self::GetGlobalPolicyStatus,
        Self::ListGlobalPolicies,
    ];

    async fn call(self, c: &mut AuthedGrpcClient) -> Result<(), Status> {
        match self {
            Self::ListProviderProfiles => c
                .list_provider_profiles(proto::ListProviderProfilesRequest::default())
                .await
                .map(drop),
            Self::GetProviderProfile => c
                .get_provider_profile(proto::GetProviderProfileRequest {
                    id: MISSING.to_string(),
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::ImportProviderProfiles => c
                .import_provider_profiles(proto::ImportProviderProfilesRequest::default())
                .await
                .map(drop),
            Self::UpdateProviderProfiles => c
                .update_provider_profiles(proto::UpdateProviderProfilesRequest {
                    id: MISSING.to_string(),
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::LintProviderProfiles => c
                .lint_provider_profiles(proto::LintProviderProfilesRequest::default())
                .await
                .map(drop),
            Self::DeleteProviderProfile => c
                .delete_provider_profile(proto::DeleteProviderProfileRequest {
                    id: MISSING.to_string(),
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::GetGlobalPolicyStatus => c
                .get_sandbox_policy_status(proto::GetSandboxPolicyStatusRequest {
                    global: true,
                    ..Default::default()
                })
                .await
                .map(drop),
            Self::ListGlobalPolicies => c
                .list_sandbox_policies(proto::ListSandboxPoliciesRequest {
                    global: true,
                    ..Default::default()
                })
                .await
                .map(drop),
        }
    }
}

// ── Expectations ───────────────────────────────────────────────────────

/// The refusal a non-member gets from the handler, naming the workspace and
/// the command that would let them in.
fn check_non_member(result: Result<(), Status>, ws: &str, sub: &str) -> Result<(), String> {
    let status = result.err().ok_or("succeeded")?;
    let command =
        format!("openshell workspace member add --workspace '{ws}' --subject '{sub}' --role user");
    if status.code() == Code::PermissionDenied
        && status
            .message()
            .contains(&format!("not a member of workspace '{ws}'"))
        && status.message().contains(&command)
    {
        Ok(())
    } else {
        Err(format!("{:?}: {}", status.code(), status.message()))
    }
}

fn check_workspace_admin_required(
    result: Result<(), Status>,
    ws: &str,
    sub: &str,
) -> Result<(), String> {
    let status = result.err().ok_or("succeeded")?;
    let command =
        format!("openshell workspace member add --workspace '{ws}' --subject '{sub}' --role admin");
    if status.code() == Code::PermissionDenied
        && status.message().contains(&format!(
            "workspace role 'admin' required in workspace '{ws}'"
        ))
        && status.message().contains(&command)
    {
        Ok(())
    } else {
        Err(format!("{:?}: {}", status.code(), status.message()))
    }
}

fn check_code(result: Result<(), Status>, code: Code) -> Result<(), String> {
    match result {
        Err(status) if status.code() == code => Ok(()),
        Err(status) => Err(format!("{:?}: {}", status.code(), status.message())),
        Ok(()) => Err("succeeded".to_string()),
    }
}

fn check_platform_admin_required(result: Result<(), Status>) -> Result<(), String> {
    check_code(result.clone(), Code::PermissionDenied)?;
    let message = result.err().map(|status| status.message().to_string());
    if message
        .as_deref()
        .is_some_and(|message| message.contains("platform admin role required"))
    {
        Ok(())
    } else {
        Err(format!(
            "refused without naming the platform admin role: {message:?}"
        ))
    }
}

/// The call wasn't refused for authorization. It may still fail, for
/// example because the sandbox it names doesn't exist.
fn check_not_denied(result: Result<(), Status>) -> Result<(), String> {
    match result {
        Err(status) if status.code() == Code::PermissionDenied => {
            Err(format!("denied: {}", status.message()))
        }
        _ => Ok(()),
    }
}

fn check_ok(result: Result<(), Status>) -> Result<(), String> {
    result.map_err(|status| format!("{:?}: {}", status.code(), status.message()))
}

/// Collects mismatches, so one run reports every RPC that misbehaves.
#[derive(Default)]
struct Failures(Vec<String>);

impl Failures {
    fn check(&mut self, what: impl std::fmt::Display, outcome: Result<(), String>) {
        if let Err(error) = outcome {
            self.0.push(format!("{what}: {error}"));
        }
    }

    fn assert_none(self) {
        assert!(self.0.is_empty(), "\n{}", self.0.join("\n"));
    }
}

async fn list_workspace_names(client: &mut AuthedGrpcClient) -> Vec<String> {
    client
        .list_workspaces(proto::ListWorkspacesRequest::default())
        .await
        .expect("list workspaces")
        .into_inner()
        .workspaces
        .into_iter()
        .filter_map(|workspace| workspace.metadata.map(|metadata| metadata.name))
        .collect()
}

// ── Tests ──────────────────────────────────────────────────────────────

/// Health answers without a token; a user RPC without a token is
/// unauthenticated.
#[tokio::test]
#[serial(oidc_pkce)]
async fn requests_without_a_token() {
    let mut anonymous = client(None).await;
    let health = anonymous
        .health(proto::HealthRequest::default())
        .await
        .expect("health without a token")
        .into_inner();
    assert_eq!(health.status, proto::ServiceStatus::Healthy as i32);

    let status = Rpc::ListSandboxes
        .call(&mut anonymous, "default")
        .await
        .expect_err("list sandboxes without a token");
    assert_eq!(status.code(), Code::Unauthenticated, "{status}");
}

/// The gateway enforces the scopes in a real Keycloak token: sandbox scopes
/// allow sandbox reads but not provider reads, and a token without any
/// `OpenShell` scope is refused, even for the Platform Admin.
#[tokio::test]
#[serial(oidc_pkce)]
async fn token_scopes_limit_rpcs() {
    let sandbox_scoped = password_token(
        "admin@test",
        "admin",
        Some("openid sandbox:read sandbox:write"),
    )
    .await;
    let mut scoped = client(Some(&sandbox_scoped)).await;
    Rpc::ListSandboxes
        .call(&mut scoped, "default")
        .await
        .expect("list sandboxes with sandbox scopes");
    let status = Rpc::ListProviders
        .call(&mut scoped, "default")
        .await
        .expect_err("list providers with only sandbox scopes");
    assert_eq!(status.code(), Code::PermissionDenied, "{status}");
    assert!(status.message().contains("provider:read"), "{status}");

    let unscoped = password_token("admin@test", "admin", None).await;
    let status = Rpc::ListSandboxes
        .call(&mut client(Some(&unscoped)).await, "default")
        .await
        .expect_err("list sandboxes without OpenShell scopes");
    assert_eq!(status.code(), Code::PermissionDenied, "{status}");
}

/// A client-credentials token for the CI client is a user the gateway can
/// make a workspace member.
#[tokio::test]
#[serial(oidc_pkce)]
async fn client_credentials_token_acts_as_member() {
    let mut admin = admin().await;
    let workspace = Workspace::create(&mut admin, "ci").await;
    let ci_token = token(&[
        ("grant_type", "client_credentials"),
        ("client_id", "openshell-ci"),
        ("client_secret", "ci-test-secret"),
    ])
    .await;
    add_member(&mut admin, &workspace.name, &subject(&ci_token), USER_ROLE).await;

    let result = Rpc::ListSandboxes
        .call(&mut client(Some(&ci_token)).await, &workspace.name)
        .await;
    workspace.delete(&mut admin).await;
    result.expect("list sandboxes with the CI client's token");
}

/// A user with a valid token who isn't a member of a workspace gets past the
/// authorization middleware on every workspace-scoped RPC, and the handler
/// refuses them: with the membership remediation, or `NOT_FOUND` for RPCs that
/// name a sandbox. The workspace isn't listed for them either.
#[tokio::test]
#[serial(oidc_pkce)]
async fn non_member_is_refused_on_every_workspace_rpc() {
    let mut admin = admin().await;
    let mut user = user().await;
    let workspace = Workspace::create(&mut admin, "nomem").await;
    let ws = workspace.name.clone();

    let mut failures = Failures::default();
    for rpc in Rpc::ALL {
        let result = rpc.call(&mut user.client, &ws).await;
        let outcome = if rpc.names_sandbox() {
            check_code(result, Code::NotFound)
        } else {
            check_non_member(result, &ws, &user.sub)
        };
        failures.check(format!("{rpc:?}"), outcome);
    }
    let listed = list_workspace_names(&mut user.client).await;
    failures.check(
        "ListWorkspaces",
        if listed.contains(&ws) {
            Err(format!("lists {ws}"))
        } else {
            Ok(())
        },
    );

    workspace.delete(&mut admin).await;
    failures.assert_none();
}

/// The Platform Admin reaches a workspace they aren't a member of.
#[tokio::test]
#[serial(oidc_pkce)]
async fn platform_admin_bypasses_membership() {
    let mut admin = admin().await;
    let workspace = Workspace::create(&mut admin, "admin").await;
    let ws = workspace.name.clone();
    let admin_sub = admin.sub.clone();
    remove_member(&mut admin, &ws, &admin_sub).await;

    let mut failures = Failures::default();
    for rpc in [Rpc::GetWorkspace, Rpc::ListSandboxes, Rpc::ListServices] {
        let outcome = check_ok(rpc.call(&mut admin.client, &ws).await);
        failures.check(format!("{rpc:?}"), outcome);
    }
    let provider = admin
        .client
        .get_provider(proto::GetProviderRequest {
            name: workspace.provider.clone(),
            workspace_scope: Some(proto::workspace_selector(&ws)),
        })
        .await
        .map(drop);
    failures.check("GetProvider (seeded)", check_ok(provider));
    let history = Rpc::GetDraftHistory.call(&mut admin.client, &ws).await;
    failures.check("GetDraftHistory", check_not_denied(history));

    workspace.delete(&mut admin).await;
    failures.assert_none();
}

/// A workspace user reads the workspace but needs the workspace admin role
/// to change it; it lists only the workspaces they belong to. A workspace
/// admin manages providers and user members, but can't grant the admin role,
/// list across workspaces, or change global settings, which need the
/// Platform Admin.
#[tokio::test]
#[serial(oidc_pkce)]
async fn workspace_roles_bound_what_members_can_do() {
    let mut admin = admin().await;
    let mut user = user().await;
    let workspace = Workspace::create(&mut admin, "roles").await;
    let other = Workspace::create(&mut admin, "other").await;
    let ws = workspace.name.clone();
    let sub = user.sub.clone();
    let mut failures = Failures::default();

    // As a workspace user.
    add_member(&mut admin, &workspace.name, &sub, USER_ROLE).await;
    for rpc in [
        Rpc::GetWorkspace,
        Rpc::ListSandboxes,
        Rpc::ListProviders,
        Rpc::ListServices,
        Rpc::ListWorkspaceMembers,
    ] {
        let outcome = check_ok(rpc.call(&mut user.client, &ws).await);
        failures.check(format!("user {rpc:?}"), outcome);
    }
    let provider = user
        .client
        .get_provider(proto::GetProviderRequest {
            name: workspace.provider.clone(),
            workspace_scope: Some(proto::workspace_selector(&ws)),
        })
        .await
        .map(drop);
    failures.check("user GetProvider (seeded)", check_ok(provider));
    for rpc in [Rpc::CreateProvider, Rpc::AddWorkspaceMember] {
        let outcome =
            check_workspace_admin_required(rpc.call(&mut user.client, &ws).await, &ws, &sub);
        failures.check(format!("user {rpc:?}"), outcome);
    }
    let approve = Rpc::ApproveDraftChunk.call(&mut user.client, &ws).await;
    failures.check(
        "user ApproveDraftChunk",
        check_code(approve, Code::NotFound),
    );
    let listed = list_workspace_names(&mut user.client).await;
    failures.check(
        "user ListWorkspaces",
        if listed.contains(&ws)
            && !listed.contains(&other.name)
            && !listed.iter().any(|name| name == "default")
        {
            Ok(())
        } else {
            Err(format!(
                "expected {ws} and neither {} nor default; got {listed:?}",
                other.name
            ))
        },
    );

    // As a workspace admin.
    remove_member(&mut admin, &ws, &sub).await;
    add_member(&mut admin, &workspace.name, &sub, ADMIN_ROLE).await;
    let created = user
        .client
        .create_provider(provider_request(&ws, "e2e-authz-ws-admin-prov"))
        .await
        .map(drop);
    failures.check("admin CreateProvider", check_ok(created));
    let added = user
        .client
        .add_workspace_member(proto::AddWorkspaceMemberRequest {
            workspace_scope: Some(proto::workspace_selector(&ws)),
            principal_subject: "another-subject".to_string(),
            role: USER_ROLE,
            ..Default::default()
        })
        .await
        .map(drop);
    failures.check("admin AddWorkspaceMember (user role)", check_ok(added));
    let granted = user
        .client
        .add_workspace_member(proto::AddWorkspaceMemberRequest {
            workspace_scope: Some(proto::workspace_selector(&ws)),
            principal_subject: "admin-subject".to_string(),
            role: ADMIN_ROLE,
            ..Default::default()
        })
        .await
        .map(drop);
    failures.check(
        "admin AddWorkspaceMember (admin role)",
        check_code(granted, Code::PermissionDenied),
    );
    let all = Some(proto::all_workspaces_selector());
    let sandboxes = user
        .client
        .list_sandboxes(proto::ListSandboxesRequest {
            workspace_scope: all.clone(),
            ..Default::default()
        })
        .await
        .map(drop);
    failures.check(
        "admin ListSandboxes (all workspaces)",
        check_code(sandboxes, Code::PermissionDenied),
    );
    let providers = user
        .client
        .list_providers(proto::ListProvidersRequest {
            workspace_scope: all.clone(),
            ..Default::default()
        })
        .await
        .map(drop);
    failures.check(
        "admin ListProviders (all workspaces)",
        check_code(providers, Code::PermissionDenied),
    );
    let services = user
        .client
        .list_services(proto::ListServicesRequest {
            workspace_scope: all,
            ..Default::default()
        })
        .await
        .map(drop);
    failures.check(
        "admin ListServices (all workspaces)",
        check_code(services, Code::PermissionDenied),
    );

    // A workspace admin of `default` still can't change global settings.
    add_member(&mut admin, "default", &sub, ADMIN_ROLE).await;
    let global = user
        .client
        .update_config(proto::UpdateConfigRequest {
            setting_key: "log_level".to_string(),
            delete_setting: true,
            global: true,
            ..Default::default()
        })
        .await
        .map(drop);
    failures.check(
        "default admin UpdateConfig (global)",
        check_platform_admin_required(global),
    );
    remove_member(&mut admin, "default", &sub).await;

    let _ = admin
        .client
        .delete_provider(proto::DeleteProviderRequest {
            name: "e2e-authz-ws-admin-prov".to_string(),
            workspace_scope: Some(proto::workspace_selector(&ws)),
            ..Default::default()
        })
        .await;
    remove_member(&mut admin, &ws, &sub).await;
    remove_member(&mut admin, &ws, "another-subject").await;
    other.delete(&mut admin).await;
    workspace.delete(&mut admin).await;
    failures.assert_none();
}

/// Platform provider profiles and global policy history need the Platform
/// Admin: a user is refused, the Platform Admin isn't.
#[tokio::test]
#[serial(oidc_pkce)]
async fn platform_scope_requires_platform_admin() {
    let mut admin = admin().await;
    let mut user = user().await;
    let mut failures = Failures::default();
    for rpc in PlatformRpc::ALL {
        let outcome = check_platform_admin_required(rpc.call(&mut user.client).await);
        failures.check(format!("user {rpc:?}"), outcome);
        let outcome = check_not_denied(rpc.call(&mut admin.client).await);
        failures.check(format!("admin {rpc:?}"), outcome);
    }
    failures.assert_none();
}
