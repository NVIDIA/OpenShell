// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workspace lifecycle handlers.

#![allow(clippy::result_large_err)] // gRPC handlers return Result<Response<_>, Status>

use std::sync::Arc;

use openshell_core::ObjectName;
use openshell_core::proto::datamodel::v1::{ObjectMeta, WorkspacePhase, WorkspaceStatus};
use openshell_core::proto::{
    AddWorkspaceMemberRequest, AddWorkspaceMemberResponse, CreateWorkspaceRequest,
    CreateWorkspaceResponse, DeleteWorkspaceRequest, DeleteWorkspaceResponse, GetWorkspaceRequest,
    GetWorkspaceResponse, InferenceRoute, ListWorkspaceMembersRequest,
    ListWorkspaceMembersResponse, ListWorkspacesRequest, ListWorkspacesResponse, Provider,
    RemoveWorkspaceMemberRequest, RemoveWorkspaceMemberResponse, Sandbox, ServiceEndpoint,
    SshSession, StoredProviderCredentialRefreshState, StoredProviderProfile, Workspace,
    WorkspaceMember, WorkspaceRole,
};
use prost::Message;
use tonic::{Request, Response, Status};

use crate::ServerState;
use crate::persistence::{
    DRAFT_CHUNK_OBJECT_TYPE, ObjectLabels, ObjectType, POLICY_OBJECT_TYPE, WriteCondition,
    current_time_ms,
};
use std::collections::HashMap;

use super::{MAX_PAGE_SIZE, clamp_limit};

pub const WORKSPACE_OBJECT_TYPE: &str = "workspace";
pub const DEFAULT_WORKSPACE_NAME: &str = "default";
const MAX_WORKSPACE_MEMBERS: u32 = 1000;

impl ObjectType for Workspace {
    fn object_type() -> &'static str {
        WORKSPACE_OBJECT_TYPE
    }
}

impl ObjectType for WorkspaceMember {
    fn object_type() -> &'static str {
        "workspace_member"
    }
}

fn validate_workspace_name(name: &str) -> Result<(), Status> {
    if name.is_empty() {
        return Err(Status::invalid_argument("workspace name is required"));
    }
    if name.len() > crate::grpc::MAX_ROUTABLE_NAME_LEN {
        return Err(Status::invalid_argument(format!(
            "workspace name exceeds maximum length ({} > {})",
            name.len(),
            crate::grpc::MAX_ROUTABLE_NAME_LEN,
        )));
    }
    super::validation::validate_dns1123_label(name, "workspace name")
}

/// A resolved workspace name with its current lifecycle state.
#[derive(Debug)]
pub struct ResolvedWorkspace {
    pub name: String,
    pub terminating: bool,
}

impl ResolvedWorkspace {
    /// Consume the resolved workspace and return the name, or reject the
    /// operation if the workspace is being deleted.
    pub fn ensure_active(self) -> Result<String, Status> {
        if self.terminating {
            return Err(Status::failed_precondition(format!(
                "workspace '{}' is being deleted",
                self.name
            )));
        }
        Ok(self.name)
    }
}

/// Resolve a workspace for provider profile operations.
///
/// Provider profiles support a platform scope where `""` is a distinct,
/// meaningful value (not an alias for `"default"`). This function preserves
/// `""` as-is for platform-scoped operations. Non-empty workspace values are
/// validated for existence via [`resolve_workspace`].
pub async fn resolve_profile_workspace(
    store: &crate::persistence::Store,
    workspace: &str,
) -> Result<ResolvedWorkspace, Status> {
    if workspace.is_empty() {
        return Ok(ResolvedWorkspace {
            name: String::new(),
            terminating: false,
        });
    }
    resolve_workspace(store, workspace).await
}

/// Resolve and validate a workspace name from a request field.
///
/// Empty strings are normalized to `"default"`. The workspace must exist in the
/// store; returns `NOT_FOUND` if it doesn't. The returned [`ResolvedWorkspace`]
/// carries the workspace's termination state so create-path handlers can reject
/// operations on workspaces that are being deleted.
///
/// TODO(phase2): this only validates existence. Workspace membership enforcement
/// (checking the caller is a member of the resolved workspace) is deferred to
/// Phase 2.
pub async fn resolve_workspace(
    store: &crate::persistence::Store,
    workspace: &str,
) -> Result<ResolvedWorkspace, Status> {
    let name = if workspace.is_empty() {
        DEFAULT_WORKSPACE_NAME.to_string()
    } else {
        workspace.to_string()
    };

    let ws: Option<Workspace> = store
        .get_message_by_name("", &name)
        .await
        .map_err(|e| Status::internal(format!("workspace lookup failed: {e}")))?;

    match ws {
        Some(ws) => {
            let terminating = ws
                .metadata
                .as_ref()
                .is_some_and(|m| m.deletion_timestamp_ms != 0);
            Ok(ResolvedWorkspace { name, terminating })
        }
        None => Err(Status::not_found(format!("workspace '{name}' not found"))),
    }
}

pub(super) async fn handle_create_workspace(
    state: &Arc<ServerState>,
    request: Request<CreateWorkspaceRequest>,
) -> Result<Response<CreateWorkspaceResponse>, Status> {
    let req = request.into_inner();

    validate_workspace_name(&req.name)?;

    let now_ms = current_time_ms();
    let workspace_id = uuid::Uuid::new_v4().to_string();

    let workspace = Workspace {
        metadata: Some(ObjectMeta {
            id: workspace_id.clone(),
            name: req.name,
            created_at_ms: now_ms,
            labels: req.labels,
            annotations: HashMap::new(),
            resource_version: 0,
            workspace: String::new(),
            deletion_timestamp_ms: 0,
        }),
        status: Some(WorkspaceStatus {
            phase: WorkspacePhase::Active.into(),
        }),
    };

    super::validation::validate_object_metadata(workspace.metadata.as_ref(), "workspace")?;

    let meta = workspace.metadata.as_ref().unwrap();
    let labels_json =
        if meta.labels.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&meta.labels).map_err(|e| {
                Status::internal(format!("failed to serialize workspace labels: {e}"))
            })?)
        };

    let result = state
        .store
        .put_if(
            Workspace::object_type(),
            &workspace_id,
            workspace.object_name(),
            "",
            &workspace.encode_to_vec(),
            labels_json.as_deref(),
            WriteCondition::MustCreate,
        )
        .await
        .map_err(|e| {
            if matches!(
                e,
                crate::persistence::PersistenceError::UniqueViolation { .. }
            ) {
                Status::already_exists("workspace already exists")
            } else {
                Status::internal(format!("persist workspace failed: {e}"))
            }
        })?;

    let mut workspace = workspace;
    if let Some(metadata) = workspace.metadata.as_mut() {
        metadata.resource_version = result.resource_version;
    }

    Ok(Response::new(CreateWorkspaceResponse {
        workspace: Some(workspace),
    }))
}

pub(super) async fn handle_get_workspace(
    state: &Arc<ServerState>,
    request: Request<GetWorkspaceRequest>,
) -> Result<Response<GetWorkspaceResponse>, Status> {
    let name = request.into_inner().name;
    if name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    let workspace: Workspace = state
        .store
        .get_message_by_name("", &name)
        .await
        .map_err(|e| Status::internal(format!("fetch workspace failed: {e}")))?
        .ok_or_else(|| Status::not_found("workspace not found"))?;

    Ok(Response::new(GetWorkspaceResponse {
        workspace: Some(workspace),
    }))
}

pub(super) async fn handle_list_workspaces(
    state: &Arc<ServerState>,
    request: Request<ListWorkspacesRequest>,
) -> Result<Response<ListWorkspacesResponse>, Status> {
    let req = request.into_inner();
    let limit = clamp_limit(req.limit, 100, MAX_PAGE_SIZE);

    let workspaces: Vec<Workspace> = if req.label_selector.is_empty() {
        state
            .store
            .list_messages("", limit, req.offset)
            .await
            .map_err(|e| Status::internal(format!("list workspaces failed: {e}")))?
    } else {
        state
            .store
            .list_messages_with_selector("", &req.label_selector, limit, req.offset)
            .await
            .map_err(|e| Status::internal(format!("list workspaces failed: {e}")))?
    };

    Ok(Response::new(ListWorkspacesResponse { workspaces }))
}

pub(super) async fn handle_delete_workspace(
    state: &Arc<ServerState>,
    request: Request<DeleteWorkspaceRequest>,
) -> Result<Response<DeleteWorkspaceResponse>, Status> {
    let name = request.into_inner().name;
    if name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    if name == DEFAULT_WORKSPACE_NAME {
        return Err(Status::failed_precondition(
            "the default workspace cannot be deleted",
        ));
    }

    let ws: Workspace = state
        .store
        .get_message_by_name("", &name)
        .await
        .map_err(|e| Status::internal(format!("fetch workspace failed: {e}")))?
        .ok_or_else(|| Status::not_found(format!("workspace '{name}' not found")))?;

    let ws_id = ws
        .metadata
        .as_ref()
        .map(|m| m.id.clone())
        .unwrap_or_default();

    let already_terminating = ws
        .metadata
        .as_ref()
        .is_some_and(|m| m.deletion_timestamp_ms != 0);

    // Track the resource_version so the final delete targets exactly this
    // workspace instance (prevents ABA if a same-name workspace is recreated
    // between the blocker scan and the delete).
    let mut delete_version = ws.metadata.as_ref().map_or(0, |m| m.resource_version);

    if !already_terminating {
        let cas_result = state
            .store
            .update_message_cas::<Workspace, _>(&ws_id, 0, |w| {
                let now_ms = current_time_ms();
                if let Some(meta) = w.metadata.as_mut() {
                    meta.deletion_timestamp_ms = now_ms;
                }
                w.status = Some(WorkspaceStatus {
                    phase: WorkspacePhase::Terminating.into(),
                });
            })
            .await;
        match cas_result {
            Ok(updated) => {
                delete_version = updated.metadata.as_ref().map_or(0, |m| m.resource_version);
            }
            Err(e) => {
                if matches!(e, crate::persistence::PersistenceError::Conflict { .. }) {
                    let refreshed: Option<Workspace> = state
                        .store
                        .get_message_by_name("", &name)
                        .await
                        .map_err(|e| Status::internal(format!("workspace re-fetch failed: {e}")))?;
                    let refreshed = refreshed.ok_or_else(|| {
                        Status::not_found(format!("workspace '{name}' not found"))
                    })?;
                    let now_terminating = refreshed
                        .metadata
                        .as_ref()
                        .is_some_and(|m| m.deletion_timestamp_ms != 0);
                    if !now_terminating {
                        return Err(Status::aborted(
                            "workspace was concurrently modified, please retry",
                        ));
                    }
                    delete_version = refreshed
                        .metadata
                        .as_ref()
                        .map_or(0, |m| m.resource_version);
                } else {
                    return Err(Status::internal(format!(
                        "mark workspace terminating failed: {e}"
                    )));
                }
            }
        }
    }

    // The workspace is now Terminating — concurrent create-path operations
    // will be rejected by resolve_workspace + ensure_active.
    let mut blocking = Vec::new();
    for (object_type, label) in [
        (Sandbox::object_type(), "sandbox"),
        (Provider::object_type(), "provider"),
        (StoredProviderProfile::object_type(), "provider profile"),
        (ServiceEndpoint::object_type(), "service"),
        (SshSession::object_type(), "ssh session"),
        (
            super::policy::SANDBOX_SETTINGS_OBJECT_TYPE,
            "sandbox settings",
        ),
        (POLICY_OBJECT_TYPE, "sandbox policy"),
        (DRAFT_CHUNK_OBJECT_TYPE, "draft policy chunk"),
        (
            StoredProviderCredentialRefreshState::object_type(),
            "credential refresh state",
        ),
    ] {
        let records = state
            .store
            .list(object_type, &name, 1, 0)
            .await
            .map_err(|e| Status::internal(format!("resource check failed: {e}")))?;
        if !records.is_empty() {
            blocking.push(label);
        }
    }
    if !blocking.is_empty() {
        return Err(Status::failed_precondition(format!(
            "workspace '{}' still contains resources: {}",
            name,
            blocking.join(", ")
        )));
    }

    // Cascade-delete non-blocking resources before the final CAS delete.
    // This is safe without a transaction: the workspace is Terminating, so
    // ensure_active rejects new resource creation. If delete_if conflicts
    // below, the retry will find no routes/members to delete and succeed.
    state
        .store
        .delete_all_in_workspace(InferenceRoute::object_type(), &name)
        .await
        .map_err(|e| Status::internal(format!("delete inference routes failed: {e}")))?;

    state
        .store
        .delete_all_in_workspace(WorkspaceMember::object_type(), &name)
        .await
        .map_err(|e| Status::internal(format!("delete workspace members failed: {e}")))?;

    let deleted = state
        .store
        .delete_if(Workspace::object_type(), &ws_id, delete_version)
        .await
        .map_err(|e| {
            if matches!(e, crate::persistence::PersistenceError::Conflict { .. }) {
                Status::aborted("workspace was concurrently modified, please retry")
            } else {
                Status::internal(format!("delete workspace failed: {e}"))
            }
        })?;

    Ok(Response::new(DeleteWorkspaceResponse { deleted }))
}

pub(super) async fn handle_add_workspace_member(
    state: &Arc<ServerState>,
    request: Request<AddWorkspaceMemberRequest>,
) -> Result<Response<AddWorkspaceMemberResponse>, Status> {
    let req = request.into_inner();

    let workspace = resolve_workspace(&state.store, &req.workspace)
        .await?
        .ensure_active()?;

    if req.principal_subject.is_empty() {
        return Err(Status::invalid_argument("principal_subject is required"));
    }

    let role = WorkspaceRole::try_from(req.role).unwrap_or(WorkspaceRole::Unspecified);
    if role == WorkspaceRole::Unspecified {
        return Err(Status::invalid_argument(
            "role must be USER or ADMIN, not UNSPECIFIED",
        ));
    }

    let count = state
        .store
        .count_in_workspace(WorkspaceMember::object_type(), &workspace)
        .await
        .map_err(|e| Status::internal(format!("count workspace members failed: {e}")))?;
    if count >= u64::from(MAX_WORKSPACE_MEMBERS) {
        return Err(Status::resource_exhausted(format!(
            "workspace has reached the maximum of {MAX_WORKSPACE_MEMBERS} members"
        )));
    }

    let member_id = uuid::Uuid::new_v4().to_string();
    let now_ms = current_time_ms();

    let member = WorkspaceMember {
        metadata: Some(ObjectMeta {
            id: member_id.clone(),
            name: req.principal_subject.clone(),
            created_at_ms: now_ms,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            resource_version: 0,
            workspace: workspace.clone(),
            deletion_timestamp_ms: 0,
        }),
        principal_subject: req.principal_subject,
        role: req.role,
    };

    let member_labels = member.object_labels();
    let member_labels_json = if member_labels.as_ref().is_none_or(HashMap::is_empty) {
        None
    } else {
        Some(
            serde_json::to_string(&member_labels)
                .map_err(|e| Status::internal(format!("failed to serialize labels: {e}")))?,
        )
    };
    let result = state
        .store
        .put_if(
            WorkspaceMember::object_type(),
            &member_id,
            member.object_name(),
            &workspace,
            &member.encode_to_vec(),
            member_labels_json.as_deref(),
            WriteCondition::MustCreate,
        )
        .await
        .map_err(|e| {
            if matches!(
                e,
                crate::persistence::PersistenceError::UniqueViolation { .. }
            ) {
                Status::already_exists("member already exists in this workspace")
            } else {
                Status::internal(format!("persist workspace member failed: {e}"))
            }
        })?;

    let mut member = member;
    if let Some(metadata) = member.metadata.as_mut() {
        metadata.resource_version = result.resource_version;
    }

    Ok(Response::new(AddWorkspaceMemberResponse {
        member: Some(member),
    }))
}

pub(super) async fn handle_remove_workspace_member(
    state: &Arc<ServerState>,
    request: Request<RemoveWorkspaceMemberRequest>,
) -> Result<Response<RemoveWorkspaceMemberResponse>, Status> {
    let req = request.into_inner();

    let workspace = resolve_workspace(&state.store, &req.workspace).await?.name;

    if req.principal_subject.is_empty() {
        return Err(Status::invalid_argument("principal_subject is required"));
    }

    let removed = state
        .store
        .delete_by_name(
            WorkspaceMember::object_type(),
            &workspace,
            &req.principal_subject,
        )
        .await
        .map_err(|e| Status::internal(format!("remove workspace member failed: {e}")))?;

    Ok(Response::new(RemoveWorkspaceMemberResponse { removed }))
}

pub(super) async fn handle_list_workspace_members(
    state: &Arc<ServerState>,
    request: Request<ListWorkspaceMembersRequest>,
) -> Result<Response<ListWorkspaceMembersResponse>, Status> {
    let req = request.into_inner();

    let workspace = resolve_workspace(&state.store, &req.workspace).await?.name;

    let limit = clamp_limit(req.limit, 100, MAX_PAGE_SIZE);

    let members: Vec<WorkspaceMember> = state
        .store
        .list_messages(&workspace, limit, req.offset)
        .await
        .map_err(|e| Status::internal(format!("list workspace members failed: {e}")))?;

    Ok(Response::new(ListWorkspaceMembersResponse { members }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use tonic::{Code, Request};

    use crate::grpc::test_support::test_server_state;

    #[tokio::test]
    async fn create_workspace_returns_metadata() {
        let state = test_server_state().await;

        let resp = handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                name: "new-ws".to_string(),
                labels: HashMap::from([("env".to_string(), "test".to_string())]),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        let ws = resp.workspace.unwrap();
        let meta = ws.metadata.as_ref().unwrap();
        assert_eq!(meta.name, "new-ws");
        assert!(!meta.id.is_empty(), "id should be a generated UUID");
        assert!(meta.created_at_ms > 0, "created_at_ms should be set");
        assert_eq!(meta.labels.get("env").map(String::as_str), Some("test"));
        assert!(meta.resource_version > 0, "resource_version should be set");
        assert_eq!(meta.deletion_timestamp_ms, 0);

        let status = ws.status.as_ref().unwrap();
        assert_eq!(status.phase, i32::from(WorkspacePhase::Active));
    }

    #[tokio::test]
    async fn create_workspace_already_exists() {
        let state = test_server_state().await;

        handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                name: "dup-ws".to_string(),
                labels: HashMap::new(),
            }),
        )
        .await
        .unwrap();

        let err = handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                name: "dup-ws".to_string(),
                labels: HashMap::new(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::AlreadyExists);
    }

    #[tokio::test]
    async fn get_workspace_round_trip() {
        let state = test_server_state().await;

        handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                name: "fetch-me".to_string(),
                labels: HashMap::from([("team".to_string(), "infra".to_string())]),
            }),
        )
        .await
        .unwrap();

        let resp = handle_get_workspace(
            &state,
            Request::new(GetWorkspaceRequest {
                name: "fetch-me".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        let ws = resp.workspace.unwrap();
        let meta = ws.metadata.as_ref().unwrap();
        assert_eq!(meta.name, "fetch-me");
        assert_eq!(meta.labels.get("team").map(String::as_str), Some("infra"));
    }

    #[tokio::test]
    async fn get_workspace_not_found() {
        let state = test_server_state().await;

        let err = handle_get_workspace(
            &state,
            Request::new(GetWorkspaceRequest {
                name: "no-such-ws".to_string(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn get_workspace_empty_name_rejected() {
        let state = test_server_state().await;

        let err = handle_get_workspace(
            &state,
            Request::new(GetWorkspaceRequest {
                name: String::new(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn resolve_workspace_not_found_rejects_sandbox_create() {
        let state = test_server_state().await;

        let err = resolve_workspace(&state.store, "ghost-ws")
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::NotFound);
        assert!(err.message().contains("ghost-ws"));
    }

    #[tokio::test]
    async fn delete_workspace_blocked_by_resources() {
        let state = test_server_state().await;

        handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                name: "ephemeral".to_string(),
                labels: HashMap::new(),
            }),
        )
        .await
        .unwrap();

        let sbx = Sandbox {
            metadata: Some(ObjectMeta {
                id: "sbx-eph-1".to_string(),
                name: "blocker".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                annotations: HashMap::new(),
                resource_version: 0,
                workspace: "ephemeral".to_string(),
                deletion_timestamp_ms: 0,
            }),
            ..Default::default()
        };
        state.store.put_message(&sbx).await.unwrap();

        let err = handle_delete_workspace(
            &state,
            Request::new(DeleteWorkspaceRequest {
                name: "ephemeral".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(
            err.message().contains("sandbox"),
            "error should name the blocking resource type: {}",
            err.message()
        );

        state
            .store
            .delete_by_name(Sandbox::object_type(), "ephemeral", "blocker")
            .await
            .unwrap();

        let resp = handle_delete_workspace(
            &state,
            Request::new(DeleteWorkspaceRequest {
                name: "ephemeral".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(resp.deleted);
    }

    #[tokio::test]
    async fn delete_workspace_blocked_by_ssh_session() {
        let state = test_server_state().await;

        handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                name: "sessioned".to_string(),
                labels: HashMap::new(),
            }),
        )
        .await
        .unwrap();

        let session = SshSession {
            metadata: Some(ObjectMeta {
                id: "ssh-1".to_string(),
                name: "session-ssh-1".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                annotations: HashMap::new(),
                resource_version: 0,
                workspace: "sessioned".to_string(),
                deletion_timestamp_ms: 0,
            }),
            sandbox_id: "sbx-1".to_string(),
            token: "ssh-1".to_string(),
            revoked: false,
            expires_at_ms: 0,
        };
        state.store.put_message(&session).await.unwrap();

        let err = handle_delete_workspace(
            &state,
            Request::new(DeleteWorkspaceRequest {
                name: "sessioned".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(
            err.message().contains("ssh session"),
            "error should name ssh session as blocker: {}",
            err.message()
        );
    }

    #[tokio::test]
    async fn delete_workspace_blocked_by_provider_profiles() {
        let state = test_server_state().await;

        handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                name: "profiles-ws".to_string(),
                labels: HashMap::new(),
            }),
        )
        .await
        .unwrap();

        let profile = StoredProviderProfile {
            metadata: Some(ObjectMeta {
                id: "prof-1".to_string(),
                name: "my-profile".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                annotations: HashMap::new(),
                resource_version: 0,
                workspace: "profiles-ws".to_string(),
                deletion_timestamp_ms: 0,
            }),
            ..Default::default()
        };
        state.store.put_message(&profile).await.unwrap();

        let err = handle_delete_workspace(
            &state,
            Request::new(DeleteWorkspaceRequest {
                name: "profiles-ws".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(
            err.message().contains("provider profile"),
            "error should name provider profile as blocking: {}",
            err.message()
        );

        state
            .store
            .delete_by_name(
                StoredProviderProfile::object_type(),
                "profiles-ws",
                "my-profile",
            )
            .await
            .unwrap();

        let resp = handle_delete_workspace(
            &state,
            Request::new(DeleteWorkspaceRequest {
                name: "profiles-ws".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(resp.deleted);
    }

    #[tokio::test]
    async fn delete_default_workspace_rejected() {
        let state = test_server_state().await;

        let err = handle_delete_workspace(
            &state,
            Request::new(DeleteWorkspaceRequest {
                name: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn add_and_list_workspace_members() {
        let state = test_server_state().await;

        let resp = handle_add_workspace_member(
            &state,
            Request::new(AddWorkspaceMemberRequest {
                workspace: "default".to_string(),
                principal_subject: "alice@example.com".to_string(),
                role: WorkspaceRole::Admin.into(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        let member = resp.member.unwrap();
        assert_eq!(member.principal_subject, "alice@example.com");
        assert_eq!(member.role, i32::from(WorkspaceRole::Admin));

        handle_add_workspace_member(
            &state,
            Request::new(AddWorkspaceMemberRequest {
                workspace: "default".to_string(),
                principal_subject: "bob@example.com".to_string(),
                role: WorkspaceRole::User.into(),
            }),
        )
        .await
        .unwrap();

        let list = handle_list_workspace_members(
            &state,
            Request::new(ListWorkspaceMembersRequest {
                workspace: "default".to_string(),
                limit: 100,
                offset: 0,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(list.members.len(), 2);
    }

    #[tokio::test]
    async fn remove_workspace_member() {
        let state = test_server_state().await;

        handle_add_workspace_member(
            &state,
            Request::new(AddWorkspaceMemberRequest {
                workspace: "default".to_string(),
                principal_subject: "charlie@example.com".to_string(),
                role: WorkspaceRole::User.into(),
            }),
        )
        .await
        .unwrap();

        let resp = handle_remove_workspace_member(
            &state,
            Request::new(RemoveWorkspaceMemberRequest {
                workspace: "default".to_string(),
                principal_subject: "charlie@example.com".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(resp.removed);

        let list = handle_list_workspace_members(
            &state,
            Request::new(ListWorkspaceMembersRequest {
                workspace: "default".to_string(),
                limit: 100,
                offset: 0,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(list.members.is_empty());
    }

    #[tokio::test]
    async fn add_duplicate_member_rejected() {
        let state = test_server_state().await;

        handle_add_workspace_member(
            &state,
            Request::new(AddWorkspaceMemberRequest {
                workspace: "default".to_string(),
                principal_subject: "dave@example.com".to_string(),
                role: WorkspaceRole::User.into(),
            }),
        )
        .await
        .unwrap();

        let err = handle_add_workspace_member(
            &state,
            Request::new(AddWorkspaceMemberRequest {
                workspace: "default".to_string(),
                principal_subject: "dave@example.com".to_string(),
                role: WorkspaceRole::Admin.into(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::AlreadyExists);
    }

    #[tokio::test]
    async fn delete_workspace_cleans_up_members() {
        let state = test_server_state().await;

        handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                name: "cleanup-test".to_string(),
                labels: HashMap::new(),
            }),
        )
        .await
        .unwrap();

        handle_add_workspace_member(
            &state,
            Request::new(AddWorkspaceMemberRequest {
                workspace: "cleanup-test".to_string(),
                principal_subject: "alice@example.com".to_string(),
                role: WorkspaceRole::Admin.into(),
            }),
        )
        .await
        .unwrap();

        handle_add_workspace_member(
            &state,
            Request::new(AddWorkspaceMemberRequest {
                workspace: "cleanup-test".to_string(),
                principal_subject: "bob@example.com".to_string(),
                role: WorkspaceRole::User.into(),
            }),
        )
        .await
        .unwrap();

        let list = handle_list_workspace_members(
            &state,
            Request::new(ListWorkspaceMembersRequest {
                workspace: "cleanup-test".to_string(),
                limit: 100,
                offset: 0,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(list.members.len(), 2);

        let resp = handle_delete_workspace(
            &state,
            Request::new(DeleteWorkspaceRequest {
                name: "cleanup-test".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(resp.deleted);

        // Membership records should have been cleaned up.
        let remaining: Vec<WorkspaceMember> = state
            .store
            .list_messages("cleanup-test", 100, 0)
            .await
            .unwrap();
        assert!(
            remaining.is_empty(),
            "expected 0 orphaned members, found {}",
            remaining.len()
        );
    }

    #[test]
    fn validate_workspace_name_accepts_single_hyphens() {
        validate_workspace_name("my-workspace").unwrap();
    }

    #[test]
    fn validate_workspace_name_rejects_uppercase() {
        let err = validate_workspace_name("MyWorkspace").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[test]
    fn validate_workspace_name_rejects_leading_hyphen() {
        let err = validate_workspace_name("-workspace").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[test]
    fn validate_workspace_name_rejects_consecutive_hyphens() {
        let err = validate_workspace_name("team--ml").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[test]
    fn validate_workspace_name_accepts_max_length() {
        validate_workspace_name(&"a".repeat(crate::grpc::MAX_ROUTABLE_NAME_LEN)).unwrap();
    }

    #[test]
    fn validate_workspace_name_rejects_over_max_length() {
        let err = validate_workspace_name(&"a".repeat(crate::grpc::MAX_ROUTABLE_NAME_LEN + 1))
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("exceeds maximum length"));
    }

    #[tokio::test]
    async fn delete_workspace_marks_terminating_before_scan() {
        let state = test_server_state().await;

        handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                name: "term-test".to_string(),
                labels: HashMap::new(),
            }),
        )
        .await
        .unwrap();

        let sbx = Sandbox {
            metadata: Some(ObjectMeta {
                id: "sbx-term-1".to_string(),
                name: "blocker".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                annotations: HashMap::new(),
                resource_version: 0,
                workspace: "term-test".to_string(),
                deletion_timestamp_ms: 0,
            }),
            ..Default::default()
        };
        state.store.put_message(&sbx).await.unwrap();

        let err = handle_delete_workspace(
            &state,
            Request::new(DeleteWorkspaceRequest {
                name: "term-test".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);

        let ws: Workspace = state
            .store
            .get_message_by_name("", "term-test")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            ws.metadata.as_ref().unwrap().deletion_timestamp_ms,
            0,
            "workspace should have deletion_timestamp set"
        );
        assert_eq!(
            ws.status.as_ref().unwrap().phase,
            i32::from(WorkspacePhase::Terminating),
        );
    }

    #[tokio::test]
    async fn create_rejected_in_terminating_workspace() {
        let state = test_server_state().await;

        handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                name: "dying-ws".to_string(),
                labels: HashMap::new(),
            }),
        )
        .await
        .unwrap();

        let sbx = Sandbox {
            metadata: Some(ObjectMeta {
                id: "sbx-dying-1".to_string(),
                name: "hold".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                annotations: HashMap::new(),
                resource_version: 0,
                workspace: "dying-ws".to_string(),
                deletion_timestamp_ms: 0,
            }),
            ..Default::default()
        };
        state.store.put_message(&sbx).await.unwrap();

        // Mark workspace as Terminating via a blocked delete.
        let _ = handle_delete_workspace(
            &state,
            Request::new(DeleteWorkspaceRequest {
                name: "dying-ws".to_string(),
            }),
        )
        .await;

        let resolved = resolve_workspace(&state.store, "dying-ws").await.unwrap();
        assert!(resolved.terminating);
        let err = resolved.ensure_active().unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("being deleted"));
    }

    #[tokio::test]
    async fn delete_workspace_idempotent_on_terminating() {
        let state = test_server_state().await;

        handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                name: "idempotent-ws".to_string(),
                labels: HashMap::new(),
            }),
        )
        .await
        .unwrap();

        let sbx = Sandbox {
            metadata: Some(ObjectMeta {
                id: "sbx-idem-1".to_string(),
                name: "temp".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                annotations: HashMap::new(),
                resource_version: 0,
                workspace: "idempotent-ws".to_string(),
                deletion_timestamp_ms: 0,
            }),
            ..Default::default()
        };
        state.store.put_message(&sbx).await.unwrap();

        // First call: marks Terminating, fails due to blocker.
        let _ = handle_delete_workspace(
            &state,
            Request::new(DeleteWorkspaceRequest {
                name: "idempotent-ws".to_string(),
            }),
        )
        .await;

        // Remove the blocker.
        state
            .store
            .delete_by_name(Sandbox::object_type(), "idempotent-ws", "temp")
            .await
            .unwrap();

        // Second call: idempotent re-entry on already-Terminating workspace.
        let resp = handle_delete_workspace(
            &state,
            Request::new(DeleteWorkspaceRequest {
                name: "idempotent-ws".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(resp.deleted);
    }

    #[tokio::test]
    async fn create_workspace_persists_labels_for_selector() {
        let state = test_server_state().await;

        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "staging".to_string());

        handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                name: "labeled-ws".to_string(),
                labels: labels.clone(),
            }),
        )
        .await
        .unwrap();

        let resp = handle_list_workspaces(
            &state,
            Request::new(ListWorkspacesRequest {
                label_selector: "env=staging".to_string(),
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(resp.workspaces.len(), 1);
        assert_eq!(
            resp.workspaces[0].metadata.as_ref().unwrap().name,
            "labeled-ws"
        );
        assert_eq!(resp.workspaces[0].metadata.as_ref().unwrap().labels, labels);

        let empty = handle_list_workspaces(
            &state,
            Request::new(ListWorkspacesRequest {
                label_selector: "env=production".to_string(),
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(empty.workspaces.is_empty());
    }

    #[test]
    fn resolved_workspace_ensure_active_passes_for_active() {
        let rw = ResolvedWorkspace {
            name: "test".to_string(),
            terminating: false,
        };
        assert_eq!(rw.ensure_active().unwrap(), "test");
    }

    #[test]
    fn resolved_workspace_ensure_active_rejects_terminating() {
        let rw = ResolvedWorkspace {
            name: "doomed".to_string(),
            terminating: true,
        };
        let err = rw.ensure_active().unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("being deleted"));
    }

    #[tokio::test]
    async fn delete_workspace_cascade_deletes_inference_routes() {
        let state = test_server_state().await;

        handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                name: "route-test".to_string(),
                labels: HashMap::new(),
            }),
        )
        .await
        .unwrap();

        let route = InferenceRoute {
            metadata: Some(ObjectMeta {
                id: "route-1".to_string(),
                name: "inference.local".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                annotations: HashMap::new(),
                resource_version: 0,
                workspace: "route-test".to_string(),
                deletion_timestamp_ms: 0,
            }),
            config: Some(openshell_core::proto::InferenceRouteConfig {
                provider_name: "test-provider".to_string(),
                model_id: "gpt-4o".to_string(),
                timeout_secs: 0,
            }),
            version: 1,
        };
        state.store.put_message(&route).await.unwrap();

        // Inference route should NOT block workspace deletion.
        let resp = handle_delete_workspace(
            &state,
            Request::new(DeleteWorkspaceRequest {
                name: "route-test".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(resp.deleted);

        // Inference route should have been cascade-deleted.
        let remaining: Vec<InferenceRoute> = state
            .store
            .list_messages("route-test", 100, 0)
            .await
            .unwrap();
        assert!(
            remaining.is_empty(),
            "inference routes should be cascade-deleted with workspace"
        );
    }
}
