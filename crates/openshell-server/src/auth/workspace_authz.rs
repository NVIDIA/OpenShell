// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workspace-scoped authorization.
//!
//! Enforces membership and role requirements for workspace-scoped operations.
//! Called by handlers after middleware authentication — the middleware validates
//! auth mode + scope + global role; this module validates workspace membership
//! and workspace-level role.

use super::principal::Principal;
use openshell_core::proto::{
    WorkspaceRole as ProtoWorkspaceRole, WorkspaceSelector,
    workspace_selector::Selection as WorkspaceSelection,
};
use tonic::Status;

use crate::persistence::Store;

fn shell_quote_for_hint(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// Minimum workspace-level role required by a handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinWorkspaceRole {
    /// Workspace User — the caller must be at least a member.
    User,
    /// Workspace Admin — the caller must be an admin member.
    Admin,
}

impl MinWorkspaceRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
        }
    }
}

/// Result of a successful workspace authorization check.
#[derive(Debug)]
pub struct AuthorizedWorkspace {
    /// Explicit workspace name selected by the caller.
    pub workspace: String,
    /// How the caller was authorized.
    pub grant: AuthGrant,
}

/// How a caller was granted workspace access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthGrant {
    /// Caller holds the platform admin OIDC role — bypasses membership.
    PlatformAdmin,
    /// Caller is a workspace member with the given role.
    Member(ProtoWorkspaceRole),
    /// Caller is a sandbox principal — scoped by JWT, no membership check.
    Sandbox,
}

/// Authorized scope for a request that supports one workspace or all workspaces.
#[derive(Debug)]
pub enum AuthorizedWorkspaceScope {
    /// One explicitly named workspace.
    Workspace(AuthorizedWorkspace),
    /// All workspaces, authorized for a platform administrator.
    AllWorkspaces,
}

/// Authorize the required named selector on a single-workspace request.
#[allow(clippy::result_large_err)]
pub async fn authorize_workspace_selector(
    store: &Store,
    admin_role: &str,
    principal: &Principal,
    selector: Option<&WorkspaceSelector>,
    min_role: MinWorkspaceRole,
) -> Result<AuthorizedWorkspace, Status> {
    let workspace = selected_workspace_name(selector)?;
    authorize_workspace(store, admin_role, principal, workspace, min_role).await
}

/// Authorize a selector on a request that explicitly supports all workspaces.
#[allow(clippy::result_large_err)]
pub async fn authorize_list_workspace_selector(
    store: &Store,
    admin_role: &str,
    principal: &Principal,
    selector: Option<&WorkspaceSelector>,
    min_role: MinWorkspaceRole,
) -> Result<AuthorizedWorkspaceScope, Status> {
    match selected_workspace(selector)? {
        WorkspaceSelection::Workspace(workspace) => {
            authorize_workspace(store, admin_role, principal, workspace, min_role)
                .await
                .map(AuthorizedWorkspaceScope::Workspace)
        }
        WorkspaceSelection::AllWorkspaces(_) => {
            require_platform_admin(admin_role, principal)?;
            Ok(AuthorizedWorkspaceScope::AllWorkspaces)
        }
    }
}

/// Return the explicitly selected workspace name, rejecting missing, empty,
/// or all-workspaces selections.
#[allow(clippy::result_large_err)]
pub fn selected_workspace_name(selector: Option<&WorkspaceSelector>) -> Result<&str, Status> {
    match selected_workspace(selector)? {
        WorkspaceSelection::Workspace(workspace) => Ok(workspace),
        WorkspaceSelection::AllWorkspaces(_) => Err(Status::invalid_argument(
            "all_workspaces is not supported by this request",
        )),
    }
}

#[allow(clippy::result_large_err)]
fn selected_workspace(selector: Option<&WorkspaceSelector>) -> Result<&WorkspaceSelection, Status> {
    let selection = selector
        .and_then(|selector| selector.selection.as_ref())
        .ok_or_else(|| Status::invalid_argument("workspace_scope is required"))?;

    if let WorkspaceSelection::Workspace(workspace) = selection {
        crate::grpc::workspace::validate_workspace_name(workspace)?;
    }

    Ok(selection)
}

/// Authorize a workspace-scoped operation for a user principal.
///
/// Checks workspace membership and role. Platform admins (callers whose
/// OIDC roles include `admin_role`) bypass the membership check entirely.
///
/// When `admin_role` is empty (auth-only mode / OIDC not configured), every
/// authenticated user is treated as a platform admin — matching the existing
/// behavior where empty role names skip RBAC.
#[allow(clippy::result_large_err)]
pub async fn authorize_workspace(
    store: &Store,
    admin_role: &str,
    principal: &Principal,
    workspace: &str,
    min_role: MinWorkspaceRole,
) -> Result<AuthorizedWorkspace, Status> {
    let workspace = workspace.to_string();

    match principal {
        Principal::User(user) => {
            if is_platform_admin(&user.identity.roles, admin_role) {
                return Ok(AuthorizedWorkspace {
                    workspace,
                    grant: AuthGrant::PlatformAdmin,
                });
            }

            let member = store
                .get_message_by_name::<openshell_core::proto::WorkspaceMember>(
                    &workspace,
                    &user.identity.subject,
                )
                .await
                .map_err(|e| Status::internal(format!("membership lookup failed: {e}")))?;

            let Some(member) = member else {
                let workspace_arg = shell_quote_for_hint(&workspace);
                let subject_arg = shell_quote_for_hint(&user.identity.subject);
                return Err(Status::permission_denied(format!(
                    "not a member of workspace '{workspace}'; ask a platform admin to run: \
                     openshell workspace member add --workspace {workspace_arg} \
                     --subject {subject_arg} --role user"
                )));
            };

            let member_role = ProtoWorkspaceRole::try_from(member.role)
                .unwrap_or(ProtoWorkspaceRole::Unspecified);

            if !role_satisfies(member_role, min_role) {
                let workspace_arg = shell_quote_for_hint(&workspace);
                let subject_arg = shell_quote_for_hint(&user.identity.subject);
                let role = min_role.as_str();
                return Err(Status::permission_denied(format!(
                    "workspace role '{role}' required in workspace '{workspace}'; ask a platform \
                     admin to run: openshell workspace member add --workspace {workspace_arg} \
                     --subject {subject_arg} --role {role}"
                )));
            }

            Ok(AuthorizedWorkspace {
                workspace,
                grant: AuthGrant::Member(member_role),
            })
        }
        Principal::Sandbox(_) => Ok(AuthorizedWorkspace {
            workspace,
            grant: AuthGrant::Sandbox,
        }),
        Principal::Anonymous => Err(Status::unauthenticated("authentication required")),
    }
}

/// Authorize a data-plane operation where the workspace is resolved from the
/// sandbox record rather than the request message.
///
/// Used by `ExecSandbox`, `ForwardTcp`, `WatchSandbox`, `CreateSshSession` — these
/// RPCs identify a sandbox by name/ID and the handler resolves the workspace
/// from the sandbox record.
#[allow(clippy::result_large_err)]
pub async fn authorize_sandbox_workspace(
    store: &Store,
    admin_role: &str,
    principal: &Principal,
    sandbox_workspace: &str,
    min_role: MinWorkspaceRole,
) -> Result<AuthGrant, Status> {
    let result =
        authorize_workspace(store, admin_role, principal, sandbox_workspace, min_role).await?;
    Ok(result.grant)
}

/// Require Platform Admin status. Used for cross-workspace operations like
/// `list_*` with `all_workspaces: true`.
#[allow(clippy::result_large_err)]
pub fn require_platform_admin(admin_role: &str, principal: &Principal) -> Result<(), Status> {
    match principal {
        Principal::User(user) if is_platform_admin(&user.identity.roles, admin_role) => Ok(()),
        Principal::User(_) => Err(Status::permission_denied(
            "platform admin role required for cross-workspace operations",
        )),
        Principal::Sandbox(_) => Err(Status::permission_denied(
            "sandbox principals cannot perform cross-workspace operations",
        )),
        Principal::Anonymous => Err(Status::unauthenticated("authentication required")),
    }
}

/// Check whether the caller's OIDC roles include the platform admin role.
///
/// When `admin_role` is empty (OIDC not configured), returns `true` —
/// matching the existing behavior where empty role names skip RBAC.
pub fn is_platform_admin_principal(identity_roles: &[String], admin_role: &str) -> bool {
    is_platform_admin(identity_roles, admin_role)
}

fn is_platform_admin(identity_roles: &[String], admin_role: &str) -> bool {
    admin_role.is_empty() || identity_roles.iter().any(|r| r == admin_role)
}

/// Check whether `member_role` satisfies the `min_role` requirement.
fn role_satisfies(member_role: ProtoWorkspaceRole, min_role: MinWorkspaceRole) -> bool {
    match min_role {
        MinWorkspaceRole::User => matches!(
            member_role,
            ProtoWorkspaceRole::User | ProtoWorkspaceRole::Admin
        ),
        MinWorkspaceRole::Admin => member_role == ProtoWorkspaceRole::Admin,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::{Identity, IdentityProvider};
    use crate::auth::principal::{SandboxIdentitySource, SandboxPrincipal, UserPrincipal};
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{WorkspaceMember, WorkspaceRole as ProtoWorkspaceRole};
    use std::collections::HashMap;

    async fn test_store() -> Store {
        crate::persistence::test_store().await
    }

    fn user_principal(subject: &str, roles: &[&str]) -> Principal {
        Principal::User(UserPrincipal {
            identity: Identity {
                subject: subject.to_string(),
                display_name: None,
                roles: roles.iter().map(|r| (*r).to_string()).collect(),
                scopes: vec![],
                provider: IdentityProvider::Oidc,
            },
        })
    }

    fn sandbox_principal() -> Principal {
        Principal::Sandbox(SandboxPrincipal {
            sandbox_id: "sandbox-a".to_string(),
            source: SandboxIdentitySource::BootstrapJwt {
                issuer: "openshell-gateway:test".to_string(),
            },
            trust_domain: Some("openshell".to_string()),
        })
    }

    async fn add_member(store: &Store, workspace: &str, subject: &str, role: ProtoWorkspaceRole) {
        let member = WorkspaceMember {
            metadata: Some(ObjectMeta {
                id: uuid::Uuid::new_v4().to_string(),
                name: subject.to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                annotations: HashMap::new(),
                resource_version: 0,
                workspace: workspace.to_string(),
                deletion_timestamp_ms: 0,
            }),
            principal_subject: subject.to_string(),
            role: role.into(),
        };
        store.put_message(&member).await.expect("add member");
    }

    #[tokio::test]
    async fn platform_admin_bypasses_membership_check() {
        let store = test_store().await;
        let principal = user_principal("admin-user", &["openshell-admin", "openshell-user"]);
        let result = authorize_workspace(
            &store,
            "openshell-admin",
            &principal,
            "any-workspace",
            MinWorkspaceRole::Admin,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().grant, AuthGrant::PlatformAdmin);
    }

    #[tokio::test]
    async fn workspace_admin_member_passes_admin_check() {
        let store = test_store().await;
        add_member(&store, "default", "user-a", ProtoWorkspaceRole::Admin).await;
        let principal = user_principal("user-a", &["openshell-user"]);
        let result = authorize_workspace(
            &store,
            "openshell-admin",
            &principal,
            "default",
            MinWorkspaceRole::Admin,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().grant,
            AuthGrant::Member(ProtoWorkspaceRole::Admin)
        );
    }

    #[tokio::test]
    async fn workspace_user_member_passes_user_check() {
        let store = test_store().await;
        add_member(&store, "default", "user-b", ProtoWorkspaceRole::User).await;
        let principal = user_principal("user-b", &["openshell-user"]);
        let result = authorize_workspace(
            &store,
            "openshell-admin",
            &principal,
            "default",
            MinWorkspaceRole::User,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().grant,
            AuthGrant::Member(ProtoWorkspaceRole::User)
        );
    }

    #[tokio::test]
    async fn workspace_user_member_rejected_for_admin_check() {
        let store = test_store().await;
        add_member(&store, "default", "user-c", ProtoWorkspaceRole::User).await;
        let principal = user_principal("user-c", &["openshell-user"]);
        let result = authorize_workspace(
            &store,
            "openshell-admin",
            &principal,
            "default",
            MinWorkspaceRole::Admin,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            err.message(),
            "workspace role 'admin' required in workspace 'default'; ask a platform admin to run: \
             openshell workspace member add --workspace 'default' --subject 'user-c' --role admin"
        );
    }

    #[tokio::test]
    async fn non_member_rejected() {
        let store = test_store().await;
        let principal = user_principal("stranger", &["openshell-user"]);
        let result = authorize_workspace(
            &store,
            "openshell-admin",
            &principal,
            "default",
            MinWorkspaceRole::User,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            err.message(),
            "not a member of workspace 'default'; ask a platform admin to run: \
             openshell workspace member add --workspace 'default' --subject 'stranger' --role user"
        );
    }

    #[tokio::test]
    async fn non_member_remediation_shell_quotes_untrusted_subject() {
        let store = test_store().await;
        let principal = user_principal("user'; echo pwned; '$(id)", &["openshell-user"]);
        let result = authorize_workspace(
            &store,
            "openshell-admin",
            &principal,
            "team-a",
            MinWorkspaceRole::User,
        )
        .await;

        let err = result.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(
            err.message()
                .contains("--subject 'user'\"'\"'; echo pwned; '\"'\"'$(id)' --role user")
        );
    }

    #[tokio::test]
    async fn anonymous_principal_rejected() {
        let store = test_store().await;
        let result = authorize_workspace(
            &store,
            "openshell-admin",
            &Principal::Anonymous,
            "default",
            MinWorkspaceRole::User,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn sandbox_principal_passes_through() {
        let store = test_store().await;
        let principal = sandbox_principal();
        let result = authorize_workspace(
            &store,
            "openshell-admin",
            &principal,
            "default",
            MinWorkspaceRole::User,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().grant, AuthGrant::Sandbox);
    }

    #[tokio::test]
    async fn empty_named_selector_is_rejected() {
        let store = test_store().await;
        add_member(&store, "default", "user-d", ProtoWorkspaceRole::User).await;
        let principal = user_principal("user-d", &["openshell-user"]);
        let result = authorize_workspace_selector(
            &store,
            "openshell-admin",
            &principal,
            Some(&openshell_core::proto::workspace_selector("")),
            MinWorkspaceRole::User,
        )
        .await;
        let err = result.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "workspace name is required");
    }

    #[test]
    fn missing_and_unset_selectors_are_rejected() {
        let missing = selected_workspace_name(None).unwrap_err();
        assert_eq!(missing.code(), tonic::Code::InvalidArgument);
        assert_eq!(missing.message(), "workspace_scope is required");

        let unset = selected_workspace_name(Some(&WorkspaceSelector::default())).unwrap_err();
        assert_eq!(unset.code(), tonic::Code::InvalidArgument);
        assert_eq!(unset.message(), "workspace_scope is required");
    }

    #[test]
    fn all_workspaces_is_rejected_for_single_workspace_requests() {
        let err = selected_workspace_name(Some(&openshell_core::proto::all_workspaces_selector()))
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            err.message(),
            "all_workspaces is not supported by this request"
        );
    }

    #[tokio::test]
    async fn all_workspaces_requires_platform_admin() {
        let store = test_store().await;
        let selector = openshell_core::proto::all_workspaces_selector();
        let principal = user_principal("workspace-user", &["openshell-user"]);
        let err = authorize_list_workspace_selector(
            &store,
            "openshell-admin",
            &principal,
            Some(&selector),
            MinWorkspaceRole::User,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let admin = user_principal("platform-admin", &["openshell-admin"]);
        let authorized = authorize_list_workspace_selector(
            &store,
            "openshell-admin",
            &admin,
            Some(&selector),
            MinWorkspaceRole::User,
        )
        .await
        .unwrap();
        assert!(matches!(
            authorized,
            AuthorizedWorkspaceScope::AllWorkspaces
        ));
    }

    #[tokio::test]
    async fn auth_disabled_empty_admin_role_is_platform_admin() {
        let store = test_store().await;
        let principal = user_principal("any-user", &[]);
        let result =
            authorize_workspace(&store, "", &principal, "default", MinWorkspaceRole::Admin).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().grant, AuthGrant::PlatformAdmin);
    }

    #[tokio::test]
    async fn workspace_admin_member_passes_user_check() {
        let store = test_store().await;
        add_member(&store, "default", "admin-member", ProtoWorkspaceRole::Admin).await;
        let principal = user_principal("admin-member", &["openshell-user"]);
        let result = authorize_workspace(
            &store,
            "openshell-admin",
            &principal,
            "default",
            MinWorkspaceRole::User,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().grant,
            AuthGrant::Member(ProtoWorkspaceRole::Admin)
        );
    }
}
