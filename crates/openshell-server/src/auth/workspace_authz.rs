// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workspace-scoped authorization.
//!
//! Enforces membership and role requirements for workspace-scoped operations.
//! Called by handlers after middleware authentication — the middleware validates
//! auth mode + scope + global role; this module validates workspace membership
//! and workspace-level role.

use super::principal::Principal;
use openshell_core::proto::WorkspaceRole as ProtoWorkspaceRole;
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
    /// Resolved workspace name (empty string normalized to `"default"`).
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
    let workspace = normalize_workspace(workspace);

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

fn normalize_workspace(workspace: &str) -> String {
    if workspace.is_empty() {
        "default".to_string()
    } else {
        workspace.to_string()
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
    async fn empty_workspace_normalizes_to_default() {
        let store = test_store().await;
        add_member(&store, "default", "user-d", ProtoWorkspaceRole::User).await;
        let principal = user_principal("user-d", &["openshell-user"]);
        let result = authorize_workspace(
            &store,
            "openshell-admin",
            &principal,
            "",
            MinWorkspaceRole::User,
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().workspace, "default");
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
