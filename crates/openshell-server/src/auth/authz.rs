// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authorization policy evaluation.
//!
//! Determines whether an authenticated identity is allowed to call a given
//! gRPC method. This module owns the RBAC policy — which methods require
//! which roles — while authentication providers (OIDC, mTLS, etc.) own
//! identity verification.
//!
//! This separation follows RFC 0001's control-plane identity design:
//! authentication is handled by explicit application-layer authenticators,
//! authorization is a gateway concern.

use super::identity::Identity;
use super::method_authz::{self, Role};
use tonic::Status;
use tracing::debug;

const SCOPE_ALL: &str = "openshell:all";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodPermission {
    pub permission: &'static str,
    pub scope: &'static str,
    pub requires_admin: bool,
}

impl MethodPermission {
    const fn new(permission: &'static str, scope: &'static str, requires_admin: bool) -> Self {
        Self {
            permission,
            scope,
            requires_admin,
        }
    }
}

/// Exhaustive mapping of Bearer-authenticated gRPC methods to `OpenShell`
/// permissions and scopes. Methods not listed here fall back to
/// `openshell:all` when scope enforcement is enabled.
const METHOD_PERMISSIONS: &[(&str, MethodPermission)] = &[
    // sandbox.read
    (
        "/openshell.v1.OpenShell/GetSandbox",
        MethodPermission::new("sandbox.read", "sandbox:read", false),
    ),
    (
        "/openshell.v1.OpenShell/ListSandboxes",
        MethodPermission::new("sandbox.read", "sandbox:read", false),
    ),
    (
        "/openshell.v1.OpenShell/ListSandboxProviders",
        MethodPermission::new("sandbox.read", "sandbox:read", false),
    ),
    (
        "/openshell.v1.OpenShell/WatchSandbox",
        MethodPermission::new("sandbox.read", "sandbox:read", false),
    ),
    (
        "/openshell.v1.OpenShell/GetSandboxLogs",
        MethodPermission::new("sandbox.read", "sandbox:read", false),
    ),
    (
        "/openshell.v1.OpenShell/GetService",
        MethodPermission::new("sandbox.read", "sandbox:read", false),
    ),
    (
        "/openshell.v1.OpenShell/ListServices",
        MethodPermission::new("sandbox.read", "sandbox:read", false),
    ),
    (
        "/openshell.v1.OpenShell/GetSandboxPolicyStatus",
        MethodPermission::new("sandbox.read", "sandbox:read", false),
    ),
    (
        "/openshell.v1.OpenShell/ListSandboxPolicies",
        MethodPermission::new("sandbox.read", "sandbox:read", false),
    ),
    // sandbox.write
    (
        "/openshell.v1.OpenShell/CreateSandbox",
        MethodPermission::new("sandbox.write", "sandbox:write", false),
    ),
    (
        "/openshell.v1.OpenShell/DeleteSandbox",
        MethodPermission::new("sandbox.write", "sandbox:write", false),
    ),
    (
        "/openshell.v1.OpenShell/ExecSandbox",
        MethodPermission::new("sandbox.write", "sandbox:write", false),
    ),
    (
        "/openshell.v1.OpenShell/ForwardTcp",
        MethodPermission::new("sandbox.write", "sandbox:write", false),
    ),
    (
        "/openshell.v1.OpenShell/CreateSshSession",
        MethodPermission::new("sandbox.write", "sandbox:write", false),
    ),
    (
        "/openshell.v1.OpenShell/RevokeSshSession",
        MethodPermission::new("sandbox.write", "sandbox:write", false),
    ),
    (
        "/openshell.v1.OpenShell/ExposeService",
        MethodPermission::new("sandbox.write", "sandbox:write", false),
    ),
    (
        "/openshell.v1.OpenShell/DeleteService",
        MethodPermission::new("sandbox.write", "sandbox:write", false),
    ),
    (
        "/openshell.v1.OpenShell/AttachSandboxProvider",
        MethodPermission::new("sandbox.write", "sandbox:write", false),
    ),
    (
        "/openshell.v1.OpenShell/DetachSandboxProvider",
        MethodPermission::new("sandbox.write", "sandbox:write", false),
    ),
    // provider.read
    (
        "/openshell.v1.OpenShell/GetProvider",
        MethodPermission::new("provider.read", "provider:read", false),
    ),
    (
        "/openshell.v1.OpenShell/ListProviders",
        MethodPermission::new("provider.read", "provider:read", false),
    ),
    (
        "/openshell.v1.OpenShell/GetProviderRefreshStatus",
        MethodPermission::new("provider.read", "provider:read", false),
    ),
    // provider.write
    (
        "/openshell.v1.OpenShell/CreateProvider",
        MethodPermission::new("provider.write", "provider:write", true),
    ),
    (
        "/openshell.v1.OpenShell/UpdateProvider",
        MethodPermission::new("provider.write", "provider:write", true),
    ),
    (
        "/openshell.v1.OpenShell/DeleteProvider",
        MethodPermission::new("provider.write", "provider:write", true),
    ),
    (
        "/openshell.v1.OpenShell/ConfigureProviderRefresh",
        MethodPermission::new("provider.write", "provider:write", true),
    ),
    (
        "/openshell.v1.OpenShell/RotateProviderCredential",
        MethodPermission::new("provider.write", "provider:write", true),
    ),
    (
        "/openshell.v1.OpenShell/DeleteProviderRefresh",
        MethodPermission::new("provider.write", "provider:write", true),
    ),
    // config.read
    (
        "/openshell.v1.OpenShell/GetGatewayConfig",
        MethodPermission::new("config.read", "config:read", false),
    ),
    (
        "/openshell.v1.OpenShell/GetSandboxConfig",
        MethodPermission::new("config.read", "config:read", false),
    ),
    (
        "/openshell.v1.OpenShell/GetDraftPolicy",
        MethodPermission::new("config.read", "config:read", false),
    ),
    (
        "/openshell.v1.OpenShell/GetDraftHistory",
        MethodPermission::new("config.read", "config:read", false),
    ),
    // config.write
    (
        "/openshell.v1.OpenShell/UpdateConfig",
        MethodPermission::new("config.write", "config:write", true),
    ),
    (
        "/openshell.v1.OpenShell/ApproveDraftChunk",
        MethodPermission::new("config.write", "config:write", true),
    ),
    (
        "/openshell.v1.OpenShell/ApproveAllDraftChunks",
        MethodPermission::new("config.write", "config:write", true),
    ),
    (
        "/openshell.v1.OpenShell/RejectDraftChunk",
        MethodPermission::new("config.write", "config:write", true),
    ),
    (
        "/openshell.v1.OpenShell/EditDraftChunk",
        MethodPermission::new("config.write", "config:write", true),
    ),
    (
        "/openshell.v1.OpenShell/UndoDraftChunk",
        MethodPermission::new("config.write", "config:write", true),
    ),
    (
        "/openshell.v1.OpenShell/ClearDraftChunks",
        MethodPermission::new("config.write", "config:write", true),
    ),
    // inference.read
    (
        "/openshell.inference.v1.Inference/GetClusterInference",
        MethodPermission::new("inference.read", "inference:read", false),
    ),
    // inference.write
    (
        "/openshell.inference.v1.Inference/SetClusterInference",
        MethodPermission::new("inference.write", "inference:write", true),
    ),
];

const UNKNOWN_METHOD_PERMISSION: MethodPermission =
    MethodPermission::new("gateway.unknown", SCOPE_ALL, false);

fn method_permission(method: &str) -> MethodPermission {
    METHOD_PERMISSIONS
        .iter()
        .find(|(candidate, _)| *candidate == method)
        .map_or(UNKNOWN_METHOD_PERMISSION, |(_, permission)| *permission)
}

/// Authorization policy configuration.
///
/// Supports two modes:
/// - **RBAC mode**: both `admin_role` and `user_role` are non-empty.
/// - **Authentication-only mode**: both are empty (any valid token is authorized).
///
/// Partial configuration (one empty, one set) is rejected at construction
/// to prevent accidentally leaving admin endpoints unprotected.
#[derive(Debug, Clone)]
pub struct AuthzPolicy {
    /// Role name that grants admin access. Empty disables admin checks.
    pub admin_role: String,
    /// Role name that grants standard user access. Empty disables user checks.
    pub user_role: String,
    /// When true, enforce scope-based permissions on top of roles.
    pub scopes_enabled: bool,
}

impl AuthzPolicy {
    /// Validate the policy configuration.
    ///
    /// Returns an error if only one of admin/user role is set — either
    /// both must be set (RBAC mode) or both empty (auth-only mode).
    pub fn validate(&self) -> Result<(), String> {
        let admin_set = !self.admin_role.is_empty();
        let user_set = !self.user_role.is_empty();
        if admin_set != user_set {
            return Err(format!(
                "OIDC RBAC misconfiguration: admin_role={:?}, user_role={:?}. \
                 Either set both roles (RBAC mode) or leave both empty (authentication-only mode).",
                self.admin_role, self.user_role,
            ));
        }
        Ok(())
    }
}

impl AuthzPolicy {
    #[must_use]
    pub(crate) fn requirement_for(method: &str) -> MethodPermission {
        method_permission(method)
    }

    /// Check whether the identity is authorized to call the given method.
    ///
    /// Returns `Ok(())` if authorized, `Err(PERMISSION_DENIED)` if not.
    /// When both role names are empty, all authenticated callers are authorized
    /// (authentication-only mode for providers like GitHub).
    #[allow(clippy::result_large_err)]
    pub fn check(&self, identity: &Identity, method: &str) -> Result<(), Status> {
        let permission = method_permission(method);
        let required = match method_authz::required_role(method) {
            Some(Role::Admin) => &self.admin_role,
            None if permission.requires_admin => &self.admin_role,
            Some(Role::User) | None => &self.user_role,
        };

        // Empty role name = skip role check for this level (auth-only mode).
        // Scope enforcement still applies if enabled.
        if !required.is_empty() {
            // Admin role implicitly satisfies user role requirements.
            let has_role = identity.roles.iter().any(|r| r == required)
                || (!self.admin_role.is_empty()
                    && required == &self.user_role
                    && identity.roles.iter().any(|r| r == &self.admin_role));

            if !has_role {
                debug!(
                    sub = %identity.subject,
                    required_permission = permission.permission,
                    required_role = required,
                    user_roles = ?identity.roles,
                    method = method,
                    "authorization denied: missing role"
                );
                return Err(Status::permission_denied(format!(
                    "permission '{}' requires role '{required}'",
                    permission.permission,
                )));
            }
        }

        if self.scopes_enabled {
            Self::check_scope(identity, method, permission)?;
        }

        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn check_scope(
        identity: &Identity,
        method: &str,
        permission: MethodPermission,
    ) -> Result<(), Status> {
        if identity.scopes.iter().any(|s| s == SCOPE_ALL) {
            return Ok(());
        }
        let required_scope = method_authz::required_scope(method).unwrap_or(permission.scope);

        if identity.scopes.iter().any(|s| s == required_scope) {
            return Ok(());
        }

        debug!(
            sub = %identity.subject,
            required_permission = permission.permission,
            required_scope = required_scope,
            user_scopes = ?identity.scopes,
            method = method,
            "authorization denied: missing scope"
        );
        Err(Status::permission_denied(format!(
            "permission '{}' requires scope '{required_scope}'",
            permission.permission,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::IdentityProvider;

    fn default_policy() -> AuthzPolicy {
        AuthzPolicy {
            admin_role: "openshell-admin".to_string(),
            user_role: "openshell-user".to_string(),
            scopes_enabled: false,
        }
    }

    fn scoped_policy() -> AuthzPolicy {
        AuthzPolicy {
            admin_role: "openshell-admin".to_string(),
            user_role: "openshell-user".to_string(),
            scopes_enabled: true,
        }
    }

    fn identity_with_roles(roles: &[&str]) -> Identity {
        Identity {
            subject: "test-user".to_string(),
            display_name: None,
            roles: roles.iter().map(|r| (*r).to_string()).collect(),
            scopes: vec![],
            provider: IdentityProvider::Oidc,
        }
    }

    fn identity_with_roles_and_scopes(roles: &[&str], scopes: &[&str]) -> Identity {
        Identity {
            subject: "test-user".to_string(),
            display_name: None,
            roles: roles.iter().map(|r| (*r).to_string()).collect(),
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            provider: IdentityProvider::Oidc,
        }
    }

    #[test]
    fn user_can_access_user_methods() {
        let id = identity_with_roles(&["openshell-user"]);
        let policy = default_policy();
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/ListSandboxes")
                .is_ok()
        );
    }

    #[test]
    fn user_cannot_access_admin_methods() {
        let id = identity_with_roles(&["openshell-user"]);
        let policy = default_policy();
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/CreateProvider")
                .is_err()
        );
    }

    #[test]
    fn admin_can_access_admin_methods() {
        let id = identity_with_roles(&["openshell-admin", "openshell-user"]);
        let policy = default_policy();
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/CreateProvider")
                .is_ok()
        );
    }

    #[test]
    fn admin_only_can_access_user_methods() {
        let id = identity_with_roles(&["openshell-admin"]);
        let policy = default_policy();
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/ListSandboxes")
                .is_ok()
        );
    }

    #[test]
    fn empty_roles_rejected() {
        let id = identity_with_roles(&[]);
        let policy = default_policy();
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/ListSandboxes")
                .is_err()
        );
    }

    #[test]
    fn empty_role_names_skip_rbac() {
        let id = identity_with_roles(&[]);
        let policy = AuthzPolicy {
            admin_role: String::new(),
            user_role: String::new(),
            scopes_enabled: false,
        };
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/ListSandboxes")
                .is_ok()
        );
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/CreateProvider")
                .is_ok()
        );
    }

    #[test]
    fn custom_role_names() {
        let id = identity_with_roles(&["OpenShell.Admin", "OpenShell.User"]);
        let policy = AuthzPolicy {
            admin_role: "OpenShell.Admin".to_string(),
            user_role: "OpenShell.User".to_string(),
            scopes_enabled: false,
        };
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/CreateProvider")
                .is_ok()
        );
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/ListSandboxes")
                .is_ok()
        );
    }

    #[test]
    fn validate_accepts_both_roles_set() {
        let policy = default_policy();
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn validate_accepts_both_roles_empty() {
        let policy = AuthzPolicy {
            admin_role: String::new(),
            user_role: String::new(),
            scopes_enabled: false,
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn validate_rejects_partial_empty_admin_only() {
        let policy = AuthzPolicy {
            admin_role: "admin".to_string(),
            user_role: String::new(),
            scopes_enabled: false,
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn validate_rejects_partial_empty_user_only() {
        let policy = AuthzPolicy {
            admin_role: String::new(),
            user_role: "user".to_string(),
            scopes_enabled: false,
        };
        assert!(policy.validate().is_err());
    }

    // ---- Scope enforcement tests ----

    #[test]
    fn scopes_disabled_skips_scope_check() {
        let id = identity_with_roles(&["openshell-user"]);
        let policy = default_policy();
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/ListSandboxes")
                .is_ok()
        );
    }

    #[test]
    fn scoped_access_allowed() {
        let id =
            identity_with_roles_and_scopes(&["openshell-user"], &["sandbox:read", "sandbox:write"]);
        let policy = scoped_policy();
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/ListSandboxes")
                .is_ok()
        );
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/ListSandboxProviders")
                .is_ok()
        );
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/ListServices")
                .is_ok()
        );
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/GetService")
                .is_ok()
        );
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/CreateSandbox")
                .is_ok()
        );
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/ForwardTcp")
                .is_ok()
        );
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/ExposeService")
                .is_ok()
        );
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/DeleteService")
                .is_ok()
        );
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/AttachSandboxProvider")
                .is_ok()
        );
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/DetachSandboxProvider")
                .is_ok()
        );
    }

    #[test]
    fn scoped_access_denied() {
        let id = identity_with_roles_and_scopes(&["openshell-user"], &["sandbox:read"]);
        let policy = scoped_policy();
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/ListSandboxes")
                .is_ok()
        );
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/ListServices")
                .is_ok()
        );
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/GetService")
                .is_ok()
        );
        let err = policy
            .check(&id, "/openshell.v1.OpenShell/AttachSandboxProvider")
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("sandbox:write"));

        let err = policy
            .check(&id, "/openshell.v1.OpenShell/ExposeService")
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("sandbox:write"));

        let err = policy
            .check(&id, "/openshell.v1.OpenShell/DeleteService")
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("sandbox:write"));
    }

    #[test]
    fn provider_refresh_methods_require_provider_scopes_and_admin_for_writes() {
        let policy = scoped_policy();
        let reader = identity_with_roles_and_scopes(&["openshell-user"], &["provider:read"]);
        assert!(
            policy
                .check(&reader, "/openshell.v1.OpenShell/GetProviderRefreshStatus")
                .is_ok()
        );

        let writer_without_admin =
            identity_with_roles_and_scopes(&["openshell-user"], &["provider:write"]);
        let err = policy
            .check(
                &writer_without_admin,
                "/openshell.v1.OpenShell/ConfigureProviderRefresh",
            )
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("openshell-admin"));

        let admin_without_scope =
            identity_with_roles_and_scopes(&["openshell-admin"], &["provider:read"]);
        let err = policy
            .check(
                &admin_without_scope,
                "/openshell.v1.OpenShell/RotateProviderCredential",
            )
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("provider:write"));

        let admin_writer =
            identity_with_roles_and_scopes(&["openshell-admin"], &["provider:write"]);
        for method in [
            "/openshell.v1.OpenShell/ConfigureProviderRefresh",
            "/openshell.v1.OpenShell/RotateProviderCredential",
            "/openshell.v1.OpenShell/DeleteProviderRefresh",
        ] {
            assert!(policy.check(&admin_writer, method).is_ok(), "{method}");
        }
    }

    #[test]
    fn get_sandbox_config_requires_config_read_scope() {
        let policy = scoped_policy();
        let id = identity_with_roles_and_scopes(&["openshell-user"], &["config:read"]);
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/GetSandboxConfig")
                .is_ok()
        );

        let wrong_scope = identity_with_roles_and_scopes(&["openshell-user"], &["sandbox:read"]);
        let err = policy
            .check(&wrong_scope, "/openshell.v1.OpenShell/GetSandboxConfig")
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("config:read"));
    }

    #[test]
    fn no_openshell_scopes_denied() {
        let id = identity_with_roles_and_scopes(&["openshell-user"], &[]);
        let policy = scoped_policy();
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/ListSandboxes")
                .is_err()
        );
    }

    #[test]
    fn openshell_all_with_user_role() {
        let id = identity_with_roles_and_scopes(&["openshell-user"], &["openshell:all"]);
        let policy = scoped_policy();
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/ListSandboxes")
                .is_ok()
        );
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/GetProvider")
                .is_ok()
        );
        // admin methods still denied by role check
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/CreateProvider")
                .is_err()
        );
    }

    #[test]
    fn openshell_all_with_admin_role() {
        let id = identity_with_roles_and_scopes(&["openshell-admin"], &["openshell:all"]);
        let policy = scoped_policy();
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/CreateProvider")
                .is_ok()
        );
        assert!(
            policy
                .check(&id, "/openshell.v1.OpenShell/ListSandboxes")
                .is_ok()
        );
    }

    #[test]
    fn unknown_method_requires_openshell_all() {
        let id = identity_with_roles_and_scopes(&["openshell-user"], &["sandbox:read"]);
        let policy = scoped_policy();
        let err = policy
            .check(&id, "/openshell.v1.OpenShell/SomeFutureMethod")
            .unwrap_err();
        assert!(err.message().contains("openshell:all"));
    }

    #[test]
    fn auth_only_mode_with_scopes_still_enforces_scopes() {
        let policy = AuthzPolicy {
            admin_role: String::new(),
            user_role: String::new(),
            scopes_enabled: true,
        };
        let id_with_scope = identity_with_roles_and_scopes(&[], &["sandbox:read"]);
        assert!(
            policy
                .check(&id_with_scope, "/openshell.v1.OpenShell/ListSandboxes")
                .is_ok()
        );
        let id_without_scope = identity_with_roles_and_scopes(&[], &[]);
        assert!(
            policy
                .check(&id_without_scope, "/openshell.v1.OpenShell/ListSandboxes")
                .is_err()
        );
    }

    #[test]
    fn method_permission_maps_sandbox_write_methods() {
        let permission = method_permission("/openshell.v1.OpenShell/CreateSandbox");
        assert_eq!(permission.permission, "sandbox.write");
        assert_eq!(permission.scope, "sandbox:write");
        assert!(!permission.requires_admin);
    }

    #[test]
    fn method_permission_maps_admin_provider_writes() {
        let permission = method_permission("/openshell.v1.OpenShell/CreateProvider");
        assert_eq!(permission.permission, "provider.write");
        assert_eq!(permission.scope, "provider:write");
        assert!(permission.requires_admin);
    }

    #[test]
    fn method_permission_falls_back_for_unknown_methods() {
        let permission = method_permission("/openshell.v1.OpenShell/SomeFutureMethod");
        assert_eq!(permission, UNKNOWN_METHOD_PERMISSION);
    }

    #[test]
    fn denied_role_message_includes_permission_name() {
        let id = identity_with_roles(&["openshell-user"]);
        let policy = default_policy();
        let err = policy
            .check(&id, "/openshell.v1.OpenShell/CreateProvider")
            .unwrap_err();
        assert!(err.message().contains("provider.write"));
        assert!(err.message().contains("openshell-admin"));
    }

    #[test]
    fn denied_scope_message_includes_permission_name() {
        let id = identity_with_roles_and_scopes(&["openshell-user"], &["sandbox:read"]);
        let policy = scoped_policy();
        let err = policy
            .check(&id, "/openshell.v1.OpenShell/CreateSandbox")
            .unwrap_err();
        assert!(err.message().contains("sandbox.write"));
        assert!(err.message().contains("sandbox:write"));
    }
}
