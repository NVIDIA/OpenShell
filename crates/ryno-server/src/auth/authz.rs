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
use super::{descriptor_authz, method_authz};
use tonic::Status;
use tracing::debug;

const SCOPE_ALL: &str = "ryno:all";

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
    /// Check whether the identity is authorized to call the given method.
    ///
    /// Returns `Ok(())` if authorized, `Err(PERMISSION_DENIED)` if not.
    /// When both role names are empty, all authenticated callers are authorized
    /// (authentication-only mode for providers like GitHub).
    ///
    /// Methods annotated with `global_role` (e.g. `"platform_admin"`) require
    /// the `admin_role` OIDC claim. Methods annotated with `workspace_role`
    /// require the `user_role` OIDC claim — the handler enforces workspace-level
    /// role via `authorize_workspace()`. A known Bearer method with neither role
    /// annotation requires authentication only.
    #[allow(clippy::result_large_err)]
    pub fn check(&self, identity: &Identity, method: &str) -> Result<(), Status> {
        let required = match descriptor_authz::lookup(method) {
            Some(entry) if entry.global_role.is_some() => Some(&self.admin_role),
            Some(entry) if entry.workspace_role.is_some() => Some(&self.user_role),
            Some(_) => None,
            None => Some(&self.user_role),
        };

        // Empty role name = skip role check for this level (auth-only mode).
        // Scope enforcement still applies if enabled.
        if let Some(required) = required
            && !required.is_empty()
        {
            // Admin role implicitly satisfies user role requirements.
            let has_role = identity.roles.iter().any(|r| r == required)
                || (!self.admin_role.is_empty()
                    && required == &self.user_role
                    && identity.roles.iter().any(|r| r == &self.admin_role));

            if !has_role {
                debug!(
                    sub = %identity.subject,
                    required_role = required,
                    user_roles = ?identity.roles,
                    method = method,
                    "authorization denied: missing role"
                );
                return Err(Status::permission_denied(format!(
                    "role '{required}' required"
                )));
            }
        }

        if self.scopes_enabled {
            self.check_scope(identity, method)?;
        }

        Ok(())
    }

    #[allow(clippy::result_large_err, clippy::unused_self)]
    fn check_scope(&self, identity: &Identity, method: &str) -> Result<(), Status> {
        if identity.scopes.iter().any(|s| s == SCOPE_ALL) {
            return Ok(());
        }

        let required_scope = match method_authz::lookup(method) {
            Some(entry) => {
                let Some(scope) = entry.scope.as_deref() else {
                    return Ok(());
                };
                scope
            }
            None => SCOPE_ALL,
        };

        if identity.scopes.iter().any(|s| s == required_scope) {
            return Ok(());
        }

        debug!(
            sub = %identity.subject,
            required_scope = required_scope,
            user_scopes = ?identity.scopes,
            method = method,
            "authorization denied: missing scope"
        );
        Err(Status::permission_denied(format!(
            "scope '{required_scope}' required"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::IdentityProvider;

    fn default_policy() -> AuthzPolicy {
        AuthzPolicy {
            admin_role: "ryno-admin".to_string(),
            user_role: "ryno-user".to_string(),
            scopes_enabled: false,
        }
    }

    fn scoped_policy() -> AuthzPolicy {
        AuthzPolicy {
            admin_role: "ryno-admin".to_string(),
            user_role: "ryno-user".to_string(),
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
        let id = identity_with_roles(&["ryno-user"]);
        let policy = default_policy();
        assert!(policy.check(&id, "/ryno.v1.Ryno/ListSandboxes").is_ok());
    }

    #[test]
    fn user_blocked_for_platform_admin_methods() {
        let id = identity_with_roles(&["ryno-user"]);
        let policy = default_policy();
        assert!(policy.check(&id, "/ryno.v1.Ryno/CreateWorkspace").is_err());
        assert!(policy.check(&id, "/ryno.v1.Ryno/GetGatewayInfo").is_err());
    }

    #[test]
    fn user_passes_middleware_for_workspace_admin_methods() {
        let id = identity_with_roles(&["ryno-user"]);
        let policy = default_policy();
        assert!(policy.check(&id, "/ryno.v1.Ryno/CreateProvider").is_ok());
        assert!(policy.check(&id, "/ryno.v1.Ryno/DeleteProvider").is_ok());
        assert!(
            policy
                .check(&id, "/ryno.v1.Ryno/AddWorkspaceMember")
                .is_ok()
        );
    }

    #[test]
    fn admin_can_access_platform_admin_methods() {
        let id = identity_with_roles(&["ryno-admin", "ryno-user"]);
        let policy = default_policy();
        assert!(policy.check(&id, "/ryno.v1.Ryno/CreateWorkspace").is_ok());
    }

    #[test]
    fn admin_only_can_access_user_methods() {
        let id = identity_with_roles(&["ryno-admin"]);
        let policy = default_policy();
        assert!(policy.check(&id, "/ryno.v1.Ryno/ListSandboxes").is_ok());
    }

    #[test]
    fn empty_roles_rejected() {
        let id = identity_with_roles(&[]);
        let policy = default_policy();
        assert!(policy.check(&id, "/ryno.v1.Ryno/ListSandboxes").is_err());
    }

    #[test]
    fn empty_role_names_skip_rbac() {
        let id = identity_with_roles(&[]);
        let policy = AuthzPolicy {
            admin_role: String::new(),
            user_role: String::new(),
            scopes_enabled: false,
        };
        assert!(policy.check(&id, "/ryno.v1.Ryno/ListSandboxes").is_ok());
        assert!(policy.check(&id, "/ryno.v1.Ryno/CreateProvider").is_ok());
    }

    #[test]
    fn custom_role_names() {
        let id = identity_with_roles(&["Ryno.Admin", "Ryno.User"]);
        let policy = AuthzPolicy {
            admin_role: "Ryno.Admin".to_string(),
            user_role: "Ryno.User".to_string(),
            scopes_enabled: false,
        };
        assert!(policy.check(&id, "/ryno.v1.Ryno/CreateWorkspace").is_ok());
        assert!(policy.check(&id, "/ryno.v1.Ryno/ListSandboxes").is_ok());
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
        let id = identity_with_roles(&["ryno-user"]);
        let policy = default_policy();
        assert!(policy.check(&id, "/ryno.v1.Ryno/ListSandboxes").is_ok());
    }

    #[test]
    fn scoped_access_allowed() {
        let id = identity_with_roles_and_scopes(&["ryno-user"], &["sandbox:read", "sandbox:write"]);
        let policy = scoped_policy();
        assert!(policy.check(&id, "/ryno.v1.Ryno/ListSandboxes").is_ok());
        assert!(
            policy
                .check(&id, "/ryno.v1.Ryno/ListSandboxProviders")
                .is_ok()
        );
        assert!(policy.check(&id, "/ryno.v1.Ryno/ListServices").is_ok());
        assert!(policy.check(&id, "/ryno.v1.Ryno/GetService").is_ok());
        assert!(policy.check(&id, "/ryno.v1.Ryno/CreateSandbox").is_ok());
        assert!(policy.check(&id, "/ryno.v1.Ryno/ForwardTcp").is_ok());
        assert!(policy.check(&id, "/ryno.v1.Ryno/ExposeService").is_ok());
        assert!(policy.check(&id, "/ryno.v1.Ryno/DeleteService").is_ok());
        assert!(
            policy
                .check(&id, "/ryno.v1.Ryno/AttachSandboxProvider")
                .is_ok()
        );
        assert!(
            policy
                .check(&id, "/ryno.v1.Ryno/DetachSandboxProvider")
                .is_ok()
        );
    }

    #[test]
    fn scoped_access_denied() {
        let id = identity_with_roles_and_scopes(&["ryno-user"], &["sandbox:read"]);
        let policy = scoped_policy();
        assert!(policy.check(&id, "/ryno.v1.Ryno/ListSandboxes").is_ok());
        assert!(policy.check(&id, "/ryno.v1.Ryno/ListServices").is_ok());
        assert!(policy.check(&id, "/ryno.v1.Ryno/GetService").is_ok());
        let err = policy
            .check(&id, "/ryno.v1.Ryno/AttachSandboxProvider")
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("sandbox:write"));

        let err = policy
            .check(&id, "/ryno.v1.Ryno/ExposeService")
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("sandbox:write"));

        let err = policy
            .check(&id, "/ryno.v1.Ryno/DeleteService")
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("sandbox:write"));
    }

    #[test]
    fn provider_refresh_methods_require_provider_scopes() {
        let policy = scoped_policy();
        let reader = identity_with_roles_and_scopes(&["ryno-user"], &["provider:read"]);
        assert!(
            policy
                .check(&reader, "/ryno.v1.Ryno/GetProviderRefreshStatus")
                .is_ok()
        );

        // Workspace-admin methods now pass middleware with user role + correct scope.
        // Handler enforces workspace membership.
        let writer = identity_with_roles_and_scopes(&["ryno-user"], &["provider:write"]);
        assert!(
            policy
                .check(&writer, "/ryno.v1.Ryno/ConfigureProviderRefresh")
                .is_ok()
        );
        assert!(
            policy
                .check(&writer, "/ryno.v1.Ryno/RotateProviderCredential")
                .is_ok()
        );
        assert!(
            policy
                .check(&writer, "/ryno.v1.Ryno/DeleteProviderRefresh")
                .is_ok()
        );

        // Wrong scope still rejected.
        let admin_without_scope =
            identity_with_roles_and_scopes(&["ryno-admin"], &["provider:read"]);
        let err = policy
            .check(
                &admin_without_scope,
                "/ryno.v1.Ryno/RotateProviderCredential",
            )
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("provider:write"));
    }

    #[test]
    fn get_sandbox_config_requires_config_read_scope() {
        let policy = scoped_policy();
        let id = identity_with_roles_and_scopes(&["ryno-user"], &["config:read"]);
        assert!(policy.check(&id, "/ryno.v1.Ryno/GetSandboxConfig").is_ok());

        let wrong_scope = identity_with_roles_and_scopes(&["ryno-user"], &["sandbox:read"]);
        let err = policy
            .check(&wrong_scope, "/ryno.v1.Ryno/GetSandboxConfig")
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("config:read"));
    }

    #[test]
    fn no_ryno_scopes_denied() {
        let id = identity_with_roles_and_scopes(&["ryno-user"], &[]);
        let policy = scoped_policy();
        let err = policy
            .check(&id, "/ryno.v1.Ryno/ListSandboxes")
            .expect_err("identity without required scope must be denied");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("sandbox:read"));
    }

    #[test]
    fn ryno_all_with_user_role() {
        let id = identity_with_roles_and_scopes(&["ryno-user"], &["ryno:all"]);
        let policy = scoped_policy();
        assert!(policy.check(&id, "/ryno.v1.Ryno/ListSandboxes").is_ok());
        assert!(policy.check(&id, "/ryno.v1.Ryno/GetProvider").is_ok());
        // Workspace-admin methods pass middleware with user role.
        assert!(policy.check(&id, "/ryno.v1.Ryno/CreateProvider").is_ok());
        // Platform-admin methods still denied by role check.
        assert!(policy.check(&id, "/ryno.v1.Ryno/CreateWorkspace").is_err());
    }

    #[test]
    fn ryno_all_with_admin_role() {
        let id = identity_with_roles_and_scopes(&["ryno-admin"], &["ryno:all"]);
        let policy = scoped_policy();
        assert!(policy.check(&id, "/ryno.v1.Ryno/CreateWorkspace").is_ok());
        assert!(policy.check(&id, "/ryno.v1.Ryno/ListSandboxes").is_ok());
    }

    #[test]
    fn unknown_method_requires_ryno_all() {
        let id = identity_with_roles_and_scopes(&["ryno-user"], &["sandbox:read"]);
        let policy = scoped_policy();
        let err = policy
            .check(&id, "/ryno.v1.Ryno/SomeFutureMethod")
            .unwrap_err();
        assert!(err.message().contains("ryno:all"));
    }

    #[test]
    fn known_bearer_method_without_scope_requires_only_authentication() {
        let id = identity_with_roles_and_scopes(&["ryno-user"], &[]);
        let policy = scoped_policy();
        assert!(policy.check(&id, "/ryno.v1.Ryno/GetCurrentUser").is_ok());
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
                .check(&id_with_scope, "/ryno.v1.Ryno/ListSandboxes")
                .is_ok()
        );
        let id_without_scope = identity_with_roles_and_scopes(&[], &[]);
        assert!(
            policy
                .check(&id_without_scope, "/ryno.v1.Ryno/ListSandboxes")
                .is_err()
        );
    }
}
