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
//! authentication is a driver concern, authorization is a gateway concern.

use crate::identity::Identity;
use tonic::Status;
use tracing::debug;

/// gRPC methods that require the admin role.
/// All other authenticated methods require the user role.
const ADMIN_METHODS: &[&str] = &[
    // Provider management
    "/openshell.v1.OpenShell/CreateProvider",
    "/openshell.v1.OpenShell/UpdateProvider",
    "/openshell.v1.OpenShell/DeleteProvider",
    // Global config and policy
    "/openshell.v1.OpenShell/UpdateConfig",
    // Draft policy approvals
    "/openshell.v1.OpenShell/ApproveDraftChunk",
    "/openshell.v1.OpenShell/ApproveAllDraftChunks",
    "/openshell.v1.OpenShell/RejectDraftChunk",
    "/openshell.v1.OpenShell/EditDraftChunk",
    "/openshell.v1.OpenShell/UndoDraftChunk",
    "/openshell.v1.OpenShell/ClearDraftChunks",
    // Cluster inference write
    "/openshell.inference.v1.Inference/SetClusterInference",
];

/// Exhaustive mapping of Bearer-authenticated gRPC methods to required scopes.
/// Methods not listed here require `openshell:all` when scope enforcement is enabled.
const SCOPED_METHODS: &[(&str, &str)] = &[
    // sandbox:read
    ("/openshell.v1.OpenShell/GetSandbox", "sandbox:read"),
    ("/openshell.v1.OpenShell/ListSandboxes", "sandbox:read"),
    ("/openshell.v1.OpenShell/WatchSandbox", "sandbox:read"),
    ("/openshell.v1.OpenShell/GetSandboxLogs", "sandbox:read"),
    (
        "/openshell.v1.OpenShell/GetSandboxPolicyStatus",
        "sandbox:read",
    ),
    (
        "/openshell.v1.OpenShell/ListSandboxPolicies",
        "sandbox:read",
    ),
    // sandbox:write
    ("/openshell.v1.OpenShell/CreateSandbox", "sandbox:write"),
    ("/openshell.v1.OpenShell/DeleteSandbox", "sandbox:write"),
    ("/openshell.v1.OpenShell/ExecSandbox", "sandbox:write"),
    ("/openshell.v1.OpenShell/CreateSshSession", "sandbox:write"),
    ("/openshell.v1.OpenShell/RevokeSshSession", "sandbox:write"),
    // provider:read
    ("/openshell.v1.OpenShell/GetProvider", "provider:read"),
    ("/openshell.v1.OpenShell/ListProviders", "provider:read"),
    // provider:write
    ("/openshell.v1.OpenShell/CreateProvider", "provider:write"),
    ("/openshell.v1.OpenShell/UpdateProvider", "provider:write"),
    ("/openshell.v1.OpenShell/DeleteProvider", "provider:write"),
    // config:read
    ("/openshell.v1.OpenShell/GetGatewayConfig", "config:read"),
    ("/openshell.v1.OpenShell/GetSandboxConfig", "config:read"),
    ("/openshell.v1.OpenShell/GetDraftPolicy", "config:read"),
    ("/openshell.v1.OpenShell/GetDraftHistory", "config:read"),
    // config:write
    ("/openshell.v1.OpenShell/UpdateConfig", "config:write"),
    ("/openshell.v1.OpenShell/ApproveDraftChunk", "config:write"),
    (
        "/openshell.v1.OpenShell/ApproveAllDraftChunks",
        "config:write",
    ),
    ("/openshell.v1.OpenShell/RejectDraftChunk", "config:write"),
    ("/openshell.v1.OpenShell/EditDraftChunk", "config:write"),
    ("/openshell.v1.OpenShell/UndoDraftChunk", "config:write"),
    ("/openshell.v1.OpenShell/ClearDraftChunks", "config:write"),
    // inference:read
    (
        "/openshell.inference.v1.Inference/GetClusterInference",
        "inference:read",
    ),
    // inference:write
    (
        "/openshell.inference.v1.Inference/SetClusterInference",
        "inference:write",
    ),
];

const SCOPE_ALL: &str = "openshell:all";

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
    pub fn check(&self, identity: &Identity, method: &str) -> Result<(), Status> {
        let required = if ADMIN_METHODS.contains(&method) {
            &self.admin_role
        } else {
            &self.user_role
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

    fn check_scope(&self, identity: &Identity, method: &str) -> Result<(), Status> {
        if identity.scopes.iter().any(|s| s == SCOPE_ALL) {
            return Ok(());
        }

        let required_scope = SCOPED_METHODS
            .iter()
            .find(|(m, _)| *m == method)
            .map(|(_, s)| *s)
            .unwrap_or(SCOPE_ALL);

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
    use crate::identity::IdentityProvider;

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
                .check(&id, "/openshell.v1.OpenShell/CreateSandbox")
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
        let err = policy
            .check(&id, "/openshell.v1.OpenShell/CreateSandbox")
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("sandbox:write"));
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
}
