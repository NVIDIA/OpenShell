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
];

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

        // Empty role name = skip RBAC for this level.
        if required.is_empty() {
            return Ok(());
        }

        // Admin role implicitly satisfies user role requirements.
        let has_role = identity.roles.iter().any(|r| r == required)
            || (!self.admin_role.is_empty()
                && required == &self.user_role
                && identity.roles.iter().any(|r| r == &self.admin_role));

        if has_role {
            Ok(())
        } else {
            debug!(
                sub = %identity.subject,
                required_role = required,
                user_roles = ?identity.roles,
                method = method,
                "authorization denied"
            );
            Err(Status::permission_denied(format!(
                "role '{required}' required"
            )))
        }
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
        }
    }

    fn identity_with_roles(roles: &[&str]) -> Identity {
        Identity {
            subject: "test-user".to_string(),
            display_name: None,
            roles: roles.iter().map(|r| (*r).to_string()).collect(),
            provider: IdentityProvider::Oidc,
        }
    }

    #[test]
    fn user_can_access_user_methods() {
        let id = identity_with_roles(&["openshell-user"]);
        let policy = default_policy();
        assert!(policy.check(&id, "/openshell.v1.OpenShell/ListSandboxes").is_ok());
    }

    #[test]
    fn user_cannot_access_admin_methods() {
        let id = identity_with_roles(&["openshell-user"]);
        let policy = default_policy();
        assert!(policy.check(&id, "/openshell.v1.OpenShell/CreateProvider").is_err());
    }

    #[test]
    fn admin_can_access_admin_methods() {
        let id = identity_with_roles(&["openshell-admin", "openshell-user"]);
        let policy = default_policy();
        assert!(policy.check(&id, "/openshell.v1.OpenShell/CreateProvider").is_ok());
    }

    #[test]
    fn admin_only_can_access_user_methods() {
        let id = identity_with_roles(&["openshell-admin"]);
        let policy = default_policy();
        assert!(policy.check(&id, "/openshell.v1.OpenShell/ListSandboxes").is_ok());
    }

    #[test]
    fn empty_roles_rejected() {
        let id = identity_with_roles(&[]);
        let policy = default_policy();
        assert!(policy.check(&id, "/openshell.v1.OpenShell/ListSandboxes").is_err());
    }

    #[test]
    fn empty_role_names_skip_rbac() {
        let id = identity_with_roles(&[]);
        let policy = AuthzPolicy {
            admin_role: String::new(),
            user_role: String::new(),
        };
        assert!(policy.check(&id, "/openshell.v1.OpenShell/ListSandboxes").is_ok());
        assert!(policy.check(&id, "/openshell.v1.OpenShell/CreateProvider").is_ok());
    }

    #[test]
    fn custom_role_names() {
        let id = identity_with_roles(&["OpenShell.Admin", "OpenShell.User"]);
        let policy = AuthzPolicy {
            admin_role: "OpenShell.Admin".to_string(),
            user_role: "OpenShell.User".to_string(),
        };
        assert!(policy.check(&id, "/openshell.v1.OpenShell/CreateProvider").is_ok());
        assert!(policy.check(&id, "/openshell.v1.OpenShell/ListSandboxes").is_ok());
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
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn validate_rejects_partial_empty_admin_only() {
        let policy = AuthzPolicy {
            admin_role: "admin".to_string(),
            user_role: String::new(),
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn validate_rejects_partial_empty_user_only() {
        let policy = AuthzPolicy {
            admin_role: String::new(),
            user_role: "user".to_string(),
        };
        assert!(policy.validate().is_err());
    }
}
