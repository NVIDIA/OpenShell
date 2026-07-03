// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Multi-tenant resource ownership enforcement.
//!
//! When enabled, every created sandbox and provider is stamped with the
//! caller's identity subject (`openshell.ai/owner`) and an optional tenant
//! identifier (`openshell.ai/tenant`). Subsequent get/list/delete operations
//! enforce that only the resource owner (or an admin) can access the resource.
//!
//! The module is a pure function library — it does not hold state and can be
//! tested without a running server.

use std::collections::HashMap;

use openshell_core::driver_utils::{LABEL_OWNER, LABEL_TENANT};
use tonic::Status;

use super::principal::Principal;

/// Server-side ownership configuration.
///
/// Built from [`openshell_core::OwnershipConfigCore`] plus the OIDC admin
/// role name so that the ownership layer can bypass checks for admins.
#[derive(Debug, Clone)]
pub struct OwnershipConfig {
    /// Whether ownership enforcement is active.
    pub enabled: bool,
    /// Role name that grants admin access (bypass ownership checks).
    pub admin_role: String,
    /// Optional tenant identifier for gateway-per-tenant deployments.
    pub tenant_id: Option<String>,
}

impl Default for OwnershipConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            admin_role: "openshell-admin".to_string(),
            tenant_id: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Label value sanitisation
// ---------------------------------------------------------------------------

/// Sanitize a raw string into a valid Kubernetes label value.
///
/// Kubernetes label values must be at most 63 characters and contain only
/// alphanumeric characters, dashes, underscores, and dots. Leading and
/// trailing characters must be alphanumeric.
///
/// This function replaces invalid characters with `_`, truncates to 63
/// characters, then trims leading/trailing non-alphanumeric characters.
pub fn sanitize_label_value(raw: &str) -> String {
    let sanitized: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .take(63)
        .collect();
    sanitized
        .trim_start_matches(|c: char| !c.is_ascii_alphanumeric())
        .trim_end_matches(|c: char| !c.is_ascii_alphanumeric())
        .to_string()
}

// ---------------------------------------------------------------------------
// Label stamping
// ---------------------------------------------------------------------------

/// Stamp owner and tenant labels onto a mutable label map.
///
/// Anti-spoofing: any client-supplied `openshell.ai/owner` or
/// `openshell.ai/tenant` labels are stripped before the server-side values
/// are applied. This prevents callers from impersonating other users.
///
/// Returns the labels unchanged when:
/// - Ownership is disabled.
/// - The principal is not a `User` (sandbox or anonymous callers).
pub fn stamp_owner_labels(
    principal: &Principal,
    config: &OwnershipConfig,
    labels: &mut HashMap<String, String>,
) {
    if !config.enabled {
        return;
    }

    let Principal::User(user) = principal else {
        return;
    };

    // Anti-spoofing: strip any client-supplied ownership labels.
    labels.remove(LABEL_OWNER);
    labels.remove(LABEL_TENANT);

    let owner = sanitize_label_value(&user.identity.subject);
    if !owner.is_empty() {
        labels.insert(LABEL_OWNER.to_string(), owner);
    }

    if let Some(ref tenant_id) = config.tenant_id {
        let tenant = sanitize_label_value(tenant_id);
        if !tenant.is_empty() {
            labels.insert(LABEL_TENANT.to_string(), tenant);
        }
    }
}

// ---------------------------------------------------------------------------
// Ownership check
// ---------------------------------------------------------------------------

/// Verify that the calling principal owns the resource identified by `labels`.
///
/// Returns `Ok(())` when:
/// - Ownership enforcement is disabled.
/// - The principal is an admin (bypass).
/// - The principal is not a `User` (sandbox or anonymous callers).
/// - The resource has no owner label (pre-existing resources).
/// - The owner label matches the caller's identity subject.
///
/// Returns `Err(Status::permission_denied(...))` on mismatch.
pub fn check_ownership(
    principal: &Principal,
    config: &OwnershipConfig,
    labels: &HashMap<String, String>,
) -> Result<(), Status> {
    if !config.enabled {
        return Ok(());
    }

    let Principal::User(user) = principal else {
        // Sandbox and anonymous principals are not subject to ownership.
        return Ok(());
    };

    // Admins bypass ownership checks.
    if user.identity.roles.iter().any(|r| r == &config.admin_role) {
        return Ok(());
    }

    let Some(owner) = labels.get(LABEL_OWNER) else {
        // No owner label — the resource predates ownership enforcement.
        return Ok(());
    };

    let caller = sanitize_label_value(&user.identity.subject);
    if caller == *owner {
        return Ok(());
    }

    Err(Status::permission_denied("you do not own this resource"))
}

// ---------------------------------------------------------------------------
// Label selector for list filtering
// ---------------------------------------------------------------------------

/// Build a label selector that filters resources to those owned by the caller.
///
/// Returns `None` when:
/// - Ownership enforcement is disabled.
/// - The principal is an admin (sees all resources).
/// - The principal is not a `User`.
///
/// Returns `Some("openshell.ai/owner=<sanitized_subject>")` for regular users.
pub fn owner_label_selector(principal: &Principal, config: &OwnershipConfig) -> Option<String> {
    if !config.enabled {
        return None;
    }

    let Principal::User(user) = principal else {
        return None;
    };

    // Admins see all resources.
    if user.identity.roles.iter().any(|r| r == &config.admin_role) {
        return None;
    }

    let owner = sanitize_label_value(&user.identity.subject);
    if owner.is_empty() {
        return None;
    }

    Some(format!("{LABEL_OWNER}={owner}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::{Identity, IdentityProvider};
    use crate::auth::principal::UserPrincipal;

    fn user_principal(subject: &str, roles: &[&str]) -> Principal {
        Principal::User(UserPrincipal {
            identity: Identity {
                subject: subject.to_string(),
                display_name: None,
                roles: roles.iter().map(|r| r.to_string()).collect(),
                scopes: vec![],
                groups: vec![],
                provider: IdentityProvider::Oidc,
            },
        })
    }

    fn enabled_config() -> OwnershipConfig {
        OwnershipConfig {
            enabled: true,
            admin_role: "openshell-admin".to_string(),
            tenant_id: None,
        }
    }

    fn disabled_config() -> OwnershipConfig {
        OwnershipConfig {
            enabled: false,
            admin_role: "openshell-admin".to_string(),
            tenant_id: None,
        }
    }

    // ── sanitize_label_value ──────────────────────────────────────────

    #[test]
    fn sanitize_preserves_valid_characters() {
        assert_eq!(sanitize_label_value("alice"), "alice");
        assert_eq!(sanitize_label_value("user-1_test.v2"), "user-1_test.v2");
    }

    #[test]
    fn sanitize_replaces_invalid_characters() {
        assert_eq!(
            sanitize_label_value("alice@example.com"),
            "alice_example.com"
        );
        assert_eq!(sanitize_label_value("user name"), "user_name");
    }

    #[test]
    fn sanitize_truncates_to_63_characters() {
        let long = "a".repeat(100);
        assert_eq!(sanitize_label_value(&long).len(), 63);
    }

    #[test]
    fn sanitize_trims_leading_trailing_non_alphanumeric() {
        assert_eq!(sanitize_label_value("-user-"), "user");
        assert_eq!(sanitize_label_value("_user_"), "user");
        assert_eq!(sanitize_label_value(".user."), "user");
        assert_eq!(sanitize_label_value("---"), "");
    }

    #[test]
    fn sanitize_empty_input_returns_empty() {
        assert_eq!(sanitize_label_value(""), "");
    }

    // ── stamp_owner_labels ──────────────────────────────────────────

    #[test]
    fn stamp_disabled_leaves_labels_unchanged() {
        let principal = user_principal("alice", &[]);
        let config = disabled_config();
        let mut labels = HashMap::from([("app".to_string(), "test".to_string())]);
        stamp_owner_labels(&principal, &config, &mut labels);
        assert_eq!(labels.len(), 1);
        assert!(!labels.contains_key(LABEL_OWNER));
    }

    #[test]
    fn stamp_enabled_adds_owner_label() {
        let principal = user_principal("alice", &[]);
        let config = enabled_config();
        let mut labels = HashMap::new();
        stamp_owner_labels(&principal, &config, &mut labels);
        assert_eq!(labels.get(LABEL_OWNER), Some(&"alice".to_string()));
    }

    #[test]
    fn stamp_enabled_with_tenant_adds_both_labels() {
        let principal = user_principal("alice", &[]);
        let mut config = enabled_config();
        config.tenant_id = Some("acme-corp".to_string());
        let mut labels = HashMap::new();
        stamp_owner_labels(&principal, &config, &mut labels);
        assert_eq!(labels.get(LABEL_OWNER), Some(&"alice".to_string()));
        assert_eq!(labels.get(LABEL_TENANT), Some(&"acme-corp".to_string()));
    }

    #[test]
    fn stamp_strips_spoofed_owner_labels() {
        let principal = user_principal("alice", &[]);
        let config = enabled_config();
        let mut labels = HashMap::from([
            (LABEL_OWNER.to_string(), "mallory".to_string()),
            (LABEL_TENANT.to_string(), "evil-corp".to_string()),
        ]);
        stamp_owner_labels(&principal, &config, &mut labels);
        assert_eq!(labels.get(LABEL_OWNER), Some(&"alice".to_string()));
        assert!(!labels.contains_key(LABEL_TENANT)); // No tenant configured.
    }

    #[test]
    fn stamp_anonymous_principal_is_noop() {
        let principal = Principal::Anonymous;
        let config = enabled_config();
        let mut labels = HashMap::new();
        stamp_owner_labels(&principal, &config, &mut labels);
        assert!(labels.is_empty());
    }

    #[test]
    fn stamp_sanitizes_subject() {
        let principal = user_principal("alice@example.com", &[]);
        let config = enabled_config();
        let mut labels = HashMap::new();
        stamp_owner_labels(&principal, &config, &mut labels);
        assert_eq!(
            labels.get(LABEL_OWNER),
            Some(&"alice_example.com".to_string())
        );
    }

    // ── check_ownership ──────────────────────────────────────────────

    #[test]
    fn check_disabled_always_ok() {
        let principal = user_principal("alice", &[]);
        let config = disabled_config();
        let labels = HashMap::from([(LABEL_OWNER.to_string(), "bob".to_string())]);
        assert!(check_ownership(&principal, &config, &labels).is_ok());
    }

    #[test]
    fn check_owner_matches() {
        let principal = user_principal("alice", &[]);
        let config = enabled_config();
        let labels = HashMap::from([(LABEL_OWNER.to_string(), "alice".to_string())]);
        assert!(check_ownership(&principal, &config, &labels).is_ok());
    }

    #[test]
    fn check_owner_mismatch_returns_permission_denied() {
        let principal = user_principal("alice", &[]);
        let config = enabled_config();
        let labels = HashMap::from([(LABEL_OWNER.to_string(), "bob".to_string())]);
        let err = check_ownership(&principal, &config, &labels).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn check_admin_bypasses_ownership() {
        let principal = user_principal("admin", &["openshell-admin"]);
        let config = enabled_config();
        let labels = HashMap::from([(LABEL_OWNER.to_string(), "alice".to_string())]);
        assert!(check_ownership(&principal, &config, &labels).is_ok());
    }

    #[test]
    fn check_no_owner_label_is_ok() {
        let principal = user_principal("alice", &[]);
        let config = enabled_config();
        let labels = HashMap::new();
        assert!(check_ownership(&principal, &config, &labels).is_ok());
    }

    #[test]
    fn check_anonymous_principal_is_ok() {
        let principal = Principal::Anonymous;
        let config = enabled_config();
        let labels = HashMap::from([(LABEL_OWNER.to_string(), "alice".to_string())]);
        assert!(check_ownership(&principal, &config, &labels).is_ok());
    }

    // ── owner_label_selector ─────────────────────────────────────────

    #[test]
    fn selector_disabled_returns_none() {
        let principal = user_principal("alice", &[]);
        let config = disabled_config();
        assert!(owner_label_selector(&principal, &config).is_none());
    }

    #[test]
    fn selector_admin_returns_none() {
        let principal = user_principal("admin", &["openshell-admin"]);
        let config = enabled_config();
        assert!(owner_label_selector(&principal, &config).is_none());
    }

    #[test]
    fn selector_regular_user_returns_filter() {
        let principal = user_principal("alice", &["openshell-user"]);
        let config = enabled_config();
        assert_eq!(
            owner_label_selector(&principal, &config),
            Some("openshell.ai/owner=alice".to_string())
        );
    }

    #[test]
    fn selector_anonymous_returns_none() {
        let principal = Principal::Anonymous;
        let config = enabled_config();
        assert!(owner_label_selector(&principal, &config).is_none());
    }

    #[test]
    fn selector_sanitizes_subject() {
        let principal = user_principal("alice@example.com", &["openshell-user"]);
        let config = enabled_config();
        assert_eq!(
            owner_label_selector(&principal, &config),
            Some("openshell.ai/owner=alice_example.com".to_string())
        );
    }

    #[test]
    fn selector_empty_sanitized_subject_returns_none() {
        let principal = user_principal("---", &["openshell-user"]);
        let config = enabled_config();
        assert!(owner_label_selector(&principal, &config).is_none());
    }

    #[test]
    fn selector_user_with_no_roles_still_gets_selector() {
        let principal = user_principal("u1", &[]);
        let config = enabled_config();
        let result = owner_label_selector(&principal, &config);
        assert!(result.is_some());
        assert!(result.unwrap().starts_with("openshell.ai/owner="));
    }
}
