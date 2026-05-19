// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-handler sandbox-scope guards.
//!
//! Closes the IDOR half of issue #1354: a sandbox principal may only
//! reference its own sandbox, identified by its [`Principal::Sandbox`]'s
//! `sandbox_id`. User principals retain the broad scope the RBAC layer
//! already evaluated.

use super::principal::Principal;
use super::principal::SandboxPrincipal;
use tonic::Status;
use tracing::info;

/// Reject a sandbox-class request whose body references a sandbox other
/// than the one the calling principal was authenticated against.
///
/// - [`Principal::User`] passes through (RBAC has already evaluated user
///   scope at the router level).
/// - [`Principal::Sandbox`] must reference the same canonical UUID it
///   was authenticated with.
/// - [`Principal::Anonymous`] is rejected — sandbox-class methods are
///   never anonymously callable.
///
/// `claimed_sandbox_id` is the canonical UUID the request is operating
/// on. Name-keyed handlers must resolve the name to a UUID via the
/// store before calling this guard.
#[allow(clippy::result_large_err)]
pub fn ensure_sandbox_scope(principal: &Principal, claimed_sandbox_id: &str) -> Result<(), Status> {
    match principal {
        Principal::User(_) => Ok(()),
        Principal::Sandbox(p) => {
            if p.sandbox_id == claimed_sandbox_id {
                Ok(())
            } else {
                info!(
                    principal_sandbox_id = %p.sandbox_id,
                    requested_sandbox_id = %claimed_sandbox_id,
                    "cross-sandbox access denied"
                );
                Err(Status::permission_denied(
                    "cross-sandbox access denied: principal does not own this sandbox",
                ))
            }
        }
        Principal::Anonymous => Err(Status::unauthenticated(
            "sandbox-scoped methods require an authenticated caller",
        )),
    }
}

/// Convenience: read the `Principal` out of a request and apply
/// [`ensure_sandbox_scope`]. Returns the principal so callers can read it
/// further (e.g. for audit logging).
#[allow(clippy::result_large_err)]
pub fn enforce_sandbox_scope<T>(
    request: &tonic::Request<T>,
    claimed_sandbox_id: &str,
) -> Result<Principal, Status> {
    let principal = request
        .extensions()
        .get::<Principal>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("missing principal"))?;
    ensure_sandbox_scope(&principal, claimed_sandbox_id)?;
    Ok(principal)
}

/// Require a sandbox principal and reject users or anonymous callers.
///
/// Supervisor-only control/data plane RPCs (`ConnectSupervisor`,
/// `RelayStream`) must be presented by the sandbox supervisor itself.
/// User principals intentionally pass [`ensure_sandbox_scope`] for normal
/// CLI/TUI APIs because RBAC is their gate, but they are not valid
/// supervisor identities.
#[allow(clippy::result_large_err)]
pub fn ensure_sandbox_principal_scope(
    principal: &Principal,
    claimed_sandbox_id: &str,
) -> Result<SandboxPrincipal, Status> {
    match principal {
        Principal::Sandbox(p) => {
            ensure_sandbox_scope(principal, claimed_sandbox_id)?;
            Ok(p.clone())
        }
        Principal::User(_) => Err(Status::permission_denied(
            "supervisor RPCs require a sandbox principal",
        )),
        Principal::Anonymous => Err(Status::unauthenticated(
            "supervisor RPCs require an authenticated sandbox principal",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::{Identity, IdentityProvider};
    use crate::auth::principal::{SandboxIdentitySource, SandboxPrincipal, UserPrincipal};

    fn user(subject: &str) -> Principal {
        Principal::User(UserPrincipal {
            identity: Identity {
                subject: subject.to_string(),
                display_name: None,
                roles: vec![],
                scopes: vec![],
                provider: IdentityProvider::Oidc,
            },
        })
    }

    fn sandbox(id: &str) -> Principal {
        Principal::Sandbox(SandboxPrincipal {
            sandbox_id: id.to_string(),
            source: SandboxIdentitySource::BootstrapJwt {
                issuer: "openshell-gateway:test".to_string(),
            },
            trust_domain: Some("openshell".to_string()),
        })
    }

    #[test]
    fn user_principal_bypasses_equality_check() {
        // RBAC was the user's gate at the router layer.
        assert!(ensure_sandbox_scope(&user("alice"), "any-sandbox").is_ok());
    }

    #[test]
    fn sandbox_principal_matching_id_is_allowed() {
        assert!(ensure_sandbox_scope(&sandbox("sbx-1"), "sbx-1").is_ok());
    }

    #[test]
    fn sandbox_principal_mismatched_id_is_denied() {
        let err =
            ensure_sandbox_scope(&sandbox("sbx-1"), "sbx-2").expect_err("must deny cross-sandbox");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn anonymous_principal_is_rejected() {
        let err =
            ensure_sandbox_scope(&Principal::Anonymous, "sbx-1").expect_err("must reject anon");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn sandbox_principal_scope_returns_matching_sandbox() {
        let principal = sandbox("sbx-1");
        let scoped = ensure_sandbox_principal_scope(&principal, "sbx-1").expect("scope OK");
        assert_eq!(scoped.sandbox_id, "sbx-1");
    }

    #[test]
    fn sandbox_principal_scope_rejects_users() {
        let err = ensure_sandbox_principal_scope(&user("alice"), "sbx-1")
            .expect_err("users are not supervisor identities");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn enforce_reads_from_request_extensions() {
        let mut req = tonic::Request::new(());
        req.extensions_mut().insert(sandbox("sbx-1"));
        let result = enforce_sandbox_scope(&req, "sbx-1").expect("scope OK");
        assert!(matches!(result, Principal::Sandbox(_)));
    }

    #[test]
    fn enforce_rejects_request_without_principal() {
        let req = tonic::Request::new(());
        let err = enforce_sandbox_scope(&req, "sbx-1").expect_err("must require principal");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
