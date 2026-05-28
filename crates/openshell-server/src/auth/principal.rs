// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authenticated caller principals.
//!
//! A `Principal` is the result of running the [`super::authenticator::Authenticator`]
//! chain on an inbound request. It generalizes over the kinds of callers the
//! gateway recognizes — human users (OIDC), sandbox supervisors (gateway-minted
//! JWT, future SPIFFE), and anonymous callers (truly unauthenticated methods
//! like health probes).
//!
//! Handlers read the principal from the gRPC `Request` extensions and gate
//! access accordingly. Sandbox-class handlers MUST compare
//! `Principal::Sandbox.sandbox_id` against the request body's `sandbox_id`
//! to prevent cross-sandbox access (see issue #1354).

use super::identity::Identity;

/// Who is calling.
///
/// Inserted into `tonic::Request::extensions` by the auth router. Handlers
/// retrieve it via `req.extensions().get::<Principal>()`.
#[derive(Debug, Clone)]
pub enum Principal {
    /// Human caller authenticated via OIDC (Keycloak, Entra ID, Okta, etc.).
    User(UserPrincipal),
    /// Sandbox supervisor authenticated by an identity bound to a specific
    /// sandbox UUID. The wrapped `sandbox_id` MUST match any sandbox referenced
    /// in the request body for sandbox-class methods.
    Sandbox(#[allow(dead_code)] SandboxPrincipal),
    /// Truly unauthenticated caller (health probes, reflection). Sandbox-class
    /// and user-class methods reject this variant.
    #[allow(dead_code)]
    Anonymous,
}

/// User caller — wraps the existing provider-agnostic [`Identity`].
#[derive(Debug, Clone)]
pub struct UserPrincipal {
    /// The verified identity from the authentication provider.
    pub identity: Identity,
}

/// Sandbox caller — bound to one specific sandbox UUID.
///
/// `sandbox_id` and `source` are consumed by the router and handler guards.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SandboxPrincipal {
    /// Canonical sandbox UUID populated from a verified sandbox credential.
    pub sandbox_id: String,
    /// How this principal was verified — used for audit logs and method-specific
    /// authorization checks.
    pub source: SandboxIdentitySource,
    /// SPIFFE trust domain. Populated when the credential is SPIFFE-shaped;
    /// reserved for future per-sandbox cert / SPIRE authenticators.
    pub trust_domain: Option<String>,
}

/// How a [`SandboxPrincipal`] was authenticated.
///
/// Variant fields are populated by the producing authenticator and consumed
/// by audit logging and method-specific authorization checks.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum SandboxIdentitySource {
    /// Gateway-minted JWT validated against the gateway's signing key.
    /// Produced by [`super::sandbox_jwt::SandboxJwtAuthenticator`].
    BootstrapJwt { issuer: String },
    /// Per-sandbox client certificate. Reserved for channel-bound sandbox
    /// identity.
    BootstrapCert { fingerprint: String },
    /// SPIRE-issued SVID. Reserved for SPIFFE/SPIRE sandbox identity.
    SpiffeSvid { spiffe_id: String },
    /// K8s `ServiceAccount` token used to bootstrap a gateway-minted JWT
    /// via `IssueSandboxToken`. Populated only on that one RPC path.
    K8sServiceAccount { pod_name: String, pod_uid: String },
}

impl Principal {
    /// Stable actor kind for gateway audit logs.
    #[must_use]
    pub const fn audit_actor_kind(&self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::Sandbox(_) => "sandbox",
            Self::Anonymous => "anonymous",
        }
    }

    /// Stable actor subject for gateway audit logs.
    #[must_use]
    pub fn audit_actor_subject(&self) -> &str {
        match self {
            Self::User(user) => &user.identity.subject,
            Self::Sandbox(sandbox) => &sandbox.sandbox_id,
            Self::Anonymous => "anonymous",
        }
    }

    /// Optional human-readable actor display for gateway audit logs.
    #[must_use]
    pub fn audit_actor_display(&self) -> Option<&str> {
        match self {
            Self::User(user) => user.identity.display_name.as_deref(),
            Self::Sandbox(_) | Self::Anonymous => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::{Identity, IdentityProvider};

    #[test]
    fn user_principal_formats_audit_actor_fields() {
        let principal = Principal::User(UserPrincipal {
            identity: Identity {
                subject: "user-123".to_string(),
                display_name: Some("alice".to_string()),
                roles: vec!["openshell-user".to_string()],
                scopes: vec![],
                provider: IdentityProvider::Oidc,
            },
        });
        assert_eq!(principal.audit_actor_kind(), "user");
        assert_eq!(principal.audit_actor_subject(), "user-123");
        assert_eq!(principal.audit_actor_display(), Some("alice"));
    }

    #[test]
    fn sandbox_principal_formats_audit_actor_fields() {
        let principal = Principal::Sandbox(SandboxPrincipal {
            sandbox_id: "sandbox-123".to_string(),
            source: SandboxIdentitySource::BootstrapJwt {
                issuer: "openshell-gateway:test".to_string(),
            },
            trust_domain: Some("openshell".to_string()),
        });
        assert_eq!(principal.audit_actor_kind(), "sandbox");
        assert_eq!(principal.audit_actor_subject(), "sandbox-123");
        assert_eq!(principal.audit_actor_display(), None);
    }
}
