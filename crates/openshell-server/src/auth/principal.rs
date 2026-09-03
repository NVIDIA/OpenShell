// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authenticated caller principals.
//!
//! A `Principal` is the result of running the [`super::authenticator::Authenticator`]
//! chain on an inbound request. It generalizes over the kinds of callers the
//! gateway recognizes — human users (OIDC), sandbox supervisors (gateway-minted
//! JWT), and anonymous callers (truly unauthenticated methods
//! like health probes).
//!
//! Handlers read the principal from the gRPC `Request` extensions and gate
//! access accordingly. Sandbox-class handlers MUST compare
//! `Principal::Sandbox.sandbox_id` against the request body's `sandbox_id`
//! to prevent cross-sandbox access (see issue #1354).

use super::identity::Identity;
use serde::{Deserialize, Serialize};

/// The authority a gateway-minted sandbox credential carries.
///
/// The credential is always bound to exactly one sandbox; this narrows *which
/// of that sandbox's* RPCs it may call. It is serialized into the sandbox JWT
/// (`caller_kind` claim) and read back onto [`SandboxPrincipal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxCallerKind {
    /// Full supervisor authority (network + process halves in one place, as in
    /// `combined`/`sidecar`). The default so tokens minted before this claim
    /// existed keep working unchanged.
    #[default]
    Full,
    /// Process-supervisor-only authority, for a topology where the network proxy
    /// runs in a separate pod (proxy-pod). Denied the network-supervisor RPCs
    /// that read provider secrets or mint upstream credentials
    /// (`GetSandboxProviderEnvironment`, `ExchangeProviderSubjectToken`,
    /// `GetInferenceBundle`); still permitted its own relays, logs, config, and
    /// token refresh.
    Process,
}

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
    /// Optional namespace component parsed from sandbox identity credentials.
    /// Gateway-minted sandbox JWTs currently use an identity-shaped subject.
    pub trust_domain: Option<String>,
}

impl SandboxPrincipal {
    /// The authority this credential carries. Only a gateway-minted JWT can be
    /// scoped; every other source (bootstrap SA token, client cert) is `Full`.
    #[must_use]
    pub fn caller_kind(&self) -> SandboxCallerKind {
        match self.source {
            SandboxIdentitySource::BootstrapJwt { caller_kind, .. } => caller_kind,
            _ => SandboxCallerKind::Full,
        }
    }
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
    BootstrapJwt {
        issuer: String,
        /// Authority carried by the token's `caller_kind` claim.
        caller_kind: SandboxCallerKind,
    },
    /// Per-sandbox client certificate. Reserved for channel-bound sandbox
    /// identity.
    BootstrapCert { fingerprint: String },
    /// Driver-native credential used to bootstrap a gateway-minted JWT via
    /// `IssueSandboxToken`. The named compute driver authenticated only the
    /// sandbox identity; the gateway still authorizes the exchange. `caller_kind`
    /// narrows the minted token when the driver reports a process-scoped caller
    /// (e.g. a proxy-pod agent pod), otherwise `Full`.
    ComputeDriver {
        driver_name: String,
        caller_kind: SandboxCallerKind,
    },
}
