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
    /// Kubernetes pod authenticated for supervisor pod registration only.
    ///
    /// This is intentionally not a sandbox principal: warm pods can be valid
    /// Kubernetes pods before they are claimed by a sandbox. The router only
    /// allows this principal to call `RegisterSupervisorPod`.
    K8sPod(RegisteredPodIdentity),
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

/// Kubernetes pod identity validated by `TokenReview` and live pod lookup.
///
/// `sandbox_id` is present only when the pod is already bound to a concrete
/// `OpenShell` sandbox. Unbound warm pods carry the owning Sandbox CR metadata
/// but must not receive a gateway sandbox JWT until a later claim binds the
/// exact pod UID to a sandbox.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RegisteredPodIdentity {
    /// Live pod name from the `TokenReview` binding.
    pub pod_name: String,
    /// Live pod UID from the `TokenReview` binding and pod lookup.
    pub pod_uid: String,
    /// `OpenShell` sandbox UUID from the pod annotation, when already bound.
    pub sandbox_id: Option<String>,
    /// Owning Sandbox CR name from the pod ownerReference.
    pub sandbox_owner_name: String,
    /// Owning Sandbox CR UID from the pod ownerReference and live CR lookup.
    pub sandbox_owner_uid: String,
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
    /// K8s `ServiceAccount` token used to bootstrap a gateway-minted JWT.
    /// Populated only on Kubernetes bootstrap RPC paths.
    K8sServiceAccount { pod_name: String, pod_uid: String },
}
