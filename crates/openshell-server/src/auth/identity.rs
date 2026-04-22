// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider-agnostic identity representation.
//!
//! Any authentication backend (OIDC, mTLS, static RBAC, OS users) produces
//! an `Identity` that the authorization layer can evaluate without knowing
//! which provider authenticated the caller.

/// Authenticated caller identity.
///
/// Produced by an authentication provider and consumed by the authorization
/// layer. The gateway's auth middleware converts provider-specific claims
/// (OIDC JWT, mTLS cert CN, etc.) into this common representation.
#[derive(Debug, Clone)]
pub struct Identity {
    /// Unique subject identifier (OIDC `sub`, cert CN, username, etc.).
    pub subject: String,

    /// Human-readable display name (OIDC `preferred_username`, cert CN, etc.).
    pub display_name: Option<String>,

    /// Roles granted to this identity (OIDC `realm_access.roles`, cert OU, etc.).
    pub roles: Vec<String>,

    /// OAuth2 scopes granted to this identity. Empty when scope enforcement is disabled.
    pub scopes: Vec<String>,

    /// Which authentication provider produced this identity.
    pub provider: IdentityProvider,
}

/// Authentication provider that produced an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityProvider {
    /// OIDC/OAuth2 JWT bearer token.
    Oidc,
    /// mTLS client certificate.
    Mtls,
    /// Cloudflare Access JWT.
    CloudflareAccess,
    /// Internal (skip-listed methods, sandbox supervisor RPCs).
    Internal,
}
