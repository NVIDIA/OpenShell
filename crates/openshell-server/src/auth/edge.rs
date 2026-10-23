// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Edge token authentication.
//!
//! A gateway behind an authenticating proxy (Cloudflare Access) receives the
//! proxy's signed token on every request. This authenticator verifies that
//! token against the provider's published signing keys, so a caller that
//! bypasses the proxy is rejected rather than trusted by network path.
//!
//! Signature, issuer, audience, expiry, and key rotation are handled by
//! [`JwksCache`], the same verifier OIDC uses.

use super::authenticator::{AuthRejection, Authentication, Authenticator};
use super::http::extract_cookie;
use super::oidc::JwksCache;
use async_trait::async_trait;
use std::borrow::Cow;
use std::sync::Arc;

/// Header Cloudflare Access sets with the signed token.
pub const EDGE_TOKEN_HEADER: &str = "cf-access-jwt-assertion";

/// Cookie Cloudflare Access sets with the same signed token.
pub const EDGE_TOKEN_COOKIE: &str = "CF_Authorization";

/// The edge token on a request: the header, else the cookie.
pub fn edge_credential(headers: &http::HeaderMap) -> Option<Cow<'_, str>> {
    let from_header = headers
        .get(EDGE_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(Cow::Borrowed);
    from_header.or_else(|| {
        headers
            .get(http::header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|cookies| extract_cookie(cookies, EDGE_TOKEN_COOKIE))
            .filter(|value| !value.is_empty())
            .map(Cow::Owned)
    })
}

/// Reject settings that would let a caller skip the edge token.
///
/// Edge authentication is the gateway's only user authentication mode when
/// configured, and an unauthenticated fallback would make the token optional.
pub fn validate_config(config: &openshell_core::Config) -> Result<(), String> {
    if config.edge_auth.is_none() {
        return Ok(());
    }
    if config.oidc.is_some() {
        return Err(
            "edge_auth and OIDC cannot both be configured; choose one user authentication mode"
                .to_string(),
        );
    }
    if config.auth.allow_unauthenticated_users {
        return Err("edge_auth cannot be combined with allow_unauthenticated_users, which would accept callers without an edge token".to_string());
    }
    Ok(())
}

/// Authenticator that validates the edge proxy's token.
///
/// Returns `NotApplicable` when the request carries no edge token. A token
/// that fails verification ends the chain with `Unauthenticated`; it never
/// falls back to another identity.
pub struct EdgeAuthenticator {
    cache: Arc<JwksCache>,
}

impl EdgeAuthenticator {
    pub fn new(cache: Arc<JwksCache>) -> Self {
        Self { cache }
    }
}

#[async_trait]
impl Authenticator for EdgeAuthenticator {
    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        _path: &str,
    ) -> Result<Authentication, AuthRejection> {
        let Some(token) = edge_credential(headers) else {
            return Ok(Authentication::NotApplicable);
        };
        self.cache.accept_user(&token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderValue};

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    fn config_with_edge() -> openshell_core::Config {
        openshell_core::Config::new(None).with_edge_auth(openshell_core::EdgeAuthConfig {
            provider: openshell_core::EdgeAuthProvider::CloudflareAccess,
            issuer: "https://team.cloudflareaccess.com".to_string(),
            audience: "aud".to_string(),
            jwks_ttl_secs: 3600,
            roles_claim: String::new(),
            admin_role: String::new(),
            user_role: String::new(),
        })
    }

    #[test]
    fn edge_auth_rejects_fallbacks_that_make_the_token_optional() {
        assert!(validate_config(&openshell_core::Config::new(None)).is_ok());
        assert!(validate_config(&config_with_edge()).is_ok());

        let mut unauthenticated = config_with_edge();
        unauthenticated.auth.allow_unauthenticated_users = true;
        let error = validate_config(&unauthenticated).expect_err("rejected");
        assert!(error.contains("allow_unauthenticated_users"), "{error}");

        let with_oidc = config_with_edge().with_oidc(openshell_core::OidcConfig {
            issuer: "https://idp.example.com".to_string(),
            dangerously_allow_insecure_http: false,
            jwks_allowed_origins: Vec::new(),
            audience: "cli".to_string(),
            jwks_ttl_secs: 3600,
            roles_claim: String::new(),
            admin_role: String::new(),
            user_role: String::new(),
            scopes_claim: String::new(),
        });
        let error = validate_config(&with_oidc).expect_err("rejected");
        assert!(error.contains("cannot both be configured"), "{error}");
    }

    #[test]
    fn credential_prefers_header_over_cookie() {
        let map = headers(&[
            ("cf-access-jwt-assertion", "from-header"),
            ("cookie", "CF_Authorization=from-cookie"),
        ]);
        assert_eq!(edge_credential(&map).as_deref(), Some("from-header"));
    }

    #[test]
    fn credential_falls_back_to_cookie() {
        let map = headers(&[("cookie", "theme=dark; CF_Authorization=from-cookie; a=b")]);
        assert_eq!(edge_credential(&map).as_deref(), Some("from-cookie"));
    }

    #[test]
    fn credential_ignores_empty_header_and_other_cookies() {
        let map = headers(&[("cf-access-jwt-assertion", "  "), ("cookie", "theme=dark")]);
        assert!(edge_credential(&map).is_none());
        assert!(edge_credential(&HeaderMap::new()).is_none());
    }
}
