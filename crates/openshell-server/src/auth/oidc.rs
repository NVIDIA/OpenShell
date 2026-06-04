// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OIDC JWT authentication provider.
//!
//! Validates `authorization: Bearer <JWT>` headers against a Keycloak (or
//! any OIDC-compliant) issuer using cached JWKS keys. Produces an
//! `Identity` that the authorization layer (`authz.rs`) evaluates.
//!
//! This module owns authentication (verifying who the caller is).
//! Authorization (deciding what the caller can do) is in `authz.rs`.

use super::authenticator::Authenticator;
use super::identity::{Identity, IdentityProvider};
use super::principal::{Principal, UserPrincipal};
use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use openshell_core::OidcConfig;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tonic::Status;
use tracing::{debug, info, warn};

/// Path prefixes that bypass OIDC validation (gRPC reflection, health probes).
///
/// These are structural bypasses for gRPC infrastructure that doesn't map to a
/// single RPC method. Per-method bypasses (e.g. `Health`) are declared at the
/// handler with `#[rpc_auth(auth = "unauthenticated")]`.
const UNAUTHENTICATED_PREFIXES: &[&str] = &["/grpc.reflection.", "/grpc.health."];

/// Returns `true` if the method needs no authentication at all.
pub fn is_unauthenticated_method(path: &str) -> bool {
    super::method_authz::is_unauthenticated(path)
        || UNAUTHENTICATED_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix))
}

/// Cached JWKS key set fetched from the OIDC issuer.
///
/// A `refresh_mutex` ensures that only one refresh runs at a time,
/// preventing a "thundering herd" when the TTL expires or a new `kid`
/// is encountered under concurrent load.
pub struct JwksCache {
    keys: Arc<RwLock<HashMap<String, DecodingKey>>>,
    jwks_uri: String,
    ttl: Duration,
    last_refresh: Arc<RwLock<Instant>>,
    /// Serializes JWKS refresh operations so concurrent requests coalesce
    /// into a single HTTP fetch rather than stampeding the OIDC provider.
    refresh_mutex: tokio::sync::Mutex<()>,
    http: Client,
    config: OidcConfig,
}

impl std::fmt::Debug for JwksCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksCache")
            .field("jwks_uri", &self.jwks_uri)
            .field("ttl", &self.ttl)
            .finish()
    }
}

/// OIDC discovery document (subset of fields we need).
#[derive(Deserialize)]
struct OidcDiscovery {
    issuer: String,
    jwks_uri: String,
}

/// JWKS key set.
#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<JwkKey>,
}

/// A single JWK key.
#[derive(Deserialize)]
struct JwkKey {
    kid: Option<String>,
    kty: String,
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
}

/// Claims extracted from a validated JWT.
#[derive(Debug, Deserialize)]
pub struct OidcClaims {
    pub sub: String,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub email: Option<String>,
    /// Roles extracted from the configurable claim path.
    #[serde(skip)]
    pub roles: Vec<String>,
    /// Raw claims for flexible role extraction.
    #[serde(flatten)]
    extra: serde_json::Value,
}

const STANDARD_OIDC_SCOPES: &[&str] = &["openid", "profile", "email", "offline_access"];

impl OidcClaims {
    /// Extract roles from the JWT claims using a dot-separated path.
    ///
    /// Supports paths like:
    /// - `realm_access.roles` (Keycloak)
    /// - `roles` (Entra ID)
    /// - `groups` (Okta)
    fn extract_roles(&mut self, roles_claim: &str) {
        let mut value = &self.extra;
        for segment in roles_claim.split('.') {
            match value.get(segment) {
                Some(v) => value = v,
                None => return,
            }
        }
        if let Some(arr) = value.as_array() {
            self.roles = arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
        }
    }

    /// Extract scopes from the JWT claims using a dot-separated path.
    ///
    /// Handles two formats:
    /// - Space-delimited string: `"openid sandbox:read sandbox:write"` (Keycloak, Entra)
    /// - JSON array: `["sandbox:read", "sandbox:write"]` (Okta)
    ///
    /// Filters out standard OIDC scopes (`openid`, `profile`, `email`, `offline_access`).
    fn extract_scopes(&self, scopes_claim: &str) -> Vec<String> {
        let mut value = &self.extra;
        for segment in scopes_claim.split('.') {
            match value.get(segment) {
                Some(v) => value = v,
                None => return vec![],
            }
        }

        let raw: Vec<String> = if let Some(s) = value.as_str() {
            s.split_whitespace().map(String::from).collect()
        } else if let Some(arr) = value.as_array() {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        } else {
            return vec![];
        };

        raw.into_iter()
            .filter(|s| !STANDARD_OIDC_SCOPES.contains(&s.as_str()))
            .collect()
    }
}

impl JwksCache {
    /// Create a new JWKS cache, discovering the JWKS URI and fetching the
    /// initial key set.
    pub async fn new(config: &OidcConfig) -> Result<Self, String> {
        let http = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("failed to create HTTP client: {e}"))?;

        // Discover JWKS URI from the OIDC discovery endpoint.
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            config.issuer.trim_end_matches('/')
        );
        info!(url = %discovery_url, "Discovering OIDC configuration");

        let discovery: OidcDiscovery = http
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| format!("OIDC discovery request failed: {e}"))?
            .json()
            .await
            .map_err(|e| format!("OIDC discovery response parse failed: {e}"))?;

        // Validate the discovery document's issuer matches our configured issuer.
        let expected = config.issuer.trim_end_matches('/');
        let actual = discovery.issuer.trim_end_matches('/');
        if expected != actual {
            return Err(format!(
                "OIDC discovery issuer mismatch: expected '{expected}', got '{actual}'"
            ));
        }

        info!(jwks_uri = %discovery.jwks_uri, "OIDC JWKS URI discovered");

        let cache = Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            jwks_uri: discovery.jwks_uri,
            ttl: Duration::from_secs(config.jwks_ttl_secs),
            last_refresh: Arc::new(RwLock::new(
                Instant::now()
                    .checked_sub(Duration::from_secs(config.jwks_ttl_secs + 1))
                    .unwrap_or_else(Instant::now),
            )),
            refresh_mutex: tokio::sync::Mutex::new(()),
            http,
            config: config.clone(),
        };

        cache.refresh_keys().await?;
        Ok(cache)
    }

    /// Fetch the JWKS and update the cached keys.
    async fn refresh_keys(&self) -> Result<(), String> {
        debug!(uri = %self.jwks_uri, "Refreshing JWKS keys");

        let jwk_set: JwkSet = self
            .http
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|e| format!("JWKS fetch failed: {e}"))?
            .json()
            .await
            .map_err(|e| format!("JWKS parse failed: {e}"))?;

        let mut new_keys = HashMap::new();
        for key in &jwk_set.keys {
            if key.kty != "RSA" {
                continue;
            }
            let Some(ref kid) = key.kid else {
                continue;
            };
            match DecodingKey::from_rsa_components(&key.n, &key.e) {
                Ok(dk) => {
                    new_keys.insert(kid.clone(), dk);
                }
                Err(e) => {
                    warn!(kid = %kid, error = %e, "Failed to parse JWK");
                }
            }
        }

        info!(count = new_keys.len(), "JWKS keys loaded");
        *self.keys.write().await = new_keys;
        *self.last_refresh.write().await = Instant::now();
        Ok(())
    }

    /// Refresh keys if the TTL has elapsed.
    ///
    /// Holds the refresh mutex so concurrent callers coalesce into a single
    /// HTTP fetch. The second caller will re-check the TTL after acquiring
    /// the lock and find it fresh.
    async fn refresh_if_stale(&self) -> Result<(), String> {
        let last = *self.last_refresh.read().await;
        if last.elapsed() <= self.ttl {
            return Ok(());
        }
        let _guard = self.refresh_mutex.lock().await;
        // Re-check after acquiring the lock — another task may have refreshed.
        let last = *self.last_refresh.read().await;
        if last.elapsed() <= self.ttl {
            return Ok(());
        }
        self.refresh_keys().await
    }

    /// Refresh keys unconditionally, coalescing concurrent callers.
    async fn refresh_keys_coalesced(&self) -> Result<(), String> {
        let _guard = self.refresh_mutex.lock().await;
        self.refresh_keys().await
    }

    /// Validate a JWT and return an `Identity`.
    ///
    /// This is the authentication step — it verifies the caller's identity
    /// but does not check authorization (that's `authz::AuthzPolicy::check`).
    pub async fn validate_token(&self, token: &str) -> Result<Identity, Status> {
        self.refresh_if_stale().await.map_err(|e| {
            warn!(error = %e, "JWKS refresh failed");
            Status::internal("OIDC key refresh failed")
        })?;

        // Decode the header to find the key ID.
        let header = decode_header(token).map_err(|e| {
            debug!(error = %e, "Failed to decode JWT header");
            Status::unauthenticated("invalid token")
        })?;

        let kid = header.kid.ok_or_else(|| {
            debug!("JWT has no kid in header");
            Status::unauthenticated("invalid token: missing kid")
        })?;

        // Look up the key in cache.
        let keys = self.keys.read().await;
        let decoding_key = if let Some(k) = keys.get(&kid) {
            k.clone()
        } else {
            // Key not found -- try refreshing once (key rotation).
            drop(keys);
            self.refresh_keys_coalesced().await.map_err(|e| {
                warn!(error = %e, "JWKS refresh on kid miss failed");
                Status::internal("OIDC key refresh failed")
            })?;
            let keys = self.keys.read().await;
            keys.get(&kid).cloned().ok_or_else(|| {
                debug!(kid = %kid, "JWT kid not found in JWKS");
                Status::unauthenticated("invalid token: unknown signing key")
            })?
        };

        // Validate the JWT.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);

        let token_data = decode::<OidcClaims>(token, &decoding_key, &validation).map_err(|e| {
            debug!(error = %e, "JWT validation failed");
            Status::unauthenticated(format!("invalid token: {e}"))
        })?;

        let mut claims = token_data.claims;
        claims.extract_roles(&self.config.roles_claim);

        let scopes = if self.config.scopes_claim.is_empty() {
            vec![]
        } else {
            claims.extract_scopes(&self.config.scopes_claim)
        };

        Ok(Identity {
            subject: claims.sub,
            display_name: claims.preferred_username,
            roles: claims.roles,
            scopes,
            provider: IdentityProvider::Oidc,
        })
    }
}

/// Authenticator that validates `Authorization: Bearer <jwt>` headers against
/// the configured OIDC issuer.
///
/// Returns `Ok(None)` when no Bearer header is present, so the chain can fall
/// through to other authenticators (e.g. the gateway-minted sandbox JWT
/// authenticator).
pub struct OidcAuthenticator {
    cache: Arc<JwksCache>,
}

impl OidcAuthenticator {
    pub fn new(cache: Arc<JwksCache>) -> Self {
        Self { cache }
    }
}

#[async_trait]
impl Authenticator for OidcAuthenticator {
    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        _path: &str,
    ) -> Result<Option<Principal>, Status> {
        let Some(token) = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        else {
            return Ok(None);
        };

        let identity = self.cache.validate_token(token).await?;
        Ok(Some(Principal::User(UserPrincipal { identity })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_is_unauthenticated() {
        assert!(is_unauthenticated_method("/openshell.v1.OpenShell/Health"));
    }

    #[test]
    fn sandbox_operations_require_auth() {
        assert!(!is_unauthenticated_method(
            "/openshell.v1.OpenShell/CreateSandbox"
        ));
    }

    #[test]
    fn reflection_is_unauthenticated() {
        assert!(is_unauthenticated_method(
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
        ));
        assert!(is_unauthenticated_method(
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
        ));
    }

    #[test]
    fn grpc_health_is_unauthenticated() {
        assert!(is_unauthenticated_method("/grpc.health.v1.Health/Check"));
    }

    #[test]
    fn extract_roles_keycloak_path() {
        let json = serde_json::json!({
            "sub": "user1",
            "realm_access": { "roles": ["openshell-user", "openshell-admin"] }
        });
        let mut claims: OidcClaims = serde_json::from_value(json).unwrap();
        claims.extract_roles("realm_access.roles");
        assert_eq!(claims.roles, vec!["openshell-user", "openshell-admin"]);
    }

    #[test]
    fn extract_roles_flat_path() {
        // Entra ID / Okta style: roles at top level
        let json = serde_json::json!({
            "sub": "user1",
            "roles": ["OpenShell.Admin", "OpenShell.User"]
        });
        let mut claims: OidcClaims = serde_json::from_value(json).unwrap();
        claims.extract_roles("roles");
        assert_eq!(claims.roles, vec!["OpenShell.Admin", "OpenShell.User"]);
    }

    #[test]
    fn extract_roles_groups_path() {
        // Okta style: groups claim
        let json = serde_json::json!({
            "sub": "user1",
            "groups": ["everyone", "openshell-admin"]
        });
        let mut claims: OidcClaims = serde_json::from_value(json).unwrap();
        claims.extract_roles("groups");
        assert_eq!(claims.roles, vec!["everyone", "openshell-admin"]);
    }

    #[test]
    fn extract_roles_missing_claim() {
        let json = serde_json::json!({ "sub": "user1" });
        let mut claims: OidcClaims = serde_json::from_value(json).unwrap();
        claims.extract_roles("realm_access.roles");
        assert!(claims.roles.is_empty());
    }

    #[test]
    fn extract_scopes_space_delimited() {
        let json = serde_json::json!({
            "sub": "user1",
            "scope": "openid sandbox:read sandbox:write"
        });
        let claims: OidcClaims = serde_json::from_value(json).unwrap();
        let scopes = claims.extract_scopes("scope");
        assert_eq!(scopes, vec!["sandbox:read", "sandbox:write"]);
    }

    #[test]
    fn extract_scopes_json_array() {
        let json = serde_json::json!({
            "sub": "user1",
            "scp": ["sandbox:read", "provider:read"]
        });
        let claims: OidcClaims = serde_json::from_value(json).unwrap();
        let scopes = claims.extract_scopes("scp");
        assert_eq!(scopes, vec!["sandbox:read", "provider:read"]);
    }

    #[test]
    fn extract_scopes_filters_standard_oidc_scopes() {
        let json = serde_json::json!({
            "sub": "user1",
            "scope": "openid profile email sandbox:read offline_access"
        });
        let claims: OidcClaims = serde_json::from_value(json).unwrap();
        let scopes = claims.extract_scopes("scope");
        assert_eq!(scopes, vec!["sandbox:read"]);
    }

    #[test]
    fn extract_scopes_missing_claim() {
        let json = serde_json::json!({ "sub": "user1" });
        let claims: OidcClaims = serde_json::from_value(json).unwrap();
        let scopes = claims.extract_scopes("scope");
        assert!(scopes.is_empty());
    }

    #[test]
    fn extract_scopes_openid_only_yields_empty() {
        let json = serde_json::json!({
            "sub": "user1",
            "scope": "openid"
        });
        let claims: OidcClaims = serde_json::from_value(json).unwrap();
        let scopes = claims.extract_scopes("scope");
        assert!(scopes.is_empty());
    }
}
