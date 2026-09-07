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
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tonic::Status;
use tracing::{debug, error, info, warn};

/// Path prefixes that bypass OIDC validation (gRPC reflection, health probes).
///
/// These are structural bypasses for gRPC infrastructure that doesn't map to a
/// single RPC method. Per-method bypasses (e.g. `Health`) are declared at the
/// handler with `auth_mode: "unauthenticated"` in the proto annotation.
const UNAUTHENTICATED_PREFIXES: &[&str] = &["/grpc.reflection.", "/grpc.health."];

/// Returns `true` if the method needs no authentication at all.
pub fn is_unauthenticated_method(path: &str) -> bool {
    super::method_authz::is_unauthenticated(path)
        || UNAUTHENTICATED_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix))
}

/// How long previously-cached keys stay trusted after a refresh starts
/// returning zero usable keys, expressed as a multiple of the configured
/// TTL. Bounds exposure to keys the issuer may have deliberately revoked,
/// while still tolerating a transient empty or bad JWKS response.
const STALE_KEY_GRACE_MULTIPLIER: u32 = 3;

/// Minimum interval between kid-miss-triggered refreshes. Bounds how much
/// a burst or steady stream of unknown-`kid` lookups can amplify requests
/// against the issuer's JWKS endpoint.
const KID_MISS_REFRESH_COOLDOWN: Duration = Duration::from_secs(1);

/// Cached JWKS key set fetched from the OIDC issuer.
///
/// A `refresh_mutex` ensures that only one refresh runs at a time,
/// preventing a "thundering herd" when the TTL expires or a new `kid`
/// is encountered under concurrent load.
pub struct JwksCache {
    keys: Arc<RwLock<HashMap<String, (DecodingKey, Algorithm)>>>,
    jwks_uri: String,
    ttl: Duration,
    last_refresh: Arc<RwLock<Instant>>,
    /// Timestamp of the last refresh that yielded at least one usable key.
    /// Bounds how long a fully-empty or fully-unusable JWKS response can
    /// keep serving stale cached keys before they're evicted.
    last_nonempty_refresh: Arc<RwLock<Instant>>,
    /// Timestamp of the last refresh triggered by an unknown `kid`, as
    /// opposed to the regular TTL cadence. See `KID_MISS_REFRESH_COOLDOWN`.
    last_kid_miss_refresh: Arc<RwLock<Instant>>,
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
    #[serde(default)]
    x: String,
    #[serde(default)]
    y: String,
    #[serde(default)]
    crv: String,
    #[serde(default)]
    alg: Option<String>,
    #[serde(rename = "use", default)]
    use_: Option<String>,
    #[serde(default)]
    key_ops: Vec<String>,
}

enum SkipReason {
    MissingKid,
    MissingComponents,
    UnsupportedKeyType {
        kty: String,
        crv: Option<String>,
    },
    ParseError(String),
    AlgMismatch {
        declared: String,
        derived: Algorithm,
    },
    UseEnc,
    UseNotSig,
    KeyOpsNotForVerify,
}

/// The RSA signature algorithms `jsonwebtoken` supports. Used to decide
/// whether a JWK's declared `alg` is a legitimate RSA algorithm selection
/// (see the RSA arm of `parse_jwk`) as opposed to an absent, unparseable, or
/// non-RSA value.
fn is_rsa_algorithm(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
    )
}

/// Log why a JWK was excluded from the cache, with the fields relevant to
/// diagnosing that specific `SkipReason`.
fn warn_skip(key: &JwkKey, reason: SkipReason) {
    match reason {
        SkipReason::MissingKid => {
            warn!(kty = %key.kty, crv = %key.crv, "Skipping JWK without kid");
        }
        SkipReason::MissingComponents => {
            warn!(
                kid = ?key.kid,
                kty = %key.kty,
                crv = %key.crv,
                "Skipping JWK with missing key components"
            );
        }
        SkipReason::UnsupportedKeyType { kty, crv } => {
            warn!(kid = ?key.kid, kty = %kty, crv = ?crv, "Skipping unsupported JWK key type");
        }
        SkipReason::ParseError(error) => {
            warn!(kid = ?key.kid, kty = %key.kty, error = %error, "Failed to parse JWK");
        }
        SkipReason::AlgMismatch { declared, derived } => {
            warn!(
                kid = ?key.kid,
                kty = %key.kty,
                declared_alg = %declared,
                derived_alg = ?derived,
                "Skipping JWK with alg mismatch"
            );
        }
        SkipReason::UseEnc => {
            warn!(kid = ?key.kid, kty = %key.kty, "Skipping encryption JWK (use: enc)");
        }
        SkipReason::UseNotSig => {
            warn!(
                kid = ?key.kid,
                kty = %key.kty,
                use_ = ?key.use_,
                "Skipping JWK with use not suitable for verify"
            );
        }
        SkipReason::KeyOpsNotForVerify => {
            warn!(kid = ?key.kid, kty = %key.kty, "Skipping JWK with key_ops not suitable for verify");
        }
    }
}

/// Validate and decode a single JWK, returning its `kid`, decoding key, and
/// pinned algorithm, or the reason it must be excluded from the cache.
fn parse_jwk(key: &JwkKey) -> Result<(String, DecodingKey, Algorithm), SkipReason> {
    // Must run before any early return below, not just before the
    // `DecodingKey::from_*` calls further down: a JWKS response whose keys
    // are all skipped by these checks would otherwise leave the process-wide
    // crypto provider never installed on this path, and a caller reaching
    // its own first `jsonwebtoken` operation without having installed one
    // itself would panic.
    crate::install_jsonwebtoken_crypto_provider();

    // Subsumed by the `use_ != "sig"` check below (`"enc" != "sig"`); kept
    // separate only to produce a more specific log line for the common
    // `use: enc` case.
    if key.use_.as_deref() == Some("enc") {
        return Err(SkipReason::UseEnc);
    }
    if let Some(use_) = key.use_.as_deref().filter(|u| !u.is_empty())
        && use_ != "sig"
    {
        return Err(SkipReason::UseNotSig);
    }

    // The gateway only ever verifies signatures, never creates them, so a
    // key advertising `key_ops` must include "verify" — mirroring the
    // strictness of the `use: "sig"` check above. `["sign"]` alone is
    // semantically incoherent for a public verification key (RFC 7517 §4.3
    // treats "sign" and "verify" as distinct operations).
    if !key.key_ops.is_empty() && !key.key_ops.iter().any(|op| op == "verify") {
        return Err(SkipReason::KeyOpsNotForVerify);
    }

    let kid = key.kid.as_deref().filter(|k| !k.is_empty());
    let Some(kid) = kid else {
        return Err(SkipReason::MissingKid);
    };

    let (decoding_key, algorithm) = match key.kty.as_str() {
        "RSA" => {
            if key.n.is_empty() || key.e.is_empty() {
                return Err(SkipReason::MissingComponents);
            }
            let dk = DecodingKey::from_rsa_components(&key.n, &key.e)
                .map_err(|e| SkipReason::ParseError(e.to_string()))?;
            // Select the algorithm from the JWK's declared `alg` when it
            // names one of the RSA family; default to RS256 otherwise (most
            // issuers, e.g. Microsoft Entra ID, omit `alg` entirely). The
            // mismatch check below still rejects genuinely contradictory
            // declarations (e.g. an RSA key declaring "ES256").
            let algorithm = key
                .alg
                .as_deref()
                .and_then(|declared| Algorithm::from_str(declared).ok())
                .filter(|declared| is_rsa_algorithm(*declared))
                .unwrap_or(Algorithm::RS256);
            (dk, algorithm)
        }
        "EC" => {
            if key.x.is_empty() || key.y.is_empty() || key.crv.is_empty() {
                return Err(SkipReason::MissingComponents);
            }
            let algorithm = match key.crv.as_str() {
                "P-256" => Algorithm::ES256,
                "P-384" => Algorithm::ES384,
                _ => {
                    return Err(SkipReason::UnsupportedKeyType {
                        kty: key.kty.clone(),
                        crv: Some(key.crv.clone()),
                    });
                }
            };
            let dk = DecodingKey::from_ec_components(&key.x, &key.y)
                .map_err(|e| SkipReason::ParseError(e.to_string()))?;
            (dk, algorithm)
        }
        "OKP" => {
            if key.x.is_empty() || key.crv.is_empty() {
                return Err(SkipReason::MissingComponents);
            }
            if key.crv != "Ed25519" {
                return Err(SkipReason::UnsupportedKeyType {
                    kty: key.kty.clone(),
                    crv: Some(key.crv.clone()),
                });
            }
            let dk = DecodingKey::from_ed_components(&key.x)
                .map_err(|e| SkipReason::ParseError(e.to_string()))?;
            (dk, Algorithm::EdDSA)
        }
        other => {
            return Err(SkipReason::UnsupportedKeyType {
                kty: other.to_string(),
                crv: if key.crv.is_empty() {
                    None
                } else {
                    Some(key.crv.clone())
                },
            });
        }
    };

    if let Some(ref declared) = key.alg {
        match Algorithm::from_str(declared) {
            Ok(parsed) if parsed == algorithm => {}
            // Either the declared algorithm genuinely contradicts the
            // derived one, or it's an unrecognized string — in both cases
            // we can't be sure the key is safe to use, so skip it rather
            // than silently accepting our own default.
            _ => {
                return Err(SkipReason::AlgMismatch {
                    declared: declared.clone(),
                    derived: algorithm,
                });
            }
        }
    }

    Ok((kid.to_string(), decoding_key, algorithm))
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
        if config.jwks_ttl_secs == 0 {
            return Err(
                "jwks_ttl_secs must be greater than zero (0 would refresh on every request and \
                 collapse the stale-key grace period to zero)"
                    .to_string(),
            );
        }

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
            // Placeholder value: the grace-period check is only reachable
            // once `self.keys` has been non-empty, at which point this
            // field always holds a freshly-stamped real value instead (see
            // `refresh_keys`), so the value here is never actually read.
            last_nonempty_refresh: Arc::new(RwLock::new(Instant::now())),
            // Backdated beyond the cooldown so the very first kid-miss
            // refresh is never throttled.
            last_kid_miss_refresh: Arc::new(RwLock::new(
                Instant::now()
                    .checked_sub(KID_MISS_REFRESH_COOLDOWN + Duration::from_secs(1))
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
        let mut poisoned_kids = HashSet::new();
        let total = jwk_set.keys.len();

        for key in &jwk_set.keys {
            if let Some(kid) = key.kid.as_ref().filter(|k| !k.is_empty())
                && poisoned_kids.contains(kid)
            {
                continue;
            }

            match parse_jwk(key) {
                Ok((kid, dk, alg)) => {
                    if let Some((_, existing_alg)) = new_keys.get(&kid) {
                        if *existing_alg == alg {
                            warn!(
                                kid = %kid,
                                algorithm = ?alg,
                                "Duplicate JWK kid, keeping first entry"
                            );
                            continue;
                        }
                        let existing_alg = *existing_alg;
                        new_keys.remove(&kid);
                        poisoned_kids.insert(kid.clone());
                        warn!(
                            kid = %kid,
                            existing_alg = ?existing_alg,
                            conflicting_alg = ?alg,
                            "Duplicate JWK kid with conflicting algorithms, poison-pilling kid"
                        );
                        continue;
                    }
                    new_keys.insert(kid, (dk, alg));
                }
                Err(reason) => warn_skip(key, reason),
            }
        }

        if new_keys.is_empty() {
            // A refresh with zero usable keys must not immediately wipe a
            // working cache, since that would turn a degraded issuer into a
            // total outage. Keys stay trusted until a later refresh
            // succeeds or the grace period expires. With no existing keys
            // to fall back to (the first load, or after eviction), the
            // empty set is committed immediately.
            let grace = self.ttl.saturating_mul(STALE_KEY_GRACE_MULTIPLIER);
            if self.keys.read().await.is_empty() {
                error!(
                    total,
                    "JWKS has zero usable signing keys and no previous keys to fall back to"
                );
                *self.keys.write().await = new_keys;
            } else if self.last_nonempty_refresh.read().await.elapsed() > grace {
                error!(
                    total,
                    grace_secs = grace.as_secs(),
                    "JWKS has had zero usable signing keys past the grace period; evicting cached keys"
                );
                *self.keys.write().await = new_keys;
            } else {
                error!(
                    total,
                    "JWKS refresh loaded zero usable signing keys; keeping previous key set within grace period"
                );
            }
        } else {
            info!(count = new_keys.len(), "JWKS keys loaded");
            *self.keys.write().await = new_keys;
            *self.last_nonempty_refresh.write().await = Instant::now();
        }
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

    /// Refresh keys on a kid-miss lookup, coalescing concurrent callers and
    /// throttling how often such refreshes may hit the issuer.
    ///
    /// Without a cooldown, a caller presenting an unknown or fast-rotating
    /// `kid` could force a fresh HTTP fetch on every single request. Only
    /// the first kid-miss refresh within `KID_MISS_REFRESH_COOLDOWN` does
    /// real work; the rest reuse its result.
    async fn refresh_keys_coalesced(&self) -> Result<(), String> {
        let _guard = self.refresh_mutex.lock().await;
        let last = *self.last_kid_miss_refresh.read().await;
        if last.elapsed() < KID_MISS_REFRESH_COOLDOWN {
            return Ok(());
        }
        *self.last_kid_miss_refresh.write().await = Instant::now();
        self.refresh_keys().await
    }

    /// Validate a JWT and return an `Identity`.
    ///
    /// This is the authentication step — it verifies the caller's identity
    /// but does not check authorization (that's `authz::AuthzPolicy::check`).
    pub async fn validate_token(&self, token: &str) -> Result<Identity, Status> {
        crate::install_jsonwebtoken_crypto_provider();

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

        // Refresh once on kid miss.
        let mut keys_guard = self.keys.read().await;
        if !keys_guard.contains_key(&kid) {
            drop(keys_guard);
            self.refresh_keys_coalesced().await.map_err(|e| {
                warn!(error = %e, "JWKS refresh on kid miss failed");
                Status::internal("OIDC key refresh failed")
            })?;
            keys_guard = self.keys.read().await;
        }

        let (decoding_key, cached_algorithm) = keys_guard
            .get(&kid)
            .map(|(dk, alg)| (dk.clone(), *alg))
            .ok_or_else(|| {
                debug!(kid = %kid, "JWT kid not found in JWKS");
                Status::unauthenticated("invalid token: unknown signing key")
            })?;
        drop(keys_guard);

        if header.alg != cached_algorithm {
            debug!(
                header_alg = ?header.alg,
                expected = ?cached_algorithm,
                "JWT algorithm mismatch for cached signing key"
            );
            return Err(Status::unauthenticated("invalid token"));
        }

        let mut validation = Validation::new(cached_algorithm);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);

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

    // -----------------------------------------------------------------------
    // RS256 verification through the real JWKS path
    //
    // The tests above only cover claim extraction from an already-trusted
    // payload. These sign real RS256 tokens and push them through
    // `JwksCache::new` + `validate_token`, so the JWKS `n`/`e` decoding and the
    // RSA signature check are exercised against whichever crypto backend
    // `jsonwebtoken` is built with — a backend swap is otherwise invisible to
    // the test suite.
    // -----------------------------------------------------------------------

    const TEST_KID: &str = "test-signing-key";
    const TEST_AUDIENCE: &str = "openshell-cli";

    /// One RSA key per test binary. Key generation dominates the runtime of
    /// these tests and the key carries no meaning beyond being valid.
    static TEST_RSA_KEY: std::sync::LazyLock<TestRsaKey> =
        std::sync::LazyLock::new(TestRsaKey::generate);

    struct TestRsaKey {
        private_pem: String,
        modulus_b64: String,
        exponent_b64: String,
    }

    impl TestRsaKey {
        fn generate() -> Self {
            use base64::Engine as _;
            use rsa::pkcs1::EncodeRsaPrivateKey as _;
            use rsa::traits::PublicKeyParts as _;

            let private = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)
                .expect("generate RSA test key");
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            Self {
                private_pem: private
                    .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                    .expect("encode RSA private key as PEM")
                    .to_string(),
                modulus_b64: b64.encode(private.n().to_bytes_be()),
                exponent_b64: b64.encode(private.e().to_bytes_be()),
            }
        }
    }

    fn now_secs() -> i64 {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is after the unix epoch")
                .as_secs(),
        )
        .expect("current time fits in i64")
    }

    /// Sign `claims` with the test key, tagging the header with `kid`.
    fn mint_rs256(claims: &serde_json::Value, kid: &str) -> String {
        crate::install_jsonwebtoken_crypto_provider();

        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_owned());
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_RSA_KEY.private_pem.as_bytes())
            .expect("load RSA signing key");
        jsonwebtoken::encode(&header, claims, &key).expect("sign RS256 token")
    }

    fn claims_for(issuer: &str, audience: &str, exp: i64) -> serde_json::Value {
        serde_json::json!({
            "sub": "user-42",
            "preferred_username": "ada",
            "iss": issuer,
            "aud": audience,
            "exp": exp,
            "scope": "openid profile sandbox:write",
            "realm_access": { "roles": ["openshell-user"] },
        })
    }

    /// Serve an OIDC discovery document and a JWKS carrying the test key, then
    /// build a cache against them the same way production does.
    async fn cache_with_mock_issuer(server: &wiremock::MockServer) -> JwksCache {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let issuer = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": issuer,
                "jwks_uri": format!("{issuer}/jwks"),
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [{
                    "kid": TEST_KID,
                    "kty": "RSA",
                    "n": TEST_RSA_KEY.modulus_b64,
                    "e": TEST_RSA_KEY.exponent_b64,
                }],
            })))
            .mount(server)
            .await;

        JwksCache::new(&OidcConfig {
            issuer,
            audience: TEST_AUDIENCE.to_owned(),
            jwks_ttl_secs: 3600,
            roles_claim: "realm_access.roles".to_owned(),
            admin_role: "openshell-admin".to_owned(),
            user_role: "openshell-user".to_owned(),
            scopes_claim: "scope".to_owned(),
        })
        .await
        .expect("cache should build from the mock issuer")
    }

    #[tokio::test]
    async fn rs256_token_signed_by_jwks_key_is_accepted() {
        let server = wiremock::MockServer::start().await;
        let cache = cache_with_mock_issuer(&server).await;

        let token = mint_rs256(
            &claims_for(&server.uri(), TEST_AUDIENCE, now_secs() + 3600),
            TEST_KID,
        );
        let identity = cache
            .validate_token(&token)
            .await
            .expect("a correctly signed token must be accepted");

        assert_eq!(identity.subject, "user-42");
        assert_eq!(identity.display_name.as_deref(), Some("ada"));
        assert_eq!(identity.roles, vec!["openshell-user".to_owned()]);
        assert_eq!(identity.scopes, vec!["sandbox:write".to_owned()]);
        assert_eq!(identity.provider, IdentityProvider::Oidc);
    }

    #[tokio::test]
    async fn rs256_token_with_tampered_payload_is_rejected() {
        let server = wiremock::MockServer::start().await;
        let cache = cache_with_mock_issuer(&server).await;

        let exp = now_secs() + 3600;
        let token = mint_rs256(&claims_for(&server.uri(), TEST_AUDIENCE, exp), TEST_KID);

        // Keep the header and signature but swap in a payload that escalates
        // the subject: only the RSA check stands between this and an identity.
        let segments: Vec<&str> = token.split('.').collect();
        assert_eq!(segments.len(), 3, "a JWT has three segments");
        let mut forged_claims = claims_for(&server.uri(), TEST_AUDIENCE, exp);
        forged_claims["sub"] = serde_json::json!("root");
        let forged_payload = {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&forged_claims).expect("serialize forged claims"))
        };
        let forged = format!("{}.{forged_payload}.{}", segments[0], segments[2]);

        cache
            .validate_token(&forged)
            .await
            .expect_err("a swapped payload must fail the signature check");
    }

    #[tokio::test]
    async fn rs256_token_signed_by_unrelated_key_is_rejected() {
        let server = wiremock::MockServer::start().await;
        let cache = cache_with_mock_issuer(&server).await;

        let other = TestRsaKey::generate();
        crate::install_jsonwebtoken_crypto_provider();
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.to_owned());
        let token = jsonwebtoken::encode(
            &header,
            &claims_for(&server.uri(), TEST_AUDIENCE, now_secs() + 3600),
            &jsonwebtoken::EncodingKey::from_rsa_pem(other.private_pem.as_bytes())
                .expect("load unrelated signing key"),
        )
        .expect("sign with unrelated key");

        cache
            .validate_token(&token)
            .await
            .expect_err("a token signed by a key outside the JWKS must be rejected");
    }

    #[tokio::test]
    async fn rs256_expired_token_is_rejected() {
        let server = wiremock::MockServer::start().await;
        let cache = cache_with_mock_issuer(&server).await;

        // Beyond the 60s default leeway.
        let token = mint_rs256(
            &claims_for(&server.uri(), TEST_AUDIENCE, now_secs() - 3600),
            TEST_KID,
        );

        cache
            .validate_token(&token)
            .await
            .expect_err("an expired token must be rejected");
    }

    #[tokio::test]
    async fn rs256_token_from_other_issuer_is_rejected() {
        let server = wiremock::MockServer::start().await;
        let cache = cache_with_mock_issuer(&server).await;

        let token = mint_rs256(
            &claims_for("https://evil.example.com", TEST_AUDIENCE, now_secs() + 3600),
            TEST_KID,
        );

        cache
            .validate_token(&token)
            .await
            .expect_err("a token from another issuer must be rejected");
    }

    #[tokio::test]
    async fn rs256_token_for_other_audience_is_rejected() {
        let server = wiremock::MockServer::start().await;
        let cache = cache_with_mock_issuer(&server).await;

        let token = mint_rs256(
            &claims_for(&server.uri(), "some-other-client", now_secs() + 3600),
            TEST_KID,
        );

        cache
            .validate_token(&token)
            .await
            .expect_err("a token minted for another audience must be rejected");
    }

    #[tokio::test]
    async fn rs256_token_with_unknown_kid_is_rejected() {
        let server = wiremock::MockServer::start().await;
        let cache = cache_with_mock_issuer(&server).await;

        let token = mint_rs256(
            &claims_for(&server.uri(), TEST_AUDIENCE, now_secs() + 3600),
            "rotated-away-key",
        );

        cache
            .validate_token(&token)
            .await
            .expect_err("a token naming a kid absent from the JWKS must be rejected");
    }

    mod jwks_validation {
        use super::*;
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use jsonwebtoken::{EncodingKey, Header, encode};
        use openshell_core::OidcConfig;
        use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519};
        use rsa::traits::PublicKeyParts;
        use std::time::{SystemTime, UNIX_EPOCH};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        struct TestSigningKey {
            kid: String,
            jwk: serde_json::Value,
            encoding_key: EncodingKey,
            algorithm: Algorithm,
        }

        fn now_secs() -> i64 {
            i64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
            .unwrap()
        }

        fn ec_coords_from_spki(spki: &[u8], coord_len: usize) -> (String, String) {
            // The uncompressed EC point (a 0x04 tag byte followed by X and Y)
            // is always the tail of an SPKI DER encoding, so slice it
            // directly at the known offset instead of scanning for the tag
            // byte (which could false-match a coordinate byte at the wrong
            // offset).
            let point_len = 1 + 2 * coord_len;
            let point = &spki[spki.len() - point_len..];
            assert_eq!(point[0], 0x04, "expected uncompressed EC point marker");
            let x = URL_SAFE_NO_PAD.encode(&point[1..=coord_len]);
            let y = URL_SAFE_NO_PAD.encode(&point[1 + coord_len..point_len]);
            (x, y)
        }

        // Precomputed 2048-bit RSA keys (PKCS8 PEM). Generating a fresh RSA
        // key per test call site is the dominant cost of this test module
        // (~7s across ~15 call sites); two static fixtures are deterministic
        // and effectively free to parse. Two distinct keys are kept because
        // a couple of tests (key rotation, duplicate-kid poisoning) need
        // genuinely different key material, not just different `kid`s.
        const RSA_TEST_KEY_PEM_PRIMARY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDFDsXUQjvihWzC\nA8UfdQ+QiQrAt8RBEMXXxiYHTn+EwDl4umH+OFURRGIlGgZ8cFrewKDotaJylEal\nnRq+urYCS3JjoerIS1lc9XZFp5ri7XB+5fB0bZQPNX4KIJ7MlbP2XG0zqvawww1A\nZQ4w9Ni8X+pptB7QlGWldALlNiOPvlVNaRFRzvY4wc2JqwlWj0ZD/5fqVaO/7oa6\nyyKuZzXQ3ps0PMbt7sz9FcyMEgkQCm0eNIOancjeQKhFNFh5VN71PhyfnhN9Xkwn\n0vaV24SRrOurLZAH4vhum0aDQLFC0yDVCKEfwW1Wl7Cs0ns6kS/IbG+RPBGH4Snr\nRoI9OaiLAgMBAAECggEAWOS9IW9vjFQcJ7mDpxkrmEv56c38Xk2ushPU+97Rb5U3\nV9rccc3/sfZjP9Fps6ELnQjQjanCSmXRKMyiT//yMz7Nr1xPiWNUQLcKT4m4OT5b\nTSN1QVBdRi8fWHo2qJuvvycarAAnoL2csLvllvgc/X1XRa/XZshKwkR/Od8eU60C\nMHuCmks+NCpUL/lMIZecAbWFyQDYJqwB/lnJdEO5oDaIcGclAOQJzj3+xCfFnLLh\nYt/7tCxOboIeyP/fLh5OyqC6NppRUSwtfWNQNwgQWw7WWVd5TW9d2wjycgQKrm6P\n1tnbs8yRJ2h8jemJR65OukW1QOfdN7QFWBAoD8BEwQKBgQDiIXhmre2qw/d4aOZV\nqDzjlHFCAG9XCAWF8pio2Uy0SUXAI4CcK6d+Njm/U7CaKNUfbNyip0iv3YoADwAv\nDlI6kqo1DOGXYgo2z0zfmxWTixQsCvZHtLrSk4Z1sxiSlFXfbTsR3vBd7qLXgKQ/\nWR9b2chPYlGew8DBRTNa0aQ/KQKBgQDfFjVKMibXSi69x704LQ9QoO0SR+pgdyw6\nJ5auf0N3ACqIOTqdD001Dn1zNO35RdTbV3vYDCq24yED5xro+fpSSbZ2+ZpMjhEk\nZjLGSlTSwsjzXx4l41f8wX7Br5OgTjA9B23NNDTf/RaD+ui5mfVA3BJyoXMkHCC2\nIV5ZZt7EkwKBgHu8Xtqor5UymDaOCAO1BGRvdK3t+P7Bh+wsvDYgeaVpNr6VbqmG\nBae9WkoELG2ejEge1Hg4W0DIU9wGWU5mYr5kRLi0rLieUAJ/2ou8m8jZYJddBDhm\nf5f8W6YJ8xc6DectKRZ1TEfJ7ddIMBft14f2GnK91PWwHchj6l72ug5JAoGAd1Hc\njOPILIyL9YvY5CwNrfV097spXBFBwZUdHhYJkqOvHA9oD0t44zDt3mnoAtTb5bmk\nDslrK0jOhtTcatIRlmPAyV/1rI6sEojrDW4CcnwmmS095cv0asdfsd7kGfDYEjxf\n+Uq8ITWwDkVspqD3MYrD/zXlbOHyiRfN7Al+iysCgYEA4Q8+8d5UwF1jzUQFmSEt\nMjlGyycrLpzadgWTG9EjQN0FuSJFK8nyEyqcfzFm+rSsReZ37JwPTCQ/Ck4g4IXY\n3VvHY+6wj0NYwRwjKCZeqN8IAANsj5Xsh5pz4ETSwnwd0bUlGP6Bcqoc5edLnB85\nEMcbZoGCXLCoi/qf8T334k4=\n-----END PRIVATE KEY-----\n";
        const RSA_TEST_KEY_PEM_SECONDARY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCnRp9lR8xbtsXp\nCTTBkyAkhYji4Hp5FnAXxZF5DGfyw3I9ol0J8Hoe9RSBkQVIKXQe5Gfi+L7o9G6v\nVcucrzILxSJ4dCPKgNaj53G4zwkySpTsVO0XjxKanozQqdRbkAGaz9AsuzfGWB9m\n1AiC0JxKmOo8Ifxi4oj0hIBV4Mp3TCfHX8vFCIn5AZ/31Y29vT1mPzoCxwGw4Yxd\nh4kYQgIIWoAekebWeJ8iowgOvbV8rmT1geMWu7JRdpcStN9PWVZKUiZplILz9ci2\n+owm8UyxdQvBt6csEJFNdbAGUR1/Ywv/unoTQfrPvwQ4of5viywRra+iCMM0SrSA\nUO6Fu5a/AgMBAAECggEATDSTzD+73XJ0Ujhz9NYSeCDvnjBXC1AKDAJhRiy9NG8O\n3f5YdX09HVpYl7haGChuct5qZ5Ab5SPqQu2Kn5x+57bM/+QlJA2y+yOm/uMvFN6+\nXrZH9woilxcxHqSoDniaCo2vEJnQDIe78owZPoNMGH32hCOVh/UdIIw2rSkGA/eM\nYHHQXxx3sbi0AxCnlDzkgST15igP1baAZKUM2vIHVdg2Ccx2CnUiLM5BgvlWd98f\nS6GmTMk4WUWvmYYFZx+5GEhMmgz64xnyjIe+tRT1iP4p5NaCZc2CWLQdycEaEeKp\nmWFjxe7t/eXLUE3h1BBf/qZvcekpYbDGjw8JSaa00QKBgQDcctFl9P4npQUkoq0M\nDWeKSITsSwOVNKBLrQv5C4inz7QGPglGgIF8G6O7mvQ9ZulzDsvWfzxS0JE6ADkU\nHAkMY4/6Rfm7XKk8Yg1QoxCqsoI85nVQOhsmvVmIwXBDdINMY+g9jez9psiiiQiC\nh0nt3n9LPKu/YCzve50YTvR/bwKBgQDCQJSmZTFVsTC29e0CCgS1Zp9z4IAcZgth\nEJsaenE/ksQriH8gl3I4bwfI1p/xquBeWO40A016T67laCUBPTCwuZTGyqUiOtAw\nV5CoUiCvu38lNW6dk/RgouR0WoIQVvKq+5NKcnQtwbDHCt4U+hnB8c6EbT8dG2XU\noAamLcq1sQKBgADYI7srPAn01Nc2FEmWh439Bx1MkD/zCqYfjIswox5ZakwX0rtF\nZLmP9YmTZ1oQ2dYJ+Xfh1t5OVDAPrihIjzRP8U45FGLGUROdIIXtifPNaThIfayH\n/HCiiwQ+EWsAuDwDqfEKaRzzlZMhyTmOwRa7ImusWNAL00A7jfd43fDbAoGAa5u8\n/USXhOIIm4I2zmdgXmFAOcAHGDRLX3UEhzGHJPGX7InL6vEanDqdtFt49TZ03q8j\nHfsqY3Ra7ci4nywXmf7kdQ9zVTgBdpY7k5MTemZCtAkagv6gZRw3tGEjJgwUmDWP\nTbGDvIlM9aaGilZWCIN8pQ2j5er0iUoxBMPfRLECgYBu8/kcgM/sEeYh5vN5QqAh\n3/ezl+xboYDGGY1SLRwAzEsyIm9lyvvrFc+zGLpHqIP7jtrnu7CTqjxX0FQ2ECnd\nLIqNx0WMFZPq+GAD0hyUpYcqGFpHLGZGIOm8YhQUYvUL6ZWU4UQaND6gEq4ZYk9g\nk4dfOCu/AeloLlC3LUC9fw==\n-----END PRIVATE KEY-----\n";

        enum RsaFixture {
            Primary,
            Secondary,
        }

        /// Build an RSA `TestSigningKey` from a precomputed fixture, with an
        /// optional declared `alg` and an explicit signing algorithm — used
        /// by tests that exercise algorithm selection from the JWK's `alg`
        /// field (RS256 default vs. a declared RS384/RS512/etc).
        fn rsa_test_key_from(
            kid: &str,
            fixture: RsaFixture,
            declared_alg: Option<&str>,
            sign_algorithm: Algorithm,
        ) -> TestSigningKey {
            use rsa::pkcs8::DecodePrivateKey;

            let pem = match fixture {
                RsaFixture::Primary => RSA_TEST_KEY_PEM_PRIMARY,
                RsaFixture::Secondary => RSA_TEST_KEY_PEM_SECONDARY,
            };
            let private_key =
                rsa::RsaPrivateKey::from_pkcs8_pem(pem).expect("valid static test RSA key");
            let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
            let public_key = private_key.to_public_key();
            let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
            let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
            let mut jwk = serde_json::json!({
                "kty": "RSA",
                "kid": kid,
                "n": n,
                "e": e,
                "use": "sig",
            });
            if let Some(alg) = declared_alg {
                jwk["alg"] = serde_json::json!(alg);
            }
            TestSigningKey {
                kid: kid.to_string(),
                jwk,
                encoding_key,
                algorithm: sign_algorithm,
            }
        }

        fn rsa_test_key(kid: &str) -> TestSigningKey {
            rsa_test_key_from(kid, RsaFixture::Primary, None, Algorithm::RS256)
        }

        /// Distinct key material from `rsa_test_key`, for tests that need
        /// two genuinely different RSA keys (e.g. key rotation, duplicate
        /// `kid` poisoning) rather than just different `kid` labels.
        fn rsa_test_key_secondary(kid: &str) -> TestSigningKey {
            rsa_test_key_from(kid, RsaFixture::Secondary, None, Algorithm::RS256)
        }

        fn ec_test_key(kid: &str, curve: &str) -> TestSigningKey {
            let (key_pair, algorithm, coord_len) = match curve {
                "P-256" => (
                    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap(),
                    Algorithm::ES256,
                    32,
                ),
                "P-384" => (
                    KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap(),
                    Algorithm::ES384,
                    48,
                ),
                other => panic!("unsupported curve {other}"),
            };
            let encoding_key =
                EncodingKey::from_ec_pem(key_pair.serialize_pem().as_bytes()).unwrap();
            let (x, y) = ec_coords_from_spki(&key_pair.public_key_der(), coord_len);
            let jwk = serde_json::json!({
                "kty": "EC",
                "kid": kid,
                "crv": curve,
                "x": x,
                "y": y,
                "use": "sig",
            });
            TestSigningKey {
                kid: kid.to_string(),
                jwk,
                encoding_key,
                algorithm,
            }
        }

        fn ed25519_test_key(kid: &str) -> TestSigningKey {
            let key_pair = KeyPair::generate_for(&PKCS_ED25519).unwrap();
            let encoding_key =
                EncodingKey::from_ed_pem(key_pair.serialize_pem().as_bytes()).unwrap();
            let spki = key_pair.public_key_der();
            let x = URL_SAFE_NO_PAD.encode(&spki[spki.len() - 32..]);
            let jwk = serde_json::json!({
                "kty": "OKP",
                "kid": kid,
                "crv": "Ed25519",
                "x": x,
                "use": "sig",
            });
            TestSigningKey {
                kid: kid.to_string(),
                jwk,
                encoding_key,
                algorithm: Algorithm::EdDSA,
            }
        }

        fn token_with_header_alg(token: &str, algorithm: Algorithm) -> String {
            let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
            assert_eq!(parts.len(), 3);
            let header_bytes = URL_SAFE_NO_PAD.decode(&parts[0]).unwrap();
            let mut header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
            header["alg"] = serde_json::json!(match algorithm {
                Algorithm::HS256 => "HS256",
                other => panic!("unsupported test algorithm {other:?}"),
            });
            parts[0] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
            parts.join(".")
        }

        fn sign_token(key: &TestSigningKey, issuer: &str, audience: &str, sub: &str) -> String {
            let mut header = Header::new(key.algorithm);
            header.kid = Some(key.kid.clone());
            let claims = serde_json::json!({
                "sub": sub,
                "iss": issuer,
                "aud": audience,
                "exp": now_secs() + 3600,
            });
            encode(&header, &claims, &key.encoding_key).unwrap()
        }

        fn test_oidc_config(issuer: &str) -> OidcConfig {
            OidcConfig {
                issuer: issuer.to_string(),
                audience: "test-audience".to_string(),
                jwks_ttl_secs: 3600,
                roles_claim: "roles".to_string(),
                admin_role: "admin".to_string(),
                user_role: "user".to_string(),
                scopes_claim: String::new(),
            }
        }

        async fn mount_oidc(server: &MockServer, jwks: serde_json::Value) -> (String, OidcConfig) {
            let issuer = format!("{}/issuer", server.uri());
            let jwks_uri = format!("{issuer}/jwks");
            Mock::given(method("GET"))
                .and(path("/issuer/.well-known/openid-configuration"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "issuer": issuer,
                    "jwks_uri": jwks_uri,
                })))
                .mount(server)
                .await;
            Mock::given(method("GET"))
                .and(path("/issuer/jwks"))
                .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
                .mount(server)
                .await;
            (issuer.clone(), test_oidc_config(&issuer))
        }

        async fn cache_from_jwks(jwks: serde_json::Value) -> (JwksCache, String, OidcConfig) {
            let server = MockServer::start().await;
            let (issuer, config) = mount_oidc(&server, jwks).await;
            let cache = JwksCache::new(&config).await.unwrap();
            (cache, issuer, config)
        }

        #[tokio::test]
        async fn validate_rsa_es256_es384_eddsa_tokens() {
            let rsa = rsa_test_key("rsa-key");
            let es256 = ec_test_key("es256-key", "P-256");
            let es384 = ec_test_key("es384-key", "P-384");
            let eddsa = ed25519_test_key("eddsa-key");
            let jwks = serde_json::json!({
                "keys": [rsa.jwk, es256.jwk, es384.jwk, eddsa.jwk]
            });
            let (cache, issuer, config) = cache_from_jwks(jwks).await;

            for (name, key) in [
                ("rsa", &rsa),
                ("es256", &es256),
                ("es384", &es384),
                ("eddsa", &eddsa),
            ] {
                let token = sign_token(key, &issuer, &config.audience, "user-1");
                let result = cache.validate_token(&token).await;
                assert!(result.is_ok(), "validation failed for {name}: {result:?}");
                assert_eq!(result.unwrap().subject, "user-1");
            }
        }

        #[tokio::test]
        async fn unsupported_curve_is_skipped() {
            let signing = rsa_test_key("good");
            let jwks = serde_json::json!({
                "keys": [
                    { "kty": "EC", "kid": "p521", "crv": "P-521", "x": "abc", "y": "def" },
                    signing.jwk,
                ]
            });
            let (cache, issuer, config) = cache_from_jwks(jwks).await;
            let token = sign_token(&signing, &issuer, &config.audience, "user-1");
            assert!(cache.validate_token(&token).await.is_ok());
        }

        #[tokio::test]
        async fn kid_miss_triggers_refresh() {
            let initial = rsa_test_key("initial");
            let rotated = rsa_test_key_secondary("rotated");
            let server = MockServer::start().await;
            let issuer = format!("{}/issuer", server.uri());
            let jwks_uri = format!("{issuer}/jwks");
            Mock::given(method("GET"))
                .and(path("/issuer/.well-known/openid-configuration"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "issuer": issuer,
                    "jwks_uri": jwks_uri,
                })))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/issuer/jwks"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "keys": [initial.jwk]
                })))
                .up_to_n_times(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/issuer/jwks"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "keys": [rotated.jwk]
                })))
                .mount(&server)
                .await;

            let config = test_oidc_config(&issuer);
            let cache = JwksCache::new(&config).await.unwrap();
            let initial_token = sign_token(&initial, &issuer, &config.audience, "user-initial");
            assert!(cache.validate_token(&initial_token).await.is_ok());

            let rotated_token = sign_token(&rotated, &issuer, &config.audience, "user-rotated");
            let identity = cache.validate_token(&rotated_token).await.unwrap();
            assert_eq!(identity.subject, "user-rotated");
        }

        /// Shared setup for the "a refresh yields no usable keys" family of
        /// regression tests: an initially-working cache, then a refresh
        /// (triggered by an unknown `kid`) whose response is `bad_jwks`.
        /// Asserts the previously cached key remains usable afterward.
        async fn assert_refresh_preserves_cache(bad_jwks: serde_json::Value) {
            let good = rsa_test_key("good");
            let server = MockServer::start().await;
            let issuer = format!("{}/issuer", server.uri());
            let jwks_uri = format!("{issuer}/jwks");
            Mock::given(method("GET"))
                .and(path("/issuer/.well-known/openid-configuration"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "issuer": issuer,
                    "jwks_uri": jwks_uri,
                })))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/issuer/jwks"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "keys": [good.jwk]
                })))
                .up_to_n_times(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/issuer/jwks"))
                .respond_with(ResponseTemplate::new(200).set_body_json(bad_jwks))
                .mount(&server)
                .await;

            let config = test_oidc_config(&issuer);
            let cache = JwksCache::new(&config).await.unwrap();
            let token = sign_token(&good, &issuer, &config.audience, "user-1");
            assert!(cache.validate_token(&token).await.is_ok());

            // An unknown kid triggers an unconditional refresh against the
            // bad response, so this specific lookup still fails, but the
            // previously cached key must remain usable afterward: the bad
            // refresh must not have wiped it.
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some("unknown".to_string());
            let claims = serde_json::json!({
                "sub": "user-2",
                "iss": issuer,
                "aud": config.audience,
                "exp": now_secs() + 3600,
            });
            let unknown_kid_token = encode(&header, &claims, &good.encoding_key).unwrap();
            let err = cache.validate_token(&unknown_kid_token).await.unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unauthenticated);

            assert!(cache.validate_token(&token).await.is_ok());
        }

        #[tokio::test]
        async fn refresh_keeps_previous_keys_when_new_jwks_fully_unusable() {
            // An issuer-side metadata change (e.g. every key switches to
            // `use: "enc"`) must not wipe a previously-working key cache —
            // otherwise a single bad JWKS response turns "working" into
            // "every OIDC request rejected".
            assert_refresh_preserves_cache(serde_json::json!({
                "keys": [{ "kty": "RSA", "kid": "good", "n": "abc", "e": "AQAB", "use": "enc" }]
            }))
            .await;
        }

        #[tokio::test]
        async fn refresh_keeps_previous_keys_when_new_jwks_response_empty() {
            // A literally empty JWKS response (`total == 0`, as opposed to
            // keys present but all filtered out) must be just as harmless
            // to an existing cache as the fully-unusable case above.
            assert_refresh_preserves_cache(serde_json::json!({ "keys": [] })).await;
        }

        #[tokio::test]
        async fn stale_keys_evicted_after_grace_period() {
            // A JWKS that goes empty and stays empty must eventually stop
            // being trusted; otherwise a key the issuer revoked could
            // remain valid indefinitely behind a permanently broken JWKS
            // endpoint.
            let good = rsa_test_key("good");
            let server = MockServer::start().await;
            let issuer = format!("{}/issuer", server.uri());
            let jwks_uri = format!("{issuer}/jwks");
            Mock::given(method("GET"))
                .and(path("/issuer/.well-known/openid-configuration"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "issuer": issuer,
                    "jwks_uri": jwks_uri,
                })))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/issuer/jwks"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "keys": [good.jwk]
                })))
                .up_to_n_times(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/issuer/jwks"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({ "keys": [] })),
                )
                .mount(&server)
                .await;

            let mut config = test_oidc_config(&issuer);
            config.jwks_ttl_secs = 1; // 1s TTL -> 3s grace period.
            let cache = JwksCache::new(&config).await.unwrap();
            let token = sign_token(&good, &issuer, &config.audience, "user-1");
            assert!(cache.validate_token(&token).await.is_ok());

            // Past the TTL but within the grace period: a scheduled refresh
            // sees the now-empty JWKS, but the cached key stays trusted.
            tokio::time::sleep(Duration::from_millis(1200)).await;
            assert!(cache.validate_token(&token).await.is_ok());

            // Past the grace period with the JWKS still empty: the stale
            // key must finally be evicted.
            tokio::time::sleep(Duration::from_millis(2500)).await;
            let err = cache.validate_token(&token).await.unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unauthenticated);
        }

        #[tokio::test]
        async fn zero_ttl_rejected_at_construction() {
            // A `jwks_ttl_secs` of 0 would refresh on every request and
            // collapse the stale-key grace period to zero, so it's rejected
            // outright rather than silently tolerated. This is consistent
            // with how `AuthzPolicy::validate` rejects OIDC RBAC
            // misconfiguration before the server starts, instead of
            // working around it later. The check runs before any network
            // I/O, so no mock server is needed here.
            let mut config = test_oidc_config("http://unused.invalid");
            config.jwks_ttl_secs = 0;
            let err = JwksCache::new(&config).await.unwrap_err();
            assert!(
                err.contains("jwks_ttl_secs"),
                "error should name the offending field: {err}"
            );
        }

        #[tokio::test]
        async fn kid_miss_refresh_throttled_within_cooldown() {
            // Repeated lookups for an unknown kid within the cooldown
            // window must not each trigger a fresh fetch. Otherwise, a
            // burst (or steady stream) of unknown-kid requests could
            // amplify load on the issuer's JWKS endpoint without bound.
            let good = rsa_test_key("good");
            let server = MockServer::start().await;
            let issuer = format!("{}/issuer", server.uri());
            let jwks_uri = format!("{issuer}/jwks");
            Mock::given(method("GET"))
                .and(path("/issuer/.well-known/openid-configuration"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "issuer": issuer,
                    "jwks_uri": jwks_uri,
                })))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/issuer/jwks"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "keys": [good.jwk]
                })))
                .mount(&server)
                .await;

            let config = test_oidc_config(&issuer);
            let cache = JwksCache::new(&config).await.unwrap();

            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some("unknown".to_string());
            let claims = serde_json::json!({
                "sub": "user-2",
                "iss": issuer,
                "aud": config.audience,
                "exp": now_secs() + 3600,
            });
            let unknown_kid_token = encode(&header, &claims, &good.encoding_key).unwrap();

            for _ in 0..5 {
                let err = cache.validate_token(&unknown_kid_token).await.unwrap_err();
                assert_eq!(err.code(), tonic::Code::Unauthenticated);
            }

            let requests = server.received_requests().await.unwrap();
            let jwks_hits = requests
                .iter()
                .filter(|r| r.url.path() == "/issuer/jwks")
                .count();
            // One fetch for the initial load, one more for the first
            // kid-miss lookup; the remaining four must be throttled.
            assert_eq!(jwks_hits, 2);
        }

        #[tokio::test]
        async fn header_alg_mismatch_rejected() {
            let ec = ec_test_key("ec", "P-256");
            let jwks = serde_json::json!({ "keys": [ec.jwk] });
            let (cache, issuer, config) = cache_from_jwks(jwks).await;
            let token = sign_token(&ec, &issuer, &config.audience, "user-1");
            let forged = token_with_header_alg(&token, Algorithm::HS256);
            let err = cache.validate_token(&forged).await.unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unauthenticated);
        }

        #[tokio::test]
        async fn missing_sub_claim_rejected() {
            let key = rsa_test_key("rsa");
            let jwks = serde_json::json!({ "keys": [key.jwk] });
            let (cache, issuer, config) = cache_from_jwks(jwks).await;
            let mut header = Header::new(key.algorithm);
            header.kid = Some(key.kid.clone());
            let claims = serde_json::json!({
                "iss": issuer,
                "aud": config.audience,
                "exp": now_secs() + 3600,
            });
            let token = encode(&header, &claims, &key.encoding_key).unwrap();
            let err = cache.validate_token(&token).await.unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unauthenticated);
        }

        #[tokio::test]
        async fn jwk_alg_mismatch_skipped() {
            let signing = rsa_test_key("rsa");
            let mut bad = signing.jwk.clone();
            bad["alg"] = serde_json::json!("ES256");
            let jwks = serde_json::json!({ "keys": [bad] });
            let (cache, issuer, config) = cache_from_jwks(jwks).await;
            let token = sign_token(&signing, &issuer, &config.audience, "user-1");
            let err = cache.validate_token(&token).await.unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unauthenticated);
        }

        #[tokio::test]
        async fn rsa_declared_alg_rs512_selected_and_pinned() {
            // An RSA JWK declaring "alg": "RS512" is validated as RS512, not
            // vetoed against a hardcoded RS256 default that would silently
            // discard the declared algorithm.
            let key = rsa_test_key_from(
                "rsa-rs512",
                RsaFixture::Primary,
                Some("RS512"),
                Algorithm::RS512,
            );
            let jwks = serde_json::json!({ "keys": [key.jwk.clone()] });
            let (cache, issuer, config) = cache_from_jwks(jwks).await;

            let token = sign_token(&key, &issuer, &config.audience, "user-1");
            let result = cache.validate_token(&token).await;
            assert!(result.is_ok(), "RS512 token should validate: {result:?}");

            // The cached algorithm is pinned to RS512, not re-derived from
            // the header — a token for the same kid claiming RS256 must
            // still be rejected.
            let mut rs256_variant = key;
            rs256_variant.algorithm = Algorithm::RS256;
            let mismatched = sign_token(&rs256_variant, &issuer, &config.audience, "user-1");
            let err = cache.validate_token(&mismatched).await.unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unauthenticated);
        }

        #[tokio::test]
        async fn rsa_missing_alg_defaults_to_rs256() {
            // No "alg" field at all (e.g. Microsoft Entra ID's JWKS) must
            // still default to RS256, not be treated as unusable.
            let key = rsa_test_key("rsa-no-alg");
            assert!(key.jwk.get("alg").is_none());
            let jwks = serde_json::json!({ "keys": [key.jwk.clone()] });
            let (cache, issuer, config) = cache_from_jwks(jwks).await;
            let token = sign_token(&key, &issuer, &config.audience, "user-1");
            assert!(cache.validate_token(&token).await.is_ok());
        }

        #[tokio::test]
        async fn key_ops_verify_accepted_sign_only_rejected() {
            // The gateway only ever verifies signatures, so `key_ops` must
            // include "verify" — `["sign"]` alone (without "verify") on a
            // public key is semantically incoherent per RFC 7517 §4.3 and
            // must be rejected, not treated as interchangeable with "verify".
            let mut verify_key = rsa_test_key("verify-key");
            verify_key.jwk["key_ops"] = serde_json::json!(["verify"]);
            let mut sign_key = rsa_test_key_secondary("sign-key");
            sign_key.jwk["key_ops"] = serde_json::json!(["sign"]);
            let jwks = serde_json::json!({ "keys": [verify_key.jwk, sign_key.jwk] });
            let (cache, issuer, config) = cache_from_jwks(jwks).await;

            let verify_token = sign_token(&verify_key, &issuer, &config.audience, "verify-user");
            assert!(cache.validate_token(&verify_token).await.is_ok());

            let sign_token_str = sign_token(&sign_key, &issuer, &config.audience, "sign-user");
            let err = cache.validate_token(&sign_token_str).await.unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unauthenticated);
        }

        #[tokio::test]
        async fn key_ops_sign_and_encrypt_rejected() {
            // RFC 7517 §4.3 permits "sign" with "verify" but not "sign" with
            // "encrypt" ("other combinations SHOULD NOT be used"). Since
            // "verify" is absent here, the key must be skipped.
            let mut key = rsa_test_key("mixed-ops");
            key.jwk["key_ops"] = serde_json::json!(["sign", "encrypt"]);
            let jwks = serde_json::json!({ "keys": [key.jwk] });
            let (cache, issuer, config) = cache_from_jwks(jwks).await;
            let token = sign_token(&key, &issuer, &config.audience, "user-1");
            let err = cache.validate_token(&token).await.unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unauthenticated);
        }

        #[tokio::test]
        async fn key_ops_encrypt_only_skipped() {
            let signing = rsa_test_key("good");
            let mut enc_ops = signing.jwk.clone();
            enc_ops["kid"] = serde_json::json!("enc-ops");
            enc_ops["key_ops"] = serde_json::json!(["encrypt"]);
            let jwks = serde_json::json!({ "keys": [enc_ops, signing.jwk] });
            let (cache, issuer, config) = cache_from_jwks(jwks).await;
            let token = sign_token(&signing, &issuer, &config.audience, "user-1");
            assert!(cache.validate_token(&token).await.is_ok());
        }

        #[tokio::test]
        async fn encryption_jwk_skipped_but_sig_key_works() {
            let signing = rsa_test_key("sig");
            let mut enc = signing.jwk.clone();
            enc["use"] = serde_json::json!("enc");
            enc["kid"] = serde_json::json!("enc-key");
            let jwks = serde_json::json!({ "keys": [enc, signing.jwk] });
            let (cache, issuer, config) = cache_from_jwks(jwks).await;
            let token = sign_token(&signing, &issuer, &config.audience, "user-1");
            assert!(cache.validate_token(&token).await.is_ok());
        }

        #[tokio::test]
        async fn duplicate_kid_same_algorithm_keeps_first() {
            let first = rsa_test_key("dup");
            let second = rsa_test_key_secondary("other");
            let mut second_jwk = second.jwk.clone();
            second_jwk["kid"] = serde_json::json!("dup");
            let jwks = serde_json::json!({ "keys": [first.jwk, second_jwk] });
            let (cache, issuer, config) = cache_from_jwks(jwks).await;

            let first_token = sign_token(&first, &issuer, &config.audience, "first-user");
            assert!(cache.validate_token(&first_token).await.is_ok());

            let mut header = Header::new(second.algorithm);
            header.kid = Some("dup".to_string());
            let claims = serde_json::json!({
                "sub": "second-user",
                "iss": issuer,
                "aud": config.audience,
                "exp": now_secs() + 3600,
            });
            let second_token = encode(&header, &claims, &second.encoding_key).unwrap();
            let err = cache.validate_token(&second_token).await.unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unauthenticated);
        }

        #[tokio::test]
        async fn duplicate_kid_conflicting_algorithms_poison_pill() {
            let rsa = rsa_test_key("conflict");
            let eddsa = ed25519_test_key("conflict");
            let jwks = serde_json::json!({ "keys": [rsa.jwk, eddsa.jwk] });
            let (cache, issuer, config) = cache_from_jwks(jwks).await;

            let rsa_token = sign_token(&rsa, &issuer, &config.audience, "rsa-user");
            let err = cache.validate_token(&rsa_token).await.unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unauthenticated);

            let eddsa_token = sign_token(&eddsa, &issuer, &config.audience, "eddsa-user");
            let err = cache.validate_token(&eddsa_token).await.unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unauthenticated);
        }
    }
}
