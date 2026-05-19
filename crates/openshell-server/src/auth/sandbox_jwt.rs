// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-minted per-sandbox JWTs.
//!
//! The gateway signs an Ed25519 JWT for each sandbox at create time and
//! the sandbox supervisor presents it as `Authorization: Bearer <jwt>` on
//! supervisor-to-gateway gRPC calls. This module implements both sides of the
//! gateway-controlled token:
//! - [`SandboxJwtIssuer`] mints fresh tokens (called from
//!   `handle_create_sandbox` and the `IssueSandboxToken` RPC).
//! - [`SandboxJwtAuthenticator`] validates tokens on inbound requests and
//!   produces a [`Principal::Sandbox`] with [`SandboxIdentitySource::BootstrapJwt`].
//!
//! Algorithm: `EdDSA` (Ed25519). Pinned via `Validation::algorithms` to
//! prevent algorithm-confusion attacks.

use super::authenticator::Authenticator;
use super::principal::{Principal, SandboxIdentitySource, SandboxPrincipal};
use async_trait::async_trait;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tonic::Status;
use tracing::{debug, warn};

/// SPIFFE-shaped subject prefix. Embedded in the `sub` claim of every
/// minted token so a future migration to per-sandbox certs or SPIRE can
/// reuse the same subject namespace without breaking handler equality
/// checks.
const SPIFFE_SUBJECT_PREFIX: &str = "spiffe://openshell/sandbox/";

/// JWT claim set serialized in every gateway-minted sandbox token.
#[derive(Debug, Serialize, Deserialize)]
pub struct SandboxJwtClaims {
    /// `spiffe://openshell/sandbox/<uuid>`. SPIFFE-shaped for forward
    /// compatibility with channel-bound identity (per-sandbox cert / SPIRE).
    pub sub: String,
    /// Gateway identity (`openshell-gateway:<gateway_id>`). Both `iss` and
    /// `aud` use the same value so any future replicas of the same
    /// deployment validate each others' tokens without configuration.
    pub iss: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    /// Canonical sandbox UUID, denormalized from `sub` for cheap parsing
    /// without a SPIFFE library.
    pub sandbox_id: String,
}

/// Mints fresh sandbox JWTs.
pub struct SandboxJwtIssuer {
    encoding_key: EncodingKey,
    kid: String,
    issuer: String,
    audience: String,
    ttl: Duration,
}

impl std::fmt::Debug for SandboxJwtIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxJwtIssuer")
            .field("kid", &self.kid)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

/// Outcome of a successful mint.
#[derive(Debug, Clone)]
pub struct MintedToken {
    pub token: String,
    pub expires_at_ms: i64,
}

impl SandboxJwtIssuer {
    pub fn from_pem(
        signing_key_pem: &[u8],
        kid: String,
        gateway_id: &str,
        ttl: Duration,
    ) -> Result<Self, String> {
        let encoding_key = EncodingKey::from_ed_pem(signing_key_pem)
            .map_err(|e| format!("failed to parse Ed25519 signing key PEM: {e}"))?;
        let identity = format!("openshell-gateway:{gateway_id}");
        Ok(Self {
            encoding_key,
            kid,
            issuer: identity.clone(),
            audience: identity,
            ttl,
        })
    }

    /// Mint a fresh token for `sandbox_id`.
    #[allow(clippy::result_large_err)] // `tonic::Status` is the natural error here
    pub fn mint(&self, sandbox_id: &str) -> Result<MintedToken, Status> {
        let now = now_secs();
        let exp = now + i64::try_from(self.ttl.as_secs()).unwrap_or(3_600);
        let claims = SandboxJwtClaims {
            sub: format!("{SPIFFE_SUBJECT_PREFIX}{sandbox_id}"),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            iat: now,
            exp,
            sandbox_id: sandbox_id.to_string(),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        let token = encode(&header, &claims, &self.encoding_key).map_err(|e| {
            warn!(error = %e, "failed to mint sandbox JWT");
            Status::internal("failed to mint sandbox token")
        })?;
        Ok(MintedToken {
            token,
            expires_at_ms: exp.saturating_mul(1000),
        })
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

/// Authenticator that validates gateway-minted sandbox JWTs.
pub struct SandboxJwtAuthenticator {
    decoding_key: DecodingKey,
    kid: String,
    issuer: String,
    audience: String,
}

impl std::fmt::Debug for SandboxJwtAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxJwtAuthenticator")
            .field("kid", &self.kid)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

impl SandboxJwtAuthenticator {
    pub fn from_pem(public_key_pem: &[u8], kid: String, gateway_id: &str) -> Result<Self, String> {
        let decoding_key = DecodingKey::from_ed_pem(public_key_pem)
            .map_err(|e| format!("failed to parse Ed25519 public key PEM: {e}"))?;
        let identity = format!("openshell-gateway:{gateway_id}");
        Ok(Self {
            decoding_key,
            kid,
            issuer: identity.clone(),
            audience: identity,
        })
    }

    #[allow(clippy::result_large_err)]
    fn validate_bearer(&self, token: &str) -> Result<Option<Principal>, Status> {
        let header = decode_header(token).map_err(|e| {
            debug!(error = %e, "sandbox JWT header decode failed");
            Status::unauthenticated("invalid token")
        })?;

        // Fall through to other authenticators when the kid does not match —
        // OIDC issuers may share the Bearer slot.
        if header.kid.as_deref() != Some(self.kid.as_str()) {
            return Ok(None);
        }
        if !matches!(header.alg, Algorithm::EdDSA) {
            return Ok(None);
        }

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.algorithms = vec![Algorithm::EdDSA];
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);

        let data =
            decode::<SandboxJwtClaims>(token, &self.decoding_key, &validation).map_err(|e| {
                debug!(error = %e, "sandbox JWT validation failed");
                Status::unauthenticated(format!("invalid token: {e}"))
            })?;

        let claims = data.claims;
        Ok(Some(Principal::Sandbox(SandboxPrincipal {
            sandbox_id: claims.sandbox_id,
            source: SandboxIdentitySource::BootstrapJwt { issuer: claims.iss },
            trust_domain: Some("openshell".to_string()),
        })))
    }
}

#[async_trait]
impl Authenticator for SandboxJwtAuthenticator {
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
        self.validate_bearer(token)
    }
}

fn now_secs() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_bootstrap::jwt::generate_jwt_key;

    fn header_map_with_bearer(token: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert(
            "authorization",
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        h
    }

    fn pair() -> (SandboxJwtIssuer, SandboxJwtAuthenticator) {
        let mat = generate_jwt_key().expect("jwt key");
        let issuer = SandboxJwtIssuer::from_pem(
            mat.signing_key_pem.as_bytes(),
            mat.kid.clone(),
            "test-gateway",
            Duration::from_secs(3600),
        )
        .unwrap();
        let auth = SandboxJwtAuthenticator::from_pem(
            mat.public_key_pem.as_bytes(),
            mat.kid,
            "test-gateway",
        )
        .unwrap();
        (issuer, auth)
    }

    #[tokio::test]
    async fn mint_and_validate_round_trip() {
        let (issuer, auth) = pair();
        let minted = issuer.mint("sandbox-a").unwrap();
        let principal = auth
            .authenticate(&header_map_with_bearer(&minted.token), "/anything")
            .await
            .unwrap()
            .expect("expected principal");
        match principal {
            Principal::Sandbox(p) => {
                assert_eq!(p.sandbox_id, "sandbox-a");
                match p.source {
                    SandboxIdentitySource::BootstrapJwt { issuer: iss } => {
                        assert_eq!(iss, "openshell-gateway:test-gateway");
                    }
                    other => panic!("unexpected source: {other:?}"),
                }
            }
            _ => panic!("expected Sandbox principal"),
        }
    }

    #[tokio::test]
    async fn token_signed_by_other_key_is_rejected() {
        let (_, auth_a) = pair();
        let (issuer_b, _) = pair(); // different keypair
        let minted = issuer_b.mint("sandbox-b").unwrap();
        // The token has a different `kid` than auth_a expects, so the
        // authenticator yields None (lets the chain fall through). That is
        // the documented behavior for cross-issuer Bearer headers.
        let result = auth_a
            .authenticate(&header_map_with_bearer(&minted.token), "/anything")
            .await
            .unwrap();
        assert!(result.is_none(), "different kid must fall through");
    }

    #[tokio::test]
    async fn missing_bearer_yields_none() {
        let (_, auth) = pair();
        let result = auth
            .authenticate(&http::HeaderMap::new(), "/anything")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn malformed_token_is_rejected() {
        let (_, auth) = pair();
        let err = auth
            .authenticate(&header_map_with_bearer("not.a.jwt"), "/anything")
            .await
            .expect_err("malformed must reject");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        // Mint a token whose iat is far in the past so its TTL window is
        // already closed by `now`. We sign the JWT directly with the same
        // signing key to bypass the issuer's TTL-vs-now coupling.
        let mat = generate_jwt_key().unwrap();
        let issuer = SandboxJwtIssuer::from_pem(
            mat.signing_key_pem.as_bytes(),
            mat.kid.clone(),
            "g",
            Duration::from_secs(3600),
        )
        .unwrap();
        let auth =
            SandboxJwtAuthenticator::from_pem(mat.public_key_pem.as_bytes(), mat.kid.clone(), "g")
                .unwrap();
        let claims = SandboxJwtClaims {
            sub: format!("{SPIFFE_SUBJECT_PREFIX}sandbox-c"),
            iss: "openshell-gateway:g".to_string(),
            aud: "openshell-gateway:g".to_string(),
            iat: now_secs() - 7200,
            exp: now_secs() - 3600,
            sandbox_id: "sandbox-c".to_string(),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(mat.kid);
        let token = encode(&header, &claims, &issuer.encoding_key).unwrap();
        let err = auth
            .authenticate(&header_map_with_bearer(&token), "/anything")
            .await
            .expect_err("expired token must reject");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
