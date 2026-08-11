// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-minted per-sandbox JWTs.
//!
//! The gateway signs a JWT for each sandbox at create time and
//! the sandbox supervisor presents it as `Authorization: Bearer <jwt>` on
//! supervisor-to-gateway gRPC calls. This module implements both sides of the
//! gateway-controlled token:
//! - [`SandboxJwtIssuer`] mints fresh tokens (called from
//!   `handle_create_sandbox` and the `IssueSandboxToken` RPC).
//! - [`SandboxJwtAuthenticator`] validates tokens on inbound requests and
//!   produces a [`Principal::Sandbox`] with [`SandboxIdentitySource::BootstrapJwt`].
//!
//! Algorithm: `EdDSA` (Ed25519) in a default build, `ES256` (ECDSA P-256) in a
//! FIPS build — see `openshell_crypto::jwt_algorithm`. Pinned via
//! `Validation::algorithms` to prevent algorithm-confusion attacks, and pinned
//! to exactly one algorithm so a FIPS gateway cannot accept a token signed with
//! a non-approved key.

use super::authenticator::Authenticator;
use super::principal::{Principal, SandboxIdentitySource, SandboxPrincipal};
use async_trait::async_trait;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tonic::Status;
use tracing::{debug, warn};

/// SPIFFE-shaped subject prefix. Embedded in the `sub` claim of every
/// minted token so a future migration to per-sandbox certs or SPIRE can
/// reuse the same subject namespace without breaking handler equality
/// checks.
const SPIFFE_SUBJECT_PREFIX: &str = "spiffe://openshell/sandbox/";
const SANDBOX_JWT_EXP_LEEWAY_SECS: i64 = 60;

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
        let encoding_key = openshell_crypto::jwt_encoding_key(signing_key_pem).map_err(|e| {
            format!(
                "failed to parse the sandbox JWT signing key as {}: {e}. A FIPS build \
                     requires an ECDSA P-256 key and a default build requires an Ed25519 key; \
                     a gateway whose key material was generated under the other build mode must \
                     rotate it by re-running `openshell-gateway generate-certs`.",
                openshell_crypto::JWT_JOSE_ALGORITHM
            )
        })?;
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
        let exp = if self.ttl.is_zero() {
            0
        } else {
            now.saturating_add(i64::try_from(self.ttl.as_secs()).unwrap_or(3_600))
        };
        let claims = SandboxJwtClaims {
            sub: format!("{SPIFFE_SUBJECT_PREFIX}{sandbox_id}"),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            iat: now,
            exp,
            sandbox_id: sandbox_id.to_string(),
        };
        let mut header = Header::new(openshell_crypto::jwt_algorithm());
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
        let decoding_key = openshell_crypto::jwt_decoding_key(public_key_pem).map_err(|e| {
            format!(
                "failed to parse the sandbox JWT public key as {}: {e}. See the signing-key \
                     error above for the key-rotation requirement when switching build modes.",
                openshell_crypto::JWT_JOSE_ALGORITHM
            )
        })?;
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
        // A FIPS build signs and accepts ES256; a default build EdDSA. The
        // sets are deliberately disjoint rather than overlapping: accepting the
        // other mode's algorithm would let a FIPS gateway validate tokens
        // signed by a non-approved key. Mixed-mode replica sets are therefore
        // unsupported — see openshell-crypto::JWT_SIGNATURE_ALGORITHM.
        if header.alg != openshell_crypto::jwt_algorithm() {
            return Ok(None);
        }

        let mut validation = Validation::new(openshell_crypto::jwt_algorithm());
        validation.algorithms = vec![openshell_crypto::jwt_algorithm()];
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);
        validation.validate_exp = false;

        let data =
            decode::<SandboxJwtClaims>(token, &self.decoding_key, &validation).map_err(|e| {
                debug!(error = %e, "sandbox JWT validation failed");
                Status::unauthenticated(format!("invalid token: {e}"))
            })?;

        let claims = data.claims;
        validate_exp(claims.exp)?;
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

#[allow(clippy::result_large_err)]
fn validate_exp(exp: i64) -> Result<(), Status> {
    if exp == 0 {
        return Ok(());
    }

    if exp < now_secs().saturating_sub(SANDBOX_JWT_EXP_LEEWAY_SECS) {
        debug!("sandbox JWT expired");
        return Err(Status::unauthenticated("invalid token: ExpiredSignature"));
    }

    Ok(())
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
        pair_with_ttl(Duration::from_secs(3600))
    }

    fn pair_with_ttl(ttl: Duration) -> (SandboxJwtIssuer, SandboxJwtAuthenticator) {
        let mat = generate_jwt_key().expect("jwt key");
        let issuer = SandboxJwtIssuer::from_pem(
            mat.signing_key_pem.as_bytes(),
            mat.kid.clone(),
            "test-gateway",
            ttl,
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

    /// Key material generated under the other build mode must be rejected with
    /// an actionable error rather than a cryptic parse failure. Switching an
    /// existing gateway to a FIPS build requires rotating the JWT key, and this
    /// is the message that has to say so.
    #[test]
    fn key_material_from_the_other_build_mode_is_rejected_with_guidance() {
        let other_mode_key = if openshell_crypto::IS_FIPS_BUILD {
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        } else {
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        }
        .expect("generate a key of the non-native type");

        let err = SandboxJwtIssuer::from_pem(
            other_mode_key.serialize_pem().as_bytes(),
            "kid".to_string(),
            "test-gateway",
            Duration::from_secs(60),
        )
        .expect_err("a key of the wrong type must not load");

        assert!(
            err.contains("rotate") && err.contains("generate-certs"),
            "the error must tell the operator how to recover, got: {err}"
        );
        assert!(
            err.contains(openshell_crypto::JWT_JOSE_ALGORITHM),
            "the error must name the expected algorithm, got: {err}"
        );
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
    async fn ttl_zero_mints_non_expiring_token() {
        let (issuer, auth) = pair_with_ttl(Duration::ZERO);
        let minted = issuer.mint("sandbox-never").unwrap();
        assert_eq!(minted.expires_at_ms, 0);

        let principal = auth
            .authenticate(&header_map_with_bearer(&minted.token), "/anything")
            .await
            .unwrap()
            .expect("exp=0 token should authenticate");
        assert!(matches!(principal, Principal::Sandbox(_)));

        let mut validation = Validation::new(openshell_crypto::jwt_algorithm());
        validation.algorithms = vec![openshell_crypto::jwt_algorithm()];
        validation.set_issuer(&["openshell-gateway:test-gateway"]);
        validation.set_audience(&["openshell-gateway:test-gateway"]);
        validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);
        validation.validate_exp = false;
        let decoded = decode::<SandboxJwtClaims>(&minted.token, &auth.decoding_key, &validation)
            .expect("token should decode");
        assert_eq!(decoded.claims.exp, 0);
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
        let mut header = Header::new(openshell_crypto::jwt_algorithm());
        header.kid = Some(mat.kid);
        let token = encode(&header, &claims, &issuer.encoding_key).unwrap();
        let err = auth
            .authenticate(&header_map_with_bearer(&token), "/anything")
            .await
            .expect_err("expired token must reject");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
