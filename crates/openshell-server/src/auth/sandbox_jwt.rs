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
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
pub use openshell_extension_core::{
    EXTENSION_JWT_TYP, ExtensionAudience, ExtensionCallerKind, ExtensionJwtClaims,
    MAX_EXTENSION_TOKEN_TTL,
};
use serde::{Deserialize, Serialize};
use std::{
    io::Cursor,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tonic::Status;
use tracing::{debug, warn};
use x509_parser::{oid_registry::OID_SIG_ED25519, prelude::FromDer, x509::SubjectPublicKeyInfo};

/// SPIFFE-shaped subject prefix. Embedded in the `sub` claim of every
/// minted token so a future migration to per-sandbox certs or SPIRE can
/// reuse the same subject namespace without breaking handler equality
/// checks.
const SPIFFE_SUBJECT_PREFIX: &str = "spiffe://openshell/sandbox/";
const SANDBOX_JWT_EXP_LEEWAY_SECS: i64 = 60;

/// Public JSON Web Key Set served by the gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GatewayJwks {
    pub keys: Vec<GatewayJwk>,
}

/// Ed25519 public key entry in the gateway JWKS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GatewayJwk {
    pub kty: &'static str,
    pub crv: &'static str,
    pub alg: &'static str,
    #[serde(rename = "use")]
    pub key_use: &'static str,
    pub kid: String,
    pub x: String,
}

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

    /// Mint a short-lived bearer token for one exact extension audience.
    ///
    /// `sandbox_id` is required for supervisor calls and forbidden for
    /// gateway calls. The subject follows the existing SPIFFE-shaped sandbox
    /// identity for supervisor calls; gateway calls use the issuer identity.
    #[allow(clippy::result_large_err)]
    pub fn mint_extension_token(
        &self,
        audience: &ExtensionAudience,
        caller_kind: ExtensionCallerKind,
        sandbox_id: Option<&str>,
        ttl: Duration,
    ) -> Result<MintedToken, Status> {
        if audience.as_str() == self.audience {
            return Err(Status::invalid_argument(
                "extension audience must not equal the gateway sandbox audience",
            ));
        }
        if ttl.is_zero() || ttl > MAX_EXTENSION_TOKEN_TTL {
            return Err(Status::invalid_argument(format!(
                "extension token TTL must be between 1 and {} seconds",
                MAX_EXTENSION_TOKEN_TTL.as_secs()
            )));
        }

        let (sub, sandbox_id) = match (caller_kind, sandbox_id) {
            (ExtensionCallerKind::Gateway, None) => (self.issuer.clone(), None),
            (ExtensionCallerKind::Supervisor, Some(id)) if !id.trim().is_empty() => {
                (format!("{SPIFFE_SUBJECT_PREFIX}{id}"), Some(id.to_string()))
            }
            (ExtensionCallerKind::Gateway, Some(_)) => {
                return Err(Status::invalid_argument(
                    "gateway extension tokens must not include a sandbox ID",
                ));
            }
            (ExtensionCallerKind::Supervisor, _) => {
                return Err(Status::invalid_argument(
                    "supervisor extension tokens require a sandbox ID",
                ));
            }
        };

        let now = now_secs();
        let exp = now.saturating_add(i64::try_from(ttl.as_secs()).unwrap_or(3_600));
        let claims = ExtensionJwtClaims {
            iss: self.issuer.clone(),
            aud: audience.as_str().to_string(),
            sub,
            iat: now,
            exp,
            jti: uuid::Uuid::new_v4().to_string(),
            caller_kind,
            sandbox_id,
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        // Explicit typing so an extension that requires this `typ` cannot be
        // handed a sandbox-to-gateway bootstrap token signed by the same key.
        header.typ = Some(EXTENSION_JWT_TYP.to_string());
        let token = encode(&header, &claims, &self.encoding_key).map_err(|e| {
            warn!(error = %e, "failed to mint extension JWT");
            Status::internal("failed to mint extension token")
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
    jwks: GatewayJwks,
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
        let jwks = GatewayJwks::from_public_key_pem(public_key_pem, kid.clone())?;
        let identity = format!("openshell-gateway:{gateway_id}");
        Ok(Self {
            decoding_key,
            kid,
            issuer: identity.clone(),
            audience: identity,
            jwks,
        })
    }

    /// Return the public signing keys integrations use to verify extension
    /// tokens. No private key material is retained by this type.
    #[must_use]
    pub const fn jwks(&self) -> &GatewayJwks {
        &self.jwks
    }

    /// The exact `iss` claim carried by every token this gateway mints.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    #[allow(clippy::result_large_err)]
    fn validate_bearer(&self, token: &str) -> Result<Option<Principal>, Status> {
        let header = decode_header(token).map_err(|e| {
            debug!(error = %e, "sandbox JWT header decode failed");
            Status::unauthenticated("invalid token")
        })?;

        // Extension credentials share this signing key during alpha, but are
        // never valid sandbox admission credentials. Check the explicit type
        // before `kid` fallthrough so another authenticator cannot accept one.
        // Legacy and untyped sandbox JWTs remain valid for rolling upgrades.
        if header.typ.as_deref() == Some(EXTENSION_JWT_TYP) {
            return Err(Status::unauthenticated(
                "extension tokens cannot authenticate to the gateway",
            ));
        }

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

impl GatewayJwks {
    fn from_public_key_pem(public_key_pem: &[u8], kid: String) -> Result<Self, String> {
        let item = rustls_pemfile::read_one(&mut Cursor::new(public_key_pem))
            .map_err(|e| format!("failed to parse Ed25519 public key PEM for JWKS: {e}"))?;
        let Some(rustls_pemfile::Item::SubjectPublicKeyInfo(der)) = item else {
            return Err("Ed25519 public key PEM does not contain a PUBLIC KEY block".into());
        };
        let (remainder, spki) = SubjectPublicKeyInfo::from_der(der.as_ref())
            .map_err(|e| format!("failed to parse SubjectPublicKeyInfo for JWKS: {e}"))?;
        if !remainder.is_empty() || spki.algorithm.algorithm != OID_SIG_ED25519 {
            return Err("public key is not an RFC 8410 Ed25519 SubjectPublicKeyInfo key".into());
        }
        let raw_key = spki.subject_public_key.data.as_ref();
        if raw_key.len() != 32 {
            return Err("Ed25519 public key must be 32 bytes".to_string());
        }

        Ok(Self {
            keys: vec![GatewayJwk {
                kty: "OKP",
                crv: "Ed25519",
                alg: "EdDSA",
                key_use: "sig",
                kid,
                x: URL_SAFE_NO_PAD.encode(raw_key),
            }],
        })
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

    fn extension_audience(value: &str) -> ExtensionAudience {
        ExtensionAudience::new(value).expect("valid extension audience")
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
    async fn extension_token_cannot_authenticate_as_a_sandbox() {
        let mat = generate_jwt_key().expect("jwt key");
        let issuer = SandboxJwtIssuer::from_pem(
            mat.signing_key_pem.as_bytes(),
            mat.kid.clone(),
            "test-gateway",
            Duration::from_secs(3600),
        )
        .expect("issuer");
        let auth = SandboxJwtAuthenticator::from_pem(
            mat.public_key_pem.as_bytes(),
            mat.kid.clone(),
            "test-gateway",
        )
        .expect("authenticator");

        // Build the token directly to model a credential minted before the
        // reserved-audience guard was added. Its claims otherwise satisfy the
        // sandbox authenticator's issuer, audience, subject, and expiry checks.
        let sandbox_id = "sandbox-a";
        let now = now_secs();
        let claims = ExtensionJwtClaims {
            iss: "openshell-gateway:test-gateway".to_string(),
            aud: "openshell-gateway:test-gateway".to_string(),
            sub: format!("{SPIFFE_SUBJECT_PREFIX}{sandbox_id}"),
            iat: now,
            exp: now + 300,
            jti: uuid::Uuid::new_v4().to_string(),
            caller_kind: ExtensionCallerKind::Supervisor,
            sandbox_id: Some(sandbox_id.to_string()),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(mat.kid);
        header.typ = Some(EXTENSION_JWT_TYP.to_string());
        let token = encode(&header, &claims, &issuer.encoding_key).expect("extension token");

        let error = auth
            .authenticate(&header_map_with_bearer(&token), "/anything")
            .await
            .expect_err("extension token must not authenticate as a sandbox");
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        assert_eq!(
            error.message(),
            "extension tokens cannot authenticate to the gateway"
        );
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

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.algorithms = vec![Algorithm::EdDSA];
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
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(mat.kid);
        let token = encode(&header, &claims, &issuer.encoding_key).unwrap();
        let err = auth
            .authenticate(&header_map_with_bearer(&token), "/anything")
            .await
            .expect_err("expired token must reject");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn extension_tokens_have_exact_audience_and_caller_identity() {
        let mat = generate_jwt_key().expect("jwt key");
        let issuer = SandboxJwtIssuer::from_pem(
            mat.signing_key_pem.as_bytes(),
            mat.kid.clone(),
            "gateway-a",
            Duration::ZERO,
        )
        .expect("issuer");
        let decoding_key = DecodingKey::from_ed_pem(mat.public_key_pem.as_bytes()).unwrap();

        let gateway = issuer
            .mint_extension_token(
                &extension_audience("urn:openshell:extension:middleware:scanner"),
                ExtensionCallerKind::Gateway,
                None,
                Duration::from_secs(300),
            )
            .expect("gateway token");
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&["openshell-gateway:gateway-a"]);
        validation.set_audience(&["urn:openshell:extension:middleware:scanner"]);
        validation.set_required_spec_claims(&["iss", "aud", "sub", "iat", "exp"]);
        let claims = decode::<ExtensionJwtClaims>(&gateway.token, &decoding_key, &validation)
            .expect("valid extension token")
            .claims;
        assert_eq!(claims.sub, "openshell-gateway:gateway-a");
        assert_eq!(claims.caller_kind, ExtensionCallerKind::Gateway);
        assert_eq!(claims.sandbox_id, None);
        assert!(!claims.jti.is_empty());
        assert_eq!(gateway.expires_at_ms, claims.exp * 1000);

        let supervisor = issuer
            .mint_extension_token(
                &extension_audience("urn:openshell:extension:middleware:scanner"),
                ExtensionCallerKind::Supervisor,
                Some("sandbox-a"),
                Duration::from_secs(300),
            )
            .expect("supervisor token");
        let claims = decode::<ExtensionJwtClaims>(&supervisor.token, &decoding_key, &validation)
            .expect("valid supervisor extension token")
            .claims;
        assert_eq!(claims.sub, "spiffe://openshell/sandbox/sandbox-a");
        assert_eq!(claims.caller_kind, ExtensionCallerKind::Supervisor);
        assert_eq!(claims.sandbox_id.as_deref(), Some("sandbox-a"));
    }

    #[test]
    fn extension_tokens_are_explicitly_typed_and_sandbox_tokens_are_not() {
        let mat = generate_jwt_key().expect("jwt key");
        let issuer = SandboxJwtIssuer::from_pem(
            mat.signing_key_pem.as_bytes(),
            mat.kid.clone(),
            "gateway-a",
            Duration::from_secs(3600),
        )
        .expect("issuer");

        let extension = issuer
            .mint_extension_token(
                &extension_audience("urn:openshell:extension:middleware:scanner"),
                ExtensionCallerKind::Gateway,
                None,
                Duration::from_secs(300),
            )
            .expect("extension token");
        assert_eq!(
            decode_header(&extension.token).unwrap().typ.as_deref(),
            Some(EXTENSION_JWT_TYP)
        );

        // The discriminator is only useful if the sandbox bootstrap token does
        // not carry it. A verifier requiring `openshell-ext+jwt` must reject a
        // gateway admission credential even though both share a signing key.
        let sandbox = issuer.mint("sandbox-a").expect("sandbox token");
        assert_ne!(
            decode_header(&sandbox.token).unwrap().typ.as_deref(),
            Some(EXTENSION_JWT_TYP)
        );
    }

    #[test]
    fn extension_token_rejects_wrong_audience() {
        let mat = generate_jwt_key().expect("jwt key");
        let issuer = SandboxJwtIssuer::from_pem(
            mat.signing_key_pem.as_bytes(),
            mat.kid,
            "gateway-a",
            Duration::ZERO,
        )
        .expect("issuer");
        let minted = issuer
            .mint_extension_token(
                &extension_audience("service-a"),
                ExtensionCallerKind::Gateway,
                None,
                Duration::from_secs(60),
            )
            .expect("token");
        let decoding_key = DecodingKey::from_ed_pem(mat.public_key_pem.as_bytes()).unwrap();
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&["openshell-gateway:gateway-a"]);
        validation.set_audience(&["service-b"]);
        assert!(decode::<ExtensionJwtClaims>(&minted.token, &decoding_key, &validation).is_err());
    }

    #[test]
    fn extension_token_rejects_gateway_sandbox_audience() {
        let (issuer, _) = pair();
        let error = issuer
            .mint_extension_token(
                &extension_audience("openshell-gateway:test-gateway"),
                ExtensionCallerKind::Supervisor,
                Some("sandbox-a"),
                Duration::from_secs(60),
            )
            .expect_err("gateway sandbox audience must be reserved");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            error.message(),
            "extension audience must not equal the gateway sandbox audience"
        );
    }

    #[test]
    fn extension_token_enforces_positive_bounded_ttl_and_caller_shape() {
        let (issuer, _) = pair_with_ttl(Duration::ZERO);
        for ttl in [
            Duration::ZERO,
            MAX_EXTENSION_TOKEN_TTL + Duration::from_secs(1),
        ] {
            let error = issuer
                .mint_extension_token(
                    &extension_audience("service"),
                    ExtensionCallerKind::Gateway,
                    None,
                    ttl,
                )
                .expect_err("invalid TTL");
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
        }
        assert!(
            issuer
                .mint_extension_token(
                    &extension_audience("service"),
                    ExtensionCallerKind::Supervisor,
                    None,
                    Duration::from_secs(60),
                )
                .is_err()
        );
        assert!(
            issuer
                .mint_extension_token(
                    &extension_audience("service"),
                    ExtensionCallerKind::Gateway,
                    Some("sandbox-a"),
                    Duration::from_secs(60),
                )
                .is_err()
        );
        assert!(ExtensionAudience::new("  ").is_err());
    }

    #[test]
    fn jwks_contains_public_ed25519_key_without_pem_material() {
        let mat = generate_jwt_key().expect("jwt key");
        let auth = SandboxJwtAuthenticator::from_pem(
            mat.public_key_pem.as_bytes(),
            mat.kid.clone(),
            "gateway-a",
        )
        .expect("authenticator");
        let jwks = auth.jwks();
        assert_eq!(jwks.keys.len(), 1);
        let key = &jwks.keys[0];
        assert_eq!(key.kid, mat.kid);
        assert_eq!(key.kty, "OKP");
        assert_eq!(key.crv, "Ed25519");
        assert_eq!(key.alg, "EdDSA");
        assert_eq!(key.key_use, "sig");
        assert_eq!(URL_SAFE_NO_PAD.decode(&key.x).unwrap().len(), 32);

        let json = serde_json::to_string(jwks).expect("JSON");
        assert!(!json.contains("BEGIN PUBLIC KEY"));
        assert!(!json.contains("PRIVATE"));
        assert!(json.contains(r#""use":"sig""#));
    }
}
