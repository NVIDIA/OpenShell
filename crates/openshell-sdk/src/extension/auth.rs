// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::time::Duration;

use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, EllipticCurve, JwkSet, PublicKeyUse},
};
use serde::{Deserialize, Serialize};
use tonic::{Request, Status};

const CLOCK_SKEW_SECS: i64 = 30;
const EXTENSION_JWT_TYP: &str = "openshell-ext+jwt";
const MAX_EXTENSION_TOKEN_TTL: Duration = Duration::from_secs(3_600);

/// `OpenShell` component authenticated as the caller of an extension service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionCallerKind {
    Gateway,
    Supervisor,
}

/// Private wire representation of gateway-minted extension claims.
///
/// Keeping the claims internal lets the SDK expose a stable, normalized caller
/// identity without making the gateway's token schema part of its public API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExtensionJwtClaims {
    iss: String,
    aud: String,
    sub: String,
    iat: i64,
    exp: i64,
    jti: String,
    caller_kind: ExtensionCallerKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox_id: Option<String>,
}

/// Verified identity presented by an `OpenShell` component to an extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedCaller {
    pub kind: ExtensionCallerKind,
    pub subject: String,
    pub sandbox_id: Option<String>,
}

/// Verifies gateway-minted JWTs presented to an extension service.
///
/// The public key or JWKS document must come from a trusted operator channel.
/// Parsing key material does not establish trust in it.
pub struct GatewayJwtAuthenticator {
    keys: HashMap<String, DecodingKey>,
    issuer: String,
    audience: String,
}

impl std::fmt::Debug for GatewayJwtAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayJwtAuthenticator")
            .field("key_ids", &self.keys.keys())
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .finish()
    }
}

impl GatewayJwtAuthenticator {
    /// Construct a verifier from one trusted Ed25519 public key.
    pub fn from_ed25519_pem(
        public_key_pem: &[u8],
        key_id: impl Into<String>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self, VerificationError> {
        let key_id = key_id.into();
        if key_id.is_empty() {
            return Err(VerificationError::MissingKeyId);
        }
        let key = DecodingKey::from_ed_pem(public_key_pem)
            .map_err(VerificationError::InvalidPublicKey)?;
        Self::new(HashMap::from([(key_id, key)]), issuer, audience)
    }

    /// Construct a verifier from a trusted JWKS document.
    pub fn from_jwks(
        jwks_json: &[u8],
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self, VerificationError> {
        let jwks: JwkSet = serde_json::from_slice(jwks_json)?;
        let mut keys = HashMap::with_capacity(jwks.keys.len());

        for jwk in jwks.keys {
            let key_id = jwk
                .common
                .key_id
                .clone()
                .filter(|key_id| !key_id.is_empty())
                .ok_or(VerificationError::MissingKeyId)?;
            let supported = jwk.common.key_algorithm
                == Some(jsonwebtoken::jwk::KeyAlgorithm::EdDSA)
                && jwk.common.public_key_use == Some(PublicKeyUse::Signature)
                && matches!(
                    &jwk.algorithm,
                    AlgorithmParameters::OctetKeyPair(parameters)
                        if parameters.curve == EllipticCurve::Ed25519
                );
            if !supported {
                return Err(VerificationError::UnsupportedKey(key_id));
            }
            let key = DecodingKey::from_jwk(&jwk)
                .map_err(|_| VerificationError::UnsupportedKey(key_id.clone()))?;
            if keys.insert(key_id.clone(), key).is_some() {
                return Err(VerificationError::DuplicateKeyId(key_id));
            }
        }

        Self::new(keys, issuer, audience)
    }

    fn new(
        keys: HashMap<String, DecodingKey>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self, VerificationError> {
        if keys.is_empty() {
            return Err(VerificationError::EmptyKeySet);
        }
        let issuer = issuer.into();
        let audience = audience.into();
        if issuer.is_empty() || audience.is_empty() {
            return Err(VerificationError::EmptyExpectedIdentity);
        }
        Ok(Self {
            keys,
            issuer,
            audience,
        })
    }

    /// Verify a bearer token and return its normalized caller identity.
    pub fn authenticate(
        &self,
        bearer_token: &str,
    ) -> Result<AuthenticatedCaller, VerificationError> {
        let header = decode_header(bearer_token).map_err(VerificationError::InvalidToken)?;
        if header.typ.as_deref() != Some(EXTENSION_JWT_TYP) {
            return Err(VerificationError::UnexpectedTokenType);
        }
        if header.alg != Algorithm::EdDSA {
            return Err(VerificationError::UnexpectedAlgorithm);
        }
        let key_id = header
            .kid
            .as_deref()
            .filter(|key_id| !key_id.is_empty())
            .ok_or(VerificationError::MissingTokenKeyId)?;
        let key = self
            .keys
            .get(key_id)
            .ok_or_else(|| VerificationError::UnknownKeyId(key_id.to_string()))?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.algorithms = vec![Algorithm::EdDSA];
        validation.leeway = u64::try_from(CLOCK_SKEW_SECS).unwrap_or_default();
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&[
            "iss",
            "aud",
            "sub",
            "iat",
            "exp",
            "jti",
            "caller_kind",
        ]);

        let claims = decode::<ExtensionJwtClaims>(bearer_token, key, &validation)
            .map_err(VerificationError::InvalidToken)?
            .claims;
        validate_claim_shape(&claims)?;
        Ok(AuthenticatedCaller {
            kind: claims.caller_kind,
            subject: claims.sub,
            sandbox_id: claims.sandbox_id,
        })
    }

    /// Extract and verify the bearer credential on a tonic request.
    ///
    /// Detailed verification failures remain available through
    /// [`Self::authenticate`]. This helper returns a stable gRPC error that
    /// does not expose verifier internals to an untrusted caller.
    pub fn authenticate_request<T>(
        &self,
        request: &Request<T>,
    ) -> Result<AuthenticatedCaller, Status> {
        let authorization = request
            .metadata()
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("missing extension authorization"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("invalid extension authorization"))?;
        let token = authorization
            .strip_prefix("Bearer ")
            .filter(|token| !token.is_empty())
            .ok_or_else(|| Status::unauthenticated("expected an extension bearer token"))?;
        self.authenticate(token)
            .map_err(|_| Status::unauthenticated("invalid extension token"))
    }
}

fn validate_claim_shape(claims: &ExtensionJwtClaims) -> Result<(), VerificationError> {
    if claims.jti.is_empty() {
        return Err(VerificationError::InvalidClaims("jti must not be empty"));
    }
    if claims.exp <= claims.iat {
        return Err(VerificationError::InvalidClaims(
            "exp must be later than iat",
        ));
    }
    let max_lifetime = i64::try_from(MAX_EXTENSION_TOKEN_TTL.as_secs()).unwrap_or(i64::MAX);
    if claims.exp.saturating_sub(claims.iat) > max_lifetime {
        return Err(VerificationError::InvalidClaims(
            "token lifetime exceeds the extension maximum",
        ));
    }
    let now = i64::try_from(jsonwebtoken::get_current_timestamp()).unwrap_or(i64::MAX);
    if claims.iat > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(VerificationError::InvalidClaims(
            "iat is later than the allowed clock skew",
        ));
    }

    match (claims.caller_kind, claims.sandbox_id.as_deref()) {
        (ExtensionCallerKind::Gateway, None) if claims.sub == claims.iss => Ok(()),
        (ExtensionCallerKind::Supervisor, Some(sandbox_id))
            if !sandbox_id.is_empty()
                && claims.sub == format!("spiffe://openshell/sandbox/{sandbox_id}") =>
        {
            Ok(())
        }
        (ExtensionCallerKind::Gateway, _) => Err(VerificationError::InvalidClaims(
            "gateway caller identity is inconsistent",
        )),
        (ExtensionCallerKind::Supervisor, _) => Err(VerificationError::InvalidClaims(
            "supervisor caller identity is inconsistent",
        )),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("invalid JWKS document: {0}")]
    InvalidJwks(#[from] serde_json::Error),
    #[error("invalid Ed25519 public key: {0}")]
    InvalidPublicKey(jsonwebtoken::errors::Error),
    #[error("extension key is missing a key ID")]
    MissingKeyId,
    #[error("JWKS contains duplicate key ID '{0}'")]
    DuplicateKeyId(String),
    #[error("JWKS key '{0}' is not a supported Ed25519 signing key")]
    UnsupportedKey(String),
    #[error("extension key set is empty")]
    EmptyKeySet,
    #[error("expected issuer and audience must not be empty")]
    EmptyExpectedIdentity,
    #[error("token does not use the OpenShell extension JWT type")]
    UnexpectedTokenType,
    #[error("token does not use EdDSA")]
    UnexpectedAlgorithm,
    #[error("token header does not contain a key ID")]
    MissingTokenKeyId,
    #[error("token references unknown key ID '{0}'")]
    UnknownKeyId(String),
    #[error("token validation failed: {0}")]
    InvalidToken(jsonwebtoken::errors::Error),
    #[error("invalid extension claims: {0}")]
    InvalidClaims(&'static str),
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{EncodingKey, Header, encode};

    use super::*;

    const PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIGrD/e7uKYqSY4twDEsRfMMuLSrODf14dpTiTK6K1YI0\n-----END PRIVATE KEY-----\n";
    const PUBLIC_KEY: &[u8] = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA2+Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8=\n-----END PUBLIC KEY-----\n";
    const JWKS: &[u8] = br#"{"keys":[{"kty":"OKP","use":"sig","crv":"Ed25519","x":"2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8","kid":"test-key","alg":"EdDSA"}]}"#;

    fn claims(kind: ExtensionCallerKind) -> ExtensionJwtClaims {
        let now = i64::try_from(jsonwebtoken::get_current_timestamp()).unwrap();
        let (subject, sandbox_id) = match kind {
            ExtensionCallerKind::Gateway => ("openshell-gateway:test".into(), None),
            ExtensionCallerKind::Supervisor => (
                "spiffe://openshell/sandbox/sandbox-1".into(),
                Some("sandbox-1".into()),
            ),
        };
        ExtensionJwtClaims {
            iss: "openshell-gateway:test".into(),
            aud: "urn:openshell:extension:middleware:test".into(),
            sub: subject,
            iat: now,
            exp: now + 300,
            jti: "unique".into(),
            caller_kind: kind,
            sandbox_id,
        }
    }

    fn token(claims: &ExtensionJwtClaims, token_type: Option<&str>) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("test-key".into());
        header.typ = token_type.map(str::to_string);
        encode(
            &header,
            claims,
            &EncodingKey::from_ed_pem(PRIVATE_KEY).unwrap(),
        )
        .unwrap()
    }

    fn verifier() -> GatewayJwtAuthenticator {
        GatewayJwtAuthenticator::from_jwks(
            JWKS,
            "openshell-gateway:test",
            "urn:openshell:extension:middleware:test",
        )
        .unwrap()
    }

    #[test]
    fn authenticates_gateway_and_supervisor_callers() {
        for kind in [
            ExtensionCallerKind::Gateway,
            ExtensionCallerKind::Supervisor,
        ] {
            let expected = claims(kind);
            let caller = verifier()
                .authenticate(&token(&expected, Some(EXTENSION_JWT_TYP)))
                .unwrap();
            assert_eq!(caller.kind, kind);
            assert_eq!(caller.subject, expected.sub);
            assert_eq!(caller.sandbox_id, expected.sandbox_id);
        }
    }

    #[test]
    fn pem_and_jwks_constructors_accept_the_same_key() {
        let verifier = GatewayJwtAuthenticator::from_ed25519_pem(
            PUBLIC_KEY,
            "test-key",
            "openshell-gateway:test",
            "urn:openshell:extension:middleware:test",
        )
        .unwrap();
        assert!(
            verifier
                .authenticate(&token(
                    &claims(ExtensionCallerKind::Gateway),
                    Some(EXTENSION_JWT_TYP)
                ))
                .is_ok()
        );
    }

    #[test]
    fn rejects_untyped_and_inconsistent_credentials() {
        let verifier = verifier();
        assert!(matches!(
            verifier.authenticate(&token(&claims(ExtensionCallerKind::Gateway), None)),
            Err(VerificationError::UnexpectedTokenType)
        ));

        let mut inconsistent = claims(ExtensionCallerKind::Supervisor);
        inconsistent.sub = "spiffe://openshell/sandbox/someone-else".into();
        assert!(matches!(
            verifier.authenticate(&token(&inconsistent, Some(EXTENSION_JWT_TYP))),
            Err(VerificationError::InvalidClaims(_))
        ));
    }

    #[test]
    fn request_helper_returns_stable_unauthenticated_errors() {
        let verifier = verifier();
        assert_eq!(
            verifier
                .authenticate_request(&Request::new(()))
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );

        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("authorization", "Bearer invalid".parse().unwrap());
        let error = verifier.authenticate_request(&request).unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        assert_eq!(error.message(), "invalid extension token");
    }
}
