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
const MAX_EXTENSION_TOKEN_TTL: Duration = Duration::from_hours(1);

/// SPIFFE trust domain used for sandbox identities unless the deployment
/// configures another one.
pub const DEFAULT_TRUST_DOMAIN: &str = "openshell";

type ErrorSource = Box<dyn std::error::Error + Send + Sync + 'static>;

/// `OpenShell` component authenticated as the caller of an extension service.
///
/// Tokens carrying a caller kind this SDK version does not know are rejected,
/// so a gateway that introduces a new kind requires an SDK upgrade first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct AuthenticatedCaller {
    pub kind: ExtensionCallerKind,
    pub subject: String,
    pub sandbox_id: Option<String>,
}

/// Verifies gateway-minted JWTs presented to an extension service.
///
/// Build one with [`GatewayJwtAuthenticator::builder`]. The public key or JWKS
/// document must come from a trusted operator channel; parsing key material
/// does not establish trust in it.
pub struct GatewayJwtAuthenticator {
    keys: HashMap<String, DecodingKey>,
    issuer: String,
    audience: String,
    trust_domain: String,
}

impl std::fmt::Debug for GatewayJwtAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayJwtAuthenticator")
            .field("key_ids", &self.keys.keys())
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("trust_domain", &self.trust_domain)
            .finish()
    }
}

impl GatewayJwtAuthenticator {
    /// Start configuring a verifier for tokens minted by `issuer` for `audience`.
    ///
    /// The issuer is exactly `openshell-gateway:<gateway_id>` and the audience
    /// is the exact value configured for this registration on the gateway.
    pub fn builder(
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> GatewayJwtAuthenticatorBuilder {
        GatewayJwtAuthenticatorBuilder {
            issuer: issuer.into(),
            audience: audience.into(),
            trust_domain: DEFAULT_TRUST_DOMAIN.to_string(),
            keys: Vec::new(),
        }
    }

    /// Verify a bearer token and return its normalized caller identity.
    pub fn authenticate(
        &self,
        bearer_token: &str,
    ) -> Result<AuthenticatedCaller, VerificationError> {
        let header = decode_header(bearer_token).map_err(invalid_token)?;
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
        validation.leeway = u64::try_from(CLOCK_SKEW_SECS).unwrap_or_default();
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["iss", "aud", "sub", "exp"]);

        let claims = decode::<ExtensionJwtClaims>(bearer_token, key, &validation)
            .map_err(invalid_token)?
            .claims;
        self.validate_claim_shape(&claims)?;
        Ok(AuthenticatedCaller {
            kind: claims.caller_kind,
            subject: claims.sub,
            sandbox_id: claims.sandbox_id,
        })
    }

    /// Extract and verify the bearer credential on a tonic request.
    ///
    /// The verification failure is logged at `warn` level and the caller
    /// receives a stable `Unauthenticated` status that does not expose verifier
    /// internals. Use [`Self::authenticate`] to inspect the failure directly.
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
        self.authenticate(token).map_err(|error| {
            tracing::warn!(error = %error, "extension caller authentication failed");
            Status::unauthenticated("invalid extension token")
        })
    }

    fn validate_claim_shape(&self, claims: &ExtensionJwtClaims) -> Result<(), VerificationError> {
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
                    && claims.sub
                        == format!("spiffe://{}/sandbox/{sandbox_id}", self.trust_domain) =>
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
}

fn invalid_token(error: jsonwebtoken::errors::Error) -> VerificationError {
    VerificationError::InvalidToken(Box::new(error))
}

enum KeySource {
    Ed25519Pem { key_id: String, pem: Vec<u8> },
    Jwks(Vec<u8>),
}

/// Configures a [`GatewayJwtAuthenticator`].
///
/// At least one trusted key source is required. Additional options are added
/// as methods so existing callers keep compiling when the SDK grows.
pub struct GatewayJwtAuthenticatorBuilder {
    issuer: String,
    audience: String,
    trust_domain: String,
    keys: Vec<KeySource>,
}

impl std::fmt::Debug for GatewayJwtAuthenticatorBuilder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayJwtAuthenticatorBuilder")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("trust_domain", &self.trust_domain)
            .field("key_sources", &self.keys.len())
            .finish()
    }
}

impl GatewayJwtAuthenticatorBuilder {
    /// Trust one Ed25519 public key in PEM form under the given `kid`.
    #[must_use]
    pub fn ed25519_pem(mut self, key_id: impl Into<String>, public_key_pem: &[u8]) -> Self {
        self.keys.push(KeySource::Ed25519Pem {
            key_id: key_id.into(),
            pem: public_key_pem.to_vec(),
        });
        self
    }

    /// Trust every Ed25519 signing key in a JWKS document.
    #[must_use]
    pub fn jwks(mut self, jwks_json: &[u8]) -> Self {
        self.keys.push(KeySource::Jwks(jwks_json.to_vec()));
        self
    }

    /// Override the SPIFFE trust domain expected in supervisor subjects.
    ///
    /// Defaults to [`DEFAULT_TRUST_DOMAIN`].
    #[must_use]
    pub fn trust_domain(mut self, trust_domain: impl Into<String>) -> Self {
        self.trust_domain = trust_domain.into();
        self
    }

    pub fn build(self) -> Result<GatewayJwtAuthenticator, VerificationError> {
        if self.issuer.is_empty() || self.audience.is_empty() {
            return Err(VerificationError::EmptyExpectedIdentity);
        }
        if self.trust_domain.is_empty() || self.trust_domain.contains('/') {
            return Err(VerificationError::InvalidTrustDomain);
        }

        let mut keys = HashMap::new();
        for source in self.keys {
            match source {
                KeySource::Ed25519Pem { key_id, pem } => {
                    if key_id.is_empty() {
                        return Err(VerificationError::MissingKeyId);
                    }
                    let key = DecodingKey::from_ed_pem(&pem)
                        .map_err(|error| VerificationError::InvalidPublicKey(Box::new(error)))?;
                    insert_key(&mut keys, key_id, key)?;
                }
                KeySource::Jwks(json) => {
                    let jwks: JwkSet = serde_json::from_slice(&json)
                        .map_err(|error| VerificationError::InvalidJwks(Box::new(error)))?;
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
                        insert_key(&mut keys, key_id, key)?;
                    }
                }
            }
        }
        if keys.is_empty() {
            return Err(VerificationError::EmptyKeySet);
        }

        Ok(GatewayJwtAuthenticator {
            keys,
            issuer: self.issuer,
            audience: self.audience,
            trust_domain: self.trust_domain,
        })
    }
}

fn insert_key(
    keys: &mut HashMap<String, DecodingKey>,
    key_id: String,
    key: DecodingKey,
) -> Result<(), VerificationError> {
    if keys.insert(key_id.clone(), key).is_some() {
        return Err(VerificationError::DuplicateKeyId(key_id));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerificationError {
    #[error("invalid JWKS document: {0}")]
    InvalidJwks(#[source] ErrorSource),
    #[error("invalid Ed25519 public key: {0}")]
    InvalidPublicKey(#[source] ErrorSource),
    #[error("extension key is missing a key ID")]
    MissingKeyId,
    #[error("trusted key set contains duplicate key ID '{0}'")]
    DuplicateKeyId(String),
    #[error("JWKS key '{0}' is not a supported Ed25519 signing key")]
    UnsupportedKey(String),
    #[error("extension key set is empty")]
    EmptyKeySet,
    #[error("expected issuer and audience must not be empty")]
    EmptyExpectedIdentity,
    #[error("trust domain must be a non-empty SPIFFE trust domain name")]
    InvalidTrustDomain,
    #[error("token does not use the OpenShell extension JWT type")]
    UnexpectedTokenType,
    #[error("token does not use EdDSA")]
    UnexpectedAlgorithm,
    #[error("token header does not contain a key ID")]
    MissingTokenKeyId,
    #[error("token references unknown key ID '{0}'")]
    UnknownKeyId(String),
    #[error("token validation failed: {0}")]
    InvalidToken(#[source] ErrorSource),
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
    const ISSUER: &str = "openshell-gateway:test";
    const AUDIENCE: &str = "urn:openshell:extension:middleware:test";

    fn claims(kind: ExtensionCallerKind) -> ExtensionJwtClaims {
        let now = i64::try_from(jsonwebtoken::get_current_timestamp()).unwrap();
        let (subject, sandbox_id) = match kind {
            ExtensionCallerKind::Gateway => (ISSUER.into(), None),
            ExtensionCallerKind::Supervisor => (
                "spiffe://openshell/sandbox/sandbox-1".into(),
                Some("sandbox-1".into()),
            ),
        };
        ExtensionJwtClaims {
            iss: ISSUER.into(),
            aud: AUDIENCE.into(),
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
        GatewayJwtAuthenticator::builder(ISSUER, AUDIENCE)
            .jwks(JWKS)
            .build()
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
    fn pem_and_jwks_sources_accept_the_same_key() {
        let verifier = GatewayJwtAuthenticator::builder(ISSUER, AUDIENCE)
            .ed25519_pem("test-key", PUBLIC_KEY)
            .build()
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
    fn builder_rejects_incomplete_or_conflicting_trust_configuration() {
        assert!(matches!(
            GatewayJwtAuthenticator::builder(ISSUER, AUDIENCE).build(),
            Err(VerificationError::EmptyKeySet)
        ));
        assert!(matches!(
            GatewayJwtAuthenticator::builder("", AUDIENCE)
                .jwks(JWKS)
                .build(),
            Err(VerificationError::EmptyExpectedIdentity)
        ));
        assert!(matches!(
            GatewayJwtAuthenticator::builder(ISSUER, AUDIENCE)
                .jwks(JWKS)
                .ed25519_pem("test-key", PUBLIC_KEY)
                .build(),
            Err(VerificationError::DuplicateKeyId(key_id)) if key_id == "test-key"
        ));
        assert!(matches!(
            GatewayJwtAuthenticator::builder(ISSUER, AUDIENCE)
                .jwks(JWKS)
                .trust_domain("bad/domain")
                .build(),
            Err(VerificationError::InvalidTrustDomain)
        ));
        assert!(matches!(
            GatewayJwtAuthenticator::builder(ISSUER, AUDIENCE)
                .jwks(b"not json")
                .build(),
            Err(VerificationError::InvalidJwks(_))
        ));
    }

    #[test]
    fn supervisor_subject_must_match_the_configured_trust_domain() {
        let mut other_domain = claims(ExtensionCallerKind::Supervisor);
        other_domain.sub = "spiffe://example.org/sandbox/sandbox-1".into();
        let signed = token(&other_domain, Some(EXTENSION_JWT_TYP));

        assert!(matches!(
            verifier().authenticate(&signed),
            Err(VerificationError::InvalidClaims(_))
        ));
        let configured = GatewayJwtAuthenticator::builder(ISSUER, AUDIENCE)
            .jwks(JWKS)
            .trust_domain("example.org")
            .build()
            .unwrap();
        assert_eq!(
            configured
                .authenticate(&signed)
                .unwrap()
                .sandbox_id
                .as_deref(),
            Some("sandbox-1")
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
