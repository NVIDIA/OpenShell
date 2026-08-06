// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Prototype service-side authentication support kept local to this example.
//!
//! This module is expected to move into an SDK for building OpenShell
//! extensions once its API and JWKS refresh behavior are ready to stabilize.

use std::collections::HashMap;

use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, EllipticCurve, JwkSet, PublicKeyUse},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const CLOCK_SKEW_SECS: i64 = 30;
const MAX_TOKEN_TTL_SECS: i64 = 3_600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionCallerKind {
    Gateway,
    Supervisor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionJwtClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub caller_kind: ExtensionCallerKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
}

/// Verifies gateway-minted JWTs presented to this middleware service.
///
/// The operator must obtain the JWKS document from a trusted gateway URL or
/// provision it out of band. Constructing this verifier does not establish
/// trust in the document by itself.
pub struct ExtensionJwtVerifier {
    keys: HashMap<String, DecodingKey>,
    issuer: String,
    audience: String,
}

impl std::fmt::Debug for ExtensionJwtVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtensionJwtVerifier")
            .field("key_ids", &self.keys.keys())
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .finish()
    }
}

impl ExtensionJwtVerifier {
    pub fn from_jwks(
        jwks_json: &[u8],
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self, VerificationError> {
        let jwks: JwkSet = serde_json::from_slice(jwks_json)?;
        let mut keys = HashMap::with_capacity(jwks.keys.len());

        for jwk in jwks.keys {
            let kid = jwk
                .common
                .key_id
                .clone()
                .filter(|kid| !kid.is_empty())
                .ok_or(VerificationError::MissingKeyId)?;
            let is_ed25519_signing_key = jwk.common.key_algorithm
                == Some(jsonwebtoken::jwk::KeyAlgorithm::EdDSA)
                && jwk.common.public_key_use == Some(PublicKeyUse::Signature)
                && matches!(
                    &jwk.algorithm,
                    AlgorithmParameters::OctetKeyPair(parameters)
                        if parameters.curve == EllipticCurve::Ed25519
                );
            if !is_ed25519_signing_key {
                return Err(VerificationError::UnsupportedKey(kid));
            }
            let key = DecodingKey::from_jwk(&jwk)
                .map_err(|_| VerificationError::UnsupportedKey(kid.clone()))?;
            if keys.insert(kid.clone(), key).is_some() {
                return Err(VerificationError::DuplicateKeyId(kid));
            }
        }

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

    pub fn verify(&self, token: &str) -> Result<ExtensionJwtClaims, VerificationError> {
        let header = decode_header(token).map_err(VerificationError::InvalidToken)?;
        if header.alg != Algorithm::EdDSA {
            return Err(VerificationError::UnexpectedAlgorithm);
        }
        let kid = header
            .kid
            .as_deref()
            .filter(|kid| !kid.is_empty())
            .ok_or(VerificationError::MissingTokenKeyId)?;
        let key = self
            .keys
            .get(kid)
            .ok_or_else(|| VerificationError::UnknownKeyId(kid.to_string()))?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.algorithms = vec![Algorithm::EdDSA];
        validation.leeway = u64::try_from(CLOCK_SKEW_SECS).unwrap_or_default();
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);

        let claims = decode::<ExtensionJwtClaims>(token, key, &validation)
            .map_err(VerificationError::InvalidToken)?
            .claims;
        validate_claim_shape(&claims)?;
        Ok(claims)
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
    let lifetime = claims.exp.saturating_sub(claims.iat);
    if lifetime > MAX_TOKEN_TTL_SECS {
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

    match (&claims.caller_kind, &claims.sandbox_id) {
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

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("invalid JWKS document: {0}")]
    InvalidJwks(#[from] serde_json::Error),
    #[error("JWKS contains a key without a kid")]
    MissingKeyId,
    #[error("JWKS contains duplicate kid '{0}'")]
    DuplicateKeyId(String),
    #[error("JWKS key '{0}' is not a supported Ed25519 signing key")]
    UnsupportedKey(String),
    #[error("JWKS contains no keys")]
    EmptyKeySet,
    #[error("expected issuer and audience must not be empty")]
    EmptyExpectedIdentity,
    #[error("token does not use EdDSA")]
    UnexpectedAlgorithm,
    #[error("token header does not contain a kid")]
    MissingTokenKeyId,
    #[error("token references unknown kid '{0}'")]
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
    const JWKS: &[u8] = br#"{"keys":[{"kty":"OKP","use":"sig","crv":"Ed25519","x":"2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8","kid":"test-key","alg":"EdDSA"}]}"#;

    fn claims(caller_kind: ExtensionCallerKind) -> ExtensionJwtClaims {
        let now = i64::try_from(jsonwebtoken::get_current_timestamp()).unwrap();
        let (sub, sandbox_id) = match caller_kind {
            ExtensionCallerKind::Gateway => ("openshell-gateway:test".into(), None),
            ExtensionCallerKind::Supervisor => (
                "spiffe://openshell/sandbox/sandbox-1".into(),
                Some("sandbox-1".into()),
            ),
        };
        ExtensionJwtClaims {
            iss: "openshell-gateway:test".into(),
            aud: "urn:openshell:extension:middleware:test".into(),
            sub,
            iat: now,
            exp: now + 300,
            jti: "unique".into(),
            caller_kind,
            sandbox_id,
        }
    }

    fn token(claims: &ExtensionJwtClaims) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("test-key".into());
        encode(
            &header,
            claims,
            &EncodingKey::from_ed_pem(PRIVATE_KEY).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn verifies_gateway_and_supervisor_claims() {
        let verifier = ExtensionJwtVerifier::from_jwks(
            JWKS,
            "openshell-gateway:test",
            "urn:openshell:extension:middleware:test",
        )
        .unwrap();

        for caller_kind in [
            ExtensionCallerKind::Gateway,
            ExtensionCallerKind::Supervisor,
        ] {
            assert_eq!(
                verifier
                    .verify(&token(&claims(caller_kind)))
                    .unwrap()
                    .caller_kind,
                caller_kind
            );
        }
    }

    #[test]
    fn rejects_wrong_audience_and_inconsistent_subject() {
        let verifier = ExtensionJwtVerifier::from_jwks(
            JWKS,
            "openshell-gateway:test",
            "urn:openshell:extension:middleware:test",
        )
        .unwrap();
        let mut wrong_audience = claims(ExtensionCallerKind::Gateway);
        wrong_audience.aud = "different".into();
        assert!(verifier.verify(&token(&wrong_audience)).is_err());

        let mut wrong_subject = claims(ExtensionCallerKind::Supervisor);
        wrong_subject.sub = "spiffe://openshell/sandbox/someone-else".into();
        assert!(matches!(
            verifier.verify(&token(&wrong_subject)),
            Err(VerificationError::InvalidClaims(_))
        ));
    }
}
