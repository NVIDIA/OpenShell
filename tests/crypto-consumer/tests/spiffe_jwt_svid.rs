// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Validates that SPIFFE JWT-SVID signing, verification, and claim extraction
//! work identically across crypto backends (aws-lc/Ring vs OpenSSL).
//!
//! Run with either backend:
//!   cargo test -p openshell-library-crypto-consumer --features runtime -- spiffe
//!   cargo test -p openshell-library-crypto-consumer --features openssl-runtime -- spiffe

use openshell_crypto::CryptoContext;
use std::sync::Once;

static INIT: Once = Once::new();

fn install_backend() {
    INIT.call_once(|| {
        #[cfg(feature = "runtime")]
        {
            // Ring-backed consumer context (same as selected_backend.rs)
            openshell_crypto::install_default_context(CryptoContext::new(Box::new(
                RingConsumer,
            )))
            .unwrap();
        }
        #[cfg(feature = "openssl-runtime")]
        {
            openshell_crypto::install_default_context(CryptoContext::new(Box::new(
                openshell_crypto::OpenSsl,
            )))
            .unwrap();
        }
    });
}

#[cfg(feature = "runtime")]
struct RingConsumer;

#[cfg(feature = "runtime")]
impl openshell_crypto::CryptoBackend for RingConsumer {
    fn capabilities(&self) -> openshell_crypto::Capabilities {
        openshell_crypto::Capabilities {
            backend: "ring-spiffe-test",
            provider_version: None,
            fips: openshell_crypto::FipsState::NotVerified,
            primitives: &[],
            key_algorithms: &[],
        }
    }
    fn fill_random(&self, buf: &mut [u8]) -> Result<(), openshell_crypto::CryptoError> {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(buf))
            .map_err(|_| openshell_crypto::CryptoError::Random)
    }
    fn sha256_digest(&self) -> Result<Box<dyn openshell_crypto::Digest>, openshell_crypto::CryptoError> {
        Err(openshell_crypto::CryptoError::Operation)
    }
    fn seal(&self, _: &[u8; 32], _: &[u8], _: &[u8]) -> Result<openshell_crypto::aead::Sealed, openshell_crypto::CryptoError> {
        Err(openshell_crypto::CryptoError::Operation)
    }
    fn open(&self, _: &[u8; 32], _: &[u8], _: &[u8; 12], _: &[u8]) -> Result<Vec<u8>, openshell_crypto::CryptoError> {
        Err(openshell_crypto::CryptoError::Authentication)
    }
}

#[cfg(feature = "runtime")]
impl openshell_crypto::ProtocolBackend for RingConsumer {
    fn tls_provider(&self) -> rustls::crypto::CryptoProvider {
        rustls::crypto::ring::default_provider()
    }
    fn jwt_provider(&self) -> &'static jsonwebtoken::crypto::CryptoProvider {
        &jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER
    }
    fn generate_keypair(
        &self,
        _: &'static rcgen::SignatureAlgorithm,
    ) -> Result<openshell_crypto::pki::KeyPair, rcgen::Error> {
        Err(rcgen::Error::RemoteKeyError)
    }
    fn import_keypair_der(&self, _: &[u8]) -> Result<openshell_crypto::pki::KeyPair, rcgen::Error> {
        Err(rcgen::Error::RemoteKeyError)
    }
    fn import_keypair_pem(&self, _: &str) -> Result<openshell_crypto::pki::KeyPair, rcgen::Error> {
        Err(rcgen::Error::RemoteKeyError)
    }
}

fn generate_ed25519_keypair() -> (String, String) {
    #[cfg(feature = "runtime")]
    {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        (key.serialize_pem(), key.public_key_pem())
    }
    #[cfg(feature = "openssl-runtime")]
    {
        let key = openshell_crypto::pki::generate_jwt_keypair().unwrap();
        (key.serialize_pem().unwrap(), key.public_key_pem())
    }
}

/// Sign and verify an EdDSA JWT-SVID with SPIFFE standard claims.
/// This is the core operation in the gateway SPIFFE token exchange flow:
/// SPIRE mints a JWT-SVID, the gateway verifies it, extracts the SPIFFE ID,
/// then exchanges it with Keycloak for a scoped access token.
#[test]
fn spiffe_eddsa_jwt_sign_and_verify() {
    install_backend();

    let (private_pem, public_pem) = generate_ed25519_keypair();
    let signing = jsonwebtoken::EncodingKey::from_ed_pem(private_pem.as_bytes()).unwrap();
    let verifying = jsonwebtoken::DecodingKey::from_ed_pem(public_pem.as_bytes()).unwrap();

    let claims = serde_json::json!({
        "sub": "spiffe://openshell.local/ns/openshell/sa/openshell-gateway",
        "iss": "https://oidc-discovery.example.com",
        "aud": ["model-api", "keycloak"],
        "exp": 4_000_000_000_u64,
        "iat": 1_700_000_000_u64
    });

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    let token = openshell_crypto::jwt::encode(&header, &claims, &signing).unwrap();

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_issuer(&["https://oidc-discovery.example.com"]);
    validation.set_audience(&["model-api"]);

    let decoded =
        openshell_crypto::jwt::decode::<serde_json::Value>(&token, &verifying, &validation)
            .unwrap();

    assert_eq!(
        decoded.claims["sub"],
        "spiffe://openshell.local/ns/openshell/sa/openshell-gateway"
    );
    assert_eq!(
        decoded.claims["aud"],
        serde_json::json!(["model-api", "keycloak"])
    );
}

/// Wrong audience must be rejected — the gateway checks `aud` before exchange.
#[test]
fn spiffe_jwt_wrong_audience_rejected() {
    install_backend();

    let (private_pem, public_pem) = generate_ed25519_keypair();
    let signing = jsonwebtoken::EncodingKey::from_ed_pem(private_pem.as_bytes()).unwrap();
    let verifying = jsonwebtoken::DecodingKey::from_ed_pem(public_pem.as_bytes()).unwrap();

    let claims = serde_json::json!({
        "sub": "spiffe://openshell.local/ns/openshell/sa/openshell-gateway",
        "iss": "https://oidc-discovery.example.com",
        "aud": "wrong-service",
        "exp": 4_000_000_000_u64
    });

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    let token = openshell_crypto::jwt::encode(&header, &claims, &signing).unwrap();

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_issuer(&["https://oidc-discovery.example.com"]);
    validation.set_audience(&["model-api"]);

    let err = openshell_crypto::jwt::decode::<serde_json::Value>(&token, &verifying, &validation)
        .unwrap_err();
    assert_eq!(
        err.kind(),
        &jsonwebtoken::errors::ErrorKind::InvalidAudience
    );
}

/// Tampered signature must be rejected — protects against SVID forgery.
#[test]
fn spiffe_jwt_tampered_signature_rejected() {
    install_backend();

    let (private_pem, public_pem) = generate_ed25519_keypair();
    let signing = jsonwebtoken::EncodingKey::from_ed_pem(private_pem.as_bytes()).unwrap();
    let verifying = jsonwebtoken::DecodingKey::from_ed_pem(public_pem.as_bytes()).unwrap();

    let claims = serde_json::json!({
        "sub": "spiffe://openshell.local/ns/openshell/sa/openshell-gateway",
        "iss": "https://oidc-discovery.example.com",
        "aud": "model-api",
        "exp": 4_000_000_000_u64
    });

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    let token = openshell_crypto::jwt::encode(&header, &claims, &signing).unwrap();

    // Tamper the signature
    let (message, sig) = token.rsplit_once('.').unwrap();
    let mut sig_bytes = sig.as_bytes().to_vec();
    sig_bytes[0] = if sig_bytes[0] == b'A' { b'B' } else { b'A' };
    let tampered = format!("{message}.{}", String::from_utf8(sig_bytes).unwrap());

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_issuer(&["https://oidc-discovery.example.com"]);
    validation.set_audience(&["model-api"]);

    let err =
        openshell_crypto::jwt::decode::<serde_json::Value>(&tampered, &verifying, &validation)
            .unwrap_err();
    assert_eq!(
        err.kind(),
        &jsonwebtoken::errors::ErrorKind::InvalidSignature
    );
}

/// Expired JWT-SVID must be rejected — SPIRE SVIDs have short TTLs.
#[test]
fn spiffe_jwt_expired_rejected() {
    install_backend();

    let (private_pem, public_pem) = generate_ed25519_keypair();
    let signing = jsonwebtoken::EncodingKey::from_ed_pem(private_pem.as_bytes()).unwrap();
    let verifying = jsonwebtoken::DecodingKey::from_ed_pem(public_pem.as_bytes()).unwrap();

    let claims = serde_json::json!({
        "sub": "spiffe://openshell.local/ns/openshell/sa/openshell-gateway",
        "iss": "https://oidc-discovery.example.com",
        "aud": "model-api",
        "exp": 1  // expired long ago
    });

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    let token = openshell_crypto::jwt::encode(&header, &claims, &signing).unwrap();

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_issuer(&["https://oidc-discovery.example.com"]);
    validation.set_audience(&["model-api"]);

    let err = openshell_crypto::jwt::decode::<serde_json::Value>(&token, &verifying, &validation)
        .unwrap_err();
    assert_eq!(
        err.kind(),
        &jsonwebtoken::errors::ErrorKind::ExpiredSignature
    );
}

/// Cross-key verification must fail — a JWT-SVID signed by one SPIRE server
/// must not verify with another server's key.
#[test]
fn spiffe_jwt_cross_key_rejected() {
    install_backend();

    let (private_pem, _) = generate_ed25519_keypair();
    let (_, other_public_pem) = generate_ed25519_keypair();

    let signing = jsonwebtoken::EncodingKey::from_ed_pem(private_pem.as_bytes()).unwrap();
    let wrong_verifier =
        jsonwebtoken::DecodingKey::from_ed_pem(other_public_pem.as_bytes()).unwrap();

    let claims = serde_json::json!({
        "sub": "spiffe://openshell.local/ns/openshell/sa/openshell-gateway",
        "iss": "https://oidc-discovery.example.com",
        "aud": "model-api",
        "exp": 4_000_000_000_u64
    });

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    let token = openshell_crypto::jwt::encode(&header, &claims, &signing).unwrap();

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_issuer(&["https://oidc-discovery.example.com"]);
    validation.set_audience(&["model-api"]);

    let err =
        openshell_crypto::jwt::decode::<serde_json::Value>(&token, &wrong_verifier, &validation)
            .unwrap_err();
    assert_eq!(
        err.kind(),
        &jsonwebtoken::errors::ErrorKind::InvalidSignature
    );
}
