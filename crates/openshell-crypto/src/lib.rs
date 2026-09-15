// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Backend-neutral crypto operations and library-specific protocol adapters.
//!
//! AWS-LC is the only production implementation in this first stage. This crate
//! does not enable FIPS mode, change algorithms, or attest dependency-owned crypto.
//! See the crate README for initialization and extension boundaries.

pub mod aead;
mod aws_lc;
pub mod jwt;
pub mod pki;
pub mod tls;

use std::sync::{Arc, OnceLock};

/// Errors contain no key material or authentication-failure details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// A backend could not obtain cryptographic randomness.
    #[error("cryptographic random generation failed")]
    Random,
    /// Encryption or key initialization failed.
    #[error("cryptographic operation failed")]
    Operation,
    /// Authentication failed; do not distinguish key, nonce, AAD, or tag errors.
    #[error("ciphertext authentication failed")]
    Authentication,
    /// The installed process provider was not verified as this context's provider.
    #[error("process crypto provider is not owned by this context")]
    ProviderConflict,
    /// The requested operating mode is not verified by this backend.
    #[error("required crypto posture is unavailable")]
    UnsupportedPosture,
}

/// Module status, scoped to this backend's operations, not the deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FipsState {
    /// No validated operating mode is asserted.
    NotVerified,
}

/// Operations implemented by a backend. Protocol coverage is documented separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// Stable backend identifier.
    pub backend: &'static str,
    /// Underlying module version, if available from the backend API.
    pub provider_version: Option<&'static str>,
    /// Effective module posture; an unknown version must not become a claim.
    pub fips: FipsState,
    /// Primitive operations supported by this implementation.
    pub primitives: &'static [&'static str],
    /// Key generation algorithms available through the PKI adapter.
    pub key_algorithms: &'static [&'static str],
}

/// Object-safe incremental SHA-256 computation.
pub trait Digest: Send {
    /// Append bytes without allocating a concatenated message.
    fn update(&mut self, bytes: &[u8]);
    /// Consume the state and return the digest.
    fn finish(self: Box<Self>) -> [u8; 32];
}

/// Primitive contract. No concrete crypto-library types cross this boundary.
///
/// Implementations must not fall back to another backend after an operation fails.
/// Protocol adapters are separate because their types and validation semantics
/// belong to the corresponding protocol library.
pub trait CryptoBackend: Send + Sync {
    /// Describe implemented operations without claiming whole-process coverage.
    fn capabilities(&self) -> Capabilities;
    /// Fill the entire output or report an entropy failure.
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError>;
    /// Create an incremental SHA-256 computation.
    fn sha256_digest(&self) -> Box<dyn Digest>;
    /// Encrypt with a fresh random 96-bit nonce, appending the 128-bit GCM tag.
    fn seal(
        &self,
        key: &[u8; 32],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<aead::Sealed, CryptoError>;
    /// Authenticate before returning plaintext. All authentication failures are opaque.
    fn open(
        &self,
        key: &[u8; 32],
        aad: &[u8],
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

/// Adapters for the protocol libraries currently used by `OpenShell`.
///
/// A follow-up backend must implement these as well as the primitive contract.
/// Returning rcgen/rustls/jsonwebtoken types does not expose AWS-LC types.
pub trait ProtocolBackend: CryptoBackend {
    /// Construct the full TLS provider, including certificate verification.
    fn tls_provider(&self) -> rustls::crypto::CryptoProvider;
    /// Generate a key for the requested certificate/JWT algorithm.
    fn generate_keypair(
        &self,
        algorithm: &'static rcgen::SignatureAlgorithm,
    ) -> Result<rcgen::KeyPair, rcgen::Error>;
    /// JWT signing, verification, and JWK operations; claims validation stays in jsonwebtoken.
    fn jwt_provider(&self) -> &'static jsonwebtoken::crypto::CryptoProvider;
}

/// Explicit backend context for embedders and contract tests.
///
/// Construction does not modify process-global providers. Retaining the context
/// retains backend resources. Select the application default before first use.
#[derive(Clone)]
pub struct CryptoContext {
    backend: Arc<dyn ProtocolBackend>,
}

impl CryptoContext {
    /// Construct a context without changing any process globals.
    #[must_use]
    pub fn new(backend: Box<dyn ProtocolBackend>) -> Self {
        Self {
            backend: Arc::from(backend),
        }
    }

    /// The selected operations and protocol adapters.
    #[must_use]
    pub fn backend(&self) -> &dyn ProtocolBackend {
        self.backend.as_ref()
    }

    /// Verify the backend's limited posture. Strict FIPS is deliberately unsupported.
    pub fn verify_posture(&self, require_fips: bool) -> Result<Capabilities, CryptoError> {
        if require_fips {
            return Err(CryptoError::UnsupportedPosture);
        }
        Ok(self.backend.capabilities())
    }
}

impl Default for CryptoContext {
    fn default() -> Self {
        Self::new(Box::new(aws_lc::AwsLc))
    }
}

static DEFAULT: OnceLock<CryptoContext> = OnceLock::new();

/// Application default, initialized lazily to AWS-LC unless selected before first use.
#[must_use]
pub fn default_context() -> &'static CryptoContext {
    DEFAULT.get_or_init(CryptoContext::default)
}

/// Select a context before the first application crypto operation.
///
/// Reinstalling a clone of the same context is idempotent. A different context
/// fails even if it reports the same backend name. This does not replace existing
/// Rustls or JWT globals: embedders must select before initializing those libraries.
pub fn install_default_context(context: CryptoContext) -> Result<(), CryptoError> {
    match DEFAULT.set(context) {
        Ok(()) => Ok(()),
        Err(context) if Arc::ptr_eq(&default_context().backend, &context.backend) => Ok(()),
        Err(_) => Err(CryptoError::ProviderConflict),
    }
}

/// Fill bytes using the application backend.
pub fn fill_random(output: &mut [u8]) -> Result<(), CryptoError> {
    default_context().backend().fill_random(output)
}

/// Generate a fixed-size random value.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut output = [0; N];
    fill_random(&mut output)?;
    Ok(output)
}

/// Create an incremental SHA-256 computation.
#[must_use]
pub fn sha256_digest() -> Box<dyn Digest> {
    default_context().backend().sha256_digest()
}

/// Compute SHA-256 using the selected implementation.
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut digest = sha256_digest();
    digest.update(bytes);
    digest.finish()
}

/// Install the JWT adapter if no provider has been installed.
///
/// jsonwebtoken 10 does not expose its installed provider. A false return means
/// ownership cannot be verified, including when it auto-installed the same backend.
/// This preserves the existing embedder behavior; it is not a posture check.
pub fn install_jwt_provider() -> bool {
    default_context()
        .backend()
        .jwt_provider()
        .install_default()
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_known_answer_and_streaming_agree() {
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(sha256(b"abc"), expected);
        let mut digest = sha256_digest();
        digest.update(b"a");
        digest.update(b"bc");
        assert_eq!(digest.finish(), expected);
    }

    #[test]
    fn aead_authenticates_every_input() {
        let key = [7; 32];
        let sealed = aead::seal(&key, b"record", b"secret").unwrap();
        assert_eq!(sealed.ciphertext.len(), 6 + 16);
        assert_eq!(
            aead::open(&key, b"record", &sealed.nonce, &sealed.ciphertext).unwrap(),
            b"secret"
        );
        let mut bad_nonce = sealed.nonce;
        bad_nonce[0] ^= 1;
        let mut bad_tag = sealed.ciphertext.clone();
        *bad_tag.last_mut().unwrap() ^= 1;
        for result in [
            aead::open(&[8; 32], b"record", &sealed.nonce, &sealed.ciphertext),
            aead::open(&key, b"other", &sealed.nonce, &sealed.ciphertext),
            aead::open(&key, b"record", &bad_nonce, &sealed.ciphertext),
            aead::open(&key, b"record", &sealed.nonce, &bad_tag),
            aead::open(&key, b"record", &sealed.nonce, &sealed.ciphertext[..15]),
        ] {
            assert_eq!(result, Err(CryptoError::Authentication));
        }
        let empty = aead::seal(&key, b"", b"").unwrap();
        assert!(
            aead::open(&key, b"", &empty.nonce, &empty.ciphertext)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn aes256_gcm_decrypts_known_answer() {
        // NIST AES-GCM: 256-bit zero key, 96-bit zero IV, empty AAD/plaintext.
        let tag = [
            0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
            0x73, 0x8b,
        ];
        assert_eq!(aead::open(&[0; 32], b"", &[0; 12], &tag).unwrap(), b"");
    }

    #[test]
    fn jwt_preserves_eddsa_and_claim_validation() {
        let key = pki::generate_jwt_keypair().unwrap();
        assert_eq!(key.algorithm(), &rcgen::PKCS_ED25519);
        let signing =
            jsonwebtoken::EncodingKey::from_ed_pem(key.serialize_pem().as_bytes()).unwrap();
        let verifying =
            jsonwebtoken::DecodingKey::from_ed_pem(key.public_key_pem().as_bytes()).unwrap();
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
        let claims = serde_json::json!({"sub":"sandbox", "iss":"gateway", "exp":4_000_000_000_u64});
        let token = jwt::encode(&header, &claims, &signing).unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_issuer(&["gateway"]);
        let decoded = jwt::decode::<serde_json::Value>(&token, &verifying, &validation).unwrap();
        assert_eq!(decoded.claims, claims);
        validation.set_issuer(&["different"]);
        assert!(jwt::decode::<serde_json::Value>(&token, &verifying, &validation).is_err());
        let expired = jwt::encode(&header, &serde_json::json!({"exp":1}), &signing).unwrap();
        assert!(jwt::decode::<serde_json::Value>(&expired, &verifying, &validation).is_err());
        assert!(jwt::encode(&jsonwebtoken::Header::default(), &claims, &signing).is_err());
    }

    struct NoEntropy;
    impl CryptoBackend for NoEntropy {
        fn capabilities(&self) -> Capabilities {
            let mut caps = aws_lc::AwsLc.capabilities();
            caps.backend = "test-no-entropy";
            caps.primitives = &["SHA-256"];
            caps
        }
        fn fill_random(&self, _: &mut [u8]) -> Result<(), CryptoError> {
            Err(CryptoError::Random)
        }
        fn sha256_digest(&self) -> Box<dyn Digest> {
            aws_lc::AwsLc.sha256_digest()
        }
        fn seal(&self, _: &[u8; 32], _: &[u8], _: &[u8]) -> Result<aead::Sealed, CryptoError> {
            Err(CryptoError::Random)
        }
        fn open(
            &self,
            _: &[u8; 32],
            _: &[u8],
            _: &[u8; 12],
            _: &[u8],
        ) -> Result<Vec<u8>, CryptoError> {
            Err(CryptoError::Operation)
        }
    }
    impl ProtocolBackend for NoEntropy {
        fn tls_provider(&self) -> rustls::crypto::CryptoProvider {
            aws_lc::AwsLc.tls_provider()
        }
        fn generate_keypair(
            &self,
            _: &'static rcgen::SignatureAlgorithm,
        ) -> Result<rcgen::KeyPair, rcgen::Error> {
            Err(rcgen::Error::KeyGenerationUnavailable)
        }
        fn jwt_provider(&self) -> &'static jsonwebtoken::crypto::CryptoProvider {
            aws_lc::AwsLc.jwt_provider()
        }
    }

    #[test]
    fn context_substitution_propagates_failure_without_fallback() {
        let context = CryptoContext::new(Box::new(NoEntropy));
        assert_eq!(
            context.verify_posture(false).unwrap().backend,
            "test-no-entropy"
        );
        assert_eq!(
            context.backend().fill_random(&mut [0; 32]),
            Err(CryptoError::Random)
        );
        assert_eq!(
            context.backend().seal(&[0; 32], b"", b"secret"),
            Err(CryptoError::Random)
        );
        assert!(
            context
                .backend()
                .generate_keypair(&rcgen::PKCS_ED25519)
                .is_err()
        );
        assert_eq!(
            context.verify_posture(true),
            Err(CryptoError::UnsupportedPosture)
        );
        assert_eq!(
            default_context().verify_posture(false).unwrap().backend,
            "aws-lc"
        );
        assert_eq!(
            default_context().verify_posture(true),
            Err(CryptoError::UnsupportedPosture)
        );
        assert_eq!(
            install_default_context(context),
            Err(CryptoError::ProviderConflict)
        );
    }
}
