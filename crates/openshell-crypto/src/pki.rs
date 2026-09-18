// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Backend-owned keys with rcgen used for certificate encoding and policy.

mod issuer;
pub use issuer::issuer_from_der;

use std::sync::Arc;

/// Backend-owned signing key.
///
/// Signatures use the declared rcgen algorithm's
/// encoding (DER ECDSA or raw Ed25519/RSA). Retain provider resources for the
/// full key lifetime; failed operations must never fall back to another backend.
pub trait SigningKey: Send + Sync {
    /// Certificate signing algorithm.
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm;
    /// Algorithm-specific public key bytes expected by rcgen remote keys.
    fn public_key_raw(&self) -> &[u8];
    /// Sign an unhashed message.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error>;
    /// Export PKCS#8 DER, or return an error for non-exportable keys.
    fn export_pkcs8_der(&self) -> Result<Vec<u8>, rcgen::Error>;
}

/// Owns a backend key and implements rcgen's signing contract directly.
/// Private key export remains a separate, fallible backend operation.
pub struct KeyPair {
    backend: Arc<dyn SigningKey>,
}
impl rcgen::PublicKeyData for KeyPair {
    fn der_bytes(&self) -> &[u8] {
        self.backend.public_key_raw()
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.backend.algorithm()
    }
}
impl rcgen::SigningKey for KeyPair {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.backend.sign(message)
    }
}

impl KeyPair {
    /// Wrap an independently implemented key without selecting crypto.
    pub fn new(key: Box<dyn SigningKey>) -> Result<Self, rcgen::Error> {
        let backend: Arc<dyn SigningKey> = Arc::from(key);
        Ok(Self { backend })
    }
    /// Import PEM through the selected backend.
    pub fn from_pem(pem: &str) -> Result<Self, rcgen::Error> {
        crate::default_context().backend().import_keypair_pem(pem)
    }
    /// Import PKCS#8 DER through the selected backend.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, rcgen::Error> {
        crate::default_context().backend().import_keypair_der(der)
    }
    /// Export the private key in PKCS#8 DER format, if permitted.
    pub fn serialize_der(&self) -> Result<Vec<u8>, rcgen::Error> {
        self.backend.export_pkcs8_der()
    }
    /// Export the private key in PKCS#8 PEM format, if permitted.
    pub fn serialize_pem(&self) -> Result<String, rcgen::Error> {
        let line_ending = if cfg!(target_family = "windows") {
            pem::LineEnding::CRLF
        } else {
            pem::LineEnding::LF
        };
        Ok(pem::encode_config(
            &pem::Pem::new("PRIVATE KEY", self.serialize_der()?),
            pem::EncodeConfig::new().set_line_ending(line_ending),
        ))
    }
    /// Public key in `SubjectPublicKeyInfo` DER format.
    #[must_use]
    pub fn public_key_der(&self) -> Vec<u8> {
        rcgen::PublicKeyData::subject_public_key_info(self)
    }
    /// Public key in `SubjectPublicKeyInfo` PEM format.
    #[must_use]
    pub fn public_key_pem(&self) -> String {
        pem::encode_config(
            &pem::Pem::new("PUBLIC KEY", self.public_key_der()),
            pem::EncodeConfig::new().set_line_ending(if cfg!(target_family = "windows") {
                pem::LineEnding::CRLF
            } else {
                pem::LineEnding::LF
            }),
        )
    }
    /// Signing algorithm.
    #[must_use]
    pub fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.backend.algorithm()
    }
}

/// Generate the existing default P-256 certificate key.
pub fn generate_keypair() -> Result<KeyPair, rcgen::Error> {
    generate_keypair_for(&rcgen::PKCS_ECDSA_P256_SHA256)
}
/// Generate a key through the selected backend.
pub fn generate_keypair_for(
    algorithm: &'static rcgen::SignatureAlgorithm,
) -> Result<KeyPair, rcgen::Error> {
    crate::default_context()
        .backend()
        .generate_keypair(algorithm)
}
/// Generate the existing Ed25519 JWT key.
pub fn generate_jwt_keypair() -> Result<KeyPair, rcgen::Error> {
    generate_keypair_for(&rcgen::PKCS_ED25519)
}
/// Encoded certificate and public issuance parameters, with no private key.
/// Parameters are retained because rcgen 0.14 separates certificates and issuers.
#[derive(Clone, Debug)]
pub struct Certificate {
    inner: rcgen::Certificate,
    params: rcgen::CertificateParams,
}
impl Certificate {
    /// DER certificate bytes.
    #[must_use]
    pub fn der(&self) -> &rustls::pki_types::CertificateDer<'static> {
        self.inner.der()
    }
    /// PEM certificate text.
    #[must_use]
    pub fn pem(&self) -> String {
        self.inner.pem()
    }
    /// Move the public issuer parameters and backend key into an issuer.
    #[must_use]
    pub fn into_issuer(self, key: KeyPair) -> rcgen::Issuer<'static, KeyPair> {
        rcgen::Issuer::new(self.params, key)
    }
}

/// Encode and sign a certificate using its backend-owned key.
pub fn self_signed(
    params: rcgen::CertificateParams,
    key: &KeyPair,
) -> Result<Certificate, rcgen::Error> {
    let params = prepare_params(params, key)?;
    let inner = params.self_signed(key)?;
    Ok(Certificate { inner, params })
}
/// Encode and sign a certificate using the backend-owned issuer key.
pub fn signed_by(
    params: rcgen::CertificateParams,
    key: &KeyPair,
    issuer: &Certificate,
    issuer_key: &KeyPair,
) -> Result<Certificate, rcgen::Error> {
    signed_by_issuer(
        params,
        key,
        &rcgen::Issuer::from_params(&issuer.params, issuer_key),
    )
}
/// Encode and sign using an issuer loaded from a persisted CA or generated locally.
pub fn signed_by_issuer(
    params: rcgen::CertificateParams,
    key: &KeyPair,
    issuer: &rcgen::Issuer<'_, impl rcgen::SigningKey>,
) -> Result<Certificate, rcgen::Error> {
    let params = prepare_params(params, key)?;
    let inner = params.signed_by(key, issuer)?;
    Ok(Certificate { inner, params })
}

/// A generated certificate and its backend-owned private key.
pub struct CertifiedKey {
    /// Generated self-signed certificate.
    pub cert: Certificate,
    /// Backend-owned key used to sign it.
    pub key_pair: KeyPair,
}
/// Generate a default certificate and key, primarily for local fixtures.
pub fn generate_simple_self_signed(
    names: impl Into<Vec<String>>,
) -> Result<CertifiedKey, rcgen::Error> {
    let key_pair = generate_keypair()?;
    let cert = self_signed(rcgen::CertificateParams::new(names)?, &key_pair)?;
    Ok(CertifiedKey { cert, key_pair })
}

// Preserve rcgen's default serial and key-ID derivation while routing hashing
// through the selected backend, including builds without rcgen's crypto feature.
fn prepare_params(
    mut params: rcgen::CertificateParams,
    key: &KeyPair,
) -> Result<rcgen::CertificateParams, rcgen::Error> {
    let hash = |bytes: &[u8]| crate::sha256(bytes).map_err(|_| rcgen::Error::RemoteKeyError);
    if params.serial_number.is_none() {
        let digest = hash(key.backend.public_key_raw())?;
        let mut serial = digest[..20].to_vec();
        serial[0] &= 0x7f;
        params.serial_number = Some(serial.into());
    }
    // rcgen defaults to SHA-256 with built-in crypto enabled, or an empty
    // pre-specified ID without it. Compare with its default rather than gating
    // on our own backend feature: another dependency may enable rcgen crypto.
    let derive =
        params.key_identifier_method == rcgen::CertificateParams::default().key_identifier_method;
    if !derive
        && !matches!(
            params.key_identifier_method,
            rcgen::KeyIdMethod::PreSpecified(_)
        )
    {
        return Err(rcgen::Error::UnsupportedSignatureAlgorithm);
    }
    if derive {
        params.key_identifier_method =
            rcgen::KeyIdMethod::PreSpecified(hash(&key.public_key_der())?[..20].to_vec());
    }
    Ok(params)
}
