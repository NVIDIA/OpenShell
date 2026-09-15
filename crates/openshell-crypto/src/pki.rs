// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! rcgen adapter. Certificate policy remains with the caller; key operations
//! route through the selected backend. No algorithm or format migration occurs.

/// Generate the existing default ECDSA P-256 certificate key.
pub fn generate_keypair() -> Result<rcgen::KeyPair, rcgen::Error> {
    generate_keypair_for(&rcgen::PKCS_ECDSA_P256_SHA256)
}

/// Generate a key for an explicit protocol algorithm.
pub fn generate_keypair_for(
    algorithm: &'static rcgen::SignatureAlgorithm,
) -> Result<rcgen::KeyPair, rcgen::Error> {
    crate::default_context()
        .backend()
        .generate_keypair(algorithm)
}

/// Generate the existing Ed25519 gateway JWT key.
pub fn generate_jwt_keypair() -> Result<rcgen::KeyPair, rcgen::Error> {
    generate_keypair_for(&rcgen::PKCS_ED25519)
}

/// Sign a certificate using its own key.
pub fn self_signed(
    params: rcgen::CertificateParams,
    key: &rcgen::KeyPair,
) -> Result<rcgen::Certificate, rcgen::Error> {
    params.self_signed(key)
}

/// Sign a certificate with an issuer, retaining rcgen's encoding and validation.
pub fn signed_by(
    params: rcgen::CertificateParams,
    key: &rcgen::KeyPair,
    issuer: &rcgen::Certificate,
    issuer_key: &rcgen::KeyPair,
) -> Result<rcgen::Certificate, rcgen::Error> {
    params.signed_by(key, issuer, issuer_key)
}
