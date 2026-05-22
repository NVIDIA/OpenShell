// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-minted JWT signing-key generation.
//!
//! The gateway mints per-sandbox identity tokens (see PR 2 of the
//! per-sandbox identity series, issue #1354) signed with an Ed25519
//! keypair generated once at gateway init and persisted alongside the
//! existing PKI bundle. The signing key never leaves the gateway; the
//! public key plus a stable `kid` are consumed by the gateway's own
//! validator and any future external verifiers.

use miette::{IntoDiagnostic, Result, WrapErr};
use rcgen::{KeyPair, PKCS_ED25519};
use sha2::{Digest, Sha256};

/// All PEM-encoded material needed to mint and validate sandbox JWTs.
///
/// The signing key stays in the gateway process. The public key is shared
/// across gateway replicas (so any replica can validate a JWT minted by
/// any other replica). The `kid` is published in every minted JWT's
/// header so the validator can pick the right key after a future rotation.
pub struct JwtKeyMaterial {
    /// PKCS#8 PEM-encoded Ed25519 private key.
    pub signing_key_pem: String,
    /// `SubjectPublicKeyInfo` PEM-encoded Ed25519 public key.
    pub public_key_pem: String,
    /// Stable identifier derived from the public key (SHA-256 hex prefix).
    /// Embedded in every minted JWT's `kid` header so future rotation can
    /// be performed in-place by adding a second key without breaking
    /// in-flight tokens.
    pub kid: String,
}

/// Generate a fresh Ed25519 JWT signing key.
///
/// Output PEM is in the formats `jsonwebtoken` consumes via
/// `EncodingKey::from_ed_pem` (signing) and `DecodingKey::from_ed_pem`
/// (validation), so the gateway can round-trip its own tokens with no
/// further conversion.
pub fn generate_jwt_key() -> Result<JwtKeyMaterial> {
    let keypair = KeyPair::generate_for(&PKCS_ED25519)
        .into_diagnostic()
        .wrap_err("failed to generate Ed25519 JWT signing key")?;
    let signing_key_pem = keypair.serialize_pem();
    let public_key_pem = keypair.public_key_pem();
    let kid = kid_from_public_key_der(&keypair.public_key_der());
    Ok(JwtKeyMaterial {
        signing_key_pem,
        public_key_pem,
        kid,
    })
}

/// Stable `kid` derived from the SHA-256 of the public-key DER.
///
/// First 16 bytes hex-encoded — collision-resistant for the small N of
/// signing keys a single deployment ever has, while staying short enough
/// to keep JWT headers compact.
fn kid_from_public_key_der(public_key_der: &[u8]) -> String {
    let digest = Sha256::digest(public_key_der);
    hex_encode_prefix(&digest, 16)
}

fn hex_encode_prefix(bytes: &[u8], n: usize) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(n * 2);
    for byte in bytes.iter().take(n) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_jwt_key_produces_parseable_pem() {
        let material = generate_jwt_key().expect("generate_jwt_key");
        assert!(material.signing_key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(material.public_key_pem.contains("BEGIN PUBLIC KEY"));
        assert_eq!(material.kid.len(), 32, "kid is 16 bytes hex-encoded");
        assert!(material.kid.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn kid_is_stable_for_identical_public_keys() {
        // Same input -> same kid. Hash of a fixed byte string.
        let kid_a = kid_from_public_key_der(b"abc");
        let kid_b = kid_from_public_key_der(b"abc");
        assert_eq!(kid_a, kid_b);
    }

    #[test]
    fn kid_differs_for_different_public_keys() {
        let kid_a = kid_from_public_key_der(b"first");
        let kid_b = kid_from_public_key_der(b"second");
        assert_ne!(kid_a, kid_b);
    }

    #[test]
    fn generated_keys_are_unique() {
        let a = generate_jwt_key().expect("generate_jwt_key");
        let b = generate_jwt_key().expect("generate_jwt_key");
        assert_ne!(
            a.kid, b.kid,
            "fresh keypairs must produce distinct public keys"
        );
        assert_ne!(a.signing_key_pem, b.signing_key_pem);
    }
}
