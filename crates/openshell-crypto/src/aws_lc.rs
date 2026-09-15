// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The sole production backend. Backend-specific imports belong here.

use crate::{Capabilities, CryptoBackend, CryptoError, Digest, FipsState, ProtocolBackend};
use aws_lc_rs::{
    aead, digest,
    rand::{SecureRandom, SystemRandom},
};

pub struct AwsLc;
struct Sha256(digest::Context);

impl Digest for Sha256 {
    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    fn finish(self: Box<Self>) -> [u8; 32] {
        let mut output = [0; 32];
        output.copy_from_slice(self.0.finish().as_ref());
        output
    }
}

impl CryptoBackend for AwsLc {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            backend: "aws-lc",
            provider_version: None,
            fips: FipsState::NotVerified,
            primitives: &["CSPRNG", "SHA-256", "AES-256-GCM"],
            key_algorithms: &["ECDSA-P256-SHA256", "ECDSA-P384-SHA384", "Ed25519"],
        }
    }
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        SystemRandom::new()
            .fill(output)
            .map_err(|_| CryptoError::Random)
    }
    fn sha256_digest(&self) -> Box<dyn Digest> {
        Box::new(Sha256(digest::Context::new(&digest::SHA256)))
    }
    fn seal(
        &self,
        key: &[u8; 32],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<crate::aead::Sealed, CryptoError> {
        let mut nonce = [0; 12];
        self.fill_random(&mut nonce)?;
        let mut ciphertext = plaintext.to_vec();
        key_handle(key)?
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                &mut ciphertext,
            )
            .map_err(|_| CryptoError::Operation)?;
        Ok(crate::aead::Sealed { nonce, ciphertext })
    }
    fn open(
        &self,
        key: &[u8; 32],
        aad: &[u8],
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut buffer = ciphertext.to_vec();
        let len = key_handle(key)?
            .open_in_place(
                aead::Nonce::assume_unique_for_key(*nonce),
                aead::Aad::from(aad),
                &mut buffer,
            )
            .map_err(|_| CryptoError::Authentication)?
            .len();
        buffer.truncate(len);
        Ok(buffer)
    }
}

fn key_handle(key: &[u8; 32]) -> Result<aead::LessSafeKey, CryptoError> {
    aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map(aead::LessSafeKey::new)
        .map_err(|_| CryptoError::Operation)
}

impl ProtocolBackend for AwsLc {
    fn tls_provider(&self) -> rustls::crypto::CryptoProvider {
        rustls::crypto::aws_lc_rs::default_provider()
    }
    fn generate_keypair(
        &self,
        algorithm: &'static rcgen::SignatureAlgorithm,
    ) -> Result<rcgen::KeyPair, rcgen::Error> {
        rcgen::KeyPair::generate_for(algorithm)
    }
    fn jwt_provider(&self) -> &'static jsonwebtoken::crypto::CryptoProvider {
        &jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
    }
}
