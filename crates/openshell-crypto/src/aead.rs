// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! AES-256-GCM authenticated encryption, backed by this build's crypto module.
//!
//! Used for credential encryption at rest. The algorithm is FIPS-approved in
//! both build modes; the difference is whether the module implementing it is
//! validated. That distinction is the entire reason this is not a direct
//! `ring::aead` call at the storage layer.
//!
//! Nonces are generated per seal from the backend DRBG and never reused with a
//! given key. Callers must pass a stable AAD that binds the ciphertext to its
//! logical location, so a value moved between records fails to open.

use crate::{CryptoError, backend, fill_random};

use backend::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

/// AES-256 key length in bytes.
pub const KEY_LEN: usize = 32;

/// GCM nonce length in bytes.
pub const NONCE_LEN: usize = 12;

/// Algorithm label recorded alongside stored ciphertext.
pub const ALGORITHM: &str = "AES-256-GCM";

/// A sealed value: the per-message nonce and the ciphertext with its auth tag
/// appended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// Randomly generated, unique per seal.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext followed by the GCM authentication tag.
    pub ciphertext: Vec<u8>,
}

fn key_handle(key: &[u8; KEY_LEN]) -> Result<LessSafeKey, CryptoError> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| CryptoError)
}

/// Encrypts `plaintext` under `key`, binding it to `aad`.
///
/// A fresh nonce comes from the backend DRBG on every call. `LessSafeKey` is
/// the correct primitive here despite the name: we manage nonces explicitly
/// because they are persisted next to the ciphertext rather than derived from a
/// sequence counter.
pub fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Sealed, CryptoError> {
    let mut nonce = [0_u8; NONCE_LEN];
    fill_random(&mut nonce)?;

    let mut in_out = plaintext.to_vec();
    key_handle(key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| CryptoError)?;

    Ok(Sealed {
        nonce,
        ciphertext: in_out,
    })
}

/// Decrypts and authenticates a sealed value.
///
/// Fails if the key, AAD, nonce, or ciphertext does not match what was sealed.
/// The error carries no distinction between those cases by design.
pub fn open(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut in_out = ciphertext.to_vec();
    let plaintext = key_handle(key)?
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| CryptoError)?;
    Ok(plaintext.to_vec())
}

/// Generates a fresh AES-256 key from the backend DRBG.
pub fn generate_key() -> Result<[u8; KEY_LEN], CryptoError> {
    crate::random_bytes::<KEY_LEN>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; KEY_LEN] {
        [7_u8; KEY_LEN]
    }

    #[test]
    fn seal_then_open_round_trips() {
        let key = test_key();
        let sealed = seal(&key, b"aad", b"secret value").expect("seal");
        let opened = open(&key, b"aad", &sealed.nonce, &sealed.ciphertext).expect("open");
        assert_eq!(opened, b"secret value");
    }

    #[test]
    fn ciphertext_is_longer_than_plaintext_by_the_tag() {
        let sealed = seal(&test_key(), b"", b"1234").expect("seal");
        assert_eq!(sealed.ciphertext.len(), 4 + AES_256_GCM.tag_len());
    }

    #[test]
    fn open_rejects_a_different_aad() {
        let key = test_key();
        let sealed = seal(&key, b"record-a", b"v").expect("seal");
        assert_eq!(
            open(&key, b"record-b", &sealed.nonce, &sealed.ciphertext),
            Err(CryptoError),
            "AAD must bind ciphertext to its logical location"
        );
    }

    #[test]
    fn open_rejects_a_different_key() {
        let sealed = seal(&test_key(), b"aad", b"v").expect("seal");
        assert_eq!(
            open(&[8_u8; KEY_LEN], b"aad", &sealed.nonce, &sealed.ciphertext),
            Err(CryptoError)
        );
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let key = test_key();
        let sealed = seal(&key, b"aad", b"value").expect("seal");
        let mut tampered = sealed.ciphertext.clone();
        tampered[0] ^= 0x01;
        assert_eq!(
            open(&key, b"aad", &sealed.nonce, &tampered),
            Err(CryptoError)
        );
    }

    #[test]
    fn nonces_do_not_repeat_across_seals() {
        let key = test_key();
        let first = seal(&key, b"aad", b"v").expect("seal");
        let second = seal(&key, b"aad", b"v").expect("seal");
        assert_ne!(
            first.nonce, second.nonce,
            "nonce reuse under one key breaks GCM"
        );
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn generated_keys_differ() {
        assert_ne!(generate_key().expect("key"), generate_key().expect("key"));
    }
}
