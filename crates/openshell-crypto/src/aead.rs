// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! AES-256-GCM envelope adapter. The persisted nonce/tag layout is unchanged.

use crate::{CryptoError, default_context};

/// AES-256 key size.
pub const KEY_LEN: usize = 32;
/// GCM nonce size.
pub const NONCE_LEN: usize = 12;
/// Persisted algorithm identifier.
pub const ALGORITHM: &str = "AES-256-GCM";

/// Ciphertext and its random nonce; ciphertext includes the trailing 16-byte tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// Random 96-bit nonce. Random generation reduces but cannot eliminate collision risk.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext followed by its authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Encrypt with a newly generated nonce. Callers must bind record identity in AAD.
pub fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Sealed, CryptoError> {
    default_context().backend().seal(key, aad, plaintext)
}

/// Authenticate and decrypt without exposing partially decrypted data on failure.
pub fn open(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    default_context()
        .backend()
        .open(key, aad, nonce, ciphertext)
}
