// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! JWT adapter preserving jsonwebtoken's algorithm binding and claims validation.
//! Existing process defaults are retained for compatibility with embedded users.

/// Sign claims without changing the caller's algorithm, headers, or key format.
pub fn encode<T: serde::Serialize>(
    header: &jsonwebtoken::Header,
    claims: &T,
    key: &jsonwebtoken::EncodingKey,
) -> jsonwebtoken::errors::Result<String> {
    crate::install_jwt_provider();
    jsonwebtoken::encode(header, claims, key)
}

/// Verify a token and all caller-specified claims constraints.
pub fn decode<T: serde::de::DeserializeOwned>(
    token: impl AsRef<[u8]>,
    key: &jsonwebtoken::DecodingKey,
    validation: &jsonwebtoken::Validation,
) -> jsonwebtoken::errors::Result<jsonwebtoken::TokenData<T>> {
    crate::install_jwt_provider();
    jsonwebtoken::decode(token, key, validation)
}
