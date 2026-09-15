// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rustls adapter. Explicit configurations use this provider. Library callers
//! may retain an embedder's process default; that default is not attested here.

use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use std::sync::Arc;

/// Construct the application's TLS provider without changing the process default.
#[must_use]
pub fn provider() -> CryptoProvider {
    crate::default_context().backend().tls_provider()
}

/// Ensure a provider is available, preserving a host application's existing choice.
///
/// Returns the actual installed provider, including when another thread wins the
/// installation race. Callers must not infer backend identity from this operation.
pub fn ensure_default_provider() -> &'static Arc<CryptoProvider> {
    if CryptoProvider::get_default().is_none() {
        let _ = provider().install_default();
    }
    CryptoProvider::get_default().expect("a crypto provider was installed")
}

/// Verification algorithms for custom TLS certificate verifiers.
#[must_use]
pub fn signature_verification_algorithms() -> WebPkiSupportedAlgorithms {
    provider().signature_verification_algorithms
}

/// Load a TLS signing key through the selected provider's key adapter.
pub fn any_supported_signing_key(
    key: &rustls::pki_types::PrivateKeyDer<'_>,
) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
    provider().key_provider.load_private_key(key.clone_key())
}
