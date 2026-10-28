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
    configuration_provider().signature_verification_algorithms
}

/// Load a TLS signing key through the selected provider's key adapter.
pub fn any_supported_signing_key(
    key: &rustls::pki_types::PrivateKeyDer<'_>,
) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
    configuration_provider()
        .key_provider
        .load_private_key(key.clone_key())
}

/// Provider for `OpenShell` configurations.
///
/// An explicitly selected context
/// wins even if a dependency initialized Rustls first. Otherwise retain an
/// embedder's installed provider, preserving the existing library contract.
#[must_use]
pub fn configuration_provider() -> Arc<CryptoProvider> {
    if crate::explicitly_selected() {
        Arc::new(provider())
    } else {
        ensure_default_provider().clone()
    }
}

/// Client builder using the same provider as key loading and custom verifiers.
#[must_use]
pub fn client_builder() -> rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier> {
    client_builder_with_protocol_versions(rustls::DEFAULT_VERSIONS)
}

/// Client builder preserving an explicit protocol-version policy.
#[must_use]
pub fn client_builder_with_protocol_versions(
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier> {
    rustls::ClientConfig::builder_with_provider(configuration_provider())
        .with_protocol_versions(versions)
        .expect("selected TLS provider must support the requested protocol versions")
}

/// Server builder using the selected configuration provider.
#[must_use]
pub fn server_builder() -> rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier> {
    server_builder_with_protocol_versions(rustls::DEFAULT_VERSIONS)
}

/// Server builder preserving an explicit protocol-version policy.
#[must_use]
pub fn server_builder_with_protocol_versions(
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier> {
    rustls::ServerConfig::builder_with_provider(configuration_provider())
        .with_protocol_versions(versions)
        .expect("selected TLS provider must support the requested protocol versions")
}
