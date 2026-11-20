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

/// Fallible client builder using the same provider as key loading and verifiers.
///
/// Returns a configuration error if the selected provider has no usable cipher
/// suites or key-exchange groups. Does not change providers or protocol policy.
pub fn try_client_builder()
-> Result<rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>, rustls::Error> {
    try_client_builder_with_protocol_versions(rustls::DEFAULT_VERSIONS)
}

/// Fallible client builder preserving an explicit protocol-version policy.
pub fn try_client_builder_with_protocol_versions(
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>, rustls::Error> {
    rustls::ClientConfig::builder_with_provider(configuration_provider())
        .with_protocol_versions(versions)
}

/// Fallible server builder using the selected configuration provider.
///
/// Returns a configuration error if the selected provider has no usable cipher
/// suites or key-exchange groups. Does not change providers or protocol policy.
pub fn try_server_builder()
-> Result<rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier>, rustls::Error> {
    try_server_builder_with_protocol_versions(rustls::DEFAULT_VERSIONS)
}

/// Fallible server builder preserving an explicit protocol-version policy.
pub fn try_server_builder_with_protocol_versions(
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier>, rustls::Error> {
    rustls::ServerConfig::builder_with_provider(configuration_provider())
        .with_protocol_versions(versions)
}

/// Compatibility client builder. Use [`try_client_builder`] in runtime code.
///
/// # Panics
/// Panics if the selected provider cannot support the default protocol versions.
#[must_use]
pub fn client_builder() -> rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier> {
    client_builder_with_protocol_versions(rustls::DEFAULT_VERSIONS)
}

/// Compatibility client builder preserving an explicit protocol-version policy.
/// Prefer [`try_client_builder_with_protocol_versions`] in runtime code.
///
/// # Panics
/// Panics if the selected provider cannot support the requested protocol versions.
#[must_use]
pub fn client_builder_with_protocol_versions(
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier> {
    try_client_builder_with_protocol_versions(versions)
        .expect("selected TLS provider must support the requested protocol versions")
}

/// Compatibility server builder. Use [`try_server_builder`] in runtime code.
///
/// # Panics
/// Panics if the selected provider cannot support the default protocol versions.
#[must_use]
pub fn server_builder() -> rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier> {
    server_builder_with_protocol_versions(rustls::DEFAULT_VERSIONS)
}

/// Compatibility server builder preserving an explicit protocol-version policy.
/// Prefer [`try_server_builder_with_protocol_versions`] in runtime code.
///
/// # Panics
/// Panics if the selected provider cannot support the requested protocol versions.
#[must_use]
pub fn server_builder_with_protocol_versions(
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier> {
    try_server_builder_with_protocol_versions(versions)
        .expect("selected TLS provider must support the requested protocol versions")
}

/// Verify a server chain against the SHA-256 digest of its presented root CA.
///
/// The caller must obtain the digest through a trusted launch channel. The
/// server supplies its root as the last certificate; normal `WebPKI` name,
/// validity, chain, and TLS handshake signature checks still apply.
#[must_use]
pub fn pinned_ca_verifier(digest: [u8; 32]) -> Arc<dyn rustls::client::danger::ServerCertVerifier> {
    Arc::new(PinnedCaVerifier { digest })
}

#[derive(Debug)]
struct PinnedCaVerifier {
    digest: [u8; 32],
}

impl rustls::client::danger::ServerCertVerifier for PinnedCaVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let (root, chain) = intermediates
            .split_last()
            .ok_or(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))?;
        let actual = crate::sha256(root.as_ref())
            .map_err(|_| rustls::Error::General("hash pinned TLS root".into()))?;
        if actual != self.digest {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root.clone())?;
        rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            configuration_provider(),
        )
        .build()
        .map_err(|_| rustls::Error::General("configure pinned TLS root".into()))?
        .verify_server_cert(end_entity, chain, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &signature_verification_algorithms(),
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &signature_verification_algorithms(),
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        signature_verification_algorithms().supported_schemes()
    }
}
