// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TLS verification of a peer with an exact SPIFFE URI identity.

use rustls::{
    DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_cert_signed_by_trust_anchor,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::ParsedCertificate,
};
use std::sync::Arc;
use x509_parser::{extensions::GeneralName, prelude::FromDer};

/// Verify a server's chain, validity, and exact SPIFFE URI SAN using the
/// selected crypto backend.
///
/// DNS names are not used for SPIFFE authentication. Revocation checking is
/// not enabled; deployments rely on short-lived SVIDs.
#[must_use]
pub fn server_verifier(roots: RootCertStore, expected: String) -> Arc<dyn ServerCertVerifier> {
    Arc::new(SpiffeServerVerifier { roots, expected })
}

#[derive(Debug)]
struct SpiffeServerVerifier {
    roots: RootCertStore,
    expected: String,
}
impl ServerCertVerifier for SpiffeServerVerifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let algorithms = super::signature_verification_algorithms();
        verify_server_cert_signed_by_trust_anchor(
            &ParsedCertificate::try_from(leaf)?,
            &self.roots,
            intermediates,
            now,
            algorithms.all,
        )?;
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(leaf.as_ref())
            .map_err(|_| rustls::Error::General("invalid agent certificate".into()))?;
        let san = cert
            .subject_alternative_name()
            .map_err(|_| rustls::Error::General("invalid agent SAN".into()))?
            .ok_or_else(|| rustls::Error::General("missing agent SAN".into()))?;
        let uris: Vec<_> = san
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::URI(uri) => Some(*uri),
                _ => None,
            })
            .collect();
        if uris != [self.expected.as_str()] {
            return Err(rustls::Error::General(
                "unexpected agent SPIFFE identity".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &super::signature_verification_algorithms(),
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &super::signature_verification_algorithms(),
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        super::signature_verification_algorithms().supported_schemes()
    }
}
