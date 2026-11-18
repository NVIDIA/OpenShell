// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TLS verification of a peer authorized by SPIFFE URI identity.

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

/// Authorized SPIFFE server identities. Prefixes authorize descendants of one
/// SPIFFE path, never sibling paths or another trust domain.
#[derive(Clone, Debug)]
pub enum ServerIdentity {
    Exact(String),
    PathPrefix(String),
}

impl ServerIdentity {
    fn matches(&self, uri: &str) -> bool {
        match self {
            Self::Exact(expected) => uri == expected,
            Self::PathPrefix(prefix) => {
                let (Some((domain, path)), Some((expected_domain, expected_path))) =
                    (spiffe_path(uri), spiffe_path(prefix))
                else {
                    return false;
                };
                domain == expected_domain
                    && path
                        .strip_prefix(expected_path)
                        .is_some_and(|suffix| suffix.starts_with('/') && suffix.len() > 1)
            }
        }
    }
}

fn spiffe_path(uri: &str) -> Option<(&str, &str)> {
    let (domain, path) = uri.strip_prefix("spiffe://")?.split_once('/')?;
    (uri.len() <= 2048
        && !domain.is_empty()
        && domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-_".contains(&b))
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
        }))
    .then_some((domain, path))
}

/// Verify the chain and one URI SAN against the configured identity policy.
///
/// DNS names are not used for SPIFFE authentication. Revocation checking is
/// not enabled; deployments rely on short-lived SVIDs.
#[must_use]
pub fn server_verifier_with_identity(
    roots: RootCertStore,
    expected: ServerIdentity,
) -> Arc<dyn ServerCertVerifier> {
    Arc::new(SpiffeServerVerifier { roots, expected })
}

#[derive(Debug)]
struct SpiffeServerVerifier {
    roots: RootCertStore,
    expected: ServerIdentity,
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
        if !matches!(uris.as_slice(), [uri] if self.expected.matches(uri)) {
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

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "spiffe://example.org/spire/agent/k8s_psat/production";

    #[test]
    fn peer_prefix_is_scoped_to_valid_descendants_in_one_cluster() {
        let policy = ServerIdentity::PathPrefix(PREFIX.into());
        for node in ["node-a", "node-b", "new-node"] {
            assert!(policy.matches(&format!("{PREFIX}/{node}")));
        }
        for id in [
            PREFIX.to_string(),
            format!("{PREFIX}-other/node"),
            format!("{PREFIX}/../other/node"),
            format!("{PREFIX}//node"),
            format!("{PREFIX}/node?extra"),
            "spiffe://other.org/spire/agent/k8s_psat/production/node".into(),
        ] {
            assert!(!policy.matches(&id), "{id}");
        }
        for prefix in [
            "",
            "spiffe://example.org",
            "spiffe://example.org/",
            "https://example.org/agent",
        ] {
            assert!(!ServerIdentity::PathPrefix(prefix.into()).matches(&format!("{PREFIX}/node")));
        }
    }

    #[test]
    #[cfg(any(feature = "aws-lc", feature = "openssl"))]
    fn certificate_verification_requires_trust_validity_and_one_authorized_uri() {
        use crate::pki;

        #[cfg(all(feature = "openssl", not(feature = "aws-lc")))]
        crate::install_default_context(crate::CryptoContext::new(Box::new(crate::OpenSsl)))
            .unwrap();

        let ca_key = pki::generate_keypair().unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca = pki::self_signed(ca_params, &ca_key).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let expected = format!("{PREFIX}/node-a");
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_hours(500_000));
        let server_name = ServerName::try_from("broker.invalid").unwrap();
        for (name, uris, trusted, expired, prefix, succeeds) in [
            ("exact", vec![expected.clone()], true, false, false, true),
            (
                "cluster",
                vec![format!("{PREFIX}/node-b")],
                true,
                false,
                true,
                true,
            ),
            (
                "wrong node",
                vec![format!("{PREFIX}/node-b")],
                true,
                false,
                false,
                false,
            ),
            (
                "wrong cluster",
                vec![format!("{PREFIX}-other/node")],
                true,
                false,
                true,
                false,
            ),
            (
                "extra URI",
                vec![expected.clone(), format!("{PREFIX}/node-b")],
                true,
                false,
                true,
                false,
            ),
            ("missing URI", vec![], true, false, true, false),
            (
                "untrusted",
                vec![expected.clone()],
                false,
                false,
                true,
                false,
            ),
            ("expired", vec![expected.clone()], true, true, true, false),
        ] {
            let key = pki::generate_keypair().unwrap();
            let mut params = rcgen::CertificateParams::default();
            params.subject_alt_names = uris
                .into_iter()
                .map(|uri| rcgen::SanType::URI(uri.try_into().unwrap()))
                .collect();
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
            if expired {
                params.not_before = rcgen::date_time_ymd(2019, 1, 1);
                params.not_after = rcgen::date_time_ymd(2020, 1, 1);
            }
            let leaf = pki::signed_by(params, &key, &ca, &ca_key).unwrap();
            let verifier = server_verifier_with_identity(
                if trusted {
                    roots.clone()
                } else {
                    RootCertStore::empty()
                },
                if prefix {
                    ServerIdentity::PathPrefix(PREFIX.into())
                } else {
                    ServerIdentity::Exact(expected.clone())
                },
            );
            assert_eq!(
                verifier
                    .verify_server_cert(leaf.der(), &[], &server_name, &[], now)
                    .is_ok(),
                succeeds,
                "{name}"
            );
        }
    }
}
