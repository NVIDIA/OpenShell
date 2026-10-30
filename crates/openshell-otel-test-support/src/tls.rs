// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Throwaway PKI for collector TLS tests.

use openshell_crypto::pki::{self, Certificate, KeyPair};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa};

/// A PEM certificate and its private key.
#[derive(Clone, Debug)]
pub struct PemIdentity {
    pub cert_pem: String,
    pub key_pem: String,
}

/// A CA with a `localhost` server certificate and a client certificate, all
/// freshly generated.
#[derive(Clone, Debug)]
pub struct TestPki {
    pub ca_pem: String,
    pub server: PemIdentity,
    pub client: PemIdentity,
}

impl TestPki {
    #[must_use]
    pub fn generate() -> Self {
        let ca_key = pki::generate_keypair().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = pki::self_signed(ca_params, &ca_key).unwrap();
        Self {
            ca_pem: ca.pem(),
            server: issue(
                &ca,
                &ca_key,
                vec!["localhost".to_string()],
                ExtendedKeyUsagePurpose::ServerAuth,
            ),
            client: issue(
                &ca,
                &ca_key,
                Vec::new(),
                ExtendedKeyUsagePurpose::ClientAuth,
            ),
        }
    }
}

fn issue(
    ca: &Certificate,
    ca_key: &KeyPair,
    names: Vec<String>,
    usage: ExtendedKeyUsagePurpose,
) -> PemIdentity {
    let key = pki::generate_keypair().unwrap();
    let mut params = CertificateParams::new(names).unwrap();
    params.extended_key_usages = vec![usage];
    let cert = pki::signed_by(params, &key, ca, ca_key).unwrap();
    PemIdentity {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem().unwrap(),
    }
}

/// Server TLS settings for a test collector: its identity and, when set, the
/// CA that client certificates must chain to.
#[derive(Clone, Debug)]
pub struct ServerTls {
    pub identity: PemIdentity,
    pub client_ca_pem: Option<String>,
}

impl ServerTls {
    /// Serve `pki`'s server certificate and require a client certificate
    /// issued by its CA.
    #[must_use]
    pub fn mutual(pki: &TestPki) -> Self {
        Self {
            identity: pki.server.clone(),
            client_ca_pem: Some(pki.ca_pem.clone()),
        }
    }

    /// Serve `pki`'s server certificate without asking for a client one.
    #[must_use]
    pub fn server_only(pki: &TestPki) -> Self {
        Self {
            identity: pki.server.clone(),
            client_ca_pem: None,
        }
    }

    pub(crate) fn rustls_config(&self) -> std::sync::Arc<rustls::ServerConfig> {
        use rustls::pki_types::pem::PemObject as _;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        let certs = CertificateDer::pem_slice_iter(self.identity.cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_slice(self.identity.key_pem.as_bytes()).unwrap();
        let builder = openshell_crypto::tls::server_builder();
        let builder = match &self.client_ca_pem {
            Some(ca_pem) => {
                let mut roots = rustls::RootCertStore::empty();
                for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
                    roots.add(cert.unwrap()).unwrap();
                }
                builder.with_client_cert_verifier(
                    rustls::server::WebPkiClientVerifier::builder_with_provider(
                        std::sync::Arc::new(roots),
                        openshell_crypto::tls::configuration_provider(),
                    )
                    .build()
                    .unwrap(),
                )
            }
            None => builder.with_no_client_auth(),
        };
        let mut config = builder.with_single_cert(certs, key).unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        std::sync::Arc::new(config)
    }

    pub(crate) fn tonic_config(&self) -> tonic::transport::ServerTlsConfig {
        let config = tonic::transport::ServerTlsConfig::new().identity(
            tonic::transport::Identity::from_pem(&self.identity.cert_pem, &self.identity.key_pem),
        );
        match &self.client_ca_pem {
            Some(ca_pem) => config.client_ca_root(tonic::transport::Certificate::from_pem(ca_pem)),
            None => config,
        }
    }
}
