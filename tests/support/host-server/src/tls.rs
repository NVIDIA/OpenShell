// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Certificate authorities for TLS host servers.
//!
//! A test signs a server certificate with a [`TestCa`] and serves it with
//! [`HttpRecorder::serve_tls`](crate::HttpRecorder::serve_tls):
//!
//! - [`TestCa::new`] makes a CA that only the test knows, so nothing trusts it
//!   unless the test hands over [`TestCa::cert_pem`].
//! - [`TestCa::from_env`] loads the environment's additional CA, which the
//!   gateway is configured to trust (`additional_ca_bundle`). The environment
//!   publishes the paths of its PEM certificate and key in
//!   `OPENSHELL_TEST_ADDITIONAL_CA_CERT` and `OPENSHELL_TEST_ADDITIONAL_CA_KEY`.

use std::path::Path;
use std::sync::Arc;

use openshell_crypto::pki::{self, KeyPair};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyUsagePurpose,
};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use testkit::{Error, Result};
use tokio_rustls::TlsAcceptor;

/// The path of the environment's additional CA certificate, in PEM.
pub const ADDITIONAL_CA_CERT_ENV: &str = "OPENSHELL_TEST_ADDITIONAL_CA_CERT";
/// The path of the environment's additional CA private key, in PEM.
pub const ADDITIONAL_CA_KEY_ENV: &str = "OPENSHELL_TEST_ADDITIONAL_CA_KEY";

/// A certificate authority that signs server certificates for host servers.
pub struct TestCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl TestCa {
    /// A new CA that only this test knows.
    pub fn new() -> Result<Self> {
        let key = pki::generate_keypair().map_err(failed("generate a test CA key"))?;
        let cert = pki::self_signed(ca_params(), &key).map_err(failed("sign the test CA"))?;
        Ok(Self {
            cert_pem: cert.pem(),
            issuer: cert.into_issuer(key),
        })
    }

    /// The environment's additional CA, from the files that
    /// `OPENSHELL_TEST_ADDITIONAL_CA_CERT` and `OPENSHELL_TEST_ADDITIONAL_CA_KEY`
    /// name. Fails if either is unset.
    pub fn from_env() -> Result<Self> {
        Self::from_vars(|name| std::env::var(name).ok())
    }

    fn from_vars(var: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let path = |name: &str| {
            var(name)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    Error::msg(format!(
                        "{name} is not set; run this test in an environment with an additional CA"
                    ))
                })
        };
        let cert = path(ADDITIONAL_CA_CERT_ENV)?;
        let key = path(ADDITIONAL_CA_KEY_ENV)?;
        Self::from_files(cert.as_ref(), key.as_ref())
    }

    /// A CA from its PEM certificate and private key files.
    pub fn from_files(cert: &Path, key: &Path) -> Result<Self> {
        let read = |path: &Path| {
            std::fs::read_to_string(path)
                .map_err(|error| Error::msg(format!("read {}: {error}", path.display())))
        };
        let cert_pem = read(cert)?;
        let key_pem = read(key)?;
        let der = CertificateDer::from_pem_slice(cert_pem.as_bytes()).map_err(failed(format!(
            "parse the CA certificate {}",
            cert.display()
        )))?;
        let key = KeyPair::from_pem(&key_pem)
            .map_err(failed(format!("parse the CA key {}", key.display())))?;
        let issuer = pki::issuer_from_der(&der, key)
            .map_err(failed(format!("load the CA {}", cert.display())))?;
        Ok(Self { cert_pem, issuer })
    }

    /// The CA certificate, in PEM, for a client that should trust it.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// A server certificate for `names`, signed by this CA. A name that parses
    /// as an IP address becomes an IP address entry.
    pub fn leaf(&self, names: &[&str]) -> Result<Identity> {
        let names: Vec<String> = names.iter().map(ToString::to_string).collect();
        let first = names
            .first()
            .cloned()
            .ok_or_else(|| Error::msg("a server certificate needs at least one name"))?;
        let mut params = CertificateParams::new(names.clone())
            .map_err(failed(format!("server certificate names {names:?}")))?;
        params.distinguished_name.push(DnType::CommonName, first);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = pki::generate_keypair().map_err(failed("generate a server key"))?;
        let cert = pki::signed_by_issuer(params, &key, &self.issuer)
            .map_err(failed(format!("sign a server certificate for {names:?}")))?;
        let key_der = key
            .serialize_der()
            .map_err(failed("export the server key"))?;
        let key_pem = key
            .serialize_pem()
            .map_err(failed("export the server key"))?;
        Ok(Identity {
            cert_pem: cert.pem(),
            key_pem,
            cert_der: cert.der().clone(),
            key_der,
        })
    }
}

/// A server certificate and its private key.
#[derive(Clone)]
pub struct Identity {
    pub cert_pem: String,
    pub key_pem: String,
    cert_der: CertificateDer<'static>,
    key_der: Vec<u8>,
}

impl Identity {
    pub(crate) fn acceptor(&self) -> Result<TlsAcceptor> {
        let key = PrivateKeyDer::Pkcs8(self.key_der.clone().into());
        let mut config = openshell_crypto::tls::try_server_builder()
            .map_err(failed("build a TLS server configuration"))?
            .with_no_client_auth()
            .with_single_cert(vec![self.cert_der.clone()], key)
            .map_err(failed("load the server certificate"))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("cert_pem", &self.cert_pem)
            .finish_non_exhaustive()
    }
}

fn ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "OpenShell test CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params
}

fn failed<E: std::fmt::Display>(context: impl std::fmt::Display) -> impl FnOnce(E) -> Error {
    move |error| Error::msg(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::client::TlsStream;

    use super::*;
    use crate::{HttpRecorder, Response};

    /// Open a TLS connection to `port` on loopback as `name`, trusting `ca`.
    async fn connect(ca: &str, name: &str, port: u16) -> std::io::Result<TlsStream<TcpStream>> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(ca.as_bytes()).unwrap())
            .unwrap();
        let config = openshell_crypto::tls::try_client_builder()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        #[allow(
            clippy::disallowed_methods,
            reason = "standalone test support has no openshell-core dependency and enables TCP_NODELAY below"
        )]
        let stream = TcpStream::connect(("127.0.0.1", port)).await?;
        stream.set_nodelay(true)?;
        TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(name.to_string()).unwrap(), stream)
            .await
    }

    async fn get(stream: &mut TlsStream<TcpStream>, path: &str) -> String {
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: test\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    fn write_ca(dir: &str) -> (PathBuf, PathBuf, String) {
        let key = pki::generate_keypair().unwrap();
        let cert = pki::self_signed(ca_params(), &key).unwrap();
        let dir = std::env::temp_dir().join(format!("{dir}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, key_path) = (dir.join("ca.pem"), dir.join("ca-key.pem"));
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem().unwrap()).unwrap();
        (cert_path, key_path, cert.pem())
    }

    #[tokio::test]
    async fn serve_tls_answers_a_client_that_trusts_the_ca() {
        let ca = TestCa::new().unwrap();
        let identity = ca.leaf(&["localhost", "127.0.0.1"]).unwrap();
        let recorder = HttpRecorder::serve_tls(&identity, |request| {
            Response::text(format!("tls {}", request.path()))
        })
        .await
        .unwrap();
        for name in ["localhost", "127.0.0.1"] {
            let mut stream = connect(ca.cert_pem(), name, recorder.port).await.unwrap();
            let response = get(&mut stream, "/hello").await;
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
            assert!(response.ends_with("tls /hello"), "{response}");
        }
        let requests = recorder.wait_for_requests(2).await.unwrap();
        assert_eq!(requests[0].path(), "/hello");
    }

    #[tokio::test]
    async fn serve_tls_is_rejected_for_another_name_or_ca() {
        let ca = TestCa::new().unwrap();
        let recorder = HttpRecorder::start_tls(&ca.leaf(&["localhost"]).unwrap(), "ok")
            .await
            .unwrap();
        let wrong_name = connect(ca.cert_pem(), "other.test", recorder.port).await;
        assert!(
            wrong_name.is_err(),
            "a certificate for another name was accepted"
        );
        let other = TestCa::new().unwrap();
        let wrong_ca = connect(other.cert_pem(), "localhost", recorder.port).await;
        assert!(
            wrong_ca.is_err(),
            "a certificate from another CA was accepted"
        );
        assert!(recorder.requests().is_empty());
    }

    #[tokio::test]
    async fn from_vars_loads_the_environment_ca() {
        let (cert, key, cert_pem) = write_ca("host-server-env-ca");
        let ca = TestCa::from_vars(|name| match name {
            ADDITIONAL_CA_CERT_ENV => Some(cert.display().to_string()),
            ADDITIONAL_CA_KEY_ENV => Some(key.display().to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(ca.cert_pem(), cert_pem);
        let recorder = HttpRecorder::start_tls(&ca.leaf(&["localhost"]).unwrap(), "env")
            .await
            .unwrap();
        let mut stream = connect(&cert_pem, "localhost", recorder.port)
            .await
            .unwrap();
        assert!(get(&mut stream, "/").await.ends_with("env"));
    }

    #[test]
    fn from_vars_fails_when_a_variable_is_missing() {
        let error = TestCa::from_vars(|name| {
            (name == ADDITIONAL_CA_CERT_ENV).then(|| "/nonexistent/ca.pem".to_string())
        })
        .err()
        .unwrap();
        assert!(error.to_string().contains(ADDITIONAL_CA_KEY_ENV), "{error}");
        let error = TestCa::from_vars(|_| None).err().unwrap();
        assert!(
            error.to_string().contains(ADDITIONAL_CA_CERT_ENV),
            "{error}"
        );
    }

    #[test]
    fn leaf_needs_a_name() {
        assert!(TestCa::new().unwrap().leaf(&[]).is_err());
    }
}
