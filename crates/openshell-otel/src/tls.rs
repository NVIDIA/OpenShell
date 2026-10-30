// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TLS settings for collector connections.

use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tonic::transport::{Certificate, ClientTlsConfig, Identity};
use zeroize::Zeroizing;

/// Largest TLS file read. Launch credentials carry a copy of each file per
/// export, and some compute drivers store them in size-limited objects.
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// TLS material that cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("the CA holds no PEM certificate")]
    NoCaCertificate,
    #[error("the client certificate holds no PEM certificate")]
    NoClientCertificate,
    #[error("the client key holds no PEM private key")]
    NoClientKey,
    #[error("no platform trust roots were found; set a CA file")]
    NoPlatformRoots,
    #[error("{0}")]
    Rustls(#[from] rustls::Error),
}

/// TLS files that cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum TlsFileError {
    #[error("{key} {}: {source}", path.display())]
    Read {
        key: &'static str,
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("{key} {} is larger than 64 KiB", path.display())]
    TooLarge {
        key: &'static str,
        path: std::path::PathBuf,
    },
    #[error("cert_file is set without key_file")]
    CertWithoutKey,
    #[error("key_file is set without cert_file")]
    KeyWithoutCert,
    #[error(transparent)]
    Tls(#[from] TlsError),
}

/// How to verify a collector and authenticate to it over `https://`. The
/// default trusts the platform roots and presents no client certificate.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct OtlpTls {
    ca_pem: Option<Vec<u8>>,
    client: Option<ClientIdentity>,
}

#[derive(Clone, PartialEq, Eq)]
struct ClientIdentity {
    cert_pem: Vec<u8>,
    key_pem: Zeroizing<Vec<u8>>,
}

impl OtlpTls {
    /// Trust only the certificates in `ca_pem`, when set, and present the
    /// `client` certificate chain and private key, when set. All are PEM.
    pub fn from_pem(
        ca_pem: Option<&[u8]>,
        client: Option<(&[u8], &[u8])>,
    ) -> Result<Self, TlsError> {
        let tls = Self {
            ca_pem: ca_pem.map(<[u8]>::to_vec),
            client: client.map(|(cert_pem, key_pem)| ClientIdentity {
                cert_pem: cert_pem.to_vec(),
                key_pem: Zeroizing::new(key_pem.to_vec()),
            }),
        };
        // Building a configuration loads the key through the crypto provider
        // and checks that it matches the certificate.
        let roots = tls
            .custom_roots()?
            .unwrap_or_else(|| Arc::new(rustls::RootCertStore::empty()));
        tls.client_config(roots)?;
        Ok(tls)
    }

    /// Read PEM files: `ca_file` to trust instead of the platform roots, and
    /// `cert_file` with `key_file` to present as a client certificate.
    pub fn from_files(
        ca_file: Option<&Path>,
        cert_file: Option<&Path>,
        key_file: Option<&Path>,
    ) -> Result<Self, TlsFileError> {
        let read = |key, path: &Path| {
            let error = |source| TlsFileError::Read {
                key,
                path: path.to_path_buf(),
                source,
            };
            let mut bytes = Vec::new();
            std::fs::File::open(path)
                .and_then(|file| file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes))
                .map_err(error)?;
            if bytes.len() as u64 > MAX_FILE_BYTES {
                return Err(TlsFileError::TooLarge {
                    key,
                    path: path.to_path_buf(),
                });
            }
            Ok(bytes)
        };
        let ca = ca_file.map(|path| read("ca_file", path)).transpose()?;
        let client = match (cert_file, key_file) {
            (Some(cert), Some(key)) => Some((
                read("cert_file", cert)?,
                Zeroizing::new(read("key_file", key)?),
            )),
            (None, None) => None,
            (Some(_), None) => return Err(TlsFileError::CertWithoutKey),
            (None, Some(_)) => return Err(TlsFileError::KeyWithoutCert),
        };
        Ok(Self::from_pem(
            ca.as_deref(),
            client
                .as_ref()
                .map(|(cert, key)| (cert.as_slice(), key.as_slice())),
        )?)
    }

    /// Whether nothing differs from the default.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.ca_pem.is_none() && self.client.is_none()
    }

    #[must_use]
    pub fn ca_pem(&self) -> Option<&[u8]> {
        self.ca_pem.as_deref()
    }

    /// The client certificate chain and private key, when set.
    #[must_use]
    pub fn client_identity(&self) -> Option<(&[u8], &[u8])> {
        self.client
            .as_ref()
            .map(|client| (client.cert_pem.as_slice(), client.key_pem.as_slice()))
    }

    /// The settings as a tonic channel TLS configuration.
    #[must_use]
    pub fn grpc_config(&self) -> ClientTlsConfig {
        // Tonic trusts nothing by default, so enable the platform roots.
        let config = self.ca_pem.as_ref().map_or_else(
            || ClientTlsConfig::new().with_enabled_roots(),
            |ca_pem| ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca_pem)),
        );
        match &self.client {
            Some(client) => config.identity(Identity::from_pem(
                &client.cert_pem,
                client.key_pem.as_slice(),
            )),
            None => config,
        }
    }

    /// A Rustls client configuration for an `https://` collector, or, with
    /// no settings, for a plaintext one, which needs no trust roots.
    pub(crate) fn http_config_for(tls: Option<&Self>) -> Result<rustls::ClientConfig, TlsError> {
        tls.map_or_else(
            || Self::default().client_config(Arc::new(rustls::RootCertStore::empty())),
            Self::http_config,
        )
    }

    /// The settings as a Rustls client configuration.
    fn http_config(&self) -> Result<rustls::ClientConfig, TlsError> {
        let roots = match self.custom_roots()? {
            Some(roots) => roots,
            None => platform_roots()?,
        };
        self.client_config(roots)
    }

    fn client_config(
        &self,
        roots: Arc<rustls::RootCertStore>,
    ) -> Result<rustls::ClientConfig, TlsError> {
        let builder = openshell_crypto::tls::client_builder().with_root_certificates(roots);
        Ok(match self.client_identity_der()? {
            Some((certs, key)) => builder.with_client_auth_cert(certs, key)?,
            None => builder.with_no_client_auth(),
        })
    }

    /// The roots from the configured CA, when one is set.
    fn custom_roots(&self) -> Result<Option<Arc<rustls::RootCertStore>>, TlsError> {
        let Some(ca_pem) = &self.ca_pem else {
            return Ok(None);
        };
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(ca_pem) {
            roots.add(cert.map_err(|_| TlsError::NoCaCertificate)?)?;
        }
        if roots.is_empty() {
            return Err(TlsError::NoCaCertificate);
        }
        Ok(Some(Arc::new(roots)))
    }

    #[allow(clippy::type_complexity)]
    fn client_identity_der(
        &self,
    ) -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>, TlsError> {
        let Some(client) = &self.client else {
            return Ok(None);
        };
        let certs = CertificateDer::pem_slice_iter(&client.cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| TlsError::NoClientCertificate)?;
        if certs.is_empty() {
            return Err(TlsError::NoClientCertificate);
        }
        let key =
            PrivateKeyDer::from_pem_slice(&client.key_pem).map_err(|_| TlsError::NoClientKey)?;
        Ok(Some((certs, key)))
    }
}

/// The platform's trust roots, or the ones `SSL_CERT_FILE` and `SSL_CERT_DIR`
/// name instead.
fn platform_roots() -> Result<Arc<rustls::RootCertStore>, TlsError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if roots.is_empty() {
        return Err(TlsError::NoPlatformRoots);
    }
    Ok(Arc::new(roots))
}

impl std::fmt::Debug for OtlpTls {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OtlpTls")
            .field("custom_ca", &self.ca_pem.is_some())
            .field("client_certificate", &self.client.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use openshell_otel_test_support::TestPki;

    use super::*;

    #[test]
    fn unusable_pem_is_rejected_when_the_settings_are_built() {
        let pki = TestPki::generate();
        let (cert, key) = (
            pki.client.cert_pem.as_bytes(),
            pki.client.key_pem.as_bytes(),
        );
        assert!(OtlpTls::from_pem(Some(pki.ca_pem.as_bytes()), Some((cert, key))).is_ok());
        assert!(matches!(
            OtlpTls::from_pem(Some(b"not pem"), None),
            Err(TlsError::NoCaCertificate)
        ));
        assert!(matches!(
            OtlpTls::from_pem(None, Some((key, key))),
            Err(TlsError::NoClientCertificate)
        ));
        assert!(matches!(
            OtlpTls::from_pem(None, Some((cert, cert))),
            Err(TlsError::NoClientKey)
        ));
    }

    #[test]
    fn files_are_read_in_pairs_and_report_which_one_failed() {
        let pki = TestPki::generate();
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name);
        std::fs::write(path("ca.pem"), &pki.ca_pem).unwrap();
        std::fs::write(path("client.pem"), &pki.client.cert_pem).unwrap();
        std::fs::write(path("client-key.pem"), &pki.client.key_pem).unwrap();
        let (ca, cert, key) = (path("ca.pem"), path("client.pem"), path("client-key.pem"));

        let tls = OtlpTls::from_files(Some(&ca), Some(&cert), Some(&key)).unwrap();
        assert_eq!(tls.ca_pem(), Some(pki.ca_pem.as_bytes()));
        assert!(tls.client_identity().is_some());
        assert!(OtlpTls::from_files(None, None, None).unwrap().is_default());
        assert!(matches!(
            OtlpTls::from_files(None, Some(&cert), None),
            Err(TlsFileError::CertWithoutKey)
        ));
        assert!(matches!(
            OtlpTls::from_files(None, None, Some(&key)),
            Err(TlsFileError::KeyWithoutCert)
        ));
        let missing = path("missing.pem");
        let error = OtlpTls::from_files(Some(&missing), None, None).unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with(&format!("ca_file {}", missing.display())),
            "{error}"
        );
        assert!(matches!(
            OtlpTls::from_files(Some(&key), None, None),
            Err(TlsFileError::Tls(TlsError::NoCaCertificate))
        ));
        let large = path("large.pem");
        std::fs::write(&large, vec![b'a'; 64 * 1024 + 1]).unwrap();
        let error = OtlpTls::from_files(Some(&large), None, None).unwrap_err();
        assert!(
            matches!(error, TlsFileError::TooLarge { key: "ca_file", .. }),
            "{error}"
        );
    }

    #[test]
    fn a_key_that_does_not_match_the_certificate_is_rejected() {
        let pki = TestPki::generate();
        let other = TestPki::generate();
        let error = OtlpTls::from_pem(
            None,
            Some((
                pki.client.cert_pem.as_bytes(),
                other.client.key_pem.as_bytes(),
            )),
        )
        .unwrap_err();
        assert!(
            matches!(error, TlsError::Rustls(rustls::Error::InconsistentKeys(_))),
            "{error:?}"
        );
    }

    #[test]
    fn debug_output_omits_the_private_key() {
        let pki = TestPki::generate();
        let tls = OtlpTls::from_pem(
            None,
            Some((
                pki.client.cert_pem.as_bytes(),
                pki.client.key_pem.as_bytes(),
            )),
        )
        .unwrap();
        let debug = format!("{tls:?}");
        assert!(debug.contains("client_certificate: true"), "{debug}");
        assert!(!debug.contains("PRIVATE KEY"), "{debug}");
    }
}
