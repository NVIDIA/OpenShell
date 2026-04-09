// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TLS termination for HTTPS L7 inspection.
//!
//! Provides MITM TLS termination so the proxy can inspect HTTPS traffic.
//! Generates an ephemeral CA at startup, injects it into the sandbox's trust
//! store, terminates TLS from the client (presenting dynamic certs per hostname),
//! inspects the plaintext HTTP, then re-encrypts to upstream using real root CAs.

use miette::{IntoDiagnostic, Result};
use rcgen::{CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use std::collections::HashMap;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const MAX_CACHED_CERTS: usize = 256;

/// System CA bundle search paths (common Linux locations).
const SYSTEM_CA_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/CentOS/Fedora
    "/etc/ssl/ca-bundle.pem",             // openSUSE
    "/etc/ssl/cert.pem",                  // Alpine/macOS
];

/// Ephemeral CA certificate and key for MITM TLS termination.
#[allow(clippy::struct_field_names)]
pub struct SandboxCa {
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
    ca_cert_pem: String,
}

impl SandboxCa {
    /// Generate a new ephemeral CA keypair.
    pub fn generate() -> Result<Self> {
        let ca_key = KeyPair::generate().into_diagnostic()?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "OpenShell Sandbox CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "OpenShell");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let ca_cert = params.self_signed(&ca_key).into_diagnostic()?;
        let ca_cert_pem = ca_cert.pem();

        Ok(Self {
            ca_cert,
            ca_key,
            ca_cert_pem,
        })
    }

    /// Returns the CA certificate in PEM format.
    pub fn cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }
}

/// A leaf certificate chain and private key for a specific hostname.
struct CertifiedLeaf {
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

/// Cache of per-hostname leaf certificates signed by the sandbox CA.
pub struct CertCache {
    ca: SandboxCa,
    cache: Mutex<HashMap<String, Arc<CertifiedLeaf>>>,
}

impl CertCache {
    /// Create a new cert cache with the given CA.
    pub fn new(ca: SandboxCa) -> Self {
        Self {
            ca,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Get or generate a leaf certificate for the given hostname.
    fn get_or_generate(&self, hostname: &str) -> Result<Arc<CertifiedLeaf>> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| miette::miette!("cert cache lock poisoned"))?;

        if let Some(leaf) = cache.get(hostname) {
            return Ok(Arc::clone(leaf));
        }

        // Overflow: clear entire map (simple, sufficient for sandbox scale)
        if cache.len() >= MAX_CACHED_CERTS {
            cache.clear();
        }

        let leaf = Arc::new(self.generate_leaf(hostname)?);
        cache.insert(hostname.to_string(), Arc::clone(&leaf));
        Ok(leaf)
    }

    /// Generate a new leaf certificate for the given hostname.
    fn generate_leaf(&self, hostname: &str) -> Result<CertifiedLeaf> {
        let leaf_key = KeyPair::generate().into_diagnostic()?;

        let mut params = CertificateParams::new(vec![hostname.to_string()]).into_diagnostic()?;
        params.distinguished_name.push(DnType::CommonName, hostname);
        params.use_authority_key_identifier_extension = true;

        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca.ca_cert, &self.ca.ca_key)
            .into_diagnostic()?;

        let leaf_der = CertificateDer::from(leaf_cert.der().to_vec());
        let ca_der = CertificateDer::from(self.ca.ca_cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(leaf_key.serialize_der())
            .map_err(|e| miette::miette!("failed to serialize leaf key: {e}"))?;

        Ok(CertifiedLeaf {
            cert_chain: vec![leaf_der, ca_der],
            private_key: key_der,
        })
    }
}

/// TLS state shared across proxy connections.
pub struct ProxyTlsState {
    cert_cache: CertCache,
    upstream_config: Arc<ClientConfig>,
}

impl ProxyTlsState {
    /// Create a new TLS state with the given cert cache and upstream config.
    pub fn new(cert_cache: CertCache, upstream_config: Arc<ClientConfig>) -> Self {
        Self {
            cert_cache,
            upstream_config,
        }
    }

    /// Get or generate a leaf cert for the hostname and return a TLS acceptor.
    fn acceptor_for(&self, hostname: &str) -> Result<TlsAcceptor> {
        let leaf = self.cert_cache.get_or_generate(hostname)?;
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(leaf.cert_chain.clone(), leaf.private_key.clone_key())
            .into_diagnostic()?;
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(TlsAcceptor::from(Arc::new(server_config)))
    }

    /// Returns a reference to the upstream client config.
    pub fn upstream_config(&self) -> &Arc<ClientConfig> {
        &self.upstream_config
    }
}

/// Accept TLS from a sandbox client, presenting a dynamic cert for the hostname.
///
/// Returns a TLS stream that can be used for plaintext HTTP inspection.
pub async fn tls_terminate_client(
    client: TcpStream,
    tls_state: &ProxyTlsState,
    hostname: &str,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send> {
    let acceptor = tls_state.acceptor_for(hostname)?;
    let tls_stream = acceptor.accept(client).await.into_diagnostic()?;
    Ok(tls_stream)
}

/// Connect TLS to an upstream server, verifying against webpki-roots.
///
/// Returns a TLS stream for re-encrypted upstream communication.
pub async fn tls_connect_upstream(
    upstream: TcpStream,
    hostname: &str,
    client_config: &Arc<ClientConfig>,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send> {
    let connector = TlsConnector::from(Arc::clone(client_config));
    let server_name = ServerName::try_from(hostname.to_string()).into_diagnostic()?;
    let tls_stream = connector
        .connect(server_name, upstream)
        .await
        .into_diagnostic()?;
    Ok(tls_stream)
}

/// Build a rustls `ClientConfig` with Mozilla + system root CAs for upstream connections.
///
/// `system_ca_bundle` is the pre-read PEM contents of the system CA bundle
/// (from [`read_system_ca_bundle`]). Pass the same string to [`write_ca_files`]
/// to avoid reading the bundle from disk twice.
pub fn build_upstream_client_config(system_ca_bundle: &str) -> Arc<ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // System bundles typically overlap with webpki-roots (Mozilla roots);
    // duplicates are harmless and ensure we also pick up any custom/corporate CAs.
    let (added, ignored) = load_pem_certs_into_store(&mut root_store, system_ca_bundle);
    if added > 0 {
        tracing::debug!(added, "Loaded system CA certificates for upstream TLS");
    }
    if ignored > 0 {
        tracing::warn!(
            ignored,
            "Some system CA certificates could not be parsed and were ignored"
        );
    }

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Arc::new(config)
}

/// Write CA certificate files for the sandbox trust store.
///
/// Writes:
/// 1. Standalone CA cert PEM (for `NODE_EXTRA_CA_CERTS` which is additive)
/// 2. Combined bundle: system CAs + sandbox CA (for `SSL_CERT_FILE` which replaces default)
///
/// `system_ca_bundle` is the pre-read PEM contents of the system CA bundle
/// (from [`read_system_ca_bundle`]). Pass the same string to
/// [`build_upstream_client_config`] to avoid reading the bundle from disk twice.
///
/// Returns `(ca_cert_path, combined_bundle_path)`.
pub fn write_ca_files(
    ca: &SandboxCa,
    output_dir: &Path,
    system_ca_bundle: &str,
) -> Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(output_dir).into_diagnostic()?;

    let ca_cert_path = output_dir.join("openshell-ca.pem");
    std::fs::write(&ca_cert_path, ca.cert_pem()).into_diagnostic()?;

    // Combine system CAs with our sandbox CA
    let mut combined = system_ca_bundle.to_string();
    if !combined.is_empty() && !combined.ends_with('\n') {
        combined.push('\n');
    }
    combined.push_str(ca.cert_pem());

    let combined_path = output_dir.join("ca-bundle.pem");
    std::fs::write(&combined_path, &combined).into_diagnostic()?;

    Ok((ca_cert_path, combined_path))
}

/// Load PEM-encoded certificates from a string into a root certificate store.
///
/// Returns `(added, ignored)` counts. Invalid or unparseable certificates
/// are silently ignored, matching the behavior of
/// `RootCertStore::add_parsable_certificates`.
fn load_pem_certs_into_store(
    root_store: &mut rustls::RootCertStore,
    pem_data: &str,
) -> (usize, usize) {
    if pem_data.is_empty() {
        return (0, 0);
    }
    let mut reader = BufReader::new(pem_data.as_bytes());
    // Collect all results so we can count PEM blocks that fail base64
    // decoding — rustls_pemfile::certs silently drops those, so without
    // this they wouldn't be reflected in the `ignored` count.
    let all_results: Vec<_> = rustls_pemfile::certs(&mut reader).collect();
    let pem_errors = all_results.iter().filter(|r| r.is_err()).count();
    let certs: Vec<CertificateDer<'static>> =
        all_results.into_iter().filter_map(Result::ok).collect();
    let (added, ignored) = root_store.add_parsable_certificates(certs);
    (added, ignored + pem_errors)
}

/// Read the system CA bundle from well-known paths.
///
/// Returns the PEM contents of the first non-empty bundle found, or an empty
/// string if none of the well-known paths exist. Call once and pass the result
/// to both [`write_ca_files`] and [`build_upstream_client_config`].
pub fn read_system_ca_bundle() -> String {
    for path in SYSTEM_CA_PATHS {
        if let Ok(contents) = std::fs::read_to_string(path)
            && !contents.is_empty()
        {
            return contents;
        }
    }
    // No system bundle found — combined file will contain only the sandbox CA.
    // This is acceptable since the proxy uses webpki-roots independently.
    String::new()
}

/// Parse PEM certificates from a file into DER-encoded certificates.
pub fn parse_pem_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path).into_diagnostic()?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .into_diagnostic()
}

/// Peek the first bytes of a stream and determine if it looks like a TLS
/// ClientHello handshake.
///
/// A TLS record starts with:
/// - byte 0: `0x16` (ContentType::Handshake)
/// - bytes 1-2: TLS version (0x0301 = TLS 1.0, 0x0302 = TLS 1.1, 0x0303 = TLS 1.2/1.3)
///
/// Returns `true` if the peeked bytes match the TLS handshake pattern.
/// Returns `false` for plaintext HTTP, raw binary, or insufficient data.
pub fn looks_like_tls(peek: &[u8]) -> bool {
    if peek.len() < 3 {
        return false;
    }
    // ContentType::Handshake
    if peek[0] != 0x16 {
        return false;
    }
    // TLS version major must be 0x03 (SSL 3.0 / TLS 1.x)
    if peek[1] != 0x03 {
        return false;
    }
    // TLS version minor: 0x00 (SSL 3.0) through 0x04 (TLS 1.3 record layer)
    peek[2] <= 0x04
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_generation() {
        let ca = SandboxCa::generate().unwrap();
        let pem = ca.cert_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));
    }

    #[test]
    fn leaf_cert_generation() {
        let ca = SandboxCa::generate().unwrap();
        let cache = CertCache::new(ca);
        let leaf = cache.get_or_generate("example.com").unwrap();
        assert_eq!(leaf.cert_chain.len(), 2); // leaf + CA
    }

    #[test]
    fn cache_dedup() {
        let ca = SandboxCa::generate().unwrap();
        let cache = CertCache::new(ca);
        let leaf1 = cache.get_or_generate("example.com").unwrap();
        let leaf2 = cache.get_or_generate("example.com").unwrap();
        assert!(Arc::ptr_eq(&leaf1, &leaf2));
    }

    #[test]
    fn cache_overflow_clears() {
        let ca = SandboxCa::generate().unwrap();
        let cache = CertCache::new(ca);

        // Fill cache to capacity
        for i in 0..MAX_CACHED_CERTS {
            cache
                .get_or_generate(&format!("host{i}.example.com"))
                .unwrap();
        }

        // This should trigger a clear and succeed
        let leaf = cache.get_or_generate("overflow.example.com").unwrap();
        assert_eq!(leaf.cert_chain.len(), 2);

        // Cache should now have just one entry
        let cache_inner = cache.cache.lock().unwrap();
        assert_eq!(cache_inner.len(), 1);
    }

    #[test]
    fn looks_like_tls_valid_clienthello() {
        // TLS 1.0 ClientHello
        assert!(looks_like_tls(&[0x16, 0x03, 0x01, 0x00, 0x05]));
        // TLS 1.2
        assert!(looks_like_tls(&[0x16, 0x03, 0x03, 0x01, 0x00]));
        // TLS 1.3 record layer (minor 0x01, but hello advertises 1.3 via extension)
        assert!(looks_like_tls(&[0x16, 0x03, 0x01]));
        // SSL 3.0
        assert!(looks_like_tls(&[0x16, 0x03, 0x00]));
    }

    #[test]
    fn looks_like_tls_rejects_http() {
        assert!(!looks_like_tls(b"GET / HTTP/1.1"));
        assert!(!looks_like_tls(b"POST /api"));
        assert!(!looks_like_tls(b"CONNECT host:443"));
    }

    #[test]
    fn looks_like_tls_rejects_short_input() {
        assert!(!looks_like_tls(&[]));
        assert!(!looks_like_tls(&[0x16]));
        assert!(!looks_like_tls(&[0x16, 0x03]));
    }

    #[test]
    fn looks_like_tls_rejects_non_tls_binary() {
        // SSH protocol
        assert!(!looks_like_tls(b"SSH-2.0-OpenSSH"));
        // Random binary
        assert!(!looks_like_tls(&[0xFF, 0xFE, 0x00]));
        // Wrong content type
        assert!(!looks_like_tls(&[0x17, 0x03, 0x03])); // Application data, not handshake
    }

    #[test]
    fn upstream_config_alpn() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = build_upstream_client_config("");
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    /// Helper: generate a self-signed CA and return its PEM string.
    fn generate_ca_pem() -> String {
        SandboxCa::generate().unwrap().ca_cert_pem
    }

    #[test]
    fn load_pem_certs_single_ca() {
        let pem = generate_ca_pem();
        let mut store = rustls::RootCertStore::empty();
        let (added, ignored) = load_pem_certs_into_store(&mut store, &pem);
        assert_eq!(added, 1);
        assert_eq!(ignored, 0);
    }

    #[test]
    fn load_pem_certs_multiple_cas() {
        let bundle = format!(
            "{}\n{}\n{}\n",
            generate_ca_pem(),
            generate_ca_pem(),
            generate_ca_pem()
        );
        let mut store = rustls::RootCertStore::empty();
        let (added, ignored) = load_pem_certs_into_store(&mut store, &bundle);
        assert_eq!(added, 3);
        assert_eq!(ignored, 0);
    }

    #[test]
    fn load_pem_certs_empty_string() {
        let mut store = rustls::RootCertStore::empty();
        let (added, ignored) = load_pem_certs_into_store(&mut store, "");
        assert_eq!(added, 0);
        assert_eq!(ignored, 0);
    }

    #[test]
    fn load_pem_certs_garbage_input() {
        let mut store = rustls::RootCertStore::empty();
        let (added, ignored) = load_pem_certs_into_store(&mut store, "this is not PEM data at all");
        assert_eq!(added, 0);
        assert_eq!(ignored, 0);
    }

    #[test]
    fn load_pem_certs_malformed_pem_block() {
        let malformed = "-----BEGIN CERTIFICATE-----\nNOTBASE64!!!\n-----END CERTIFICATE-----\n";
        let mut store = rustls::RootCertStore::empty();
        let (added, ignored) = load_pem_certs_into_store(&mut store, malformed);
        assert_eq!(added, 0);
        assert_eq!(ignored, 1);
    }

    #[test]
    fn load_pem_certs_mixed_valid_and_invalid() {
        let malformed = "-----BEGIN CERTIFICATE-----\nNOTBASE64!!!\n-----END CERTIFICATE-----\n";
        let bundle = format!(
            "{}\n{}{}\n",
            generate_ca_pem(),
            malformed,
            generate_ca_pem()
        );
        let mut store = rustls::RootCertStore::empty();
        let (added, ignored) = load_pem_certs_into_store(&mut store, &bundle);
        assert_eq!(added, 2);
        assert_eq!(ignored, 1);
    }

    #[test]
    fn write_ca_files_includes_sandbox_ca() {
        let ca = SandboxCa::generate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (ca_path, bundle_path) = write_ca_files(&ca, dir.path(), "").unwrap();

        // Standalone CA cert file should exist and be valid PEM
        let ca_pem = std::fs::read_to_string(&ca_path).unwrap();
        assert!(ca_pem.starts_with("-----BEGIN CERTIFICATE-----"));

        // Combined bundle should contain at least the sandbox CA
        let bundle_pem = std::fs::read_to_string(&bundle_path).unwrap();
        assert!(bundle_pem.contains(ca.cert_pem()));

        // Bundle should be parseable as PEM certificates
        let mut reader = BufReader::new(bundle_pem.as_bytes());
        assert!(
            rustls_pemfile::certs(&mut reader).any(|r| r.is_ok()),
            "bundle should contain at least one cert",
        );
    }
}
