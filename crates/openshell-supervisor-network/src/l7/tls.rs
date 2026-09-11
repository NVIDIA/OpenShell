// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TLS termination for HTTPS L7 inspection.
//!
//! Provides MITM TLS termination so the proxy can inspect HTTPS traffic.
//! Generates an ephemeral CA at startup, injects it into the sandbox's trust
//! store, terminates TLS from the client (presenting dynamic certs per hostname),
//! inspects the plaintext HTTP, then re-encrypts to upstream using real root CAs.

use base64::Engine as _;
use miette::{IntoDiagnostic, Result, WrapErr, miette};
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

/// Connect TLS to an upstream server, verifying against the configured CA roots.
///
/// Returns a TLS stream for re-encrypted upstream communication.
pub async fn tls_connect_upstream(
    upstream: impl AsyncRead + AsyncWrite + Unpin + Send,
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

/// Build a rustls `ClientConfig` using the configured CA root source.
///
/// In `bundled-ca-roots` mode this uses Mozilla roots from `webpki-roots` overlaid
/// with any locally-installed CAs from `system_ca_bundle` (e.g. corporate or private
/// CAs added to `/etc/pki/ca-trust`). Duplicates with the Mozilla bundle are harmless.
///
/// Without `bundled-ca-roots` this starts with the platform/native trust store
/// and overlays `system_ca_bundle`. The overlay preserves explicitly staged
/// corporate-proxy roots even when they are not installed in the native store.
pub fn build_upstream_client_config(system_ca_bundle: &str) -> Result<Arc<ClientConfig>> {
    build_upstream_client_config_with_additional(system_ca_bundle, None)
}

/// Build the upstream TLS configuration with an explicit additive destination
/// trust bundle. The additional roots are loaded after the normal bundled or
/// native roots in every feature variant.
pub fn build_upstream_client_config_with_additional(
    system_ca_bundle: &str,
    additional_ca_bundle: Option<&str>,
) -> Result<Arc<ClientConfig>> {
    let mut config = ClientConfig::builder()
        .with_root_certificates(build_upstream_root_store(
            system_ca_bundle,
            additional_ca_bundle,
        )?)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

fn build_upstream_root_store(
    system_ca_bundle: &str,
    additional_ca_bundle: Option<&str>,
) -> Result<rustls::RootCertStore> {
    let mut root_store = rustls::RootCertStore::empty();

    #[cfg(feature = "bundled-ca-roots")]
    {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // Overlay system/corporate CAs so custom trust anchors are honoured in
        // default upstream builds. Duplicates with webpki-roots are harmless.
        let (added, ignored) = load_pem_certs_into_store(&mut root_store, system_ca_bundle);
        if added > 0 {
            tracing::debug!(added, "loaded system CA certificates for upstream TLS");
        }
        if ignored > 0 {
            tracing::warn!(
                ignored,
                "some system CA certificates could not be parsed and were ignored"
            );
        }
    }

    #[cfg(not(feature = "bundled-ca-roots"))]
    {
        add_native_roots(&mut root_store)?;
        // Native roots cover host-installed anchors, while this explicit
        // overlay also carries a driver-staged corporate-proxy CA. Duplicate
        // system roots are harmless.
        let (added, ignored) = load_pem_certs_into_store(&mut root_store, system_ca_bundle);
        if added > 0 {
            tracing::debug!(added, "loaded system CA certificates for upstream TLS");
        }
        if ignored > 0 {
            tracing::warn!(
                ignored,
                "some system CA certificates could not be parsed and were ignored"
            );
        }
    }

    if let Some(pem) = additional_ca_bundle {
        let certificates =
            strict_pem_certificates(pem.as_bytes(), "additional destination CA bundle")?;
        let expected = certificates.len();
        let (added, ignored) = root_store.add_parsable_certificates(certificates);
        if added != expected || ignored != 0 {
            return Err(miette!(
                "additional destination CA bundle contains an unusable X.509 certificate"
            ));
        }
        tracing::debug!(added, "loaded additional destination CA certificates");
    }

    if root_store.is_empty() {
        return Err(miette!("no TLS root certificates available"));
    }

    Ok(root_store)
}

#[cfg(not(feature = "bundled-ca-roots"))]
fn add_native_roots(root_store: &mut rustls::RootCertStore) -> Result<()> {
    let native_certs = rustls_native_certs::load_native_certs();
    let cert_count = native_certs.certs.len();
    let (added, ignored) = root_store.add_parsable_certificates(native_certs.certs);
    let ignored = ignored + native_certs.errors.len();

    if ignored > 0 {
        tracing::debug!(ignored, "ignored unparsable native root certificates");
    }

    if added == 0 {
        return Err(miette!(
            "no usable native TLS root certificates found ({cert_count} loaded, {ignored} ignored)"
        ));
    }

    Ok(())
}

/// Write CA certificate files for the sandbox trust store.
///
/// Writes:
/// 1. Standalone CA cert PEM (for `NODE_EXTRA_CA_CERTS` which is additive)
/// 2. Combined bundle: system CAs + sandbox CA (for `SSL_CERT_FILE` which replaces default)
///
/// `system_ca_bundle` is the pre-read PEM contents of the system CA bundle
/// (from [`read_system_ca_bundle`]).
///
/// Returns `(ca_cert_path, combined_bundle_path)`.
pub fn write_ca_files(
    ca: &SandboxCa,
    output_dir: &Path,
    system_ca_bundle: &str,
) -> Result<(PathBuf, PathBuf)> {
    write_ca_files_with_additional(Some(ca), output_dir, system_ca_bundle, None)
}

/// Write the child-process trust files with optional additional destination
/// roots and an optional proxy interception CA.
///
/// The standalone file is additive (`NODE_EXTRA_CA_CERTS`, `DENO_CERT`) and
/// contains the configured destination roots followed by the generated proxy
/// CA. The combined file contains system roots, destination roots, then the
/// generated proxy CA. Calling this with neither source is invalid.
pub fn write_ca_files_with_additional(
    ca: Option<&SandboxCa>,
    output_dir: &Path,
    system_ca_bundle: &str,
    additional_ca_bundle: Option<&str>,
) -> Result<(PathBuf, PathBuf)> {
    if ca.is_none() && additional_ca_bundle.is_none() {
        return Err(miette!("no CA material available for child trust files"));
    }
    std::fs::create_dir_all(output_dir).into_diagnostic()?;

    let mut standalone = String::new();
    if let Some(additional) = additional_ca_bundle {
        append_pem(&mut standalone, additional);
    }
    if let Some(ca) = ca {
        append_pem(&mut standalone, ca.cert_pem());
    }

    let ca_cert_path = output_dir.join("openshell-ca.pem");
    std::fs::write(&ca_cert_path, &standalone).into_diagnostic()?;

    let mut combined = system_ca_bundle.to_string();
    if let Some(additional) = additional_ca_bundle {
        append_pem(&mut combined, additional);
    }
    if let Some(ca) = ca {
        append_pem(&mut combined, ca.cert_pem());
    }

    let combined_path = output_dir.join("ca-bundle.pem");
    std::fs::write(&combined_path, &combined).into_diagnostic()?;

    Ok((ca_cert_path, combined_path))
}

fn append_pem(target: &mut String, pem: &str) {
    if !target.is_empty() && !target.ends_with('\n') {
        target.push('\n');
    }
    target.push_str(pem);
}

/// Read, strictly validate, and canonicalize the supervisor's explicitly
/// requested staged destination bundle.
pub fn read_additional_ca_bundle(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).into_diagnostic().wrap_err_with(|| {
        format!(
            "failed to read --network-additional-ca-bundle at {}",
            path.display()
        )
    })?;
    let certificates = strict_pem_certificates(&bytes, "--network-additional-ca-bundle")
        .wrap_err_with(|| format!("invalid staged destination CA bundle at {}", path.display()))?;
    let mut roots = rustls::RootCertStore::empty();
    let expected = certificates.len();
    let (added, ignored) = roots.add_parsable_certificates(certificates.clone());
    if added != expected || ignored != 0 {
        return Err(miette!(
            "invalid staged destination CA bundle at {}: contains an unusable X.509 certificate",
            path.display()
        ));
    }

    Ok(canonical_pem(&certificates))
}

fn strict_pem_certificates(
    source: &[u8],
    description: &str,
) -> Result<Vec<CertificateDer<'static>>> {
    let text = std::str::from_utf8(source)
        .into_diagnostic()
        .wrap_err_with(|| format!("{description} is not UTF-8 PEM text"))?;
    validate_pem_envelope(text, description)?;

    let mut certificates = Vec::new();
    for item in rustls_pemfile::read_all(&mut std::io::Cursor::new(source)) {
        let item = item
            .into_diagnostic()
            .wrap_err_with(|| format!("{description} contains malformed PEM data"))?;
        let rustls_pemfile::Item::X509Certificate(certificate) = item else {
            return Err(miette!(
                "{description} contains a non-certificate PEM block"
            ));
        };
        certificates.push(certificate);
    }
    if certificates.is_empty() {
        return Err(miette!("{description} contains no PEM certificate blocks"));
    }
    Ok(certificates)
}

fn validate_pem_envelope(text: &str, description: &str) -> Result<()> {
    let mut in_block = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !in_block {
            if line.starts_with("-----BEGIN ") && line.ends_with("-----") {
                in_block = true;
            } else {
                return Err(miette!(
                    "{description} contains non-PEM content outside certificate blocks"
                ));
            }
        } else if line.starts_with("-----END ") && line.ends_with("-----") {
            in_block = false;
        } else if !line
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return Err(miette!("{description} contains malformed PEM data"));
        }
    }
    if in_block {
        return Err(miette!("{description} contains an unterminated PEM block"));
    }
    Ok(())
}

fn canonical_pem(certificates: &[CertificateDer<'static>]) -> String {
    let mut normalized = String::new();
    for certificate in certificates {
        normalized.push_str("-----BEGIN CERTIFICATE-----\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(certificate.as_ref());
        for line in encoded.as_bytes().chunks(64) {
            normalized.push_str(std::str::from_utf8(line).expect("base64 is UTF-8"));
            normalized.push('\n');
        }
        normalized.push_str("-----END CERTIFICATE-----\n");
    }
    normalized
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
/// to [`write_ca_files`].
pub fn read_system_ca_bundle() -> String {
    for path in SYSTEM_CA_PATHS {
        if let Ok(contents) = std::fs::read_to_string(path)
            && !contents.is_empty()
        {
            return contents;
        }
    }
    // No system bundle found — combined file will contain only the sandbox CA.
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
/// `ClientHello` handshake.
///
/// A TLS record starts with:
/// - byte 0: `0x16` (`ContentType::Handshake`)
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
        let config = build_upstream_client_config("").unwrap();
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

    #[test]
    fn additional_roots_are_additive_in_proxy_and_direct_child_files() {
        let additional = generate_ca_pem();
        let system = generate_ca_pem();
        let proxy_ca = SandboxCa::generate().unwrap();

        let proxy_dir = tempfile::tempdir().unwrap();
        let (standalone, combined) = write_ca_files_with_additional(
            Some(&proxy_ca),
            proxy_dir.path(),
            &system,
            Some(&additional),
        )
        .unwrap();
        let standalone = std::fs::read_to_string(standalone).unwrap();
        let combined = std::fs::read_to_string(combined).unwrap();
        assert!(standalone.contains(&additional));
        assert!(standalone.contains(proxy_ca.cert_pem()));
        assert!(!standalone.contains(&system));
        assert!(combined.contains(&system));
        assert!(combined.contains(&additional));
        assert!(combined.contains(proxy_ca.cert_pem()));

        let direct_dir = tempfile::tempdir().unwrap();
        let (standalone, combined) =
            write_ca_files_with_additional(None, direct_dir.path(), &system, Some(&additional))
                .unwrap();
        assert_eq!(std::fs::read_to_string(standalone).unwrap(), additional);
        let combined = std::fs::read_to_string(combined).unwrap();
        assert!(combined.contains(&system));
        assert!(combined.contains(&additional));
    }

    #[test]
    fn no_additional_setting_preserves_existing_ca_file_bytes() {
        let ca = SandboxCa::generate().unwrap();
        let system = generate_ca_pem();
        let legacy_dir = tempfile::tempdir().unwrap();
        let additive_dir = tempfile::tempdir().unwrap();
        let legacy = write_ca_files(&ca, legacy_dir.path(), &system).unwrap();
        let additive =
            write_ca_files_with_additional(Some(&ca), additive_dir.path(), &system, None).unwrap();
        assert_eq!(
            std::fs::read(legacy.0).unwrap(),
            std::fs::read(additive.0).unwrap()
        );
        assert_eq!(
            std::fs::read(legacy.1).unwrap(),
            std::fs::read(additive.1).unwrap()
        );
    }

    #[test]
    fn staged_additional_bundle_is_strict_and_canonical() {
        let directory = tempfile::tempdir().unwrap();
        let generated =
            rcgen::generate_simple_self_signed(vec!["destination.example".into()]).unwrap();
        let certificate_path = directory.path().join("additional.pem");
        std::fs::write(&certificate_path, format!("\n{}\n", generated.cert.pem())).unwrap();
        let canonical = read_additional_ca_bundle(&certificate_path).unwrap();
        assert_eq!(canonical, generated.cert.pem());

        for (name, contents) in [
            ("empty.pem", String::new()),
            ("malformed.pem", "not pem".to_string()),
            ("private-key.pem", generated.key_pair.serialize_pem()),
            (
                "mixed.pem",
                format!(
                    "{}{}",
                    generated.cert.pem(),
                    generated.key_pair.serialize_pem()
                ),
            ),
        ] {
            let path = directory.path().join(name);
            std::fs::write(&path, contents).unwrap();
            let error = read_additional_ca_bundle(&path).unwrap_err().to_string();
            assert!(error.contains("destination CA bundle"), "{error}");
            assert!(error.contains(&path.display().to_string()), "{error}");
            assert!(!error.contains("BEGIN CERTIFICATE"), "{error}");
        }
    }

    #[tokio::test]
    async fn additional_root_trusts_matching_hostname_and_rejects_mismatch() {
        const HOSTNAME: &str = "private.destination.test";

        async fn handshake(server_hostname: &str, client_hostname: &str) -> Result<()> {
            let destination_ca = SandboxCa::generate().unwrap();
            let additional = destination_ca.cert_pem().to_string();
            let server_state = Arc::new(ProxyTlsState::new(
                CertCache::new(destination_ca),
                build_upstream_client_config("").unwrap(),
            ));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server_hostname = server_hostname.to_string();
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let _ = tls_terminate_client(stream, &server_state, &server_hostname).await;
            });

            let stream = TcpStream::connect(address).await.into_diagnostic()?;
            let config = build_upstream_client_config_with_additional("", Some(&additional))?;
            tls_connect_upstream(stream, client_hostname, &config)
                .await
                .map(drop)
        }

        handshake(HOSTNAME, HOSTNAME).await.unwrap();
        let error = handshake(HOSTNAME, "wrong.destination.test")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("certificate"), "{error:?}");
    }

    #[test]
    fn additional_roots_augment_the_feature_selected_default_store() {
        let baseline = build_upstream_root_store("", None).unwrap();
        let additional = generate_ca_pem();
        let augmented = build_upstream_root_store("", Some(&additional)).unwrap();
        assert!(augmented.len() > baseline.len());
    }
}
