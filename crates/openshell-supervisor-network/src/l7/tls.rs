// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TLS termination for HTTPS L7 inspection.
//!
//! Provides MITM TLS termination so the proxy can inspect HTTPS traffic.
//! Generates an ephemeral CA at startup, injects it into the sandbox's trust
//! store, terminates TLS from the client (presenting dynamic certs per hostname),
//! inspects the plaintext HTTP, then re-encrypts to upstream using real root CAs.

use miette::{IntoDiagnostic, Result, WrapErr, miette};
use rcgen::{CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use std::collections::HashMap;
use std::io::{BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const MAX_CACHED_CERTS: usize = 256;

/// System CA bundle search paths (common Linux locations).
#[cfg(not(windows))]
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

    /// Returns the CA private key in PKCS#8 PEM format.
    pub fn private_key_pem(&self) -> String {
        self.ca_key.serialize_pem()
    }

    /// Load a durable CA certificate and matching private key from absolute paths.
    pub fn load_from_paths(certificate_path: &Path, private_key_path: &Path) -> Result<Self> {
        if !certificate_path.is_absolute() || !private_key_path.is_absolute() {
            return Err(miette!(
                "proxy CA certificate and key paths must be absolute"
            ));
        }
        if certificate_path == private_key_path {
            return Err(miette!(
                "proxy CA certificate and private key must use different paths"
            ));
        }
        let certificate_pem = std::fs::read_to_string(certificate_path)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!("read proxy CA certificate {}", certificate_path.display())
            })?;
        let private_key_pem = std::fs::read_to_string(private_key_path)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!("read proxy CA private key {}", private_key_path.display())
            })?;
        Self::from_pem(&certificate_pem, &private_key_pem)
    }

    /// Load a durable CA while preserving the exact certificate bytes supplied
    /// by the provisioner for boundary launch replay.
    pub fn from_pem(certificate_pem: &str, private_key_pem: &str) -> Result<Self> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca_key = KeyPair::from_pem(private_key_pem)
            .into_diagnostic()
            .wrap_err("parse proxy CA private key")?;
        let certificates = rustls_pemfile::certs(&mut certificate_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .into_diagnostic()
            .wrap_err("parse proxy CA certificate")?;
        if certificates.len() != 1 {
            return Err(miette!(
                "proxy CA certificate file must contain exactly one certificate"
            ));
        }
        let private_key = rustls_pemfile::private_key(&mut private_key_pem.as_bytes())
            .into_diagnostic()
            .wrap_err("parse proxy CA private key")?
            .ok_or_else(|| miette!("proxy CA private key file contains no private key"))?;
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .into_diagnostic()
            .wrap_err("proxy CA certificate and private key do not match")?;

        let params = CertificateParams::from_ca_cert_pem(certificate_pem)
            .into_diagnostic()
            .wrap_err("parse proxy CA signing certificate")?;
        let ca_cert = params
            .self_signed(&ca_key)
            .into_diagnostic()
            .wrap_err("initialize proxy CA signer")?;
        Ok(Self {
            ca_cert,
            ca_key,
            ca_cert_pem: certificate_pem.to_string(),
        })
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
pub async fn tls_terminate_client<S>(
    client: S,
    tls_state: &ProxyTlsState,
    hostname: &str,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
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
/// Without `bundled-ca-roots` this uses the platform/native trust store exclusively;
/// `system_ca_bundle` is ignored because the native store already reflects all
/// operator-installed trust anchors.
pub fn build_upstream_client_config(system_ca_bundle: &str) -> Result<Arc<ClientConfig>> {
    let mut config = ClientConfig::builder()
        .with_root_certificates(build_upstream_root_store(system_ca_bundle)?)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

fn build_upstream_root_store(system_ca_bundle: &str) -> Result<rustls::RootCertStore> {
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
        let _ = system_ca_bundle; // native store already includes operator-installed CAs
        add_native_roots(&mut root_store)?;
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
    std::fs::create_dir_all(output_dir).into_diagnostic()?;

    let ca_cert_path = output_dir.join("openshell-ca.pem");
    write_tls_output(&ca_cert_path, ca.cert_pem().as_bytes())?;

    // Combine system CAs with our sandbox CA
    let mut combined = system_ca_bundle.to_string();
    if !combined.is_empty() && !combined.ends_with('\n') {
        combined.push('\n');
    }
    combined.push_str(ca.cert_pem());

    let combined_path = output_dir.join("ca-bundle.pem");
    write_tls_output(&combined_path, combined.as_bytes())?;

    Ok((ca_cert_path, combined_path))
}

fn write_tls_output(path: &Path, contents: &[u8]) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(miette!(
                "refusing to replace symlinked TLS output {}",
                path.display()
            ));
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(miette!(
                "refusing to replace non-file TLS output {}",
                path.display()
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).into_diagnostic(),
    }

    // `NamedTempFile::persist` passes the temporary file's path to
    // `SetFileAttributesW` and both paths to `MoveFileExW` unchanged, and those
    // calls fail for paths longer than `MAX_PATH` unless they carry the `\\?\`
    // prefix. A sandbox's host state directory can be that deep.
    #[cfg(windows)]
    let extended = extended_length_path(path);
    #[cfg(windows)]
    let path = extended.as_path();

    let parent = path
        .parent()
        .ok_or_else(|| miette!("TLS output has no parent: {}", path.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .into_diagnostic()
        .wrap_err_with(|| format!("create temporary TLS output in {}", parent.display()))?;
    temporary
        .write_all(contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("write temporary TLS output for {}", path.display()))?;
    temporary
        .as_file()
        .sync_all()
        .into_diagnostic()
        .wrap_err_with(|| format!("sync temporary TLS output for {}", path.display()))?;
    temporary.persist(path).map_err(|error| {
        miette!(
            "atomically install TLS output {}: {}",
            path.display(),
            error.error
        )
    })?;
    Ok(())
}

/// `path` with its directory in the extended-length (`\\?\`) form that
/// `canonicalize` returns on Windows, or `path` unchanged if `canonicalize`
/// fails. It can fail on volumes that the Mount Manager does not track, where
/// paths shorter than `MAX_PATH` still work as given.
#[cfg(windows)]
fn extended_length_path(path: &Path) -> PathBuf {
    let (Some(parent), Some(file_name)) = (path.parent(), path.file_name()) else {
        return path.to_path_buf();
    };
    std::fs::canonicalize(parent)
        .map_or_else(|_| path.to_path_buf(), |parent| parent.join(file_name))
}

/// Load PEM-encoded certificates from a string into a root certificate store.
///
/// Returns `(added, ignored)` counts. Invalid or unparseable certificates
/// are silently ignored, matching the behavior of
/// `RootCertStore::add_parsable_certificates`.
#[cfg_attr(not(feature = "bundled-ca-roots"), allow(dead_code))]
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
#[cfg(not(windows))]
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

/// Largest system CA bundle, in bytes of PEM, that Windows sandboxes receive.
///
/// On Windows the combined bundle reaches the sandbox boundary inside the
/// `StartAgent` control frame, which is limited to 1 MiB and also carries the
/// agent spec, the policy and the provider environment. The currently valid
/// roots of Microsoft's trusted root program encode to about 800 KiB of PEM,
/// and hosts that preinstall the whole program hold all of them. A larger
/// system bundle is left out so that it cannot fail every sandbox start.
#[cfg(windows)]
const MAX_WINDOWS_SYSTEM_CA_BUNDLE_BYTES: usize = 896 * 1024;

/// Read the system CA bundle from the Windows certificate store.
///
/// Windows keeps its trust anchors in the certificate store rather than in a
/// PEM file. Returns the roots that `rustls-native-certs` loads, PEM-encoded:
/// the current user's `ROOT` store, which also holds the machine, Group
/// Policy, enterprise and third-party roots, limited to certificates that are
/// currently valid and usable for server authentication. As in
/// `rustls-native-certs`, `SSL_CERT_FILE` or `SSL_CERT_DIR` in the
/// supervisor's environment replaces the store, and the certificates found
/// there are used without that filter. Returns an empty string if no
/// certificate is found or the bundle is larger than
/// `MAX_WINDOWS_SYSTEM_CA_BUNDLE_BYTES`. Call once and pass the result to
/// [`write_ca_files`].
#[cfg(windows)]
pub fn read_system_ca_bundle() -> String {
    let native = rustls_native_certs::load_native_certs();
    for error in &native.errors {
        tracing::warn!(%error, "failed to load root certificates for the system CA bundle");
    }
    encode_system_ca_bundle(&native.certs, MAX_WINDOWS_SYSTEM_CA_BUNDLE_BYTES)
}

/// PEM-encode the system CA bundle, or return an empty string if the encoding
/// is larger than `max_bytes`.
#[cfg(any(windows, test))]
fn encode_system_ca_bundle(certificates: &[CertificateDer<'_>], max_bytes: usize) -> String {
    let pem = pem_encode_certificates(certificates);
    if pem.len() > max_bytes {
        tracing::warn!(
            certificates = certificates.len(),
            bytes = pem.len(),
            max_bytes,
            "system root certificates exceed the CA bundle size limit and were left out"
        );
        return String::new();
    }
    pem
}

/// Encode DER certificates as concatenated PEM `CERTIFICATE` blocks.
#[cfg(any(windows, test))]
fn pem_encode_certificates(certificates: &[CertificateDer<'_>]) -> String {
    use base64::Engine as _;

    let mut pem = String::new();
    for certificate in certificates {
        pem.push_str("-----BEGIN CERTIFICATE-----\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(certificate);
        for line in encoded.as_bytes().chunks(64) {
            pem.extend(line.iter().copied().map(char::from));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
    }
    pem
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

    /// Helper: generate `count` self-signed CAs and return their DER encodings.
    fn generate_ca_ders(count: usize) -> Vec<CertificateDer<'static>> {
        (0..count)
            .map(|_| {
                rustls_pemfile::certs(&mut generate_ca_pem().as_bytes())
                    .next()
                    .unwrap()
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn pem_encode_certificates_round_trips_der() {
        let certificates = generate_ca_ders(3);

        let pem = pem_encode_certificates(&certificates);

        assert!(pem.lines().all(|line| line.len() <= 64));
        let decoded = rustls_pemfile::certs(&mut pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(decoded, certificates);
        assert_eq!(pem_encode_certificates(&[]), "");
    }

    #[test]
    fn encode_system_ca_bundle_leaves_out_bundles_over_the_limit() {
        let certificates = generate_ca_ders(2);
        let pem = pem_encode_certificates(&certificates);

        assert_eq!(encode_system_ca_bundle(&certificates, pem.len()), pem);
        assert_eq!(encode_system_ca_bundle(&certificates, pem.len() - 1), "");
    }

    #[cfg(windows)]
    #[test]
    fn windows_sandbox_bundle_includes_certificate_store_roots() {
        // The bundle variables replace a client's own trust, so connections the
        // proxy does not terminate verify only if the bundle holds these roots.
        // Clearing the overrides makes both reads use the store.
        temp_env::with_vars_unset(["SSL_CERT_FILE", "SSL_CERT_DIR"], || {
            let roots = rustls_native_certs::load_native_certs().certs;
            assert!(
                !roots.is_empty(),
                "the Windows certificate store has no roots"
            );
            let ca = SandboxCa::generate().unwrap();
            let dir = tempfile::tempdir().unwrap();

            let (_, bundle_path) =
                write_ca_files(&ca, dir.path(), &read_system_ca_bundle()).unwrap();

            let bundle = std::fs::read(bundle_path).unwrap();
            let mut bundled = rustls_pemfile::certs(&mut bundle.as_slice())
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            let sandbox_ca = rustls_pemfile::certs(&mut ca.cert_pem().as_bytes())
                .next()
                .unwrap()
                .unwrap();
            assert_eq!(
                bundled.pop(),
                Some(sandbox_ca),
                "the sandbox CA must come last"
            );
            assert!(
                bundled == roots,
                "the bundle holds {} certificates before the sandbox CA; the store has {} roots",
                bundled.len(),
                roots.len()
            );
        });
    }

    #[cfg(windows)]
    #[test]
    fn windows_system_ca_bundle_over_the_limit_is_left_out() {
        // SSL_CERT_FILE replaces the store, and its loader does not parse the
        // certificates, so distinct opaque blocks are enough to pass the limit.
        let block_len = 64 * 1024;
        let block_count = MAX_WINDOWS_SYSTEM_CA_BUNDLE_BYTES / block_len + 1;
        let blocks: Vec<CertificateDer<'static>> = (0..block_count)
            .map(|index| CertificateDer::from(vec![u8::try_from(index).unwrap(); block_len]))
            .collect();
        let dir = tempfile::tempdir().unwrap();
        let within_limit = dir.path().join("within-limit.pem");
        let over_limit = dir.path().join("over-limit.pem");
        std::fs::write(&within_limit, pem_encode_certificates(&blocks[..1])).unwrap();
        std::fs::write(&over_limit, pem_encode_certificates(&blocks)).unwrap();
        let read_with_cert_file = |path: &Path| {
            temp_env::with_vars(
                [
                    ("SSL_CERT_FILE", Some(path.as_os_str())),
                    ("SSL_CERT_DIR", None),
                ],
                read_system_ca_bundle,
            )
        };

        let within = read_with_cert_file(&within_limit);
        let over = read_with_cert_file(&over_limit);

        assert!(
            within == pem_encode_certificates(&blocks[..1]),
            "the {}-byte bundle under the limit was changed",
            within.len()
        );
        assert!(
            over.is_empty(),
            "the {}-byte bundle over the limit was kept",
            over.len()
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_ca_files_rejects_symlinked_outputs() {
        use std::os::unix::fs::symlink;

        for output_name in ["openshell-ca.pem", "ca-bundle.pem"] {
            let ca = SandboxCa::generate().expect("generate CA");
            let dir = tempfile::tempdir().expect("temporary directory");
            let sentinel = dir.path().join("sentinel");
            std::fs::write(&sentinel, b"unchanged").expect("write sentinel");
            symlink(&sentinel, dir.path().join(output_name)).expect("create output symlink");

            let error = write_ca_files(&ca, dir.path(), "")
                .expect_err("symlinked TLS output must be rejected");
            assert!(error.to_string().contains("symlinked TLS output"));
            assert_eq!(
                std::fs::read(&sentinel).expect("read sentinel"),
                b"unchanged"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn write_ca_files_accepts_paths_longer_than_max_path() {
        use std::os::windows::ffi::OsStrExt;

        let ca = SandboxCa::generate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut output_dir = dir.path().to_path_buf();
        // `MAX_PATH` counts UTF-16 code units.
        while output_dir
            .join("openshell-ca.pem")
            .as_os_str()
            .encode_wide()
            .count()
            <= 260
        {
            output_dir.push("0123456789abcdef0123456789abcdef");
        }

        let (ca_path, bundle_path) = write_ca_files(&ca, &output_dir, "").unwrap();

        assert_eq!(std::fs::read_to_string(&ca_path).unwrap(), ca.cert_pem());
        assert!(
            std::fs::read_to_string(&bundle_path)
                .unwrap()
                .contains(ca.cert_pem())
        );
    }

    #[cfg(windows)]
    #[test]
    fn extended_length_path_keeps_the_path_when_canonicalize_fails() {
        let dir = tempfile::tempdir().unwrap();
        let resolved = extended_length_path(&dir.path().join("openshell-ca.pem"));
        assert!(resolved.as_os_str().to_string_lossy().starts_with(r"\\?\"));

        // The directory does not exist, so `canonicalize` fails.
        let unresolved = dir.path().join("missing").join("openshell-ca.pem");
        assert_eq!(extended_length_path(&unresolved), unresolved);
    }

    #[test]
    fn durable_ca_round_trip_preserves_certificate_bytes() {
        let generated = SandboxCa::generate().unwrap();
        let certificate = generated.cert_pem().to_string();
        let private_key = generated.private_key_pem();
        let loaded = SandboxCa::from_pem(&certificate, &private_key).unwrap();

        assert_eq!(loaded.cert_pem(), certificate);
        assert_eq!(loaded.private_key_pem(), private_key);
    }

    #[test]
    fn durable_ca_rejects_mismatched_key_and_relative_paths() {
        let certificate = SandboxCa::generate().unwrap();
        let other_key = SandboxCa::generate().unwrap();
        assert!(SandboxCa::from_pem(certificate.cert_pem(), &other_key.private_key_pem()).is_err());
        assert!(SandboxCa::load_from_paths(Path::new("ca.pem"), Path::new("ca.key")).is_err());
    }
}
