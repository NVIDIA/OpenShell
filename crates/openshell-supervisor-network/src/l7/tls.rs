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
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{BufReader, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite};
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
    build_upstream_client_config_with_additional(system_ca_bundle, None)
}

/// Build upstream TLS configuration with optional additive destination roots.
///
/// The additional roots are installed after the feature-selected default roots
/// (Mozilla plus the system overlay, or native roots). They authenticate only
/// destination TLS connections and never feed the child/interception CA files.
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
        let _ = system_ca_bundle; // native store already includes operator-installed CAs
        add_native_roots(&mut root_store)?;
    }

    if let Some(additional_ca_bundle) = additional_ca_bundle {
        let certificates = strict_pem_certificates(
            additional_ca_bundle.as_bytes(),
            "additional destination CA bundle",
        )?;
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

/// Validate the canonical SHA-256 syntax used by the protected destination
/// trust argument. The gateway emits exactly this lower-case representation.
pub fn validate_additional_ca_digest(digest: &str) -> Result<()> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(miette!(
            "--network-additional-ca-digest must use sha256:<64 lowercase hexadecimal characters> format"
        ));
    };
    if hex.len() != Sha256::output_size() * 2
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(miette!(
            "--network-additional-ca-digest must use sha256:<64 lowercase hexadecimal characters> format"
        ));
    }
    Ok(())
}

/// Validate the protected all-or-nothing destination-trust argument pair.
///
/// This is separate from file verification so both supervisor roles can
/// reject incoherent or malformed command lines before any role-specific
/// setup begins.
pub fn validate_network_additional_ca_args(
    bundle: Option<&Path>,
    digest: Option<&str>,
) -> Result<()> {
    match (bundle, digest) {
        (None, None) => Ok(()),
        (Some(_), Some(digest)) => validate_additional_ca_digest(digest),
        _ => Err(miette!(
            "--network-additional-ca-bundle and --network-additional-ca-digest must be set together"
        )),
    }
}

/// Read, strictly canonicalize, and authenticate a staged destination trust
/// bundle before network setup uses it.
///
/// The digest covers canonical certificate-only PEM rather than the mounted
/// bytes, matching gateway normalization. The bounded, no-follow read closes
/// the path substitution and unbounded-read hazards at this trust boundary.
/// Diagnostics intentionally identify only the path and expected digest.
pub fn read_and_verify_additional_ca_bundle(path: &Path, expected_digest: &str) -> Result<String> {
    validate_additional_ca_digest(expected_digest)?;
    let source = read_additional_ca_bundle_file(path)?;
    let certificates = strict_pem_certificates(&source, "--network-additional-ca-bundle")
        .wrap_err_with(|| format!("invalid staged destination CA bundle at {}", path.display()))?;

    let expected_certificate_count = certificates.len();
    let mut roots = rustls::RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(certificates.clone());
    if added != expected_certificate_count || ignored != 0 {
        return Err(miette!(
            "invalid staged destination CA bundle at {}: contains an unusable X.509 certificate",
            path.display()
        ));
    }

    let canonical = canonical_pem(&certificates);
    let limit = openshell_core::network_trust::MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES;
    if canonical.len() > limit {
        return Err(miette!(
            "--network-additional-ca-bundle at {} exceeds the shared {limit}-byte limit",
            path.display()
        ));
    }
    let actual_digest = format!("sha256:{:x}", Sha256::digest(canonical.as_bytes()));
    if actual_digest != expected_digest {
        return Err(miette!(
            "network additional CA digest mismatch at {}: expected {expected_digest}; mounted bundle does not match",
            path.display()
        ));
    }
    Ok(canonical)
}

/// Read the gateway-owned artifact with the shared normalized-bundle limit.
///
/// `NetworkSupervisorTrustBundle::verify_artifact` offers the corresponding
/// public-core check when the expected canonical bytes are available. The
/// supervisor receives only their digest on argv, so it must canonicalize the
/// opened file first before it can compare that protected generation.
fn read_additional_ca_bundle_file(path: &Path) -> Result<Vec<u8>> {
    use std::fs::{self, OpenOptions};

    let limit = openshell_core::network_trust::MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES;
    let metadata = fs::symlink_metadata(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("read --network-additional-ca-bundle at {}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(miette!(
            "--network-additional-ca-bundle at {} is not a regular file",
            path.display()
        ));
    }
    if metadata.len() > limit as u64 {
        return Err(miette!(
            "--network-additional-ca-bundle at {} exceeds the shared {limit}-byte limit",
            path.display()
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Do not follow a symlink introduced after the metadata check, and do
        // not block if a regular file is swapped for a FIFO before open.
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("read --network-additional-ca-bundle at {}", path.display()))?;
    let opened_metadata = file
        .metadata()
        .into_diagnostic()
        .wrap_err_with(|| format!("read --network-additional-ca-bundle at {}", path.display()))?;
    if !opened_metadata.file_type().is_file() {
        return Err(miette!(
            "--network-additional-ca-bundle at {} is not a regular file",
            path.display()
        ));
    }
    if opened_metadata.len() > limit as u64 {
        return Err(miette!(
            "--network-additional-ca-bundle at {} exceeds the shared {limit}-byte limit",
            path.display()
        ));
    }

    let capacity = usize::try_from(opened_metadata.len()).map_err(|_| {
        miette!(
            "--network-additional-ca-bundle at {} exceeds the platform allocation limit",
            path.display()
        )
    })?;
    let mut source = Vec::with_capacity(capacity);
    std::io::Read::by_ref(&mut file)
        .take((limit + 1) as u64)
        .read_to_end(&mut source)
        .into_diagnostic()
        .wrap_err_with(|| format!("read --network-additional-ca-bundle at {}", path.display()))?;
    if source.len() > limit {
        return Err(miette!(
            "--network-additional-ca-bundle at {} exceeds the shared {limit}-byte limit",
            path.display()
        ));
    }
    Ok(source)
}

/// Parse a certificate-only PEM bundle and reject every non-certificate or
/// malformed item instead of accepting a valid subset.
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

/// Apply the gateway's strict PEM framing rules before canonicalization.
fn validate_pem_envelope(text: &str, description: &str) -> Result<()> {
    let mut begin_label = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(expected_label) = begin_label {
            if let Some(end_label) = pem_label(line, "-----END ") {
                if end_label != expected_label {
                    return Err(miette!(
                        "{description} contains malformed PEM data: END label does not match BEGIN label"
                    ));
                }
                begin_label = None;
            } else if pem_label(line, "-----BEGIN ").is_some()
                || !line
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
            {
                return Err(miette!("{description} contains malformed PEM data"));
            }
        } else if let Some(label) = pem_label(line, "-----BEGIN ") {
            begin_label = Some(label);
        } else {
            return Err(miette!(
                "{description} contains non-PEM content outside certificate blocks"
            ));
        }
    }
    if begin_label.is_some() {
        return Err(miette!("{description} contains an unterminated PEM block"));
    }
    Ok(())
}

fn pem_label<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let label = line.strip_prefix(prefix)?.strip_suffix("-----")?;
    (!label.is_empty()
        && label
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b' '))
    .then_some(label)
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

    #[test]
    fn additional_roots_augment_feature_selected_default_store() {
        let baseline = build_upstream_root_store("", None).unwrap();
        let additional = generate_ca_pem();
        let augmented = build_upstream_root_store("", Some(&additional)).unwrap();
        assert!(augmented.len() > baseline.len());
    }

    #[tokio::test]
    async fn additional_destination_root_authenticates_an_upstream_tls_connection() {
        const HOSTNAME: &str = "private.destination.test";

        let destination_ca = SandboxCa::generate().unwrap();
        let additional = destination_ca.cert_pem().to_string();
        let server_state = Arc::new(ProxyTlsState::new(
            CertCache::new(destination_ca),
            build_upstream_client_config("").unwrap(),
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_hostname = HOSTNAME.to_string();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tls_terminate_client(stream, &server_state, &server_hostname)
                .await
                .unwrap();
        });

        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let client_config = build_upstream_client_config_with_additional("", Some(&additional))
            .expect("additional destination root should be accepted");
        tls_connect_upstream(stream, HOSTNAME, &client_config)
            .await
            .expect("additional destination root should authenticate the server");
    }

    #[test]
    fn destination_ca_digest_requires_canonical_sha256_syntax() {
        let valid = format!("sha256:{}", "a".repeat(64));
        validate_additional_ca_digest(&valid).unwrap();
        for invalid in [
            "sha256:abc",
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            let error = validate_additional_ca_digest(invalid).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("sha256:<64 lowercase hexadecimal characters>"),
                "{error}"
            );
        }
    }

    #[test]
    fn destination_ca_file_is_canonicalized_and_authenticated() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("additional.pem");
        let certificate = generate_ca_pem();
        std::fs::write(&path, format!("\n{certificate}\n")).unwrap();
        let expected_digest = format!("sha256:{:x}", Sha256::digest(certificate.as_bytes()));

        assert_eq!(
            read_and_verify_additional_ca_bundle(&path, &expected_digest).unwrap(),
            certificate
        );
    }

    #[test]
    fn destination_ca_file_rejects_private_key_or_mixed_pem_without_leaking_contents() {
        let directory = tempfile::tempdir().unwrap();
        let certificate = SandboxCa::generate().unwrap();
        let private_key = certificate.private_key_pem();
        let private_key_payload = private_key
            .lines()
            .find(|line| !line.starts_with("-----") && !line.is_empty())
            .unwrap();
        let expected_digest = format!("sha256:{}", "a".repeat(64));

        for (name, contents) in [
            ("empty.pem", String::new()),
            ("malformed.pem", "not PEM material".to_string()),
            ("private-key.pem", private_key.clone()),
            (
                "mixed.pem",
                format!("{}{}", certificate.cert_pem(), private_key),
            ),
        ] {
            let path = directory.path().join(name);
            std::fs::write(&path, contents).unwrap();
            let error = read_and_verify_additional_ca_bundle(&path, &expected_digest)
                .unwrap_err()
                .to_string();
            assert!(error.contains("destination CA bundle"), "{error}");
            assert!(error.contains(&path.display().to_string()), "{error}");
            assert!(!error.contains(private_key_payload), "{error}");
            assert!(!error.contains("BEGIN PRIVATE KEY"), "{error}");
        }
    }

    #[test]
    fn destination_ca_file_rejects_valid_wrong_generation_without_leaking_pem() {
        let directory = tempfile::tempdir().unwrap();
        let expected_path = directory.path().join("expected.pem");
        let mounted_path = directory.path().join("mounted.pem");
        let expected = generate_ca_pem();
        std::fs::write(&expected_path, &expected).unwrap();
        let expected_digest = format!("sha256:{:x}", Sha256::digest(expected.as_bytes()));

        let replacement = generate_ca_pem();
        let replacement_payload = replacement
            .lines()
            .find(|line| !line.starts_with("-----") && !line.is_empty())
            .unwrap();
        std::fs::write(&mounted_path, &replacement).unwrap();

        let error = read_and_verify_additional_ca_bundle(&mounted_path, &expected_digest)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("network additional CA digest mismatch"),
            "{error}"
        );
        assert!(error.contains(&expected_digest), "{error}");
        assert!(!error.contains(replacement_payload), "{error}");
        assert!(!error.contains("BEGIN CERTIFICATE"), "{error}");
    }

    #[test]
    fn destination_ca_file_enforces_shared_size_limit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("oversized-additional.pem");
        let limit = openshell_core::network_trust::MAX_NETWORK_SUPERVISOR_TRUST_BUNDLE_BYTES;
        std::fs::write(&path, vec![b'x'; limit + 1]).unwrap();

        let error =
            read_and_verify_additional_ca_bundle(&path, &format!("sha256:{}", "a".repeat(64)))
                .unwrap_err()
                .to_string();
        assert!(error.contains("--network-additional-ca-bundle"), "{error}");
        assert!(error.contains(&format!("{limit}-byte limit")), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn destination_ca_file_rejects_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.pem");
        let link = directory.path().join("additional.pem");
        std::fs::write(&target, generate_ca_pem()).unwrap();
        symlink(&target, &link).unwrap();

        let error =
            read_and_verify_additional_ca_bundle(&link, &format!("sha256:{}", "a".repeat(64)))
                .unwrap_err()
                .to_string();
        assert!(error.contains("not a regular file"), "{error}");
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
