// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TLS support using tokio-rustls.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::event::EventKind;
use notify::{Event, RecursiveMode, Watcher};
use openshell_core::{Error, Result};
use openshell_ocsf::{
    ConfigStateChangeBuilder, OCSF_TARGET, SandboxContext, SeverityId, StateId, StatusId,
};
use rustls::ServerConfig;
use rustls::crypto::ring::sign;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

/// TLS acceptor for wrapping connections.
///
/// Uses `ArcSwap` internally so the active `ServerConfig` can be atomically
/// swapped by a background reload worker without blocking TLS handshakes.
///
/// Stores the cert/key/CA paths from construction so that `reload()` can
/// re-read from the same files without the caller tracking them separately.
#[derive(Clone)]
pub struct TlsAcceptor {
    config: Arc<ArcSwap<ServerConfig>>,
    cert_path: PathBuf,
    key_path: PathBuf,
    client_ca_path: Option<PathBuf>,
    require_client_auth: bool,
    external_cert_path: Option<PathBuf>,
    external_key_path: Option<PathBuf>,
    external_server_names: Vec<String>,
    reload_spawned: Arc<AtomicBool>,
}

impl TlsAcceptor {
    /// Create a new TLS acceptor from certificate and key files.
    ///
    /// When `client_ca_path` is `Some` and `require_client_auth` is `true`,
    /// the TLS handshake rejects connections that do not present a valid
    /// client certificate signed by the given CA.
    ///
    /// When `client_ca_path` is `Some` and `require_client_auth` is `false`,
    /// client certificates are validated against the CA but not required.
    /// Clients may connect without a certificate; presented certs from an
    /// unknown CA are still rejected.
    ///
    /// When `client_ca_path` is `None`, the server does not request client
    /// certificates at all (HTTPS-only).
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate, key, or CA files cannot be read or parsed.
    pub fn from_files(
        cert_path: &Path,
        key_path: &Path,
        client_ca_path: Option<&Path>,
        require_client_auth: bool,
        external_cert_path: Option<&Path>,
        external_key_path: Option<&Path>,
        external_server_names: Vec<String>,
    ) -> Result<Self> {
        let config = build_server_config(
            cert_path,
            key_path,
            client_ca_path,
            require_client_auth,
            external_cert_path,
            external_key_path,
            &external_server_names,
        )?;
        Ok(Self {
            config: Arc::new(ArcSwap::from(config)),
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
            client_ca_path: client_ca_path.map(Path::to_path_buf),
            require_client_auth,
            external_cert_path: external_cert_path.map(Path::to_path_buf),
            external_key_path: external_key_path.map(Path::to_path_buf),
            external_server_names,
            reload_spawned: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Re-read certificates from the same paths used at construction and
    /// atomically swap the active config.
    ///
    /// Returns `Ok(())` when the new config was built and swapped successfully.
    /// Returns `Err(...)` if cert/key loading fails — the old config is preserved.
    pub fn reload(&self) -> Result<()> {
        let new_config = build_server_config(
            &self.cert_path,
            &self.key_path,
            self.client_ca_path.as_deref(),
            self.require_client_auth,
            self.external_cert_path.as_deref(),
            self.external_key_path.as_deref(),
            &self.external_server_names,
        )?;
        self.config.store(new_config);

        let event = ConfigStateChangeBuilder::new(&tls_ocsf_ctx())
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .state(StateId::Enabled, "reloaded")
            .message("TLS certificate config reloaded successfully")
            .build();
        info!(
            target: OCSF_TARGET,
            sandbox_id = "",
            message = %event.format_shorthand()
        );

        Ok(())
    }

    /// Return a fresh `tokio_rustls::TlsAcceptor` backed by the current config
    /// snapshot. Each call clones the active `Arc<ServerConfig>` so it remains
    /// alive for the duration of the TLS handshake.
    #[must_use]
    pub fn acceptor(&self) -> tokio_rustls::TlsAcceptor {
        tokio_rustls::TlsAcceptor::from(self.config.load_full())
    }

    /// Spawn a background worker that watches the parent directories of the
    /// cert, key, and CA files and calls [`reload`](Self::reload) when changes
    /// are detected.
    ///
    /// A 1-second debounce window coalesces rapid filesystem events (such as
    /// Kubernetes Secret volume atomic swaps) into a single reload. If reload
    /// fails, the old config is preserved and a warning is logged.
    ///
    /// The worker exits when the `shutdown` watch channel fires, allowing the
    /// gateway to perform a graceful shutdown without orphaned reload
    /// tasks.
    pub fn spawn_reload_worker(
        &self,
        mut shutdown: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        if self.reload_spawned.swap(true, Ordering::Relaxed) {
            warn!("TLS certificate reload worker already spawned, ignoring duplicate call");
            return tokio::spawn(async {});
        }

        let this = self.clone();

        // Collect unique parent directories to watch.
        let cert_dir = self.cert_path.parent().unwrap_or_else(|| Path::new("."));
        let key_dir = self.key_path.parent().unwrap_or_else(|| Path::new("."));
        let mut dirs = vec![cert_dir.to_path_buf()];
        if key_dir != cert_dir {
            dirs.push(key_dir.to_path_buf());
        }
        if let Some(ref ca) = self.client_ca_path {
            let ca_dir = ca.parent().unwrap_or_else(|| Path::new("."));
            if !dirs.contains(&ca_dir.to_path_buf()) {
                dirs.push(ca_dir.to_path_buf());
            }
        }
        if let Some(ref ext_cert) = self.external_cert_path {
            let ext_dir = ext_cert.parent().unwrap_or_else(|| Path::new("."));
            if !dirs.contains(&ext_dir.to_path_buf()) {
                dirs.push(ext_dir.to_path_buf());
            }
        }
        if let Some(ref ext_key) = self.external_key_path {
            let ext_dir = ext_key.parent().unwrap_or_else(|| Path::new("."));
            if !dirs.contains(&ext_dir.to_path_buf()) {
                dirs.push(ext_dir.to_path_buf());
            }
        }

        let debounce = Duration::from_secs(1);

        tokio::spawn(async move {
            let (tx, mut rx) = mpsc::unbounded_channel();

            // recommended_watcher runs its own thread; we bridge events into
            // the tokio runtime via the unbounded mpsc channel.
            let mut watcher = match notify::recommended_watcher(
                move |res: std::result::Result<Event, notify::Error>| {
                    if let Ok(event) = res
                        && matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_))
                    {
                        let _ = tx.send(());
                    }
                },
            ) {
                Ok(w) => w,
                Err(e) => {
                    warn!(error = %e, "Failed to start TLS cert file watcher, hot-reload disabled");
                    return;
                }
            };

            for dir in &dirs {
                if let Err(e) = watcher.watch(dir, RecursiveMode::NonRecursive) {
                    warn!(error = %e, dir = %dir.display(), "Failed to watch TLS cert directory, hot-reload disabled");
                    return;
                }
            }

            info!(?dirs, "TLS certificate file watcher started");

            // Event loop with manual debounce.
            // When the watcher fires, we drain any follow-up events that
            // arrive within the debounce window before calling reload().
            // This handles Kubernetes Secret atomic-swap patterns where
            // kubelet writes a new ..data directory and swaps symlinks in
            // rapid succession.

            'outer: loop {
                // Wait for the first event (or shutdown).
                let got_event = tokio::select! {
                    r = rx.recv() => r.is_some(),
                    _ = shutdown.changed() => break 'outer,
                };

                if !got_event {
                    warn!("TLS cert file watcher disconnected, hot-reload stopping");
                    break 'outer;
                }

                // Debounce: keep draining events for the debounce duration.
                loop {
                    tokio::select! {
                        () = tokio::time::sleep(debounce) => {
                            // Debounce window elapsed — reload now.
                            if let Err(e) = this.reload() {
                                let event = ConfigStateChangeBuilder::new(&tls_ocsf_ctx())
                                    .severity(SeverityId::Medium)
                                    .status(StatusId::Failure)
                                    .state(StateId::Enabled, "reload_failed")
                                    .message(format!(
                                        "TLS certificate reload failed: {e}"
                                    ))
                                    .build();
                                info!(
                                    target: OCSF_TARGET,
                                    sandbox_id = "",
                                    message = %event.format_shorthand()
                                );
                                warn!(error = %e, "TLS certificate reload failed, keeping existing config");
                            }
                            break;
                        }
                        r = rx.recv() => {
                            if r.is_some() {
                                // Another event arrived — reset debounce.
                                continue;
                            }
                            warn!("TLS cert file watcher disconnected, hot-reload stopping");
                            break 'outer;
                        }
                        _ = shutdown.changed() => {
                            debug!("TLS certificate reload worker stopped");
                            break 'outer;
                        }
                    }
                }
            }

            // `watcher` dropped here — stops the underlying watcher thread.
        })
    }
}

/// SNI-based certificate resolver that presents an external (e.g. ACME)
/// certificate for configured hostnames and the internal (chart CA) certificate
/// for everything else, including connections with no SNI.
struct DualCertResolver {
    internal: Arc<CertifiedKey>,
    external: Arc<CertifiedKey>,
    external_names: Vec<String>,
}

/// Check whether `sni` matches a configured external name.
///
/// Supports exact matches and single-level wildcard matches per RFC 6125:
/// `*.example.com` matches `foo.example.com` but not `bar.foo.example.com`
/// or `example.com` itself.
fn sni_matches(pattern: &str, sni: &str) -> bool {
    pattern.strip_prefix("*.").map_or(pattern == sni, |suffix| {
        // Wildcard: SNI must have exactly one label before the suffix.
        // e.g. "foo." for "foo.example.com" against "*.example.com"
        sni.strip_suffix(suffix).is_some_and(|prefix| {
            prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.')
        })
    })
}

impl ResolvesServerCert for DualCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(name) = client_hello.server_name()
            && self.external_names.iter().any(|n| sni_matches(n, name))
        {
            return Some(self.external.clone());
        }
        Some(self.internal.clone())
    }
}

impl std::fmt::Debug for DualCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DualCertResolver")
            .field("external_names", &self.external_names)
            .finish()
    }
}

/// Build a `CertifiedKey` from certificate and key file paths.
fn load_certified_key(cert_path: &Path, key_path: &Path) -> Result<Arc<CertifiedKey>> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let signing_key = sign::any_supported_type(&key)
        .map_err(|e| Error::tls(format!("unsupported private key type: {e}")))?;
    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// Build an SNI-based cert resolver when an external certificate is configured.
/// Returns `None` when no external cert is configured (single-cert mode).
fn build_cert_resolver(
    cert_path: &Path,
    key_path: &Path,
    external_cert_path: Option<&Path>,
    external_key_path: Option<&Path>,
    external_server_names: &[String],
) -> Result<Option<Arc<dyn ResolvesServerCert>>> {
    match (external_cert_path, external_key_path) {
        (None, None) => Ok(None),
        (Some(_), None) => Err(Error::tls(
            "external_cert_path is set but external_key_path is missing",
        )),
        (None, Some(_)) => Err(Error::tls(
            "external_key_path is set but external_cert_path is missing",
        )),
        (Some(ext_cert_path), Some(ext_key_path)) => {
            if external_server_names.is_empty() {
                return Err(Error::tls(
                    "external certificate is configured but external_server_names is empty — \
                     the external cert would never be served",
                ));
            }
            let internal = load_certified_key(cert_path, key_path)?;
            let external = load_certified_key(ext_cert_path, ext_key_path)?;
            Ok(Some(Arc::new(DualCertResolver {
                internal,
                external,
                external_names: external_server_names.to_vec(),
            })))
        }
    }
}

/// Build a `ServerConfig` from certificate, key, and optional client CA files.
fn build_server_config(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: Option<&Path>,
    require_client_auth: bool,
    external_cert_path: Option<&Path>,
    external_key_path: Option<&Path>,
    external_server_names: &[String],
) -> Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;

    // Validate the key type early — rustls defers this to handshake time,
    // which produces a cryptic error. A bad key type surfaces clearly here.
    sign::any_supported_type(&key)
        .map_err(|e| Error::tls(format!("unsupported private key type: {e}")))?;

    let resolver = build_cert_resolver(
        cert_path,
        key_path,
        external_cert_path,
        external_key_path,
        external_server_names,
    )?;

    let mut config = if let Some(ca_path) = client_ca_path {
        let ca_certs = load_certs(ca_path)?;
        let mut root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            root_store
                .add(cert)
                .map_err(|e| Error::tls(format!("failed to add CA certificate: {e}")))?;
        }

        let verifier_builder = WebPkiClientVerifier::builder(Arc::new(root_store));
        let verifier = if require_client_auth {
            verifier_builder
        } else {
            verifier_builder.allow_unauthenticated()
        }
        .build()
        .map_err(|e| Error::tls(format!("failed to build client verifier: {e}")))?;

        let builder = ServerConfig::builder().with_client_cert_verifier(verifier);
        if let Some(resolver) = resolver {
            builder.with_cert_resolver(resolver)
        } else {
            builder
                .with_single_cert(certs, key)
                .map_err(|e| Error::tls(format!("failed to create TLS config: {e}")))?
        }
    } else {
        let builder = ServerConfig::builder().with_no_client_auth();
        if let Some(resolver) = resolver {
            builder.with_cert_resolver(resolver)
        } else {
            builder
                .with_single_cert(certs, key)
                .map_err(|e| Error::tls(format!("failed to create TLS config: {e}")))?
        }
    };

    config
        .alpn_protocols
        .extend([b"h2".to_vec(), b"http/1.1".to_vec()]);

    Ok(Arc::new(config))
}

/// Load certificates from a PEM file.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).map_err(|e| Error::tls(format!("failed to open cert file: {e}")))?;
    let mut reader = BufReader::new(file);

    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::tls(format!("failed to parse certificates: {e}")))?;

    if certs.is_empty() {
        return Err(Error::tls("no certificates found in file"));
    }

    Ok(certs)
}

/// Load a private key from a PEM file.
fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).map_err(|e| Error::tls(format!("failed to open key file: {e}")))?;
    let mut reader = BufReader::new(file);

    loop {
        let item = rustls_pemfile::read_one(&mut reader)
            .map_err(|e| Error::tls(format!("failed to parse key file: {e}")))?;

        match item {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(key.into()),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(key.into()),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(key.into()),
            None => break,
            _ => {}
        }
    }

    Err(Error::tls("no private key found in file"))
}

/// Build an OCSF context for gateway-level (non-sandbox) events.
fn tls_ocsf_ctx() -> SandboxContext {
    SandboxContext {
        sandbox_id: String::new(),
        sandbox_name: String::new(),
        container_image: "openshell/gateway".to_string(),
        hostname: "openshell-gateway".to_string(),
        product_version: openshell_core::VERSION.to_string(),
        proxy_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        proxy_port: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_test_utils::{
        generate_test_certs_with_ca, install_rustls_provider, write_test_file,
    };
    use rcgen::{CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    use tokio::net::{TcpListener, TcpStream};

    /// Generate a new server cert + key in `dir`, signed by the given CA.
    /// Overwrites `server-cert.pem` and `server-key.pem`.
    fn generate_server_cert(ca_cert: &rcgen::Certificate, ca_key: &KeyPair, dir: &Path) {
        let server_params = CertificateParams::new(vec!["localhost".to_string()])
            .expect("failed to create server params");
        let server_key = KeyPair::generate().expect("failed to generate server key");
        let server_cert = server_params
            .signed_by(&server_key, ca_cert, ca_key)
            .expect("failed to sign server cert");

        write_test_file(dir, "server-cert.pem", server_cert.pem().as_bytes());
        write_test_file(dir, "server-key.pem", server_key.serialize_pem().as_bytes());
    }

    fn build_test_client_config(ca_path: &Path) -> Arc<rustls::ClientConfig> {
        let ca_certs = load_certs(ca_path).expect("failed to load CA certs");
        let mut root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            root_store
                .add(cert)
                .expect("failed to add CA to root store");
        }
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        )
    }

    /// Extract the DER-encoded server certificate from a TLS session.
    fn peer_cert_der(tls: &tokio_rustls::client::TlsStream<TcpStream>) -> Vec<u8> {
        tls.get_ref().1.peer_certificates().expect("no peer certs")[0]
            .as_ref()
            .to_vec()
    }

    #[test]
    fn test_build_server_config() {
        install_rustls_provider();
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let _ = generate_test_certs_with_ca(dir.path());

        let config = build_server_config(
            &dir.path().join("server-cert.pem"),
            &dir.path().join("server-key.pem"),
            Some(&dir.path().join("ca.pem")),
            false,
            None,
            None,
            &[],
        )
        .expect("failed to build server config");

        assert!(config.alpn_protocols.contains(&b"h2".to_vec()));
        assert!(config.alpn_protocols.contains(&b"http/1.1".to_vec()));
    }

    #[test]
    fn test_reload_success() {
        install_rustls_provider();
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let (ca_cert, ca_key) = generate_test_certs_with_ca(dir.path());

        let acceptor = TlsAcceptor::from_files(
            &dir.path().join("server-cert.pem"),
            &dir.path().join("server-key.pem"),
            Some(&dir.path().join("ca.pem")),
            false,
            None,
            None,
            Vec::new(),
        )
        .expect("failed to build acceptor");

        generate_server_cert(&ca_cert, &ca_key, dir.path());
        acceptor.reload().expect("reload should succeed");
    }

    #[test]
    fn test_reload_invalid_preserves_old() {
        install_rustls_provider();
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        generate_test_certs_with_ca(dir.path());

        let acceptor = TlsAcceptor::from_files(
            &dir.path().join("server-cert.pem"),
            &dir.path().join("server-key.pem"),
            Some(&dir.path().join("ca.pem")),
            false,
            None,
            None,
            Vec::new(),
        )
        .expect("failed to build acceptor");

        // Snapshot the current config before corrupting files.
        let acceptor_before = acceptor.acceptor();

        std::fs::write(dir.path().join("server-cert.pem"), b"garbage")
            .expect("failed to write garbage");

        assert!(
            acceptor.reload().is_err(),
            "reload with garbage cert should fail"
        );

        // Old config must still be accessible after a failed reload.
        drop(acceptor_before);
        let _ = acceptor.acceptor(); // does not panic
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_handshake_and_reload() {
        install_rustls_provider();

        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let (ca_cert, ca_key) = generate_test_certs_with_ca(dir.path());
        let acceptor = TlsAcceptor::from_files(
            &dir.path().join("server-cert.pem"),
            &dir.path().join("server-key.pem"),
            Some(&dir.path().join("ca.pem")),
            false,
            None,
            None,
            Vec::new(),
        )
        .expect("failed to build acceptor");

        let client_config = build_test_client_config(&dir.path().join("ca.pem"));
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let server_name =
            rustls::pki_types::ServerName::try_from("localhost").expect("invalid server name");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind");
        let listen_addr = listener.local_addr().expect("failed to get local addr");

        let acceptor_for_server = acceptor.clone();
        let (server_done_tx, mut server_done_rx) = watch::channel(false);
        let server_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let acc = acceptor_for_server.clone();
                                tokio::spawn(async move {
                                    let _ = acc.acceptor().accept(stream).await;
                                });
                            }
                            Err(_) => break,
                        }
                    }
                    _ = server_done_rx.changed() => break,
                }
            }
        });

        let num_clients = 10;
        let cycles_per_client = 5;
        let mut client_handles = Vec::with_capacity(num_clients);

        for i in 0..num_clients {
            let connector = connector.clone();
            let name = server_name.clone();
            let addr = listen_addr;
            client_handles.push(tokio::spawn(async move {
                for _ in 0..cycles_per_client {
                    let tcp = TcpStream::connect(addr)
                        .await
                        .expect("client connect failed");
                    let _tls = connector
                        .connect(name.clone(), tcp)
                        .await
                        .expect("client TLS handshake failed");
                }
                i
            }));
        }

        let reload_handle = tokio::spawn(async move {
            for _ in 0..20 {
                generate_server_cert(&ca_cert, &ca_key, dir.path());
                acceptor
                    .reload()
                    .expect("reload with valid cert should succeed");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        let mut client_failures = 0;
        for handle in client_handles {
            match handle.await {
                Err(e) if e.is_panic() => client_failures += 1,
                _ => {}
            }
        }
        assert_eq!(client_failures, 0, "some client tasks panicked");

        reload_handle.await.expect("reload task panicked");

        let _ = server_done_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
    }

    #[tokio::test]
    async fn test_reload_serves_new_cert() {
        install_rustls_provider();

        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let (ca_cert, ca_key) = generate_test_certs_with_ca(dir.path());
        let acceptor = TlsAcceptor::from_files(
            &dir.path().join("server-cert.pem"),
            &dir.path().join("server-key.pem"),
            Some(&dir.path().join("ca.pem")),
            false,
            None,
            None,
            Vec::new(),
        )
        .expect("failed to build acceptor");

        let client_config = build_test_client_config(&dir.path().join("ca.pem"));
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let server_name =
            rustls::pki_types::ServerName::try_from("localhost").expect("invalid server name");

        // Connection 1: original cert
        let listener1 = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind");
        let addr1 = listener1.local_addr().expect("failed to get local addr");
        let acc1 = acceptor.clone();
        let server_task_1 = tokio::spawn(async move {
            let (stream, _) = listener1.accept().await.expect("accept failed");
            acc1.acceptor()
                .accept(stream)
                .await
                .expect("TLS accept failed");
        });
        let tcp_1 = TcpStream::connect(addr1).await.expect("connect failed");
        let tls_1 = connector
            .connect(server_name.clone(), tcp_1)
            .await
            .expect("TLS handshake failed");
        let server_cert_1 = peer_cert_der(&tls_1);
        server_task_1.await.expect("server task 1 failed");
        assert!(!server_cert_1.is_empty());

        // Generate new server cert + reload
        generate_server_cert(&ca_cert, &ca_key, dir.path());
        acceptor.reload().expect("reload should succeed");

        // Connection 2: new cert on a fresh listener
        let listener2 = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind");
        let addr2 = listener2.local_addr().expect("failed to get local addr");
        let acc2 = acceptor.clone();
        let server_task_2 = tokio::spawn(async move {
            let (stream, _) = listener2.accept().await.expect("accept failed");
            acc2.acceptor()
                .accept(stream)
                .await
                .expect("TLS accept failed");
        });
        let tcp_2 = TcpStream::connect(addr2).await.expect("connect failed");
        let tls_2 = connector
            .connect(server_name.clone(), tcp_2)
            .await
            .expect("TLS handshake failed");
        let server_cert_2 = peer_cert_der(&tls_2);
        server_task_2.await.expect("server task 2 failed");
        assert!(!server_cert_2.is_empty());

        assert_ne!(
            server_cert_1, server_cert_2,
            "served cert should change after reload"
        );
    }

    #[tokio::test]
    async fn test_reload_worker_shutdown() {
        install_rustls_provider();

        let dir = tempfile::tempdir().expect("failed to create tempdir");
        generate_test_certs_with_ca(dir.path());
        let acceptor = TlsAcceptor::from_files(
            &dir.path().join("server-cert.pem"),
            &dir.path().join("server-key.pem"),
            Some(&dir.path().join("ca.pem")),
            false,
            None,
            None,
            Vec::new(),
        )
        .expect("failed to build acceptor");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = acceptor.spawn_reload_worker(shutdown_rx);

        // Give the watcher time to start
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Send shutdown signal and verify the worker exits promptly.
        // shutdown.changed() is checked in both the outer select (waiting
        // for first event) and the inner debounce loop — no file change is
        // needed to exercise the shutdown path.
        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("reload worker should exit after shutdown signal")
            .expect("reload worker should not panic");
    }

    #[tokio::test]
    async fn test_reload_worker_detects_file_change() {
        install_rustls_provider();

        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let (ca_cert, ca_key) = generate_test_certs_with_ca(dir.path());
        let acceptor = TlsAcceptor::from_files(
            &dir.path().join("server-cert.pem"),
            &dir.path().join("server-key.pem"),
            Some(&dir.path().join("ca.pem")),
            false,
            None,
            None,
            Vec::new(),
        )
        .expect("failed to build acceptor");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = acceptor.spawn_reload_worker(shutdown_rx);

        // Give the watcher time to start
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Capture the original cert DER so we can distinguish a stale
        // handshake from a genuinely reloaded config.
        let original_der = load_certs(&dir.path().join("server-cert.pem"))
            .expect("failed to load original cert")[0]
            .as_ref()
            .to_vec();

        // Generate new server cert — the file watcher should detect this
        generate_server_cert(&ca_cert, &ca_key, dir.path());

        // Retry TLS handshake until the watcher picks up the new cert or
        // the deadline expires. Follows the wait_for_status pattern
        // (health_endpoint_integration.rs).
        let client_config = build_test_client_config(&dir.path().join("ca.pem"));
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let server_name =
            rustls::pki_types::ServerName::try_from("localhost").expect("invalid server name");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("failed to bind");
            let listen_addr = listener.local_addr().expect("failed to get local addr");

            let acc = acceptor.clone();
            let server_task = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept failed");
                acc.acceptor().accept(stream).await
            });

            let tcp = TcpStream::connect(listen_addr)
                .await
                .expect("connect failed");
            let handshake_result = tokio::time::timeout(
                Duration::from_millis(500),
                connector.connect(server_name.clone(), tcp),
            )
            .await;

            if let Ok(Ok(tls)) = handshake_result {
                let served_der = peer_cert_der(&tls);
                server_task
                    .await
                    .expect("server task panicked")
                    .expect("TLS accept should succeed");
                if served_der != original_der {
                    break;
                }
                // Handshake succeeded but cert still matches original —
                // watcher hasn't reloaded yet, keep retrying.
            } else {
                server_task.abort();
            }

            assert!(
                tokio::time::Instant::now() < deadline,
                "watcher did not detect cert change within 10s"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        // Clean shutdown
        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn test_reload_mtls_ca_rotation() {
        install_rustls_provider();

        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let (initial_ca_cert, initial_ca_key) = generate_test_certs_with_ca(dir.path());

        let acceptor = TlsAcceptor::from_files(
            &dir.path().join("server-cert.pem"),
            &dir.path().join("server-key.pem"),
            Some(&dir.path().join("ca.pem")),
            true, // require mTLS
            None,
            None,
            Vec::new(),
        )
        .expect("failed to build acceptor with mTLS");

        // Generate new CA and overwrite ca.pem
        let mut new_ca_params =
            CertificateParams::new(Vec::<String>::new()).expect("failed to create CA params");
        new_ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        new_ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "new-ca");
        let new_ca_key = KeyPair::generate().expect("failed to generate new CA key");
        let new_ca_cert = new_ca_params
            .self_signed(&new_ca_key)
            .expect("failed to sign new CA cert");
        std::fs::write(dir.path().join("ca.pem"), new_ca_cert.pem().as_bytes())
            .expect("failed to write new CA");

        // Generate new server cert signed by new CA and reload
        generate_server_cert(&new_ca_cert, &new_ca_key, dir.path());
        acceptor
            .reload()
            .expect("reload with new CA should succeed");

        // Generate client cert signed by new CA, write to files
        let client_key = KeyPair::generate().expect("failed to generate client key");
        let mut client_params =
            CertificateParams::new(Vec::<String>::new()).expect("failed to create client params");
        client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-client");
        client_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        let client_cert = client_params
            .signed_by(&client_key, &new_ca_cert, &new_ca_key)
            .expect("failed to sign client cert");

        // Write client cert + key as PEM files and load via load_certs/load_key
        let client_cert_path = dir.path().join("client-cert.pem");
        let client_key_path = dir.path().join("client-key.pem");
        std::fs::write(&client_cert_path, client_cert.pem().as_bytes())
            .expect("failed to write client cert");
        std::fs::write(&client_key_path, client_key.serialize_pem().as_bytes())
            .expect("failed to write client key");

        let client_cert_chain = load_certs(&client_cert_path).expect("failed to load client cert");
        let client_private_key = load_key(&client_key_path).expect("failed to load client key");

        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(CertificateDer::from(new_ca_cert.der().to_vec()))
            .expect("failed to add new CA to root store");
        let new_ca_client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_client_auth_cert(client_cert_chain, client_private_key)
                .expect("failed to set client auth cert"),
        );

        // Verify a real handshake succeeds with the new CA
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind");
        let listen_addr = listener.local_addr().expect("failed to get local addr");

        let acceptor_srv = acceptor.clone();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept failed");
            acceptor_srv
                .acceptor()
                .accept(stream)
                .await
                .expect("TLS accept with new mTLS CA failed");
        });

        let connector = tokio_rustls::TlsConnector::from(new_ca_client_config);
        let server_name =
            rustls::pki_types::ServerName::try_from("localhost").expect("invalid server name");
        let tcp = TcpStream::connect(listen_addr)
            .await
            .expect("connect failed");
        connector
            .connect(server_name.clone(), tcp)
            .await
            .expect("mTLS handshake with new CA should succeed");

        server_task.await.expect("server task failed");

        // Verify old CA is no longer trusted: a client cert signed by the
        // initial CA should be rejected after rotation.
        let old_client_key = KeyPair::generate().expect("failed to generate old client key");
        let mut old_client_params = CertificateParams::new(Vec::<String>::new())
            .expect("failed to create old client params");
        old_client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "old-client");
        old_client_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        let old_client_cert = old_client_params
            .signed_by(&old_client_key, &initial_ca_cert, &initial_ca_key)
            .expect("failed to sign old client cert");

        let old_cert_path = dir.path().join("old-client-cert.pem");
        let old_key_path = dir.path().join("old-client-key.pem");
        std::fs::write(&old_cert_path, old_client_cert.pem().as_bytes())
            .expect("failed to write old client cert");
        std::fs::write(&old_key_path, old_client_key.serialize_pem().as_bytes())
            .expect("failed to write old client key");

        let old_cert_chain = load_certs(&old_cert_path).expect("failed to load old client cert");
        let old_key_der = load_key(&old_key_path).expect("failed to load old client key");

        let mut old_root_store = rustls::RootCertStore::empty();
        old_root_store
            .add(CertificateDer::from(new_ca_cert.der().to_vec()))
            .expect("failed to add new CA to root store");
        let old_ca_client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(old_root_store)
                .with_client_auth_cert(old_cert_chain, old_key_der)
                .expect("failed to set old client auth cert"),
        );

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind");
        let listen_addr = listener.local_addr().expect("failed to get local addr");

        let acceptor_srv = acceptor.clone();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept failed");
            let result = acceptor_srv.acceptor().accept(stream).await;
            assert!(
                result.is_err(),
                "TLS accept should reject client cert signed by old CA"
            );
        });

        // Drive the client side so the server has something to accept.
        // tokio_rustls::TlsConnector::connect() may return Ok even when the
        // server rejects the client cert (TLS 1.3 post-handshake auth),
        // so the authoritative check is the server-side accept result above.
        let connector = tokio_rustls::TlsConnector::from(old_ca_client_config);
        let tcp = TcpStream::connect(listen_addr)
            .await
            .expect("connect failed");
        let _ = connector.connect(server_name, tcp).await;

        server_task.await.expect("server task failed");
    }

    /// Generate a cert+key pair with given SANs, signed by the provided CA,
    /// and write them to the specified files in `dir`.
    fn generate_named_cert(
        ca_cert: &rcgen::Certificate,
        ca_key: &KeyPair,
        dir: &Path,
        cert_file: &str,
        key_file: &str,
        san: &str,
    ) {
        let params =
            CertificateParams::new(vec![san.to_string()]).expect("failed to create cert params");
        let key = KeyPair::generate().expect("failed to generate key");
        let cert = params
            .signed_by(&key, ca_cert, ca_key)
            .expect("failed to sign cert");
        write_test_file(dir, cert_file, cert.pem().as_bytes());
        write_test_file(dir, key_file, key.serialize_pem().as_bytes());
    }

    #[test]
    fn test_sni_matches_exact() {
        assert!(sni_matches("example.com", "example.com"));
        assert!(!sni_matches("example.com", "other.com"));
        assert!(!sni_matches("example.com", "sub.example.com"));
    }

    #[test]
    fn test_sni_matches_wildcard() {
        assert!(sni_matches("*.example.com", "foo.example.com"));
        assert!(sni_matches("*.example.com", "bar.example.com"));
        // Must not match bare domain.
        assert!(!sni_matches("*.example.com", "example.com"));
        // Must not match nested subdomains (RFC 6125).
        assert!(!sni_matches("*.example.com", "sub.foo.example.com"));
        // Must not match unrelated domain with same suffix.
        assert!(!sni_matches("*.example.com", "notexample.com"));
    }

    #[test]
    fn test_build_cert_resolver_returns_none_when_no_external() {
        install_rustls_provider();
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        generate_test_certs_with_ca(dir.path());

        let result = build_cert_resolver(
            &dir.path().join("server-cert.pem"),
            &dir.path().join("server-key.pem"),
            None,
            None,
            &[],
        )
        .expect("build_cert_resolver should succeed");
        assert!(result.is_none(), "should return None when no external cert");
    }

    #[test]
    fn test_build_cert_resolver_errors_on_cert_without_key() {
        install_rustls_provider();
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        generate_test_certs_with_ca(dir.path());

        let result = build_cert_resolver(
            &dir.path().join("server-cert.pem"),
            &dir.path().join("server-key.pem"),
            Some(&dir.path().join("server-cert.pem")),
            None,
            &["example.com".to_string()],
        );
        let err = result.expect_err("should error when key is missing");
        assert!(
            err.to_string().contains("external_key_path is missing"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_build_cert_resolver_errors_on_key_without_cert() {
        install_rustls_provider();
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        generate_test_certs_with_ca(dir.path());

        let result = build_cert_resolver(
            &dir.path().join("server-cert.pem"),
            &dir.path().join("server-key.pem"),
            None,
            Some(&dir.path().join("server-key.pem")),
            &["example.com".to_string()],
        );
        let err = result.expect_err("should error when cert is missing");
        assert!(
            err.to_string().contains("external_cert_path is missing"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_build_cert_resolver_errors_on_empty_server_names() {
        install_rustls_provider();
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let (ca_cert, ca_key) = generate_test_certs_with_ca(dir.path());
        generate_named_cert(
            &ca_cert,
            &ca_key,
            dir.path(),
            "ext-cert.pem",
            "ext-key.pem",
            "external.example.com",
        );

        let result = build_cert_resolver(
            &dir.path().join("server-cert.pem"),
            &dir.path().join("server-key.pem"),
            Some(&dir.path().join("ext-cert.pem")),
            Some(&dir.path().join("ext-key.pem")),
            &[],
        );
        let err = result.expect_err("should error when server names are empty");
        assert!(
            err.to_string().contains("external_server_names is empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_dual_cert_resolver_returns_external_on_sni_match() {
        install_rustls_provider();
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let (ca_cert, ca_key) = generate_test_certs_with_ca(dir.path());
        generate_named_cert(
            &ca_cert,
            &ca_key,
            dir.path(),
            "ext-cert.pem",
            "ext-key.pem",
            "external.example.com",
        );

        let internal = load_certified_key(
            &dir.path().join("server-cert.pem"),
            &dir.path().join("server-key.pem"),
        )
        .expect("load internal");
        let external = load_certified_key(
            &dir.path().join("ext-cert.pem"),
            &dir.path().join("ext-key.pem"),
        )
        .expect("load external");

        let internal_der = internal.cert[0].as_ref().to_vec();
        let external_der = external.cert[0].as_ref().to_vec();

        // `ClientHello` cannot be constructed directly in tests, so
        // SNI-based selection is exercised in the async integration test
        // below. Here we verify the certs are distinct so the integration
        // test's DER comparisons are meaningful.
        assert_ne!(
            internal_der, external_der,
            "internal and external certs should be distinct"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dual_cert_resolver_sni_selects_correct_cert() {
        install_rustls_provider();

        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let (ca_cert, ca_key) = generate_test_certs_with_ca(dir.path());
        generate_named_cert(
            &ca_cert,
            &ca_key,
            dir.path(),
            "ext-cert.pem",
            "ext-key.pem",
            "external.example.com",
        );

        // Snapshot the DER of the internal and external leaf certs.
        let internal_der = load_certs(&dir.path().join("server-cert.pem"))
            .expect("load internal certs")[0]
            .as_ref()
            .to_vec();
        let external_der = load_certs(&dir.path().join("ext-cert.pem"))
            .expect("load external certs")[0]
            .as_ref()
            .to_vec();

        let acceptor = TlsAcceptor::from_files(
            &dir.path().join("server-cert.pem"),
            &dir.path().join("server-key.pem"),
            Some(&dir.path().join("ca.pem")),
            false,
            Some(&dir.path().join("ext-cert.pem")),
            Some(&dir.path().join("ext-key.pem")),
            vec!["external.example.com".to_string()],
        )
        .expect("failed to build acceptor");

        let client_config = build_test_client_config(&dir.path().join("ca.pem"));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind");
        let listen_addr = listener.local_addr().expect("failed to get local addr");

        // --- Connection 1: SNI matches external name → external cert ---
        let acceptor_srv = acceptor.clone();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept failed");
            acceptor_srv
                .acceptor()
                .accept(stream)
                .await
                .expect("TLS accept failed")
        });

        let connector = tokio_rustls::TlsConnector::from(client_config.clone());
        let tcp = TcpStream::connect(listen_addr)
            .await
            .expect("connect failed");
        let server_name = "external.example.com"
            .try_into()
            .expect("invalid server name");
        let tls = connector
            .connect(server_name, tcp)
            .await
            .expect("TLS connect failed");

        assert_eq!(
            peer_cert_der(&tls),
            external_der,
            "SNI matching external name should serve external cert"
        );
        drop(tls);
        let _ = server_task.await;

        // --- Connection 2: SNI = "localhost" → internal cert ---
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind");
        let listen_addr = listener.local_addr().expect("failed to get local addr");

        let acceptor_srv = acceptor.clone();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept failed");
            acceptor_srv
                .acceptor()
                .accept(stream)
                .await
                .expect("TLS accept failed")
        });

        let connector = tokio_rustls::TlsConnector::from(client_config);
        let tcp = TcpStream::connect(listen_addr)
            .await
            .expect("connect failed");
        let server_name = "localhost".try_into().expect("invalid server name");
        let tls = connector
            .connect(server_name, tcp)
            .await
            .expect("TLS connect failed");

        assert_eq!(
            peer_cert_der(&tls),
            internal_der,
            "SNI not matching external name should serve internal cert"
        );
        drop(tls);
        let _ = server_task.await;
    }
}
