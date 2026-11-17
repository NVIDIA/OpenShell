// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Narrow metrics HTTPS/mTLS listener. All TLS operations use openshell-crypto;
//! rustls types below provide protocol configuration and PEM parsing only.

use std::io::Read as _;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use miette::{IntoDiagnostic as _, Result, WrapErr as _};
use openshell_core::MetricsTlsConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const RELOAD_INTERVAL: Duration = Duration::from_secs(5);
const MAX_PEM_BYTES: u64 = 1024 * 1024;

struct Material {
    pem: Vec<Vec<u8>>,
    server: Arc<rustls::ServerConfig>,
}

pub(super) struct Config {
    paths: MetricsTlsConfig,
    material: RwLock<Material>,
}

impl Config {
    pub(super) fn load(paths: MetricsTlsConfig) -> Result<Self> {
        let pem = read_material(&paths)?;
        let server = build_config(&paths, &pem)?;
        Ok(Self {
            paths,
            material: RwLock::new(Material { pem, server }),
        })
    }

    fn acceptor(&self) -> TlsAcceptor {
        let material = self
            .material
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        TlsAcceptor::from(material.server.clone())
    }

    fn reload(&self) -> Result<bool> {
        // Reopening each path follows Kubernetes projected Secret symlinks.
        let pem = read_material(&self.paths)?;
        if self
            .material
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pem
            == pem
        {
            return Ok(false);
        }
        // Build and validate all material before publishing any replacement.
        let server = build_config(&self.paths, &pem)?;
        *self
            .material
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Material { pem, server };
        Ok(true)
    }
}

fn read_pem(path: &std::path::Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("read metrics TLS file {}", path.display()))?
        .take(MAX_PEM_BYTES + 1)
        .read_to_end(&mut bytes)
        .into_diagnostic()?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_PEM_BYTES {
        return Err(miette::miette!(
            "metrics TLS PEM file is empty or exceeds 1 MiB"
        ));
    }
    Ok(bytes)
}

fn read_material(paths: &MetricsTlsConfig) -> Result<Vec<Vec<u8>>> {
    let mut pem = vec![read_pem(&paths.cert_path)?, read_pem(&paths.key_path)?];
    if let Some(ca) = &paths.client_ca_path {
        pem.push(read_pem(ca)?);
    }
    Ok(pem)
}

fn certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .into_diagnostic()?;
    if certs.is_empty() {
        return Err(miette::miette!("metrics TLS PEM contains no certificates"));
    }
    Ok(certs)
}

fn build_config(paths: &MetricsTlsConfig, pem: &[Vec<u8>]) -> Result<Arc<rustls::ServerConfig>> {
    let certs = certificates(&pem[0])?;
    let key = PrivateKeyDer::from_pem_slice(&pem[1]).into_diagnostic()?;
    let builder = openshell_crypto::tls::try_server_builder().into_diagnostic()?;
    let builder = if let Some(ca) = pem.get(2) {
        let mut roots = rustls::RootCertStore::empty();
        for cert in certificates(ca)? {
            roots.add(cert).into_diagnostic()?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            openshell_crypto::tls::configuration_provider(),
        );
        let verifier = if paths.require_client_auth {
            verifier
        } else {
            verifier.allow_unauthenticated()
        };
        builder.with_client_cert_verifier(verifier.build().into_diagnostic()?)
    } else {
        if paths.require_client_auth {
            return Err(miette::miette!("metrics mTLS requires a client CA"));
        }
        builder.with_no_client_auth()
    };
    let mut config = builder.with_single_cert(certs, key).into_diagnostic()?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub(super) async fn serve(listener: TcpListener, router: axum::Router, tls: Arc<Config>) {
    let permits = Arc::new(Semaphore::new(64));
    let mut connections = JoinSet::new();
    let mut reload = tokio::time::interval(RELOAD_INTERVAL);
    reload.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Initial material was just loaded; the first tick is immediate.
    reload.tick().await;
    loop {
        tokio::select! {
            _ = reload.tick() => {
                let tls = tls.clone();
                match tokio::task::spawn_blocking(move || tls.reload()).await {
                    Ok(Ok(true)) => tracing::info!(listener = "metrics", "Supervisor metrics TLS configuration reloaded"),
                    Ok(Ok(false)) => {},
                    Ok(Err(error)) => tracing::warn!(%error, listener = "metrics", "Metrics TLS reload failed; retaining last valid configuration"),
                    Err(error) => tracing::warn!(%error, listener = "metrics", "Metrics TLS reload task failed"),
                }
            }
            _ = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => {
                        tracing::warn!(%error, listener = "metrics", "Metrics TLS accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                let acceptor = tls.acceptor();
                let service = TowerToHyperService::new(router.clone());
                connections.spawn(async move {
                    let _permit = permit;
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => {
                            let mut builder = Builder::new(TokioExecutor::new());
                            builder.http1().timer(TokioTimer::new()).header_read_timeout(HANDSHAKE_TIMEOUT);
                            if let Err(error) = builder.serve_connection(TokioIo::new(stream), service).await {
                                tracing::debug!(%error, listener = "metrics", "Metrics HTTPS connection closed");
                            }
                        }
                        Ok(Err(error)) => tracing::debug!(%error, listener = "metrics", "Metrics TLS handshake rejected"),
                        Err(_) => tracing::debug!(listener = "metrics", "Metrics TLS handshake timed out"),
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_bootstrap::pki::{PkiBundle, generate_pki};
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    struct Fixture {
        _dir: tempfile::TempDir,
        paths: MetricsTlsConfig,
        bundle: PkiBundle,
    }

    impl Fixture {
        fn new(client_ca: bool, required: bool) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let paths = MetricsTlsConfig {
                cert_path: dir.path().join("tls.crt"),
                key_path: dir.path().join("tls.key"),
                client_ca_path: client_ca.then(|| dir.path().join("ca.crt")),
                require_client_auth: required,
            };
            let bundle = generate_pki(&["metrics.test".into()]).unwrap();
            let fixture = Self {
                _dir: dir,
                paths,
                bundle,
            };
            fixture.write(&fixture.bundle);
            fixture
        }

        fn write(&self, bundle: &PkiBundle) {
            std::fs::write(&self.paths.cert_path, &bundle.server_cert_pem).unwrap();
            std::fs::write(&self.paths.key_path, &bundle.server_key_pem).unwrap();
            if let Some(ca) = &self.paths.client_ca_path {
                std::fs::write(ca, &bundle.ca_cert_pem).unwrap();
            }
        }
    }

    fn client(server: &PkiBundle, identity: Option<&PkiBundle>) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in certificates(server.ca_cert_pem.as_bytes()).unwrap() {
            roots.add(cert).unwrap();
        }
        let builder = openshell_crypto::tls::try_client_builder()
            .unwrap()
            .with_root_certificates(roots);
        Arc::new(match identity {
            Some(identity) => builder
                .with_client_auth_cert(
                    certificates(identity.client_cert_pem.as_bytes()).unwrap(),
                    PrivateKeyDer::from_pem_slice(identity.client_key_pem.as_bytes()).unwrap(),
                )
                .unwrap(),
            None => builder.with_no_client_auth(),
        })
    }

    async fn start(config: Arc<Config>) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = axum::Router::new().route(
            "/metrics",
            axum::routing::get(|| async { "test_metric 1\n" }),
        );
        (address, tokio::spawn(serve(listener, router, config)))
    }

    async fn scrape(address: std::net::SocketAddr, client: Arc<rustls::ClientConfig>) -> bool {
        let operation = async {
            let stream = tokio::net::TcpStream::connect(address).await?;
            openshell_core::net::set_tcp_nodelay_best_effort(&stream);
            let mut stream = tokio_rustls::TlsConnector::from(client)
                .connect(ServerName::try_from("metrics.test").unwrap(), stream)
                .await?;
            stream
                .write_all(
                    b"GET /metrics HTTP/1.1\r\nHost: metrics.test\r\nConnection: close\r\n\r\n",
                )
                .await?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;
            Ok::<_, std::io::Error>(
                response.starts_with(b"HTTP/1.1 200")
                    && response.windows(13).any(|w| w == b"test_metric 1"),
            )
        };
        matches!(
            tokio::time::timeout(Duration::from_secs(3), operation).await,
            Ok(Ok(true))
        )
    }

    #[tokio::test]
    async fn https_scrapes_without_a_client_certificate_and_rejects_plaintext() {
        let f = Fixture::new(false, false);
        let (address, server) = start(Arc::new(Config::load(f.paths.clone()).unwrap())).await;
        // An idle plaintext connection cannot prevent an independent TLS scrape.
        let mut plaintext = tokio::net::TcpStream::connect(address).await.unwrap();
        assert!(scrape(address, client(&f.bundle, None)).await);
        plaintext
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: metrics.test\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), plaintext.read_to_end(&mut response))
            .await;
        assert!(!response.windows(13).any(|w| w == b"test_metric 1"));
        server.abort();
    }

    #[tokio::test]
    async fn mtls_accepts_only_the_scraper_ca_and_optional_auth_still_verifies_presented_certificates()
     {
        let f = Fixture::new(true, true);
        let wrong = Fixture::new(true, true);
        let (address, server) = start(Arc::new(Config::load(f.paths.clone()).unwrap())).await;
        assert!(scrape(address, client(&f.bundle, Some(&f.bundle))).await);
        assert!(!scrape(address, client(&f.bundle, None)).await);
        assert!(!scrape(address, client(&f.bundle, Some(&wrong.bundle))).await);
        server.abort();

        let mut optional = f.paths.clone();
        optional.require_client_auth = false;
        let (address, server) = start(Arc::new(Config::load(optional).unwrap())).await;
        assert!(scrape(address, client(&f.bundle, None)).await);
        assert!(!scrape(address, client(&f.bundle, Some(&wrong.bundle))).await);
        server.abort();
    }

    #[tokio::test]
    async fn valid_rotation_replaces_the_bundle_and_bad_rotation_retains_the_last_valid_config() {
        let f = Fixture::new(true, true);
        let tls = Arc::new(Config::load(f.paths.clone()).unwrap());
        let (address, server) = start(tls.clone()).await;
        assert!(scrape(address, client(&f.bundle, Some(&f.bundle))).await);
        assert!(!tls.reload().unwrap());
        let next = generate_pki(&["metrics.test".into()]).unwrap();
        f.write(&next);
        assert!(tls.reload().unwrap());
        assert!(scrape(address, client(&next, Some(&next))).await);
        assert!(!scrape(address, client(&f.bundle, Some(&f.bundle))).await);
        std::fs::write(&f.paths.key_path, b"invalid replacement").unwrap();
        assert!(tls.reload().is_err());
        assert!(scrape(address, client(&next, Some(&next))).await);
        server.abort();
    }

    #[test]
    fn invalid_initial_material_and_missing_client_ca_fail_closed() {
        let f = Fixture::new(false, true);
        assert!(Config::load(f.paths).is_err());
        let f = Fixture::new(true, true);
        std::fs::write(f.paths.client_ca_path.as_ref().unwrap(), b"not a CA").unwrap();
        assert!(Config::load(f.paths.clone()).is_err());
        f.write(&f.bundle);
        let wrong = generate_pki(&[]).unwrap();
        std::fs::write(&f.paths.key_path, wrong.server_key_pem).unwrap();
        assert!(Config::load(f.paths).is_err());
    }
}
