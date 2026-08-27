// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::time::Duration;

#[cfg(unix)]
use hyper_util::rt::TokioIo;
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
use tonic::transport::Uri;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
#[cfg(unix)]
use tower::service_fn;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);

/// Trust policy used to authenticate a remote extension service.
///
/// This enum is intentionally independent of middleware and interceptor
/// protocols. Future transport identities, such as SPIFFE X.509-SVIDs or
/// pinned public keys, can be added here without changing either caller.
#[derive(Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ExtensionServerTrust {
    /// Authenticate the HTTPS service with the platform trust store and the
    /// endpoint's DNS name.
    #[default]
    PlatformRoots,
    /// Authenticate the HTTPS service with only this PEM CA bundle and the
    /// endpoint's DNS name.
    CustomCaPem(Vec<u8>),
}

impl std::fmt::Debug for ExtensionServerTrust {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PlatformRoots => formatter.write_str("PlatformRoots"),
            Self::CustomCaPem(_) => formatter.write_str("CustomCaPem(<redacted>)"),
        }
    }
}

/// Configuration for an outbound extension gRPC channel.
#[derive(Clone, PartialEq, Eq)]
pub struct ExtensionChannelConfig {
    endpoint: String,
    server_trust: ExtensionServerTrust,
}

impl ExtensionChannelConfig {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            server_trust: ExtensionServerTrust::default(),
        }
    }

    /// Select how the remote extension service is authenticated.
    #[must_use]
    pub fn with_server_trust(mut self, server_trust: ExtensionServerTrust) -> Self {
        self.server_trust = server_trust;
        self
    }

    /// Pin HTTPS verification to this CA bundle instead of platform roots.
    /// Normal TLS hostname verification remains enabled.
    #[must_use]
    pub fn with_custom_ca_pem(self, custom_ca_pem: impl Into<Vec<u8>>) -> Self {
        self.with_server_trust(ExtensionServerTrust::CustomCaPem(custom_ca_pem.into()))
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn server_trust(&self) -> &ExtensionServerTrust {
        &self.server_trust
    }

    /// Returns whether HTTPS verification uses an operator-provided CA bundle.
    pub fn has_custom_ca(&self) -> bool {
        matches!(&self.server_trust, ExtensionServerTrust::CustomCaPem(_))
    }
}

impl std::fmt::Debug for ExtensionChannelConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExtensionChannelConfig")
            .field("endpoint", &self.endpoint)
            .field("server_trust", &self.server_trust)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("extension endpoint must not be empty")]
    EmptyEndpoint,
    #[error("extension endpoint must use http://, https://, or unix://")]
    UnsupportedScheme,
    #[error("custom CA certificates require an https:// extension endpoint")]
    CustomCaRequiresHttps,
    #[error("unix extension endpoint must contain an absolute socket path")]
    InvalidUnixPath,
    #[error("unix extension endpoints are not supported on this platform")]
    UnixUnsupported,
    #[error("invalid extension endpoint: {0}")]
    InvalidEndpoint(#[source] tonic::transport::Error),
    #[error("could not configure extension TLS: {0}")]
    Tls(#[source] tonic::transport::Error),
    #[error("could not connect to extension service: {0}")]
    Connect(#[source] tonic::transport::Error),
}

pub async fn connect_channel(config: &ExtensionChannelConfig) -> Result<Channel, TransportError> {
    validate_config(config)?;
    if let Some(path) = config.endpoint.strip_prefix("unix://") {
        return connect_unix(PathBuf::from(path)).await;
    }

    let mut endpoint = standard_endpoint(&config.endpoint)?;
    if config.endpoint.starts_with("https://") {
        let tls = match &config.server_trust {
            ExtensionServerTrust::PlatformRoots => ClientTlsConfig::new().with_enabled_roots(),
            ExtensionServerTrust::CustomCaPem(pem) => {
                ClientTlsConfig::new().ca_certificate(Certificate::from_pem(pem))
            }
        };
        endpoint = endpoint.tls_config(tls).map_err(TransportError::Tls)?;
    }
    endpoint.connect().await.map_err(TransportError::Connect)
}

fn validate_config(config: &ExtensionChannelConfig) -> Result<(), TransportError> {
    if config.endpoint.is_empty() {
        return Err(TransportError::EmptyEndpoint);
    }
    let is_https = config.endpoint.starts_with("https://");
    let is_http = config.endpoint.starts_with("http://");
    let is_unix = config.endpoint.starts_with("unix://");
    if !is_https && !is_http && !is_unix {
        return Err(TransportError::UnsupportedScheme);
    }
    if !matches!(&config.server_trust, ExtensionServerTrust::PlatformRoots) && !is_https {
        return Err(TransportError::CustomCaRequiresHttps);
    }
    if let Some(path) = config.endpoint.strip_prefix("unix://")
        && (path.is_empty() || !PathBuf::from(path).is_absolute())
    {
        return Err(TransportError::InvalidUnixPath);
    }
    Ok(())
}

fn standard_endpoint(uri: &str) -> Result<Endpoint, TransportError> {
    Endpoint::from_shared(uri.to_string())
        .map(|endpoint| {
            endpoint
                .connect_timeout(CONNECT_TIMEOUT)
                .http2_keep_alive_interval(KEEP_ALIVE_INTERVAL)
                .keep_alive_while_idle(true)
                .keep_alive_timeout(KEEP_ALIVE_TIMEOUT)
                .http2_adaptive_window(true)
        })
        .map_err(TransportError::InvalidEndpoint)
}

#[cfg(unix)]
async fn connect_unix(path: PathBuf) -> Result<Channel, TransportError> {
    standard_endpoint("http://[::]:50051")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await
        .map_err(TransportError::Connect)
}

#[cfg(not(unix))]
async fn connect_unix(_path: PathBuf) -> Result<Channel, TransportError> {
    Err(TransportError::UnixUnsupported)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::future::{Ready, ready};
    use std::task::{Context, Poll};

    use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::body::Body;
    use tonic::server::NamedService;
    use tonic::transport::{Identity, Server, ServerTlsConfig};
    use tower::Service;

    use super::*;

    #[derive(Clone)]
    struct NoopGrpcService;

    impl NamedService for NoopGrpcService {
        const NAME: &'static str = "openshell.test.Noop";
    }

    impl Service<http::Request<Body>> for NoopGrpcService {
        type Response = http::Response<Body>;
        type Error = Infallible;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: http::Request<Body>) -> Self::Future {
            ready(Ok(http::Response::new(Body::empty())))
        }
    }

    #[test]
    fn accepts_supported_endpoint_forms() {
        for endpoint in ["http://127.0.0.1:50051", "https://middleware.example:443"] {
            validate_config(&ExtensionChannelConfig::new(endpoint)).unwrap();
        }
        #[cfg(unix)]
        validate_config(&ExtensionChannelConfig::new(
            "unix:///run/openshell/middleware.sock",
        ))
        .unwrap();
    }

    #[test]
    fn server_trust_is_an_explicit_shared_policy() {
        let default = ExtensionChannelConfig::new("https://middleware.example");
        assert!(matches!(
            default.server_trust(),
            ExtensionServerTrust::PlatformRoots
        ));

        let custom =
            default.with_server_trust(ExtensionServerTrust::CustomCaPem(b"test CA".to_vec()));
        assert!(matches!(
            custom.server_trust(),
            ExtensionServerTrust::CustomCaPem(pem) if pem == b"test CA"
        ));
    }

    #[test]
    fn custom_ca_is_restricted_to_https() {
        for endpoint in [
            "http://127.0.0.1:50051",
            "unix:///run/openshell/middleware.sock",
        ] {
            let config = ExtensionChannelConfig::new(endpoint).with_custom_ca_pem(b"test CA");
            assert!(matches!(
                validate_config(&config),
                Err(TransportError::CustomCaRequiresHttps)
            ));
        }
        validate_config(
            &ExtensionChannelConfig::new("https://middleware.example")
                .with_custom_ca_pem(b"test CA"),
        )
        .unwrap();
    }

    #[test]
    fn rejects_unsupported_schemes_and_relative_unix_paths() {
        assert!(matches!(
            validate_config(&ExtensionChannelConfig::new("tcp://middleware:50051")),
            Err(TransportError::UnsupportedScheme)
        ));
        assert!(matches!(
            validate_config(&ExtensionChannelConfig::new("unix://relative.sock")),
            Err(TransportError::InvalidUnixPath)
        ));
    }

    #[test]
    fn debug_does_not_render_ca_contents() {
        let secretish_pem = b"private deployment CA material";
        let config = ExtensionChannelConfig::new("https://middleware.example")
            .with_custom_ca_pem(secretish_pem);
        assert!(!format!("{config:?}").contains("private deployment"));
    }

    #[tokio::test]
    async fn custom_ca_verifies_certificate_and_hostname() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let server_key = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = server_params.signed_by(&server_key, &ca, &ca_key).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let incoming = TcpListenerStream::new(listener);
        let tls = ServerTlsConfig::new().identity(Identity::from_pem(
            server_cert.pem(),
            server_key.serialize_pem(),
        ));
        tokio::spawn(async move {
            Server::builder()
                .tls_config(tls)
                .unwrap()
                .add_service(NoopGrpcService)
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        });

        let trusted = ExtensionChannelConfig::new(format!("https://localhost:{}", address.port()))
            .with_custom_ca_pem(ca.pem());
        connect_channel(&trusted).await.unwrap();

        let wrong_hostname =
            ExtensionChannelConfig::new(format!("https://127.0.0.1:{}", address.port()))
                .with_custom_ca_pem(ca.pem());
        assert!(matches!(
            connect_channel(&wrong_hostname).await,
            Err(TransportError::Connect(_))
        ));

        let rogue_key = KeyPair::generate().unwrap();
        let mut rogue_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        rogue_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let rogue_ca = rogue_params.self_signed(&rogue_key).unwrap();
        let wrong_ca = ExtensionChannelConfig::new(format!("https://localhost:{}", address.port()))
            .with_custom_ca_pem(rogue_ca.pem());
        assert!(matches!(
            connect_channel(&wrong_ca).await,
            Err(TransportError::Connect(_))
        ));
    }
}
