// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::error::Error as StdError;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

#[cfg(unix)]
use hyper_util::rt::TokioIo;
#[cfg(unix)]
use tokio::net::UnixStream;
use tonic::Status;
#[cfg(unix)]
use tonic::transport::Uri;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
#[cfg(unix)]
use tower::service_fn;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);
/// Longest time a call without a deadline keeps being sent again.
const UNPROCESSED_RETRY_WINDOW: Duration = Duration::from_secs(5);
const UNPROCESSED_RETRY_FIRST_PAUSE: Duration = Duration::from_millis(5);
const UNPROCESSED_RETRY_MAX_PAUSE: Duration = Duration::from_millis(100);

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

/// Returns whether `status` proves the extension service never started
/// processing the call, so sending it again cannot run it twice.
///
/// Three transport outcomes give that proof:
///
/// - The connection attempt failed, so no request bytes were sent.
/// - The request was still queued in the client when the connection closed.
/// - The service refused the stream: either a graceful `GOAWAY` whose last
///   stream ID is below this call's stream, or `RST_STREAM(REFUSED_STREAM)`.
///
/// Every other failure, including a connection that drops after the request
/// was sent, leaves the outcome unknown and returns `false`.
fn call_was_not_processed(status: &Status) -> bool {
    // An I/O error counts only while connecting. Errors on an established
    // connection reach the status through `hyper::Error` or `h2::Error`.
    let mut connecting = true;
    let mut source = status.source();
    while let Some(error) = source {
        if let Some(error) = error.downcast_ref::<hyper::Error>() {
            if error.is_canceled() {
                return true;
            }
            connecting = false;
        }
        if let Some(error) = error.downcast_ref::<h2::Error>() {
            if error.is_remote()
                && matches!(
                    (error.is_go_away(), error.reason()),
                    (true, Some(h2::Reason::NO_ERROR)) | (false, Some(h2::Reason::REFUSED_STREAM))
                )
            {
                return true;
            }
            connecting = false;
        }
        if let Some(error) = error.downcast_ref::<io::Error>() {
            return connecting
                && matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::NotFound
                );
        }
        source = error.source();
    }
    false
}

/// Sends a unary extension call, and sends it again while the failure proves
/// the service never started processing it.
///
/// An extension service that restarts or hands over to another instance
/// closes its connections. Calls caught by that close fail in the transport
/// without reaching a handler; this sends them again on the next connection.
/// Failures with an unknown outcome and every answer from the service are
/// returned as they are.
///
/// `call` builds and sends one attempt. No attempt starts after `deadline`,
/// or after a fixed window when there is none, and the failure of the last
/// attempt is returned. An attempt still running at `deadline` is the
/// caller's to cut short.
pub async fn call_with_retries<T, F, Fut>(
    deadline: Option<tokio::time::Instant>,
    mut call: F,
) -> Result<T, Status>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, Status>>,
{
    let give_up =
        deadline.unwrap_or_else(|| tokio::time::Instant::now() + UNPROCESSED_RETRY_WINDOW);
    let mut pause = UNPROCESSED_RETRY_FIRST_PAUSE;
    loop {
        let status = match call().await {
            Ok(response) => return Ok(response),
            Err(status) => status,
        };
        if !call_was_not_processed(&status) || tokio::time::Instant::now() + pause > give_up {
            return Err(status);
        }
        tokio::time::sleep(pause).await;
        pause = (pause * 2).min(UNPROCESSED_RETRY_MAX_PAUSE);
    }
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

    use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa};
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
        let ca_key = openshell_crypto::pki::generate_keypair().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = openshell_crypto::pki::self_signed(ca_params, &ca_key).unwrap();

        let server_key = openshell_crypto::pki::generate_keypair().unwrap();
        let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert =
            openshell_crypto::pki::signed_by(server_params, &server_key, &ca, &ca_key).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let incoming = TcpListenerStream::new(listener);
        let tls = ServerTlsConfig::new().identity(Identity::from_pem(
            server_cert.pem(),
            server_key.serialize_pem().unwrap(),
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

        let rogue_key = openshell_crypto::pki::generate_keypair().unwrap();
        let mut rogue_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        rogue_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let rogue_ca = openshell_crypto::pki::self_signed(rogue_params, &rogue_key).unwrap();
        let wrong_ca = ExtensionChannelConfig::new(format!("https://localhost:{}", address.port()))
            .with_custom_ca_pem(rogue_ca.pem());
        assert!(matches!(
            connect_channel(&wrong_ca).await,
            Err(TransportError::Connect(_))
        ));
    }

    /// A failure to connect, as the channel reports it.
    fn connect_failure(kind: io::ErrorKind) -> Status {
        Status::from_error(Box::new(io::Error::new(kind, "connect failure")))
    }

    /// A status the service answered with; it carries no transport error.
    fn answered(code: tonic::Code) -> Status {
        Status::new(code, "answered")
    }

    #[test]
    fn a_failed_connection_attempt_proves_the_call_was_not_processed() {
        for kind in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::NotFound,
        ] {
            assert!(call_was_not_processed(&connect_failure(kind)));
        }
        // A certificate the client rejects fails every attempt the same way.
        assert!(!call_was_not_processed(&connect_failure(
            io::ErrorKind::InvalidData
        )));
    }

    #[test]
    fn an_answer_from_the_service_is_never_sent_again() {
        for code in [
            tonic::Code::Unavailable,
            tonic::Code::Cancelled,
            tonic::Code::Internal,
            tonic::Code::Unknown,
        ] {
            assert!(!call_was_not_processed(&answered(code)));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_unprocessed_call_is_sent_again_until_it_is_answered() {
        let mut attempts = 0;
        let answer = call_with_retries(None, || {
            attempts += 1;
            let refused = attempts < 4;
            async move {
                if refused {
                    Err(connect_failure(io::ErrorKind::ConnectionRefused))
                } else {
                    Ok("answer")
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(answer, "answer");
        assert_eq!(attempts, 4);
    }

    #[tokio::test(start_paused = true)]
    async fn a_call_with_an_unknown_outcome_is_sent_once() {
        for status in [
            connect_failure(io::ErrorKind::InvalidData),
            answered(tonic::Code::Unavailable),
            answered(tonic::Code::PermissionDenied),
        ] {
            let code = status.code();
            let mut status = Some(status);
            let mut attempts = 0;
            let result: Result<(), Status> = call_with_retries(None, || {
                attempts += 1;
                let status = status.take().expect("one attempt");
                async move { Err(status) }
            })
            .await;
            assert_eq!(result.unwrap_err().code(), code);
            assert_eq!(attempts, 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn sending_again_stops_at_the_window() {
        let started = tokio::time::Instant::now();
        let result: Result<(), Status> = call_with_retries(None, || async {
            Err(connect_failure(io::ErrorKind::ConnectionRefused))
        })
        .await;
        assert!(call_was_not_processed(&result.unwrap_err()));
        let elapsed = started.elapsed();
        assert!(elapsed <= UNPROCESSED_RETRY_WINDOW);
        assert!(elapsed + UNPROCESSED_RETRY_MAX_PAUSE > UNPROCESSED_RETRY_WINDOW);
    }

    #[tokio::test(start_paused = true)]
    async fn sending_again_stops_at_the_deadline_with_the_transport_failure() {
        for timeout in [Duration::from_millis(500), Duration::from_secs(20)] {
            let started = tokio::time::Instant::now();
            let result: Result<(), Status> = call_with_retries(Some(started + timeout), || async {
                Err(connect_failure(io::ErrorKind::ConnectionRefused))
            })
            .await;
            let status = result.unwrap_err();
            assert!(status.to_string().contains("connect failure"), "{status}");
            let elapsed = started.elapsed();
            assert!(elapsed <= timeout);
            assert!(elapsed + UNPROCESSED_RETRY_MAX_PAUSE > timeout);
        }
    }

    #[test]
    fn a_stream_error_this_side_raised_does_not_prove_the_call_was_not_processed() {
        for reason in [
            h2::Reason::NO_ERROR,
            h2::Reason::REFUSED_STREAM,
            h2::Reason::INTERNAL_ERROR,
        ] {
            let status = Status::from_error(Box::new(h2::Error::from(reason)));
            assert!(!call_was_not_processed(&status), "{reason:?}");
        }
    }
}
