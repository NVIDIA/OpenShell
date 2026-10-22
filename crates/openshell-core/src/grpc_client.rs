// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! gRPC client for fetching sandbox policy and provider environment from the
//! `OpenShell` server.
//!
//! Every request carries a sandbox bearer credential in the `Authorization`
//! header. Each sandbox instance owns its [`GatewayCredentials`], usually
//! built from the trusted launch bundle with
//! [`GatewayCredentials::from_auth_bundle`]. Diagnostic tools can instead
//! resolve a token with [`GatewayCredentials::from_environment`] from one of:
//!
//! 1. `OPENSHELL_SANDBOX_TOKEN` — raw JWT in the env (test harness path).
//! 2. `OPENSHELL_SANDBOX_TOKEN_FILE` — file containing the JWT.
//! 3. `OPENSHELL_K8S_SA_TOKEN_FILE` — projected `ServiceAccount` JWT; the
//!    caller exchanges it for a gateway JWT via `IssueSandboxToken`.
//!
//! Callers reach the gateway through a [`GatewayEndpoint`], which pairs the
//! URL with one sandbox instance's credentials. No credential is installed
//! process-wide, so instances hosted by one supervisor process cannot use or
//! rotate each other's identity.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::endpoint_status::{EndpointResult, EndpointStatusSnapshot};
use crate::proto::{
    DenialSummary, EndpointObservation as ProtoEndpointObservation,
    EndpointResult as ProtoEndpointResult, ExchangeProviderSubjectTokenRequest,
    GetDraftPolicyRequest, GetSandboxConfigRequest, GetSandboxProviderEnvironmentRequest,
    GetSandboxProviderEnvironmentResponse, IssueSandboxTokenRequest, NetworkActivitySummary,
    PolicyChunk, PolicySource, PolicyStatus, RefreshSandboxTokenRequest,
    ReportEndpointStatusRequest, ReportPolicyStatusRequest, SandboxPolicy as ProtoSandboxPolicy,
    SubmitPolicyAnalysisRequest, SubmitPolicyAnalysisResponse, UpdateConfigRequest,
    open_shell_client::OpenShellClient,
};
use crate::sandbox_env;
use crate::time::{duration_to_std, timestamp_to_millis};
use crate::token_grant_failure::{TokenGrantFailure, TokenGrantFailureKind, TokenGrantStage};
use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_extension_core::{BearerTokenSlot, ExtensionCredentialStore};
use tonic::Status;
use tonic::metadata::AsciiMetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tracing::{debug, info, warn};

/// Preserve the gRPC status as a source so callers can classify retryable errors.
/// `IntoDiagnostic` alone hides the wrapped error's concrete type.
pub fn grpc_status_error(status: Status) -> miette::Report {
    #[derive(Debug, thiserror::Error, miette::Diagnostic)]
    #[error("{0}")]
    struct GrpcStatusError(#[source] Status);
    GrpcStatusError(status).into()
}

/// Channel type after the [`AuthInterceptor`] is applied. Aliased so the
/// generated client type signatures stay readable.
pub type AuthedChannel = InterceptedService<Channel, AuthInterceptor>;

/// Largest gateway message a supervisor accepts on its `ConnectSupervisor`
/// stream. The gateway keeps configuration updates below it.
pub const MAX_SUPERVISOR_STREAM_MESSAGE_BYTES: usize = 9 * 1024 * 1024;

/// Shared, refreshable Bearer header. All [`AuthInterceptor`] clones read
/// the same slot, so the renewal task can replace the token in place without
/// rebuilding the channel. `None` means the owning sandbox instance revoked it.
type TokenSlot = Arc<RwLock<Option<AsciiMetadataValue>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenSource {
    Env,
    File,
    K8sServiceAccount,
}

/// Gateway credentials owned by one sandbox instance.
///
/// Clients built from a [`GatewayEndpoint`] read only these slots, and the
/// renewal task started by the first connection updates only them. Dropping
/// the last clone or calling [`GatewayCredentials::revoke`] stops renewal.
#[derive(Clone)]
pub struct GatewayCredentials {
    inner: Arc<CredentialState>,
}

struct CredentialState {
    bearer: TokenSlot,
    source: TokenSource,
    #[cfg(feature = "jwt")]
    sandbox_bearer: Option<crate::jwt::SessionBearerTokenSlot>,
    renewal: std::sync::Mutex<Renewal>,
}

enum Renewal {
    Idle,
    Started(tokio::task::AbortHandle),
    Revoked,
}

impl Drop for CredentialState {
    fn drop(&mut self) {
        let renewal = self
            .renewal
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Renewal::Started(task) = renewal {
            task.abort();
        }
    }
}

impl std::fmt::Debug for GatewayCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayCredentials")
            .field("source", &self.inner.source)
            .finish_non_exhaustive()
    }
}

impl GatewayCredentials {
    fn new(bearer: AsciiMetadataValue, source: TokenSource) -> Self {
        Self {
            inner: Arc::new(CredentialState {
                bearer: Arc::new(RwLock::new(Some(bearer))),
                source,
                #[cfg(feature = "jwt")]
                sandbox_bearer: None,
                renewal: std::sync::Mutex::new(Renewal::Idle),
            }),
        }
    }

    /// Credentials issued for one exact sandbox launch. Renewal also rotates
    /// the bundle's Sandbox Protocol credential, returned by
    /// [`GatewayCredentials::sandbox_bearer`].
    #[cfg(feature = "jwt")]
    pub fn from_auth_bundle(bundle: &crate::jwt::SupervisorAuthBundle) -> Result<Self> {
        let bearer = validate_gateway_bearer(bundle.gateway_token.expose_secret())?;
        let sandbox_bearer = bundle
            .sandbox_bearer_slot()
            .into_diagnostic()
            .wrap_err("invalid Sandbox Protocol credential")?;
        Ok(Self {
            inner: Arc::new(CredentialState {
                bearer: Arc::new(RwLock::new(Some(bearer))),
                source: TokenSource::File,
                sandbox_bearer: Some(sandbox_bearer),
                renewal: std::sync::Mutex::new(Renewal::Idle),
            }),
        })
    }

    /// Use a caller-supplied gateway JWT. Renewal cannot rebootstrap it.
    pub fn from_gateway_token(token: &str) -> Result<Self> {
        Ok(Self::new(validate_gateway_bearer(token)?, TokenSource::Env))
    }

    /// Resolve a token for diagnostic tools from the environment, exchanging a
    /// projected `ServiceAccount` token when no gateway JWT is present.
    pub async fn from_environment(endpoint: &str) -> Result<Self> {
        let plain_channel = build_plain_channel(endpoint).await?;
        let acquired = acquire_sandbox_token(endpoint, &plain_channel).await?;
        Ok(Self::new(
            validate_gateway_bearer(&acquired.token)?,
            acquired.source,
        ))
    }

    /// The Sandbox Protocol credential renewed with these gateway credentials.
    #[cfg(feature = "jwt")]
    #[must_use]
    pub fn sandbox_bearer(&self) -> Option<crate::jwt::SessionBearerTokenSlot> {
        self.inner.sandbox_bearer.clone()
    }

    /// Clear both credentials and stop renewal. Existing clients fail their
    /// next request locally instead of presenting a revoked identity.
    pub fn revoke(&self) {
        let mut renewal = self
            .inner
            .renewal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Renewal::Started(task) = &*renewal {
            task.abort();
        }
        *renewal = Renewal::Revoked;
        *self
            .inner
            .bearer
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        #[cfg(feature = "jwt")]
        if let Some(sandbox_bearer) = &self.inner.sandbox_bearer {
            sandbox_bearer.clear();
        }
    }

    /// Start the renewal task once for these credentials, on the caller's
    /// runtime, so a hosted sandbox instance's renewal stops with that instance.
    fn start_renewal(&self, channel: &AuthedChannel, plain_channel: &Channel, endpoint: &str) {
        let mut renewal = self
            .inner
            .renewal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !matches!(*renewal, Renewal::Idle) {
            return;
        }
        let task = tokio::spawn(refresh_token_loop(RenewalTarget {
            channel: channel.clone(),
            bearer: self.inner.bearer.clone(),
            #[cfg(feature = "jwt")]
            sandbox_bearer: self.inner.sandbox_bearer.clone(),
            source: self.inner.source,
            endpoint: endpoint.to_string(),
            plain_channel: plain_channel.clone(),
        }));
        *renewal = Renewal::Started(task.abort_handle());
    }

    fn is_revoked(&self) -> bool {
        matches!(
            *self
                .inner
                .renewal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Renewal::Revoked
        )
    }

    fn install_gateway_bearer(&self, bearer: AsciiMetadataValue) {
        let mut slot = self
            .inner
            .bearer
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Revoked instance credentials must not be revived by an in-flight
        // response.
        if slot.is_some() {
            *slot = Some(bearer);
        }
    }
}

/// The gateway URL a sandbox instance uses, paired with that instance's
/// credentials.
#[derive(Clone)]
pub struct GatewayEndpoint {
    url: Arc<str>,
    credentials: GatewayCredentials,
}

impl GatewayEndpoint {
    pub fn new(url: impl Into<Arc<str>>, credentials: GatewayCredentials) -> Self {
        Self {
            url: url.into(),
            credentials,
        }
    }

    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    #[must_use]
    pub fn credentials(&self) -> &GatewayCredentials {
        &self.credentials
    }

    /// Reach another gateway address with the same sandbox instance credentials.
    #[must_use]
    pub fn with_url(&self, url: impl Into<Arc<str>>) -> Self {
        Self::new(url, self.credentials.clone())
    }
}

impl std::fmt::Debug for GatewayEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayEndpoint")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct AcquiredToken {
    token: String,
    source: TokenSource,
}

fn validate_gateway_bearer(token: &str) -> Result<AsciiMetadataValue> {
    AsciiMetadataValue::try_from(format!("Bearer {token}"))
        .into_diagnostic()
        .wrap_err("sandbox JWT contained characters not valid for a header value")
}

#[cfg(feature = "jwt")]
struct ValidatedSandboxRefresh {
    token: crate::jwt::SecretJwt,
    expires_at: i64,
    credential_epoch: crate::jwt::CredentialEpoch,
}

#[cfg(feature = "jwt")]
fn validate_sandbox_refresh(
    response: &crate::proto::RefreshSandboxTokenResponse,
) -> std::result::Result<ValidatedSandboxRefresh, crate::jwt::SessionJwtError> {
    let token = crate::jwt::SecretJwt::parse(response.sandbox_token.clone())?;
    let credential_epoch = crate::jwt::CredentialEpoch::new(response.credential_epoch)?;
    let expires_at = response
        .sandbox_expiration_time
        .as_ref()
        .map(|expiration_time| {
            crate::time::validate_timestamp(expiration_time)
                .map_err(|_| crate::jwt::SessionJwtError::InvalidLifetime)?;
            if expiration_time.seconds == 0 {
                return Err(crate::jwt::SessionJwtError::InvalidLifetime);
            }
            Ok(expiration_time.seconds)
        })
        .transpose()?
        .unwrap_or(0);
    crate::jwt::SessionBearerTokenSlot::new(token.clone(), expires_at, credential_epoch)?;
    Ok(ValidatedSandboxRefresh {
        token,
        expires_at,
        credential_epoch,
    })
}

/// gRPC interceptor that injects `authorization: Bearer <token>` on every
/// outbound request. The token lives in a shared [`TokenSlot`] so the renewal
/// task can replace it without rebuilding clients.
#[derive(Clone)]
pub struct AuthInterceptor {
    bearer: TokenSlot,
}

impl AuthInterceptor {
    fn new(bearer: TokenSlot) -> Self {
        Self { bearer }
    }
}

impl tonic::service::Interceptor for AuthInterceptor {
    fn call(
        &mut self,
        mut req: tonic::Request<()>,
    ) -> std::result::Result<tonic::Request<()>, Status> {
        let bearer = self
            .bearer
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                Status::unauthenticated("sandbox instance gateway credentials were revoked")
            })?;
        req.metadata_mut().insert("authorization", bearer);
        #[cfg(feature = "trace-context")]
        let req =
            tonic::service::Interceptor::call(&mut openshell_otel::TraceContextInterceptor, req)?;
        Ok(req)
    }
}


/// Configure server-authenticated TLS for the gateway control-plane endpoint.
///
/// Trust only the configured gateway CA. Destination, system, and proxy
/// trust are intentionally not parameters to this control-plane boundary.
fn configure_gateway_tls(
    ep: Endpoint,
    ca_pem: Vec<u8>,
    server_name: Option<&str>,
) -> Result<Endpoint> {
    let mut tls_config = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca_pem));
    if let Some(server_name) = server_name.filter(|name| !name.is_empty()) {
        tls_config = tls_config.domain_name(server_name);
    }
    ep.tls_config(tls_config)
        .into_diagnostic()
        .wrap_err("failed to configure TLS")
}


/// Build the plain (un-intercepted) gRPC channel.
///
/// When the endpoint uses `https://`, server-authenticated TLS is configured
/// using this env var:
/// - `OPENSHELL_TLS_CA` -- path to the CA certificate
///
/// When the endpoint uses `http://`, a plaintext connection is used (for
/// deployments where TLS is disabled, e.g. behind a Cloudflare Tunnel).
async fn build_plain_channel(endpoint: &str) -> Result<Channel> {
    let mut ep = Endpoint::from_shared(endpoint.to_string())
        .into_diagnostic()
        .wrap_err("invalid gRPC endpoint")?
        .connect_timeout(Duration::from_secs(10))
        .http2_keep_alive_interval(Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .keep_alive_timeout(Duration::from_secs(20))
        // Match the gateway-side HTTP/2 flow control (see `multiplex.rs`).
        // Adaptive sizing lets idle streams stay tiny while bulk
        // RelayStream data flows get a BDP-sized window.
        .http2_adaptive_window(true);

    let tls_enabled = endpoint.starts_with("https://");

    // TODO: The TLS CA is loaded once here and never re-read. The gateway
    // server side supports hot-reload (ArcSwap + notify in tls.rs). The
    // supervisor should do the same so that cert-manager rotations take
    // effect without restarting the sandbox.
    if tls_enabled {
        let ca_path = std::env::var(sandbox_env::TLS_CA)
            .into_diagnostic()
            .wrap_err("OPENSHELL_TLS_CA is required")?;
        let ca_pem = std::fs::read(&ca_path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read CA cert from {ca_path}"))?;

        // The gateway uses SNI-based certificate selection to present its
        // internal cert to supervisor connections. Do not add native,
        // webpki, destination, or child-process roots here: an image that can
        // influence DNS must not broaden supervisor→gateway authentication.
        let server_name = std::env::var(sandbox_env::GATEWAY_TLS_SERVER_NAME).ok();
        ep = configure_gateway_tls(ep, ca_pem, server_name.as_deref())?;
    }

    ep.connect()
        .await
        .into_diagnostic()
        .wrap_err("failed to connect to OpenShell server")
}

/// Marks the current client span failed unless the call finishes successfully.
struct ClientSpanStatus {
    span: tracing::Span,
    finished: bool,
}

impl ClientSpanStatus {
    fn current() -> Self {
        Self {
            span: tracing::Span::current(),
            finished: false,
        }
    }

    fn finish<T, E>(mut self, result: std::result::Result<T, E>) -> std::result::Result<T, E> {
        self.finished = result.is_ok();
        result
    }
}

impl Drop for ClientSpanStatus {
    fn drop(&mut self) {
        if !self.finished {
            self.span.record("otel.status_code", "ERROR");
        }
    }
}

#[cfg(test)]
mod gateway_tls_isolation_tests {
    use super::*;
    use rcgen::{CertificateParams, IsCa, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::io::Cursor;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    #[allow(clippy::struct_field_names)]
    struct TestPki {
        ca_pem: Vec<u8>,
        server_cert_pem: Vec<u8>,
        server_key_pem: Vec<u8>,
    }

    fn test_pki(server_name: &str) -> TestPki {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let server_key = KeyPair::generate().unwrap();
        let server = CertificateParams::new(vec![server_name.to_string()])
            .unwrap()
            .signed_by(&server_key, &ca, &ca_key)
            .unwrap();
        TestPki {
            ca_pem: ca.pem().into_bytes(),
            server_cert_pem: server.pem().into_bytes(),
            server_key_pem: server_key.serialize_pem().into_bytes(),
        }
    }

    async fn start_h2_tls_server(pki: &TestPki) -> std::net::SocketAddr {
        let certificates = rustls_pemfile::certs(&mut Cursor::new(&pki.server_cert_pem))
            .collect::<std::result::Result<Vec<CertificateDer<'static>>, _>>()
            .unwrap();
        let key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut Cursor::new(&pki.server_key_pem))
                .unwrap()
                .unwrap();
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(stream) = acceptor.accept(stream).await else {
                return;
            };
            if let Ok(mut connection) = h2::server::handshake(stream).await {
                while let Some(request) = connection.accept().await {
                    if request.is_err() {
                        break;
                    }
                }
            }
        });
        address
    }

    async fn connect_with_gateway_ca(
        address: std::net::SocketAddr,
        pki: &TestPki,
        server_name: &str,
    ) -> Result<Channel> {
        let endpoint = Endpoint::from_shared(format!("https://{address}")).into_diagnostic()?;
        configure_gateway_tls(endpoint, pki.ca_pem.clone(), Some(server_name))?
        .connect()
        .await
        .into_diagnostic()
    }

    #[tokio::test]
    async fn destination_ca_cannot_authenticate_gateway() {
        const GATEWAY_NAME: &str = "gateway.internal.test";
        let gateway = test_pki(GATEWAY_NAME);
        let destination = test_pki(GATEWAY_NAME);

        let real_address = start_h2_tls_server(&gateway).await;
        tokio::time::timeout(
            Duration::from_secs(5),
            connect_with_gateway_ca(real_address, &gateway, GATEWAY_NAME),
        )
        .await
        .expect("real gateway connection timed out")
        .expect("configured gateway CA should authenticate the gateway");

        let fake_address = start_h2_tls_server(&destination).await;
        let error = tokio::time::timeout(
            Duration::from_secs(5),
            connect_with_gateway_ca(fake_address, &gateway, GATEWAY_NAME),
        )
        .await
        .expect("fake gateway rejection timed out")
        .expect_err("destination-signed fake gateway must be rejected");
        assert!(format!("{error:?}").contains("certificate"), "{error:?}");

        let mismatch_address = start_h2_tls_server(&gateway).await;
        tokio::time::timeout(
            Duration::from_secs(5),
            connect_with_gateway_ca(mismatch_address, &gateway, "wrong.internal.test"),
        )
        .await
        .expect("hostname mismatch rejection timed out")
        .expect_err("normal server-name verification must remain enabled");
    }
}

/// Build a Bearer-authenticated channel to the gateway with one sandbox
/// instance's credentials. The first connection starts that instance's
/// renewal task.
async fn connect_channel(gateway: &GatewayEndpoint) -> Result<AuthedChannel> {
    if gateway.credentials.is_revoked() {
        return Err(miette::miette!(
            "sandbox instance gateway credentials were revoked"
        ));
    }
    let channel = build_plain_channel(gateway.url()).await?;
    let intercepted = InterceptedService::new(
        channel.clone(),
        AuthInterceptor::new(gateway.credentials.inner.bearer.clone()),
    );
    gateway
        .credentials
        .start_renewal(&intercepted, &channel, gateway.url());
    Ok(intercepted)
}

/// Resolve the sandbox JWT used to authenticate every outbound RPC.
///
/// `endpoint` is logged on errors but never used for transport here; the
/// actual network call lives inside this function only on the K8s
/// bootstrap path, which uses `plain_channel` to call `IssueSandboxToken`
/// once before the steady-state Bearer-authenticated channel is built.
async fn acquire_sandbox_token(endpoint: &str, plain_channel: &Channel) -> Result<AcquiredToken> {
    if let Ok(t) = std::env::var(sandbox_env::SANDBOX_TOKEN)
        && !t.is_empty()
    {
        debug!(source = "env", "loaded sandbox token");
        return Ok(AcquiredToken {
            token: t,
            source: TokenSource::Env,
        });
    }

    if let Ok(path) = std::env::var(sandbox_env::SANDBOX_TOKEN_FILE)
        && !path.is_empty()
    {
        let contents = std::fs::read_to_string(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read sandbox token from {path}"))?;
        debug!(source = "file", path = %path, "loaded sandbox token");
        return Ok(AcquiredToken {
            token: contents.trim().to_string(),
            source: TokenSource::File,
        });
    }

    if let Ok(sa_path) = std::env::var(sandbox_env::K8S_SA_TOKEN_FILE)
        && !sa_path.is_empty()
    {
        return Ok(AcquiredToken {
            token: acquire_k8s_sandbox_token(endpoint, plain_channel, &sa_path).await?,
            source: TokenSource::K8sServiceAccount,
        });
    }

    Err(miette::miette!(
        "no sandbox token source available — set one of {}, {}, or {}",
        sandbox_env::SANDBOX_TOKEN,
        sandbox_env::SANDBOX_TOKEN_FILE,
        sandbox_env::K8S_SA_TOKEN_FILE,
    ))
}

async fn acquire_k8s_sandbox_token(
    endpoint: &str,
    plain_channel: &Channel,
    sa_path: &str,
) -> Result<String> {
    let sa_token = std::fs::read_to_string(sa_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read K8s SA token from {sa_path}"))?
        .trim()
        .to_string();
    info!(endpoint = %endpoint, "exchanging K8s ServiceAccount token for sandbox JWT");
    // The bootstrap exchange uses a one-off interceptor pinned to the SA
    // token; the caller installs the resulting gateway JWT.
    let bootstrap_slot: TokenSlot = Arc::new(RwLock::new(Some(
        AsciiMetadataValue::try_from(format!("Bearer {sa_token}"))
            .into_diagnostic()
            .wrap_err("SA token contained characters not valid for a header value")?,
    )));
    let interceptor = AuthInterceptor::new(bootstrap_slot);
    let bootstrap = InterceptedService::new(plain_channel.clone(), interceptor);
    let mut client = OpenShellClient::new(bootstrap);
    let resp = client
        .issue_sandbox_token(IssueSandboxTokenRequest {})
        .await
        .into_diagnostic()
        .wrap_err("IssueSandboxToken bootstrap exchange failed")?;
    Ok(resp.into_inner().token)
}

/// Build an authenticated channel for direct external use (e.g. the
/// long-lived `supervisor_session` control stream).
pub async fn connect_channel_pub(gateway: &GatewayEndpoint) -> Result<AuthedChannel> {
    connect_channel(gateway).await
}

/// Build a credential-free gateway channel for callers that attach their own bearer.
///
/// Uses the supervisor-side transport settings: server-authenticated TLS from
/// `OPENSHELL_TLS_CA` and `OPENSHELL_GATEWAY_TLS_SERVER_NAME` for `https`
/// endpoints, plaintext for `http` ones.
pub async fn connect_gateway_channel(endpoint: &str) -> Result<Channel> {
    build_plain_channel(endpoint).await
}

/// Report installed provider state for the current authenticated supervisor session.
///
/// The observation must carry the session ID returned by `ConnectSupervisor`.
/// Reconnects start a new report sequence; retries preserve the complete report.
pub async fn report_provider_readiness(
    gateway: &GatewayEndpoint,
    sandbox_id: &str,
    observation: crate::proto::ProviderReadinessObservation,
) -> Result<crate::proto::ReportProviderReadinessResponse> {
    let mut client = connect(gateway).await?;
    client
        .report_provider_readiness(crate::proto::ReportProviderReadinessRequest {
            sandbox_id: sandbox_id.to_string(),
            observation: Some(observation),
        })
        .await
        .map(tonic::Response::into_inner)
        .into_diagnostic()
}

/// Slots and transport retained by one sandbox instance's renewal task. It
/// holds no reference to [`GatewayCredentials`], so dropping them still stops
/// it.
struct RenewalTarget {
    channel: AuthedChannel,
    bearer: TokenSlot,
    #[cfg(feature = "jwt")]
    sandbox_bearer: Option<crate::jwt::SessionBearerTokenSlot>,
    source: TokenSource,
    endpoint: String,
    plain_channel: Channel,
}

/// Background task that renews the sandbox JWT at ~80% of its remaining
/// lifetime. The new token replaces the value in the sandbox instance's slot,
/// so all in-flight and future clients of that instance pick it up on their
/// next request. The loop never panics: every failure is logged and
/// re-attempted after a bounded backoff.
async fn refresh_token_loop(target: RenewalTarget) {
    let RenewalTarget {
        channel,
        bearer: slot,
        #[cfg(feature = "jwt")]
        sandbox_bearer,
        source,
        endpoint,
        plain_channel,
    } = target;
    let mut client = OpenShellClient::new(channel);
    loop {
        let Some(sleep) = compute_refresh_delay(&slot) else {
            debug!("gateway sandbox JWT does not expire; stopping periodic renewal");
            return;
        };
        tokio::time::sleep(sleep).await;
        match client
            .refresh_sandbox_token(RefreshSandboxTokenRequest {
                extension_service_names: Vec::new(),
            })
            .await
        {
            Ok(resp) => {
                let response = resp.into_inner();
                #[cfg(feature = "jwt")]
                let sandbox_refresh = match validate_sandbox_refresh(&response) {
                    Ok(refresh) => refresh,
                    Err(error) => {
                        warn!(%error, "gateway returned an invalid Sandbox Protocol credential");
                        continue;
                    }
                };
                let gateway_bearer = match validate_gateway_bearer(&response.token) {
                    Ok(value) => value,
                    Err(error) => {
                        warn!(%error, "refreshed JWT contained invalid header bytes");
                        continue;
                    }
                };

                {
                    let mut current = slot
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if current.is_none() {
                        return;
                    }
                    *current = Some(gateway_bearer);
                }
                #[cfg(feature = "jwt")]
                if let Some(sandbox_slot) = sandbox_bearer.as_ref()
                    && let Err(error) = sandbox_slot.update(
                        sandbox_refresh.token,
                        sandbox_refresh.expires_at,
                        sandbox_refresh.credential_epoch,
                    )
                    && error != crate::jwt::SessionJwtError::StaleCredentialEpoch
                {
                    warn!(%error, "gateway returned an invalid Sandbox Protocol credential");
                }
                info!("renewed gateway and Sandbox Protocol credentials in-place");
            }
            Err(status) => {
                if status.code() == tonic::Code::Unauthenticated
                    && source == TokenSource::K8sServiceAccount
                {
                    if let Some(sa_path) = std::env::var(sandbox_env::K8S_SA_TOKEN_FILE)
                        .ok()
                        .filter(|p| !p.is_empty())
                    {
                        match acquire_k8s_sandbox_token(&endpoint, &plain_channel, &sa_path).await {
                            Ok(new_token) => {
                                match AsciiMetadataValue::try_from(format!("Bearer {new_token}")) {
                                    Ok(value) => {
                                        if let Ok(mut guard) = slot.write()
                                            && guard.is_some()
                                        {
                                            *guard = Some(value);
                                            info!(
                                                "rebootstrapped gateway sandbox JWT after refresh authentication failure"
                                            );
                                            continue;
                                        }
                                    }
                                    Err(e) => warn!(
                                        error = %e,
                                        "rebootstrapped JWT contained invalid header bytes"
                                    ),
                                }
                            }
                            Err(e) => warn!(
                                error = %e,
                                "K8s ServiceAccount bootstrap retry failed after refresh authentication failure"
                            ),
                        }
                    } else {
                        warn!(
                            "RefreshSandboxToken returned Unauthenticated and K8s SA token file is unavailable"
                        );
                    }
                } else if status.code() == tonic::Code::Unauthenticated {
                    warn!(
                        source = ?source,
                        "RefreshSandboxToken returned Unauthenticated; static token sources cannot rebootstrap automatically"
                    );
                }
                warn!(error = %status, "RefreshSandboxToken failed; will retry");
                // Backoff so we don't spin against a sustained failure.
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}

/// Registration names to request credentials for.
///
/// Registrations the operator opted out of extension authentication have no
/// credential to request; asking for one is rejected by the gateway.
fn authenticated_service_names(
    services: &[crate::proto::SupervisorMiddlewareService],
) -> Vec<String> {
    services
        .iter()
        .filter(|service| !service.allow_insecure_transport)
        .map(|service| service.name.clone())
        .collect()
}

async fn refresh_extension_credentials_with_client(
    client: &mut OpenShellClient<AuthedChannel>,
    credentials: &GatewayCredentials,
    store: &ExtensionCredentialStore,
    services: &[crate::proto::SupervisorMiddlewareService],
) -> Result<HashMap<String, BearerTokenSlot>> {
    let names = authenticated_service_names(services);
    if names.is_empty() {
        return Ok(HashMap::new());
    }

    let response = client
        .refresh_sandbox_token(RefreshSandboxTokenRequest {
            extension_service_names: names.clone(),
        })
        .await
        .into_diagnostic()
        .wrap_err("failed to refresh extension service credentials")?
        .into_inner();

    let gateway_bearer = validate_gateway_bearer(&response.token)?;
    #[cfg(feature = "jwt")]
    let sandbox_refresh = validate_sandbox_refresh(&response)
        .into_diagnostic()
        .wrap_err("gateway returned an invalid Sandbox Protocol credential")?;

    // Validate the whole response before mutating any slot, so a malformed or
    // partial reply cannot leave the store half-rotated.
    let expected = names
        .iter()
        .map(String::as_str)
        .collect::<std::collections::HashSet<_>>();
    let mut validated = HashMap::with_capacity(response.extension_credentials.len());
    for credential in response.extension_credentials {
        if !expected.contains(credential.service_name.as_str())
            || validated.contains_key(&credential.service_name)
        {
            return Err(miette::miette!(
                "gateway returned an unexpected or duplicate extension credential"
            ));
        }
        let expiration_time = credential.expiration_time.as_ref().ok_or_else(|| {
            miette::miette!("gateway returned an extension credential without an expiration time")
        })?;
        let expires_at_ms = timestamp_to_millis(expiration_time).into_diagnostic()?;
        validated.insert(credential.service_name, (credential.token, expires_at_ms));
    }
    if validated.len() != expected.len() {
        return Err(miette::miette!(
            "gateway omitted one or more requested extension credentials"
        ));
    }

    let now_ms = now_ms();
    for (token, expires_at_ms) in validated.values() {
        BearerTokenSlot::new(token, *expires_at_ms)
            .into_diagnostic()
            .wrap_err("gateway returned an invalid extension credential")?;
    }

    // Commit only after the gateway, Sandbox Protocol, and extension
    // credentials have all been parsed and validated. The remaining updates
    // repeat those validations but cannot fail for the validated inputs.
    credentials.install_gateway_bearer(gateway_bearer);
    #[cfg(feature = "jwt")]
    if let Some(sandbox_slot) = credentials.inner.sandbox_bearer.as_ref() {
        match sandbox_slot.update(
            sandbox_refresh.token,
            sandbox_refresh.expires_at,
            sandbox_refresh.credential_epoch,
        ) {
            Ok(()) | Err(crate::jwt::SessionJwtError::StaleCredentialEpoch) => {}
            Err(error) => {
                return Err(miette::miette!(
                    "validated Sandbox Protocol credential could not be installed: {error}"
                ));
            }
        }
    }

    let mut selected = HashMap::with_capacity(validated.len());
    for (name, (token, expires_at_ms)) in validated {
        let slot = store
            .install(&name, &token, expires_at_ms, now_ms)
            .into_diagnostic()
            .wrap_err("gateway returned an invalid extension credential")?;
        selected.insert(name, slot);
    }
    Ok(selected)
}

/// Compute the next refresh delay: 80 % of the time remaining until the
/// current token's `exp`, plus up to 10 % jitter, with a small lower bound
/// for already-expired tokens and capped at 12 h. An `exp` of zero denotes a
/// non-expiring session credential and needs no periodic refresh. If the token
/// can't be parsed (for example, an opaque bootstrap bearer), default to 6 h.
fn compute_refresh_delay(slot: &TokenSlot) -> Option<Duration> {
    let token = {
        let current = slot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Revoked instance credentials have nothing to renew.
        current.as_ref()?.to_str().ok().map(str::to_string)
    }
    .unwrap_or_default();
    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()),
    )
    .unwrap_or(i64::MAX);
    let expires_at = parse_jwt_exp_ms(&token);
    if expires_at == Some(0) {
        return None;
    }
    let mut delay_ms = expires_at.map_or(21_600_000, |exp| {
        let remaining_ms = exp - now_ms;
        if remaining_ms <= 0 {
            1_000
        } else {
            (remaining_ms * 8 / 10).clamp(1_000, 43_200_000)
        }
    });
    // Up to 10 % jitter, derived deterministically from token bytes so
    // unit tests are reproducible without injecting an RNG.
    let jitter_pct = (token.len() % 10) as u64;
    let jitter_ms = (u64::try_from(delay_ms).unwrap_or(0) * jitter_pct) / 100;
    delay_ms = delay_ms.saturating_add(i64::try_from(jitter_ms).unwrap_or(0));
    Some(Duration::from_millis(u64::try_from(delay_ms).unwrap_or(0)))
}

/// Decode the `exp` claim from a JWT without verifying its signature.
/// Returns the expiry in milliseconds since the Unix epoch, or `None` if
/// the token is not a parseable JWT.
fn parse_jwt_exp_ms(jwt: &str) -> Option<i64> {
    crate::jwt::parse_exp_secs(jwt)?.checked_mul(1000)
}

#[cfg(test)]
mod auth_tests {
    use super::*;

    #[cfg(feature = "jwt")]
    #[test]
    fn sandbox_refresh_validation_rejects_epoch_expiration() {
        let response = crate::proto::RefreshSandboxTokenResponse {
            sandbox_token: "sandbox-token".to_string(),
            sandbox_expiration_time: Some(prost_types::Timestamp {
                seconds: 0,
                nanos: 0,
            }),
            credential_epoch: 2,
            ..Default::default()
        };

        assert_eq!(
            validate_sandbox_refresh(&response).err(),
            Some(crate::jwt::SessionJwtError::InvalidLifetime)
        );
    }

    #[cfg(feature = "jwt")]
    #[test]
    fn sandbox_refresh_validation_accepts_missing_expiration_as_non_expiring() {
        let response = crate::proto::RefreshSandboxTokenResponse {
            sandbox_token: "sandbox-token".to_string(),
            credential_epoch: 2,
            ..Default::default()
        };

        let refresh = validate_sandbox_refresh(&response).expect("non-expiring refresh");
        assert_eq!(refresh.expires_at, 0);
    }

    #[cfg(feature = "jwt")]
    #[test]
    fn sandbox_refresh_validation_rejects_malformed_expiration() {
        let response = crate::proto::RefreshSandboxTokenResponse {
            sandbox_token: "sandbox-token".to_string(),
            sandbox_expiration_time: Some(prost_types::Timestamp {
                seconds: 1,
                nanos: -1,
            }),
            credential_epoch: 2,
            ..Default::default()
        };

        assert_eq!(
            validate_sandbox_refresh(&response).err(),
            Some(crate::jwt::SessionJwtError::InvalidLifetime)
        );
    }

    #[cfg(feature = "jwt")]
    #[test]
    fn sandbox_refresh_validation_accepts_canonical_fractional_expiration() {
        let response = crate::proto::RefreshSandboxTokenResponse {
            sandbox_token: "sandbox-token".to_string(),
            sandbox_expiration_time: Some(prost_types::Timestamp {
                seconds: 1_900_000_000,
                nanos: 500_000_000,
            }),
            credential_epoch: 2,
            ..Default::default()
        };

        let refresh = validate_sandbox_refresh(&response).expect("valid refresh");
        assert_eq!(refresh.expires_at, 1_900_000_000);
    }

    #[test]
    fn parse_jwt_exp_reads_unsigned_payload() {
        use base64::Engine as _;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"exp":1234567890,"sandbox_id":"sb-1"}"#);
        let token = format!("h.{payload}.sig");
        assert_eq!(parse_jwt_exp_ms(&token), Some(1_234_567_890_000));
    }

    #[test]
    fn parse_jwt_exp_returns_none_for_malformed_token() {
        assert!(parse_jwt_exp_ms("not-a-jwt").is_none());
        assert!(parse_jwt_exp_ms("only.two").is_none());
        assert!(parse_jwt_exp_ms("a.!!!.c").is_none());
    }

    #[test]
    fn compute_refresh_delay_uses_80_percent_when_token_present() {
        // Build a JWT whose exp is 1000 seconds in the future. With 0-jitter
        // the delay should be roughly 800 seconds.
        use base64::Engine as _;
        let now_s = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let exp = now_s + 1000;
        let payload_json = format!(r#"{{"exp":{exp}}}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json);
        let token = format!("h.{payload}.s");
        let bearer = AsciiMetadataValue::try_from(format!("Bearer {token}")).unwrap();
        let slot: TokenSlot = Arc::new(RwLock::new(Some(bearer)));
        let delay = compute_refresh_delay(&slot).expect("expiring token needs refresh");
        // 800 s baseline + up to 10 % jitter → 800..=880 s, with some slack
        // for the 1-second resolution of the exp claim.
        let secs = delay.as_secs();
        assert!(
            (700..=900).contains(&secs),
            "expected 80%-of-1000s delay, got {secs}s"
        );
    }

    #[test]
    fn compute_refresh_delay_uses_short_delay_for_expired_token() {
        // Already-expired token still produces a small positive delay so the
        // loop doesn't busy-spin.
        use base64::Engine as _;
        let exp = 1; // past
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{exp}}}"#));
        let token = format!("h.{payload}.s");
        let bearer = AsciiMetadataValue::try_from(format!("Bearer {token}")).unwrap();
        let slot: TokenSlot = Arc::new(RwLock::new(Some(bearer)));
        let delay = compute_refresh_delay(&slot).expect("expired token needs refresh");
        assert!((1..60).contains(&delay.as_secs()));
    }

    #[test]
    fn compute_refresh_delay_skips_non_expiring_token() {
        use base64::Engine as _;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"exp":0}"#);
        let token = format!("h.{payload}.s");
        let bearer = AsciiMetadataValue::try_from(format!("Bearer {token}")).unwrap();
        let slot: TokenSlot = Arc::new(RwLock::new(Some(bearer)));
        assert_eq!(compute_refresh_delay(&slot), None);
    }

    #[test]
    fn compute_refresh_delay_supports_short_token_ttl() {
        use base64::Engine as _;
        let now_s = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let exp = now_s + 30;
        let payload_json = format!(r#"{{"exp":{exp}}}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json);
        let token = format!("h.{payload}.s");
        let bearer = AsciiMetadataValue::try_from(format!("Bearer {token}")).unwrap();
        let slot: TokenSlot = Arc::new(RwLock::new(Some(bearer)));
        let delay = compute_refresh_delay(&slot).expect("expiring token needs refresh");
        assert!(
            delay.as_secs() < 30,
            "expected refresh before 30s expiry, got {delay:?}",
        );
    }
}

#[cfg(test)]
mod workspace_tests {
    use super::*;

    #[test]
    fn cached_client_workspace_defaults_to_empty_before_poll() {
        let client_ws: Arc<tokio::sync::OnceCell<String>> = Arc::new(tokio::sync::OnceCell::new());
        assert_eq!(client_ws.get().cloned().unwrap_or_default(), "");
    }

    #[test]
    fn cached_client_workspace_returns_learned_value() {
        let client_ws: Arc<tokio::sync::OnceCell<String>> = Arc::new(tokio::sync::OnceCell::new());
        let _ = client_ws.set("beta".to_string());
        assert_eq!(client_ws.get().cloned().unwrap_or_default(), "beta");
    }

    #[test]
    fn cached_client_workspace_is_set_once() {
        let client_ws: Arc<tokio::sync::OnceCell<String>> = Arc::new(tokio::sync::OnceCell::new());
        let _ = client_ws.set("beta".to_string());
        let _ = client_ws.set("gamma".to_string());
        assert_eq!(
            client_ws.get().cloned().unwrap_or_default(),
            "beta",
            "workspace should not change after first poll"
        );
    }
}

/// Connect to the `OpenShell` server with one sandbox instance's credentials.
async fn connect(gateway: &GatewayEndpoint) -> Result<OpenShellClient<AuthedChannel>> {
    let channel = connect_channel(gateway).await?;
    Ok(OpenShellClient::new(channel))
}

/// Fetch sandbox policy from `OpenShell` server via gRPC.
///
/// Returns `Ok(Some(policy))` when the server has a policy configured,
/// or `Ok(None)` when the sandbox was created without a policy (the sandbox
/// should discover one from disk or use the restrictive default).
pub async fn fetch_policy(
    gateway: &GatewayEndpoint,
    sandbox_name: &str,
) -> Result<Option<ProtoSandboxPolicy>> {
    debug!(endpoint = %gateway.url(), sandbox_name = %sandbox_name, "Connecting to OpenShell server");

    let mut client = connect(gateway).await?;

    debug!("Connected, fetching sandbox policy");

    fetch_policy_with_client(&mut client, sandbox_name).await
}

/// Fetch the authoritative policy and revision metadata in one response.
///
/// Callers that must acknowledge the exact revision they loaded should retain
/// this snapshot instead of re-fetching metadata after policy construction.
/// The snapshot also carries the external middleware registrations required
/// by the policy.
#[tracing::instrument(
    name = "supervisor.gateway.fetch_settings_snapshot",
    skip_all,
    fields(otel.kind = "client", otel.status_code = tracing::field::Empty)
)]
pub async fn fetch_settings_snapshot(
    gateway: &GatewayEndpoint,
    sandbox_name: &str,
) -> Result<SettingsPollResult> {
    let status = ClientSpanStatus::current();
    debug!(endpoint = %gateway.url(), sandbox_name = %sandbox_name, "Connecting to fetch OpenShell settings snapshot");
    let mut client = connect(gateway).await?;
    status.finish(fetch_settings_snapshot_with_client(&mut client, sandbox_name, None).await)
}

async fn fetch_settings_snapshot_with_client(
    client: &mut OpenShellClient<AuthedChannel>,
    sandbox_name: &str,
    workspace: Option<&str>,
) -> Result<SettingsPollResult> {
    let response = client
        .get_sandbox_config(GetSandboxConfigRequest {
            workspace_scope: workspace.map(crate::proto::workspace_selector),
            name: sandbox_name.to_string(),
        })
        .await
        .map_err(grpc_status_error)?;

    Ok(settings_poll_result(response.into_inner()))
}

fn learned_workspace_selector(workspace: Option<&str>) -> Option<crate::proto::WorkspaceSelector> {
    workspace.map(crate::proto::workspace_selector)
}

/// Fetch sandbox policy using an existing client connection.
async fn fetch_policy_with_client(
    client: &mut OpenShellClient<AuthedChannel>,
    sandbox_name: &str,
) -> Result<Option<ProtoSandboxPolicy>> {
    let snapshot = fetch_settings_snapshot_with_client(client, sandbox_name, None).await?;

    // version 0 with no policy means the sandbox was created without one.
    if snapshot.version == 0 && snapshot.policy.is_none() {
        return Ok(None);
    }

    Ok(Some(snapshot.policy.ok_or_else(|| {
        miette::miette!("Server returned non-zero version but empty policy")
    })?))
}

/// Sync a locally-discovered policy using an existing client connection.
async fn sync_policy_with_client(
    client: &mut OpenShellClient<AuthedChannel>,
    sandbox: &str,
    policy: &ProtoSandboxPolicy,
    workspace: &str,
) -> Result<()> {
    client
        .update_config(UpdateConfigRequest {
            sandbox: sandbox.to_string(),
            workspace_scope: Some(crate::proto::workspace_selector(workspace)),
            policy: Some(policy.clone()),
            ..Default::default()
        })
        .await
        .map_err(grpc_status_error)
        .wrap_err("failed to sync policy to server")?;

    Ok(())
}

/// Discover and sync policy using a single gRPC connection.
///
/// Performs the full discovery flow (fetch → sync → re-fetch) over one
/// channel instead of establishing three separate connections.
pub async fn discover_and_sync_policy(
    gateway: &GatewayEndpoint,
    sandbox: &str,
    discovered_policy: &ProtoSandboxPolicy,
    workspace: &str,
) -> Result<ProtoSandboxPolicy> {
    debug!(
        endpoint = %gateway.url(),
        sandbox = %sandbox,
        "Syncing discovered policy and re-fetching canonical version"
    );

    let mut client = connect(gateway).await?;

    // Sync the discovered policy to the gateway.
    sync_policy_with_client(&mut client, sandbox, discovered_policy, workspace).await?;

    // Re-fetch from the gateway to get the canonical version/hash.
    fetch_settings_snapshot_with_client(&mut client, sandbox, Some(workspace))
        .await?
        .policy
        .ok_or_else(|| {
            miette::miette!("Server still returned no policy after sync — this is a bug")
        })
}

/// Sync an enriched policy back to the gateway.
///
/// Used by the supervisor to push baseline-path-enriched policies so the
/// gateway stores the effective policy users see via `openshell sandbox get`.
pub async fn sync_policy(
    gateway: &GatewayEndpoint,
    sandbox: &str,
    policy: &ProtoSandboxPolicy,
    workspace: &str,
) -> Result<()> {
    debug!(endpoint = %gateway.url(), sandbox = %sandbox, "Syncing enriched policy to gateway");
    let mut client = connect(gateway).await?;
    sync_policy_with_client(&mut client, sandbox, policy, workspace).await
}

/// Sync an enriched policy and return the authoritative revision snapshot.
#[tracing::instrument(
    name = "supervisor.gateway.sync_policy_and_fetch_snapshot",
    skip_all,
    fields(otel.kind = "client", otel.status_code = tracing::field::Empty)
)]
pub async fn sync_policy_and_fetch_snapshot(
    gateway: &GatewayEndpoint,
    sandbox: &str,
    policy: &ProtoSandboxPolicy,
    workspace: &str,
) -> Result<SettingsPollResult> {
    let status = ClientSpanStatus::current();
    let mut client = connect(gateway).await?;
    sync_policy_with_client(&mut client, sandbox, policy, workspace).await?;
    status.finish(fetch_settings_snapshot_with_client(&mut client, sandbox, Some(workspace)).await)
}

/// Report an exact runtime configuration generation. Pending registration uses
/// the snapshot's instance fence; retain that snapshot across registration retries.
#[tracing::instrument(
    name = "supervisor.gateway.report_sandbox_configuration",
    skip_all,
    fields(otel.kind = "client", otel.status_code = tracing::field::Empty)
)]
pub async fn report_sandbox_configuration(
    gateway: &GatewayEndpoint,
    sandbox_id: &str,
    instance_id: &str,
    snapshot: Option<&SettingsPollResult>,
    state: crate::proto::ConfigurationAdmissionState,
    error: &str,
) -> Result<()> {
    let status = ClientSpanStatus::current();
    let mut client = connect(gateway).await?;
    client
        .report_sandbox_configuration(crate::proto::ReportSandboxConfigurationRequest {
            sandbox_id: sandbox_id.to_string(),
            expected_instance_id: snapshot.map_or_else(String::new, |snapshot| {
                snapshot.configuration_instance_id.clone()
            }),
            admission: Some(crate::proto::SandboxConfigurationAdmission {
                instance_id: instance_id.to_string(),
                state: state.into(),
                policy_version: snapshot.map_or(0, |snapshot| snapshot.version),
                policy_hash: snapshot
                    .map_or_else(String::new, |snapshot| snapshot.policy_hash.clone()),
                config_revision: snapshot.map_or(0, |snapshot| snapshot.config_revision),
                provider_env_revision: snapshot
                    .map_or(0, |snapshot| snapshot.provider_env_revision),
                error: error.to_string(),
            }),
        })
        .await
        .map_err(grpc_status_error)?;
    status.finish(Ok(()))
}

/// Fetch provider environment variables for a sandbox from `OpenShell` server via gRPC.
///
/// Returns the credential snapshot and its exact readiness identity. An empty
/// environment represents a sandbox without provider credentials. Transport
/// failure returns an error so callers can revoke credentials and retry.
pub async fn fetch_provider_environment(
    gateway: &GatewayEndpoint,
    sandbox_id: &str,
) -> Result<ProviderEnvironmentResult> {
    fetch_provider_environment_with_stable_placeholders(gateway, sandbox_id, false).await
}

/// Fetch a snapshot without downgrading previously activated external stable credentials.
///
/// Ordinary credentials remain compatible with gateways predating stable delivery.
/// Callers retain the requirement across refresh failures until an acknowledged
/// snapshot removes the last external stable credential.
#[tracing::instrument(
    name = "supervisor.gateway.fetch_provider_environment",
    skip_all,
    fields(otel.kind = "client", otel.status_code = tracing::field::Empty)
)]
pub async fn fetch_provider_environment_with_stable_placeholders(
    gateway: &GatewayEndpoint,
    sandbox_id: &str,
    requires_stable_placeholders: bool,
) -> Result<ProviderEnvironmentResult> {
    let status = ClientSpanStatus::current();
    debug!(endpoint = %gateway.url(), sandbox_id = %sandbox_id, "Fetching provider environment");

    let mut client = connect(gateway).await?;

    let response = client
        .get_sandbox_provider_environment(GetSandboxProviderEnvironmentRequest {
            sandbox_id: sandbox_id.to_string(),
            supports_static_credential_bindings: true,
            supports_stable_placeholder_environment_keys: true,
        })
        .await
        .map_err(grpc_status_error)?;

    status.finish(provider_environment_result(
        response.into_inner(),
        requires_stable_placeholders,
    ))
}

/// Preserve snapshot authority and reject invalid credential expiration times.
/// Unknown delivery reasons withhold credentials rather than implying readiness.
/// A gateway must acknowledge stable delivery until a successful snapshot removes it.
fn provider_environment_result(
    inner: GetSandboxProviderEnvironmentResponse,
    requires_stable_placeholders: bool,
) -> Result<ProviderEnvironmentResult> {
    // An empty stable-key list cannot distinguish an acknowledged detach from
    // an older gateway silently discarding the activated delivery requirement.
    if !inner.supports_stable_placeholder_environment_keys
        && (requires_stable_placeholders || !inner.stable_placeholder_environment_keys.is_empty())
    {
        miette::bail!("gateway does not support the required stable credential placeholders");
    }
    let credential_expires_at_ms = inner
        .credential_expiration_times
        .iter()
        .map(|(name, expiration_time)| {
            timestamp_to_millis(expiration_time)
                .map(|value| (name.clone(), value))
                .into_diagnostic()
        })
        .collect::<Result<HashMap<_, _>>>()?;
    Ok(ProviderEnvironmentResult {
        environment: inner.environment,
        files: inner.files,
        provider_env_revision: inner.provider_env_revision,
        provider_attachment_epoch: inner.provider_attachment_epoch,
        policy_hash: inner.policy_hash,
        readiness_reason: crate::proto::ProviderReadinessReason::try_from(inner.readiness_reason)
            .unwrap_or(crate::proto::ProviderReadinessReason::CredentialsWithheld),
        credential_expires_at_ms,
        dynamic_credentials: inner.dynamic_credentials,
        static_credential_bindings: inner.static_credential_bindings,
        non_secret_environment_keys: inner.non_secret_environment_keys,
        stable_placeholder_environment_keys: inner.stable_placeholder_environment_keys,
    })
}

#[cfg(test)]
mod provider_environment_tests {
    use super::*;
    use crate::proto::{StaticCredentialBinding, StaticCredentialEndpointBinding};
    use prost::Message;

    #[test]
    fn stable_placeholder_gateway_ack_preserves_legacy_compatibility() {
        let response = GetSandboxProviderEnvironmentResponse {
            environment: HashMap::from([("TOKEN".to_string(), "synthetic".to_string())]),
            static_credential_bindings: HashMap::from([(
                "TOKEN".to_string(),
                StaticCredentialBinding {
                    endpoints: vec![StaticCredentialEndpointBinding {
                        host: "api.example.com".to_string(),
                        port: 443,
                        path: "/v1/**".to_string(),
                    }],
                    credential_identity: "provider:TOKEN".to_string(),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        // Legacy wire responses omit field 12. Also test an explicit false value
        // rather than relying only on a locally constructed default message.
        let absent = response.encode_to_vec();
        let mut explicit_false = absent.clone();
        explicit_false.extend_from_slice(&[0x60, 0x00]);
        for encoded in [absent, explicit_false] {
            let decoded = GetSandboxProviderEnvironmentResponse::decode(encoded.as_slice())
                .expect("provider response wire format");
            assert!(provider_environment_result(decoded.clone(), false).is_ok());
            assert!(provider_environment_result(decoded, true).is_err());
        }
        assert!(
            provider_environment_result(GetSandboxProviderEnvironmentResponse::default(), false)
                .is_ok()
        );
        assert!(
            provider_environment_result(GetSandboxProviderEnvironmentResponse::default(), true)
                .is_err()
        );

        let mut declared_stable = response.clone();
        declared_stable.stable_placeholder_environment_keys = vec!["TOKEN".to_string()];
        assert!(provider_environment_result(declared_stable, false).is_err());

        // Managed refresh handles predate this external opt-in and do not
        // require the new capability merely because they use opaque handles.
        let mut managed_refresh = response;
        managed_refresh
            .static_credential_bindings
            .get_mut("TOKEN")
            .expect("binding")
            .workload_credential_handle = "managed-refresh-handle".to_string();
        assert!(provider_environment_result(managed_refresh, false).is_ok());
    }

    #[test]
    fn stable_placeholder_gateway_ack_preserves_environment_metadata() {
        for stable_keys in [Vec::new(), vec!["TOKEN".to_string()]] {
            let response = GetSandboxProviderEnvironmentResponse {
                environment: HashMap::from([("TOKEN".to_string(), "synthetic".to_string())]),
                provider_env_revision: 42,
                stable_placeholder_environment_keys: stable_keys.clone(),
                supports_stable_placeholder_environment_keys: true,
                ..Default::default()
            };
            let result =
                provider_environment_result(response, true).expect("acknowledged delivery");
            assert_eq!(result.provider_env_revision, 42);
            assert_eq!(result.stable_placeholder_environment_keys, stable_keys);
            assert!(
                result
                    .environment
                    .get("TOKEN")
                    .is_some_and(|value| value == "synthetic")
            );
        }
    }

    #[test]
    fn provider_environment_preserves_readiness_identity() {
        let result = provider_environment_result(
            GetSandboxProviderEnvironmentResponse {
                environment: HashMap::from([("TOKEN".to_string(), "synthetic".to_string())]),
                provider_env_revision: 42,
                provider_attachment_epoch: "attachment-epoch".to_string(),
                policy_hash: "binding-policy".to_string(),
                readiness_reason: crate::proto::ProviderReadinessReason::CredentialsWithheld.into(),
                credential_expiration_times: HashMap::from([(
                    "TOKEN".to_string(),
                    prost_types::Timestamp {
                        seconds: 1_900_000_000,
                        nanos: 123_000_000,
                    },
                )]),
                ..Default::default()
            },
            false,
        )
        .expect("valid provider environment");
        assert_eq!(result.provider_env_revision, 42);
        assert_eq!(result.provider_attachment_epoch, "attachment-epoch");
        assert_eq!(result.policy_hash, "binding-policy");
        assert_eq!(
            result.readiness_reason,
            crate::proto::ProviderReadinessReason::CredentialsWithheld
        );
        assert_eq!(
            result.environment.get("TOKEN").map(String::as_str),
            Some("synthetic")
        );
        assert_eq!(
            result.credential_expires_at_ms.get("TOKEN"),
            Some(&1_900_000_000_123)
        );
    }

    #[test]
    fn provider_readiness_unknown_delivery_reason_is_withheld() {
        let result = provider_environment_result(
            GetSandboxProviderEnvironmentResponse {
                policy_hash: "binding-policy".to_string(),
                readiness_reason: i32::MAX,
                ..Default::default()
            },
            false,
        )
        .expect("valid provider environment");
        assert_eq!(
            result.readiness_reason,
            crate::proto::ProviderReadinessReason::CredentialsWithheld
        );
    }

    #[test]
    fn provider_environment_rejects_invalid_credential_expiration() {
        let result = provider_environment_result(
            GetSandboxProviderEnvironmentResponse {
                credential_expiration_times: HashMap::from([(
                    "TOKEN".to_string(),
                    prost_types::Timestamp {
                        seconds: 1_900_000_000,
                        nanos: -1,
                    },
                )]),
                ..Default::default()
            },
            false,
        );
        assert!(result.is_err());
    }
}

/// Exchange a provider credential without retaining gateway diagnostics.
///
/// Only a verified TLS connection can establish the provenance of a precise
/// grant classification. Plaintext responses remain safe unknown failures.
/// A `request_id` travels as `x-request-id` metadata, which the gateway keeps
/// on its request span and failure log line.
#[tracing::instrument(
    name = "supervisor.gateway.exchange_provider_subject_token",
    skip_all,
    fields(otel.kind = "client", otel.status_code = tracing::field::Empty)
)]
pub async fn exchange_provider_subject_token(
    gateway: &GatewayEndpoint,
    sandbox_id: &str,
    provider: &str,
    credential_key: &str,
    supervisor_jwt_svid: &str,
    request_id: Option<&str>,
) -> std::result::Result<ProviderSubjectTokenExchangeResult, TokenGrantFailure> {
    let status = ClientSpanStatus::current();
    let endpoint = token_grant_gateway_endpoint(gateway.url())?;
    if sandbox_id.is_empty() || provider.is_empty() || credential_key.is_empty() {
        return Err(gateway_grant_failure(TokenGrantFailureKind::Configuration));
    }
    if supervisor_jwt_svid.is_empty() {
        return Err(TokenGrantFailure::new(
            TokenGrantFailureKind::WorkloadIdentityRejected,
            TokenGrantStage::WorkloadIdentity,
        ));
    }
    // TLS setup errors can contain paths and transport errors can contain URLs.
    // Discard those sources at the grant boundary; never diagnose from prose.
    // The shared channel bounds the connection attempt; the gateway bounds its
    // token-service calls, and a gateway deadline arrives as DeadlineExceeded.
    let mut client = connect(&gateway.with_url(endpoint.as_str()))
        .await
        .map_err(|_| gateway_grant_failure(TokenGrantFailureKind::Unclassified))?;
    let request = provider_subject_token_exchange_request(
        ExchangeProviderSubjectTokenRequest {
            sandbox_id: sandbox_id.to_string(),
            provider: provider.to_string(),
            credential_key: credential_key.to_string(),
            supervisor_jwt_svid: supervisor_jwt_svid.to_string(),
        },
        request_id,
    );
    let response = client
        .exchange_provider_subject_token(request)
        .await
        .map_err(|status| provider_subject_token_exchange_status(&status, &endpoint))?;
    status.finish(provider_subject_token_exchange_result(
        response.into_inner(),
    ))
}

/// Attach the exchange's request ID as `x-request-id` gRPC metadata.
///
/// A value that is not valid metadata is omitted, never rewritten.
fn provider_subject_token_exchange_request(
    body: ExchangeProviderSubjectTokenRequest,
    request_id: Option<&str>,
) -> tonic::Request<ExchangeProviderSubjectTokenRequest> {
    let mut request = tonic::Request::new(body);
    if let Some(request_id) = request_id.and_then(|value| value.parse().ok()) {
        request.metadata_mut().insert("x-request-id", request_id);
    }
    request
}

fn gateway_grant_failure(kind: TokenGrantFailureKind) -> TokenGrantFailure {
    TokenGrantFailure::new(kind, TokenGrantStage::GatewayRpc)
}

/// Validate a grant gateway authority before acquiring a workload assertion.
pub fn token_grant_gateway_endpoint(
    endpoint: &str,
) -> std::result::Result<url::Url, TokenGrantFailure> {
    let endpoint = url::Url::parse(endpoint)
        .map_err(|_| gateway_grant_failure(TokenGrantFailureKind::Configuration))?;
    // gRPC endpoints identify an authority, not an arbitrary token-service URL.
    // Reject sensitive URL components before shared connection code can use it.
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != "/"
    {
        return Err(gateway_grant_failure(TokenGrantFailureKind::Configuration));
    }
    Ok(endpoint)
}

fn provider_subject_token_exchange_result(
    inner: crate::proto::ExchangeProviderSubjectTokenResponse,
) -> std::result::Result<ProviderSubjectTokenExchangeResult, TokenGrantFailure> {
    let expires_in = inner
        .expires_after
        .as_ref()
        .map(duration_to_std)
        .transpose()
        .map_err(|_| gateway_grant_failure(TokenGrantFailureKind::Unclassified))?
        .map_or(0, |value| {
            i64::try_from(value.as_secs()).unwrap_or(i64::MAX)
        });
    Ok(ProviderSubjectTokenExchangeResult {
        access_token: inner.access_token,
        expires_in,
        token_type: inner.token_type,
    })
}

fn provider_subject_token_exchange_status(
    status: &Status,
    endpoint: &url::Url,
) -> TokenGrantFailure {
    // The shared connector verifies the gateway certificate for https
    // endpoints; only that channel can vouch for a precise classification.
    if endpoint.scheme() == "https" {
        TokenGrantFailure::from_status(status)
    } else {
        // HTTP provides no authenticated server identity, even when the caller
        // supplied a valid bearer. Structured details cannot confer that trust.
        gateway_grant_failure(TokenGrantFailureKind::Unclassified)
    }
}

#[cfg(test)]
mod token_grant_exchange_tests {
    use super::*;

    #[test]
    fn authenticated_gateway_preserves_typed_failure_and_http_downgrades_it() {
        let failure = TokenGrantFailure::new(
            TokenGrantFailureKind::ProviderAuthorizationRequired,
            TokenGrantStage::IntermediateExchange,
        );
        let status = failure.to_status();
        let endpoint = |value: &str| url::Url::parse(value).unwrap();
        assert_eq!(
            provider_subject_token_exchange_status(&status, &endpoint("https://gateway:8080/")),
            failure
        );
        assert_eq!(
            provider_subject_token_exchange_status(&status, &endpoint("http://gateway:8080/")),
            gateway_grant_failure(TokenGrantFailureKind::Unclassified)
        );
    }

    #[test]
    fn exchange_request_carries_only_a_valid_request_id() {
        let request_id = "5c4b3a29-1807-4f6e-8d5c-4b3a29180716";
        for (value, expected) in [
            (Some(request_id), Some(request_id)),
            (Some("line\nbreak"), None),
            (None, None),
        ] {
            let request = provider_subject_token_exchange_request(
                ExchangeProviderSubjectTokenRequest::default(),
                value,
            );
            let carried = request.metadata().get("x-request-id");
            assert_eq!(carried.and_then(|value| value.to_str().ok()), expected);
        }
    }

    #[test]
    fn grant_gateway_endpoint_rejects_sensitive_components() {
        for endpoint in [
            "https://user:SECRET@localhost/",
            "https://localhost/?token=SECRET",
            "https://localhost/SECRET",
            "file:///SECRET",
        ] {
            let failure = token_grant_gateway_endpoint(endpoint).unwrap_err();
            assert_eq!(failure.kind(), TokenGrantFailureKind::Configuration);
        }
        assert!(token_grant_gateway_endpoint("https://localhost:8443").is_ok());
    }

    #[test]
    fn gateway_response_keeps_expiration_and_rejects_invalid_duration() {
        let response = |seconds, nanos| crate::proto::ExchangeProviderSubjectTokenResponse {
            access_token: "valid-token".into(),
            token_type: "Bearer".into(),
            expires_after: Some(prost_types::Duration { seconds, nanos }),
        };
        let result = provider_subject_token_exchange_result(response(120, 0)).unwrap();
        assert_eq!(result.access_token, "valid-token");
        assert_eq!(result.expires_in, 120);
        let failure = provider_subject_token_exchange_result(response(1, -1))
            .err()
            .expect("invalid duration is rejected");
        assert_eq!(failure.kind(), TokenGrantFailureKind::Unclassified);
    }
}

/// A reusable gRPC client for the `OpenShell` service.
///
/// Wraps a tonic channel connected once and reused for policy polling
/// and status reporting, avoiding per-request TLS handshake overhead.
#[derive(Clone)]
pub struct CachedOpenShellClient {
    client: OpenShellClient<AuthedChannel>,
    /// Sandbox instance gateway credentials rotated alongside extension
    /// credentials.
    credentials: GatewayCredentials,
    workspace: Arc<tokio::sync::OnceCell<String>>,
    /// Extension credentials for this supervisor. Cloning the client shares
    /// the store, so the middleware registry and the polling loop that rotates
    /// it observe the same slots.
    extension_credentials: ExtensionCredentialStore,
}

/// Settings poll result returned by [`CachedOpenShellClient::poll_settings`].
#[derive(Clone, Debug)]
pub struct SettingsPollResult {
    pub configuration_instance_id: String,
    pub configuration_admitted: bool,
    pub configuration_error: String,
    pub policy: Option<ProtoSandboxPolicy>,
    pub version: u32,
    pub policy_hash: String,
    pub config_revision: u64,
    pub settings_revision: u64,
    pub policy_source: PolicySource,
    /// Effective settings keyed by name.
    pub settings: HashMap<String, crate::proto::EffectiveSetting>,
    /// When `policy_source` is `Global`, the version of the global policy revision.
    pub global_policy_version: u32,
    pub provider_env_revision: u64,
    /// Attachment identity captured with this effective configuration.
    pub provider_attachment_epoch: String,
    pub supervisor_middleware_services: Vec<crate::proto::SupervisorMiddlewareService>,
    /// Workspace the sandbox belongs to.
    pub workspace: String,
    /// Gateway-configured posture for rejected policy generations.
    pub policy_validation_failure_mode: crate::PolicyValidationFailureMode,
    /// Whether the gateway can mint authenticated extension credentials.
    pub extension_authentication_enabled: bool,
}

fn settings_poll_result(inner: crate::proto::GetSandboxConfigResponse) -> SettingsPollResult {
    SettingsPollResult {
        configuration_instance_id: inner.configuration_instance_id,
        configuration_admitted: inner.configuration_admitted,
        configuration_error: inner.configuration_error,
        policy: inner.policy,
        version: inner.version,
        policy_hash: inner.policy_hash,
        config_revision: inner.config_revision,
        settings_revision: inner.settings_revision,
        policy_source: PolicySource::try_from(inner.policy_source)
            .unwrap_or(PolicySource::Unspecified),
        settings: inner.settings,
        global_policy_version: inner.global_policy_version,
        provider_env_revision: inner.provider_env_revision,
        provider_attachment_epoch: inner.provider_attachment_epoch,
        supervisor_middleware_services: inner.supervisor_middleware_services,
        workspace: inner.workspace,
        policy_validation_failure_mode: inner
            .policy_validation_failure_mode
            .parse()
            .unwrap_or_default(),
        extension_authentication_enabled: inner.extension_authentication_enabled,
    }
}

/// Delivered snapshots go through the polling projection, so both paths
/// apply the same defaults and validation.
impl From<crate::proto::SandboxConfigSnapshot> for SettingsPollResult {
    fn from(snapshot: crate::proto::SandboxConfigSnapshot) -> Self {
        settings_poll_result(crate::proto::GetSandboxConfigResponse {
            policy: snapshot.policy,
            version: snapshot.version,
            policy_hash: snapshot.policy_hash,
            settings: snapshot.settings,
            config_revision: snapshot.config_revision,
            policy_source: snapshot.policy_source,
            global_policy_version: snapshot.global_policy_version,
            provider_env_revision: snapshot.provider_env_revision,
            supervisor_middleware_services: snapshot.supervisor_middleware_services,
            workspace: snapshot.workspace,
            policy_validation_failure_mode: snapshot.policy_validation_failure_mode,
            extension_authentication_enabled: snapshot.extension_authentication_enabled,
            configuration_admitted: snapshot.configuration_admitted,
            provider_attachment_epoch: snapshot.provider_attachment_epoch,
            configuration_instance_id: snapshot.configuration_instance_id,
            configuration_error: snapshot.configuration_error,
            settings_revision: snapshot.settings_revision,
        })
    }
}

#[cfg(test)]
mod settings_poll_tests {
    use super::{learned_workspace_selector, settings_poll_result};
    use crate::PolicyValidationFailureMode;
    use crate::proto::GetSandboxConfigResponse;

    #[test]
    fn validation_failure_mode_round_trips_from_gateway_config() {
        let result = settings_poll_result(GetSandboxConfigResponse {
            policy_validation_failure_mode: "retain_last_valid".to_string(),
            ..Default::default()
        });
        assert_eq!(
            result.policy_validation_failure_mode,
            PolicyValidationFailureMode::RetainLastValid
        );
    }

    #[test]
    fn unknown_validation_failure_mode_fails_closed() {
        let result = settings_poll_result(GetSandboxConfigResponse {
            policy_validation_failure_mode: "future_mode".to_string(),
            ..Default::default()
        });
        assert_eq!(
            result.policy_validation_failure_mode,
            PolicyValidationFailureMode::FailClosed
        );
    }

    #[test]
    fn extension_authentication_capability_round_trips_and_defaults_disabled() {
        let enabled = settings_poll_result(GetSandboxConfigResponse {
            extension_authentication_enabled: true,
            ..Default::default()
        });
        assert!(enabled.extension_authentication_enabled);

        let legacy = settings_poll_result(GetSandboxConfigResponse::default());
        assert!(!legacy.extension_authentication_enabled);
    }

    #[test]
    fn delivered_sandbox_snapshot_uses_the_polling_projection() {
        let result = super::SettingsPollResult::from(crate::proto::SandboxConfigSnapshot {
            version: 7,
            policy_hash: "hash-7".to_string(),
            config_revision: 42,
            provider_env_revision: 9,
            workspace: "workspace-a".to_string(),
            extension_authentication_enabled: true,
            ..Default::default()
        });
        assert_eq!(result.version, 7);
        assert_eq!(result.policy_hash, "hash-7");
        assert_eq!(result.config_revision, 42);
        assert_eq!(result.provider_env_revision, 9);
        assert_eq!(result.workspace, "workspace-a");
        assert!(result.extension_authentication_enabled);
    }

    #[test]
    fn workspace_selector_is_omitted_until_bootstrap_learns_the_workspace() {
        assert!(learned_workspace_selector(None).is_none());

        let selector = learned_workspace_selector(Some("team-a")).expect("workspace selector");
        assert_eq!(
            selector.selection,
            Some(crate::proto::workspace_selector::Selection::Workspace(
                "team-a".to_string()
            ))
        );
    }
}

/// Credential material and the authority snapshot that produced its bindings.
pub struct ProviderEnvironmentResult {
    pub environment: HashMap<String, String>,
    pub files: HashMap<String, String>,
    pub provider_env_revision: u64,
    /// Attachment identity captured with the delivered credential records.
    pub provider_attachment_epoch: String,
    /// Effective policy used to derive the delivered endpoint bindings.
    pub policy_hash: String,
    /// Closed failure category; withheld material cannot establish readiness.
    pub readiness_reason: crate::proto::ProviderReadinessReason,
    pub credential_expires_at_ms: HashMap<String, i64>,
    pub dynamic_credentials: HashMap<String, crate::proto::ProviderProfileCredential>,
    pub static_credential_bindings: HashMap<String, crate::proto::StaticCredentialBinding>,
    pub non_secret_environment_keys: Vec<String>,
    /// Credential keys whose stable opaque handles are explicitly authorized
    /// by the gateway's endpoint bindings.
    pub stable_placeholder_environment_keys: Vec<String>,
}

/// Delivered snapshots go through the polling projection, so both paths
/// reject invalid expiration times and withhold on unknown readiness reasons.
impl TryFrom<crate::proto::ProviderEnvironmentSnapshot> for ProviderEnvironmentResult {
    type Error = miette::Report;

    fn try_from(snapshot: crate::proto::ProviderEnvironmentSnapshot) -> Result<Self> {
        use crate::proto::ProviderEnvironmentValueClassification;

        let mut response = GetSandboxProviderEnvironmentResponse {
            provider_env_revision: snapshot.provider_env_revision,
            dynamic_credentials: snapshot.dynamic_credentials,
            provider_attachment_epoch: snapshot.provider_attachment_epoch,
            policy_hash: snapshot.policy_hash,
            readiness_reason: snapshot.readiness_reason,
            files: snapshot.files,
            // Supervisor session payloads are version-locked with the gateway,
            // so every delivered snapshot carries stable-placeholder metadata.
            supports_stable_placeholder_environment_keys: true,
            ..Default::default()
        };
        for value in snapshot.values {
            if let Some(expiration_time) = value.expiration_time {
                response
                    .credential_expiration_times
                    .insert(value.name.clone(), expiration_time);
            }
            match ProviderEnvironmentValueClassification::try_from(value.classification)
                .unwrap_or_default()
            {
                ProviderEnvironmentValueClassification::NonSecret => {
                    response
                        .non_secret_environment_keys
                        .push(value.name.clone());
                }
                ProviderEnvironmentValueClassification::StaticCredential => {
                    if value.stable_placeholder {
                        response
                            .stable_placeholder_environment_keys
                            .push(value.name.clone());
                    }
                    if let Some(binding) = value.static_credential_binding {
                        response
                            .static_credential_bindings
                            .insert(value.name.clone(), binding);
                    }
                }
                ProviderEnvironmentValueClassification::Unspecified => {}
            }
            response.environment.insert(value.name, value.value);
        }
        provider_environment_result(response, false)
    }
}

#[cfg(test)]
mod provider_snapshot_tests {
    use super::ProviderEnvironmentResult;
    use crate::proto::{
        ProviderEnvironmentSnapshot, ProviderEnvironmentValue,
        ProviderEnvironmentValueClassification, ProviderReadinessReason, StaticCredentialBinding,
    };

    #[test]
    fn delivered_provider_snapshot_preserves_secret_classification_metadata() {
        let result = ProviderEnvironmentResult::try_from(ProviderEnvironmentSnapshot {
            provider_env_revision: 11,
            values: vec![
                ProviderEnvironmentValue {
                    name: "REGION".to_string(),
                    value: "west".to_string(),
                    classification: ProviderEnvironmentValueClassification::NonSecret.into(),
                    ..Default::default()
                },
                ProviderEnvironmentValue {
                    name: "TOKEN".to_string(),
                    value: "redacted".to_string(),
                    classification: ProviderEnvironmentValueClassification::StaticCredential.into(),
                    static_credential_binding: Some(StaticCredentialBinding::default()),
                    expiration_time: Some(prost_types::Timestamp {
                        seconds: 1_900_000_000,
                        nanos: 123_000_000,
                    }),
                    stable_placeholder: true,
                },
            ],
            ..Default::default()
        })
        .expect("valid provider snapshot");
        assert_eq!(result.provider_env_revision, 11);
        assert_eq!(result.environment.len(), 2);
        assert_eq!(result.non_secret_environment_keys, ["REGION"]);
        assert!(result.static_credential_bindings.contains_key("TOKEN"));
        assert_eq!(result.stable_placeholder_environment_keys, ["TOKEN"]);
        assert_eq!(
            result.credential_expires_at_ms.get("TOKEN"),
            Some(&1_900_000_000_123)
        );
        assert_eq!(
            result.readiness_reason,
            ProviderReadinessReason::Unspecified
        );
    }

    #[test]
    fn delivered_provider_snapshot_withholds_unknown_readiness_reason() {
        let result = ProviderEnvironmentResult::try_from(ProviderEnvironmentSnapshot {
            readiness_reason: i32::MAX,
            ..Default::default()
        })
        .expect("valid provider snapshot");
        assert_eq!(
            result.readiness_reason,
            ProviderReadinessReason::CredentialsWithheld
        );
    }

    #[test]
    fn delivered_provider_snapshot_rejects_invalid_credential_expiration() {
        let result = ProviderEnvironmentResult::try_from(ProviderEnvironmentSnapshot {
            values: vec![ProviderEnvironmentValue {
                name: "TOKEN".to_string(),
                value: "redacted".to_string(),
                expiration_time: Some(prost_types::Timestamp {
                    seconds: 1_900_000_000,
                    nanos: -1,
                }),
                ..Default::default()
            }],
            ..Default::default()
        });
        assert!(result.is_err());
    }
}

/// Intermediate provider credential returned to the trusted supervisor.
///
/// Tokens deliberately have no Debug representation.
pub struct ProviderSubjectTokenExchangeResult {
    /// Bearer material for the final token exchange; never log this field.
    pub access_token: String,
    /// Remaining lifetime in seconds, or zero when the gateway omitted it.
    pub expires_in: i64,
    pub token_type: String,
}

impl CachedOpenShellClient {
    pub async fn connect(gateway: &GatewayEndpoint) -> Result<Self> {
        Self::connect_with_credentials(gateway, ExtensionCredentialStore::new()).await
    }

    /// Connect while sharing an existing credential store.
    ///
    /// The supervisor opens the gateway channel more than once (policy load,
    /// then the polling loop). Both must observe the same slots, otherwise the
    /// credentials handed to the middleware registry are not the ones the loop
    /// rotates.
    pub async fn connect_with_credentials(
        gateway: &GatewayEndpoint,
        extension_credentials: ExtensionCredentialStore,
    ) -> Result<Self> {
        debug!(endpoint = %gateway.url(), "Connecting openshell gRPC client for policy polling");
        let client = connect(gateway).await?;
        Ok(Self {
            client,
            credentials: gateway.credentials.clone(),
            workspace: Arc::new(tokio::sync::OnceCell::new()),
            extension_credentials,
        })
    }

    /// Get a clone of the underlying tonic client for direct RPC calls.
    pub fn raw_client(&self) -> OpenShellClient<AuthedChannel> {
        self.client.clone()
    }

    /// Poll for current effective sandbox settings and policy metadata.
    pub async fn poll_settings(&self, sandbox_name: &str) -> Result<SettingsPollResult> {
        // Sandbox-authenticated callers may omit the selector during bootstrap.
        // Once the first response identifies the workspace, scope every later
        // poll explicitly instead of constructing an invalid empty selector.
        let workspace_scope = learned_workspace_selector(self.workspace.get().map(String::as_str));
        let response = self
            .client
            .clone()
            .get_sandbox_config(GetSandboxConfigRequest {
                workspace_scope,
                name: sandbox_name.to_string(),
            })
            .await
            .into_diagnostic()?;

        let result = settings_poll_result(response.into_inner());
        let _ = self.workspace.set(result.workspace.clone());
        Ok(result)
    }

    /// The credential store backing this connection's extension clients.
    #[must_use]
    pub fn extension_credentials(&self) -> &ExtensionCredentialStore {
        &self.extension_credentials
    }

    /// Return the slots for `services`, rotating only when one is missing or
    /// due.
    ///
    /// Configuration polling runs far more often than credentials expire, so
    /// rotating unconditionally would mint tokens and re-run gateway policy
    /// authorization roughly ninety times per useful rotation.
    pub async fn extension_credentials_for(
        &self,
        services: &[crate::proto::SupervisorMiddlewareService],
    ) -> Result<HashMap<String, BearerTokenSlot>> {
        let names = authenticated_service_names(services);
        if names.is_empty() {
            return Ok(HashMap::new());
        }
        if !self.extension_credentials.needs_refresh(&names, now_ms())
            && let Some(slots) = self.extension_credentials.slots_for(&names)
        {
            return Ok(slots);
        }
        self.refresh_extension_credentials(services).await
    }

    /// Rotate credentials for `services` unconditionally.
    pub async fn refresh_extension_credentials(
        &self,
        services: &[crate::proto::SupervisorMiddlewareService],
    ) -> Result<HashMap<String, BearerTokenSlot>> {
        let mut client = self.client.clone();
        refresh_extension_credentials_with_client(
            &mut client,
            &self.credentials,
            &self.extension_credentials,
            services,
        )
        .await
    }

    /// Rotate every credential currently retained by the installed registry.
    /// This remains available when configuration polling fails independently.
    pub async fn refresh_installed_extension_credentials(&self) -> Result<()> {
        let names = self.extension_credentials.names();
        if names.is_empty() || !self.extension_credentials.needs_refresh(&names, now_ms()) {
            return Ok(());
        }
        let services = names
            .into_iter()
            .map(|name| crate::proto::SupervisorMiddlewareService {
                name,
                ..Default::default()
            })
            .collect::<Vec<_>>();
        self.refresh_extension_credentials(&services)
            .await
            .map(drop)
    }

    /// Returns the workspace learned from the server, or empty if not yet polled.
    pub fn workspace(&self) -> String {
        self.workspace.get().cloned().unwrap_or_default()
    }

    /// Pre-seed the workspace without polling. The value is ignored if the
    /// workspace was already learned from `poll_settings`.
    pub fn set_workspace(&self, workspace: String) {
        let _ = self.workspace.set(workspace);
    }

    /// Submit denial summaries and/or agent-authored proposals for policy analysis.
    ///
    /// Returns the gateway response so callers can surface accepted/rejected
    /// counts, rejection reasons, and server-assigned `accepted_chunk_ids`
    /// (e.g., the `policy.local` API forwards these to the in-sandbox agent
    /// so it can watch proposal state via `GET /v1/proposals/{id}`).
    pub async fn submit_policy_analysis(
        &self,
        sandbox_name: &str,
        summaries: Vec<DenialSummary>,
        proposed_chunks: Vec<PolicyChunk>,
        network_activity_summaries: Vec<NetworkActivitySummary>,
        analysis_mode: &str,
    ) -> Result<SubmitPolicyAnalysisResponse> {
        let response = self
            .client
            .clone()
            .submit_policy_analysis(SubmitPolicyAnalysisRequest {
                name: sandbox_name.to_string(),
                summaries,
                proposed_chunks,
                network_activity_summaries,
                analysis_mode: analysis_mode.to_string(),
                workspace_scope: Some(crate::proto::workspace_selector(self.workspace())),
            })
            .await
            .into_diagnostic()?;

        Ok(response.into_inner())
    }

    /// Fetch the current draft chunks for a sandbox. `status_filter` may be
    /// `"pending"`, `"approved"`, `"rejected"`, or empty for all. Used by
    /// `policy.local`'s `GET /v1/proposals/{id}` and `/wait` routes to
    /// inspect proposal state.
    pub async fn get_draft_policy(
        &self,
        sandbox_name: &str,
        status_filter: &str,
    ) -> Result<Vec<PolicyChunk>> {
        let response = self
            .client
            .clone()
            .get_draft_policy(GetDraftPolicyRequest {
                status_filter: status_filter.to_string(),
                sandbox: sandbox_name.to_string(),
                workspace_scope: Some(crate::proto::workspace_selector(self.workspace())),
            })
            .await
            .into_diagnostic()?;
        Ok(response.into_inner().chunks)
    }

    /// Report policy load status back to the server.
    pub async fn report_policy_status(
        &self,
        sandbox_id: &str,
        version: u32,
        loaded: bool,
        error_msg: &str,
    ) -> Result<()> {
        let status = if loaded {
            PolicyStatus::Loaded
        } else {
            PolicyStatus::Failed
        };

        self.client
            .clone()
            .report_policy_status(ReportPolicyStatusRequest {
                sandbox_id: sandbox_id.to_string(),
                version,
                status: status.into(),
                load_error: error_msg.to_string(),
            })
            .await
            .into_diagnostic()?;

        Ok(())
    }

    /// Report the latest network results for all configured tool endpoints.
    ///
    /// The shared snapshot contains only endpoint identifiers, typed results,
    /// and the endpoints observed in the current batch, so this RPC cannot
    /// accidentally attach request or credential material to public status.
    pub async fn report_endpoint_status(
        &self,
        sandbox_id: &str,
        snapshot: &EndpointStatusSnapshot,
    ) -> Result<()> {
        let observations = snapshot
            .endpoints
            .iter()
            .map(|endpoint| ProtoEndpointObservation {
                endpoint_id: endpoint.endpoint_id.clone(),
                result: match endpoint.result {
                    EndpointResult::NoObservedExchange => ProtoEndpointResult::NoObservedExchange,
                    EndpointResult::HttpResponseReceived => {
                        ProtoEndpointResult::HttpResponseReceived
                    }
                    EndpointResult::PolicyDenied => ProtoEndpointResult::PolicyDenied,
                    EndpointResult::CredentialUnavailable => {
                        ProtoEndpointResult::CredentialUnavailable
                    }
                    EndpointResult::TlsFailed => ProtoEndpointResult::TlsFailed,
                    EndpointResult::TransportFailed => ProtoEndpointResult::TransportFailed,
                    EndpointResult::UpstreamRejected => ProtoEndpointResult::UpstreamRejected,
                }
                .into(),
                failure: endpoint
                    .failure
                    .as_ref()
                    .map(crate::endpoint_failure::EndpointFailure::to_proto),
            })
            .collect();

        self.client
            .clone()
            .report_endpoint_status(ReportEndpointStatusRequest {
                sandbox_id: sandbox_id.to_string(),
                policy_hash: snapshot.config_version.policy_hash.clone(),
                provider_env_revision: snapshot.config_version.provider_env_revision,
                observations,
                observed_endpoint_ids: snapshot.observed_endpoint_ids.clone(),
                supervisor_session_id: snapshot.supervisor_session_id.clone(),
                report_sequence: snapshot.report_sequence,
                token_grant_status: Some(crate::proto::TokenGrantStatus {
                    last_failure: snapshot.last_token_grant_failure.clone(),
                }),
            })
            .await
            .into_diagnostic()?;

        Ok(())
    }
}
