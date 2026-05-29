// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! gRPC client for fetching sandbox policy, provider environment, and inference
//! route bundles from `OpenShell` server.
//!
//! Every request carries a gateway-minted JWT in the `Authorization` header.
//! The token is resolved at startup from the explicit
//! `OPENSHELL_SANDBOX_AUTH_MODE`:
//!
//! - `static-token` reads `OPENSHELL_SANDBOX_TOKEN` and never refreshes it.
//! - `gateway-managed-file` reads `OPENSHELL_SANDBOX_TOKEN_FILE`; Docker and
//!   Podman refresh that host-side file from the gateway.
//! - `gateway-managed-supervisor-push` reads `OPENSHELL_SANDBOX_TOKEN_FILE`;
//!   VM refreshes that file through gateway control-stream pushes.
//! - `kubernetes-service-account-exchange` reads
//!   `OPENSHELL_K8S_SA_TOKEN_FILE` and exchanges it for a gateway JWT via
//!   `IssueSandboxToken`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::proto::{
    DenialSummary, GetDraftPolicyRequest, GetInferenceBundleRequest, GetInferenceBundleResponse,
    GetSandboxConfigRequest, GetSandboxProviderEnvironmentRequest, IssueSandboxTokenRequest,
    PolicyChunk, PolicySource, PolicyStatus, ReportPolicyStatusRequest,
    SandboxPolicy as ProtoSandboxPolicy, SubmitPolicyAnalysisRequest, SubmitPolicyAnalysisResponse,
    UpdateConfigRequest, inference_client::InferenceClient, open_shell_client::OpenShellClient,
};
use openshell_core::sandbox_env;
use openshell_core::sandbox_env::SandboxAuthMode;
use tonic::Status;
use tonic::metadata::AsciiMetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tracing::{debug, info, warn};

/// Channel type after the [`AuthInterceptor`] is applied. Aliased so the
/// generated client type signatures stay readable.
pub type AuthedChannel = InterceptedService<Channel, AuthInterceptor>;

/// Shared Bearer header. All [`AuthInterceptor`] clones read the same slot, so
/// Kubernetes token re-exchange can replace the token in place without
/// rebuilding the channel.
type TokenSlot = Arc<RwLock<AsciiMetadataValue>>;

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenSource {
    StaticToken,
    GatewayManagedFile { path: PathBuf },
    GatewayManagedSupervisorPush { path: PathBuf },
    K8sServiceAccount { path: PathBuf },
}

impl TokenSource {
    fn token_file_path(&self) -> Option<&Path> {
        match self {
            Self::GatewayManagedFile { path } | Self::GatewayManagedSupervisorPush { path } => {
                Some(path)
            }
            Self::StaticToken | Self::K8sServiceAccount { .. } => None,
        }
    }
}

#[derive(Debug)]
struct AcquiredToken {
    token: String,
    source: TokenSource,
}

/// Process-wide token slot. Initialized by the first [`connect_channel`]
/// call and shared with every subsequent client and the Kubernetes exchange
/// loop, when that auth mode is active.
static TOKEN_SLOT: OnceLock<TokenSlot> = OnceLock::new();

/// Source used to acquire the process-wide token slot.
static TOKEN_SOURCE: OnceLock<TokenSource> = OnceLock::new();

/// Serializes the first token acquisition. Several supervisor subsystems
/// connect during startup; without this guard they can all observe an empty
/// [`TOKEN_SLOT`] and perform duplicate Kubernetes `ServiceAccount` exchanges.
static TOKEN_INIT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// One-shot guard so the Kubernetes exchange loop spawns at most once per
/// process.
static REFRESH_SPAWNED: OnceLock<()> = OnceLock::new();

fn bearer_value(token: &str) -> Result<AsciiMetadataValue> {
    AsciiMetadataValue::try_from(format!("Bearer {token}"))
        .into_diagnostic()
        .wrap_err("sandbox JWT contained characters not valid for a header value")
}

fn install_token_slot(token: &str) -> Result<TokenSlot> {
    let bearer = bearer_value(token)?;
    if let Some(existing) = TOKEN_SLOT.get() {
        *existing.write().expect("token slot poisoned") = bearer;
        return Ok(existing.clone());
    }
    let slot: TokenSlot = Arc::new(RwLock::new(bearer));
    let _ = TOKEN_SLOT.set(slot.clone());
    Ok(TOKEN_SLOT.get().cloned().unwrap_or(slot))
}

/// gRPC interceptor that injects `authorization: Bearer <token>` on every
/// outbound request. The token lives in a shared [`TokenSlot`] so Kubernetes
/// token re-exchange can replace it without rebuilding clients.
#[derive(Clone)]
pub struct AuthInterceptor {
    bearer: TokenSlot,
    source: TokenSource,
}

impl AuthInterceptor {
    fn new(bearer: TokenSlot, source: TokenSource) -> Self {
        Self { bearer, source }
    }

    fn current_bearer(&self) -> AsciiMetadataValue {
        if let Some(path) = self.source.token_file_path() {
            match read_sandbox_token_file(path).and_then(|token| bearer_value(&token)) {
                Ok(value) => {
                    if let Ok(mut guard) = self.bearer.write()
                        && *guard != value
                    {
                        *guard = value.clone();
                        debug!(
                            path = %path.display(),
                            "loaded rotated sandbox token from file"
                        );
                    }
                    return value;
                }
                Err(err) => warn!(
                    path = %path.display(),
                    error = %err,
                    "failed to reload sandbox token file; using cached token"
                ),
            }
        }

        self.bearer
            .read()
            .expect("auth interceptor token slot poisoned")
            .clone()
    }
}

impl tonic::service::Interceptor for AuthInterceptor {
    fn call(
        &mut self,
        mut req: tonic::Request<()>,
    ) -> std::result::Result<tonic::Request<()>, Status> {
        req.metadata_mut()
            .insert("authorization", self.current_bearer());
        Ok(req)
    }
}

/// Build the plain (un-intercepted) gRPC channel.
///
/// When the endpoint uses `https://`, mTLS is configured using these env vars:
/// - `OPENSHELL_TLS_CA` -- path to the CA certificate
/// - `OPENSHELL_TLS_CERT` -- path to the client certificate
/// - `OPENSHELL_TLS_KEY` -- path to the client private key
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

    if tls_enabled {
        let ca_path = std::env::var(sandbox_env::TLS_CA)
            .into_diagnostic()
            .wrap_err("OPENSHELL_TLS_CA is required")?;
        let cert_path = std::env::var(sandbox_env::TLS_CERT)
            .into_diagnostic()
            .wrap_err("OPENSHELL_TLS_CERT is required")?;
        let key_path = std::env::var(sandbox_env::TLS_KEY)
            .into_diagnostic()
            .wrap_err("OPENSHELL_TLS_KEY is required")?;

        let ca_pem = std::fs::read(&ca_path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read CA cert from {ca_path}"))?;
        let cert_pem = std::fs::read(&cert_path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read client cert from {cert_path}"))?;
        let key_pem = std::fs::read(&key_path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read client key from {key_path}"))?;

        let tls_config = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca_pem))
            .identity(Identity::from_pem(cert_pem, key_pem));

        ep = ep
            .tls_config(tls_config)
            .into_diagnostic()
            .wrap_err("failed to configure TLS")?;
    }

    ep.connect()
        .await
        .into_diagnostic()
        .wrap_err("failed to connect to OpenShell server")
}

/// Build a Bearer-authenticated channel to the gateway.
///
/// First call per process resolves the sandbox JWT from
/// `OPENSHELL_SANDBOX_AUTH_MODE` and installs it into the process-wide
/// [`TOKEN_SLOT`]. Subsequent calls reuse the cached slot. For Kubernetes
/// service-account exchange mode, the refresh loop is spawned once per process
/// via [`REFRESH_SPAWNED`].
async fn connect_channel(endpoint: &str) -> Result<AuthedChannel> {
    let channel = build_plain_channel(endpoint).await?;
    let (slot, source) = token_slot(endpoint, &channel).await?;
    let plain_channel = channel.clone();
    let intercepted =
        InterceptedService::new(channel, AuthInterceptor::new(slot.clone(), source.clone()));
    if let TokenSource::K8sServiceAccount { path } = &source
        && REFRESH_SPAWNED.set(()).is_ok()
    {
        let endpoint = endpoint.to_string();
        let path = path.clone();
        tokio::spawn(async move {
            refresh_k8s_exchange_loop(slot, endpoint, plain_channel, path).await;
        });
    }
    Ok(intercepted)
}

async fn token_slot(endpoint: &str, plain_channel: &Channel) -> Result<(TokenSlot, TokenSource)> {
    if let Some(existing) = TOKEN_SLOT.get() {
        let source = TOKEN_SOURCE
            .get()
            .cloned()
            .unwrap_or(TokenSource::StaticToken);
        return Ok((existing.clone(), source));
    }

    let _guard = TOKEN_INIT_LOCK.lock().await;

    if let Some(existing) = TOKEN_SLOT.get() {
        let source = TOKEN_SOURCE
            .get()
            .cloned()
            .unwrap_or(TokenSource::StaticToken);
        return Ok((existing.clone(), source));
    }

    let acquired = acquire_sandbox_token(endpoint, plain_channel).await?;
    let slot = install_token_slot(&acquired.token)?;
    let _ = TOKEN_SOURCE.set(acquired.source.clone());
    Ok((slot, acquired.source))
}

/// Resolve the sandbox JWT used to authenticate every outbound RPC.
///
/// `endpoint` is logged on errors but never used for transport here; the
/// actual network call lives inside this function only on the K8s
/// bootstrap path, which uses `plain_channel` to call `IssueSandboxToken`
/// once before the steady-state Bearer-authenticated channel is built.
async fn acquire_sandbox_token(endpoint: &str, plain_channel: &Channel) -> Result<AcquiredToken> {
    let auth_mode = sandbox_auth_mode()?;

    match auth_mode {
        SandboxAuthMode::StaticToken => {
            let token = required_env(sandbox_env::SANDBOX_TOKEN, auth_mode)?;
            debug!(
                source = "env",
                mode = auth_mode.as_str(),
                "loaded sandbox token"
            );
            Ok(AcquiredToken {
                token,
                source: TokenSource::StaticToken,
            })
        }
        SandboxAuthMode::GatewayManagedFile => {
            let path = required_path_env(sandbox_env::SANDBOX_TOKEN_FILE, auth_mode)?;
            let token = read_sandbox_token_file(&path)?;
            debug!(source = "file", mode = auth_mode.as_str(), path = %path.display(), "loaded sandbox token");
            Ok(AcquiredToken {
                token,
                source: TokenSource::GatewayManagedFile { path },
            })
        }
        SandboxAuthMode::GatewayManagedSupervisorPush => {
            let path = required_path_env(sandbox_env::SANDBOX_TOKEN_FILE, auth_mode)?;
            let token = read_sandbox_token_file(&path)?;
            debug!(source = "file", mode = auth_mode.as_str(), path = %path.display(), "loaded sandbox token");
            Ok(AcquiredToken {
                token,
                source: TokenSource::GatewayManagedSupervisorPush { path },
            })
        }
        SandboxAuthMode::KubernetesServiceAccountExchange => {
            let path = required_path_env(sandbox_env::K8S_SA_TOKEN_FILE, auth_mode)?;
            Ok(AcquiredToken {
                token: acquire_k8s_sandbox_token(endpoint, plain_channel, &path).await?,
                source: TokenSource::K8sServiceAccount { path },
            })
        }
    }
}

fn sandbox_auth_mode() -> Result<SandboxAuthMode> {
    let value = std::env::var(sandbox_env::SANDBOX_AUTH_MODE)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "{} is required (expected one of: {})",
                sandbox_env::SANDBOX_AUTH_MODE,
                SandboxAuthMode::allowed_values()
            )
        })?;
    value
        .parse::<SandboxAuthMode>()
        .map_err(|err| miette::miette!("{err}"))
}

fn required_env(name: &str, auth_mode: SandboxAuthMode) -> Result<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            miette::miette!(
                "{} is required when {}={}",
                name,
                sandbox_env::SANDBOX_AUTH_MODE,
                auth_mode.as_str()
            )
        })
}

fn required_path_env(name: &str, auth_mode: SandboxAuthMode) -> Result<PathBuf> {
    required_env(name, auth_mode).map(PathBuf::from)
}

async fn acquire_k8s_sandbox_token(
    endpoint: &str,
    plain_channel: &Channel,
    sa_path: &Path,
) -> Result<String> {
    let sa_token = std::fs::read_to_string(sa_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read K8s SA token from {}", sa_path.display()))?
        .trim()
        .to_string();
    info!(endpoint = %endpoint, "exchanging K8s ServiceAccount token for sandbox JWT");
    // The ServiceAccount exchange uses a one-off interceptor pinned to the
    // SA token; the resulting gateway JWT becomes the value in the
    // shared `TOKEN_SLOT` once `connect_channel` returns.
    let bootstrap_slot: TokenSlot = Arc::new(RwLock::new(
        AsciiMetadataValue::try_from(format!("Bearer {sa_token}"))
            .into_diagnostic()
            .wrap_err("SA token contained characters not valid for a header value")?,
    ));
    let interceptor = AuthInterceptor::new(bootstrap_slot, TokenSource::StaticToken);
    let bootstrap = InterceptedService::new(plain_channel.clone(), interceptor);
    let mut client = OpenShellClient::new(bootstrap);
    let resp = client
        .issue_sandbox_token(IssueSandboxTokenRequest {})
        .await
        .into_diagnostic()
        .wrap_err("IssueSandboxToken service-account exchange failed")?;
    Ok(resp.into_inner().token)
}

/// Build an authenticated channel for direct external use (e.g. the
/// long-lived `supervisor_session` control stream).
pub async fn connect_channel_pub(endpoint: &str) -> Result<AuthedChannel> {
    connect_channel(endpoint).await
}

/// Background task that re-exchanges the Kubernetes `ServiceAccount` JWT at
/// ~80% of the gateway JWT's remaining lifetime. The new gateway token
/// replaces the value in [`TOKEN_SLOT`], so all in-flight and future clients
/// pick it up on their next request. The loop never panics: every failure is
/// logged and retried after a bounded backoff.
async fn refresh_k8s_exchange_loop(
    slot: TokenSlot,
    endpoint: String,
    plain_channel: Channel,
    sa_path: PathBuf,
) {
    loop {
        let sleep = compute_refresh_delay(&slot);
        tokio::time::sleep(sleep).await;
        match acquire_k8s_sandbox_token(&endpoint, &plain_channel, &sa_path).await {
            Ok(new_token) => match AsciiMetadataValue::try_from(format!("Bearer {new_token}")) {
                Ok(value) => {
                    if let Ok(mut guard) = slot.write() {
                        *guard = value;
                        info!("re-exchanged Kubernetes ServiceAccount token for sandbox JWT");
                    }
                }
                Err(e) => warn!(error = %e, "refreshed JWT contained invalid header bytes"),
            },
            Err(err) => {
                warn!(
                    path = %sa_path.display(),
                    error = %err,
                    "Kubernetes ServiceAccount token exchange failed; will retry"
                );
                // Backoff so we don't spin against a sustained failure.
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}

pub fn supervisor_pushed_token_file_path() -> Option<PathBuf> {
    if sandbox_auth_mode().ok() != Some(SandboxAuthMode::GatewayManagedSupervisorPush) {
        return None;
    }
    std::env::var(sandbox_env::SANDBOX_TOKEN_FILE)
        .ok()
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

fn read_sandbox_token_file(path: &Path) -> Result<String> {
    let contents = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read sandbox token from {}", path.display()))?;
    let token = contents.trim().to_string();
    if token.is_empty() {
        return Err(miette::miette!(
            "sandbox token file {} was empty",
            path.display()
        ));
    }
    Ok(token)
}

/// Compute the next refresh delay: 80 % of the time remaining until the
/// current token's `exp`, plus up to 10 % jitter, with a small lower bound
/// for already-expired tokens and capped at 12 h. If the token can't be parsed
/// (legacy/non-JWT bearer)
/// default to 6 h.
fn compute_refresh_delay(slot: &TokenSlot) -> Duration {
    let token = slot
        .read()
        .ok()
        .and_then(|v| v.to_str().ok().map(str::to_string))
        .unwrap_or_default();
    let bearer = token.strip_prefix("Bearer ").unwrap_or(&token);
    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()),
    )
    .unwrap_or(i64::MAX);
    let remaining_ms = parse_jwt_exp_ms(bearer).map_or(21_600_000, |exp| exp - now_ms); // 6 h fallback
    let mut delay_ms = if remaining_ms <= 0 {
        1_000
    } else {
        (remaining_ms * 8 / 10).clamp(1_000, 43_200_000)
    };
    // Up to 10 % jitter, derived deterministically from token bytes so
    // unit tests are reproducible without injecting an RNG.
    let jitter_pct = (token.len() % 10) as u64;
    let jitter_ms = (u64::try_from(delay_ms).unwrap_or(0) * jitter_pct) / 100;
    delay_ms = delay_ms.saturating_add(i64::try_from(jitter_ms).unwrap_or(0));
    Duration::from_millis(u64::try_from(delay_ms).unwrap_or(0))
}

/// Decode the `exp` claim from a JWT without verifying its signature.
/// Returns the expiry in milliseconds since the Unix epoch, or `None` if
/// the token is not a parseable JWT.
fn parse_jwt_exp_ms(jwt: &str) -> Option<i64> {
    use base64::Engine;
    let mut parts = jwt.splitn(3, '.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    let exp_secs = value.get("exp")?.as_i64()?;
    exp_secs.checked_mul(1000)
}

#[cfg(test)]
mod auth_tests {
    use super::*;

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
        let slot: TokenSlot = Arc::new(RwLock::new(bearer));
        let delay = compute_refresh_delay(&slot);
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
        let slot: TokenSlot = Arc::new(RwLock::new(bearer));
        let delay = compute_refresh_delay(&slot);
        assert!((1..60).contains(&delay.as_secs()));
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
        let slot: TokenSlot = Arc::new(RwLock::new(bearer));
        let delay = compute_refresh_delay(&slot);
        assert!(
            delay.as_secs() < 30,
            "expected refresh before 30s expiry, got {delay:?}",
        );
    }

    #[test]
    fn file_token_interceptor_reads_rotated_token_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sandbox.jwt");
        std::fs::write(&path, "old-token\n").unwrap();
        let slot: TokenSlot = Arc::new(RwLock::new(bearer_value("old-token").unwrap()));
        let mut interceptor = AuthInterceptor::new(
            slot.clone(),
            TokenSource::GatewayManagedFile { path: path.clone() },
        );

        let req =
            tonic::service::Interceptor::call(&mut interceptor, tonic::Request::new(())).unwrap();
        assert_eq!(
            req.metadata()
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer old-token")
        );

        std::fs::write(&path, "new-token\n").unwrap();

        let req =
            tonic::service::Interceptor::call(&mut interceptor, tonic::Request::new(())).unwrap();
        assert_eq!(
            req.metadata()
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer new-token")
        );
        let guard = slot.read().unwrap();
        assert_eq!(guard.to_str().ok(), Some("Bearer new-token"));
    }
}

/// Connect to the `OpenShell` server.
async fn connect(endpoint: &str) -> Result<OpenShellClient<AuthedChannel>> {
    let channel = connect_channel(endpoint).await?;
    Ok(OpenShellClient::new(channel))
}

/// Connect to the inference service.
async fn connect_inference(endpoint: &str) -> Result<InferenceClient<AuthedChannel>> {
    let channel = connect_channel(endpoint).await?;
    Ok(InferenceClient::new(channel))
}

/// Fetch sandbox policy from `OpenShell` server via gRPC.
///
/// Returns `Ok(Some(policy))` when the server has a policy configured,
/// or `Ok(None)` when the sandbox was created without a policy (the sandbox
/// should discover one from disk or use the restrictive default).
pub async fn fetch_policy(endpoint: &str, sandbox_id: &str) -> Result<Option<ProtoSandboxPolicy>> {
    debug!(endpoint = %endpoint, sandbox_id = %sandbox_id, "Connecting to OpenShell server");

    let mut client = connect(endpoint).await?;

    debug!("Connected, fetching sandbox policy");

    fetch_policy_with_client(&mut client, sandbox_id).await
}

/// Fetch sandbox policy using an existing client connection.
async fn fetch_policy_with_client(
    client: &mut OpenShellClient<AuthedChannel>,
    sandbox_id: &str,
) -> Result<Option<ProtoSandboxPolicy>> {
    let response = client
        .get_sandbox_config(GetSandboxConfigRequest {
            sandbox_id: sandbox_id.to_string(),
        })
        .await
        .into_diagnostic()?;

    let inner = response.into_inner();

    // version 0 with no policy means the sandbox was created without one.
    if inner.version == 0 && inner.policy.is_none() {
        return Ok(None);
    }

    Ok(Some(inner.policy.ok_or_else(|| {
        miette::miette!("Server returned non-zero version but empty policy")
    })?))
}

/// Sync a locally-discovered policy using an existing client connection.
async fn sync_policy_with_client(
    client: &mut OpenShellClient<AuthedChannel>,
    sandbox: &str,
    policy: &ProtoSandboxPolicy,
) -> Result<()> {
    client
        .update_config(UpdateConfigRequest {
            name: sandbox.to_string(),
            policy: Some(policy.clone()),
            setting_key: String::new(),
            setting_value: None,
            delete_setting: false,
            global: false,
            merge_operations: vec![],
            expected_resource_version: 0,
        })
        .await
        .into_diagnostic()
        .wrap_err("failed to sync policy to server")?;

    Ok(())
}

/// Discover and sync policy using a single gRPC connection.
///
/// Performs the full discovery flow (fetch → sync → re-fetch) over one
/// channel instead of establishing three separate connections.
pub async fn discover_and_sync_policy(
    endpoint: &str,
    sandbox_id: &str,
    sandbox: &str,
    discovered_policy: &ProtoSandboxPolicy,
) -> Result<ProtoSandboxPolicy> {
    debug!(
        endpoint = %endpoint,
        sandbox_id = %sandbox_id,
        sandbox = %sandbox,
        "Syncing discovered policy and re-fetching canonical version"
    );

    let mut client = connect(endpoint).await?;

    // Sync the discovered policy to the gateway.
    sync_policy_with_client(&mut client, sandbox, discovered_policy).await?;

    // Re-fetch from the gateway to get the canonical version/hash.
    fetch_policy_with_client(&mut client, sandbox_id)
        .await?
        .ok_or_else(|| {
            miette::miette!("Server still returned no policy after sync — this is a bug")
        })
}

/// Sync an enriched policy back to the gateway.
///
/// Used by the supervisor to push baseline-path-enriched policies so the
/// gateway stores the effective policy users see via `openshell sandbox get`.
pub async fn sync_policy(endpoint: &str, sandbox: &str, policy: &ProtoSandboxPolicy) -> Result<()> {
    debug!(endpoint = %endpoint, sandbox = %sandbox, "Syncing enriched policy to gateway");
    let mut client = connect(endpoint).await?;
    sync_policy_with_client(&mut client, sandbox, policy).await
}

/// Fetch provider environment variables for a sandbox from `OpenShell` server via gRPC.
///
/// Returns a map of environment variable names to values derived from provider
/// credentials configured on the sandbox. Returns an empty map if the sandbox
/// has no providers or the call fails.
pub async fn fetch_provider_environment(
    endpoint: &str,
    sandbox_id: &str,
) -> Result<ProviderEnvironmentResult> {
    debug!(endpoint = %endpoint, sandbox_id = %sandbox_id, "Fetching provider environment");

    let mut client = connect(endpoint).await?;

    let response = client
        .get_sandbox_provider_environment(GetSandboxProviderEnvironmentRequest {
            sandbox_id: sandbox_id.to_string(),
        })
        .await
        .into_diagnostic()?;

    let inner = response.into_inner();
    Ok(ProviderEnvironmentResult {
        environment: inner.environment,
        provider_env_revision: inner.provider_env_revision,
        credential_expires_at_ms: inner.credential_expires_at_ms,
    })
}

/// A reusable gRPC client for the `OpenShell` service.
///
/// Wraps a tonic channel connected once and reused for policy polling
/// and status reporting, avoiding per-request TLS handshake overhead.
#[derive(Clone)]
pub struct CachedOpenShellClient {
    client: OpenShellClient<AuthedChannel>,
}

/// Settings poll result returned by [`CachedOpenShellClient::poll_settings`].
pub struct SettingsPollResult {
    pub policy: Option<ProtoSandboxPolicy>,
    pub version: u32,
    pub policy_hash: String,
    pub config_revision: u64,
    pub policy_source: PolicySource,
    /// Effective settings keyed by name.
    pub settings: HashMap<String, openshell_core::proto::EffectiveSetting>,
    /// When `policy_source` is `Global`, the version of the global policy revision.
    pub global_policy_version: u32,
    pub provider_env_revision: u64,
}

pub struct ProviderEnvironmentResult {
    pub environment: HashMap<String, String>,
    pub provider_env_revision: u64,
    pub credential_expires_at_ms: HashMap<String, i64>,
}

impl CachedOpenShellClient {
    pub async fn connect(endpoint: &str) -> Result<Self> {
        debug!(endpoint = %endpoint, "Connecting openshell gRPC client for policy polling");
        let client = connect(endpoint).await?;
        Ok(Self { client })
    }

    /// Get a clone of the underlying tonic client for direct RPC calls.
    pub fn raw_client(&self) -> OpenShellClient<AuthedChannel> {
        self.client.clone()
    }

    /// Poll for current effective sandbox settings and policy metadata.
    pub async fn poll_settings(&self, sandbox_id: &str) -> Result<SettingsPollResult> {
        let response = self
            .client
            .clone()
            .get_sandbox_config(GetSandboxConfigRequest {
                sandbox_id: sandbox_id.to_string(),
            })
            .await
            .into_diagnostic()?;

        let inner = response.into_inner();

        Ok(SettingsPollResult {
            policy: inner.policy,
            version: inner.version,
            policy_hash: inner.policy_hash,
            config_revision: inner.config_revision,
            policy_source: PolicySource::try_from(inner.policy_source)
                .unwrap_or(PolicySource::Unspecified),
            settings: inner.settings,
            global_policy_version: inner.global_policy_version,
            provider_env_revision: inner.provider_env_revision,
        })
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
        analysis_mode: &str,
    ) -> Result<SubmitPolicyAnalysisResponse> {
        let response = self
            .client
            .clone()
            .submit_policy_analysis(SubmitPolicyAnalysisRequest {
                name: sandbox_name.to_string(),
                summaries,
                proposed_chunks,
                analysis_mode: analysis_mode.to_string(),
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
                name: sandbox_name.to_string(),
                status_filter: status_filter.to_string(),
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
}

/// Fetch the resolved inference route bundle from the server.
pub async fn fetch_inference_bundle(endpoint: &str) -> Result<GetInferenceBundleResponse> {
    debug!(endpoint = %endpoint, "Fetching inference route bundle");

    let mut client = connect_inference(endpoint).await?;

    let response = client
        .get_inference_bundle(GetInferenceBundleRequest {})
        .await
        .into_diagnostic()?;

    Ok(response.into_inner())
}
