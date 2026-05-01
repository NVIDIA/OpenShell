// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! gRPC client for fetching sandbox policy, provider environment, and inference
//! route bundles from `OpenShell` server.

use std::collections::HashMap;
use std::time::Duration;

use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::proto::{
    DenialSummary, GetInferenceBundleRequest, GetInferenceBundleResponse, GetSandboxConfigRequest,
    GetSandboxProviderEnvironmentRequest, PolicySource, PolicyStatus, ReportPolicyStatusRequest,
    SandboxPolicy as ProtoSandboxPolicy, SubmitPolicyAnalysisRequest, UpdateConfigRequest,
    inference_client::InferenceClient, open_shell_client::OpenShellClient,
};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tracing::debug;

/// Create a channel to the `OpenShell` server.
///
/// When the endpoint uses `https://`, mTLS is configured using these env vars:
/// - `OPENSHELL_TLS_CA` -- path to the CA certificate
/// - `OPENSHELL_TLS_CERT` -- path to the client certificate
/// - `OPENSHELL_TLS_KEY` -- path to the client private key
///
/// When the endpoint uses `http://`, a plaintext connection is used (for
/// deployments where TLS is disabled, e.g. behind a Cloudflare Tunnel).
async fn connect_channel(endpoint: &str) -> Result<Channel> {
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
        let ca_path = std::env::var("OPENSHELL_TLS_CA")
            .into_diagnostic()
            .wrap_err("OPENSHELL_TLS_CA is required")?;
        let cert_path = std::env::var("OPENSHELL_TLS_CERT")
            .into_diagnostic()
            .wrap_err("OPENSHELL_TLS_CERT is required")?;
        let key_path = std::env::var("OPENSHELL_TLS_KEY")
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

/// Create a channel to the `OpenShell` server (public for use by `supervisor_session`).
pub async fn connect_channel_pub(endpoint: &str) -> Result<Channel> {
    connect_channel(endpoint).await
}

/// Interceptor that injects the sandbox shared secret into every gRPC request.
///
/// The server validates this header on sandbox-to-server RPCs (`GetSandboxConfig`,
/// `GetSandboxProviderEnvironment`, etc.) instead of requiring an OIDC Bearer token.
#[derive(Clone)]
pub struct SandboxSecretInterceptor {
    secret: Option<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>,
}

impl tonic::service::Interceptor for SandboxSecretInterceptor {
    fn call(
        &mut self,
        mut req: tonic::Request<()>,
    ) -> std::result::Result<tonic::Request<()>, tonic::Status> {
        if let Some(ref val) = self.secret {
            req.metadata_mut().insert("x-sandbox-secret", val.clone());
        }
        Ok(req)
    }
}

type AuthenticatedClient = OpenShellClient<InterceptedService<Channel, SandboxSecretInterceptor>>;
type AuthenticatedInferenceClient =
    InferenceClient<InterceptedService<Channel, SandboxSecretInterceptor>>;

fn sandbox_secret_interceptor() -> SandboxSecretInterceptor {
    let secret = std::env::var("OPENSHELL_SSH_HANDSHAKE_SECRET")
        .ok()
        .and_then(|s| s.parse().ok());
    SandboxSecretInterceptor { secret }
}

/// Connect to the `OpenShell` server with sandbox secret authentication.
async fn connect(endpoint: &str) -> Result<AuthenticatedClient> {
    let channel = connect_channel(endpoint).await?;
    Ok(OpenShellClient::with_interceptor(
        channel,
        sandbox_secret_interceptor(),
    ))
}

/// Connect to the inference service with sandbox secret authentication.
async fn connect_inference(endpoint: &str) -> Result<AuthenticatedInferenceClient> {
    let channel = connect_channel(endpoint).await?;
    Ok(InferenceClient::with_interceptor(
        channel,
        sandbox_secret_interceptor(),
    ))
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
    client: &mut AuthenticatedClient,
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
    client: &mut AuthenticatedClient,
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
) -> Result<HashMap<String, String>> {
    debug!(endpoint = %endpoint, sandbox_id = %sandbox_id, "Fetching provider environment");

    let mut client = connect(endpoint).await?;

    let response = client
        .get_sandbox_provider_environment(GetSandboxProviderEnvironmentRequest {
            sandbox_id: sandbox_id.to_string(),
        })
        .await
        .into_diagnostic()?;

    Ok(response.into_inner().environment)
}

/// A reusable gRPC client for the `OpenShell` service.
///
/// Wraps a tonic channel connected once and reused for policy polling
/// and status reporting, avoiding per-request TLS handshake overhead.
#[derive(Clone)]
pub struct CachedOpenShellClient {
    client: AuthenticatedClient,
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
}

impl CachedOpenShellClient {
    pub async fn connect(endpoint: &str) -> Result<Self> {
        debug!(endpoint = %endpoint, "Connecting openshell gRPC client for policy polling");
        let client = connect(endpoint).await?;
        Ok(Self { client })
    }

    /// Get a clone of the underlying tonic client for direct RPC calls.
    pub fn raw_client(&self) -> AuthenticatedClient {
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
        })
    }

    /// Submit denial summaries for policy analysis.
    pub async fn submit_policy_analysis(
        &self,
        sandbox_name: &str,
        summaries: Vec<DenialSummary>,
        proposed_chunks: Vec<openshell_core::proto::PolicyChunk>,
        analysis_mode: &str,
    ) -> Result<()> {
        self.client
            .clone()
            .submit_policy_analysis(SubmitPolicyAnalysisRequest {
                name: sandbox_name.to_string(),
                summaries,
                proposed_chunks,
                analysis_mode: analysis_mode.to_string(),
            })
            .await
            .into_diagnostic()?;

        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_secret_interceptor_injects_header() {
        let mut interceptor = SandboxSecretInterceptor {
            secret: Some("test-secret".parse().unwrap()),
        };
        let request =
            tonic::service::Interceptor::call(&mut interceptor, tonic::Request::new(())).unwrap();
        assert_eq!(
            request
                .metadata()
                .get("x-sandbox-secret")
                .and_then(|v| v.to_str().ok()),
            Some("test-secret")
        );
    }

    #[test]
    fn sandbox_secret_interceptor_is_noop_without_secret() {
        let mut interceptor = SandboxSecretInterceptor { secret: None };
        let request =
            tonic::service::Interceptor::call(&mut interceptor, tonic::Request::new(())).unwrap();
        assert!(request.metadata().get("x-sandbox-secret").is_none());
    }
}
