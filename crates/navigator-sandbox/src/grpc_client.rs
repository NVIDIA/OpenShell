// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! gRPC client for fetching sandbox policy, provider environment, and inference
//! route bundles from Navigator server.

use std::collections::HashMap;
use std::time::Duration;

use miette::{IntoDiagnostic, Result, WrapErr};
use navigator_core::proto::{
    GetSandboxInferenceBundleRequest, GetSandboxInferenceBundleResponse, GetSandboxPolicyRequest,
    GetSandboxProviderEnvironmentRequest, PolicyStatus, ReportPolicyStatusRequest,
    SandboxPolicy as ProtoSandboxPolicy, inference_client::InferenceClient,
    navigator_client::NavigatorClient,
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tracing::debug;

/// Create an mTLS-configured channel to the Navigator server.
///
/// TLS materials are read from the environment variables:
/// - `NAVIGATOR_TLS_CA` -- path to the CA certificate
/// - `NAVIGATOR_TLS_CERT` -- path to the client certificate
/// - `NAVIGATOR_TLS_KEY` -- path to the client private key
async fn connect_channel(endpoint: &str) -> Result<Channel> {
    let mut ep = Endpoint::from_shared(endpoint.to_string())
        .into_diagnostic()
        .wrap_err("invalid gRPC endpoint")?
        .connect_timeout(Duration::from_secs(10))
        .http2_keep_alive_interval(Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .keep_alive_timeout(Duration::from_secs(20));

    let ca_path = std::env::var("NAVIGATOR_TLS_CA")
        .into_diagnostic()
        .wrap_err("NAVIGATOR_TLS_CA is required")?;
    let cert_path = std::env::var("NAVIGATOR_TLS_CERT")
        .into_diagnostic()
        .wrap_err("NAVIGATOR_TLS_CERT is required")?;
    let key_path = std::env::var("NAVIGATOR_TLS_KEY")
        .into_diagnostic()
        .wrap_err("NAVIGATOR_TLS_KEY is required")?;

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

    ep.connect()
        .await
        .into_diagnostic()
        .wrap_err("failed to connect to Navigator server")
}

/// Connect to the Navigator server using mTLS.
async fn connect(endpoint: &str) -> Result<NavigatorClient<Channel>> {
    let channel = connect_channel(endpoint).await?;
    Ok(NavigatorClient::new(channel))
}

/// Fetch sandbox policy from Navigator server via gRPC.
pub async fn fetch_policy(endpoint: &str, sandbox_id: &str) -> Result<ProtoSandboxPolicy> {
    debug!(endpoint = %endpoint, sandbox_id = %sandbox_id, "Connecting to Navigator server");

    let mut client = connect(endpoint).await?;

    debug!("Connected, fetching sandbox policy");

    let response = client
        .get_sandbox_policy(GetSandboxPolicyRequest {
            sandbox_id: sandbox_id.to_string(),
        })
        .await
        .into_diagnostic()?;

    response
        .into_inner()
        .policy
        .ok_or_else(|| miette::miette!("Server returned empty policy"))
}

/// Fetch provider environment variables for a sandbox from Navigator server via gRPC.
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

/// A reusable gRPC client for the Navigator service.
///
/// Wraps a tonic channel connected once and reused for policy polling
/// and status reporting, avoiding per-request TLS handshake overhead.
#[derive(Clone)]
pub struct CachedNavigatorClient {
    client: NavigatorClient<Channel>,
}

/// Policy poll result returned by [`CachedNavigatorClient::poll_policy`].
pub struct PolicyPollResult {
    pub policy: ProtoSandboxPolicy,
    pub version: u32,
    pub policy_hash: String,
}

impl CachedNavigatorClient {
    pub async fn connect(endpoint: &str) -> Result<Self> {
        debug!(endpoint = %endpoint, "Connecting navigator gRPC client for policy polling");
        let channel = connect_channel(endpoint).await?;
        let client = NavigatorClient::new(channel);
        Ok(Self { client })
    }

    /// Get a clone of the underlying tonic client for direct RPC calls.
    pub fn raw_client(&self) -> NavigatorClient<Channel> {
        self.client.clone()
    }

    /// Poll for the current sandbox policy version.
    pub async fn poll_policy(&self, sandbox_id: &str) -> Result<PolicyPollResult> {
        let response = self
            .client
            .clone()
            .get_sandbox_policy(GetSandboxPolicyRequest {
                sandbox_id: sandbox_id.to_string(),
            })
            .await
            .into_diagnostic()?;

        let inner = response.into_inner();
        let policy = inner
            .policy
            .ok_or_else(|| miette::miette!("Server returned empty policy"))?;

        Ok(PolicyPollResult {
            policy,
            version: inner.version,
            policy_hash: inner.policy_hash,
        })
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

/// Fetch the pre-filtered inference route bundle for a sandbox.
pub async fn fetch_inference_bundle(
    endpoint: &str,
    sandbox_id: &str,
) -> Result<GetSandboxInferenceBundleResponse> {
    debug!(endpoint = %endpoint, sandbox_id = %sandbox_id, "Fetching inference route bundle");

    let channel = connect_channel(endpoint).await?;
    let mut client = InferenceClient::new(channel);

    let response = client
        .get_sandbox_inference_bundle(GetSandboxInferenceBundleRequest {
            sandbox_id: sandbox_id.to_string(),
        })
        .await
        .into_diagnostic()?;

    Ok(response.into_inner())
}
