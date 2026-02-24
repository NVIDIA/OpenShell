//! gRPC client for fetching sandbox policy and provider environment from Navigator server.

use miette::{IntoDiagnostic, Result, WrapErr};
use navigator_core::proto::{
    GetSandboxPolicyRequest, GetSandboxProviderEnvironmentRequest, HttpHeader,
    ProxyInferenceRequest, ProxyInferenceResponse, SandboxPolicy as ProtoSandboxPolicy,
    inference_client::InferenceClient, navigator_client::NavigatorClient,
};
use std::collections::HashMap;
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
        .wrap_err("invalid gRPC endpoint")?;

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
///
/// # Arguments
///
/// * `endpoint` - The Navigator server gRPC endpoint (e.g., `https://navigator:8080`)
/// * `sandbox_id` - The sandbox ID to fetch policy for
///
/// # Errors
///
/// Returns an error if the gRPC connection fails or the sandbox is not found.
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
///
/// # Arguments
///
/// * `endpoint` - The Navigator server gRPC endpoint (e.g., `https://navigator:8080`)
/// * `sandbox_id` - The sandbox ID to fetch provider environment for
///
/// # Errors
///
/// Returns an error if the gRPC connection fails or the sandbox is not found.
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

/// A reusable gRPC client for the inference service.
///
/// Wraps a tonic channel that is connected once and reused for all
/// subsequent `ProxyInference` calls, avoiding per-request connection overhead.
#[derive(Clone)]
pub struct CachedInferenceClient {
    client: InferenceClient<Channel>,
}

impl CachedInferenceClient {
    pub async fn connect(endpoint: &str) -> Result<Self> {
        debug!(endpoint = %endpoint, "Connecting inference gRPC client");
        let channel = connect_channel(endpoint).await?;
        let client = InferenceClient::new(channel);
        Ok(Self { client })
    }

    /// Forward an intercepted inference request to the gateway via gRPC.
    pub async fn proxy_inference(
        &self,
        sandbox_id: &str,
        source_protocol: &str,
        http_method: &str,
        http_path: &str,
        http_headers: Vec<(String, String)>,
        http_body: Vec<u8>,
    ) -> Result<ProxyInferenceResponse> {
        debug!(
            sandbox_id = %sandbox_id,
            source_protocol = %source_protocol,
            method = %http_method,
            path = %http_path,
            "Forwarding inference request to gateway"
        );

        let headers: Vec<HttpHeader> = http_headers
            .into_iter()
            .map(|(name, value)| HttpHeader { name, value })
            .collect();

        let response = self
            .client
            .clone()
            .proxy_inference(ProxyInferenceRequest {
                sandbox_id: sandbox_id.to_string(),
                source_protocol: source_protocol.to_string(),
                http_method: http_method.to_string(),
                http_path: http_path.to_string(),
                http_headers: headers,
                http_body,
            })
            .await
            .into_diagnostic()?;

        Ok(response.into_inner())
    }
}
