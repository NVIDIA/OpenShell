//! gRPC client for fetching sandbox policy and provider environment from Navigator server.

use miette::{IntoDiagnostic, Result};
use navigator_core::proto::{
    GetSandboxPolicyRequest, GetSandboxProviderEnvironmentRequest, HttpHeader,
    ProxyInferenceRequest, ProxyInferenceResponse, SandboxPolicy as ProtoSandboxPolicy,
    inference_client::InferenceClient, navigator_client::NavigatorClient,
};
use std::collections::HashMap;
use tracing::debug;

/// Fetch sandbox policy from Navigator server via gRPC.
///
/// # Arguments
///
/// * `endpoint` - The Navigator server gRPC endpoint (e.g., `http://navigator:8080`)
/// * `sandbox_id` - The sandbox ID to fetch policy for
///
/// # Errors
///
/// Returns an error if the gRPC connection fails or the sandbox is not found.
pub async fn fetch_policy(endpoint: &str, sandbox_id: &str) -> Result<ProtoSandboxPolicy> {
    debug!(endpoint = %endpoint, sandbox_id = %sandbox_id, "Connecting to Navigator server");

    let mut client = NavigatorClient::connect(endpoint.to_string())
        .await
        .into_diagnostic()?;

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
/// * `endpoint` - The Navigator server gRPC endpoint (e.g., `http://navigator:8080`)
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

    let mut client = NavigatorClient::connect(endpoint.to_string())
        .await
        .into_diagnostic()?;

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
    client: InferenceClient<tonic::transport::Channel>,
}

impl CachedInferenceClient {
    pub async fn connect(endpoint: &str) -> Result<Self> {
        debug!(endpoint = %endpoint, "Connecting inference gRPC client");
        let client = InferenceClient::connect(endpoint.to_string())
            .await
            .into_diagnostic()?;
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
