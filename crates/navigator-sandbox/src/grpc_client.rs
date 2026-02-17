//! gRPC client for fetching sandbox policy and provider environment from Navigator server.

use miette::{IntoDiagnostic, Result};
use navigator_core::proto::{
    GetSandboxPolicyRequest, GetSandboxProviderEnvironmentRequest,
    SandboxPolicy as ProtoSandboxPolicy, navigator_client::NavigatorClient,
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
