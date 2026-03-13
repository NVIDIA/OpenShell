// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::future::Future;
use std::time::Duration;

use clap_complete::engine::CompletionCandidate;
use openshell_bootstrap::{list_gateways, load_active_gateway, load_gateway_metadata};
use openshell_core::proto::open_shell_client::OpenShellClient;
use openshell_core::proto::{ListProvidersRequest, ListSandboxesRequest};
use tonic::transport::{Channel, Endpoint};

use crate::tls::{TlsOptions, build_tonic_tls_config, require_tls_materials};

/// Complete gateway names from local metadata files (no network call).
pub fn complete_gateway_names(_prefix: &OsStr) -> Vec<CompletionCandidate> {
    let Ok(gateways) = list_gateways() else {
        return Vec::new();
    };
    gateways
        .into_iter()
        .map(|g| CompletionCandidate::new(g.name))
        .collect()
}

/// Complete sandbox names by querying the active gateway.
pub fn complete_sandbox_names(_prefix: &OsStr) -> Vec<CompletionCandidate> {
    blocking_complete(async {
        let (endpoint, gateway_name) = resolve_active_gateway()?;
        let mut client = completion_grpc_client(&endpoint, &gateway_name).await?;
        let response = client
            .list_sandboxes(ListSandboxesRequest {
                limit: 200,
                offset: 0,
            })
            .await
            .ok()?;
        Some(
            response
                .into_inner()
                .sandboxes
                .into_iter()
                .map(|s| CompletionCandidate::new(s.name))
                .collect(),
        )
    })
}

/// Complete provider names by querying the active gateway.
pub fn complete_provider_names(_prefix: &OsStr) -> Vec<CompletionCandidate> {
    blocking_complete(async {
        let (endpoint, gateway_name) = resolve_active_gateway()?;
        let mut client = completion_grpc_client(&endpoint, &gateway_name).await?;
        let response = client
            .list_providers(ListProvidersRequest {
                limit: 200,
                offset: 0,
            })
            .await
            .ok()?;
        Some(
            response
                .into_inner()
                .providers
                .into_iter()
                .map(|p| CompletionCandidate::new(p.name))
                .collect(),
        )
    })
}

fn resolve_active_gateway() -> Option<(String, String)> {
    let name = std::env::var("OPENSHELL_GATEWAY")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(load_active_gateway)?;
    let metadata = load_gateway_metadata(&name).ok()?;
    Some((metadata.gateway_endpoint, name))
}

async fn completion_grpc_client(
    server: &str,
    gateway_name: &str,
) -> Option<OpenShellClient<Channel>> {
    let tls_opts = TlsOptions::default().with_gateway_name(gateway_name);
    let materials = require_tls_materials(server, &tls_opts).ok()?;
    let tls_config = build_tonic_tls_config(&materials);
    let endpoint = Endpoint::from_shared(server.to_string())
        .ok()?
        .connect_timeout(Duration::from_secs(2))
        .tls_config(tls_config)
        .ok()?;
    let channel = endpoint.connect().await.ok()?;
    Some(OpenShellClient::new(channel))
}

/// Run an async future on a dedicated thread to avoid nested tokio runtime panics.
///
/// `#[tokio::main]` creates a runtime, and `CompleteEnv::complete()` runs synchronously
/// inside its `block_on`. Creating another runtime on the same thread would panic, so
/// we spawn a new OS thread with its own single-threaded runtime.
fn blocking_complete<F>(future: F) -> Vec<CompletionCandidate>
where
    F: Future<Output = Option<Vec<CompletionCandidate>>> + Send + 'static,
{
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?;
        rt.block_on(future)
    })
    .join()
    .ok()
    .flatten()
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TEST_ENV_LOCK;
    use openshell_bootstrap::{GatewayMetadata, store_gateway_metadata};
    use temp_env::with_vars;

    fn with_isolated_cli_env<F: FnOnce()>(tmp: &std::path::Path, f: F) {
        let _guard = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tmp.to_string_lossy().into_owned();
        with_vars(
            [
                ("XDG_CONFIG_HOME", Some(tmp.as_str())),
                ("OPENSHELL_GATEWAY", None::<&str>),
            ],
            f,
        );
    }

    #[test]
    fn gateway_completer_returns_empty_when_no_config() {
        let temp = tempfile::tempdir().unwrap();
        with_isolated_cli_env(temp.path(), || {
            let result = complete_gateway_names(OsStr::new(""));
            assert!(result.is_empty());
        });
    }

    #[test]
    fn sandbox_completer_returns_empty_when_no_active_gateway() {
        let temp = tempfile::tempdir().unwrap();
        with_isolated_cli_env(temp.path(), || {
            let result = complete_sandbox_names(OsStr::new(""));
            assert!(result.is_empty());
        });
    }

    #[test]
    fn provider_completer_returns_empty_when_no_active_gateway() {
        let temp = tempfile::tempdir().unwrap();
        with_isolated_cli_env(temp.path(), || {
            let result = complete_provider_names(OsStr::new(""));
            assert!(result.is_empty());
        });
    }

    #[test]
    fn gateway_completer_returns_registered_gateways() {
        let temp = tempfile::tempdir().unwrap();
        with_isolated_cli_env(temp.path(), || {
            store_gateway_metadata(
                "alpha",
                &GatewayMetadata {
                    name: "alpha".to_string(),
                    gateway_endpoint: "https://alpha.example.com".to_string(),
                    is_remote: true,
                    gateway_port: 0,
                    remote_host: None,
                    resolved_host: None,
                    auth_mode: Some("cloudflare_jwt".to_string()),
                    edge_team_domain: None,
                    edge_auth_url: None,
                },
            )
            .unwrap();

            let result = complete_gateway_names(OsStr::new("a"));
            let names: Vec<String> = result
                .iter()
                .map(|candidate| candidate.get_value().to_string_lossy().into_owned())
                .collect();
            assert!(names.contains(&"alpha".to_string()));
        });
    }
}
