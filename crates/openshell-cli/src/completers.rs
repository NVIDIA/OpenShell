// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::future::Future;

use clap_complete::engine::CompletionCandidate;
use openshell_bootstrap::edge_token::load_edge_token;
use openshell_bootstrap::oidc_token::{is_token_expired, load_oidc_token, store_oidc_token};
use openshell_bootstrap::{list_gateways, load_active_gateway, load_gateway_metadata};
use openshell_core::ObjectName;
use openshell_core::auth::EdgeAuthInterceptor;
use openshell_core::proto::open_shell_client::OpenShellClient;
use openshell_core::proto::{ListProvidersRequest, ListSandboxesRequest};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

use crate::oidc_auth::oidc_refresh_token;
use crate::tls::{TlsOptions, build_channel};

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
                label_selector: String::new(),
            })
            .await
            .ok()?;
        Some(
            response
                .into_inner()
                .sandboxes
                .into_iter()
                .map(|s| CompletionCandidate::new(s.object_name()))
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
                .map(|p| CompletionCandidate::new(p.object_name()))
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
) -> Option<OpenShellClient<InterceptedService<Channel, EdgeAuthInterceptor>>> {
    let mut tls_opts = TlsOptions::default().with_gateway_name(gateway_name);
    tls_opts.gateway_insecure = std::env::var("OPENSHELL_GATEWAY_INSECURE")
        .is_ok_and(|v| !v.is_empty() && v != "0" && v != "false");

    if let Ok(meta) = load_gateway_metadata(gateway_name) {
        match meta.auth_mode.as_deref() {
            Some("oidc") => {
                if let Some(bundle) = load_oidc_token(gateway_name) {
                    if is_token_expired(&bundle) {
                        match oidc_refresh_token(&bundle, tls_opts.gateway_insecure).await {
                            Ok(refreshed) => {
                                let _ = store_oidc_token(gateway_name, &refreshed);
                                tls_opts.oidc_token = Some(refreshed.access_token);
                            }
                            Err(_) => {
                                tls_opts.oidc_token = Some(bundle.access_token);
                            }
                        }
                    } else {
                        tls_opts.oidc_token = Some(bundle.access_token);
                    }
                }
            }
            Some("cloudflare_jwt") => {
                if let Some(token) = load_edge_token(gateway_name) {
                    tls_opts.edge_token = Some(token);
                }
            }
            _ => {}
        }
    }

    let channel = build_channel(server, &tls_opts).await.ok()?;
    let interceptor = EdgeAuthInterceptor::new(
        tls_opts.oidc_token.as_deref(),
        tls_opts.edge_token.as_deref(),
    )
    .ok()?;
    Some(OpenShellClient::with_interceptor(channel, interceptor))
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
                    auth_mode: Some("cloudflare_jwt".to_string()),
                    ..Default::default()
                },
            )
            .unwrap();

            let result = complete_gateway_names(OsStr::new("a"));
            assert!(
                result
                    .iter()
                    .any(|candidate| candidate.get_value().to_string_lossy() == "alpha")
            );
        });
    }
}
