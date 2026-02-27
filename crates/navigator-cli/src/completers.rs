use std::ffi::OsStr;
use std::future::Future;
use std::time::Duration;

use clap_complete::engine::CompletionCandidate;
use navigator_bootstrap::{list_clusters, load_active_cluster, load_cluster_metadata};
use navigator_core::proto::navigator_client::NavigatorClient;
use navigator_core::proto::{ListProvidersRequest, ListSandboxesRequest};
use tonic::transport::{Channel, Endpoint};

use crate::tls::{TlsOptions, build_tonic_tls_config, require_tls_materials};

/// Complete cluster names from local metadata files (no network call).
pub fn complete_cluster_names(_prefix: &OsStr) -> Vec<CompletionCandidate> {
    let Ok(clusters) = list_clusters() else {
        return Vec::new();
    };
    clusters
        .into_iter()
        .map(|c| CompletionCandidate::new(c.name))
        .collect()
}

/// Complete sandbox names by querying the active cluster's gateway.
pub fn complete_sandbox_names(_prefix: &OsStr) -> Vec<CompletionCandidate> {
    blocking_complete(async {
        let (endpoint, cluster_name) = resolve_active_cluster()?;
        let mut client = completion_grpc_client(&endpoint, &cluster_name).await?;
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

/// Complete provider names by querying the active cluster's gateway.
pub fn complete_provider_names(_prefix: &OsStr) -> Vec<CompletionCandidate> {
    blocking_complete(async {
        let (endpoint, cluster_name) = resolve_active_cluster()?;
        let mut client = completion_grpc_client(&endpoint, &cluster_name).await?;
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

fn resolve_active_cluster() -> Option<(String, String)> {
    let name = std::env::var("NAVIGATOR_CLUSTER")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(load_active_cluster)?;
    let metadata = load_cluster_metadata(&name).ok()?;
    Some((metadata.gateway_endpoint, name))
}

async fn completion_grpc_client(
    server: &str,
    cluster_name: &str,
) -> Option<NavigatorClient<Channel>> {
    let tls_opts = TlsOptions::new(None, None, None).with_cluster_name(cluster_name);
    let materials = require_tls_materials(server, &tls_opts).ok()?;
    let tls_config = build_tonic_tls_config(&materials);
    let endpoint = Endpoint::from_shared(server.to_string())
        .ok()?
        .connect_timeout(Duration::from_secs(2))
        .tls_config(tls_config)
        .ok()?;
    let channel = endpoint.connect().await.ok()?;
    Some(NavigatorClient::new(channel))
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
#[allow(unsafe_code)]
mod tests {
    use super::*;

    #[test]
    fn cluster_completer_returns_empty_when_no_config() {
        let temp = tempfile::tempdir().unwrap();
        // SAFETY: test-only; tests run with --test-threads=1 or are isolated.
        unsafe { std::env::set_var("XDG_CONFIG_HOME", temp.path()) };
        let result = complete_cluster_names(OsStr::new(""));
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
        assert!(result.is_empty());
    }

    #[test]
    fn sandbox_completer_returns_empty_when_no_active_cluster() {
        unsafe { std::env::remove_var("NAVIGATOR_CLUSTER") };
        let temp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("XDG_CONFIG_HOME", temp.path()) };
        let result = complete_sandbox_names(OsStr::new(""));
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
        assert!(result.is_empty());
    }

    #[test]
    fn provider_completer_returns_empty_when_no_active_cluster() {
        unsafe { std::env::remove_var("NAVIGATOR_CLUSTER") };
        let temp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("XDG_CONFIG_HOME", temp.path()) };
        let result = complete_provider_names(OsStr::new(""));
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
        assert!(result.is_empty());
    }
}
