pub mod image;

mod constants;
mod docker;
mod kubeconfig;
mod metadata;
mod mtls;
mod paths;
mod push;
mod runtime;

use bollard::Docker;
use miette::{IntoDiagnostic, Result};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::constants::{DEFAULT_IMAGE_NAME, container_name, volume_name};
use crate::docker::{
    check_existing_cluster, create_ssh_docker_client, destroy_cluster_resources, ensure_container,
    ensure_image, ensure_network, ensure_volume, start_container, stop_container,
};
use crate::kubeconfig::{rewrite_kubeconfig, rewrite_kubeconfig_remote, store_kubeconfig};
use crate::metadata::{
    create_cluster_metadata, extract_host_from_ssh_destination, local_gateway_host,
    resolve_ssh_hostname,
};
use crate::mtls::fetch_and_store_cli_mtls;
use crate::runtime::{
    clean_stale_nodes, restart_navigator_deployment, wait_for_cluster_ready, wait_for_kubeconfig,
};

pub use crate::docker::ExistingClusterInfo;
pub use crate::kubeconfig::{
    default_local_kubeconfig_path, print_kubeconfig, stored_kubeconfig_path,
    update_local_kubeconfig,
};
pub use crate::metadata::{
    ClusterMetadata, clear_active_cluster, get_cluster_metadata, list_clusters,
    load_active_cluster, load_cluster_metadata, remove_cluster_metadata, save_active_cluster,
    store_cluster_metadata,
};

/// Options for remote SSH deployment.
#[derive(Debug, Clone)]
pub struct RemoteOptions {
    /// SSH destination in the form `user@hostname` or `ssh://user@hostname`.
    pub destination: String,
    /// Path to SSH private key. If None, uses SSH agent.
    pub ssh_key: Option<String>,
}

impl RemoteOptions {
    /// Create new remote options with the given SSH destination.
    pub fn new(destination: impl Into<String>) -> Self {
        Self {
            destination: destination.into(),
            ssh_key: None,
        }
    }

    /// Set the SSH key path.
    #[must_use]
    pub fn with_ssh_key(mut self, path: impl Into<String>) -> Self {
        self.ssh_key = Some(path.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct DeployOptions {
    pub name: String,
    pub image_ref: Option<String>,
    /// Remote deployment options. If None, deploys locally.
    pub remote: Option<RemoteOptions>,
}

impl DeployOptions {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            image_ref: None,
            remote: None,
        }
    }

    /// Set remote deployment options.
    #[must_use]
    pub fn with_remote(mut self, remote: RemoteOptions) -> Self {
        self.remote = Some(remote);
        self
    }
}

#[derive(Debug, Clone)]
pub struct ClusterHandle {
    name: String,
    kubeconfig_path: PathBuf,
    metadata: ClusterMetadata,
    docker: Docker,
}

impl ClusterHandle {
    pub fn kubeconfig_path(&self) -> &Path {
        &self.kubeconfig_path
    }

    /// Get the cluster metadata.
    pub fn metadata(&self) -> &ClusterMetadata {
        &self.metadata
    }

    /// Get the gateway endpoint URL.
    pub fn gateway_endpoint(&self) -> &str {
        &self.metadata.gateway_endpoint
    }

    pub async fn stop(&self) -> Result<()> {
        stop_container(&self.docker, &container_name(&self.name)).await
    }

    pub async fn destroy(&self) -> Result<()> {
        destroy_cluster_resources(&self.docker, &self.name, &self.kubeconfig_path).await
    }
}

/// Check whether a cluster with the given name already has resources deployed.
///
/// Returns `None` if no existing cluster resources are found, or
/// `Some(ExistingClusterInfo)` with details about what exists.
pub async fn check_existing_deployment(
    name: &str,
    remote: Option<&RemoteOptions>,
) -> Result<Option<ExistingClusterInfo>> {
    let docker = match remote {
        Some(remote_opts) => create_ssh_docker_client(remote_opts)?,
        None => Docker::connect_with_local_defaults().into_diagnostic()?,
    };
    check_existing_cluster(&docker, name).await
}

pub async fn deploy_cluster(options: DeployOptions) -> Result<ClusterHandle> {
    deploy_cluster_with_logs(options, |_| {}).await
}

pub async fn deploy_cluster_with_logs<F>(options: DeployOptions, on_log: F) -> Result<ClusterHandle>
where
    F: FnMut(String) + Send + 'static,
{
    let name = options.name;
    let image_ref = options.image_ref.unwrap_or_else(default_cluster_image_ref);
    let kubeconfig_path = stored_kubeconfig_path(&name)?;

    // Wrap on_log in Arc<Mutex<>> so we can share it with pull_remote_image
    // which needs a 'static callback for the bollard streaming pull.
    let on_log = Arc::new(Mutex::new(on_log));

    // Helper to call on_log from the shared reference
    let log = |msg: String| {
        if let Ok(mut f) = on_log.lock() {
            f(msg);
        }
    };

    // Create Docker client based on deployment mode
    let (target_docker, remote_opts) = match &options.remote {
        Some(remote_opts) => {
            let remote = create_ssh_docker_client(remote_opts)?;
            (remote, Some(remote_opts.clone()))
        }
        None => (
            Docker::connect_with_local_defaults().into_diagnostic()?,
            None,
        ),
    };

    // Ensure the image is available on the target Docker daemon
    if remote_opts.is_some() {
        log("[status] Pulling cluster image on remote host".to_string());
        let on_log_clone = Arc::clone(&on_log);
        let progress_cb = move |msg: String| {
            if let Ok(mut f) = on_log_clone.lock() {
                f(msg);
            }
        };
        image::pull_remote_image(&target_docker, &image_ref, progress_cb).await?;
    } else {
        // Local deployment: ensure image exists (pull if needed)
        log("[status] Ensuring cluster image is available".to_string());
        ensure_image(&target_docker, &image_ref).await?;
    }

    // All subsequent operations use the target Docker (remote or local)
    log("[status] Creating cluster network".to_string());
    ensure_network(&target_docker).await?;
    log("[status] Preparing cluster volume".to_string());
    ensure_volume(&target_docker, &volume_name(&name)).await?;

    // Compute extra TLS SANs for remote deployments so the gateway and k3s
    // API server certificates include the remote host's IP/hostname.
    // Also determine the SSH gateway host so the server returns the correct
    // address to CLI clients for SSH proxy CONNECT requests.
    let (extra_sans, ssh_gateway_host): (Vec<String>, Option<String>) =
        remote_opts.as_ref().map_or_else(
            || {
                let sans = local_gateway_host().into_iter().collect();
                (sans, None)
            },
            |opts| {
                let ssh_host = extract_host_from_ssh_destination(&opts.destination);
                let resolved = resolve_ssh_hostname(&ssh_host);
                // Include both the SSH alias and resolved IP if they differ, so the
                // certificate covers both names.
                let mut sans = vec![resolved.clone()];
                if ssh_host != resolved {
                    sans.push(ssh_host);
                }
                (sans, Some(resolved))
            },
        );

    log("[status] Creating cluster container".to_string());
    ensure_container(
        &target_docker,
        &name,
        &image_ref,
        &extra_sans,
        ssh_gateway_host.as_deref(),
    )
    .await?;
    log("[status] Starting cluster container".to_string());
    start_container(&target_docker, &name).await?;

    log("[status] Waiting for kubeconfig".to_string());
    let raw_kubeconfig = wait_for_kubeconfig(&target_docker, &name).await?;

    // Rewrite kubeconfig based on deployment mode
    let rewritten = remote_opts.as_ref().map_or_else(
        || rewrite_kubeconfig(&raw_kubeconfig, &name),
        |opts| rewrite_kubeconfig_remote(&raw_kubeconfig, &name, &opts.destination),
    );
    log("[status] Writing kubeconfig".to_string());
    store_kubeconfig(&kubeconfig_path, &rewritten)?;
    // Clean up stale k3s nodes left over from previous container instances that
    // used the same persistent volume. Without this, pods remain scheduled on
    // NotReady ghost nodes and the health check will time out.
    log("[status] Cleaning stale nodes".to_string());
    match clean_stale_nodes(&target_docker, &name).await {
        Ok(0) => {}
        Ok(n) => log(format!("[status] Removed {n} stale node(s)")),
        Err(err) => {
            tracing::debug!("stale node cleanup failed (non-fatal): {err}");
        }
    }

    // Push locally-built component images into the k3s containerd runtime.
    // This is the "push" path for local development — images are exported from
    // the local Docker daemon and streamed into the cluster's containerd so
    // k3s can resolve them without pulling from the remote registry.
    if remote_opts.is_none()
        && let Ok(push_images_str) = std::env::var("NAVIGATOR_PUSH_IMAGES")
    {
        let images: Vec<&str> = push_images_str
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if !images.is_empty() {
            log(format!(
                "[status] Push mode: importing {} local image(s) into cluster",
                images.len()
            ));
            let local_docker = Docker::connect_with_local_defaults().into_diagnostic()?;
            let container = container_name(&name);
            let on_log_ref = Arc::clone(&on_log);
            let mut push_log = move |msg: String| {
                if let Ok(mut f) = on_log_ref.lock() {
                    f(msg);
                }
            };
            push::push_local_images(
                &local_docker,
                &target_docker,
                &container,
                &images,
                &mut push_log,
            )
            .await?;

            log("[status] Restarting navigator deployment to pick up imported images".to_string());
            restart_navigator_deployment(&target_docker, &name).await?;
        }
    }

    log("[status] Waiting for control plane health checks".to_string());
    {
        // Create a short-lived closure that locks on each call rather than holding
        // the MutexGuard across await points.
        let on_log_ref = Arc::clone(&on_log);
        let mut cluster_log = move |msg: String| {
            if let Ok(mut f) = on_log_ref.lock() {
                f(msg);
            }
        };
        wait_for_cluster_ready(&target_docker, &name, &mut cluster_log).await?;
    }
    log("[status] Fetching mTLS credentials".to_string());
    fetch_and_store_cli_mtls(&target_docker, &name).await?;

    // Create and store cluster metadata
    log("[status] Persisting cluster metadata".to_string());
    let metadata = create_cluster_metadata(&name, remote_opts.as_ref());
    store_cluster_metadata(&name, &metadata)?;

    Ok(ClusterHandle {
        name,
        kubeconfig_path,
        metadata,
        docker: target_docker,
    })
}

/// Get a handle to an existing cluster.
///
/// For local clusters, pass `None` for remote options.
/// For remote clusters, pass the same `RemoteOptions` used during deployment.
pub fn cluster_handle(name: &str, remote: Option<&RemoteOptions>) -> Result<ClusterHandle> {
    let docker = match remote {
        Some(remote_opts) => create_ssh_docker_client(remote_opts)?,
        None => Docker::connect_with_local_defaults().into_diagnostic()?,
    };
    let kubeconfig_path = stored_kubeconfig_path(name)?;
    // Try to load existing metadata, fall back to creating new metadata
    let metadata =
        load_cluster_metadata(name).unwrap_or_else(|_| create_cluster_metadata(name, remote));
    Ok(ClusterHandle {
        name: name.to_string(),
        kubeconfig_path,
        metadata,
        docker,
    })
}

pub async fn ensure_cluster_image(version: &str) -> Result<String> {
    let docker = Docker::connect_with_local_defaults().into_diagnostic()?;
    let image_ref = format!("{DEFAULT_IMAGE_NAME}:{version}");
    ensure_image(&docker, &image_ref).await?;
    Ok(image_ref)
}

fn default_cluster_image_ref() -> String {
    if let Ok(image) = std::env::var("NAVIGATOR_CLUSTER_IMAGE")
        && !image.trim().is_empty()
    {
        return image;
    }
    let tag = std::env::var("IMAGE_TAG")
        .ok()
        .filter(|val| !val.trim().is_empty())
        .unwrap_or_else(|| "dev".to_string());
    format!("{DEFAULT_IMAGE_NAME}:{tag}")
}
