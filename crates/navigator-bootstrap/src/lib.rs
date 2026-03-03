pub mod build;
pub mod image;

mod constants;
mod docker;
mod kubeconfig;
mod metadata;
mod mtls;
mod paths;
mod pki;
pub(crate) mod push;
mod runtime;

use bollard::Docker;
use miette::{IntoDiagnostic, Result};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::constants::{
    CLIENT_TLS_SECRET_NAME, SERVER_CLIENT_CA_SECRET_NAME, SERVER_TLS_SECRET_NAME, container_name,
    volume_name,
};
use crate::docker::{
    check_existing_cluster, create_ssh_docker_client, destroy_cluster_resources, ensure_container,
    ensure_image, ensure_network, ensure_volume, start_container, stop_container,
};
use crate::kubeconfig::{rewrite_kubeconfig, rewrite_kubeconfig_remote, store_kubeconfig};
use crate::metadata::{
    create_cluster_metadata, create_cluster_metadata_with_host, extract_host_from_ssh_destination,
    local_gateway_host, resolve_ssh_hostname,
};
use crate::mtls::store_pki_bundle;
use crate::pki::generate_pki;
use crate::runtime::{
    clean_stale_nodes, exec_capture_with_exit, fetch_recent_logs, navigator_workload_exists,
    restart_navigator_deployment, wait_for_cluster_ready, wait_for_kubeconfig,
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

/// Default host port that maps to the k3s `NodePort` (30051) for the gateway.
pub const DEFAULT_GATEWAY_PORT: u16 = 8080;

/// Find a random available TCP port by binding to port 0.
///
/// Binds to `127.0.0.1:0` and returns the OS-assigned port.
pub fn pick_available_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").into_diagnostic()?;
    let port = listener.local_addr().into_diagnostic()?.port();
    Ok(port)
}

#[derive(Debug, Clone)]
pub struct DeployOptions {
    pub name: String,
    pub image_ref: Option<String>,
    /// Remote deployment options. If None, deploys locally.
    pub remote: Option<RemoteOptions>,
    /// Host port to map to the gateway `NodePort` (30051). Defaults to 8080.
    pub port: u16,
    /// Override the gateway host advertised in cluster metadata and passed to
    /// the server. When set, the metadata will use this host instead of
    /// `127.0.0.1` and the container will receive `SSH_GATEWAY_HOST`.
    /// Useful in CI where `127.0.0.1` is not reachable from the test runner
    /// (e.g., `host.docker.internal`).
    pub gateway_host: Option<String>,
    /// Host port to expose the k3s Kubernetes control plane on.
    /// When `None`, the control plane port (6443) is not exposed on the host,
    /// allowing multiple clusters to run simultaneously without port conflicts.
    pub kube_port: Option<u16>,
}

impl DeployOptions {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            image_ref: None,
            remote: None,
            port: DEFAULT_GATEWAY_PORT,
            gateway_host: None,
            kube_port: None,
        }
    }

    /// Set remote deployment options.
    #[must_use]
    pub fn with_remote(mut self, remote: RemoteOptions) -> Self {
        self.remote = Some(remote);
        self
    }

    /// Set the host port for the gateway.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Override the gateway host advertised in cluster metadata.
    #[must_use]
    pub fn with_gateway_host(mut self, host: impl Into<String>) -> Self {
        self.gateway_host = Some(host.into());
        self
    }

    /// Set the host port for the k3s Kubernetes control plane.
    /// When set, the control plane is accessible via `kubectl` at this port.
    #[must_use]
    pub fn with_kube_port(mut self, kube_port: u16) -> Self {
        self.kube_port = Some(kube_port);
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
        Some(remote_opts) => create_ssh_docker_client(remote_opts).await?,
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
    let port = options.port;
    let gateway_host = options.gateway_host;
    let kube_port = options.kube_port;
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
            let remote = create_ssh_docker_client(remote_opts).await?;
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
    //
    // When `gateway_host` is provided (e.g., `host.docker.internal` in CI),
    // it is added to the SAN list and used as `ssh_gateway_host` so the
    // server advertises the correct address even for local clusters.
    let (extra_sans, ssh_gateway_host): (Vec<String>, Option<String>) =
        if let Some(opts) = remote_opts.as_ref() {
            let ssh_host = extract_host_from_ssh_destination(&opts.destination);
            let resolved = resolve_ssh_hostname(&ssh_host);
            // Include both the SSH alias and resolved IP if they differ, so the
            // certificate covers both names.
            let mut sans = vec![resolved.clone()];
            if ssh_host != resolved {
                sans.push(ssh_host);
            }
            if let Some(ref host) = gateway_host
                && !sans.contains(host)
            {
                sans.push(host.clone());
            }
            (sans, gateway_host.or(Some(resolved)))
        } else {
            let mut sans: Vec<String> = local_gateway_host().into_iter().collect();
            if let Some(ref host) = gateway_host
                && !sans.contains(host)
            {
                sans.push(host.clone());
            }
            (sans, gateway_host)
        };

    log("[status] Creating cluster container".to_string());
    ensure_container(
        &target_docker,
        &name,
        &image_ref,
        &extra_sans,
        ssh_gateway_host.as_deref(),
        port,
        kube_port,
    )
    .await?;
    log("[status] Starting cluster container".to_string());
    start_container(&target_docker, &name).await?;

    log("[status] Waiting for kubeconfig".to_string());
    let raw_kubeconfig = wait_for_kubeconfig(&target_docker, &name).await?;

    // Rewrite kubeconfig based on deployment mode
    let rewritten = remote_opts.as_ref().map_or_else(
        || rewrite_kubeconfig(&raw_kubeconfig, &name, kube_port),
        |opts| rewrite_kubeconfig_remote(&raw_kubeconfig, &name, &opts.destination, kube_port),
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

    // Reconcile PKI: reuse existing cluster TLS secrets if they are complete and
    // valid; only generate fresh PKI when secrets are missing, incomplete,
    // malformed, or expiring within MIN_REMAINING_VALIDITY_DAYS.
    //
    // Ordering is: kubeconfig ready -> reconcile secrets -> (if rotated and
    // workload exists: rollout restart and wait) -> persist CLI-side bundle.
    //
    // We check workload presence before reconciliation. On a fresh/recreated
    // cluster, secrets are always newly generated and a restart is unnecessary.
    // Restarting only when workload pre-existed avoids extra rollout latency.
    let workload_existed_before_pki = navigator_workload_exists(&target_docker, &name).await?;
    log("[status] Reconciling TLS certificates".to_string());
    let (pki_bundle, rotated) = reconcile_pki(&target_docker, &name, &extra_sans, &log).await?;

    if rotated && workload_existed_before_pki {
        // If a navigator workload is already running, it must be restarted so
        // it picks up the new TLS secrets before we write CLI-side certs.
        // A failed rollout is a hard error — CLI certs must not be persisted
        // if the server cannot come up with the new PKI.
        log("[status] PKI rotated — restarting navigator workload".to_string());
        restart_navigator_deployment(&target_docker, &name).await?;
    }

    log("[status] Storing CLI mTLS credentials".to_string());
    store_pki_bundle(&name, &pki_bundle)?;

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

    // Create and store cluster metadata
    log("[status] Persisting cluster metadata".to_string());
    let metadata = create_cluster_metadata_with_host(
        &name,
        remote_opts.as_ref(),
        port,
        kube_port,
        ssh_gateway_host.as_deref(),
    );
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
pub async fn cluster_handle(name: &str, remote: Option<&RemoteOptions>) -> Result<ClusterHandle> {
    let docker = match remote {
        Some(remote_opts) => create_ssh_docker_client(remote_opts).await?,
        None => Docker::connect_with_local_defaults().into_diagnostic()?,
    };
    let kubeconfig_path = stored_kubeconfig_path(name)?;
    // Try to load existing metadata, fall back to creating new metadata
    // with the default ports (the actual ports are only known at deploy time).
    let metadata = load_cluster_metadata(name)
        .unwrap_or_else(|_| create_cluster_metadata(name, remote, DEFAULT_GATEWAY_PORT, None));
    Ok(ClusterHandle {
        name: name.to_string(),
        kubeconfig_path,
        metadata,
        docker,
    })
}

pub async fn ensure_cluster_image(version: &str) -> Result<String> {
    let docker = Docker::connect_with_local_defaults().into_diagnostic()?;
    let image_ref = format!("{}:{version}", image::pull_registry_image());
    ensure_image(&docker, &image_ref).await?;
    Ok(image_ref)
}

fn default_cluster_image_ref() -> String {
    if let Ok(image) = std::env::var("NAVIGATOR_CLUSTER_IMAGE")
        && !image.trim().is_empty()
    {
        return image;
    }
    image::pull_registry_image()
}

/// Create the three TLS K8s secrets required by the Navigator server and sandbox pods.
///
/// Secrets are created via `kubectl` exec'd inside the cluster container:
/// - `navigator-server-tls` (kubernetes.io/tls): server cert + key
/// - `navigator-server-client-ca` (Opaque): CA cert for verifying client certs
/// - `navigator-client-tls` (Opaque): client cert + key + CA cert (shared by CLI & sandboxes)
async fn create_k8s_tls_secrets(
    docker: &Docker,
    name: &str,
    bundle: &pki::PkiBundle,
) -> Result<()> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use miette::WrapErr;

    let cname = container_name(name);
    let kubeconfig = constants::KUBECONFIG_PATH;

    // Helper: run kubectl apply -f - with a JSON secret manifest.
    let apply_secret = |manifest: String| {
        let docker = docker.clone();
        let cname = cname.clone();
        async move {
            let (output, exit_code) = exec_capture_with_exit(
                &docker,
                &cname,
                vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    format!(
                        "KUBECONFIG={kubeconfig} kubectl apply -f - <<'ENDOFMANIFEST'\n{manifest}\nENDOFMANIFEST"
                    ),
                ],
            )
            .await?;
            if exit_code != 0 {
                return Err(miette::miette!(
                    "kubectl apply failed (exit {exit_code}): {output}"
                ));
            }
            Ok(())
        }
    };

    // 1. navigator-server-tls (kubernetes.io/tls)
    let server_tls_manifest = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": SERVER_TLS_SECRET_NAME,
            "namespace": "navigator"
        },
        "type": "kubernetes.io/tls",
        "data": {
            "tls.crt": STANDARD.encode(&bundle.server_cert_pem),
            "tls.key": STANDARD.encode(&bundle.server_key_pem)
        }
    });
    apply_secret(server_tls_manifest.to_string())
        .await
        .wrap_err("failed to create navigator-server-tls secret")?;

    // 2. navigator-server-client-ca (Opaque)
    let client_ca_manifest = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": SERVER_CLIENT_CA_SECRET_NAME,
            "namespace": "navigator"
        },
        "type": "Opaque",
        "data": {
            "ca.crt": STANDARD.encode(&bundle.ca_cert_pem)
        }
    });
    apply_secret(client_ca_manifest.to_string())
        .await
        .wrap_err("failed to create navigator-server-client-ca secret")?;

    // 3. navigator-client-tls (Opaque) — shared by CLI and sandbox pods
    let client_tls_manifest = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": CLIENT_TLS_SECRET_NAME,
            "namespace": "navigator"
        },
        "type": "Opaque",
        "data": {
            "tls.crt": STANDARD.encode(&bundle.client_cert_pem),
            "tls.key": STANDARD.encode(&bundle.client_key_pem),
            "ca.crt": STANDARD.encode(&bundle.ca_cert_pem)
        }
    });
    apply_secret(client_tls_manifest.to_string())
        .await
        .wrap_err("failed to create navigator-client-tls secret")?;

    Ok(())
}

/// Reconcile cluster TLS secrets: reuse existing PKI if valid, generate new if needed.
///
/// Returns `(bundle, rotated)` where `rotated` is true if new PKI was generated
/// and applied to the cluster (meaning the server needs a restart to pick it up).
async fn reconcile_pki<F>(
    docker: &Docker,
    name: &str,
    extra_sans: &[String],
    log: &F,
) -> Result<(pki::PkiBundle, bool)>
where
    F: Fn(String) + Sync,
{
    use miette::WrapErr;

    let cname = container_name(name);
    let kubeconfig = constants::KUBECONFIG_PATH;

    // Try to load existing secrets.
    match load_existing_pki_bundle(docker, &cname, kubeconfig).await {
        Ok(bundle) => {
            log("[status] Reusing existing TLS certificates".to_string());
            return Ok((bundle, false));
        }
        Err(reason) => {
            log(format!(
                "[status] Cannot reuse existing TLS secrets ({reason}) — generating new PKI"
            ));
        }
    }

    // Generate fresh PKI and apply to cluster.
    // Namespace may still be creating on first bootstrap, so wait here only
    // when rotation is actually needed.
    wait_for_namespace(docker, &cname, kubeconfig, "navigator").await?;
    let bundle = generate_pki(extra_sans)?;
    create_k8s_tls_secrets(docker, name, &bundle)
        .await
        .wrap_err("failed to apply new TLS secrets")?;

    Ok((bundle, true))
}

/// Load existing TLS secrets from the cluster and reconstruct a [`PkiBundle`].
///
/// Returns an error string describing why secrets couldn't be loaded (for logging).
async fn load_existing_pki_bundle(
    docker: &Docker,
    container_name: &str,
    kubeconfig: &str,
) -> std::result::Result<pki::PkiBundle, String> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    // Helper to read a specific key from a K8s secret.
    let read_secret_key = |secret: &str, key: &str| {
        let docker = docker.clone();
        let container_name = container_name.to_string();
        let secret = secret.to_string();
        let key = key.to_string();
        async move {
            let jsonpath = format!("{{.data.{}}}", key.replace('.', "\\."));
            let cmd = format!(
                "KUBECONFIG={kubeconfig} kubectl get secret {secret} -n navigator -o jsonpath='{jsonpath}' 2>/dev/null"
            );
            let (output, exit_code) = exec_capture_with_exit(
                &docker,
                &container_name,
                vec!["sh".to_string(), "-c".to_string(), cmd],
            )
            .await
            .map_err(|e| format!("exec failed: {e}"))?;

            if exit_code != 0 || output.trim().is_empty() {
                return Err(format!("secret {secret} key {key} not found or empty"));
            }

            let decoded = STANDARD
                .decode(output.trim())
                .map_err(|e| format!("base64 decode failed for {secret}/{key}: {e}"))?;
            String::from_utf8(decoded).map_err(|e| format!("non-UTF8 data in {secret}/{key}: {e}"))
        }
    };

    // Read required fields concurrently to reduce bootstrap latency.
    let (server_cert, server_key, ca_cert, client_cert, client_key, client_ca) = tokio::try_join!(
        read_secret_key(SERVER_TLS_SECRET_NAME, "tls.crt"),
        read_secret_key(SERVER_TLS_SECRET_NAME, "tls.key"),
        read_secret_key(SERVER_CLIENT_CA_SECRET_NAME, "ca.crt"),
        read_secret_key(CLIENT_TLS_SECRET_NAME, "tls.crt"),
        read_secret_key(CLIENT_TLS_SECRET_NAME, "tls.key"),
        // Also read ca.crt from client-tls for completeness check.
        read_secret_key(CLIENT_TLS_SECRET_NAME, "ca.crt"),
    )?;

    // Validate that all PEM data contains expected markers.
    for (label, data) in [
        ("server cert", &server_cert),
        ("server key", &server_key),
        ("CA cert", &ca_cert),
        ("client cert", &client_cert),
        ("client key", &client_key),
        ("client CA", &client_ca),
    ] {
        if !data.contains("-----BEGIN ") {
            return Err(format!("{label} does not contain valid PEM data"));
        }
    }

    Ok(pki::PkiBundle {
        ca_cert_pem: ca_cert,
        ca_key_pem: String::new(), // CA key is not stored in cluster secrets
        server_cert_pem: server_cert,
        server_key_pem: server_key,
        client_cert_pem: client_cert,
        client_key_pem: client_key,
    })
}

/// Wait for a K8s namespace to exist inside the cluster container.
///
/// The Helm controller creates the `navigator` namespace when it processes
/// the `HelmChart` manifest, but there's a race between kubeconfig being ready
/// and the namespace being created. We poll briefly.
async fn wait_for_namespace(
    docker: &Docker,
    container_name: &str,
    kubeconfig: &str,
    namespace: &str,
) -> Result<()> {
    use miette::WrapErr;

    let attempts = 60;
    let max_backoff = std::time::Duration::from_secs(2);
    let mut backoff = std::time::Duration::from_millis(200);

    for attempt in 0..attempts {
        let exec_result = exec_capture_with_exit(
            docker,
            container_name,
            vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("KUBECONFIG={kubeconfig} kubectl get namespace {namespace} -o name 2>&1"),
            ],
        )
        .await;

        let (output, exit_code) = match exec_result {
            Ok(result) => result,
            Err(err) => {
                if let Err(status_err) =
                    docker::check_container_running(docker, container_name).await
                {
                    let logs = fetch_recent_logs(docker, container_name, 40).await;
                    return Err(miette::miette!(
                        "cluster container is not running while waiting for namespace '{namespace}': {status_err}\n{logs}"
                    ))
                    .wrap_err("K8s namespace not ready");
                }

                if attempt + 1 == attempts {
                    return Err(err).wrap_err("K8s namespace not ready");
                }
                tokio::time::sleep(backoff).await;
                backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);
                continue;
            }
        };

        if exit_code == 0 && output.contains(namespace) {
            return Ok(());
        }

        if attempt + 1 == attempts {
            return Err(miette::miette!(
                "timed out waiting for namespace '{namespace}' to exist: {output}"
            ))
            .wrap_err("K8s namespace not ready");
        }

        tokio::time::sleep(backoff).await;
        backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);
    }

    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_existing_pki_bundle_validates_pem_markers() {
        // The PEM validation in load_existing_pki_bundle checks for "-----BEGIN "
        // markers. This test verifies that generate_pki produces bundles that
        // would pass that check.
        let bundle = generate_pki(&[]).expect("generate_pki failed");
        for (label, pem) in [
            ("ca_cert", &bundle.ca_cert_pem),
            ("server_cert", &bundle.server_cert_pem),
            ("server_key", &bundle.server_key_pem),
            ("client_cert", &bundle.client_cert_pem),
            ("client_key", &bundle.client_key_pem),
        ] {
            assert!(
                pem.contains("-----BEGIN "),
                "{label} should contain PEM marker"
            );
        }
    }
}
