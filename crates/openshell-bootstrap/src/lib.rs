// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod build;
pub mod edge_token;
pub mod errors;
pub mod image;

mod constants;
mod docker;
mod metadata;
mod mtls;
mod paths;
mod pki;
pub(crate) mod push;
mod runtime;

/// Shared lock for tests that mutate the process-global `XDG_CONFIG_HOME`
/// env var. All such tests in any module must hold this lock to avoid
/// concurrent clobbering.
#[cfg(test)]
pub(crate) static XDG_TEST_LOCK: Mutex<()> = Mutex::new(());

use bollard::Docker;
use miette::{IntoDiagnostic, Result};
use std::sync::{Arc, Mutex};

use crate::constants::{
    CLIENT_TLS_SECRET_NAME, SERVER_CLIENT_CA_SECRET_NAME, SERVER_TLS_SECRET_NAME, network_name,
    volume_name,
};
use crate::docker::{
    check_existing_gateway, check_port_conflicts, destroy_gateway_resources, ensure_container,
    ensure_image, ensure_network, ensure_volume, start_container, stop_container,
};
use crate::metadata::{
    create_gateway_metadata, create_gateway_metadata_with_host, local_gateway_host,
};
use crate::mtls::store_pki_bundle;
use crate::pki::generate_pki;
use crate::runtime::{
    clean_stale_nodes, exec_capture_with_exit, fetch_recent_logs, openshell_workload_exists,
    restart_openshell_deployment, wait_for_gateway_ready,
};

pub use crate::constants::container_name;
pub use crate::docker::{
    DockerPreflight, ExistingGatewayInfo, check_docker_available, create_ssh_docker_client,
};
pub use crate::metadata::{
    GatewayMetadata, clear_active_gateway, extract_host_from_ssh_destination, get_gateway_metadata,
    list_gateways, load_active_gateway, load_gateway_metadata, load_last_sandbox,
    remove_gateway_metadata, resolve_ssh_hostname, save_active_gateway, save_last_sandbox,
    store_gateway_metadata,
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
    /// Needed whenever the client cannot reach the Docker host at 127.0.0.1
    /// — CI containers, WSL, remote Docker hosts, etc.
    pub gateway_host: Option<String>,
    /// Disable TLS entirely — the server listens on plaintext HTTP.
    pub disable_tls: bool,
    /// Disable gateway authentication (mTLS client certificate requirement).
    /// Ignored when `disable_tls` is true.
    pub disable_gateway_auth: bool,
    /// Registry authentication username. Defaults to `__token__` when a
    /// `registry_token` is provided but no username is set. Only needed
    /// for private registries — public GHCR repos pull without auth.
    pub registry_username: Option<String>,
    /// Registry authentication token (e.g. a GitHub PAT with `read:packages`
    /// scope) used to pull images from the registry both during the initial
    /// bootstrap pull and inside the k3s cluster at runtime. Only needed
    /// for private registries.
    pub registry_token: Option<String>,
    /// Enable NVIDIA GPU passthrough. When true, the Docker container is
    /// created with GPU device requests (`--gpus all`) and the NVIDIA
    /// k8s-device-plugin is deployed inside the k3s cluster.
    pub gpu: bool,
    /// When true, destroy any existing gateway resources before deploying.
    /// When false, an existing gateway is left as-is and deployment is
    /// skipped (the caller is responsible for prompting the user first).
    pub recreate: bool,
}

impl DeployOptions {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            image_ref: None,
            remote: None,
            port: DEFAULT_GATEWAY_PORT,
            gateway_host: None,
            disable_tls: false,
            disable_gateway_auth: false,
            registry_username: None,
            registry_token: None,
            gpu: false,
            recreate: false,
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

    /// Disable TLS entirely — the server listens on plaintext HTTP.
    #[must_use]
    pub fn with_disable_tls(mut self, disable: bool) -> Self {
        self.disable_tls = disable;
        self
    }

    /// Disable gateway authentication (mTLS client certificate requirement).
    #[must_use]
    pub fn with_disable_gateway_auth(mut self, disable: bool) -> Self {
        self.disable_gateway_auth = disable;
        self
    }

    /// Set the registry authentication username.
    #[must_use]
    pub fn with_registry_username(mut self, username: impl Into<String>) -> Self {
        self.registry_username = Some(username.into());
        self
    }

    /// Set the registry authentication token for pulling images.
    #[must_use]
    pub fn with_registry_token(mut self, token: impl Into<String>) -> Self {
        self.registry_token = Some(token.into());
        self
    }

    /// Enable NVIDIA GPU passthrough for the cluster container.
    #[must_use]
    pub fn with_gpu(mut self, gpu: bool) -> Self {
        self.gpu = gpu;
        self
    }

    /// Set whether to destroy and recreate existing gateway resources.
    #[must_use]
    pub fn with_recreate(mut self, recreate: bool) -> Self {
        self.recreate = recreate;
        self
    }
}

#[derive(Debug, Clone)]
pub struct GatewayHandle {
    name: String,
    metadata: GatewayMetadata,
    docker: Docker,
}

impl GatewayHandle {
    /// Get the gateway metadata.
    pub fn metadata(&self) -> &GatewayMetadata {
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
        destroy_gateway_resources(&self.docker, &self.name).await
    }
}

/// Check whether a gateway with the given name already has resources deployed.
///
/// Returns `None` if no existing gateway resources are found, or
/// `Some(ExistingGatewayInfo)` with details about what exists.
pub async fn check_existing_deployment(
    name: &str,
    remote: Option<&RemoteOptions>,
) -> Result<Option<ExistingGatewayInfo>> {
    let docker = if let Some(remote_opts) = remote {
        create_ssh_docker_client(remote_opts).await?
    } else {
        let preflight = check_docker_available().await?;
        preflight.docker
    };
    check_existing_gateway(&docker, name).await
}

pub async fn deploy_gateway(options: DeployOptions) -> Result<GatewayHandle> {
    deploy_gateway_with_logs(options, |_| {}).await
}

pub async fn deploy_gateway_with_logs<F>(options: DeployOptions, on_log: F) -> Result<GatewayHandle>
where
    F: FnMut(String) + Send + 'static,
{
    let name = options.name;
    let image_ref = options.image_ref.unwrap_or_else(default_gateway_image_ref);
    let port = options.port;
    let gateway_host = options.gateway_host;
    let disable_tls = options.disable_tls;
    let disable_gateway_auth = options.disable_gateway_auth;
    let registry_username = options.registry_username;
    let registry_token = options.registry_token;
    let gpu = options.gpu;
    let recreate = options.recreate;

    // Wrap on_log in Arc<Mutex<>> so we can share it with pull_remote_image
    // which needs a 'static callback for the bollard streaming pull.
    let on_log = Arc::new(Mutex::new(on_log));

    // Helper to call on_log from the shared reference
    let log = |msg: String| {
        if let Ok(mut f) = on_log.lock() {
            f(msg);
        }
    };

    // Create Docker client based on deployment mode.
    // For local deploys, run a preflight check to fail fast with actionable
    // guidance when Docker is not installed, not running, or unreachable.
    let (target_docker, remote_opts) = if let Some(remote_opts) = &options.remote {
        let remote = create_ssh_docker_client(remote_opts).await?;
        (remote, Some(remote_opts.clone()))
    } else {
        log("[status] Checking Docker".to_string());
        let preflight = check_docker_available().await?;
        (preflight.docker, None)
    };

    // If an existing gateway is found, either tear it down (when recreate is
    // requested) or bail out so the caller can prompt the user / reuse it.
    if let Some(existing) = check_existing_gateway(&target_docker, &name).await? {
        if recreate {
            log("[status] Removing existing gateway".to_string());
            destroy_gateway_resources(&target_docker, &name).await?;
        } else {
            return Err(miette::miette!(
                "Gateway '{name}' already exists (container_running={}).\n\
                 Use --recreate to destroy and redeploy, or destroy it first with:\n\n    \
                 openshell gateway destroy --name {name}",
                existing.container_running,
            ));
        }
    }

    // Ensure the image is available on the target Docker daemon
    if remote_opts.is_some() {
        log("[status] Downloading gateway".to_string());
        let on_log_clone = Arc::clone(&on_log);
        let progress_cb = move |msg: String| {
            if let Ok(mut f) = on_log_clone.lock() {
                f(msg);
            }
        };
        image::pull_remote_image(
            &target_docker,
            &image_ref,
            registry_username.as_deref(),
            registry_token.as_deref(),
            progress_cb,
        )
        .await?;
    } else {
        // Local deployment: ensure image exists (pull if needed)
        log("[status] Downloading gateway".to_string());
        ensure_image(
            &target_docker,
            &image_ref,
            registry_username.as_deref(),
            registry_token.as_deref(),
        )
        .await?;
    }

    // All subsequent operations use the target Docker (remote or local)
    log("[status] Initializing environment".to_string());
    ensure_network(&target_docker, &network_name(&name)).await?;
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

    // Check for port conflicts before creating/starting the container.
    // Docker silently fails to attach networking when a host port is already
    // bound by another container, leaving the new container with only loopback
    // and no default route.  Detecting this up-front avoids a confusing 30s
    // timeout followed by a misleading "Docker networking issue" diagnostic.
    let conflicts = check_port_conflicts(&target_docker, &name, port).await?;
    if !conflicts.is_empty() {
        let details: Vec<String> = conflicts
            .iter()
            .map(|c| {
                format!(
                    "port {} is held by container \"{}\"",
                    c.host_port, c.container_name
                )
            })
            .collect();
        return Err(miette::miette!(
            "cannot start gateway: {}\n\nStop or remove the conflicting container(s) first, \
             then retry:\n{}",
            details.join(", "),
            conflicts
                .iter()
                .map(|c| format!("  docker stop {}", c.container_name))
                .collect::<Vec<_>>()
                .join("\n"),
        ));
    }

    ensure_container(
        &target_docker,
        &name,
        &image_ref,
        &extra_sans,
        ssh_gateway_host.as_deref(),
        port,
        disable_tls,
        disable_gateway_auth,
        registry_username.as_deref(),
        registry_token.as_deref(),
        gpu,
    )
    .await?;
    start_container(&target_docker, &name).await?;

    // Clean up stale k3s nodes left over from previous container instances that
    // used the same persistent volume. Without this, pods remain scheduled on
    // NotReady ghost nodes and the health check will time out.
    match clean_stale_nodes(&target_docker, &name).await {
        Ok(0) => {}
        Ok(n) => tracing::debug!("removed {n} stale node(s)"),
        Err(err) => {
            tracing::debug!("stale node cleanup failed (non-fatal): {err}");
        }
    }

    // Reconcile PKI: reuse existing cluster TLS secrets if they are complete and
    // valid; only generate fresh PKI when secrets are missing, incomplete,
    // malformed, or expiring within MIN_REMAINING_VALIDITY_DAYS.
    //
    // Ordering is: reconcile secrets -> (if rotated and workload exists:
    // rollout restart and wait) -> persist CLI-side bundle.
    //
    // We check workload presence before reconciliation. On a fresh/recreated
    // cluster, secrets are always newly generated and a restart is unnecessary.
    // Restarting only when workload pre-existed avoids extra rollout latency.
    let workload_existed_before_pki = openshell_workload_exists(&target_docker, &name).await?;
    let (pki_bundle, rotated) = reconcile_pki(&target_docker, &name, &extra_sans, &log).await?;

    if rotated && workload_existed_before_pki {
        // If an openshell workload is already running, it must be restarted so
        // it picks up the new TLS secrets before we write CLI-side certs.
        // A failed rollout is a hard error — CLI certs must not be persisted
        // if the server cannot come up with the new PKI.
        restart_openshell_deployment(&target_docker, &name).await?;
    }

    store_pki_bundle(&name, &pki_bundle)?;

    // Push locally-built component images into the k3s containerd runtime.
    // This is the "push" path for local development — images are exported from
    // the local Docker daemon and streamed into the cluster's containerd so
    // k3s can resolve them without pulling from the remote registry.
    if remote_opts.is_none()
        && let Ok(push_images_str) = std::env::var("OPENSHELL_PUSH_IMAGES")
    {
        let images: Vec<&str> = push_images_str
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if !images.is_empty() {
            log("[status] Deploying components".to_string());
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

            restart_openshell_deployment(&target_docker, &name).await?;
        }
    }

    log("[status] Starting gateway".to_string());
    {
        // Create a short-lived closure that locks on each call rather than holding
        // the MutexGuard across await points.
        let on_log_ref = Arc::clone(&on_log);
        let mut gateway_log = move |msg: String| {
            if let Ok(mut f) = on_log_ref.lock() {
                f(msg);
            }
        };
        wait_for_gateway_ready(&target_docker, &name, &mut gateway_log).await?;
    }

    // Create and store gateway metadata.
    let metadata = create_gateway_metadata_with_host(
        &name,
        remote_opts.as_ref(),
        port,
        ssh_gateway_host.as_deref(),
        disable_tls,
    );
    store_gateway_metadata(&name, &metadata)?;

    Ok(GatewayHandle {
        name,
        metadata,
        docker: target_docker,
    })
}

/// Get a handle to an existing gateway.
///
/// For local gateways, pass `None` for remote options.
/// For remote gateways, pass the same `RemoteOptions` used during deployment.
pub async fn gateway_handle(name: &str, remote: Option<&RemoteOptions>) -> Result<GatewayHandle> {
    let docker = match remote {
        Some(remote_opts) => create_ssh_docker_client(remote_opts).await?,
        None => Docker::connect_with_local_defaults().into_diagnostic()?,
    };
    // Try to load existing metadata, fall back to creating new metadata
    // with the default ports (the actual ports are only known at deploy time).
    let metadata = load_gateway_metadata(name)
        .unwrap_or_else(|_| create_gateway_metadata(name, remote, DEFAULT_GATEWAY_PORT));
    Ok(GatewayHandle {
        name: name.to_string(),
        metadata,
        docker,
    })
}

/// Extract mTLS certificates from an existing gateway container and store
/// them locally so the CLI can connect.
///
/// Connects to Docker (local or remote via SSH), auto-discovers the running
/// gateway container by image name (narrowed by `port` when provided), reads
/// the PKI bundle from Kubernetes secrets inside it, and writes the client
/// materials (ca.crt, tls.crt, tls.key) to the gateway config directory.
pub async fn extract_and_store_pki(
    name: &str,
    remote: Option<&RemoteOptions>,
    port: Option<u16>,
) -> Result<()> {
    let docker = match remote {
        Some(r) => create_ssh_docker_client(r).await?,
        None => Docker::connect_with_local_defaults().into_diagnostic()?,
    };
    let cname = docker::find_gateway_container(&docker, port).await?;
    let bundle = load_existing_pki_bundle(&docker, &cname, constants::KUBECONFIG_PATH)
        .await
        .map_err(|e| miette::miette!("Failed to extract TLS certificates: {e}"))?;
    store_pki_bundle(name, &bundle)?;
    Ok(())
}

pub async fn ensure_gateway_image(
    version: &str,
    registry_username: Option<&str>,
    registry_token: Option<&str>,
) -> Result<String> {
    let docker = Docker::connect_with_local_defaults().into_diagnostic()?;
    let image_ref = format!("{}:{version}", image::DEFAULT_GATEWAY_IMAGE);
    ensure_image(&docker, &image_ref, registry_username, registry_token).await?;
    Ok(image_ref)
}

/// Fetch logs from the gateway Docker container.
///
/// Connects to Docker (local or remote), retrieves logs from
/// `openshell-cluster-{name}`, and writes them to the provided writer.
///
/// When `follow` is true, streams logs in real-time (blocks until cancelled).
/// When `lines` is `Some(n)`, returns the last `n` lines; when `None`,
/// returns all available logs.
pub async fn gateway_container_logs<W: std::io::Write>(
    remote: Option<&RemoteOptions>,
    name: &str,
    lines: Option<usize>,
    follow: bool,
    mut writer: W,
) -> Result<()> {
    use bollard::container::LogOutput;
    use bollard::query_parameters::LogsOptionsBuilder;
    use futures::StreamExt;
    use miette::WrapErr;

    let docker = match remote {
        Some(remote_opts) => create_ssh_docker_client(remote_opts).await?,
        None => Docker::connect_with_local_defaults().into_diagnostic()?,
    };

    let container = container_name(name);

    let tail_value = match (follow, lines) {
        (true, _) => "0".to_string(),
        (false, Some(n)) => n.to_string(),
        (false, None) => "all".to_string(),
    };

    let options = LogsOptionsBuilder::new()
        .follow(follow)
        .stdout(true)
        .stderr(true)
        .tail(&tail_value)
        .timestamps(true)
        .build();

    let mut stream = docker.logs(&container, Some(options));

    while let Some(item) = stream.next().await {
        match item {
            Ok(log) => {
                let text = match log {
                    LogOutput::StdOut { message }
                    | LogOutput::StdErr { message }
                    | LogOutput::Console { message } => {
                        String::from_utf8_lossy(&message).to_string()
                    }
                    LogOutput::StdIn { .. } => continue,
                };
                writer
                    .write_all(text.as_bytes())
                    .into_diagnostic()
                    .wrap_err("failed to write log output")?;
            }
            Err(err) => {
                return Err(miette::miette!("error reading container logs: {err}"));
            }
        }
    }

    Ok(())
}

fn default_gateway_image_ref() -> String {
    if let Ok(image) = std::env::var("OPENSHELL_CLUSTER_IMAGE")
        && !image.trim().is_empty()
    {
        return image;
    }
    format!(
        "{}:{}",
        image::DEFAULT_GATEWAY_IMAGE,
        image::DEFAULT_IMAGE_TAG
    )
}

/// Create the three TLS K8s secrets required by the `OpenShell` server and sandbox pods.
///
/// Secrets are created via `kubectl` exec'd inside the cluster container:
/// - `openshell-server-tls` (kubernetes.io/tls): server cert + key
/// - `openshell-server-client-ca` (Opaque): CA cert for verifying client certs
/// - `openshell-client-tls` (Opaque): client cert + key + CA cert (shared by CLI & sandboxes)
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

    // 1. openshell-server-tls (kubernetes.io/tls)
    let server_tls_manifest = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": SERVER_TLS_SECRET_NAME,
            "namespace": "openshell"
        },
        "type": "kubernetes.io/tls",
        "data": {
            "tls.crt": STANDARD.encode(&bundle.server_cert_pem),
            "tls.key": STANDARD.encode(&bundle.server_key_pem)
        }
    });
    apply_secret(server_tls_manifest.to_string())
        .await
        .wrap_err("failed to create openshell-server-tls secret")?;

    // 2. openshell-server-client-ca (Opaque)
    let client_ca_manifest = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": SERVER_CLIENT_CA_SECRET_NAME,
            "namespace": "openshell"
        },
        "type": "Opaque",
        "data": {
            "ca.crt": STANDARD.encode(&bundle.ca_cert_pem)
        }
    });
    apply_secret(client_ca_manifest.to_string())
        .await
        .wrap_err("failed to create openshell-server-client-ca secret")?;

    // 3. openshell-client-tls (Opaque) — shared by CLI and sandbox pods
    let client_tls_manifest = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": CLIENT_TLS_SECRET_NAME,
            "namespace": "openshell"
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
        .wrap_err("failed to create openshell-client-tls secret")?;

    Ok(())
}

/// Reconcile gateway TLS secrets: reuse existing PKI if valid, generate new if needed.
///
/// Returns `(bundle, rotated)` where `rotated` is true if new PKI was generated
/// and applied to the gateway (meaning the server needs a restart to pick it up).
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
            log("[progress] Reusing existing TLS certificates".to_string());
            return Ok((bundle, false));
        }
        Err(reason) => {
            log(format!(
                "[progress] Cannot reuse existing TLS secrets ({reason}) — generating new PKI"
            ));
        }
    }

    // Generate fresh PKI and apply to cluster.
    // Namespace may still be creating on first bootstrap, so wait here only
    // when rotation is actually needed.
    log("[progress] Waiting for openshell namespace".to_string());
    wait_for_namespace(docker, &cname, kubeconfig, "openshell").await?;
    log("[progress] Generating TLS certificates".to_string());
    let bundle = generate_pki(extra_sans)?;
    log("[progress] Applying TLS secrets to gateway".to_string());
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
                "KUBECONFIG={kubeconfig} kubectl get secret {secret} -n openshell -o jsonpath='{jsonpath}' 2>/dev/null"
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
/// The Helm controller creates the `openshell` namespace when it processes
/// the `HelmChart` manifest, but there's a race between kubeconfig being ready
/// and the namespace being created. We poll briefly.
/// Check whether DNS resolution is working inside the container.
///
/// Probes the configured `REGISTRY_HOST` (falling back to `ghcr.io`) since
/// that is the primary registry the cluster needs to reach for image pulls.
///
/// Returns `Ok(true)` if DNS is functional, `Ok(false)` if the probe ran but
/// resolution failed, and `Err` if the exec itself failed.
async fn probe_container_dns(docker: &Docker, container_name: &str) -> Result<bool> {
    // The probe must handle IP-literal registry hosts (e.g. 127.0.0.1:5000)
    // which don't need DNS resolution. Strip the port suffix since nslookup
    // doesn't understand host:port, and skip the probe entirely for IP
    // literals.
    let (output, exit_code) = exec_capture_with_exit(
        docker,
        container_name,
        vec![
            "sh".to_string(),
            "-c".to_string(),
            concat!(
                "host=\"${REGISTRY_HOST:-ghcr.io}\"; ",
                "host=\"${host%%:*}\"; ",
                "echo \"$host\" | grep -qE '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' && { echo DNS_OK; exit 0; }; ",
                "echo \"$host\" | grep -qE '^\\[?[0-9a-fA-F:]+\\]?$' && { echo DNS_OK; exit 0; }; ",
                "nslookup \"$host\" >/dev/null 2>&1 && echo DNS_OK || echo DNS_FAIL",
            )
            .to_string(),
        ],
    )
    .await?;
    Ok(exit_code == 0 && output.contains("DNS_OK"))
}

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

    // Track consecutive DNS failures. We start probing early (iteration 3,
    // giving k3s a few seconds to boot) and probe every 3 iterations after
    // that. Two consecutive failures are enough to abort — the nslookup
    // timeout already provides a built-in retry window.
    let dns_probe_start = 3; // skip the first few iterations while k3s boots
    let dns_probe_interval = 3; // probe every N iterations after start
    let dns_failure_threshold: u32 = 2; // consecutive probe failures to abort
    let mut dns_consecutive_failures: u32 = 0;

    for attempt in 0..attempts {
        // --- Periodic DNS health probe ---
        if attempt >= dns_probe_start && (attempt - dns_probe_start) % dns_probe_interval == 0 {
            match probe_container_dns(docker, container_name).await {
                Ok(true) => {
                    dns_consecutive_failures = 0;
                }
                Ok(false) => {
                    dns_consecutive_failures += 1;
                    if dns_consecutive_failures >= dns_failure_threshold {
                        let logs = fetch_recent_logs(docker, container_name, 40).await;
                        return Err(miette::miette!(
                            "dial tcp: lookup registry: Try again\n\
                             DNS resolution is failing inside the gateway container. \
                             The cluster cannot pull images or create the '{namespace}' namespace \
                             until DNS is fixed.\n{logs}"
                        ))
                        .wrap_err("K8s namespace not ready");
                    }
                }
                Err(_) => {
                    // Exec failed — container may be restarting; don't count
                    // as a DNS failure.
                }
            }
        }

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
                        "gateway container is not running while waiting for namespace '{namespace}': {status_err}\n{logs}"
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
