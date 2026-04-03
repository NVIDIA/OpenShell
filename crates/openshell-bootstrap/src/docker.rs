// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::RemoteOptions;
use crate::constants::{container_name, network_name, node_name, volume_name};
use crate::image::{self, DEFAULT_IMAGE_REPO_BASE, DEFAULT_REGISTRY, parse_image_ref};
use bollard::API_DEFAULT_VERSION;
use bollard::Docker;
use bollard::errors::Error as BollardError;
use bollard::models::{
    ContainerCreateBody, DeviceRequest, EndpointSettings, HostConfig, HostConfigCgroupnsModeEnum,
    NetworkConnectRequest, NetworkCreateRequest, NetworkDisconnectRequest, PortBinding,
    RestartPolicy, RestartPolicyNameEnum, VolumeCreateRequest,
};
use bollard::query_parameters::{
    CreateContainerOptions, CreateImageOptions, InspectContainerOptions, InspectNetworkOptions,
    ListContainersOptionsBuilder, RemoveContainerOptions, RemoveImageOptions, RemoveVolumeOptions,
    StartContainerOptions,
};
use futures::StreamExt;
use miette::{IntoDiagnostic, Result, WrapErr};
use std::collections::HashMap;

const REGISTRY_NAMESPACE_DEFAULT: &str = "openshell";

/// Resolve the raw GPU device-ID list, replacing the `"auto"` sentinel with a
/// concrete device ID based on whether CDI is enabled on the daemon.
///
/// | Input        | Output                                                       |
/// |--------------|--------------------------------------------------------------|
/// | `[]`         | `[]`  — no GPU                                               |
/// | `["legacy"]` | `["legacy"]`  — pass through to the non-CDI fallback path    |
/// | `["auto"]`   | `["nvidia.com/gpu=all"]` if CDI enabled, else `["legacy"]`   |
/// | `[cdi-ids…]` | unchanged                                                    |
pub(crate) fn resolve_gpu_device_ids(gpu: &[String], cdi_enabled: bool) -> Vec<String> {
    match gpu {
        [] => vec![],
        [v] if v == "auto" => {
            if cdi_enabled {
                vec!["nvidia.com/gpu=all".to_string()]
            } else {
                vec!["legacy".to_string()]
            }
        }
        other => other.to_vec(),
    }
}

const REGISTRY_MODE_EXTERNAL: &str = "external";

fn env_non_empty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn env_bool(key: &str) -> Option<bool> {
    env_non_empty(key).map(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// Platform information for a Docker daemon host.
#[derive(Debug, Clone)]
pub struct HostPlatform {
    /// CPU architecture (e.g., "amd64", "arm64")
    pub arch: String,
    /// Operating system (e.g., "linux")
    pub os: String,
}

impl HostPlatform {
    /// Return the platform string in the format `os/arch` (e.g., `linux/amd64`).
    pub fn platform_string(&self) -> String {
        format!("{}/{}", self.os, self.arch)
    }
}

/// Query the Docker daemon for the host platform (architecture and OS).
pub async fn get_host_platform(docker: &Docker) -> Result<HostPlatform> {
    let version = docker
        .version()
        .await
        .into_diagnostic()
        .wrap_err("failed to query Docker daemon version")?;

    let arch = version
        .arch
        .ok_or_else(|| miette::miette!("Docker daemon did not report architecture"))?;
    let os = version
        .os
        .ok_or_else(|| miette::miette!("Docker daemon did not report OS"))?;

    Ok(HostPlatform {
        arch: normalize_arch(&arch),
        os: os.to_lowercase(),
    })
}

/// Normalize architecture names to Docker convention.
///
/// Docker uses `amd64` / `arm64` / `arm` etc., but some systems may report
/// `x86_64` or `aarch64` instead.
pub fn normalize_arch(arch: &str) -> String {
    match arch {
        "x86_64" => "amd64".to_string(),
        "aarch64" => "arm64".to_string(),
        other => other.to_lowercase(),
    }
}

/// Result of a successful Docker preflight check.
///
/// Contains the validated Docker client and metadata about the daemon so
/// callers can reuse the connection without re-checking.
#[derive(Debug)]
pub struct DockerPreflight {
    /// A Docker client that has been verified as connected and responsive.
    pub docker: Docker,
    /// Docker daemon version string (e.g., "28.1.1").
    pub version: Option<String>,
}

/// Well-known Docker socket paths to probe when the default fails.
///
/// These cover common container runtimes on macOS and Linux:
/// - `/var/run/docker.sock` — default for Docker Desktop, `OrbStack`, Colima
/// - `$HOME/.colima/docker.sock` — Colima (older installs)
/// - `$HOME/.orbstack/run/docker.sock` — `OrbStack` (if symlink is missing)
const WELL_KNOWN_SOCKET_PATHS: &[&str] = &[
    "/var/run/docker.sock",
    // Expanded at runtime via home_dir():
    // ~/.colima/docker.sock
    // ~/.orbstack/run/docker.sock
];

/// Check that a Docker-compatible runtime is installed, running, and reachable.
///
/// This is the primary preflight gate. It must be called before any gateway
/// deploy work begins. On failure it produces a user-friendly error with
/// actionable recovery steps instead of a raw bollard connection error.
pub async fn check_docker_available() -> Result<DockerPreflight> {
    // Step 1: Try to connect using bollard's default resolution
    // (respects DOCKER_HOST, then falls back to /var/run/docker.sock).
    let docker = match Docker::connect_with_local_defaults() {
        Ok(d) => d,
        Err(err) => {
            return Err(docker_not_reachable_error(
                &format!("{err}"),
                "Failed to create Docker client",
            ));
        }
    };

    // Step 2: Ping the daemon to confirm it's responsive.
    if let Err(err) = docker.ping().await {
        return Err(docker_not_reachable_error(
            &format!("{err}"),
            "Docker socket exists but the daemon is not responding",
        ));
    }

    // Step 3: Query version info (best-effort — don't fail on this).
    let version = match docker.version().await {
        Ok(v) => v.version,
        Err(_) => None,
    };

    Ok(DockerPreflight { docker, version })
}

/// Build a rich, user-friendly error when Docker is not reachable.
fn docker_not_reachable_error(raw_err: &str, summary: &str) -> miette::Report {
    let docker_host = std::env::var("DOCKER_HOST").ok();
    let socket_exists = std::path::Path::new("/var/run/docker.sock").exists();

    let mut hints: Vec<String> = Vec::new();

    if !socket_exists && docker_host.is_none() {
        // No socket and no DOCKER_HOST — likely nothing is installed or started
        hints.push(
            "No Docker socket found at /var/run/docker.sock and DOCKER_HOST is not set."
                .to_string(),
        );
        hints.push(
            "Install and start a Docker-compatible runtime. See the support matrix \
             in the OpenShell docs for tested configurations."
                .to_string(),
        );

        // Check for alternative sockets that might exist
        let alt_sockets = find_alternative_sockets();
        if !alt_sockets.is_empty() {
            hints.push(format!(
                "Found Docker-compatible socket(s) at alternative path(s):\n  {}\n\n  \
                 Set DOCKER_HOST to use one, e.g.:\n\n    \
                 export DOCKER_HOST=unix://{}",
                alt_sockets.join("\n  "),
                alt_sockets[0],
            ));
        }
    } else if docker_host.is_some() {
        // DOCKER_HOST is set but daemon didn't respond
        let host_val = docker_host.unwrap();
        hints.push(format!(
            "DOCKER_HOST is set to '{host_val}' but the Docker daemon is not responding."
        ));
        hints.push(
            "Verify your Docker runtime is started and the DOCKER_HOST value is correct."
                .to_string(),
        );
    } else {
        // Socket exists but daemon isn't responding
        hints.push(
            "Docker socket found at /var/run/docker.sock but the daemon is not responding."
                .to_string(),
        );
        hints.push("Start your Docker runtime and try again.".to_string());
    }

    hints.push("Verify Docker is working with: docker info".to_string());

    let help_text = hints.join("\n\n");

    miette::miette!(help = help_text, "{summary}.\n\n  {raw_err}")
}

/// Probe for Docker-compatible sockets at non-default locations.
fn find_alternative_sockets() -> Vec<String> {
    let mut found = Vec::new();

    // Check well-known static paths
    for path in WELL_KNOWN_SOCKET_PATHS {
        if std::path::Path::new(path).exists() {
            found.push(path.to_string());
        }
    }

    // Check home-relative paths
    if let Some(home) = home_dir() {
        let home_sockets = [
            format!("{home}/.colima/docker.sock"),
            format!("{home}/.orbstack/run/docker.sock"),
        ];
        for path in &home_sockets {
            if std::path::Path::new(path).exists() && !found.contains(path) {
                found.push(path.clone());
            }
        }
    }

    found
}

fn home_dir() -> Option<String> {
    std::env::var("HOME").ok()
}

/// Create an SSH Docker client from remote options.
pub async fn create_ssh_docker_client(remote: &RemoteOptions) -> Result<Docker> {
    // Ensure destination has ssh:// prefix
    let ssh_url = if remote.destination.starts_with("ssh://") {
        remote.destination.clone()
    } else {
        format!("ssh://{}", remote.destination)
    };

    let docker = Docker::connect_with_ssh(
        &ssh_url,
        600, // timeout in seconds (10 minutes for large image transfers)
        API_DEFAULT_VERSION,
        remote.ssh_key.clone(),
    )
    .into_diagnostic()
    .wrap_err_with(|| format!("failed to connect to remote Docker daemon at {ssh_url}"))?;

    // Negotiate the API version with the remote daemon.  bollard defaults to
    // a recent API version (1.52) which may be higher than what the remote
    // Docker supports.  Version negotiation downgrades the client version to
    // match the server, preventing errors like "Schema 2 manifest not
    // supported by client" when pulling images on older Docker daemons.
    docker
        .negotiate_version()
        .await
        .into_diagnostic()
        .wrap_err("failed to negotiate Docker API version with remote daemon")
}

/// Find the running openshell gateway container by image name.
///
/// Lists all running containers and returns the name of the one whose image
/// contains `openshell/cluster`. When `port` is provided, only containers
/// with a matching host port binding are considered — this disambiguates
/// when multiple gateway containers are running on the same host.
///
/// Fails if zero or multiple containers match.
pub async fn find_gateway_container(docker: &Docker, port: Option<u16>) -> Result<String> {
    let containers = docker
        .list_containers(Some(ListContainersOptionsBuilder::new().all(false).build()))
        .await
        .into_diagnostic()
        .wrap_err("failed to list Docker containers")?;

    let is_gateway_image = |c: &bollard::models::ContainerSummary| {
        c.image
            .as_deref()
            .is_some_and(|img| img.contains("openshell/cluster"))
    };

    let has_port = |c: &bollard::models::ContainerSummary, p: u16| {
        c.ports
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|binding| binding.public_port == Some(p))
    };

    let container_name = |c: &bollard::models::ContainerSummary| {
        c.names
            .as_ref()
            .and_then(|n| n.first())
            .map(|n| n.trim_start_matches('/').to_string())
    };

    let matches: Vec<String> = containers
        .iter()
        .filter(|c| is_gateway_image(c) && port.map_or(true, |p| has_port(c, p)))
        .filter_map(container_name)
        .collect();

    match matches.len() {
        0 => {
            let hint = if let Some(p) = port {
                format!(
                    "No openshell gateway container found listening on port {p}.\n\
                     Is the gateway running? Check with: docker ps"
                )
            } else {
                "No openshell gateway container found.\n\
                 Is the gateway running? Check with: docker ps"
                    .to_string()
            };
            Err(miette::miette!("{hint}"))
        }
        1 => Ok(matches.into_iter().next().unwrap()),
        _ => Err(miette::miette!(
            "Found multiple openshell gateway containers: {}\n\
             Specify the port in the endpoint URL to select one (e.g. https://host:8080).",
            matches.join(", ")
        )),
    }
}

/// Create a fresh Docker bridge network for the gateway.
///
/// Always removes and recreates the network to guarantee a clean state.
/// Stale Docker networks (e.g., from a previous interrupted destroy or
/// Docker Desktop restart) can leave broken routing that causes the
/// container to fail with "no default routes found".
pub async fn ensure_network(docker: &Docker, net_name: &str) -> Result<()> {
    force_remove_network(docker, net_name).await?;

    // Docker may return a 409 conflict if the previous network teardown has
    // not fully completed in the daemon. Retry a few times with back-off,
    // re-attempting the removal before each create.
    let mut last_err = None;
    for attempt in 0u64..5 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(500 * attempt)).await;
            // Re-attempt removal in case the previous teardown has now settled.
            force_remove_network(docker, net_name).await?;
        }
        match docker
            .create_network(NetworkCreateRequest {
                name: net_name.to_string(),
                driver: Some("bridge".to_string()),
                attachable: Some(true),
                ..Default::default()
            })
            .await
        {
            Ok(_) => return Ok(()),
            Err(err) if is_conflict(&err) => {
                tracing::debug!(
                    "Network create conflict (attempt {}/5), retrying: {}",
                    attempt + 1,
                    err,
                );
                last_err = Some(err);
            }
            Err(err) => {
                return Err(err)
                    .into_diagnostic()
                    .wrap_err("failed to create Docker network");
            }
        }
    }
    Err(last_err.expect("at least one retry attempt"))
        .into_diagnostic()
        .wrap_err("failed to create Docker network after retries (network still in use)")
}

pub async fn ensure_volume(docker: &Docker, name: &str) -> Result<()> {
    match docker.inspect_volume(name).await {
        Ok(_) => return Ok(()),
        Err(err) if is_not_found(&err) => {}
        Err(err) => return Err(err).into_diagnostic(),
    }

    docker
        .create_volume(VolumeCreateRequest {
            name: Some(name.to_string()),
            ..Default::default()
        })
        .await
        .into_diagnostic()
        .wrap_err("failed to create Docker volume")?;
    Ok(())
}

pub async fn ensure_image(
    docker: &Docker,
    image_ref: &str,
    registry_username: Option<&str>,
    registry_token: Option<&str>,
) -> Result<()> {
    match docker.inspect_image(image_ref).await {
        Ok(_) => return Ok(()),
        Err(err) if is_not_found(&err) => {}
        Err(err) => return Err(err).into_diagnostic(),
    }

    // For local-only images (no registry prefix), give a clear error instead
    // of attempting a pull from Docker Hub that will always fail.
    if image::is_local_image_ref(image_ref) {
        return Err(miette::miette!(
            "Image '{}' not found locally. This looks like a locally-built image \
             (no registry prefix). Build it first with `mise run docker:build:gateway`.",
            image_ref,
        ));
    }

    let (repo, tag) = parse_image_ref(image_ref);

    // Use explicit GHCR credentials when provided for ghcr.io images.
    // Public repos are pulled without authentication by default.
    let credentials = if repo.starts_with("ghcr.io/") {
        image::ghcr_credentials(registry_username, registry_token)
    } else {
        None
    };

    let options = CreateImageOptions {
        from_image: Some(repo.clone()),
        tag: if tag.is_empty() { None } else { Some(tag) },
        ..Default::default()
    };

    let mut stream = docker.create_image(Some(options), None, credentials);
    while let Some(result) = stream.next().await {
        result.into_diagnostic()?;
    }
    Ok(())
}

/// Returns the actual host port the container is using.  When an existing
/// container is reused (same image), this may differ from `gateway_port`
/// because the container was originally created with a different port.
pub async fn ensure_container(
    docker: &Docker,
    name: &str,
    image_ref: &str,
    extra_sans: &[String],
    ssh_gateway_host: Option<&str>,
    gateway_port: u16,
    disable_tls: bool,
    disable_gateway_auth: bool,
    registry_username: Option<&str>,
    registry_token: Option<&str>,
    device_ids: &[String],
    resume: bool,
) -> Result<u16> {
    let container_name = container_name(name);

    // Check if the container already exists
    match docker
        .inspect_container(&container_name, None::<InspectContainerOptions>)
        .await
    {
        Ok(info) => {
            // On resume we always reuse the existing container — the persistent
            // volume holds k3s etcd state, and recreating the container with
            // different env vars would cause the entrypoint to rewrite the
            // HelmChart manifest, triggering a Helm upgrade that changes the
            // StatefulSet image reference while the old pod still runs with the
            // previous image.  Reusing the container avoids this entirely.
            //
            // On a non-resume path we check whether the image changed and
            // recreate only when necessary.
            let reuse = if resume {
                true
            } else {
                let desired_id = docker
                    .inspect_image(image_ref)
                    .await
                    .ok()
                    .and_then(|img| img.id);

                let container_image_id = info.image.clone();

                match (&desired_id, &container_image_id) {
                    (Some(desired), Some(current)) => desired == current,
                    _ => false,
                }
            };

            if reuse {
                // The container exists and should be reused. Its network
                // attachment may be stale. When the gateway is resumed after a
                // container kill, `ensure_network` destroys and recreates the
                // Docker network (giving it a new ID). The stopped container
                // still references the old network ID, so `docker start` would
                // fail with "network <old-id> not found".
                //
                // Fix: disconnect from any existing networks and reconnect to
                // the current (just-created) network before returning.
                let expected_net = network_name(name);
                reconcile_container_network(docker, &container_name, &expected_net).await?;

                // Read the actual host port from the container's port bindings
                // as a cross-check.  The caller should already pass the correct
                // port (from stored metadata), but this catches mismatches if
                // the container was recreated with a different port externally.
                let actual_port = info
                    .host_config
                    .as_ref()
                    .and_then(|hc| hc.port_bindings.as_ref())
                    .and_then(|pb| pb.get("30051/tcp"))
                    .and_then(|bindings| bindings.as_ref())
                    .and_then(|bindings| bindings.first())
                    .and_then(|b| b.host_port.as_ref())
                    .and_then(|p| p.parse::<u16>().ok())
                    .unwrap_or(gateway_port);

                return Ok(actual_port);
            }

            // Image changed — remove the stale container so we can recreate it.
            tracing::info!(
                "Container {} exists but uses a different image (container={}, desired={}), recreating",
                container_name,
                info.image.as_deref().map_or("unknown", truncate_id),
                image_ref,
            );

            let _ = docker.stop_container(&container_name, None).await;
            docker
                .remove_container(
                    &container_name,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await
                .into_diagnostic()
                .wrap_err("failed to remove stale container")?;
        }
        Err(err) if is_not_found(&err) => {
            // Container does not exist — will create below
        }
        Err(err) => return Err(err).into_diagnostic(),
    }

    let mut port_bindings = HashMap::new();
    port_bindings.insert(
        "30051/tcp".to_string(),
        Some(vec![PortBinding {
            host_ip: Some("0.0.0.0".to_string()),
            host_port: Some(gateway_port.to_string()),
        }]),
    );
    let exposed_ports = vec!["30051/tcp".to_string()];

    let mut host_config = HostConfig {
        privileged: Some(true),
        // Use host cgroup namespace so k3s kubelet can manage cgroup controllers
        // (cpu, cpuset, memory, pids, etc.) required for pod QoS. With cgroup v2
        // and a private cgroupns, the controllers are not delegated into the
        // container's namespace, causing kubelet ContainerManager to fail.
        cgroupns_mode: Some(HostConfigCgroupnsModeEnum::HOST),
        port_bindings: Some(port_bindings),
        binds: Some(vec![format!("{}:/var/lib/rancher/k3s", volume_name(name))]),
        network_mode: Some(network_name(name)),
        // Automatically restart the container when Docker restarts, unless the
        // user explicitly stopped it with `gateway stop`.
        restart_policy: Some(RestartPolicy {
            name: Some(RestartPolicyNameEnum::UNLESS_STOPPED),
            maximum_retry_count: None,
        }),
        // Add host gateway aliases for DNS resolution.
        // This allows both the entrypoint script and the running gateway
        // process to reach services on the Docker host.
        extra_hosts: Some(vec![
            "host.docker.internal:host-gateway".to_string(),
            "host.openshell.internal:host-gateway".to_string(),
        ]),
        ..Default::default()
    };

    // Inject GPU devices into the container based on the resolved device ID list.
    //
    // The list is pre-resolved by `resolve_gpu_device_ids` before reaching here:
    //   []           — no GPU passthrough
    //   ["legacy"]   — internal non-CDI fallback path: `driver="nvidia"`,
    //                  `count=-1`; relies on the NVIDIA Container Runtime hook
    //   [cdi-ids…]   — CDI DeviceRequest (driver="cdi") with the given device IDs;
    //                  Docker resolves them against the host CDI spec at /etc/cdi/
    match device_ids {
        [] => {}
        [id] if id == "legacy" => {
            host_config.device_requests = Some(vec![DeviceRequest {
                driver: Some("nvidia".to_string()),
                count: Some(-1), // all GPUs
                capabilities: Some(vec![vec![
                    "gpu".to_string(),
                    "utility".to_string(),
                    "compute".to_string(),
                ]]),
                ..Default::default()
            }]);
        }
        ids => {
            host_config.device_requests = Some(vec![DeviceRequest {
                driver: Some("cdi".to_string()),
                device_ids: Some(ids.to_vec()),
                ..Default::default()
            }]);
        }
    }

    let mut cmd = vec![
        "server".to_string(),
        "--disable=traefik".to_string(),
        "--tls-san=127.0.0.1".to_string(),
        "--tls-san=localhost".to_string(),
        "--tls-san=host.docker.internal".to_string(),
    ];
    for san in extra_sans {
        cmd.push(format!("--tls-san={san}"));
    }

    // Pass extra SANs, SSH gateway config, and registry credentials to the
    // entrypoint so they can be injected into the HelmChart manifest and
    // k3s registries.yaml.
    let registry_host =
        env_non_empty("OPENSHELL_REGISTRY_HOST").unwrap_or_else(|| DEFAULT_REGISTRY.to_string());
    let registry_namespace = env_non_empty("OPENSHELL_REGISTRY_NAMESPACE")
        .unwrap_or_else(|| REGISTRY_NAMESPACE_DEFAULT.to_string());
    let image_repo_base = env_non_empty("IMAGE_REPO_BASE")
        .or_else(|| env_non_empty("OPENSHELL_IMAGE_REPO_BASE"))
        .unwrap_or_else(|| {
            if registry_host == DEFAULT_REGISTRY {
                // For ghcr.io the default namespace is the full org path.
                DEFAULT_IMAGE_REPO_BASE.to_string()
            } else {
                format!("{registry_host}/{registry_namespace}")
            }
        });
    let registry_insecure = env_bool("OPENSHELL_REGISTRY_INSECURE").unwrap_or(false);
    let registry_endpoint = env_non_empty("OPENSHELL_REGISTRY_ENDPOINT");

    // Credential priority:
    // 1. OPENSHELL_REGISTRY_USERNAME/PASSWORD env vars (power-user override)
    // 2. registry_username/registry_token from CLI flags / env vars
    // No built-in default — GHCR repos are public and pull without auth.
    let effective_username = env_non_empty("OPENSHELL_REGISTRY_USERNAME").or_else(|| {
        registry_username
            .filter(|u| !u.is_empty())
            .map(ToString::to_string)
    });
    let effective_password = env_non_empty("OPENSHELL_REGISTRY_PASSWORD").or_else(|| {
        registry_token
            .filter(|t| !t.is_empty())
            .map(ToString::to_string)
    });

    let mut env_vars: Vec<String> = vec![
        format!("REGISTRY_MODE={REGISTRY_MODE_EXTERNAL}"),
        format!("REGISTRY_HOST={registry_host}"),
        format!("REGISTRY_INSECURE={registry_insecure}"),
        format!("IMAGE_REPO_BASE={image_repo_base}"),
        // Deterministic k3s node name so the node identity survives container
        // recreation (e.g. after an image upgrade). Without this, k3s uses
        // the container ID as the hostname/node name, which changes on every
        // container recreate and triggers stale-node PVC cleanup.
        format!("OPENSHELL_NODE_NAME={}", node_name(name)),
    ];
    if let Some(endpoint) = registry_endpoint {
        env_vars.push(format!("REGISTRY_ENDPOINT={endpoint}"));
    }
    if let Some(password) = effective_password {
        // Default to __token__ when only a password/token is provided.
        let username = effective_username.unwrap_or_else(|| "__token__".to_string());
        env_vars.push(format!("REGISTRY_USERNAME={username}"));
        env_vars.push(format!("REGISTRY_PASSWORD={password}"));
    }

    if !extra_sans.is_empty() {
        env_vars.push(format!("EXTRA_SANS={}", extra_sans.join(",")));
    }
    if let Some(host) = ssh_gateway_host {
        env_vars.push(format!("SSH_GATEWAY_HOST={host}"));
        // The NodePort is mapped to the configured host port, so the SSH
        // gateway port for remote clusters must match.
        env_vars.push(format!("SSH_GATEWAY_PORT={gateway_port}"));
    }

    // Pass image configuration to the cluster entrypoint.
    // The effective tag is resolved from the runtime IMAGE_TAG env var (if set)
    // or the compile-time default (see image::DEFAULT_IMAGE_TAG).
    // When OPENSHELL_PUSH_IMAGES is set the entrypoint overrides the baked-in
    // HelmChart manifest so k3s uses the locally-pushed images with
    // IfNotPresent pull policy instead of pulling from the remote registry.
    let push_mode = std::env::var("OPENSHELL_PUSH_IMAGES")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .is_some();
    let effective_tag = std::env::var("IMAGE_TAG")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| image::DEFAULT_IMAGE_TAG.to_string());
    if push_mode {
        if let Ok(images) = std::env::var("OPENSHELL_PUSH_IMAGES")
            && !images.trim().is_empty()
        {
            env_vars.push(format!("PUSH_IMAGE_REFS={images}"));
        }
        env_vars.push(format!("IMAGE_TAG={effective_tag}"));
        env_vars.push("IMAGE_PULL_POLICY=IfNotPresent".to_string());
    } else {
        env_vars.push(format!("IMAGE_TAG={effective_tag}"));
    }

    // Disable TLS: pass through to the entrypoint so the HelmChart manifest
    // configures the server pod for plaintext HTTP.
    if disable_tls {
        env_vars.push("DISABLE_TLS=true".to_string());
    }

    // Disable gateway auth: pass through to the entrypoint so the HelmChart
    // manifest sets the flag on the server pod.
    if disable_gateway_auth {
        env_vars.push("DISABLE_GATEWAY_AUTH=true".to_string());
    }

    // GPU support: tell the entrypoint to deploy the NVIDIA device plugin
    // HelmChart CR so k8s workloads can request nvidia.com/gpu resources.
    if !device_ids.is_empty() {
        env_vars.push("GPU_ENABLED=true".to_string());
    }

    let env = Some(env_vars);

    let config = ContainerCreateBody {
        image: Some(image_ref.to_string()),
        // Set the container hostname to the deterministic node name.
        // k3s uses the container hostname as its default node name.  Without
        // this, Docker defaults to the container ID (first 12 hex chars),
        // which changes on every container recreation and can cause
        // `clean_stale_nodes` to delete the wrong node on resume.  The
        // hostname persists across container stop/start cycles, ensuring a
        // stable node identity.
        hostname: Some(node_name(name)),
        cmd: Some(cmd),
        env,
        exposed_ports: Some(exposed_ports),
        host_config: Some(host_config),
        ..Default::default()
    };

    docker
        .create_container(
            Some(CreateContainerOptions {
                name: Some(container_name),
                platform: String::new(),
            }),
            config,
        )
        .await
        .into_diagnostic()
        .wrap_err("failed to create gateway container")?;
    Ok(gateway_port)
}

/// Information about a container that is holding a port we need.
#[derive(Debug, Clone)]
pub struct PortConflict {
    /// Name of the container holding the port (without leading `/`).
    pub container_name: String,
    /// The host port that conflicts.
    pub host_port: u16,
}

/// Check whether any *other* running container already binds the host ports
/// that the gateway needs.  Returns a list of conflicts (empty if none).
///
/// Docker silently fails to attach networking when a port is already bound,
/// leaving the new container with only a loopback interface.  Detecting this
/// up-front lets us give a clear error instead of a cryptic "no default route"
/// failure 30 seconds later.
pub async fn check_port_conflicts(
    docker: &Docker,
    name: &str,
    gateway_port: u16,
) -> Result<Vec<PortConflict>> {
    let our_container = container_name(name);
    let needed_ports: Vec<u16> = vec![gateway_port];

    let containers = docker
        .list_containers(Some(
            ListContainersOptionsBuilder::new()
                // Only running containers can hold port bindings.
                .all(false)
                .build(),
        ))
        .await
        .into_diagnostic()
        .wrap_err("failed to list containers for port conflict check")?;

    let mut conflicts = Vec::new();
    for container in &containers {
        // Skip our own container (it may already exist from a previous run).
        let names = container.names.as_deref().unwrap_or_default();
        let is_ours = names
            .iter()
            .any(|n| n.trim_start_matches('/') == our_container);
        if is_ours {
            continue;
        }

        let ports = container.ports.as_deref().unwrap_or_default();
        for port in ports {
            if let Some(public) = port.public_port {
                if needed_ports.contains(&public) {
                    let cname = names
                        .first()
                        .map(|n| n.trim_start_matches('/').to_string())
                        .unwrap_or_else(|| {
                            container
                                .id
                                .clone()
                                .unwrap_or_else(|| "<unknown>".to_string())
                        });
                    conflicts.push(PortConflict {
                        container_name: cname,
                        host_port: public,
                    });
                }
            }
        }
    }
    Ok(conflicts)
}

pub async fn start_container(docker: &Docker, name: &str) -> Result<()> {
    let container_name = container_name(name);

    // Retry with backoff when the start fails due to a port binding conflict.
    // After a container is destroyed the OS may take a moment to release the
    // TCP socket, so the new container's start can transiently fail with
    // "port is already allocated".
    let max_attempts: u64 = 5;
    for attempt in 1..=max_attempts {
        let response = docker
            .start_container(&container_name, None::<StartContainerOptions>)
            .await;
        match response {
            Ok(()) => return Ok(()),
            Err(err) if is_conflict(&err) => return Ok(()),
            Err(ref err) if attempt < max_attempts && is_port_conflict(err) => {
                tracing::debug!(
                    "Port conflict on start attempt {attempt}/{max_attempts}, retrying after backoff"
                );
                tokio::time::sleep(std::time::Duration::from_millis(500 * attempt)).await;
            }
            Err(err) => {
                return Err(err)
                    .into_diagnostic()
                    .wrap_err("failed to start gateway container");
            }
        }
    }
    unreachable!()
}

pub async fn stop_container(docker: &Docker, container_name: &str) -> Result<()> {
    let response = docker.stop_container(container_name, None).await;
    match response {
        Ok(()) => Ok(()),
        Err(err) if is_conflict(&err) => Ok(()),
        Err(err) if is_not_found(&err) => Ok(()),
        Err(err) => Err(err).into_diagnostic(),
    }
}

pub async fn destroy_gateway_resources(docker: &Docker, name: &str) -> Result<()> {
    let container_name = container_name(name);
    let volume_name = volume_name(name);

    // Capture the container's image reference before removing the container so
    // we can clean it up afterwards.  This prevents stale images from being
    // re-used on subsequent deploys.
    let container_image = docker
        .inspect_container(&container_name, None::<InspectContainerOptions>)
        .await
        .ok()
        .and_then(|info| info.image);

    // Explicitly disconnect the container from the per-gateway network before
    // removing it. This ensures Docker tears down the network endpoint
    // synchronously so port bindings are released immediately and the
    // subsequent network cleanup sees zero connected containers.
    let net_name = network_name(name);
    let _ = docker
        .disconnect_network(
            &net_name,
            NetworkDisconnectRequest {
                container: container_name.clone(),
                force: Some(true),
            },
        )
        .await;

    let _ = stop_container(docker, &container_name).await;

    let remove_container = docker
        .remove_container(
            &container_name,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    if let Err(err) = remove_container
        && !is_not_found(&err)
    {
        return Err(err).into_diagnostic();
    }

    // Remove the gateway image so the next deploy always pulls the latest
    // version from the registry instead of reusing a stale local copy.
    // Docker may briefly report the container as still running after a
    // force-remove, so retry a few times on conflict (409) errors.
    if let Some(ref image_id) = container_image {
        tracing::debug!("Removing gateway image: {}", image_id);
        let mut last_err = None;
        for attempt in 0..5 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            match docker
                .remove_image(
                    image_id,
                    Some(RemoveImageOptions {
                        force: true,
                        noprune: true,
                        ..Default::default()
                    }),
                    None,
                )
                .await
            {
                Ok(_) => {
                    last_err = None;
                    break;
                }
                Err(err) if is_not_found(&err) => {
                    last_err = None;
                    break;
                }
                Err(err) if is_conflict(&err) => {
                    last_err = Some(err);
                }
                Err(err) => {
                    last_err = Some(err);
                    break;
                }
            }
        }
        if let Some(err) = last_err {
            tracing::warn!("Failed to remove gateway image {}: {}", image_id, err);
        }
    }

    let remove_volume = docker
        .remove_volume(&volume_name, Some(RemoveVolumeOptions { force: true }))
        .await;
    if let Err(err) = remove_volume
        && !is_not_found(&err)
    {
        return Err(err).into_diagnostic();
    }

    // Force-remove the per-gateway network during a full destroy. First
    // disconnect any stale endpoints that Docker may still report (race
    // between container removal and network bookkeeping), then remove the
    // network itself.
    force_remove_network(docker, &net_name).await?;

    Ok(())
}

/// Clean up the gateway container and network, preserving the persistent volume.
///
/// Used when a resume attempt fails — we want to remove the container we may
/// have just created but keep the volume so the user can retry without losing
/// their k3s/etcd state and sandbox data.
pub async fn cleanup_gateway_container(docker: &Docker, name: &str) -> Result<()> {
    let container_name = container_name(name);
    let net_name = network_name(name);

    // Disconnect container from network
    let _ = docker
        .disconnect_network(
            &net_name,
            NetworkDisconnectRequest {
                container: container_name.clone(),
                force: Some(true),
            },
        )
        .await;

    let _ = stop_container(docker, &container_name).await;

    let remove_container = docker
        .remove_container(
            &container_name,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    if let Err(err) = remove_container
        && !is_not_found(&err)
    {
        return Err(err).into_diagnostic();
    }

    force_remove_network(docker, &net_name).await?;

    Ok(())
}

/// Forcefully remove a Docker network, disconnecting any remaining
/// containers first. This ensures that stale Docker network endpoints
/// cannot prevent port bindings from being released.
async fn force_remove_network(docker: &Docker, net_name: &str) -> Result<()> {
    let network = match docker
        .inspect_network(net_name, None::<InspectNetworkOptions>)
        .await
    {
        Ok(info) => info,
        Err(err) if is_not_found(&err) => return Ok(()),
        Err(err) => return Err(err).into_diagnostic(),
    };

    // Disconnect any containers still attached to the network.
    if let Some(containers) = network.containers {
        for (id, _) in containers {
            let _ = docker
                .disconnect_network(
                    net_name,
                    NetworkDisconnectRequest {
                        container: id,
                        force: Some(true),
                    },
                )
                .await;
        }
    }

    match docker.remove_network(net_name).await {
        Ok(()) => Ok(()),
        Err(err) if is_not_found(&err) => Ok(()),
        Err(err) => Err(err)
            .into_diagnostic()
            .wrap_err("failed to remove Docker network"),
    }
}

/// Ensure a stopped container is connected to the expected Docker network.
///
/// When a gateway is resumed after the container was killed (but not removed),
/// `ensure_network` destroys and recreates the network with a new ID. The
/// stopped container still holds a reference to the old network ID in its
/// config, so `docker start` would fail with a 404 "network not found" error.
///
/// This function disconnects the container from any networks that no longer
/// match the expected network name and connects it to the correct one.
async fn reconcile_container_network(
    docker: &Docker,
    container_name: &str,
    expected_network: &str,
) -> Result<()> {
    let info = docker
        .inspect_container(container_name, None::<InspectContainerOptions>)
        .await
        .into_diagnostic()
        .wrap_err("failed to inspect container for network reconciliation")?;

    // Check the container's current network attachments via NetworkSettings.
    let attached_networks: Vec<String> = info
        .network_settings
        .as_ref()
        .and_then(|ns| ns.networks.as_ref())
        .map(|nets| nets.keys().cloned().collect())
        .unwrap_or_default();

    // If the container is already attached to the expected network (by name),
    // Docker will resolve the name to the current network ID on start.
    // However, when the network was destroyed and recreated, the container's
    // stored endpoint references the old ID. Disconnect and reconnect to
    // pick up the new network ID.
    for net_name in &attached_networks {
        let _ = docker
            .disconnect_network(
                net_name,
                NetworkDisconnectRequest {
                    container: container_name.to_string(),
                    force: Some(true),
                },
            )
            .await;
    }

    // Connect to the (freshly created) expected network.
    docker
        .connect_network(
            expected_network,
            NetworkConnectRequest {
                container: container_name.to_string(),
                endpoint_config: Some(EndpointSettings::default()),
            },
        )
        .await
        .into_diagnostic()
        .wrap_err("failed to connect container to gateway network")?;

    tracing::debug!(
        "Reconciled network for container {container_name}: disconnected from {attached_networks:?}, connected to {expected_network}"
    );

    Ok(())
}

fn is_not_found(err: &BollardError) -> bool {
    matches!(
        err,
        BollardError::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

/// Check whether a container is still running.
/// Returns `Ok(())` if running, or an `Err` with the exit status if the container has stopped.
pub async fn check_container_running(docker: &Docker, container_name: &str) -> Result<()> {
    let inspect = docker
        .inspect_container(container_name, None::<InspectContainerOptions>)
        .await
        .into_diagnostic()
        .wrap_err("failed to inspect container")?;

    let state = inspect.state.as_ref();
    let running = state.and_then(|s| s.running).unwrap_or(false);
    if running {
        return Ok(());
    }

    let status = state
        .and_then(|s| s.status.as_ref())
        .map_or_else(|| "unknown".to_string(), |s| format!("{s:?}"));
    let exit_code = state.and_then(|s| s.exit_code).unwrap_or(-1);
    let error_msg = state.and_then(|s| s.error.as_deref()).unwrap_or("");
    let oom = state.and_then(|s| s.oom_killed).unwrap_or(false);

    let mut detail = format!("container exited (status={status}, exit_code={exit_code})");
    if !error_msg.is_empty() {
        use std::fmt::Write;
        let _ = write!(detail, ", error={error_msg}");
    }
    if oom {
        detail.push_str(", OOMKilled=true");
    }

    Err(miette::miette!(detail))
}

/// Truncate an image ID for display (e.g., `sha256:abcdef1234...` -> `sha256:abcdef1234ab`).
fn truncate_id(id: &str) -> &str {
    const DISPLAY_LEN: usize = "sha256:".len() + 12;
    if id.len() > DISPLAY_LEN {
        &id[..DISPLAY_LEN]
    } else {
        id
    }
}

/// Information about an existing gateway deployment.
#[derive(Debug, Clone)]
pub struct ExistingGatewayInfo {
    /// Whether the container exists.
    pub container_exists: bool,
    /// Whether the container is currently running.
    pub container_running: bool,
    /// Whether the persistent volume exists.
    pub volume_exists: bool,
    /// The image used by the existing container (if any).
    pub container_image: Option<String>,
}

/// Check whether a gateway with the given name already exists.
///
/// Returns `None` if no gateway resources exist, or `Some(info)` with
/// details about the existing deployment.
pub async fn check_existing_gateway(
    docker: &Docker,
    name: &str,
) -> Result<Option<ExistingGatewayInfo>> {
    let container_name = container_name(name);
    let vol_name = volume_name(name);

    let volume_exists = match docker.inspect_volume(&vol_name).await {
        Ok(_) => true,
        Err(err) if is_not_found(&err) => false,
        Err(err) => return Err(err).into_diagnostic(),
    };

    let (container_exists, container_running, container_image) = match docker
        .inspect_container(&container_name, None::<InspectContainerOptions>)
        .await
    {
        Ok(info) => {
            let running = info.state.as_ref().and_then(|s| s.running).unwrap_or(false);
            let image = info.config.and_then(|c| c.image);
            (true, running, image)
        }
        Err(err) if is_not_found(&err) => (false, false, None),
        Err(err) => return Err(err).into_diagnostic(),
    };

    if !container_exists && !volume_exists {
        return Ok(None);
    }

    Ok(Some(ExistingGatewayInfo {
        container_exists,
        container_running,
        volume_exists,
        container_image,
    }))
}

fn is_conflict(err: &BollardError) -> bool {
    matches!(
        err,
        BollardError::DockerResponseServerError {
            status_code: 409,
            ..
        }
    )
}

/// Detect Docker "port is already allocated" errors that can occur transiently
/// after a container using the same port was just destroyed.
fn is_port_conflict(err: &BollardError) -> bool {
    matches!(
        err,
        BollardError::DockerResponseServerError {
            status_code: 500,
            message,
            ..
        } if message.contains("port is already allocated")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_arch_x86_64() {
        assert_eq!(normalize_arch("x86_64"), "amd64");
    }

    #[test]
    fn normalize_arch_aarch64() {
        assert_eq!(normalize_arch("aarch64"), "arm64");
    }

    #[test]
    fn normalize_arch_passthrough_amd64() {
        assert_eq!(normalize_arch("amd64"), "amd64");
    }

    #[test]
    fn normalize_arch_passthrough_arm64() {
        assert_eq!(normalize_arch("arm64"), "arm64");
    }

    #[test]
    fn normalize_arch_uppercase() {
        assert_eq!(normalize_arch("ARM64"), "arm64");
    }

    #[test]
    fn host_platform_string() {
        let platform = HostPlatform {
            arch: "arm64".to_string(),
            os: "linux".to_string(),
        };
        assert_eq!(platform.platform_string(), "linux/arm64");
    }

    #[test]
    fn docker_not_reachable_error_no_socket_no_docker_host() {
        // Simulate: no socket at default path, no DOCKER_HOST set.
        // We can't guarantee /var/run/docker.sock state in CI, but we can
        // verify the error message is well-formed and contains guidance.
        let err =
            docker_not_reachable_error("connection refused", "Failed to create Docker client");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("Failed to create Docker client"),
            "should include the summary"
        );
        assert!(
            msg.contains("connection refused"),
            "should include the raw error"
        );
        // The message should always include the verification step
        assert!(
            msg.contains("docker info"),
            "should suggest 'docker info' verification"
        );
    }

    #[test]
    fn docker_not_reachable_error_with_docker_host() {
        // Simulate: DOCKER_HOST is set but daemon unresponsive.
        // We set the env var temporarily (this is test-only).
        let prev_docker_host = std::env::var("DOCKER_HOST").ok();
        // SAFETY: test-only, single-threaded test runner for this test
        unsafe {
            std::env::set_var("DOCKER_HOST", "unix:///tmp/fake-docker.sock");
        }

        let err = docker_not_reachable_error(
            "daemon not responding",
            "Docker socket exists but the daemon is not responding",
        );
        let msg = format!("{err:?}");

        // Restore env
        // SAFETY: test-only, restoring previous state
        unsafe {
            match prev_docker_host {
                Some(val) => std::env::set_var("DOCKER_HOST", val),
                None => std::env::remove_var("DOCKER_HOST"),
            }
        }

        assert!(
            msg.contains("DOCKER_HOST"),
            "should mention DOCKER_HOST when it is set"
        );
        assert!(
            msg.contains("unix:///tmp/fake-docker.sock"),
            "should show the current DOCKER_HOST value"
        );
    }

    #[test]
    fn find_alternative_sockets_returns_vec() {
        // Verify the function runs without panic and returns a vec.
        // Exact contents depend on the host system, so we just check the type.
        let sockets = find_alternative_sockets();
        // On any system, /var/run/docker.sock may or may not exist
        assert!(
            sockets.len() <= 10,
            "should return a reasonable number of sockets"
        );
    }

    // --- resolve_gpu_device_ids ---

    #[test]
    fn resolve_gpu_empty_returns_empty() {
        assert_eq!(resolve_gpu_device_ids(&[], true), Vec::<String>::new());
        assert_eq!(resolve_gpu_device_ids(&[], false), Vec::<String>::new());
    }

    #[test]
    fn resolve_gpu_auto_cdi_enabled() {
        assert_eq!(
            resolve_gpu_device_ids(&["auto".to_string()], true),
            vec!["nvidia.com/gpu=all"],
        );
    }

    #[test]
    fn resolve_gpu_auto_cdi_disabled() {
        assert_eq!(
            resolve_gpu_device_ids(&["auto".to_string()], false),
            vec!["legacy"],
        );
    }

    #[test]
    fn resolve_gpu_legacy_passthrough() {
        assert_eq!(
            resolve_gpu_device_ids(&["legacy".to_string()], true),
            vec!["legacy"],
        );
        assert_eq!(
            resolve_gpu_device_ids(&["legacy".to_string()], false),
            vec!["legacy"],
        );
    }

    #[test]
    fn resolve_gpu_cdi_ids_passthrough() {
        let ids = vec!["nvidia.com/gpu=all".to_string()];
        assert_eq!(resolve_gpu_device_ids(&ids, true), ids);
        assert_eq!(resolve_gpu_device_ids(&ids, false), ids);

        let multi = vec![
            "nvidia.com/gpu=0".to_string(),
            "nvidia.com/gpu=1".to_string(),
        ];
        assert_eq!(resolve_gpu_device_ids(&multi, true), multi);
    }
}
