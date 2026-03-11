// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::RemoteOptions;
use crate::constants::{NETWORK_NAME, container_name, volume_name};
use crate::image::{
    self, DEFAULT_IMAGE_REPO_BASE, DEFAULT_REGISTRY, DEFAULT_REGISTRY_USERNAME, parse_image_ref,
};
use bollard::API_DEFAULT_VERSION;
use bollard::Docker;
use bollard::errors::Error as BollardError;
use bollard::models::{
    ContainerCreateBody, HostConfig, NetworkCreateRequest, NetworkDisconnectRequest, PortBinding,
    VolumeCreateRequest,
};
use bollard::query_parameters::{
    CreateContainerOptions, CreateImageOptions, InspectContainerOptions, InspectNetworkOptions,
    ListContainersOptionsBuilder, RemoveContainerOptions, RemoveImageOptions, RemoveVolumeOptions,
    StartContainerOptions,
};
use futures::StreamExt;
use miette::{IntoDiagnostic, Result, WrapErr};
use std::collections::HashMap;
use std::path::Path;

const REGISTRY_NAMESPACE_DEFAULT: &str = "openshell";

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

pub async fn ensure_network(docker: &Docker) -> Result<()> {
    // Always remove and recreate the network to guarantee a clean state.
    // Stale Docker networks (e.g., from a previous interrupted destroy or
    // Docker Desktop restart) can leave broken routing that causes the
    // container to fail with "no default routes found".
    force_remove_network(docker).await?;

    // Docker may return a 409 conflict if the previous network teardown has
    // not fully completed in the daemon.  Retry a few times with back-off,
    // re-attempting the removal before each create.
    let mut last_err = None;
    for attempt in 0u64..5 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(500 * attempt)).await;
            // Re-attempt removal in case the previous teardown has now settled.
            force_remove_network(docker).await?;
        }
        match docker
            .create_network(NetworkCreateRequest {
                name: NETWORK_NAME.to_string(),
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

    // Use GHCR credentials (explicit or built-in default) for ghcr.io images.
    let credentials = if repo.starts_with("ghcr.io/") {
        image::ghcr_credentials(registry_token)
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

#[allow(clippy::too_many_arguments)]
pub async fn ensure_container(
    docker: &Docker,
    name: &str,
    image_ref: &str,
    extra_sans: &[String],
    ssh_gateway_host: Option<&str>,
    gateway_port: u16,
    kube_port: Option<u16>,
    disable_tls: bool,
    disable_gateway_auth: bool,
    registry_token: Option<&str>,
) -> Result<()> {
    let container_name = container_name(name);

    // Check if the container already exists
    match docker
        .inspect_container(&container_name, None::<InspectContainerOptions>)
        .await
    {
        Ok(info) => {
            // Container exists — verify it is using the expected image.
            // Resolve the desired image ref to its content-addressable ID so we
            // can compare against the container's image field (which Docker
            // stores as an ID).
            let desired_id = docker
                .inspect_image(image_ref)
                .await
                .ok()
                .and_then(|img| img.id);

            let container_image_id = info.image;

            let image_matches = match (&desired_id, &container_image_id) {
                (Some(desired), Some(current)) => desired == current,
                _ => false,
            };

            if image_matches {
                return Ok(());
            }

            // Image changed — remove the stale container so we can recreate it
            tracing::info!(
                "Container {} exists but uses a different image (container={}, desired={}), recreating",
                container_name,
                container_image_id.as_deref().map_or("unknown", truncate_id),
                desired_id.as_deref().map_or("unknown", truncate_id),
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
    if let Some(kp) = kube_port {
        port_bindings.insert(
            "6443/tcp".to_string(),
            Some(vec![PortBinding {
                host_ip: Some("0.0.0.0".to_string()),
                host_port: Some(kp.to_string()),
            }]),
        );
    }
    port_bindings.insert(
        "30051/tcp".to_string(),
        Some(vec![PortBinding {
            host_ip: Some("0.0.0.0".to_string()),
            host_port: Some(gateway_port.to_string()),
        }]),
    );
    let mut exposed_ports = vec!["30051/tcp".to_string()];
    if kube_port.is_some() {
        exposed_ports.push("6443/tcp".to_string());
    }

    let host_config = HostConfig {
        privileged: Some(true),
        port_bindings: Some(port_bindings),
        binds: Some(vec![format!("{}:/var/lib/rancher/k3s", volume_name(name))]),
        network_mode: Some(NETWORK_NAME.to_string()),
        // Add host.docker.internal mapping for DNS resolution
        // This allows the entrypoint script to configure CoreDNS to use the host gateway
        extra_hosts: Some(vec!["host.docker.internal:host-gateway".to_string()]),
        ..Default::default()
    };

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
    // 2. registry_token from --registry-token / OPENSHELL_REGISTRY_TOKEN
    // 3. Built-in default XOR-decoded token
    let registry_username = env_non_empty("OPENSHELL_REGISTRY_USERNAME")
        .or_else(|| Some(DEFAULT_REGISTRY_USERNAME.to_string()));
    let registry_password = env_non_empty("OPENSHELL_REGISTRY_PASSWORD").or_else(|| {
        registry_token
            .filter(|t| !t.is_empty())
            .map(ToString::to_string)
            .or_else(|| Some(image::default_registry_token()))
    });

    let mut env_vars: Vec<String> = vec![
        format!("REGISTRY_MODE={REGISTRY_MODE_EXTERNAL}"),
        format!("REGISTRY_HOST={registry_host}"),
        format!("REGISTRY_INSECURE={registry_insecure}"),
        format!("IMAGE_REPO_BASE={image_repo_base}"),
    ];
    if let Some(endpoint) = registry_endpoint {
        env_vars.push(format!("REGISTRY_ENDPOINT={endpoint}"));
    }
    if let (Some(username), Some(password)) = (registry_username, registry_password) {
        env_vars.push(format!("REGISTRY_USERNAME={username}"));
        env_vars.push(format!("REGISTRY_PASSWORD={password}"));
    }

    // When the primary registry is NOT ghcr.io (e.g. a local registry in
    // push-mode), we still need containerd credentials for the community
    // registry so that community sandbox images
    // (ghcr.io/nvidia/openshell-community/sandboxes/*) can be pulled at
    // runtime.  Pass community registry credentials as a separate set of
    // env vars so the entrypoint can add a second block to registries.yaml.
    if registry_host != DEFAULT_REGISTRY {
        env_vars.push(format!("COMMUNITY_REGISTRY_HOST={DEFAULT_REGISTRY}"));
        env_vars.push(format!(
            "COMMUNITY_REGISTRY_USERNAME={DEFAULT_REGISTRY_USERNAME}"
        ));
        env_vars.push(format!(
            "COMMUNITY_REGISTRY_PASSWORD={}",
            image::default_registry_token()
        ));
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

    // Pass image configuration for local development.
    // When OPENSHELL_PUSH_IMAGES is set the entrypoint overrides the baked-in
    // HelmChart manifest so k3s uses the locally-pushed images with
    // IfNotPresent pull policy instead of pulling from the remote registry.
    let push_mode = std::env::var("OPENSHELL_PUSH_IMAGES")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .is_some();
    if push_mode {
        let tag = std::env::var("IMAGE_TAG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "dev".to_string());
        if let Ok(images) = std::env::var("OPENSHELL_PUSH_IMAGES")
            && !images.trim().is_empty()
        {
            env_vars.push(format!("PUSH_IMAGE_REFS={images}"));
        }
        env_vars.push(format!("IMAGE_TAG={tag}"));
        env_vars.push("IMAGE_PULL_POLICY=IfNotPresent".to_string());
    } else if let Ok(tag) = std::env::var("IMAGE_TAG")
        && !tag.trim().is_empty()
    {
        env_vars.push(format!("IMAGE_TAG={tag}"));
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

    let env = Some(env_vars);

    let config = ContainerCreateBody {
        image: Some(image_ref.to_string()),
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
    Ok(())
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
    kube_port: Option<u16>,
) -> Result<Vec<PortConflict>> {
    let our_container = container_name(name);
    let needed_ports: Vec<u16> = std::iter::once(gateway_port).chain(kube_port).collect();

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

pub async fn destroy_gateway_resources(
    docker: &Docker,
    name: &str,
    kubeconfig_path: &Path,
) -> Result<()> {
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

    // Explicitly disconnect the container from the cluster network before
    // removing it.  This ensures Docker tears down the network endpoint
    // synchronously so port bindings are released immediately and the
    // subsequent network cleanup sees zero connected containers.
    let _ = docker
        .disconnect_network(
            NETWORK_NAME,
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

    let _ = std::fs::remove_file(kubeconfig_path);

    // Force-remove the network during a full destroy.  First disconnect any
    // stale endpoints that Docker may still report (race between container
    // removal and network bookkeeping), then remove the network itself.
    force_remove_network(docker).await?;
    Ok(())
}

/// Forcefully remove the gateway network, disconnecting any remaining
/// containers first.  This ensures that stale Docker network endpoints
/// cannot prevent port bindings from being released.
async fn force_remove_network(docker: &Docker) -> Result<()> {
    let network = match docker
        .inspect_network(NETWORK_NAME, None::<InspectNetworkOptions>)
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
                    NETWORK_NAME,
                    NetworkDisconnectRequest {
                        container: id,
                        force: Some(true),
                    },
                )
                .await;
        }
    }

    match docker.remove_network(NETWORK_NAME).await {
        Ok(()) => Ok(()),
        Err(err) if is_not_found(&err) => Ok(()),
        Err(err) => Err(err)
            .into_diagnostic()
            .wrap_err("failed to remove Docker network"),
    }
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
}
