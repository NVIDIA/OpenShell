// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::RemoteOptions;
use crate::paths::{active_cluster_path, clusters_dir, xdg_config_dir};
use miette::{IntoDiagnostic, Result, WrapErr};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Cluster metadata stored alongside the kubeconfig.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterMetadata {
    /// The cluster name.
    pub name: String,
    /// Gateway endpoint URL (e.g., `https://127.0.0.1:8080`).
    pub gateway_endpoint: String,
    /// Whether this is a remote cluster.
    pub is_remote: bool,
    /// Host port mapped to the gateway `NodePort`.
    pub gateway_port: u16,
    /// Host port mapped to the k3s Kubernetes control plane (6443 inside the container).
    /// `None` means the control plane is not exposed on the host.
    /// Old metadata files without this field are deserialized as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kube_port: Option<u16>,
    /// For remote clusters, the SSH destination (e.g., `user@hostname`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_host: Option<String>,
    /// For remote clusters, the resolved hostname/IP from SSH config.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resolved_host: Option<String>,
}

pub fn create_cluster_metadata(
    name: &str,
    remote: Option<&RemoteOptions>,
    port: u16,
    kube_port: Option<u16>,
) -> ClusterMetadata {
    create_cluster_metadata_with_host(name, remote, port, kube_port, None)
}

/// Create cluster metadata, optionally overriding the gateway host.
///
/// When `gateway_host` is `Some`, that value is used as the host portion of
/// `gateway_endpoint` instead of the default (`127.0.0.1` for local clusters,
/// or the resolved SSH host for remote clusters).
pub fn create_cluster_metadata_with_host(
    name: &str,
    remote: Option<&RemoteOptions>,
    port: u16,
    kube_port: Option<u16>,
    gateway_host: Option<&str>,
) -> ClusterMetadata {
    let (gateway_endpoint, is_remote, remote_host, resolved_host) = remote.map_or_else(
        || {
            let host = gateway_host.map_or_else(
                || local_gateway_host().unwrap_or_else(|| "127.0.0.1".to_string()),
                String::from,
            );
            (format!("https://{host}:{port}"), false, None, None)
        },
        |opts| {
            // Extract the host portion from the SSH destination, then resolve it
            // via `ssh -G` to get the actual hostname/IP (handles SSH config aliases).
            let ssh_host = extract_host_from_ssh_destination(&opts.destination);
            let resolved = resolve_ssh_hostname(&ssh_host);
            let host = gateway_host.unwrap_or(&resolved);
            let endpoint = format!("https://{host}:{port}");
            (
                endpoint,
                true,
                Some(opts.destination.clone()),
                Some(resolved),
            )
        },
    );

    ClusterMetadata {
        name: name.to_string(),
        gateway_endpoint,
        is_remote,
        gateway_port: port,
        kube_port,
        remote_host,
        resolved_host,
    }
}

pub fn local_gateway_host() -> Option<String> {
    std::env::var("DOCKER_HOST")
        .ok()
        .and_then(|value| local_gateway_host_from_docker_host(&value))
}

pub fn local_gateway_host_from_docker_host(docker_host: &str) -> Option<String> {
    let target = docker_host.strip_prefix("tcp://")?;
    let authority = target.split('/').next()?;
    if authority.is_empty() {
        return None;
    }

    let host = authority
        .strip_prefix('[')
        .map_or_else(
            || authority.split(':').next().unwrap_or(""),
            |rest| rest.split(']').next().unwrap_or(""),
        )
        .trim();

    if host.is_empty() || host == "localhost" || host == "127.0.0.1" || host == "::1" {
        return None;
    }

    Some(host.to_string())
}

fn stored_metadata_path(name: &str) -> Result<PathBuf> {
    let base = xdg_config_dir()?;
    Ok(base
        .join("navigator")
        .join("clusters")
        .join(format!("{name}_metadata.json")))
}

/// Extract the hostname from an SSH destination string.
///
/// Handles formats like:
/// - `user@hostname` -> `hostname`
/// - `ssh://user@hostname` -> `hostname`
/// - `hostname` -> `hostname`
pub fn extract_host_from_ssh_destination(destination: &str) -> String {
    let dest = destination.strip_prefix("ssh://").unwrap_or(destination);

    // Handle user@host format
    dest.find('@')
        .map_or_else(|| dest.to_string(), |at_pos| dest[at_pos + 1..].to_string())
}

/// Resolve an SSH host alias to the actual hostname or IP address.
///
/// Uses `ssh -G <host>` to query the effective SSH configuration, which
/// resolves `~/.ssh/config` aliases and `HostName` directives. Falls back
/// to the original host string if the command fails.
pub fn resolve_ssh_hostname(host: &str) -> String {
    let output = std::process::Command::new("ssh")
        .args(["-G", host])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            for line in stdout.lines() {
                if let Some(value) = line.strip_prefix("hostname ") {
                    let resolved = value.trim();
                    if !resolved.is_empty() {
                        tracing::debug!(
                            ssh_host = host,
                            resolved_hostname = resolved,
                            "resolved SSH host alias"
                        );
                        return resolved.to_string();
                    }
                }
            }
            // ssh -G succeeded but no hostname line found; use original
            host.to_string()
        }
        Ok(result) => {
            tracing::warn!(
                ssh_host = host,
                stderr = %String::from_utf8_lossy(&result.stderr).trim(),
                "ssh -G failed, using original host"
            );
            host.to_string()
        }
        Err(err) => {
            tracing::warn!(
                ssh_host = host,
                error = %err,
                "failed to run ssh -G, using original host"
            );
            host.to_string()
        }
    }
}

pub fn store_cluster_metadata(name: &str, metadata: &ClusterMetadata) -> Result<()> {
    let path = stored_metadata_path(name)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    let contents = serde_json::to_string_pretty(metadata)
        .into_diagnostic()
        .wrap_err("failed to serialize cluster metadata")?;
    std::fs::write(&path, contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write metadata to {}", path.display()))?;
    Ok(())
}

pub fn load_cluster_metadata(name: &str) -> Result<ClusterMetadata> {
    let path = stored_metadata_path(name)?;
    let contents = std::fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read metadata from {}", path.display()))?;
    serde_json::from_str(&contents)
        .into_diagnostic()
        .wrap_err("failed to parse cluster metadata")
}

/// Load cluster metadata if available.
pub fn get_cluster_metadata(name: &str) -> Option<ClusterMetadata> {
    load_cluster_metadata(name).ok()
}

/// Save the active cluster name to persistent storage.
pub fn save_active_cluster(name: &str) -> Result<()> {
    let path = active_cluster_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(&path, name)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write active cluster to {}", path.display()))?;
    Ok(())
}

/// Load the active cluster name from persistent storage.
///
/// Returns `None` if no active cluster has been set.
pub fn load_active_cluster() -> Option<String> {
    let path = active_cluster_path().ok()?;
    let contents = std::fs::read_to_string(&path).ok()?;
    let name = contents.trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

/// List all clusters that have stored metadata.
///
/// Scans `$XDG_CONFIG_HOME/navigator/clusters/` for `*_metadata.json` files
/// and returns the parsed metadata for each.
pub fn list_clusters() -> Result<Vec<ClusterMetadata>> {
    let dir = clusters_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut clusters = Vec::new();
    let entries = std::fs::read_dir(&dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read directory {}", dir.display()))?;

    for entry in entries {
        let entry = entry.into_diagnostic()?;
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if let Some(cluster_name) = name_str.strip_suffix("_metadata.json")
            && let Ok(metadata) = load_cluster_metadata(cluster_name)
        {
            clusters.push(metadata);
        }
    }

    // Sort by name for stable output
    clusters.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(clusters)
}

/// Remove the active cluster file (used when destroying the active cluster).
pub fn clear_active_cluster() -> Result<()> {
    let path = active_cluster_path()?;
    if path.exists() {
        std::fs::remove_file(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(())
}

/// Remove cluster metadata file.
pub fn remove_cluster_metadata(name: &str) -> Result<()> {
    let path = stored_metadata_path(name)?;
    if path.exists() {
        std::fs::remove_file(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_plain_hostname() {
        assert_eq!(extract_host_from_ssh_destination("myserver"), "myserver");
    }

    #[test]
    fn extract_host_user_at_hostname() {
        assert_eq!(
            extract_host_from_ssh_destination("ubuntu@myserver"),
            "myserver"
        );
    }

    #[test]
    fn extract_host_ssh_scheme() {
        assert_eq!(
            extract_host_from_ssh_destination("ssh://ubuntu@myserver"),
            "myserver"
        );
    }

    #[test]
    fn extract_host_ssh_scheme_no_user() {
        assert_eq!(
            extract_host_from_ssh_destination("ssh://myserver"),
            "myserver"
        );
    }

    #[test]
    fn local_cluster_metadata() {
        let meta = create_cluster_metadata("test", None, 8080, None);
        assert_eq!(meta.name, "test");
        assert_eq!(meta.gateway_endpoint, "https://127.0.0.1:8080");
        assert_eq!(meta.gateway_port, 8080);
        assert!(meta.kube_port.is_none());
        assert!(!meta.is_remote);
        assert!(meta.remote_host.is_none());
        assert!(meta.resolved_host.is_none());
    }

    #[test]
    fn local_cluster_metadata_custom_port() {
        let meta = create_cluster_metadata("test", None, 9090, None);
        assert_eq!(meta.gateway_endpoint, "https://127.0.0.1:9090");
        assert_eq!(meta.gateway_port, 9090);
    }

    #[test]
    fn local_cluster_metadata_with_kube_port() {
        let meta = create_cluster_metadata("test", None, 8080, Some(7443));
        assert_eq!(meta.kube_port, Some(7443));
    }

    #[test]
    fn local_cluster_metadata_without_kube_port() {
        let meta = create_cluster_metadata("test", None, 8080, None);
        assert!(meta.kube_port.is_none());
    }

    #[test]
    fn local_gateway_host_from_docker_host_tcp_service_name() {
        let host = local_gateway_host_from_docker_host("tcp://docker:2375");
        assert_eq!(host.as_deref(), Some("docker"));
    }

    #[test]
    fn local_gateway_host_from_docker_host_tcp_loopback() {
        let host = local_gateway_host_from_docker_host("tcp://127.0.0.1:2375");
        assert!(host.is_none());
    }

    #[test]
    fn local_gateway_host_from_docker_host_unix_socket() {
        let host = local_gateway_host_from_docker_host("unix:///var/run/docker.sock");
        assert!(host.is_none());
    }

    #[test]
    fn remote_cluster_metadata_has_resolved_host() {
        let opts = RemoteOptions::new("user@10.0.0.5");
        let meta = create_cluster_metadata("test", Some(&opts), 8080, Some(6443));
        assert!(meta.is_remote);
        assert_eq!(meta.remote_host.as_deref(), Some("user@10.0.0.5"));
        // When the host is a plain IP, ssh -G should resolve it to itself
        assert!(meta.resolved_host.is_some());
        assert_eq!(
            meta.gateway_endpoint,
            format!("https://{}:8080", meta.resolved_host.as_ref().unwrap())
        );
        assert_eq!(meta.gateway_port, 8080);
        assert_eq!(meta.kube_port, Some(6443));
    }

    #[test]
    fn metadata_roundtrip_with_kube_port() {
        let meta = ClusterMetadata {
            name: "test".to_string(),
            gateway_endpoint: "https://10.0.0.5:8080".to_string(),
            is_remote: true,
            gateway_port: 8080,
            kube_port: Some(7443),
            remote_host: Some("user@navigator-dev".to_string()),
            resolved_host: Some("10.0.0.5".to_string()),
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: ClusterMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.resolved_host.as_deref(), Some("10.0.0.5"));
        assert_eq!(parsed.gateway_endpoint, "https://10.0.0.5:8080");
        assert_eq!(parsed.gateway_port, 8080);
        assert_eq!(parsed.kube_port, Some(7443));
    }

    #[test]
    fn metadata_roundtrip_without_kube_port() {
        let meta = ClusterMetadata {
            name: "test".to_string(),
            gateway_endpoint: "https://10.0.0.5:8080".to_string(),
            is_remote: true,
            gateway_port: 8080,
            kube_port: None,
            remote_host: Some("user@navigator-dev".to_string()),
            resolved_host: Some("10.0.0.5".to_string()),
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(
            !json.contains("kube_port"),
            "None should be omitted from JSON"
        );
        let parsed: ClusterMetadata = serde_json::from_str(&json).unwrap();
        assert!(parsed.kube_port.is_none());
    }

    #[test]
    fn metadata_deserialize_without_resolved_host() {
        // Existing metadata files won't have the resolved_host or kube_port fields.
        // Ensure backwards compatibility via serde(default).
        let json = r#"{
            "name": "test",
            "gateway_endpoint": "http://myserver:8080",
            "is_remote": true,
            "gateway_port": 8080,
            "remote_host": "user@myserver"
        }"#;
        let parsed: ClusterMetadata = serde_json::from_str(json).unwrap();
        assert!(parsed.resolved_host.is_none());
        // kube_port should default to None when not present in JSON
        assert!(parsed.kube_port.is_none());
    }

    #[test]
    fn local_cluster_metadata_with_gateway_host_override() {
        let meta = create_cluster_metadata_with_host(
            "test",
            None,
            8080,
            None,
            Some("host.docker.internal"),
        );
        assert_eq!(meta.name, "test");
        assert_eq!(meta.gateway_endpoint, "https://host.docker.internal:8080");
        assert_eq!(meta.gateway_port, 8080);
        assert!(!meta.is_remote);
        assert!(meta.remote_host.is_none());
        assert!(meta.resolved_host.is_none());
    }

    #[test]
    fn local_cluster_metadata_with_no_gateway_host_override() {
        // When gateway_host is None, behaviour matches create_cluster_metadata.
        let meta = create_cluster_metadata_with_host("test", None, 8080, None, None);
        assert_eq!(meta.gateway_endpoint, "https://127.0.0.1:8080");
    }
}
