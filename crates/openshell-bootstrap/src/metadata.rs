// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::RemoteOptions;
use crate::paths::{active_gateway_path, gateways_dir, last_sandbox_path};
use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::paths::ensure_parent_dir_restricted;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Gateway metadata stored alongside deployment info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayMetadata {
    /// The gateway name.
    pub name: String,
    /// Gateway endpoint URL (e.g., `https://127.0.0.1:8080`).
    pub gateway_endpoint: String,
    /// Whether this is a remote gateway.
    pub is_remote: bool,
    /// Host port mapped to the gateway `NodePort`.
    pub gateway_port: u16,
    /// For remote gateways, the SSH destination (e.g., `user@hostname`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_host: Option<String>,
    /// For remote gateways, the resolved hostname/IP from SSH config.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resolved_host: Option<String>,

    /// Auth mode: `None` or `"mtls"` = mTLS (default), `"plaintext"` = direct HTTP,
    /// `"cloudflare_jwt"` = CF JWT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_mode: Option<String>,

    /// Edge proxy team/org domain (e.g., `brevlab.cloudflareaccess.com`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "cf_team_domain"
    )]
    pub edge_team_domain: Option<String>,

    /// URL for triggering re-authentication in the browser.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "cf_auth_url"
    )]
    pub edge_auth_url: Option<String>,
}

impl GatewayMetadata {
    /// Extract the host portion from the stored `gateway_endpoint` URL.
    ///
    /// Returns `None` if the endpoint is malformed or uses a default loopback
    /// address (`127.0.0.1`, `localhost`, `::1`) — those are never meaningful
    /// as a `--gateway-host` override.
    pub fn gateway_host(&self) -> Option<&str> {
        // Endpoint format: "https://host:port" or "http://host:port"
        let after_scheme = self
            .gateway_endpoint
            .strip_prefix("https://")
            .or_else(|| self.gateway_endpoint.strip_prefix("http://"))?;
        // Strip port suffix (":8082")
        let host = after_scheme
            .rsplit_once(':')
            .map_or(after_scheme, |(h, _)| h);
        if host.is_empty()
            || host == "127.0.0.1"
            || host == "localhost"
            || host == "::1"
            || host == "[::1]"
        {
            return None;
        }
        Some(host)
    }
}

pub fn create_gateway_metadata(
    name: &str,
    remote: Option<&RemoteOptions>,
    port: u16,
) -> GatewayMetadata {
    create_gateway_metadata_with_host(name, remote, port, None, false)
}

/// Create gateway metadata, optionally overriding the gateway host.
///
/// When `gateway_host` is `Some`, that value is used as the host portion of
/// `gateway_endpoint` instead of the default (`127.0.0.1` for local gateways,
/// or the resolved SSH host for remote gateways).
///
/// When `disable_tls` is `true`, the gateway endpoint uses the `http://`
/// scheme instead of `https://`.  This must match the server configuration
/// so that the CLI connects with the correct protocol.
pub fn create_gateway_metadata_with_host(
    name: &str,
    remote: Option<&RemoteOptions>,
    port: u16,
    gateway_host: Option<&str>,
    disable_tls: bool,
) -> GatewayMetadata {
    let scheme = if disable_tls { "http" } else { "https" };

    let (gateway_endpoint, is_remote, remote_host, resolved_host) = remote.map_or_else(
        || {
            let host = gateway_host.map_or_else(
                || local_gateway_host().unwrap_or_else(|| "127.0.0.1".to_string()),
                String::from,
            );
            (format!("{scheme}://{host}:{port}"), false, None, None)
        },
        |opts| {
            // Extract the host portion from the SSH destination, then resolve it
            // via `ssh -G` to get the actual hostname/IP (handles SSH config aliases).
            let ssh_host = extract_host_from_ssh_destination(&opts.destination);
            let resolved = resolve_ssh_hostname(&ssh_host);
            let host = gateway_host.unwrap_or(&resolved);
            let endpoint = format!("{scheme}://{host}:{port}");
            (
                endpoint,
                true,
                Some(opts.destination.clone()),
                Some(resolved),
            )
        },
    );

    GatewayMetadata {
        name: name.to_string(),
        gateway_endpoint,
        is_remote,
        gateway_port: port,
        remote_host,
        resolved_host,
        auth_mode: disable_tls.then(|| "plaintext".to_string()),
        edge_team_domain: None,
        edge_auth_url: None,
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
    Ok(gateways_dir()?.join(name).join("metadata.json"))
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

pub fn store_gateway_metadata(name: &str, metadata: &GatewayMetadata) -> Result<()> {
    let path = stored_metadata_path(name)?;
    ensure_parent_dir_restricted(&path)?;
    let contents = serde_json::to_string_pretty(metadata)
        .into_diagnostic()
        .wrap_err("failed to serialize gateway metadata")?;
    std::fs::write(&path, contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write metadata to {}", path.display()))?;
    Ok(())
}

pub fn load_gateway_metadata(name: &str) -> Result<GatewayMetadata> {
    let path = stored_metadata_path(name)?;
    let contents = std::fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read metadata from {}", path.display()))?;
    serde_json::from_str(&contents)
        .into_diagnostic()
        .wrap_err("failed to parse gateway metadata")
}

/// Load gateway metadata if available.
pub fn get_gateway_metadata(name: &str) -> Option<GatewayMetadata> {
    load_gateway_metadata(name).ok()
}

/// Save the active gateway name to persistent storage.
pub fn save_active_gateway(name: &str) -> Result<()> {
    let path = active_gateway_path()?;
    ensure_parent_dir_restricted(&path)?;
    std::fs::write(&path, name)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write active gateway to {}", path.display()))?;
    Ok(())
}

/// Load the active gateway name from persistent storage.
///
/// Returns `None` if no active gateway has been set.
pub fn load_active_gateway() -> Option<String> {
    let path = active_gateway_path().ok()?;
    let contents = std::fs::read_to_string(&path).ok()?;
    let name = contents.trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

/// Save the last-used sandbox name for a gateway to persistent storage.
pub fn save_last_sandbox(gateway: &str, sandbox: &str) -> Result<()> {
    let path = last_sandbox_path(gateway)?;
    ensure_parent_dir_restricted(&path)?;
    std::fs::write(&path, sandbox)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write last sandbox to {}", path.display()))?;
    Ok(())
}

/// Load the last-used sandbox name for a gateway from persistent storage.
///
/// Returns `None` if no last sandbox has been set.
pub fn load_last_sandbox(gateway: &str) -> Option<String> {
    let path = last_sandbox_path(gateway).ok()?;
    let contents = std::fs::read_to_string(&path).ok()?;
    let name = contents.trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

/// Clear the last-used sandbox record for a gateway if it matches the given name.
///
/// This should be called after a sandbox is deleted so that subsequent commands
/// don't try to connect to a sandbox that no longer exists.
pub fn clear_last_sandbox_if_matches(gateway: &str, sandbox: &str) {
    if let Some(current) = load_last_sandbox(gateway) {
        if current == sandbox {
            if let Ok(path) = last_sandbox_path(gateway) {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

/// List all gateways that have stored metadata.
///
/// Scans `$XDG_CONFIG_HOME/openshell/gateways/` for subdirectories containing
/// `metadata.json` and returns the parsed metadata for each.
pub fn list_gateways() -> Result<Vec<GatewayMetadata>> {
    let dir = gateways_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut gateways = Vec::new();
    let entries = std::fs::read_dir(&dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read directory {}", dir.display()))?;

    for entry in entries {
        let entry = entry.into_diagnostic()?;
        let path = entry.path();
        // Only consider directories that contain a metadata.json file
        if path.is_dir() {
            let gateway_name = entry.file_name().to_string_lossy().to_string();
            if let Ok(metadata) = load_gateway_metadata(&gateway_name) {
                gateways.push(metadata);
            }
        }
    }

    // Sort by name for stable output
    gateways.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(gateways)
}

/// Remove the active gateway file (used when destroying the active gateway).
pub fn clear_active_gateway() -> Result<()> {
    let path = active_gateway_path()?;
    if path.exists() {
        std::fs::remove_file(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(())
}

/// Remove gateway metadata file.
pub fn remove_gateway_metadata(name: &str) -> Result<()> {
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
    fn local_gateway_metadata() {
        let meta = create_gateway_metadata("test", None, 8080);
        assert_eq!(meta.name, "test");
        assert_eq!(meta.gateway_endpoint, "https://127.0.0.1:8080");
        assert_eq!(meta.gateway_port, 8080);
        assert!(!meta.is_remote);
        assert!(meta.remote_host.is_none());
        assert!(meta.resolved_host.is_none());
    }

    #[test]
    fn local_gateway_metadata_custom_port() {
        let meta = create_gateway_metadata("test", None, 9090);
        assert_eq!(meta.gateway_endpoint, "https://127.0.0.1:9090");
        assert_eq!(meta.gateway_port, 9090);
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
    fn remote_gateway_metadata_has_resolved_host() {
        let opts = RemoteOptions::new("user@10.0.0.5");
        let meta = create_gateway_metadata("test", Some(&opts), 8080);
        assert!(meta.is_remote);
        assert_eq!(meta.remote_host.as_deref(), Some("user@10.0.0.5"));
        // When the host is a plain IP, ssh -G should resolve it to itself
        assert!(meta.resolved_host.is_some());
        assert_eq!(
            meta.gateway_endpoint,
            format!("https://{}:8080", meta.resolved_host.as_ref().unwrap())
        );
        assert_eq!(meta.gateway_port, 8080);
    }

    #[test]
    fn metadata_roundtrip() {
        let meta = GatewayMetadata {
            name: "test".to_string(),
            gateway_endpoint: "https://10.0.0.5:8080".to_string(),
            is_remote: true,
            gateway_port: 8080,
            remote_host: Some("user@openshell-dev".to_string()),
            resolved_host: Some("10.0.0.5".to_string()),
            auth_mode: None,
            edge_team_domain: None,
            edge_auth_url: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: GatewayMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.resolved_host.as_deref(), Some("10.0.0.5"));
        assert_eq!(parsed.gateway_endpoint, "https://10.0.0.5:8080");
        assert_eq!(parsed.gateway_port, 8080);
    }

    #[test]
    fn metadata_deserialize_without_resolved_host() {
        // Existing metadata files won't have the resolved_host field.
        // Ensure backwards compatibility via serde(default).
        let json = r#"{
            "name": "test",
            "gateway_endpoint": "http://myserver:8080",
            "is_remote": true,
            "gateway_port": 8080,
            "remote_host": "user@myserver"
        }"#;
        let parsed: GatewayMetadata = serde_json::from_str(json).unwrap();
        assert!(parsed.resolved_host.is_none());
    }

    #[test]
    fn local_gateway_metadata_with_gateway_host_override() {
        let meta = create_gateway_metadata_with_host(
            "test",
            None,
            8080,
            Some("host.docker.internal"),
            false,
        );
        assert_eq!(meta.name, "test");
        assert_eq!(meta.gateway_endpoint, "https://host.docker.internal:8080");
        assert_eq!(meta.gateway_port, 8080);
        assert!(!meta.is_remote);
        assert!(meta.remote_host.is_none());
        assert!(meta.resolved_host.is_none());
    }

    #[test]
    fn local_gateway_metadata_with_no_gateway_host_override() {
        // When gateway_host is None, behaviour matches create_gateway_metadata.
        let meta = create_gateway_metadata_with_host("test", None, 8080, None, false);
        assert_eq!(meta.gateway_endpoint, "https://127.0.0.1:8080");
    }

    #[test]
    fn local_gateway_metadata_with_tls_disabled() {
        let meta = create_gateway_metadata_with_host("test", None, 8080, None, true);
        assert_eq!(meta.gateway_endpoint, "http://127.0.0.1:8080");
        assert_eq!(meta.auth_mode.as_deref(), Some("plaintext"));
    }

    #[test]
    fn local_gateway_metadata_with_tls_disabled_and_gateway_host() {
        let meta = create_gateway_metadata_with_host(
            "test",
            None,
            8080,
            Some("host.docker.internal"),
            true,
        );
        assert_eq!(meta.gateway_endpoint, "http://host.docker.internal:8080");
        assert_eq!(meta.auth_mode.as_deref(), Some("plaintext"));
    }

    // ── GatewayMetadata::gateway_host() ──────────────────────────────

    #[test]
    fn gateway_host_returns_custom_host() {
        let meta =
            create_gateway_metadata_with_host("t", None, 8082, Some("host.docker.internal"), false);
        assert_eq!(meta.gateway_host(), Some("host.docker.internal"));
    }

    #[test]
    fn gateway_host_returns_none_for_loopback() {
        let meta = create_gateway_metadata("t", None, 8080);
        // Default endpoint is https://127.0.0.1:8080
        assert_eq!(meta.gateway_host(), None);
    }

    #[test]
    fn gateway_host_returns_none_for_localhost() {
        let meta = GatewayMetadata {
            name: "t".into(),
            gateway_endpoint: "https://localhost:8080".into(),
            is_remote: false,
            gateway_port: 8080,
            remote_host: None,
            resolved_host: None,
            auth_mode: None,
            edge_team_domain: None,
            edge_auth_url: None,
        };
        assert_eq!(meta.gateway_host(), None);
    }

    #[test]
    fn gateway_host_returns_ip_for_remote() {
        let meta = GatewayMetadata {
            name: "t".into(),
            gateway_endpoint: "https://10.0.0.5:8080".into(),
            is_remote: true,
            gateway_port: 8080,
            remote_host: Some("user@10.0.0.5".into()),
            resolved_host: Some("10.0.0.5".into()),
            auth_mode: None,
            edge_team_domain: None,
            edge_auth_url: None,
        };
        assert_eq!(meta.gateway_host(), Some("10.0.0.5"));
    }

    #[test]
    fn gateway_host_handles_http_scheme() {
        let meta =
            create_gateway_metadata_with_host("t", None, 8080, Some("host.docker.internal"), true);
        assert_eq!(meta.gateway_host(), Some("host.docker.internal"));
    }

    #[test]
    fn remote_gateway_metadata_with_tls_disabled() {
        let opts = RemoteOptions::new("user@10.0.0.5");
        let meta = create_gateway_metadata_with_host("test", Some(&opts), 8080, None, true);
        assert!(meta.is_remote);
        assert!(meta.gateway_endpoint.starts_with("http://"));
        assert!(!meta.gateway_endpoint.starts_with("https://"));
        assert_eq!(meta.auth_mode.as_deref(), Some("plaintext"));
    }

    // ── last-sandbox persistence ──────────────────────────────────────

    /// Helper: hold the shared XDG test lock, set `XDG_CONFIG_HOME` to a
    /// tempdir, run `f`, then restore the original value.
    #[allow(unsafe_code)]
    fn with_tmp_xdg<F: FnOnce()>(tmp: &std::path::Path, f: F) {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let orig = std::env::var("XDG_CONFIG_HOME").ok();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", tmp);
        }
        f();
        unsafe {
            match orig {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
    }

    #[test]
    fn save_and_load_last_sandbox_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            save_last_sandbox("mygateway", "dev-box").unwrap();
            assert_eq!(load_last_sandbox("mygateway"), Some("dev-box".to_string()));
        });
    }

    #[test]
    fn load_last_sandbox_returns_none_when_not_set() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            assert_eq!(load_last_sandbox("no-such-gateway"), None);
        });
    }

    #[test]
    fn save_last_sandbox_overwrites_previous() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            save_last_sandbox("g1", "first").unwrap();
            save_last_sandbox("g1", "second").unwrap();
            assert_eq!(load_last_sandbox("g1"), Some("second".to_string()));
        });
    }

    #[test]
    fn save_last_sandbox_creates_parent_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            // The gateway subdir doesn't exist yet — save should create it.
            save_last_sandbox("brand-new-gateway", "sb1").unwrap();
            assert_eq!(
                load_last_sandbox("brand-new-gateway"),
                Some("sb1".to_string())
            );
        });
    }

    #[test]
    fn load_last_sandbox_ignores_whitespace() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            // Write the file manually with surrounding whitespace.
            let path = last_sandbox_path("ws-gateway").unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "  my-sb \n").unwrap();
            assert_eq!(load_last_sandbox("ws-gateway"), Some("my-sb".to_string()));
        });
    }

    #[test]
    fn load_last_sandbox_returns_none_for_empty_file() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            let path = last_sandbox_path("empty-gateway").unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "   \n").unwrap();
            assert_eq!(load_last_sandbox("empty-gateway"), None);
        });
    }

    #[test]
    fn last_sandbox_is_per_gateway() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            save_last_sandbox("gateway-a", "sandbox-a").unwrap();
            save_last_sandbox("gateway-b", "sandbox-b").unwrap();
            assert_eq!(
                load_last_sandbox("gateway-a"),
                Some("sandbox-a".to_string())
            );
            assert_eq!(
                load_last_sandbox("gateway-b"),
                Some("sandbox-b".to_string())
            );
        });
    }
}
