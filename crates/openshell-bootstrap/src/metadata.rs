// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::paths::{
    last_sandbox_path, system_active_gateway_path, system_gateway_dir, system_gateways_dir,
    user_active_gateway_path, user_gateway_dir, user_gateways_dir, validated_gateway_name,
};
use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::paths::ensure_parent_dir_restricted;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Gateway metadata stored for CLI endpoint resolution and authentication.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

    /// Auth mode: `None` or `"mtls"` = mTLS, `"plaintext"` = direct HTTP,
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

    /// OIDC issuer URL (set when `auth_mode == "oidc"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_issuer: Option<String>,

    /// OIDC client ID for the CLI login flow (set when `auth_mode == "oidc"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_client_id: Option<String>,

    /// OIDC audience for the resource server (API). When different from
    /// `client_id`, the CLI requests this audience in the token exchange.
    /// When `None`, defaults to the `client_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_audience: Option<String>,

    /// Space-separated `OAuth2` scopes to request during OIDC login.
    /// When set, tokens will include these scopes for fine-grained access control.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_scopes: Option<String>,

    /// Local VM driver state directory for standalone VM gateways.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_driver_state_dir: Option<PathBuf>,
}

/// Storage layer that provides a gateway metadata record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayMetadataSource {
    /// Per-user metadata under `$XDG_CONFIG_HOME/openshell/gateways`.
    User,
    /// Installer-provided metadata under the system gateway registry.
    System,
}

impl GatewayMetadataSource {
    pub const fn label(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::System => "system",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ListedGateway {
    pub metadata: GatewayMetadata,
    pub source: GatewayMetadataSource,
}

fn user_gateway_metadata_path(name: &str) -> Result<PathBuf> {
    Ok(user_gateway_dir(name)?.join("metadata.json"))
}

fn system_gateway_metadata_path(name: &str) -> Result<PathBuf> {
    Ok(system_gateway_dir(name)?.join("metadata.json"))
}

fn resolve_gateway_metadata_path(name: &str) -> Result<Option<(PathBuf, GatewayMetadataSource)>> {
    let user = user_gateway_metadata_path(name)?;
    if user_entry_shadows_system(&user) {
        return Ok(Some((user, GatewayMetadataSource::User)));
    }

    let system = system_gateway_metadata_path(name)?;
    if system.exists() {
        return Ok(Some((system, GatewayMetadataSource::System)));
    }

    Ok(None)
}

fn parse_gateway_metadata(path: &Path) -> Result<GatewayMetadata> {
    let contents = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read metadata from {}", path.display()))?;
    serde_json::from_str(&contents)
        .into_diagnostic()
        .wrap_err("failed to parse gateway metadata")
}
fn user_entry_shadows_system(metadata_path: &Path) -> bool {
    metadata_path.try_exists().unwrap_or(true)
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
    let path = user_gateway_metadata_path(name)?;
    ensure_parent_dir_restricted(&path)?;
    let contents = serde_json::to_string_pretty(metadata)
        .into_diagnostic()
        .wrap_err("failed to serialize gateway metadata")?;
    std::fs::write(&path, contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write metadata to {}", path.display()))?;
    Ok(())
}

/// Return whether a gateway metadata record would resolve from user or system config.
pub fn gateway_metadata_source(name: &str) -> Result<Option<GatewayMetadataSource>> {
    Ok(resolve_gateway_metadata_path(name)?.map(|(_, source)| source))
}

pub fn load_gateway_metadata(name: &str) -> Result<GatewayMetadata> {
    let primary = user_gateway_metadata_path(name)?;
    let system = system_gateway_metadata_path(name)?;
    let Some((path, _source)) = resolve_gateway_metadata_path(name)? else {
        return Err(miette::miette!(
            "no metadata found for gateway '{name}' (looked in {} and {})",
            primary.display(),
            system.display(),
        ));
    };
    parse_gateway_metadata(&path)
}

/// Load gateway metadata if available.
pub fn get_gateway_metadata(name: &str) -> Option<GatewayMetadata> {
    load_gateway_metadata(name).ok()
}

/// Save the active gateway name to persistent storage.
pub fn save_active_gateway(name: &str) -> Result<()> {
    validated_gateway_name(name)?;
    let path = user_active_gateway_path()?;
    ensure_parent_dir_restricted(&path)?;
    std::fs::write(&path, name)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write active gateway to {}", path.display()))?;
    Ok(())
}

fn read_gateway_name(path: &Path) -> Option<String> {
    let value = read_nonempty_trimmed(path)?;
    match validated_gateway_name(&value) {
        Ok(_) => Some(value),
        Err(err) => {
            tracing::warn!(path = %path.display(), error = %err, "ignoring invalid active gateway name");
            None
        }
    }
}
fn read_nonempty_trimmed(path: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    let value = contents.trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// Load the per-user active gateway name from persistent storage.
///
/// Returns `None` if no user-scoped active gateway has been set.
pub fn load_user_active_gateway() -> Option<String> {
    user_active_gateway_path()
        .ok()
        .as_deref()
        .and_then(read_gateway_name)
}

/// Load the active gateway name from persistent storage.
///
/// Returns `None` if no active gateway has been set. Falls back to the
/// system-level active gateway file when no per-user selection exists, so
/// installer-provided defaults can take effect on a fresh system.
pub fn load_active_gateway() -> Option<String> {
    load_user_active_gateway().or_else(|| read_gateway_name(&system_active_gateway_path()))
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
    last_sandbox_path(gateway)
        .ok()
        .as_deref()
        .and_then(read_nonempty_trimmed)
}

/// Clear the last-used sandbox record for a gateway if it matches the given name.
///
/// This should be called after a sandbox is deleted so that subsequent commands
/// don't try to connect to a sandbox that no longer exists.
pub fn clear_last_sandbox_if_matches(gateway: &str, sandbox: &str) {
    if let Some(current) = load_last_sandbox(gateway)
        && current == sandbox
        && let Ok(path) = last_sandbox_path(gateway)
    {
        let _ = std::fs::remove_file(path);
    }
}

/// List all gateways that have stored metadata, along with the config layer
/// that supplied each record.
pub fn list_gateways_with_source() -> Result<Vec<ListedGateway>> {
    let mut gateways = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    let user_dir = user_gateways_dir()?;
    if user_dir.exists() {
        let entries = std::fs::read_dir(&user_dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read directory {}", user_dir.display()))?;
        for entry in entries {
            let entry = entry.into_diagnostic()?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let metadata_path = path.join("metadata.json");
            if !user_entry_shadows_system(&metadata_path) {
                continue;
            }

            let name = entry.file_name().to_string_lossy().to_string();
            if !seen.insert(name) {
                continue;
            }

            if let Ok(metadata) = parse_gateway_metadata(&metadata_path) {
                gateways.push(ListedGateway {
                    metadata,
                    source: GatewayMetadataSource::User,
                });
            }
        }
    }

    let system_dir = system_gateways_dir();
    if system_dir.exists() {
        let entries = std::fs::read_dir(&system_dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read directory {}", system_dir.display()))?;
        for entry in entries {
            let entry = entry.into_diagnostic()?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let name = entry.file_name().to_string_lossy().to_string();
            if seen.contains(&name) {
                continue;
            }

            let metadata_path = path.join("metadata.json");
            if let Ok(metadata) = parse_gateway_metadata(&metadata_path) {
                gateways.push(ListedGateway {
                    metadata,
                    source: GatewayMetadataSource::System,
                });
            }
        }
    }

    gateways.sort_by(|a, b| a.metadata.name.cmp(&b.metadata.name));
    Ok(gateways)
}

/// List all gateways that have stored metadata.
///
/// Scans `$XDG_CONFIG_HOME/openshell/gateways/` and the system registry under
/// `/etc/openshell/gateways/` (or `OPENSHELL_SYSTEM_GATEWAY_DIR/gateways/`
/// when set). Per-user entries shadow system entries on name collision.
pub fn list_gateways() -> Result<Vec<GatewayMetadata>> {
    Ok(list_gateways_with_source()?
        .into_iter()
        .map(|gateway| gateway.metadata)
        .collect())
}

/// Remove the active gateway file (used when destroying the active gateway).
pub fn clear_active_gateway() -> Result<()> {
    let path = user_active_gateway_path()?;
    if path.exists() {
        std::fs::remove_file(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(())
}

/// Remove gateway metadata file.
pub fn remove_gateway_metadata(name: &str) -> Result<()> {
    let path = user_gateway_metadata_path(name)?;
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
    fn metadata_roundtrip() {
        let meta = GatewayMetadata {
            name: "test".to_string(),
            gateway_endpoint: "https://10.0.0.5:8080".to_string(),
            is_remote: true,
            gateway_port: 8080,
            remote_host: Some("user@openshell-dev".to_string()),
            resolved_host: Some("10.0.0.5".to_string()),
            ..Default::default()
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

    // ── last-sandbox persistence ──────────────────────────────────────

    /// Helper: hold the shared XDG test lock, set `XDG_CONFIG_HOME` to a
    /// tempdir, run `f`, then restore the original value.
    #[allow(unsafe_code)]
    fn with_tmp_xdg<F: FnOnce()>(tmp: &Path, f: F) {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let orig_xdg = std::env::var("XDG_CONFIG_HOME").ok();
        let orig_sys = std::env::var(crate::paths::SYSTEM_GATEWAY_DIR_ENV).ok();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", tmp);
            std::env::remove_var(crate::paths::SYSTEM_GATEWAY_DIR_ENV);
        }
        f();
        unsafe {
            match orig_xdg {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
            match orig_sys {
                Some(v) => std::env::set_var(crate::paths::SYSTEM_GATEWAY_DIR_ENV, v),
                None => std::env::remove_var(crate::paths::SYSTEM_GATEWAY_DIR_ENV),
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

    // ── system gateway dir fallback ───────────────────────────────────

    /// Helper: hold the shared XDG test lock, point `XDG_CONFIG_HOME` at
    /// `user` and `OPENSHELL_SYSTEM_GATEWAY_DIR` at the system config root,
    /// run `f`, then restore both env vars.
    #[allow(unsafe_code)]
    fn with_tmp_xdg_and_system<F: FnOnce()>(user: &Path, system: &Path, f: F) {
        let _guard = crate::XDG_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let orig_xdg = std::env::var("XDG_CONFIG_HOME").ok();
        let orig_sys = std::env::var(crate::paths::SYSTEM_GATEWAY_DIR_ENV).ok();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", user);
            std::env::set_var(crate::paths::SYSTEM_GATEWAY_DIR_ENV, system);
        }
        f();
        unsafe {
            match orig_xdg {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
            match orig_sys {
                Some(v) => std::env::set_var(crate::paths::SYSTEM_GATEWAY_DIR_ENV, v),
                None => std::env::remove_var(crate::paths::SYSTEM_GATEWAY_DIR_ENV),
            }
        }
    }

    /// Write a `<gateways-dir>/<name>/metadata.json` file for the given endpoint.
    fn write_system_metadata(dir: &Path, name: &str, endpoint: &str) {
        let gw_dir = dir.join(name);
        std::fs::create_dir_all(&gw_dir).unwrap();
        let meta = GatewayMetadata {
            name: name.to_string(),
            gateway_endpoint: endpoint.to_string(),
            ..Default::default()
        };
        std::fs::write(
            gw_dir.join("metadata.json"),
            serde_json::to_string(&meta).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn system_gateway_last_sandbox_persists_in_user_config_without_shadowing() {
        let user = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        with_tmp_xdg_and_system(user.path(), system.path(), || {
            write_system_metadata(&system.path().join("gateways"), "shared", "https://system");

            save_last_sandbox("shared", "sb-123").unwrap();

            assert_eq!(load_last_sandbox("shared"), Some("sb-123".to_string()));
            assert_eq!(
                gateway_metadata_source("shared").unwrap(),
                Some(GatewayMetadataSource::System)
            );
            assert_eq!(
                load_gateway_metadata("shared").unwrap().gateway_endpoint,
                "https://system"
            );

            let user_gateway_dir = user_gateway_metadata_path("shared")
                .unwrap()
                .parent()
                .unwrap()
                .to_path_buf();
            assert!(user_gateway_dir.join("last_sandbox").exists());
            assert!(!user_gateway_dir.join("metadata.json").exists());
        });
    }

    #[test]
    fn system_gateway_last_sandbox_creates_user_parent_dir_without_metadata() {
        let user = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        with_tmp_xdg_and_system(user.path(), system.path(), || {
            write_system_metadata(&system.path().join("gateways"), "shared", "https://system");

            let user_gateway_dir = user_gateway_metadata_path("shared")
                .unwrap()
                .parent()
                .unwrap()
                .to_path_buf();
            assert!(!user_gateway_dir.exists());

            save_last_sandbox("shared", "sb-123").unwrap();

            assert!(user_gateway_dir.is_dir());
            assert_eq!(
                std::fs::read_to_string(user_gateway_dir.join("last_sandbox")).unwrap(),
                "sb-123"
            );
            assert!(!user_gateway_dir.join("metadata.json").exists());
            assert_eq!(
                gateway_metadata_source("shared").unwrap(),
                Some(GatewayMetadataSource::System)
            );
        });
    }

    #[test]
    fn clearing_system_gateway_last_sandbox_keeps_system_metadata_visible() {
        let user = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        with_tmp_xdg_and_system(user.path(), system.path(), || {
            write_system_metadata(&system.path().join("gateways"), "shared", "https://system");
            save_last_sandbox("shared", "sb-123").unwrap();

            clear_last_sandbox_if_matches("shared", "sb-123");

            assert_eq!(load_last_sandbox("shared"), None);
            let gateways = list_gateways_with_source().unwrap();
            assert_eq!(gateways.len(), 1);
            assert_eq!(gateways[0].metadata.name, "shared");
            assert_eq!(gateways[0].source, GatewayMetadataSource::System);
            assert_eq!(gateways[0].metadata.gateway_endpoint, "https://system");
        });
    }
    #[test]
    fn load_user_active_gateway_does_not_fall_back_to_system_dir() {
        let user = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        with_tmp_xdg_and_system(user.path(), system.path(), || {
            std::fs::write(system.path().join("active_gateway"), "from-system").unwrap();
            assert_eq!(load_user_active_gateway(), None);
        });
    }
    #[test]
    fn load_active_gateway_falls_back_to_system_dir() {
        let user = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        with_tmp_xdg_and_system(user.path(), system.path(), || {
            std::fs::write(system.path().join("active_gateway"), "from-system").unwrap();
            assert_eq!(load_active_gateway(), Some("from-system".to_string()));
        });
    }

    #[test]
    fn load_active_gateway_prefers_user_over_system() {
        let user = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        with_tmp_xdg_and_system(user.path(), system.path(), || {
            save_active_gateway("from-user").unwrap();
            std::fs::write(system.path().join("active_gateway"), "from-system").unwrap();
            assert_eq!(load_active_gateway(), Some("from-user".to_string()));
        });
    }

    #[test]
    fn load_gateway_metadata_falls_back_to_system_dir() {
        let user = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        with_tmp_xdg_and_system(user.path(), system.path(), || {
            write_system_metadata(
                &system.path().join("gateways"),
                "sys-gw",
                "unix:///tmp/sys.sock",
            );
            let meta = load_gateway_metadata("sys-gw").unwrap();
            assert_eq!(meta.name, "sys-gw");
            assert_eq!(meta.gateway_endpoint, "unix:///tmp/sys.sock");
        });
    }

    #[test]
    fn gateway_metadata_source_reports_user_system_and_missing() {
        let user = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        with_tmp_xdg_and_system(user.path(), system.path(), || {
            write_system_metadata(
                &system.path().join("gateways"),
                "sys-gw",
                "unix:///tmp/sys.sock",
            );
            assert_eq!(
                gateway_metadata_source("sys-gw").unwrap(),
                Some(GatewayMetadataSource::System)
            );

            let user_meta = GatewayMetadata {
                name: "user-gw".to_string(),
                gateway_endpoint: "https://user-endpoint".to_string(),
                ..Default::default()
            };
            store_gateway_metadata("user-gw", &user_meta).unwrap();
            assert_eq!(
                gateway_metadata_source("user-gw").unwrap(),
                Some(GatewayMetadataSource::User)
            );

            assert_eq!(gateway_metadata_source("missing").unwrap(), None);
        });
    }

    #[test]
    fn load_gateway_metadata_error_mentions_both_search_paths() {
        let user = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        with_tmp_xdg_and_system(user.path(), system.path(), || {
            let err = load_gateway_metadata("missing").unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("missing"), "expected name in error: {msg}");
            assert!(
                msg.contains(user.path().to_str().unwrap()),
                "expected user path in error: {msg}"
            );
            assert!(
                msg.contains(system.path().to_str().unwrap()),
                "expected system path in error: {msg}"
            );
        });
    }

    #[test]
    fn load_gateway_metadata_prefers_user_over_system() {
        let user = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        with_tmp_xdg_and_system(user.path(), system.path(), || {
            let user_meta = GatewayMetadata {
                name: "shared".to_string(),
                gateway_endpoint: "https://user-endpoint".to_string(),
                ..Default::default()
            };
            store_gateway_metadata("shared", &user_meta).unwrap();
            write_system_metadata(
                &system.path().join("gateways"),
                "shared",
                "https://system-endpoint",
            );
            let meta = load_gateway_metadata("shared").unwrap();
            assert_eq!(meta.gateway_endpoint, "https://user-endpoint");
        });
    }

    #[test]
    fn list_gateways_merges_user_and_system() {
        let user = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        with_tmp_xdg_and_system(user.path(), system.path(), || {
            let user_meta = GatewayMetadata {
                name: "alpha".to_string(),
                gateway_endpoint: "https://alpha".to_string(),
                ..Default::default()
            };
            store_gateway_metadata("alpha", &user_meta).unwrap();
            write_system_metadata(&system.path().join("gateways"), "beta", "https://beta");
            let gateways = list_gateways_with_source().unwrap();
            assert_eq!(gateways.len(), 2);
            assert_eq!(gateways[0].metadata.name, "alpha");
            assert_eq!(gateways[0].source, GatewayMetadataSource::User);
            assert_eq!(gateways[1].metadata.name, "beta");
            assert_eq!(gateways[1].source, GatewayMetadataSource::System);
        });
    }

    #[test]
    fn list_gateways_user_shadows_system_on_collision() {
        let user = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        with_tmp_xdg_and_system(user.path(), system.path(), || {
            let user_meta = GatewayMetadata {
                name: "local-vm".to_string(),
                gateway_endpoint: "https://user-override".to_string(),
                ..Default::default()
            };
            store_gateway_metadata("local-vm", &user_meta).unwrap();
            write_system_metadata(
                &system.path().join("gateways"),
                "local-vm",
                "unix:///tmp/sys.sock",
            );
            let gateways = list_gateways_with_source().unwrap();
            assert_eq!(gateways.len(), 1);
            assert_eq!(
                gateways[0].metadata.gateway_endpoint,
                "https://user-override"
            );
            assert_eq!(gateways[0].source, GatewayMetadataSource::User);
        });
    }

    #[test]
    fn list_gateways_invalid_user_entry_still_shadows_system() {
        let user = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        with_tmp_xdg_and_system(user.path(), system.path(), || {
            let user_metadata_path = user_gateway_metadata_path("shared").unwrap();
            std::fs::create_dir_all(user_metadata_path.parent().unwrap()).unwrap();
            std::fs::write(&user_metadata_path, "{not-json").unwrap();

            write_system_metadata(&system.path().join("gateways"), "shared", "https://system");

            let gateways = list_gateways_with_source().unwrap();
            assert!(gateways.is_empty());
        });
    }
    #[test]
    fn list_gateways_empty_user_dir_does_not_hide_system() {
        let user = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        with_tmp_xdg_and_system(user.path(), system.path(), || {
            let user_meta = GatewayMetadata {
                name: "shared".to_string(),
                gateway_endpoint: "https://user".to_string(),
                ..Default::default()
            };
            store_gateway_metadata("shared", &user_meta).unwrap();
            remove_gateway_metadata("shared").unwrap();

            let user_gateway_dir = user_gateway_metadata_path("shared")
                .unwrap()
                .parent()
                .unwrap()
                .to_path_buf();
            assert!(user_gateway_dir.is_dir());
            assert!(!user_gateway_dir.join("metadata.json").exists());

            write_system_metadata(&system.path().join("gateways"), "shared", "https://system");

            let gateways = list_gateways_with_source().unwrap();
            assert_eq!(gateways.len(), 1);
            assert_eq!(gateways[0].metadata.gateway_endpoint, "https://system");
            assert_eq!(gateways[0].source, GatewayMetadataSource::System);
        });
    }

    #[test]
    fn gateway_names_must_be_single_path_components() {
        let user = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        with_tmp_xdg_and_system(user.path(), system.path(), || {
            let meta = GatewayMetadata {
                name: "shared".to_string(),
                gateway_endpoint: "https://example.com".to_string(),
                ..Default::default()
            };
            assert!(store_gateway_metadata("../escape", &meta).is_err());
            assert!(load_gateway_metadata("../escape").is_err());
            assert!(save_last_sandbox("../escape", "sb-123").is_err());
            assert!(save_active_gateway("../escape").is_err());
        });
    }

    #[test]
    fn load_active_gateway_ignores_invalid_user_name_and_falls_back_to_system() {
        let user = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        with_tmp_xdg_and_system(user.path(), system.path(), || {
            std::fs::write(user.path().join("active_gateway"), "../escape").unwrap();
            std::fs::write(system.path().join("active_gateway"), "system-default").unwrap();

            assert_eq!(load_user_active_gateway(), None);
            assert_eq!(load_active_gateway(), Some("system-default".to_string()));
        });
    }
}
