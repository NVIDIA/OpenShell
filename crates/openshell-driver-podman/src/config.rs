// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

/// Default Podman bridge network name.
pub const DEFAULT_NETWORK_NAME: &str = "openshell";
pub const MACOS_PODMAN_MACHINE_HOST_GATEWAY_IP: &str = "192.168.127.254";
/// Default Podman stop timeout in seconds (SIGTERM → SIGKILL).
pub const DEFAULT_PODMAN_STOP_TIMEOUT_SECS: u32 = 45;

// Re-export the shared default so existing imports inside this crate keep working.
pub use openshell_core::config::DEFAULT_SANDBOX_PIDS_LIMIT;

/// Image pull policy for sandbox and supervisor images.
///
/// Controls when the Podman driver fetches a newer copy of an OCI image
/// from the registry.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImagePullPolicy {
    /// Always pull, even if a local copy exists.
    Always,
    /// Pull only when no local copy exists (default).
    #[default]
    Missing,
    /// Never pull; fail if not available locally.
    Never,
    /// Pull only if the remote image is newer.
    Newer,
}

impl ImagePullPolicy {
    /// Return the policy string expected by the Podman libpod API.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Missing => "missing",
            Self::Never => "never",
            Self::Newer => "newer",
        }
    }
}

impl std::fmt::Display for ImagePullPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ImagePullPolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "always" => Ok(Self::Always),
            "missing" => Ok(Self::Missing),
            "never" => Ok(Self::Never),
            "newer" => Ok(Self::Newer),
            other => Err(format!(
                "invalid pull policy '{other}'; expected one of: always, missing, never, newer"
            )),
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PodmanComputeConfig {
    /// Podman API Unix socket. When unset, use the socket selected by
    /// gateway auto-detection.
    pub socket_path: Option<PathBuf>,
    /// Default OCI image for sandboxes.
    pub default_image: String,
    /// Image pull policy for sandbox images.
    pub image_pull_policy: ImagePullPolicy,
    /// Gateway gRPC endpoint the sandbox connects back to.
    ///
    /// When empty, the driver auto-detects the endpoint using
    /// `gateway_port` and `host.containers.internal`.
    pub grpc_endpoint: String,
    /// Port the gateway server is actually listening on.
    ///
    /// Used by the driver's auto-detection fallback when `grpc_endpoint`
    /// is empty.  The server must set this to `config.bind_address.port()`
    /// so the correct port is used even when `--port` differs from the
    /// default.  Defaults to [`openshell_core::config::DEFAULT_SERVER_PORT`].
    pub gateway_port: u16,
    /// Unix socket path the in-container supervisor bridges relay traffic to.
    pub sandbox_ssh_socket_path: String,
    /// Name of the Podman bridge network.
    /// Created automatically if it does not exist.
    pub network_name: String,
    /// Host gateway IP used for sandbox host aliases.
    ///
    /// Empty uses Podman's `host-gateway` resolver. macOS defaults to
    /// gvproxy's host-loopback IP because stale Podman machines may fail to
    /// resolve `host-gateway` while still serving `host.containers.internal`
    /// through gvproxy.
    pub host_gateway_ip: String,
    /// Container stop timeout in seconds (SIGTERM → SIGKILL).
    pub stop_timeout_secs: u32,
    /// OCI image containing the openshell-sandbox supervisor binary.
    /// Mounted read-only into sandbox containers at /opt/openshell/bin
    /// using Podman's `type=image` mount.
    pub supervisor_image: String,
    /// Host path to the CA certificate for sandbox mTLS.
    ///
    /// When all three TLS paths (`guest_tls_ca`, `guest_tls_cert`,
    /// `guest_tls_key`) are set, the driver bind-mounts them into sandbox
    /// containers and switches the auto-detected endpoint from `http://`
    /// to `https://`.
    pub guest_tls_ca: Option<PathBuf>,
    /// Host path to the client certificate for sandbox mTLS.
    pub guest_tls_cert: Option<PathBuf>,
    /// Host path to the client private key for sandbox mTLS.
    pub guest_tls_key: Option<PathBuf>,
    /// Container cgroup PID limit for Podman-managed sandboxes.
    ///
    /// Set to `0` to leave Podman's runtime/default PID limit unchanged.
    pub sandbox_pids_limit: i64,
    /// Allow sandbox requests to attach host bind mounts through
    /// `template.driver_config`.
    #[serde(default)]
    pub enable_bind_mounts: bool,
    /// Health check interval in seconds for sandbox containers.
    ///
    /// Podman runs the health check command at this interval to determine
    /// container readiness. Lower values detect readiness faster but
    /// increase process churn (each check spawns a conmon subprocess).
    /// Set to `0` to disable health checks entirely.
    /// Defaults to [`DEFAULT_HEALTH_CHECK_INTERVAL_SECS`] (10 seconds).
    pub health_check_interval_secs: u64,
    /// Corporate forward proxy URL passed to the in-container supervisor
    /// (e.g. `http://proxy.corp.com:8080`).
    ///
    /// The supervisor chains policy-approved TLS tunnels through this proxy
    /// with HTTP CONNECT instead of dialing upstream destinations directly.
    /// Only `http://` proxy URLs in explicit `http://host:port` form (scheme
    /// and port required) are supported. This is an operator-owned egress
    /// boundary delivered on the supervisor's command line, so
    /// sandbox/template environment cannot override it, and the conventional
    /// `HTTPS_PROXY` variables are not used.
    pub https_proxy: Option<String>,
    /// Comma-separated `NO_PROXY` list passed alongside the proxy URL (e.g.
    /// `*.svc.cluster.local,10.0.0.0/8`). Destinations matching an entry are
    /// dialed directly instead of through the corporate proxy. Entries take
    /// an optional `:port` qualifier that limits them to that destination
    /// port, and IP/CIDR entries also match hostnames through their
    /// validated DNS resolution.
    pub no_proxy: Option<String>,
    /// Path (on the gateway host) to a file containing the corporate proxy
    /// credentials as `user:pass`.
    ///
    /// Credentials must be supplied through this file, never embedded in the
    /// proxy URL: an inline `user:pass@` in `https_proxy` is
    /// rejected at startup because it would leak into `gateway.toml` and
    /// container metadata. The gateway reads this file at sandbox-create time
    /// and delivers it to the supervisor through a root-only secret mount.
    pub proxy_auth_file: Option<String>,
    /// Explicit acknowledgement that proxy credentials are sent in cleartext.
    ///
    /// `Proxy-Authorization: Basic` is base64, not encryption, and the
    /// connection to an `http://` corporate proxy is plain TCP, so anyone on
    /// the network path between the sandbox host and the proxy can recover
    /// the credential. Setting `proxy_auth_file` therefore requires
    /// `proxy_auth_allow_insecure = true`; without it the configuration is
    /// rejected at startup. Set it only when the path to the proxy is a
    /// trusted network segment.
    pub proxy_auth_allow_insecure: Option<bool>,
    /// Send the destination *hostname* in CONNECT requests to the corporate
    /// proxy instead of a validated IP.
    ///
    /// By default the supervisor CONNECTs to an address that already passed
    /// SSRF and `allowed_ips` validation, so the proxy performs no DNS
    /// resolution and the tunnel stays bound to the validated answer. Set
    /// this to `true` only when the proxy's ACLs filter on hostnames and
    /// reject IP CONNECT targets: the proxy then resolves the name itself,
    /// so a name that resolves differently at the proxy (split-horizon DNS,
    /// rebinding) can reach destinations the sandbox policy never approved,
    /// and the proxy's own ACLs become the effective egress control. Prefer
    /// pointing the gateway host at the corporate resolver so validated-IP
    /// CONNECT works in split-horizon networks.
    pub proxy_connect_by_hostname: Option<bool>,
    /// User namespace mode for sandbox containers (e.g. `auto`, `private`).
    /// When unset, containers use the default user namespace.
    pub userns: Option<String>,
    /// Explicit UID mappings for `userns = "private"`.
    /// Each entry is `"container_id:host_id:size"`.
    #[serde(default)]
    pub uidmap: Vec<String>,
    /// Explicit GID mappings for `userns = "private"`.
    /// Each entry is `"container_id:host_id:size"`.
    #[serde(default)]
    pub gidmap: Vec<String>,
}

pub const DEFAULT_HEALTH_CHECK_INTERVAL_SECS: u64 = 10;

/// Parse a single `"container_id:host_id:size"` mapping entry.
///
/// Returns `(container_id, host_id, size)` on success.
pub fn parse_id_map_entry(
    field: &str,
    entry: &str,
) -> Result<(u32, u32, u32), crate::client::PodmanApiError> {
    let parts: Vec<&str> = entry.split(':').collect();
    if parts.len() != 3 {
        return Err(crate::client::PodmanApiError::InvalidInput(format!(
            "{field} entry '{entry}' must be 'container_id:host_id:size'",
        )));
    }
    let container_id: u32 = parts[0].parse().map_err(|_| {
        crate::client::PodmanApiError::InvalidInput(format!(
            "{field} entry '{entry}': container_id must be a non-negative integer",
        ))
    })?;
    let host_id: u32 = parts[1].parse().map_err(|_| {
        crate::client::PodmanApiError::InvalidInput(format!(
            "{field} entry '{entry}': host_id must be a non-negative integer",
        ))
    })?;
    let size: u32 = parts[2].parse().map_err(|_| {
        crate::client::PodmanApiError::InvalidInput(format!(
            "{field} entry '{entry}': size must be a non-negative integer",
        ))
    })?;
    if size == 0 {
        return Err(crate::client::PodmanApiError::InvalidInput(format!(
            "{field} entry '{entry}': size must be greater than 0",
        )));
    }
    Ok((container_id, host_id, size))
}

impl PodmanComputeConfig {
    /// Returns `true` when all three TLS paths are configured.
    #[must_use]
    pub fn tls_enabled(&self) -> bool {
        self.guest_tls_ca.is_some() && self.guest_tls_cert.is_some() && self.guest_tls_key.is_some()
    }

    /// Validate TLS configuration consistency.
    ///
    /// Returns `Ok(())` when either all three TLS paths are set (full mTLS)
    /// or none are set (plaintext).  Returns an error naming the missing
    /// fields when only a subset is provided — this prevents silent
    /// fallback to plaintext when an operator partially configures mTLS.
    pub fn validate_tls_config(&self) -> Result<(), crate::client::PodmanApiError> {
        let has_ca = self.guest_tls_ca.is_some();
        let has_cert = self.guest_tls_cert.is_some();
        let has_key = self.guest_tls_key.is_some();

        // All set or none set — both are valid.
        if (has_ca && has_cert && has_key) || (!has_ca && !has_cert && !has_key) {
            return Ok(());
        }

        let mut missing = Vec::new();
        if !has_ca {
            missing.push("--podman-tls-ca / OPENSHELL_PODMAN_TLS_CA");
        }
        if !has_cert {
            missing.push("--podman-tls-cert / OPENSHELL_PODMAN_TLS_CERT");
        }
        if !has_key {
            missing.push("--podman-tls-key / OPENSHELL_PODMAN_TLS_KEY");
        }

        Err(crate::client::PodmanApiError::InvalidInput(format!(
            "Partial TLS configuration: all three TLS paths must be provided together. \
             Missing: {}",
            missing.join(", ")
        )))
    }

    /// Validate runtime resource-limit configuration.
    pub fn validate_runtime_limits(&self) -> Result<(), crate::client::PodmanApiError> {
        if self.sandbox_pids_limit < 0 {
            return Err(crate::client::PodmanApiError::InvalidInput(
                "sandbox_pids_limit must be zero or greater".to_string(),
            ));
        }
        Ok(())
    }

    /// Validate optional corporate proxy configuration.
    ///
    /// Shares validation semantics with the in-container supervisor through
    /// [`openshell_core::driver_utils::parse_upstream_proxy_url`], so a value
    /// accepted here can never be rejected by the supervisor at sandbox
    /// startup (or vice versa). The supervisor only supports `http://`
    /// forward proxies, so other schemes are rejected at config time instead
    /// of failing inside every sandbox. Credentials must be supplied through
    /// `proxy_auth_file`; an inline `user:pass@` in the URL is rejected
    /// because it would otherwise be stored in `gateway.toml` and exposed in
    /// container metadata.
    pub fn validate_proxy_config(&self) -> Result<(), crate::client::PodmanApiError> {
        use openshell_core::driver_utils::{UpstreamProxyUrlError, parse_upstream_proxy_url};
        if let Some(url) = &self.https_proxy {
            parse_upstream_proxy_url(url).map_err(|err| {
                crate::client::PodmanApiError::InvalidInput(match err {
                    UpstreamProxyUrlError::Empty => {
                        "https_proxy must not be empty when set".to_string()
                    }
                    UpstreamProxyUrlError::InlineCredentials => {
                        "https_proxy must not embed credentials in the URL; supply them via \
                         proxy_auth_file so they are not stored in config or container metadata"
                            .to_string()
                    }
                    err => format!("https_proxy {err}"),
                })
            })?;
        }

        // The supervisor treats a present-but-empty driver-supplied argument
        // as a fatal misconfiguration, so never accept (and later pass) one.
        if let Some(list) = self.no_proxy.as_deref() {
            if list.trim().is_empty() {
                return Err(crate::client::PodmanApiError::InvalidInput(
                    "no_proxy must not be empty when set; omit it instead".to_string(),
                ));
            }
            // A bypass list only makes sense relative to a proxy boundary. An
            // operator who set one believed proxying was in effect, so accepting
            // it while all egress dials directly would hide a fail-open state.
            if self.https_proxy.is_none() {
                return Err(crate::client::PodmanApiError::InvalidInput(
                    "no_proxy is set but no https_proxy is configured".to_string(),
                ));
            }
        }

        if let Some(path) = self.proxy_auth_file.as_deref() {
            if path.trim().is_empty() {
                return Err(crate::client::PodmanApiError::InvalidInput(
                    "proxy_auth_file must not be empty when set".to_string(),
                ));
            }
            if self.https_proxy.is_none() {
                return Err(crate::client::PodmanApiError::InvalidInput(
                    "proxy_auth_file is set but no https_proxy is configured".to_string(),
                ));
            }
            // Basic auth over the plain-TCP proxy connection is readable by
            // anyone on the network path; sending it requires an explicit
            // operator acknowledgement rather than being an implicit side
            // effect of configuring credentials.
            if self.proxy_auth_allow_insecure != Some(true) {
                return Err(crate::client::PodmanApiError::InvalidInput(
                    "proxy_auth_file sends the credential as cleartext Basic auth over the \
                     plain-TCP connection to the http:// proxy; set proxy_auth_allow_insecure \
                     = true to accept that exposure, or remove proxy_auth_file"
                        .to_string(),
                ));
            }
        } else if self.proxy_auth_allow_insecure.is_some() {
            // The acknowledgement without credentials means the operator
            // believed an auth file was configured; surface the mismatch.
            return Err(crate::client::PodmanApiError::InvalidInput(
                "proxy_auth_allow_insecure is set but no proxy_auth_file is configured".to_string(),
            ));
        }

        // The CONNECT-target mode only means something relative to a proxy
        // boundary the operator believed was in effect.
        if self.proxy_connect_by_hostname.is_some() && self.https_proxy.is_none() {
            return Err(crate::client::PodmanApiError::InvalidInput(
                "proxy_connect_by_hostname is set but no https_proxy is configured".to_string(),
            ));
        }
        Ok(())
    }

    /// Validate and canonicalize the optional `userns` mode.
    ///
    /// Supported modes: `auto` (with optional params, e.g. `auto:size=65536`),
    /// `host`, `keep-id` (with optional params), `no-map` (alias `nomap`),
    /// and `private` (requires explicit `uidmap`/`gidmap`).
    /// Modes that don't accept parameters (`host`, `no-map`, `private`) are
    /// rejected when a colon-separated suffix is present.
    ///
    /// On success, `self.userns` is rewritten with the canonical lowercase
    /// mode string so downstream code can rely on exact matches.
    pub fn canonicalize_userns(&mut self) -> Result<(), crate::client::PodmanApiError> {
        let Some(mode) = self.userns.as_deref() else {
            return Ok(());
        };
        let (base, has_params) = mode
            .split_once(':')
            .map_or((mode, false), |(b, _)| (b, true));
        let canonical = match base.to_ascii_lowercase().as_str() {
            "auto" => "auto",
            "host" => "host",
            "keep-id" => "keep-id",
            "nomap" | "no-map" => "no-map",
            "private" => "private",
            _ => {
                return Err(crate::client::PodmanApiError::InvalidInput(format!(
                    "unsupported userns mode '{mode}'; \
                     supported modes: auto, host, keep-id, no-map, private",
                )));
            }
        };
        if has_params {
            match canonical {
                "auto" | "keep-id" => {}
                _ => {
                    return Err(crate::client::PodmanApiError::InvalidInput(format!(
                        "userns mode '{canonical}' does not accept parameters",
                    )));
                }
            }
        }
        self.userns = Some(if has_params {
            let params = mode.split_once(':').unwrap().1;
            format!("{canonical}:{params}")
        } else {
            canonical.to_string()
        });
        Ok(())
    }

    /// Validate `uidmap`/`gidmap` consistency with the userns mode.
    ///
    /// `private` requires at least one entry in both `uidmap` and `gidmap`;
    /// other modes (or no userns) reject non-empty mappings. Each entry must
    /// be `"container_id:host_id:size"` with `size > 0`.
    pub fn validate_userns_mappings(&self) -> Result<(), crate::client::PodmanApiError> {
        let is_private = self
            .userns
            .as_deref()
            .is_some_and(|m| m.eq_ignore_ascii_case("private"));

        if is_private {
            if self.uidmap.is_empty() || self.gidmap.is_empty() {
                return Err(crate::client::PodmanApiError::InvalidInput(
                    "userns mode 'private' requires at least one entry in both \
                     uidmap and gidmap"
                        .to_string(),
                ));
            }
        } else if !self.uidmap.is_empty() || !self.gidmap.is_empty() {
            return Err(crate::client::PodmanApiError::InvalidInput(
                "uidmap/gidmap are only valid with userns = \"private\"".to_string(),
            ));
        }

        for (field, entries) in [("uidmap", &self.uidmap), ("gidmap", &self.gidmap)] {
            for entry in entries {
                parse_id_map_entry(field, entry)?;
            }
        }
        Ok(())
    }

    /// Validate optional host gateway override.
    pub fn validate_host_gateway_ip(&self) -> Result<(), crate::client::PodmanApiError> {
        let trimmed = self.host_gateway_ip.trim();
        if trimmed.is_empty() {
            return Ok(());
        }

        trimmed.parse::<IpAddr>().map(|_| ()).map_err(|err| {
            crate::client::PodmanApiError::InvalidInput(format!(
                "invalid host_gateway_ip value '{trimmed}': {err}"
            ))
        })
    }

    /// Resolve the default host gateway override for the current platform.
    #[must_use]
    pub fn default_host_gateway_ip() -> String {
        #[cfg(target_os = "macos")]
        {
            MACOS_PODMAN_MACHINE_HOST_GATEWAY_IP.to_string()
        }
        #[cfg(not(target_os = "macos"))]
        {
            String::new()
        }
    }
}

impl Default for PodmanComputeConfig {
    fn default() -> Self {
        Self {
            socket_path: None,
            default_image: openshell_core::image::default_sandbox_image(),
            image_pull_policy: ImagePullPolicy::default(),
            grpc_endpoint: String::new(),
            gateway_port: openshell_core::config::DEFAULT_SERVER_PORT,
            sandbox_ssh_socket_path: openshell_core::container_paths::SSH_SOCKET_PATH.to_string(),
            network_name: DEFAULT_NETWORK_NAME.to_string(),
            host_gateway_ip: Self::default_host_gateway_ip(),
            stop_timeout_secs: DEFAULT_PODMAN_STOP_TIMEOUT_SECS,
            supervisor_image: openshell_core::config::default_supervisor_image(),
            guest_tls_ca: None,
            guest_tls_cert: None,
            guest_tls_key: None,
            sandbox_pids_limit: DEFAULT_SANDBOX_PIDS_LIMIT,
            enable_bind_mounts: false,
            health_check_interval_secs: DEFAULT_HEALTH_CHECK_INTERVAL_SECS,
            https_proxy: None,
            no_proxy: None,
            proxy_auth_file: None,
            proxy_auth_allow_insecure: None,
            proxy_connect_by_hostname: None,
            userns: None,
            uidmap: Vec::new(),
            gidmap: Vec::new(),
        }
    }
}

impl std::fmt::Debug for PodmanComputeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PodmanComputeConfig")
            .field("socket_path", &self.socket_path)
            .field("default_image", &self.default_image)
            .field("image_pull_policy", &self.image_pull_policy.as_str())
            .field("grpc_endpoint", &self.grpc_endpoint)
            .field("gateway_port", &self.gateway_port)
            .field("sandbox_ssh_socket_path", &self.sandbox_ssh_socket_path)
            .field("network_name", &self.network_name)
            .field("host_gateway_ip", &self.host_gateway_ip)
            .field("stop_timeout_secs", &self.stop_timeout_secs)
            .field("supervisor_image", &self.supervisor_image)
            .field("guest_tls_ca", &self.guest_tls_ca)
            .field("guest_tls_cert", &self.guest_tls_cert)
            .field("guest_tls_key", &self.guest_tls_key)
            .field("sandbox_pids_limit", &self.sandbox_pids_limit)
            .field("enable_bind_mounts", &self.enable_bind_mounts)
            .field(
                "health_check_interval_secs",
                &self.health_check_interval_secs,
            )
            // Proxy URLs may embed credentials in userinfo; log presence only.
            .field("https_proxy", &self.https_proxy.is_some())
            .field("no_proxy", &self.no_proxy)
            .field("proxy_auth_file", &self.proxy_auth_file.is_some())
            .field("proxy_auth_allow_insecure", &self.proxy_auth_allow_insecure)
            .field("proxy_connect_by_hostname", &self.proxy_connect_by_hostname)
            .field("userns", &self.userns)
            .field("uidmap", &self.uidmap)
            .field("gidmap", &self.gidmap)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_sets_health_check_interval() {
        let cfg = PodmanComputeConfig::default();
        assert_eq!(
            cfg.health_check_interval_secs,
            DEFAULT_HEALTH_CHECK_INTERVAL_SECS
        );
    }

    #[test]
    fn default_config_sets_podman_stop_timeout() {
        let cfg = PodmanComputeConfig::default();
        assert_eq!(cfg.stop_timeout_secs, DEFAULT_PODMAN_STOP_TIMEOUT_SECS);
    }

    #[test]
    fn default_config_sets_driver_owned_pids_limit() {
        let cfg = PodmanComputeConfig::default();
        assert_eq!(cfg.sandbox_pids_limit, DEFAULT_SANDBOX_PIDS_LIMIT);
        assert!(!cfg.enable_bind_mounts);
        assert!(cfg.validate_runtime_limits().is_ok());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn default_config_uses_gvproxy_host_gateway_ip_on_macos() {
        let cfg = PodmanComputeConfig::default();
        assert_eq!(cfg.host_gateway_ip, MACOS_PODMAN_MACHINE_HOST_GATEWAY_IP);
        assert!(cfg.validate_host_gateway_ip().is_ok());
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn default_config_leaves_host_gateway_ip_empty_off_macos() {
        let cfg = PodmanComputeConfig::default();
        assert!(cfg.host_gateway_ip.is_empty());
        assert!(cfg.validate_host_gateway_ip().is_ok());
    }

    #[test]
    fn host_gateway_ip_validation_rejects_invalid_values() {
        let cfg = PodmanComputeConfig {
            host_gateway_ip: "not-an-ip".to_string(),
            ..PodmanComputeConfig::default()
        };
        let err = cfg.validate_host_gateway_ip().unwrap_err();
        assert!(err.to_string().contains("host_gateway_ip"));
    }

    #[test]
    fn runtime_limit_validation_rejects_negative_pids_limit() {
        let cfg = PodmanComputeConfig {
            sandbox_pids_limit: -1,
            ..PodmanComputeConfig::default()
        };
        let err = cfg.validate_runtime_limits().unwrap_err();
        assert!(err.to_string().contains("sandbox_pids_limit"));
    }

    // ── Proxy config validation ───────────────────────────────────────

    #[test]
    fn validate_proxy_config_accepts_unset_and_http() {
        assert!(
            PodmanComputeConfig::default()
                .validate_proxy_config()
                .is_ok()
        );
        let cfg = PodmanComputeConfig {
            https_proxy: Some("http://proxy.corp.com:8080".to_string()),
            no_proxy: Some("*.svc.cluster.local".to_string()),
            ..PodmanComputeConfig::default()
        };
        assert!(cfg.validate_proxy_config().is_ok());
    }

    #[test]
    fn validate_proxy_config_rejects_non_http_schemes() {
        for url in ["https://proxy:443", "socks5://proxy:1080"] {
            let cfg = PodmanComputeConfig {
                https_proxy: Some(url.to_string()),
                ..PodmanComputeConfig::default()
            };
            let err = cfg.validate_proxy_config().unwrap_err();
            assert!(
                err.to_string().contains("unsupported proxy scheme"),
                "{url}: {err}"
            );
        }
    }

    #[test]
    fn validate_proxy_config_rejects_url_components() {
        for url in [
            "http://proxy.corp.com:8080/path",
            "http://proxy.corp.com:8080?x=1",
            "http://proxy.corp.com:8080#frag",
        ] {
            let cfg = PodmanComputeConfig {
                https_proxy: Some(url.to_string()),
                ..PodmanComputeConfig::default()
            };
            let err = cfg.validate_proxy_config().unwrap_err();
            assert!(
                err.to_string().contains("scheme://host:port"),
                "{url}: {err}"
            );
        }
    }

    #[test]
    fn validate_proxy_config_rejects_zero_port() {
        let cfg = PodmanComputeConfig {
            https_proxy: Some("http://proxy.corp.com:0".to_string()),
            ..PodmanComputeConfig::default()
        };
        let err = cfg.validate_proxy_config().unwrap_err();
        assert!(err.to_string().contains("port must not be 0"), "{err}");
    }

    #[test]
    fn validate_proxy_config_rejects_missing_scheme_or_port() {
        // A scheme-less value (previously normalized to http://) and a
        // port-less value (previously defaulted to 80) are both rejected so
        // gateway.toml matches the documented http://host:port grammar.
        for url in ["proxy.corp.com:8080", "http://proxy.corp.com"] {
            let cfg = PodmanComputeConfig {
                https_proxy: Some(url.to_string()),
                ..PodmanComputeConfig::default()
            };
            let err = cfg.validate_proxy_config().unwrap_err();
            assert!(err.to_string().contains("explicit"), "{url}: {err}");
        }
    }

    #[test]
    fn validate_proxy_config_rejects_empty_value() {
        let cfg = PodmanComputeConfig {
            https_proxy: Some("  ".to_string()),
            ..PodmanComputeConfig::default()
        };
        let err = cfg.validate_proxy_config().unwrap_err();
        assert!(err.to_string().contains("https_proxy"), "{err}");
    }

    #[test]
    fn validate_proxy_config_rejects_empty_no_proxy() {
        let cfg = PodmanComputeConfig {
            https_proxy: Some("http://proxy.corp.com:8080".to_string()),
            no_proxy: Some(" ".to_string()),
            ..PodmanComputeConfig::default()
        };
        let err = cfg.validate_proxy_config().unwrap_err();
        assert!(err.to_string().contains("no_proxy"), "{err}");
    }

    #[test]
    fn validate_proxy_config_rejects_no_proxy_without_proxy() {
        let cfg = PodmanComputeConfig {
            no_proxy: Some("*.svc.cluster.local".to_string()),
            ..PodmanComputeConfig::default()
        };
        let err = cfg.validate_proxy_config().unwrap_err();
        assert!(err.to_string().contains("no_proxy"), "{err}");
    }

    #[test]
    fn validate_proxy_config_rejects_inline_credentials() {
        for url in [
            "http://user:pass@proxy.corp.com:8080",
            "http://user@proxy.corp.com:8080",
        ] {
            let cfg = PodmanComputeConfig {
                https_proxy: Some(url.to_string()),
                ..PodmanComputeConfig::default()
            };
            let err = cfg.validate_proxy_config().unwrap_err();
            assert!(
                err.to_string().contains("proxy_auth_file"),
                "{url} should be rejected and point at proxy_auth_file: {err}"
            );
        }
    }

    #[test]
    fn validate_proxy_config_accepts_auth_file_with_proxy_and_acknowledgement() {
        let cfg = PodmanComputeConfig {
            https_proxy: Some("http://proxy.corp.com:8080".to_string()),
            proxy_auth_file: Some("/etc/openshell/secrets/proxy-auth".to_string()),
            proxy_auth_allow_insecure: Some(true),
            ..PodmanComputeConfig::default()
        };
        assert!(cfg.validate_proxy_config().is_ok());
    }

    #[test]
    fn validate_proxy_config_rejects_auth_file_without_insecure_acknowledgement() {
        // Basic auth over the plain-TCP proxy connection is readable on the
        // network path; sending it must be an explicit operator decision.
        for allow in [None, Some(false)] {
            let cfg = PodmanComputeConfig {
                https_proxy: Some("http://proxy.corp.com:8080".to_string()),
                proxy_auth_file: Some("/etc/openshell/secrets/proxy-auth".to_string()),
                proxy_auth_allow_insecure: allow,
                ..PodmanComputeConfig::default()
            };
            let err = cfg.validate_proxy_config().unwrap_err();
            assert!(
                err.to_string().contains("proxy_auth_allow_insecure"),
                "{allow:?}: {err}"
            );
            assert!(err.to_string().contains("cleartext"), "{allow:?}: {err}");
        }
    }

    #[test]
    fn validate_proxy_config_accepts_connect_by_hostname_with_proxy() {
        for by_hostname in [Some(true), Some(false)] {
            let cfg = PodmanComputeConfig {
                https_proxy: Some("http://proxy.corp.com:8080".to_string()),
                proxy_connect_by_hostname: by_hostname,
                ..PodmanComputeConfig::default()
            };
            assert!(cfg.validate_proxy_config().is_ok(), "{by_hostname:?}");
        }
    }

    #[test]
    fn validate_proxy_config_rejects_connect_by_hostname_without_proxy() {
        let cfg = PodmanComputeConfig {
            proxy_connect_by_hostname: Some(true),
            ..PodmanComputeConfig::default()
        };
        let err = cfg.validate_proxy_config().unwrap_err();
        assert!(err.to_string().contains("no https_proxy"), "{err}");
    }

    #[test]
    fn validate_proxy_config_rejects_acknowledgement_without_auth_file() {
        for allow in [Some(true), Some(false)] {
            let cfg = PodmanComputeConfig {
                https_proxy: Some("http://proxy.corp.com:8080".to_string()),
                proxy_auth_allow_insecure: allow,
                ..PodmanComputeConfig::default()
            };
            let err = cfg.validate_proxy_config().unwrap_err();
            assert!(
                err.to_string().contains("no proxy_auth_file"),
                "{allow:?}: {err}"
            );
        }
    }

    #[test]
    fn validate_proxy_config_rejects_auth_file_without_proxy() {
        let cfg = PodmanComputeConfig {
            proxy_auth_file: Some("/etc/openshell/secrets/proxy-auth".to_string()),
            ..PodmanComputeConfig::default()
        };
        let err = cfg.validate_proxy_config().unwrap_err();
        assert!(err.to_string().contains("proxy_auth_file"), "{err}");
    }

    // ── TLS config validation ─────────────────────────────────────────

    #[test]
    fn validate_tls_config_all_none_is_ok() {
        let cfg = PodmanComputeConfig::default();
        assert!(cfg.validate_tls_config().is_ok());
    }

    #[test]
    fn validate_tls_config_all_set_is_ok() {
        let cfg = PodmanComputeConfig {
            guest_tls_ca: Some(PathBuf::from("/tls/ca.crt")),
            guest_tls_cert: Some(PathBuf::from("/tls/tls.crt")),
            guest_tls_key: Some(PathBuf::from("/tls/tls.key")),
            ..PodmanComputeConfig::default()
        };
        assert!(cfg.validate_tls_config().is_ok());
    }

    #[test]
    fn validate_tls_config_only_ca_is_error() {
        let cfg = PodmanComputeConfig {
            guest_tls_ca: Some(PathBuf::from("/tls/ca.crt")),
            ..PodmanComputeConfig::default()
        };
        let err = cfg
            .validate_tls_config()
            .expect_err("only CA should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("OPENSHELL_PODMAN_TLS_CERT"), "{msg}");
        assert!(msg.contains("OPENSHELL_PODMAN_TLS_KEY"), "{msg}");
        assert!(!msg.contains("OPENSHELL_PODMAN_TLS_CA"), "{msg}");
    }

    #[test]
    fn validate_tls_config_only_cert_is_error() {
        let cfg = PodmanComputeConfig {
            guest_tls_cert: Some(PathBuf::from("/tls/tls.crt")),
            ..PodmanComputeConfig::default()
        };
        let err = cfg
            .validate_tls_config()
            .expect_err("only cert should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("OPENSHELL_PODMAN_TLS_CA"), "{msg}");
        assert!(msg.contains("OPENSHELL_PODMAN_TLS_KEY"), "{msg}");
        assert!(!msg.contains("OPENSHELL_PODMAN_TLS_CERT"), "{msg}");
    }

    #[test]
    fn validate_tls_config_only_key_is_error() {
        let cfg = PodmanComputeConfig {
            guest_tls_key: Some(PathBuf::from("/tls/tls.key")),
            ..PodmanComputeConfig::default()
        };
        let err = cfg
            .validate_tls_config()
            .expect_err("only key should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("OPENSHELL_PODMAN_TLS_CA"), "{msg}");
        assert!(msg.contains("OPENSHELL_PODMAN_TLS_CERT"), "{msg}");
        assert!(!msg.contains("OPENSHELL_PODMAN_TLS_KEY"), "{msg}");
    }

    #[test]
    fn validate_tls_config_ca_and_cert_missing_key_is_error() {
        let cfg = PodmanComputeConfig {
            guest_tls_ca: Some(PathBuf::from("/tls/ca.crt")),
            guest_tls_cert: Some(PathBuf::from("/tls/tls.crt")),
            ..PodmanComputeConfig::default()
        };
        let err = cfg
            .validate_tls_config()
            .expect_err("missing key should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("OPENSHELL_PODMAN_TLS_KEY"), "{msg}");
        assert!(!msg.contains("OPENSHELL_PODMAN_TLS_CA"), "{msg}");
        assert!(!msg.contains("OPENSHELL_PODMAN_TLS_CERT"), "{msg}");
    }

    #[test]
    fn validate_tls_config_ca_and_key_missing_cert_is_error() {
        let cfg = PodmanComputeConfig {
            guest_tls_ca: Some(PathBuf::from("/tls/ca.crt")),
            guest_tls_key: Some(PathBuf::from("/tls/tls.key")),
            ..PodmanComputeConfig::default()
        };
        let err = cfg
            .validate_tls_config()
            .expect_err("missing cert should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("OPENSHELL_PODMAN_TLS_CERT"), "{msg}");
        assert!(!msg.contains("OPENSHELL_PODMAN_TLS_CA"), "{msg}");
        assert!(!msg.contains("OPENSHELL_PODMAN_TLS_KEY"), "{msg}");
    }

    #[test]
    fn validate_tls_config_cert_and_key_missing_ca_is_error() {
        let cfg = PodmanComputeConfig {
            guest_tls_cert: Some(PathBuf::from("/tls/tls.crt")),
            guest_tls_key: Some(PathBuf::from("/tls/tls.key")),
            ..PodmanComputeConfig::default()
        };
        let err = cfg
            .validate_tls_config()
            .expect_err("missing CA should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("OPENSHELL_PODMAN_TLS_CA"), "{msg}");
        assert!(!msg.contains("OPENSHELL_PODMAN_TLS_CERT"), "{msg}");
        assert!(!msg.contains("OPENSHELL_PODMAN_TLS_KEY"), "{msg}");
    }

    #[test]
    fn canonicalize_userns_accepts_supported_modes() {
        for mode in [
            "auto",
            "host",
            "keep-id",
            "no-map",
            "private",
            "auto:size=65536",
            "keep-id:uid=1000,gid=1000",
        ] {
            let mut cfg = PodmanComputeConfig {
                userns: Some(mode.to_string()),
                ..PodmanComputeConfig::default()
            };
            cfg.canonicalize_userns()
                .unwrap_or_else(|_| panic!("mode '{mode}' should be accepted"));
        }
    }

    #[test]
    fn canonicalize_userns_normalizes_case_and_aliases() {
        let cases = [
            ("Auto", "auto"),
            ("HOST", "host"),
            ("KEEP-ID:uid=1000", "keep-id:uid=1000"),
            ("nomap", "no-map"),
            ("no-map", "no-map"),
            ("Private", "private"),
            ("auto:SIZE=65536", "auto:SIZE=65536"),
        ];
        for (input, expected) in cases {
            let mut cfg = PodmanComputeConfig {
                userns: Some(input.to_string()),
                ..PodmanComputeConfig::default()
            };
            cfg.canonicalize_userns()
                .unwrap_or_else(|_| panic!("mode '{input}' should be accepted"));
            assert_eq!(
                cfg.userns.as_deref(),
                Some(expected),
                "input '{input}' should canonicalize to '{expected}'"
            );
        }
    }

    #[test]
    fn canonicalize_userns_rejects_unsupported_modes() {
        for mode in ["container:foo", "ns:/proc/1/ns/user", "4000:5000"] {
            let mut cfg = PodmanComputeConfig {
                userns: Some(mode.to_string()),
                ..PodmanComputeConfig::default()
            };
            let err = cfg
                .canonicalize_userns()
                .expect_err(&format!("mode '{mode}' should be rejected"));
            let msg = err.to_string();
            assert!(msg.contains("unsupported userns mode"), "{msg}");
        }
    }

    #[test]
    fn canonicalize_userns_rejects_params_on_non_parameterizable_modes() {
        for mode in ["host:foo", "no-map:x=1", "private:x=1"] {
            let mut cfg = PodmanComputeConfig {
                userns: Some(mode.to_string()),
                ..PodmanComputeConfig::default()
            };
            let err = cfg
                .canonicalize_userns()
                .expect_err(&format!("mode '{mode}' should be rejected"));
            let msg = err.to_string();
            assert!(msg.contains("does not accept parameters"), "{msg}");
        }
    }

    #[test]
    fn canonicalize_userns_accepts_none() {
        let mut cfg = PodmanComputeConfig::default();
        cfg.canonicalize_userns().expect("None should be accepted");
    }

    // ── Userns mapping validation ────────────────────────────────────

    #[test]
    fn validate_userns_mappings_accepts_private_with_maps() {
        let cfg = PodmanComputeConfig {
            userns: Some("private".to_string()),
            uidmap: vec!["0:1000:1".to_string(), "1:100000:65536".to_string()],
            gidmap: vec!["0:1000:1".to_string(), "1:100000:65536".to_string()],
            ..PodmanComputeConfig::default()
        };
        cfg.validate_userns_mappings()
            .expect("private with mappings should be accepted");
    }

    #[test]
    fn validate_userns_mappings_rejects_private_without_uidmap() {
        let cfg = PodmanComputeConfig {
            userns: Some("private".to_string()),
            gidmap: vec!["0:1000:1".to_string()],
            ..PodmanComputeConfig::default()
        };
        let err = cfg
            .validate_userns_mappings()
            .expect_err("private without uidmap should be rejected");
        assert!(err.to_string().contains("uidmap"), "{err}");
    }

    #[test]
    fn validate_userns_mappings_rejects_private_without_gidmap() {
        let cfg = PodmanComputeConfig {
            userns: Some("private".to_string()),
            uidmap: vec!["0:1000:1".to_string()],
            ..PodmanComputeConfig::default()
        };
        let err = cfg
            .validate_userns_mappings()
            .expect_err("private without gidmap should be rejected");
        assert!(err.to_string().contains("gidmap"), "{err}");
    }

    #[test]
    fn validate_userns_mappings_rejects_maps_without_private() {
        for mode in [Some("auto"), Some("host"), Some("keep-id"), None] {
            let cfg = PodmanComputeConfig {
                userns: mode.map(ToString::to_string),
                uidmap: vec!["0:1000:1".to_string()],
                gidmap: vec!["0:1000:1".to_string()],
                ..PodmanComputeConfig::default()
            };
            let err = cfg.validate_userns_mappings().expect_err(&format!(
                "mappings without private should be rejected (mode={mode:?})"
            ));
            assert!(
                err.to_string().contains("only valid with"),
                "{mode:?}: {err}"
            );
        }
    }

    #[test]
    fn validate_userns_mappings_rejects_malformed_entries() {
        let cases = [
            ("0:1000", "too few fields"),
            ("0:1000:1:extra", "too many fields"),
            ("abc:1000:1", "non-numeric container_id"),
            ("0:abc:1", "non-numeric host_id"),
            ("0:1000:abc", "non-numeric size"),
            ("0:1000:0", "zero size"),
        ];
        for (entry, desc) in cases {
            let cfg = PodmanComputeConfig {
                userns: Some("private".to_string()),
                uidmap: vec![entry.to_string()],
                gidmap: vec!["0:1000:1".to_string()],
                ..PodmanComputeConfig::default()
            };
            cfg.validate_userns_mappings()
                .expect_err(&format!("{desc}: '{entry}' should be rejected"));
        }
    }

    #[test]
    fn validate_userns_mappings_accepts_no_userns_no_maps() {
        let cfg = PodmanComputeConfig::default();
        cfg.validate_userns_mappings()
            .expect("no userns and no maps should be accepted");
    }
}
