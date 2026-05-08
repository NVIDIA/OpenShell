// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::config::{
    DEFAULT_NETWORK_NAME, DEFAULT_SSH_HANDSHAKE_SKEW_SECS, DEFAULT_SSH_PORT,
    DEFAULT_STOP_TIMEOUT_SECS, DEFAULT_SUPERVISOR_IMAGE,
};
use std::path::PathBuf;
use std::str::FromStr;

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

#[derive(Clone)]
pub struct PodmanComputeConfig {
    /// Path to the Podman API Unix socket.
    /// Default: `$XDG_RUNTIME_DIR/podman/podman.sock` (Linux),
    /// `$HOME/.local/share/containers/podman/machine/podman.sock` (macOS).
    pub socket_path: PathBuf,
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
    /// SSH port inside the container.
    pub ssh_port: u16,
    /// Shared secret for the NSSH1 SSH handshake.
    pub ssh_handshake_secret: String,
    /// Maximum clock skew in seconds for SSH handshake timestamps.
    pub ssh_handshake_skew_secs: u64,
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

    /// Resolve the default socket path from the environment.
    ///
    /// - **macOS**: `$HOME/.local/share/containers/podman/machine/podman.sock`
    ///   (the symlink created by `podman machine` pointing to the VM API socket).
    /// - **Linux**: `$XDG_RUNTIME_DIR/podman/podman.sock` when set (by
    ///   `pam_systemd`/logind), otherwise `/run/user/{uid}/podman/podman.sock`
    ///   using the real UID via `getuid()`.
    #[must_use]
    pub fn default_socket_path() -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            let home = std::env::var("HOME").expect("HOME must be set on macOS");
            PathBuf::from(home).join(".local/share/containers/podman/machine/podman.sock")
        }
        #[cfg(target_os = "linux")]
        {
            std::env::var("XDG_RUNTIME_DIR").map_or_else(
                |_| {
                    let uid = nix::unistd::getuid();
                    PathBuf::from(format!("/run/user/{uid}/podman/podman.sock"))
                },
                |xdg| PathBuf::from(xdg).join("podman/podman.sock"),
            )
        }
    }
}

impl Default for PodmanComputeConfig {
    fn default() -> Self {
        Self {
            socket_path: Self::default_socket_path(),
            default_image: String::new(),
            image_pull_policy: ImagePullPolicy::default(),
            grpc_endpoint: String::new(),
            gateway_port: openshell_core::config::DEFAULT_SERVER_PORT,
            sandbox_ssh_socket_path: "/run/openshell/ssh.sock".to_string(),
            network_name: DEFAULT_NETWORK_NAME.to_string(),
            ssh_port: DEFAULT_SSH_PORT,
            ssh_handshake_secret: String::new(),
            ssh_handshake_skew_secs: DEFAULT_SSH_HANDSHAKE_SKEW_SECS,
            stop_timeout_secs: DEFAULT_STOP_TIMEOUT_SECS,
            supervisor_image: DEFAULT_SUPERVISOR_IMAGE.to_string(),
            guest_tls_ca: None,
            guest_tls_cert: None,
            guest_tls_key: None,
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
            .field("ssh_port", &self.ssh_port)
            .field("ssh_handshake_secret", &"[REDACTED]")
            .field("ssh_handshake_skew_secs", &self.ssh_handshake_skew_secs)
            .field("stop_timeout_secs", &self.stop_timeout_secs)
            .field("supervisor_image", &self.supervisor_image)
            .field("guest_tls_ca", &self.guest_tls_ca)
            .field("guest_tls_cert", &self.guest_tls_cert)
            .field("guest_tls_key", &self.guest_tls_key)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises env-mutating tests so that parallel test threads cannot
    /// observe each other's changes to `XDG_RUNTIME_DIR`.
    static ENV_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

    #[test]
    #[cfg(target_os = "linux")]
    fn default_socket_path_respects_xdg_runtime_dir() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        temp_env::with_vars([("XDG_RUNTIME_DIR", Some("/tmp/test-xdg"))], || {
            let path = PodmanComputeConfig::default_socket_path();
            assert_eq!(path, PathBuf::from("/tmp/test-xdg/podman/podman.sock"));
        });
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn default_socket_path_falls_back_to_uid() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        temp_env::with_vars([("XDG_RUNTIME_DIR", None::<&str>)], || {
            let path = PodmanComputeConfig::default_socket_path();
            let uid = nix::unistd::getuid();
            assert_eq!(
                path,
                PathBuf::from(format!("/run/user/{uid}/podman/podman.sock"))
            );
        });
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn default_socket_path_uses_podman_machine_on_macos() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        temp_env::with_vars([("HOME", Some("/Users/testuser"))], || {
            let path = PodmanComputeConfig::default_socket_path();
            assert_eq!(
                path,
                PathBuf::from("/Users/testuser/.local/share/containers/podman/machine/podman.sock")
            );
        });
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
}
