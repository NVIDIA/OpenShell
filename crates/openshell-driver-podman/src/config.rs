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
    /// Default: `$XDG_RUNTIME_DIR/podman/podman.sock`
    pub socket_path: PathBuf,
    /// Default OCI image for sandboxes.
    pub default_image: String,
    /// Image pull policy for sandbox images.
    pub image_pull_policy: ImagePullPolicy,
    /// Gateway gRPC endpoint the sandbox connects back to.
    pub grpc_endpoint: String,
    /// Unix socket path the in-container supervisor bridges relay traffic to.
    pub sandbox_ssh_socket_path: String,
    /// Name of the Podman bridge network.
    /// Created automatically if it does not exist.
    pub network_name: String,
    /// SSH listen address passed to the sandbox binary.
    pub ssh_listen_addr: String,
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
}

impl PodmanComputeConfig {
    /// Resolve the default socket path from the environment.
    ///
    /// Uses `$XDG_RUNTIME_DIR` when available (set by `pam_systemd`/logind),
    /// otherwise falls back to the real UID via `getuid()` — matching how the
    /// Podman CLI itself resolves the rootless socket path.
    #[must_use]
    pub fn default_socket_path() -> PathBuf {
        if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(xdg).join("podman/podman.sock")
        } else {
            // Use the real UID from the kernel — reliable in containers,
            // systemd services, CI, and after su/sudo.
            let uid = nix::unistd::getuid();
            PathBuf::from(format!("/run/user/{uid}/podman/podman.sock"))
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
            sandbox_ssh_socket_path: "/run/openshell/ssh.sock".to_string(),
            network_name: DEFAULT_NETWORK_NAME.to_string(),
            ssh_listen_addr: String::new(),
            ssh_port: DEFAULT_SSH_PORT,
            ssh_handshake_secret: String::new(),
            ssh_handshake_skew_secs: DEFAULT_SSH_HANDSHAKE_SKEW_SECS,
            stop_timeout_secs: DEFAULT_STOP_TIMEOUT_SECS,
            supervisor_image: DEFAULT_SUPERVISOR_IMAGE.to_string(),
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
            .field("sandbox_ssh_socket_path", &self.sandbox_ssh_socket_path)
            .field("network_name", &self.network_name)
            .field("ssh_listen_addr", &self.ssh_listen_addr)
            .field("ssh_port", &self.ssh_port)
            .field("ssh_handshake_secret", &"[REDACTED]")
            .field("ssh_handshake_skew_secs", &self.ssh_handshake_skew_secs)
            .field("stop_timeout_secs", &self.stop_timeout_secs)
            .field("supervisor_image", &self.supervisor_image)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_socket_path_respects_xdg_runtime_dir() {
        // Temporarily set XDG_RUNTIME_DIR and verify it is used.
        let _guard = TempEnvVar::set("XDG_RUNTIME_DIR", "/tmp/test-xdg");
        let path = PodmanComputeConfig::default_socket_path();
        assert_eq!(path, PathBuf::from("/tmp/test-xdg/podman/podman.sock"));
    }

    #[test]
    fn default_socket_path_falls_back_to_uid() {
        let _guard = TempEnvVar::remove("XDG_RUNTIME_DIR");
        let path = PodmanComputeConfig::default_socket_path();
        let uid = nix::unistd::getuid();
        assert_eq!(
            path,
            PathBuf::from(format!("/run/user/{uid}/podman/podman.sock"))
        );
    }

    /// RAII guard that sets/removes an env var and restores it on drop.
    ///
    /// # Safety
    /// These tests must not run in parallel with other tests that read
    /// `XDG_RUNTIME_DIR`. Cargo runs test binaries with a single thread
    /// by default for `#[test]` within the same crate, so this is safe
    /// as long as no other thread inspects the env concurrently.
    #[allow(unsafe_code)]
    struct TempEnvVar {
        key: &'static str,
        original: Option<String>,
    }

    #[allow(unsafe_code)]
    impl TempEnvVar {
        fn set(key: &'static str, value: &str) -> Self {
            let original = std::env::var(key).ok();
            // SAFETY: No other thread reads this env var concurrently in
            // these unit tests.
            unsafe { std::env::set_var(key, value) };
            Self { key, original }
        }

        fn remove(key: &'static str) -> Self {
            let original = std::env::var(key).ok();
            // SAFETY: see above.
            unsafe { std::env::remove_var(key) };
            Self { key, original }
        }
    }

    #[allow(unsafe_code)]
    impl Drop for TempEnvVar {
        fn drop(&mut self) {
            match &self.original {
                // SAFETY: restoring original value in drop; same thread safety
                // guarantee as set/remove above.
                Some(val) => unsafe { std::env::set_var(self.key, val) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }
}
