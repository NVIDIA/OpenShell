// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration management for OpenShell components.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

/// Compute backends the gateway can orchestrate sandboxes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputeDriverKind {
    Kubernetes,
    Vm,
    Podman,
}

impl ComputeDriverKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kubernetes => "kubernetes",
            Self::Vm => "vm",
            Self::Podman => "podman",
        }
    }
}

impl fmt::Display for ComputeDriverKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ComputeDriverKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "kubernetes" => Ok(Self::Kubernetes),
            "vm" => Ok(Self::Vm),
            "podman" => Ok(Self::Podman),
            other => Err(format!(
                "unsupported compute driver '{other}'. expected one of: kubernetes, vm, podman"
            )),
        }
    }
}

/// Server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Address to bind the server to.
    #[serde(default = "default_bind_address")]
    pub bind_address: SocketAddr,

    /// Address to bind the unauthenticated health endpoint to.
    ///
    /// When `None`, the dedicated health listener is disabled.
    #[serde(default)]
    pub health_bind_address: Option<SocketAddr>,

    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// TLS configuration.  When `None`, the server listens on plaintext HTTP.
    pub tls: Option<TlsConfig>,

    /// Database URL for persistence.
    pub database_url: String,

    /// Compute drivers configured for the gateway.
    ///
    /// The config shape allows multiple drivers so the gateway can evolve
    /// toward multi-backend routing. Current releases require exactly one
    /// configured driver.
    #[serde(default = "default_compute_drivers")]
    pub compute_drivers: Vec<ComputeDriverKind>,

    /// Kubernetes namespace for sandboxes.
    #[serde(default = "default_sandbox_namespace")]
    pub sandbox_namespace: String,

    /// Default container image for sandboxes.
    #[serde(default)]
    pub sandbox_image: String,

    /// Kubernetes `imagePullPolicy` for sandbox pods (e.g. `Always`,
    /// `IfNotPresent`, `Never`).  Defaults to empty, which lets Kubernetes
    /// apply its own default (`:latest` → `Always`, anything else →
    /// `IfNotPresent`).
    #[serde(default)]
    pub sandbox_image_pull_policy: String,

    /// gRPC endpoint for sandboxes to connect back to OpenShell.
    /// Used by sandbox pods to fetch their policy at startup.
    #[serde(default)]
    pub grpc_endpoint: String,

    /// Public gateway host for SSH proxy connections.
    #[serde(default = "default_ssh_gateway_host")]
    pub ssh_gateway_host: String,

    /// Public gateway port for SSH proxy connections.
    #[serde(default = "default_ssh_gateway_port")]
    pub ssh_gateway_port: u16,

    /// Path for SSH CONNECT/upgrade requests.
    #[serde(default = "default_ssh_connect_path")]
    pub ssh_connect_path: String,

    /// Filesystem path where the sandbox supervisor binds its SSH Unix
    /// socket. The supervisor is passed this path via
    /// `OPENSHELL_SSH_SOCKET_PATH` / `--ssh-socket-path` and connects its
    /// relay bridge to the same path.
    ///
    /// When the gateway orchestrates sandboxes that each live in their own
    /// filesystem (K8s pod, libkrun VM, etc.), the default is safe. For
    /// local dev where multiple supervisors share `/run`, override this to
    /// something unique per sandbox.
    #[serde(default = "default_sandbox_ssh_socket_path")]
    pub sandbox_ssh_socket_path: String,

    /// Shared secret for gateway-to-sandbox SSH handshake.
    #[serde(default)]
    pub ssh_handshake_secret: String,

    /// Allowed clock skew for SSH handshake validation, in seconds.
    #[serde(default = "default_ssh_handshake_skew_secs")]
    pub ssh_handshake_skew_secs: u64,

    /// TTL for SSH session tokens, in seconds. 0 disables expiry.
    #[serde(default = "default_ssh_session_ttl_secs")]
    pub ssh_session_ttl_secs: u64,

    /// Kubernetes secret name containing client TLS materials for sandbox pods.
    /// When set, sandbox pods get this secret mounted so they can connect to
    /// the server over mTLS.
    #[serde(default)]
    pub client_tls_secret_name: String,

    /// Host gateway IP for sandbox pod hostAliases.
    /// When set, sandbox pods get hostAliases entries mapping
    /// `host.docker.internal` and `host.openshell.internal` to this IP,
    /// allowing them to reach services running on the Docker host.
    #[serde(default)]
    pub host_gateway_ip: String,
}

/// TLS configuration.
///
/// By default mTLS is enforced — all clients must present a certificate
/// signed by the given CA.  When `allow_unauthenticated` is `true`, the
/// TLS handshake also accepts connections without a client certificate
/// (needed for reverse-proxy deployments like Cloudflare Tunnel).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the TLS certificate file.
    pub cert_path: PathBuf,

    /// Path to the TLS private key file.
    pub key_path: PathBuf,

    /// Path to the CA certificate file for client certificate verification (mTLS).
    /// The server requires all clients to present a valid certificate signed by
    /// this CA.
    pub client_ca_path: PathBuf,

    /// When `true`, the TLS handshake succeeds even without a client
    /// certificate.  Application-layer middleware must then enforce auth
    /// (e.g. via a CF JWT header).
    #[serde(default)]
    pub allow_unauthenticated: bool,
}

impl Config {
    /// Create a new config with optional TLS.
    pub fn new(tls: Option<TlsConfig>) -> Self {
        Self {
            bind_address: default_bind_address(),
            health_bind_address: None,
            log_level: default_log_level(),
            tls,
            database_url: String::new(),
            compute_drivers: default_compute_drivers(),
            sandbox_namespace: default_sandbox_namespace(),
            sandbox_image: String::new(),
            sandbox_image_pull_policy: String::new(),
            grpc_endpoint: String::new(),
            ssh_gateway_host: default_ssh_gateway_host(),
            ssh_gateway_port: default_ssh_gateway_port(),
            ssh_connect_path: default_ssh_connect_path(),
            sandbox_ssh_socket_path: default_sandbox_ssh_socket_path(),
            ssh_handshake_secret: String::new(),
            ssh_handshake_skew_secs: default_ssh_handshake_skew_secs(),
            ssh_session_ttl_secs: default_ssh_session_ttl_secs(),
            client_tls_secret_name: String::new(),
            host_gateway_ip: String::new(),
        }
    }

    /// Create a new configuration with the given bind address.
    #[must_use]
    pub const fn with_bind_address(mut self, addr: SocketAddr) -> Self {
        self.bind_address = addr;
        self
    }

    #[must_use]
    pub const fn with_health_bind_address(mut self, addr: SocketAddr) -> Self {
        self.health_bind_address = Some(addr);
        self
    }

    /// Create a new configuration with the given log level.
    #[must_use]
    pub fn with_log_level(mut self, level: impl Into<String>) -> Self {
        self.log_level = level.into();
        self
    }

    /// Create a new configuration with a database URL.
    #[must_use]
    pub fn with_database_url(mut self, url: impl Into<String>) -> Self {
        self.database_url = url.into();
        self
    }

    /// Create a new configuration with the configured compute drivers.
    #[must_use]
    pub fn with_compute_drivers<I>(mut self, drivers: I) -> Self
    where
        I: IntoIterator<Item = ComputeDriverKind>,
    {
        self.compute_drivers = drivers.into_iter().collect();
        self
    }

    /// Create a new configuration with a sandbox namespace.
    #[must_use]
    pub fn with_sandbox_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.sandbox_namespace = namespace.into();
        self
    }

    /// Create a new configuration with a default sandbox image.
    #[must_use]
    pub fn with_sandbox_image(mut self, image: impl Into<String>) -> Self {
        self.sandbox_image = image.into();
        self
    }

    /// Create a new configuration with a sandbox image pull policy.
    #[must_use]
    pub fn with_sandbox_image_pull_policy(mut self, policy: impl Into<String>) -> Self {
        self.sandbox_image_pull_policy = policy.into();
        self
    }

    /// Create a new configuration with a gRPC endpoint for sandbox callback.
    #[must_use]
    pub fn with_grpc_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.grpc_endpoint = endpoint.into();
        self
    }

    /// Create a new configuration with the SSH gateway host.
    #[must_use]
    pub fn with_ssh_gateway_host(mut self, host: impl Into<String>) -> Self {
        self.ssh_gateway_host = host.into();
        self
    }

    /// Create a new configuration with the SSH gateway port.
    #[must_use]
    pub const fn with_ssh_gateway_port(mut self, port: u16) -> Self {
        self.ssh_gateway_port = port;
        self
    }

    /// Create a new configuration with the SSH connect path.
    #[must_use]
    pub fn with_ssh_connect_path(mut self, path: impl Into<String>) -> Self {
        self.ssh_connect_path = path.into();
        self
    }

    /// Create a new configuration with the SSH handshake secret.
    #[must_use]
    pub fn with_ssh_handshake_secret(mut self, secret: impl Into<String>) -> Self {
        self.ssh_handshake_secret = secret.into();
        self
    }

    /// Create a new configuration with SSH handshake skew allowance.
    #[must_use]
    pub const fn with_ssh_handshake_skew_secs(mut self, secs: u64) -> Self {
        self.ssh_handshake_skew_secs = secs;
        self
    }

    /// Create a new configuration with the SSH session TTL.
    #[must_use]
    pub const fn with_ssh_session_ttl_secs(mut self, secs: u64) -> Self {
        self.ssh_session_ttl_secs = secs;
        self
    }

    /// Set the Kubernetes secret name for sandbox client TLS materials.
    #[must_use]
    pub fn with_client_tls_secret_name(mut self, name: impl Into<String>) -> Self {
        self.client_tls_secret_name = name.into();
        self
    }

    /// Set the host gateway IP for sandbox pod hostAliases.
    #[must_use]
    pub fn with_host_gateway_ip(mut self, ip: impl Into<String>) -> Self {
        self.host_gateway_ip = ip.into();
        self
    }
}

fn default_bind_address() -> SocketAddr {
    "0.0.0.0:8080".parse().expect("valid default address")
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_sandbox_namespace() -> String {
    "default".to_string()
}

fn default_compute_drivers() -> Vec<ComputeDriverKind> {
    vec![ComputeDriverKind::Kubernetes]
}

fn default_ssh_gateway_host() -> String {
    "127.0.0.1".to_string()
}

const fn default_ssh_gateway_port() -> u16 {
    8080
}

fn default_ssh_connect_path() -> String {
    "/connect/ssh".to_string()
}

fn default_sandbox_ssh_socket_path() -> String {
    "/run/openshell/ssh.sock".to_string()
}

const fn default_ssh_handshake_skew_secs() -> u64 {
    300
}

const fn default_ssh_session_ttl_secs() -> u64 {
    86400 // 24 hours
}

#[cfg(test)]
mod tests {
    use super::{ComputeDriverKind, Config};
    use std::net::SocketAddr;

    #[test]
    fn compute_driver_kind_parses_supported_values() {
        assert_eq!(
            "kubernetes".parse::<ComputeDriverKind>().unwrap(),
            ComputeDriverKind::Kubernetes
        );
        assert_eq!(
            "vm".parse::<ComputeDriverKind>().unwrap(),
            ComputeDriverKind::Vm
        );
        assert_eq!(
            "podman".parse::<ComputeDriverKind>().unwrap(),
            ComputeDriverKind::Podman
        );
    }

    #[test]
    fn compute_driver_kind_rejects_unknown_values() {
        let err = "docker".parse::<ComputeDriverKind>().unwrap_err();
        assert!(err.contains("unsupported compute driver 'docker'"));
    }

    #[test]
    fn config_defaults_to_kubernetes_driver() {
        assert_eq!(
            Config::new(None).compute_drivers,
            vec![ComputeDriverKind::Kubernetes]
        );
    }

    #[test]
    fn config_new_disables_health_bind_by_default() {
        let cfg = Config::new(None);
        assert!(cfg.health_bind_address.is_none());
    }

    #[test]
    fn config_with_health_bind_address_sets_address() {
        let addr: SocketAddr = "0.0.0.0:9090".parse().expect("valid address");
        let cfg = Config::new(None).with_health_bind_address(addr);
        assert_eq!(cfg.health_bind_address, Some(addr));
    }
}
