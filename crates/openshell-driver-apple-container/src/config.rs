// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration for the Apple Container compute driver.

use openshell_core::config::{DEFAULT_SERVER_PORT, DEFAULT_STOP_TIMEOUT_SECS};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const DEFAULT_APPLE_CONTAINER_HOST_CALLBACK_HOST: &str = "host.container.internal";

/// Runtime configuration for the Apple Container driver.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppleContainerComputeConfig {
    /// Path to the `container` CLI.
    pub container_bin: PathBuf,
    /// Default OCI image for sandboxes.
    pub default_image: String,
    /// Namespace label applied to Apple Container sandboxes.
    pub sandbox_namespace: String,
    /// Gateway gRPC endpoint the sandbox supervisor dials.
    pub grpc_endpoint: String,
    /// Gateway listener port used when `grpc_endpoint` is empty.
    pub gateway_port: u16,
    /// Hostname or IP address Apple container VMs use to call back to the gateway.
    pub host_callback_host: String,
    /// Host path to the CA certificate for sandbox mTLS.
    ///
    /// When all three guest TLS paths are set, the driver bind-mounts them
    /// into Apple Container sandboxes and the implicit supervisor endpoint
    /// switches from `http://` to `https://`.
    pub guest_tls_ca: Option<PathBuf>,
    /// Host path to the client certificate for sandbox mTLS.
    pub guest_tls_cert: Option<PathBuf>,
    /// Host path to the client private key for sandbox mTLS.
    pub guest_tls_key: Option<PathBuf>,
    /// Parent directory containing the Linux `openshell-sandbox` binary.
    pub supervisor_bin_dir: PathBuf,
    /// Unix socket path where the supervisor exposes SSH relay traffic.
    pub sandbox_ssh_socket_path: String,
    /// Container stop timeout in seconds.
    pub stop_timeout_secs: u32,
    /// Default log level injected into the sandbox supervisor.
    pub log_level: String,
}

impl AppleContainerComputeConfig {
    /// Returns `true` when all three sandbox mTLS paths are configured.
    #[must_use]
    pub fn tls_enabled(&self) -> bool {
        self.guest_tls_ca.is_some() && self.guest_tls_cert.is_some() && self.guest_tls_key.is_some()
    }

    /// Return the endpoint used by sandbox supervisors.
    #[must_use]
    pub fn effective_grpc_endpoint(&self) -> String {
        if self.grpc_endpoint.trim().is_empty() {
            let scheme = if self.tls_enabled() { "https" } else { "http" };
            format!(
                "{scheme}://{}:{}",
                self.host_callback_host, self.gateway_port
            )
        } else {
            self.grpc_endpoint.clone()
        }
    }
}

impl Default for AppleContainerComputeConfig {
    fn default() -> Self {
        Self {
            container_bin: PathBuf::from("container"),
            default_image: openshell_core::image::default_sandbox_image(),
            sandbox_namespace: "default".to_string(),
            grpc_endpoint: String::new(),
            gateway_port: DEFAULT_SERVER_PORT,
            host_callback_host: DEFAULT_APPLE_CONTAINER_HOST_CALLBACK_HOST.to_string(),
            guest_tls_ca: None,
            guest_tls_cert: None,
            guest_tls_key: None,
            supervisor_bin_dir: PathBuf::new(),
            sandbox_ssh_socket_path: "/run/openshell/ssh.sock".to_string(),
            stop_timeout_secs: DEFAULT_STOP_TIMEOUT_SECS,
            log_level: "warn".to_string(),
        }
    }
}
