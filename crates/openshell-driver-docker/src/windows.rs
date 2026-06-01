// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::config::DEFAULT_DOCKER_NETWORK_NAME;
use std::path::PathBuf;

const DEFAULT_DOCKER_SUPERVISOR_IMAGE_REPO: &str = "ghcr.io/nvidia/openshell/supervisor";
const DEFAULT_SANDBOX_PIDS_LIMIT: i64 = 2048;

#[must_use]
pub fn default_docker_supervisor_image() -> String {
    format!(
        "{DEFAULT_DOCKER_SUPERVISOR_IMAGE_REPO}:{}",
        default_docker_supervisor_image_tag()
    )
}

fn default_docker_supervisor_image_tag() -> String {
    let tag = option_env!("OPENSHELL_IMAGE_TAG")
        .filter(|tag| !tag.is_empty())
        .or_else(|| option_env!("IMAGE_TAG").filter(|tag| !tag.is_empty()))
        .unwrap_or_else(|| {
            if env!("CARGO_PKG_VERSION").is_empty() || env!("CARGO_PKG_VERSION") == "0.0.0" {
                "dev"
            } else {
                env!("CARGO_PKG_VERSION")
            }
        });

    tag.replace('+', "-")
}

/// Gateway-local configuration for the Docker compute driver.
///
/// Windows builds keep this type so existing config files continue to parse,
/// but Docker runtime support is intentionally unavailable on Windows.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DockerComputeConfig {
    pub socket_path: Option<PathBuf>,
    pub default_image: String,
    pub image_pull_policy: String,
    pub sandbox_namespace: String,
    pub grpc_endpoint: String,
    pub supervisor_bin: Option<PathBuf>,
    pub supervisor_image: Option<String>,
    pub guest_tls_ca: Option<PathBuf>,
    pub guest_tls_cert: Option<PathBuf>,
    pub guest_tls_key: Option<PathBuf>,
    pub network_name: String,
    pub host_gateway_ip: String,
    pub ssh_socket_path: String,
    pub sandbox_pids_limit: i64,
    pub enable_bind_mounts: bool,
}

impl Default for DockerComputeConfig {
    fn default() -> Self {
        Self {
            socket_path: None,
            default_image: openshell_core::image::default_sandbox_image(),
            image_pull_policy: String::new(),
            sandbox_namespace: "default".to_string(),
            grpc_endpoint: String::new(),
            supervisor_bin: None,
            supervisor_image: None,
            guest_tls_ca: None,
            guest_tls_cert: None,
            guest_tls_key: None,
            network_name: DEFAULT_DOCKER_NETWORK_NAME.to_string(),
            host_gateway_ip: String::new(),
            ssh_socket_path: "/run/openshell/ssh.sock".to_string(),
            sandbox_pids_limit: DEFAULT_SANDBOX_PIDS_LIMIT,
            enable_bind_mounts: false,
        }
    }
}
