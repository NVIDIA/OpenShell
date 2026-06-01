// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

const DEFAULT_SANDBOX_IMAGE: &str = "ghcr.io/nvidia/openshell/sandbox:latest";
const DEFAULT_SUPERVISOR_IMAGE: &str = "ghcr.io/nvidia/openshell/supervisor:latest";
const DEFAULT_SERVER_PORT: u16 = 8080;
const DEFAULT_STOP_TIMEOUT_SECS: u32 = 10;
const DEFAULT_NETWORK_NAME: &str = "openshell";
const DEFAULT_SANDBOX_PIDS_LIMIT: i64 = 2048;
const DEFAULT_HEALTH_CHECK_INTERVAL_SECS: u64 = 10;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImagePullPolicy {
    Always,
    #[default]
    Missing,
    Never,
    Newer,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PodmanComputeConfig {
    pub socket_path: Option<PathBuf>,
    pub default_image: String,
    pub image_pull_policy: ImagePullPolicy,
    pub grpc_endpoint: String,
    pub gateway_port: u16,
    pub host_gateway_ip: String,
    pub sandbox_ssh_socket_path: String,
    pub network_name: String,
    pub stop_timeout_secs: u32,
    pub supervisor_image: String,
    pub guest_tls_ca: Option<PathBuf>,
    pub guest_tls_cert: Option<PathBuf>,
    pub guest_tls_key: Option<PathBuf>,
    pub sandbox_pids_limit: i64,
    pub enable_bind_mounts: bool,
    pub health_check_interval_secs: u64,
}

impl Default for PodmanComputeConfig {
    fn default() -> Self {
        Self {
            socket_path: None,
            default_image: DEFAULT_SANDBOX_IMAGE.to_string(),
            image_pull_policy: ImagePullPolicy::default(),
            grpc_endpoint: String::new(),
            gateway_port: DEFAULT_SERVER_PORT,
            host_gateway_ip: String::new(),
            sandbox_ssh_socket_path: String::new(),
            network_name: DEFAULT_NETWORK_NAME.to_string(),
            stop_timeout_secs: DEFAULT_STOP_TIMEOUT_SECS,
            supervisor_image: DEFAULT_SUPERVISOR_IMAGE.to_string(),
            guest_tls_ca: None,
            guest_tls_cert: None,
            guest_tls_key: None,
            sandbox_pids_limit: DEFAULT_SANDBOX_PIDS_LIMIT,
            enable_bind_mounts: false,
            health_check_interval_secs: DEFAULT_HEALTH_CHECK_INTERVAL_SECS,
        }
    }
}
