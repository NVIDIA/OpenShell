// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone)]
pub struct KubernetesComputeConfig {
    pub namespace: String,
    pub default_image: String,
    pub image_pull_policy: String,
    pub grpc_endpoint: String,
    pub ssh_listen_addr: String,
    pub ssh_port: u16,
    pub ssh_handshake_secret: String,
    pub ssh_handshake_skew_secs: u64,
    pub client_tls_secret_name: String,
    pub host_gateway_ip: String,
}
