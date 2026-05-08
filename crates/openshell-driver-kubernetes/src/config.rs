// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone)]
pub struct KubernetesComputeConfig {
    pub namespace: String,
    pub default_image: String,
    pub image_pull_policy: String,
    /// Image that provides the `openshell-sandbox` supervisor binary.
    /// An init container copies the binary from this image into a shared
    /// emptyDir volume before the sandbox container starts.
    pub supervisor_image: String,
    /// Kubernetes `imagePullPolicy` for the supervisor init container.
    /// Empty string delegates to the Kubernetes default.
    pub supervisor_image_pull_policy: String,
    pub grpc_endpoint: String,
    pub ssh_socket_path: String,
    pub ssh_handshake_secret: String,
    pub ssh_handshake_skew_secs: u64,
    pub client_tls_secret_name: String,
    pub host_gateway_ip: String,
}
