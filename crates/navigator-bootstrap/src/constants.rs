// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub const NETWORK_NAME: &str = "navigator-cluster";
pub const KUBECONFIG_PATH: &str = "/etc/rancher/k3s/k3s.yaml";

/// K8s secret holding the server's TLS certificate and private key.
pub const SERVER_TLS_SECRET_NAME: &str = "navigator-server-tls";
/// K8s secret holding the CA certificate used to verify client certificates.
pub const SERVER_CLIENT_CA_SECRET_NAME: &str = "navigator-server-client-ca";
/// K8s secret holding the client TLS certificate, key, and CA cert (shared by CLI and sandboxes).
pub const CLIENT_TLS_SECRET_NAME: &str = "navigator-client-tls";

pub fn container_name(name: &str) -> String {
    format!("navigator-cluster-{name}")
}

pub fn volume_name(name: &str) -> String {
    format!("navigator-cluster-{name}")
}
