// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::config::DEFAULT_SUPERVISOR_IMAGE;
use serde::{Deserialize, Serialize};

/// Default Kubernetes namespace for sandbox resources.
pub const DEFAULT_K8S_NAMESPACE: &str = "openshell";

/// How the supervisor binary is delivered into sandbox pods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupervisorSideloadMethod {
    /// Mount the supervisor OCI image directly as a read-only volume
    /// (requires Kubernetes >= v1.33 with the `ImageVolume` feature gate,
    /// or >= v1.36 where it is GA).
    #[default]
    ImageVolume,
    /// Copy the binary via an init container and emptyDir volume.
    /// Works on all Kubernetes versions.
    InitContainer,
}

impl std::fmt::Display for SupervisorSideloadMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ImageVolume => f.write_str("image-volume"),
            Self::InitContainer => f.write_str("init-container"),
        }
    }
}

impl std::str::FromStr for SupervisorSideloadMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "image-volume" => Ok(Self::ImageVolume),
            "init-container" => Ok(Self::InitContainer),
            other => Err(format!(
                "unknown supervisor sideload method '{other}'; expected 'image-volume' or 'init-container'"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KubernetesComputeConfig {
    pub namespace: String,
    pub default_image: String,
    pub image_pull_policy: String,
    /// Image that provides the `openshell-sandbox` supervisor binary.
    /// Mounted directly as an image volume, or copied via an init container,
    /// depending on `supervisor_sideload_method`.
    pub supervisor_image: String,
    /// Kubernetes `imagePullPolicy` for the supervisor image.
    /// Empty string delegates to the Kubernetes default.
    pub supervisor_image_pull_policy: String,
    /// How the supervisor binary is delivered into sandbox pods.
    pub supervisor_sideload_method: SupervisorSideloadMethod,
    pub grpc_endpoint: String,
    pub ssh_socket_path: String,
    pub client_tls_secret_name: String,
    pub host_gateway_ip: String,
    pub enable_user_namespaces: bool,
}

impl Default for KubernetesComputeConfig {
    fn default() -> Self {
        Self {
            namespace: DEFAULT_K8S_NAMESPACE.to_string(),
            default_image: default_sandbox_image(),
            // Default empty so the gateway omits `imagePullPolicy` from pod
            // specs and Kubernetes applies its own default (Always for `latest`,
            // IfNotPresent otherwise). `DEFAULT_IMAGE_PULL_POLICY` ("missing")
            // is Podman vocabulary and is not a valid Kubernetes value.
            image_pull_policy: String::new(),
            supervisor_image: DEFAULT_SUPERVISOR_IMAGE.to_string(),
            supervisor_image_pull_policy: String::new(),
            supervisor_sideload_method: SupervisorSideloadMethod::default(),
            grpc_endpoint: String::new(),
            ssh_socket_path: "/run/openshell/ssh.sock".to_string(),
            client_tls_secret_name: String::new(),
            host_gateway_ip: String::new(),
            enable_user_namespaces: false,
        }
    }
}

fn default_sandbox_image() -> String {
    format!(
        "{}/base:latest",
        openshell_core::image::DEFAULT_COMMUNITY_REGISTRY
    )
}
