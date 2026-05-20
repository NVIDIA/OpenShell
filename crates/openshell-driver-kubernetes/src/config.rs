// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::config::DEFAULT_SUPERVISOR_IMAGE;
use serde::{Deserialize, Serialize};

/// Default Kubernetes namespace for sandbox resources.
pub const DEFAULT_K8S_NAMESPACE: &str = "openshell";

/// Default Kubernetes `ServiceAccount` assigned to sandbox pods.
pub const DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME: &str = "default";

/// Default storage size for the workspace PVC.
pub const DEFAULT_WORKSPACE_STORAGE_SIZE: &str = "2Gi";

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
    /// Kubernetes `ServiceAccount` assigned to sandbox pods and accepted by
    /// the gateway's `TokenReview` bootstrap authenticator.
    pub service_account_name: String,
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
    pub workspace_default_storage_size: String,
    /// Lifetime (seconds) of the projected `ServiceAccount` token kubelet
    /// writes into each sandbox pod. Used only for the one-shot
    /// `IssueSandboxToken` bootstrap exchange — the gateway-minted JWT
    /// that follows has its own TTL set via `gateway_jwt.ttl_secs`.
    ///
    /// Kubelet enforces a minimum of 600 seconds; the supervisor uses
    /// this token within a few seconds of pod start, so any value at
    /// the floor is sufficient. Default 3600.
    pub sa_token_ttl_secs: i64,
}

/// Lower bound enforced by kubelet for projected SA tokens.
pub const MIN_SA_TOKEN_TTL_SECS: i64 = 600;

/// Cap at 24h — operators who want longer-lived bootstrap tokens are
/// almost certainly misconfigured (the token is consumed seconds after
/// pod start).
pub const MAX_SA_TOKEN_TTL_SECS: i64 = 86_400;

impl Default for KubernetesComputeConfig {
    fn default() -> Self {
        Self {
            namespace: DEFAULT_K8S_NAMESPACE.to_string(),
            service_account_name: DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME.to_string(),
            default_image: openshell_core::image::default_sandbox_image(),
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
            workspace_default_storage_size: DEFAULT_WORKSPACE_STORAGE_SIZE.to_string(),
            sa_token_ttl_secs: 3600,
        }
    }
}

impl KubernetesComputeConfig {
    /// Clamp `sa_token_ttl_secs` into the `[MIN_SA_TOKEN_TTL_SECS,
    /// MAX_SA_TOKEN_TTL_SECS]` range used by the projected-volume spec.
    /// Invalid (≤0) values fall back to the default 3600.
    #[must_use]
    pub fn effective_sa_token_ttl_secs(&self) -> i64 {
        if self.sa_token_ttl_secs <= 0 {
            3600
        } else {
            self.sa_token_ttl_secs
                .clamp(MIN_SA_TOKEN_TTL_SECS, MAX_SA_TOKEN_TTL_SECS)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_workspace_storage_size_is_2gi() {
        let cfg = KubernetesComputeConfig::default();
        assert_eq!(
            cfg.workspace_default_storage_size,
            DEFAULT_WORKSPACE_STORAGE_SIZE
        );
    }

    #[test]
    fn default_service_account_name_is_default() {
        let cfg = KubernetesComputeConfig::default();
        assert_eq!(
            cfg.service_account_name,
            DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME
        );
    }

    #[test]
    fn serde_override_workspace_storage_size() {
        let json = serde_json::json!({
            "workspace_default_storage_size": "10Gi"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.workspace_default_storage_size, "10Gi");
    }

    #[test]
    fn serde_override_service_account_name() {
        let json = serde_json::json!({
            "service_account_name": "openshell-sandbox"
        });
        let cfg: KubernetesComputeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.service_account_name, "openshell-sandbox");
    }
}
