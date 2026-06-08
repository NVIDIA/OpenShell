// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rust mirror of the `OpenShellSandbox` CRD schema shipped in
//! `deploy/helm/openshell/crds/openshellsandbox.yaml`.
//!
//! The two must stay in lockstep — adding a field here without updating the
//! CRD schema (or vice versa) lets the kube-apiserver reject or silently
//! drop content at admission.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// `OpenShellSandbox` — declarative request for a single sandbox.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "openshell.nvidia.com",
    version = "v1alpha1",
    kind = "OpenShellSandbox",
    plural = "openshellsandboxes",
    singular = "openshellsandbox",
    shortname = "oshs",
    namespaced,
    status = "OpenShellSandboxStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct OpenShellSandboxSpec {
    /// OCI image reference for the sandbox workload (PID 1 inside the
    /// sandbox container).
    pub image: String,

    /// PID-1 argv inside the sandbox. When `None`, the image's entrypoint
    /// is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_command: Option<Vec<String>>,

    /// Inline policy YAML body, applied to the sandbox via the gateway's
    /// `policy set` semantics.
    pub policy_yaml: String,

    /// In-sandbox listener exposed through the forwarder Service.
    pub expose: ExposeSpec,

    /// Optional pod-shape overrides applied to the agent-sandbox `Sandbox`
    /// podSpec that materialises the workload pod.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_customisations: Option<PodCustomisations>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExposeSpec {
    /// In-sandbox TCP port the forwarder Service publishes.
    pub port: u16,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PodCustomisations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_selector: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tolerations: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affinity: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_class_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_context: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub containers: Vec<ContainerOverride>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<StorageSpec>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ContainerOverride {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_context: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvVar>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volume_mounts: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EnvVar {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_from: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StorageSpec {
    #[serde(default = "default_storage_type")]
    pub r#type: StorageType,
    /// Kubernetes quantity string (e.g. `10Gi`). `None` preserves the
    /// gateway/cluster default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum StorageType {
    #[default]
    Persistent,
    Ephemeral,
}

fn default_storage_type() -> StorageType {
    StorageType::Persistent
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OpenShellSandboxStatus {
    /// Lifecycle phase as observed by the in-process controller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<Phase>,
    /// The gateway's internal UUID for this sandbox, populated once the
    /// gateway create-sandbox call succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
    /// Human-readable detail about the current state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_updated: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
pub enum Phase {
    Pending,
    Provisioning,
    Running,
    Terminating,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    pub r#type: String,
    pub status: String,
    pub last_transition_time: String,
    pub reason: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

