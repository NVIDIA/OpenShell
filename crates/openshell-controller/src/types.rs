// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rust mirror of the `OpenShellSandbox` CRD schema shipped in
//! `deploy/helm/openshell/crds/openshellsandbox.yaml`.
//!
//! The two must stay in lockstep — adding a field here without updating the
//! CRD schema (or vice versa) lets the kube-apiserver reject or silently
//! drop content at admission.

use std::collections::BTreeMap;

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
    /// OCI image reference for the sandbox workload.
    pub image: String,

    /// Inline sandbox policy YAML.
    pub policy_yaml: String,

    /// Environment variables injected into the sandbox at runtime.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environment: BTreeMap<String, String>,

    /// Credential provider names attached to the sandbox.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<String>,

    /// Request an NVIDIA GPU for the sandbox.
    #[serde(default)]
    pub gpu: bool,

    /// PCI BDF or device index for GPU pinning when `gpu` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_device: Option<String>,

    /// Log level exposed to processes running inside the sandbox.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,

    /// Kubernetes `RuntimeClass` name requested for the sandbox pod.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_class_name: Option<String>,

    /// User-supplied labels propagated to the gateway-side sandbox.
    ///
    /// Keys prefixed with `openshell.nvidia.com/` are reserved for the
    /// controller and silently filtered out on the wire.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
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
    Deleted,
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
