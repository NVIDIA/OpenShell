// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SandboxRuntime custom resource definition.
//!
//! Ported from Kagenti's AgentRuntime CRD (`agent.kagenti.dev/v1alpha1`),
//! adapted to OpenShell's sandbox-centric model.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Specification for a SandboxRuntime custom resource.
///
/// Defines the desired state of a managed sandbox workload, including
/// the container image, replica count, environment variables, resource
/// requirements, and service port configuration.
#[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[kube(
    group = "openshell.io",
    version = "v1alpha1",
    kind = "SandboxRuntime",
    plural = "sandboxruntimes",
    namespaced,
    status = "SandboxRuntimeStatus",
    shortname = "srt",
    printcolumn = r#"{"name":"Type","type":"string","jsonPath":".spec.runtimeType"}"#,
    printcolumn = r#"{"name":"Image","type":"string","jsonPath":".spec.image"}"#,
    printcolumn = r#"{"name":"Replicas","type":"integer","jsonPath":".spec.replicas"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
pub struct SandboxRuntimeSpec {
    /// The type of runtime (e.g., "agent", "tool").
    #[serde(default = "default_runtime_type")]
    pub runtime_type: String,

    /// Reference to the target workload managed by this runtime.
    pub target_ref: TargetRef,

    /// Container image for the workload.
    pub image: String,

    /// Desired number of replicas.
    #[serde(default = "default_replicas")]
    pub replicas: i32,

    /// Environment variables to inject into the workload containers.
    #[serde(default)]
    pub env: Vec<EnvVar>,

    /// Resource requirements for the primary container.
    #[serde(default)]
    pub resources: Option<ResourceRequirements>,

    /// Service ports to expose.
    #[serde(default = "default_service_ports")]
    pub service_ports: Vec<ServicePort>,

    /// Human-readable description of the runtime.
    #[serde(default)]
    pub description: String,
}

/// Reference to the Kubernetes workload managed by this `SandboxRuntime`.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TargetRef {
    /// API version of the target (e.g., `"apps/v1"`).
    #[serde(default = "default_api_version")]
    pub api_version: String,

    /// Kind of the target (e.g., `"Deployment"`, `"StatefulSet"`, `"Sandbox"`).
    pub kind: String,

    /// Name of the target workload. Defaults to the `SandboxRuntime` name.
    #[serde(default)]
    pub name: String,
}

/// Environment variable for a container.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct EnvVar {
    /// Variable name.
    pub name: String,
    /// Variable value.
    pub value: String,
}

/// Resource requirements for a container.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ResourceRequirements {
    /// Resource requests (minimum guaranteed).
    #[serde(default)]
    pub requests: Option<ResourceSpec>,
    /// Resource limits (maximum allowed).
    #[serde(default)]
    pub limits: Option<ResourceSpec>,
}

/// CPU and memory resource specifications.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ResourceSpec {
    /// CPU quantity (e.g., `"100m"`, `"1"`).
    #[serde(default)]
    pub cpu: Option<String>,
    /// Memory quantity (e.g., `"256Mi"`, `"1Gi"`).
    #[serde(default)]
    pub memory: Option<String>,
}

/// Service port specification.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServicePort {
    /// Port name.
    #[serde(default = "default_port_name")]
    pub name: String,
    /// Service port number (external).
    #[serde(default = "default_port")]
    pub port: i32,
    /// Target port number (container).
    #[serde(default = "default_target_port")]
    pub target_port: i32,
    /// Protocol (TCP, UDP).
    #[serde(default = "default_protocol")]
    pub protocol: String,
}

/// Status of the `SandboxRuntime` custom resource.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SandboxRuntimeStatus {
    /// Current phase: `Pending`, `Provisioning`, `Ready`, `Error`, `Deleting`.
    #[serde(default)]
    pub phase: String,

    /// Human-readable message about the current state.
    #[serde(default)]
    pub message: String,

    /// Number of ready replicas observed by the controller.
    #[serde(default)]
    pub ready_replicas: i32,

    /// The generation of the spec that was last reconciled.
    #[serde(default)]
    pub observed_generation: i64,

    /// Conditions following Kubernetes conventions.
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

/// Kubernetes-style condition.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    /// Condition type (e.g., `"Ready"`, `"Progressing"`).
    pub r#type: String,
    /// Status value: `"True"`, `"False"`, or `"Unknown"`.
    pub status: String,
    /// Machine-readable reason for the condition.
    #[serde(default)]
    pub reason: String,
    /// Human-readable message.
    #[serde(default)]
    pub message: String,
    /// When the condition last transitioned.
    #[serde(default)]
    pub last_transition_time: Option<String>,
}

// -- Default value functions --------------------------------------------------

fn default_runtime_type() -> String {
    "agent".to_string()
}

fn default_replicas() -> i32 {
    1
}

fn default_api_version() -> String {
    "apps/v1".to_string()
}

fn default_service_ports() -> Vec<ServicePort> {
    vec![ServicePort {
        name: "http".to_string(),
        port: 8080,
        target_port: 8000,
        protocol: "TCP".to_string(),
    }]
}

fn default_port_name() -> String {
    "http".to_string()
}

fn default_port() -> i32 {
    8080
}

fn default_target_port() -> i32 {
    8000
}

fn default_protocol() -> String {
    "TCP".to_string()
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn spec_serializes_all_fields() {
        let spec = SandboxRuntimeSpec {
            runtime_type: "agent".into(),
            target_ref: TargetRef {
                api_version: "apps/v1".into(),
                kind: "Deployment".into(),
                name: "my-agent".into(),
            },
            image: "my-image:latest".into(),
            replicas: 2,
            env: vec![EnvVar {
                name: "PORT".into(),
                value: "8000".into(),
            }],
            resources: Some(ResourceRequirements {
                requests: Some(ResourceSpec {
                    cpu: Some("100m".into()),
                    memory: Some("256Mi".into()),
                }),
                limits: Some(ResourceSpec {
                    cpu: Some("500m".into()),
                    memory: Some("1Gi".into()),
                }),
            }),
            service_ports: vec![ServicePort {
                name: "http".into(),
                port: 8080,
                target_port: 8000,
                protocol: "TCP".into(),
            }],
            description: "Test runtime".into(),
        };

        let json = serde_json::to_string(&spec).unwrap();
        let roundtrip: SandboxRuntimeSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.runtime_type, spec.runtime_type);
        assert_eq!(roundtrip.image, spec.image);
        assert_eq!(roundtrip.replicas, spec.replicas);
        assert_eq!(roundtrip.env, spec.env);
    }

    #[test]
    fn spec_defaults_applied() {
        // Use camelCase keys to match #[serde(rename_all = "camelCase")]
        let json = r#"{"targetRef":{"kind":"Deployment"},"image":"test:v1"}"#;
        let spec: SandboxRuntimeSpec = serde_json::from_str(json).unwrap();
        assert_eq!(spec.runtime_type, "agent");
        assert_eq!(spec.replicas, 1);
        assert_eq!(spec.target_ref.api_version, "apps/v1");
        assert_eq!(spec.service_ports.len(), 1);
        assert_eq!(spec.service_ports[0].port, 8080);
    }

    #[test]
    fn target_ref_deployment() {
        let tr = TargetRef {
            api_version: "apps/v1".into(),
            kind: "Deployment".into(),
            name: "my-agent".into(),
        };
        let json = serde_json::to_value(&tr).unwrap();
        assert_eq!(json["apiVersion"], "apps/v1");
        assert_eq!(json["kind"], "Deployment");
        assert_eq!(json["name"], "my-agent");
    }

    #[test]
    fn target_ref_sandbox() {
        let tr = TargetRef {
            api_version: "agents.x-k8s.io/v1alpha1".into(),
            kind: "Sandbox".into(),
            name: "my-sandbox".into(),
        };
        let json = serde_json::to_value(&tr).unwrap();
        assert_eq!(json["apiVersion"], "agents.x-k8s.io/v1alpha1");
        assert_eq!(json["kind"], "Sandbox");
    }

    #[test]
    fn status_default_is_empty() {
        let status = SandboxRuntimeStatus::default();
        assert!(status.phase.is_empty());
        assert!(status.conditions.is_empty());
        assert_eq!(status.ready_replicas, 0);
    }

    #[test]
    fn status_serializes_with_conditions() {
        let status = SandboxRuntimeStatus {
            phase: "Ready".into(),
            message: "All replicas ready".into(),
            ready_replicas: 1,
            observed_generation: 3,
            conditions: vec![Condition {
                r#type: "Ready".into(),
                status: "True".into(),
                reason: "ReplicasReady".into(),
                message: "All replicas are available".into(),
                last_transition_time: Some("2026-07-03T00:00:00Z".into()),
            }],
        };
        let json = serde_json::to_string(&status).unwrap();
        let roundtrip: SandboxRuntimeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.phase, "Ready");
        assert_eq!(roundtrip.conditions.len(), 1);
        assert_eq!(roundtrip.conditions[0].r#type, "Ready");
    }

    #[test]
    fn conditions_none_deserializes_to_empty_vec() {
        let json = r#"{"phase":"Ready","message":"ok"}"#;
        let status: SandboxRuntimeStatus = serde_json::from_str(json).unwrap();
        assert!(status.conditions.is_empty());
    }

    #[test]
    fn crd_group_version_is_correct() {
        let crd = SandboxRuntime::crd();
        assert_eq!(crd.spec.group, "openshell.io");
        assert_eq!(crd.spec.versions[0].name, "v1alpha1");
    }

    #[test]
    fn crd_plural_is_sandboxruntimes() {
        let crd = SandboxRuntime::crd();
        assert_eq!(crd.spec.names.plural, "sandboxruntimes");
    }

    #[test]
    fn crd_scope_is_namespaced() {
        let crd = SandboxRuntime::crd();
        assert_eq!(crd.spec.scope, "Namespaced");
    }

    #[test]
    fn service_port_defaults() {
        let json = r#"{}"#;
        let sp: ServicePort = serde_json::from_str(json).unwrap();
        assert_eq!(sp.name, "http");
        assert_eq!(sp.port, 8080);
        assert_eq!(sp.target_port, 8000);
        assert_eq!(sp.protocol, "TCP");
    }

    #[test]
    fn env_var_round_trip() {
        let ev = EnvVar {
            name: "MY_VAR".into(),
            value: "my_value".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let roundtrip: EnvVar = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, ev);
    }

    #[test]
    fn camel_case_serialization() {
        let spec = SandboxRuntimeSpec {
            runtime_type: "agent".into(),
            target_ref: TargetRef {
                api_version: "apps/v1".into(),
                kind: "Deployment".into(),
                name: "test".into(),
            },
            image: "img:v1".into(),
            replicas: 1,
            env: vec![],
            resources: None,
            service_ports: vec![],
            description: String::new(),
        };
        let json = serde_json::to_value(&spec).unwrap();
        assert!(json.get("runtimeType").is_some());
        assert!(json.get("targetRef").is_some());
        assert!(json.get("servicePorts").is_some());
    }

    #[test]
    fn crd_shortname_is_srt() {
        let crd = SandboxRuntime::crd();
        let short_names = &crd.spec.names.short_names;
        assert!(
            short_names
                .as_ref()
                .is_some_and(|s| s.contains(&"srt".to_string())),
            "expected shortname 'srt', got: {short_names:?}"
        );
    }

    #[test]
    fn crd_has_print_columns() {
        let crd = SandboxRuntime::crd();
        let version = &crd.spec.versions[0];
        let columns = version
            .additional_printer_columns
            .as_ref()
            .expect("expected print columns");
        assert!(columns.len() >= 4, "expected at least 4 print columns");
    }

    #[test]
    fn resource_requirements_optional() {
        let json = r#"{"targetRef":{"kind":"Deployment"},"image":"test:v1"}"#;
        let spec: SandboxRuntimeSpec = serde_json::from_str(json).unwrap();
        assert!(spec.resources.is_none());
    }

    #[test]
    fn target_ref_name_defaults_to_empty() {
        let json = r#"{"kind":"Deployment"}"#;
        let tr: TargetRef = serde_json::from_str(json).unwrap();
        assert!(tr.name.is_empty());
    }
}
