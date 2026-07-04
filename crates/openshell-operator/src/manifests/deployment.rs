// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Deployment manifest builder.

use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    Container, ContainerPort, EnvVar as K8sEnvVar, PodSpec, PodTemplateSpec,
    ResourceRequirements as K8sResources,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};

use crate::crd::{SandboxRuntime, SandboxRuntimeSpec};
use crate::labels;
use crate::manifests::build_owner_reference;

/// Build a Deployment manifest from a `SandboxRuntime` spec.
///
/// The Deployment is created with an `OwnerReference` pointing back to the
/// `SandboxRuntime`, ensuring garbage collection on CRD deletion.
pub fn build_deployment(runtime: &SandboxRuntime) -> Deployment {
    let spec = &runtime.spec;
    let name = runtime.metadata.name.as_deref().unwrap_or("unknown");
    let namespace = runtime.metadata.namespace.as_deref().unwrap_or("default");

    let common_labels = build_common_labels(name, spec);
    let selector_labels = build_selector_labels(name);

    Deployment {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(common_labels.clone()),
            owner_references: Some(vec![build_owner_reference(runtime)]),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(spec.replicas),
            selector: LabelSelector {
                match_labels: Some(selector_labels),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(common_labels),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![build_container(spec)],
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn build_container(spec: &SandboxRuntimeSpec) -> Container {
    let env_vars: Vec<K8sEnvVar> = spec
        .env
        .iter()
        .map(|e| K8sEnvVar {
            name: e.name.clone(),
            value: Some(e.value.clone()),
            ..Default::default()
        })
        .collect();

    let ports: Vec<ContainerPort> = spec
        .service_ports
        .iter()
        .map(|sp| ContainerPort {
            name: Some(sp.name.clone()),
            container_port: sp.target_port,
            protocol: Some(sp.protocol.clone()),
            ..Default::default()
        })
        .collect();

    let resources = spec.resources.as_ref().map(|r| {
        let mut k8s_res = K8sResources::default();
        if let Some(req) = &r.requests {
            let mut map = BTreeMap::new();
            if let Some(cpu) = &req.cpu {
                map.insert("cpu".to_string(), Quantity(cpu.clone()));
            }
            if let Some(mem) = &req.memory {
                map.insert("memory".to_string(), Quantity(mem.clone()));
            }
            k8s_res.requests = Some(map);
        }
        if let Some(lim) = &r.limits {
            let mut map = BTreeMap::new();
            if let Some(cpu) = &lim.cpu {
                map.insert("cpu".to_string(), Quantity(cpu.clone()));
            }
            if let Some(mem) = &lim.memory {
                map.insert("memory".to_string(), Quantity(mem.clone()));
            }
            k8s_res.limits = Some(map);
        }
        k8s_res
    });

    Container {
        name: labels::DEFAULT_CONTAINER_NAME.to_string(),
        image: Some(spec.image.clone()),
        image_pull_policy: Some(labels::DEFAULT_IMAGE_PULL_POLICY.to_string()),
        env: if env_vars.is_empty() {
            None
        } else {
            Some(env_vars)
        },
        ports: if ports.is_empty() { None } else { Some(ports) },
        resources,
        ..Default::default()
    }
}

/// Build the common label set for workload metadata and pod templates.
pub fn build_common_labels(name: &str, spec: &SandboxRuntimeSpec) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert(labels::APP_NAME_KEY.to_string(), name.to_string());
    map.insert(
        labels::MANAGED_BY_KEY.to_string(),
        labels::MANAGER_NAME.to_string(),
    );
    map.insert(
        labels::RUNTIME_TYPE_KEY.to_string(),
        spec.runtime_type.clone(),
    );
    map.insert(
        labels::WORKLOAD_TYPE_KEY.to_string(),
        spec.target_ref.kind.to_lowercase(),
    );
    map.insert(
        labels::COMPONENT_KEY.to_string(),
        labels::COMPONENT_SANDBOX.to_string(),
    );
    map
}

/// Build the pod selector labels (subset of common labels).
pub fn build_selector_labels(name: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert(labels::APP_NAME_KEY.to_string(), name.to_string());
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{ResourceRequirements, ResourceSpec, ServicePort, TargetRef};

    fn make_runtime(name: &str) -> SandboxRuntime {
        SandboxRuntime::new(
            name,
            SandboxRuntimeSpec {
                runtime_type: "agent".into(),
                target_ref: TargetRef {
                    api_version: "apps/v1".into(),
                    kind: "Deployment".into(),
                    name: name.into(),
                },
                image: "my-image:v1".into(),
                replicas: 1,
                env: vec![],
                resources: None,
                service_ports: vec![ServicePort {
                    name: "http".into(),
                    port: 8080,
                    target_port: 8000,
                    protocol: "TCP".into(),
                }],
                description: "test".into(),
            },
        )
    }

    #[test]
    fn deployment_has_correct_name() {
        let rt = make_runtime("my-agent");
        let dep = build_deployment(&rt);
        assert_eq!(dep.metadata.name.as_deref(), Some("my-agent"));
    }

    #[test]
    fn deployment_has_single_replica() {
        let rt = make_runtime("my-agent");
        let dep = build_deployment(&rt);
        assert_eq!(dep.spec.as_ref().unwrap().replicas, Some(1));
    }

    #[test]
    fn deployment_uses_specified_image() {
        let rt = make_runtime("my-agent");
        let dep = build_deployment(&rt);
        let container =
            &dep.spec.as_ref().unwrap().template.spec.as_ref().unwrap().containers[0];
        assert_eq!(container.image.as_deref(), Some("my-image:v1"));
    }

    #[test]
    fn deployment_has_agent_container() {
        let rt = make_runtime("my-agent");
        let dep = build_deployment(&rt);
        let containers =
            &dep.spec.as_ref().unwrap().template.spec.as_ref().unwrap().containers;
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].name, "agent");
    }

    #[test]
    fn deployment_labels_match_selector() {
        let rt = make_runtime("my-agent");
        let dep = build_deployment(&rt);
        let dep_spec = dep.spec.as_ref().unwrap();
        let selector = dep_spec.selector.match_labels.as_ref().unwrap();
        let template_labels = dep_spec
            .template
            .metadata
            .as_ref()
            .unwrap()
            .labels
            .as_ref()
            .unwrap();
        for (k, v) in selector {
            assert_eq!(
                template_labels.get(k),
                Some(v),
                "selector label {k} missing from template"
            );
        }
    }

    #[test]
    fn deployment_owner_reference_set() {
        let mut rt = make_runtime("my-agent");
        rt.metadata.uid = Some("test-uid".into());
        let dep = build_deployment(&rt);
        let refs = dep.metadata.owner_references.as_ref().unwrap();
        assert_eq!(refs.len(), 1);
        assert!(refs[0].controller.unwrap());
        assert!(refs[0].block_owner_deletion.unwrap());
        assert_eq!(refs[0].name, "my-agent");
        assert_eq!(refs[0].uid, "test-uid");
    }

    #[test]
    fn deployment_env_vars_included() {
        let mut rt = make_runtime("my-agent");
        rt.spec.env = vec![crate::crd::EnvVar {
            name: "PORT".into(),
            value: "8000".into(),
        }];
        let dep = build_deployment(&rt);
        let container =
            &dep.spec.as_ref().unwrap().template.spec.as_ref().unwrap().containers[0];
        let env = container.env.as_ref().unwrap();
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].name, "PORT");
        assert_eq!(env[0].value.as_deref(), Some("8000"));
    }

    #[test]
    fn deployment_resource_limits_set() {
        let mut rt = make_runtime("my-agent");
        rt.spec.resources = Some(ResourceRequirements {
            requests: Some(ResourceSpec {
                cpu: Some("100m".into()),
                memory: Some("256Mi".into()),
            }),
            limits: Some(ResourceSpec {
                cpu: Some("500m".into()),
                memory: Some("1Gi".into()),
            }),
        });
        let dep = build_deployment(&rt);
        let container =
            &dep.spec.as_ref().unwrap().template.spec.as_ref().unwrap().containers[0];
        let res = container.resources.as_ref().unwrap();
        let limits = res.limits.as_ref().unwrap();
        assert_eq!(limits.get("cpu").unwrap().0, "500m");
        assert_eq!(limits.get("memory").unwrap().0, "1Gi");
        let requests = res.requests.as_ref().unwrap();
        assert_eq!(requests.get("cpu").unwrap().0, "100m");
    }

    #[test]
    fn deployment_port_set() {
        let rt = make_runtime("my-agent");
        let dep = build_deployment(&rt);
        let container =
            &dep.spec.as_ref().unwrap().template.spec.as_ref().unwrap().containers[0];
        let ports = container.ports.as_ref().unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].container_port, 8000);
        assert_eq!(ports[0].name.as_deref(), Some("http"));
    }

    #[test]
    fn common_labels_include_all_keys() {
        let spec = SandboxRuntimeSpec {
            runtime_type: "agent".into(),
            target_ref: TargetRef {
                api_version: "apps/v1".into(),
                kind: "Deployment".into(),
                name: "test".into(),
            },
            image: "img".into(),
            replicas: 1,
            env: vec![],
            resources: None,
            service_ports: vec![],
            description: String::new(),
        };
        let labels = build_common_labels("my-agent", &spec);
        assert_eq!(labels.get(labels::APP_NAME_KEY).unwrap(), "my-agent");
        assert_eq!(
            labels.get(labels::MANAGED_BY_KEY).unwrap(),
            "openshell-operator"
        );
        assert_eq!(labels.get(labels::RUNTIME_TYPE_KEY).unwrap(), "agent");
        assert_eq!(
            labels.get(labels::WORKLOAD_TYPE_KEY).unwrap(),
            "deployment"
        );
        assert_eq!(labels.get(labels::COMPONENT_KEY).unwrap(), "sandbox");
    }

    #[test]
    fn selector_labels_only_name() {
        let labels = build_selector_labels("my-agent");
        assert_eq!(labels.len(), 1);
        assert_eq!(labels.get(labels::APP_NAME_KEY).unwrap(), "my-agent");
    }

    #[test]
    fn selector_labels_subset_of_common() {
        let spec = SandboxRuntimeSpec {
            runtime_type: "agent".into(),
            target_ref: TargetRef {
                api_version: "apps/v1".into(),
                kind: "Deployment".into(),
                name: "test".into(),
            },
            image: "img".into(),
            replicas: 1,
            env: vec![],
            resources: None,
            service_ports: vec![],
            description: String::new(),
        };
        let common = build_common_labels("my-agent", &spec);
        let selector = build_selector_labels("my-agent");
        for (k, v) in &selector {
            assert_eq!(
                common.get(k),
                Some(v),
                "selector key {k} not in common labels"
            );
        }
    }

    #[test]
    fn deployment_no_env_is_none() {
        let rt = make_runtime("my-agent");
        let dep = build_deployment(&rt);
        let container =
            &dep.spec.as_ref().unwrap().template.spec.as_ref().unwrap().containers[0];
        assert!(container.env.is_none());
    }

    #[test]
    fn deployment_multiple_replicas() {
        let mut rt = make_runtime("my-agent");
        rt.spec.replicas = 3;
        let dep = build_deployment(&rt);
        assert_eq!(dep.spec.as_ref().unwrap().replicas, Some(3));
    }
}
