// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Service manifest builder.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{Service, ServicePort as K8sServicePort, ServiceSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

use crate::crd::SandboxRuntime;
use crate::labels;
use crate::manifests::build_owner_reference;

/// Build a ClusterIP Service manifest from a `SandboxRuntime` spec.
pub fn build_service(runtime: &SandboxRuntime) -> Service {
    let spec = &runtime.spec;
    let name = runtime.metadata.name.as_deref().unwrap_or("unknown");
    let namespace = runtime.metadata.namespace.as_deref().unwrap_or("default");

    let mut selector = BTreeMap::new();
    selector.insert(labels::APP_NAME_KEY.to_string(), name.to_string());

    let ports: Vec<K8sServicePort> = spec
        .service_ports
        .iter()
        .map(|sp| K8sServicePort {
            name: Some(sp.name.clone()),
            port: sp.port,
            target_port: Some(IntOrString::Int(sp.target_port)),
            protocol: Some(sp.protocol.clone()),
            ..Default::default()
        })
        .collect();

    let mut svc_labels = BTreeMap::new();
    svc_labels.insert(labels::APP_NAME_KEY.to_string(), name.to_string());
    svc_labels.insert(
        labels::MANAGED_BY_KEY.to_string(),
        labels::MANAGER_NAME.to_string(),
    );

    Service {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(svc_labels),
            owner_references: Some(vec![build_owner_reference(runtime)]),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(selector),
            ports: Some(ports),
            type_: Some("ClusterIP".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{SandboxRuntimeSpec, ServicePort, TargetRef};

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
                description: String::new(),
            },
        )
    }

    #[test]
    fn service_has_correct_type() {
        let rt = make_runtime("my-agent");
        let svc = build_service(&rt);
        assert_eq!(
            svc.spec.as_ref().unwrap().type_.as_deref(),
            Some("ClusterIP")
        );
    }

    #[test]
    fn service_selector_matches_deployment() {
        let rt = make_runtime("my-agent");
        let svc = build_service(&rt);
        let selector = svc.spec.as_ref().unwrap().selector.as_ref().unwrap();
        assert_eq!(selector.get(labels::APP_NAME_KEY).unwrap(), "my-agent");
    }

    #[test]
    fn service_port_maps_correctly() {
        let rt = make_runtime("my-agent");
        let svc = build_service(&rt);
        let ports = svc.spec.as_ref().unwrap().ports.as_ref().unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 8080);
        assert_eq!(ports[0].target_port, Some(IntOrString::Int(8000)));
        assert_eq!(ports[0].name.as_deref(), Some("http"));
    }

    #[test]
    fn service_owner_reference_set() {
        let mut rt = make_runtime("my-agent");
        rt.metadata.uid = Some("test-uid".into());
        let svc = build_service(&rt);
        let refs = svc.metadata.owner_references.as_ref().unwrap();
        assert_eq!(refs.len(), 1);
        assert!(refs[0].controller.unwrap());
        assert_eq!(refs[0].name, "my-agent");
    }

    #[test]
    fn service_name_matches_runtime() {
        let rt = make_runtime("my-agent");
        let svc = build_service(&rt);
        assert_eq!(svc.metadata.name.as_deref(), Some("my-agent"));
    }

    #[test]
    fn service_namespace_matches_runtime() {
        let rt = make_runtime("my-agent");
        let svc = build_service(&rt);
        // SandboxRuntime::new doesn't set namespace by default
        assert_eq!(svc.metadata.namespace.as_deref(), Some("default"));
    }

    #[test]
    fn service_has_managed_by_label() {
        let rt = make_runtime("my-agent");
        let svc = build_service(&rt);
        let labels = svc.metadata.labels.as_ref().unwrap();
        assert_eq!(
            labels.get(labels::MANAGED_BY_KEY).unwrap(),
            labels::MANAGER_NAME
        );
    }

    #[test]
    fn service_multiple_ports() {
        let mut rt = make_runtime("my-agent");
        rt.spec.service_ports = vec![
            ServicePort {
                name: "http".into(),
                port: 8080,
                target_port: 8000,
                protocol: "TCP".into(),
            },
            ServicePort {
                name: "metrics".into(),
                port: 9090,
                target_port: 9090,
                protocol: "TCP".into(),
            },
        ];
        let svc = build_service(&rt);
        let ports = svc.spec.as_ref().unwrap().ports.as_ref().unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[1].port, 9090);
    }
}
