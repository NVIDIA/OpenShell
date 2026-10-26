// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reachable supervisor app endpoints. External ingress routes are owned by
//! ingress integrations, not by this compute driver.

use crate::config::KubernetesAppListenerConfig;
use crate::driver::KubernetesDriverError;
use k8s_openapi::api::core::v1::{
    ContainerPort, EnvVar, Pod, SecretVolumeSource, Service, ServicePort, ServiceSpec, Volume,
    VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{DeleteParams, Patch, PatchParams, PostParams, Preconditions};
use kube::{Api, Client};
use std::collections::BTreeMap;

const TLS_PATH: &str = "/etc/openshell/app-tls";

pub fn configure_supervisor_pod(mut pod: Pod, config: &KubernetesAppListenerConfig) -> Pod {
    if !config.common.enabled {
        return pod;
    }
    let spec = pod.spec.as_mut().expect("supervisor Pod spec");
    let container = spec
        .containers
        .iter_mut()
        .find(|c| c.name == "supervisor")
        .expect("supervisor container");
    let env = container.env.get_or_insert_default();
    for (name, value) in [
        ("OPENSHELL_APP_LISTENER_ENABLED", "true".to_string()),
        (
            "OPENSHELL_APP_LISTEN_ADDRESS",
            format!("0.0.0.0:{}", config.common.port),
        ),
        ("OPENSHELL_APP_SERVICE_DOMAIN", config.common.domain.clone()),
        ("OPENSHELL_APP_TLS_CERT", format!("{TLS_PATH}/tls.crt")),
        ("OPENSHELL_APP_TLS_KEY", format!("{TLS_PATH}/tls.key")),
    ] {
        env.push(EnvVar {
            name: name.into(),
            value: Some(value),
            ..Default::default()
        });
    }
    container.ports.get_or_insert_default().push(ContainerPort {
        name: Some("app".into()),
        container_port: i32::from(config.common.port),
        protocol: Some("TCP".into()),
        ..Default::default()
    });
    container
        .volume_mounts
        .get_or_insert_default()
        .push(VolumeMount {
            name: "app-tls".into(),
            mount_path: TLS_PATH.into(),
            read_only: Some(true),
            ..Default::default()
        });
    spec.volumes.get_or_insert_default().push(Volume {
        name: "app-tls".into(),
        secret: Some(SecretVolumeSource {
            secret_name: Some(config.tls_secret_name.clone()),
            ..Default::default()
        }),
        ..Default::default()
    });
    pod
}

pub fn app_service(namespace: &str, sandbox_id: &str, port: u16, owner: OwnerReference) -> Service {
    Service {
        metadata: ObjectMeta {
            name: Some(format!("os-app-{sandbox_id}")),
            namespace: Some(namespace.into()),
            owner_references: Some(vec![owner]),
            labels: Some(BTreeMap::from([
                ("openshell.ai/managed-by".into(), "openshell".into()),
                ("openshell.ai/sandbox-id".into(), sandbox_id.into()),
                ("openshell.ai/component".into(), "app-service".into()),
            ])),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            cluster_ip: Some("None".into()),
            selector: Some(BTreeMap::from([
                ("openshell.ai/sandbox-id".into(), sandbox_id.into()),
                ("openshell.ai/component".into(), "supervisor".into()),
            ])),
            ports: Some(vec![ServicePort {
                name: Some("app".into()),
                port: i32::from(port),
                target_port: Some(IntOrString::Int(i32::from(port))),
                protocol: Some("TCP".into()),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub(crate) async fn ensure_service(
    client: Client,
    namespace: &str,
    sandbox_id: &str,
    config: &KubernetesAppListenerConfig,
    owner: OwnerReference,
) -> Result<(), KubernetesDriverError> {
    if !config.create_service {
        return Ok(());
    }
    let api: Api<Service> = Api::namespaced(client, namespace);
    let expected = app_service(namespace, sandbox_id, config.common.port, owner.clone());
    let name = expected.metadata.name.as_deref().expect("app Service name");
    if !config.common.enabled {
        if let Some(current) = api
            .get_opt(name)
            .await
            .map_err(KubernetesDriverError::from_kube)?
            && current
                .metadata
                .owner_references
                .as_ref()
                .is_some_and(|owners| owners.iter().any(|o| same_owner(o, &owner)))
        {
            let params = DeleteParams {
                preconditions: Some(Preconditions {
                    uid: current.metadata.uid,
                    resource_version: current.metadata.resource_version,
                }),
                ..Default::default()
            };
            match api.delete(name, &params).await {
                Ok(_) => {}
                Err(kube::Error::Api(error)) if error.code == 404 => {}
                Err(error) => return Err(KubernetesDriverError::from_kube(error)),
            }
        }
        return Ok(());
    }
    match api.create(&PostParams::default(), &expected).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(error)) if error.code == 409 => {
            let current = api
                .get(name)
                .await
                .map_err(KubernetesDriverError::from_kube)?;
            if !current
                .metadata
                .owner_references
                .as_ref()
                .is_some_and(|owners| owners.iter().any(|o| same_owner(o, &owner)))
            {
                return Err(KubernetesDriverError::Precondition(format!(
                    "app Service {name} is not owned by this sandbox"
                )));
            }
            api.patch(
                name,
                &PatchParams::default(),
                &Patch::Merge(serde_json::json!({
                    "metadata": {"resourceVersion": current.metadata.resource_version},
                    "spec": expected.spec,
                })),
            )
            .await
            .map_err(KubernetesDriverError::from_kube)?;
            Ok(())
        }
        Err(error) => Err(KubernetesDriverError::from_kube(error)),
    }
}

fn same_owner(current: &OwnerReference, expected: &OwnerReference) -> bool {
    // Runtime companions deliberately use non-controller references: the
    // Agent Sandbox controller owns the workload, while this driver owns its
    // companion resources. Preserve that relationship on repeated reconcile.
    current.uid == expected.uid
        && current.name == expected.name
        && current.kind == expected.kind
        && current.api_version == expected.api_version
        && current.controller.unwrap_or(false) == expected.controller.unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reconciles_non_controller_owned_service_without_adopting_foreign_service() {
        use http_body_util::BodyExt as _;
        use std::sync::{Arc, Mutex};

        for enabled in [true, false] {
            for owned in [true, false] {
                let owner = OwnerReference {
                    api_version: "agents.x-k8s.io/v1beta1".into(),
                    kind: "Sandbox".into(),
                    name: "default--demo".into(),
                    uid: "sandbox-uid".into(),
                    controller: Some(false),
                    block_owner_deletion: Some(false),
                };
                let mut current = app_service("workspace", "sandbox-a", 9443, owner.clone());
                current.metadata.uid = Some("service-uid".into());
                current.metadata.resource_version = Some("42".into());
                if !owned {
                    current.metadata.owner_references.as_mut().unwrap()[0].uid = "foreign".into();
                }
                let calls = Arc::new(Mutex::new(Vec::new()));
                let recorded = calls.clone();
                let service = tower::service_fn(
                    move |request: http::Request<kube::client::Body>| {
                        let current = current.clone();
                        let recorded = recorded.clone();
                        async move {
                            let method = request.method().to_string();
                            recorded.lock().unwrap().push(method.clone());
                            let (status, body) = match method.as_str() {
                                "POST" => (
                                    409,
                                    serde_json::json!({
                                        "kind": "Status", "apiVersion": "v1", "status": "Failure",
                                        "reason": "AlreadyExists", "message": "exists", "code": 409,
                                    }),
                                ),
                                "GET" | "PATCH" => (200, serde_json::to_value(&current).unwrap()),
                                "DELETE" => {
                                    let bytes =
                                        request.into_body().collect().await.unwrap().to_bytes();
                                    let body: serde_json::Value =
                                        serde_json::from_slice(&bytes).unwrap();
                                    assert_eq!(body["preconditions"]["uid"], "service-uid");
                                    assert_eq!(body["preconditions"]["resourceVersion"], "42");
                                    (
                                        200,
                                        serde_json::json!({"kind": "Status", "apiVersion": "v1", "status": "Success"}),
                                    )
                                }
                                _ => panic!("unexpected method {method}"),
                            };
                            Ok::<_, std::convert::Infallible>(
                                http::Response::builder()
                                    .status(status)
                                    .body(kube::client::Body::from(body.to_string().into_bytes()))
                                    .unwrap(),
                            )
                        }
                    },
                );
                let config = KubernetesAppListenerConfig {
                    create_service: true,
                    common: openshell_core::app_listener::AppListenerConfig {
                        enabled,
                        port: 9443,
                        domain: "services.example.com".into(),
                    },
                    ..Default::default()
                };
                let result = ensure_service(
                    Client::new(service, "workspace"),
                    "workspace",
                    "sandbox-a",
                    &config,
                    owner,
                )
                .await;
                assert_eq!(result.is_ok(), !enabled || owned);
                let expected = match (enabled, owned) {
                    (true, true) => vec!["POST", "GET", "PATCH"],
                    (true, false) => vec!["POST", "GET"],
                    (false, true) => vec!["GET", "DELETE"],
                    (false, false) => vec!["GET"],
                };
                assert_eq!(*calls.lock().unwrap(), expected);
            }
        }
    }

    #[test]
    fn disabled_listener_does_not_add_ports_or_private_key_mounts() {
        let pod = Pod {
            spec: Some(k8s_openapi::api::core::v1::PodSpec {
                containers: vec![k8s_openapi::api::core::v1::Container {
                    name: "supervisor".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let config = KubernetesAppListenerConfig {
            tls_secret_name: "app-tls".into(),
            create_service: true,
            ..Default::default()
        };
        assert_eq!(configure_supervisor_pod(pod.clone(), &config), pod);
    }

    #[test]
    fn app_endpoint_is_headless_and_selects_only_its_supervisor() {
        let owner = OwnerReference {
            api_version: "v1".into(),
            kind: "Sandbox".into(),
            name: "demo".into(),
            uid: "uid-a".into(),
            controller: Some(true),
            ..Default::default()
        };
        let service = app_service("workspace", "sandbox-a", 9443, owner.clone());
        assert_eq!(service.metadata.owner_references, Some(vec![owner]));
        let spec = service.spec.unwrap();
        assert_eq!(spec.cluster_ip.as_deref(), Some("None"));
        assert_eq!(
            spec.selector.unwrap()["openshell.ai/component"],
            "supervisor"
        );
        assert_eq!(spec.ports.unwrap()[0].port, 9443);
        assert_ne!(spec.publish_not_ready_addresses, Some(true));
    }
}
