// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reachable supervisor app endpoints. External ingress routes are owned by
//! ingress integrations, not by this compute driver.

use crate::config::KubernetesAppListenerConfig;
use k8s_openapi::api::core::v1::{
    ContainerPort, EnvVar, Pod, SecretVolumeSource, Volume, VolumeMount,
};

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
        (
            "OPENSHELL_APP_BASE_URL",
            config.common.base_url.clone().unwrap_or_default(),
        ),
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

#[cfg(test)]
mod tests {
    use super::*;

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
            ..Default::default()
        };
        assert_eq!(configure_supervisor_pod(pod.clone(), &config), pod);
    }

    #[test]
    fn supervisor_receives_base_url_separately_from_its_listener_port() {
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
            common: openshell_core::app_listener::AppListenerConfig {
                enabled: true,
                port: 9443,
                base_url: Some("https://services.example.com:10443".into()),
            },
            tls_secret_name: "app-tls".into(),
        };
        config.common.validate().unwrap();
        let pod = configure_supervisor_pod(pod, &config);
        let env = pod.spec.unwrap().containers.remove(0).env.unwrap();
        let value = |name| {
            env.iter()
                .find(|entry| entry.name == name)
                .unwrap()
                .value
                .as_deref()
        };
        assert_eq!(
            value("OPENSHELL_APP_BASE_URL"),
            Some("https://services.example.com:10443")
        );
        assert_eq!(value("OPENSHELL_APP_LISTEN_ADDRESS"), Some("0.0.0.0:9443"));
    }
}
