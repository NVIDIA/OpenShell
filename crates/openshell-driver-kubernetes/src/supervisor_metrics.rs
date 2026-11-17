// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in deployment inputs for dedicated supervisor metrics.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{
    ContainerPort, EnvVar, Pod, SecretVolumeSource, Volume, VolumeMount,
};
use k8s_openapi::api::networking::v1::{
    NetworkPolicy, NetworkPolicyIngressRule, NetworkPolicyPeer, NetworkPolicyPort,
    NetworkPolicySpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::core::ObjectMeta;
use serde::{Deserialize, Serialize};

const METRICS_LABEL: &str = "openshell.ai/supervisor-metrics";
const SERVER_PATH: &str = "/etc/openshell-metrics/server";
const CLIENT_CA_PATH: &str = "/etc/openshell-metrics/client-ca";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    pub port: u16,
    pub scraper_namespace: String,
    pub tls_cert_secret_name: Option<String>,
    pub tls_client_ca_secret_name: Option<String>,
    pub require_client_auth: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 9091,
            scraper_namespace: "observability".into(),
            tls_cert_secret_name: None,
            tls_client_ca_secret_name: None,
            require_client_auth: false,
        }
    }
}

impl Config {
    pub(crate) fn validate(
        &self,
        runtime_port: u16,
        app: &openshell_core::app_listener::AppListenerConfig,
    ) -> Result<(), String> {
        use crate::config::is_dns_subdomain;
        if !self.enabled {
            if self.tls_cert_secret_name.is_some()
                || self.tls_client_ca_secret_name.is_some()
                || self.require_client_auth
            {
                return Err("supervisor metrics TLS requires metrics.enabled".into());
            }
            return Ok(());
        }
        if self.port < 1024
            || [runtime_port, 5501].contains(&self.port)
            || (app.enabled && self.port == app.port)
        {
            return Err("supervisor metrics port must be at least 1024 and distinct from runtime, health, and enabled app ports".into());
        }
        if self.scraper_namespace.len() > 63
            || !is_dns_subdomain(&self.scraper_namespace)
            || self.scraper_namespace.contains('.')
        {
            return Err(
                "supervisor metrics scraper_namespace must be a Kubernetes namespace name".into(),
            );
        }
        for name in [&self.tls_cert_secret_name, &self.tls_client_ca_secret_name]
            .into_iter()
            .flatten()
        {
            if !is_dns_subdomain(name) {
                return Err(
                    "supervisor metrics TLS Secret names must be DNS subdomain names".into(),
                );
            }
        }
        if self.tls_cert_secret_name.is_none()
            && (self.tls_client_ca_secret_name.is_some() || self.require_client_auth)
        {
            return Err(
                "supervisor metrics client authentication requires tls_cert_secret_name".into(),
            );
        }
        if self.require_client_auth && self.tls_client_ca_secret_name.is_none() {
            return Err(
                "supervisor metrics require_client_auth requires tls_client_ca_secret_name".into(),
            );
        }
        Ok(())
    }
}

pub(crate) fn configure_pod(mut pod: Pod, config: &Config) -> Pod {
    if !config.enabled {
        return pod;
    }
    pod.metadata
        .labels
        .get_or_insert_default()
        .insert(METRICS_LABEL.into(), "enabled".into());
    let spec = pod.spec.as_mut().expect("supervisor Pod spec");
    let container = spec
        .containers
        .iter_mut()
        .find(|c| c.name == "supervisor")
        .expect("supervisor container");
    let env = container.env.get_or_insert_default();
    let mut add_env = |name: &str, value: String| {
        env.push(EnvVar {
            name: name.into(),
            value: Some(value),
            ..Default::default()
        });
    };
    add_env(
        "OPENSHELL_SUPERVISOR_METRICS_BIND_ADDRESS",
        format!("0.0.0.0:{}", config.port),
    );
    if config.tls_cert_secret_name.is_some() {
        add_env(
            "OPENSHELL_SUPERVISOR_METRICS_TLS_CERT",
            format!("{SERVER_PATH}/tls.crt"),
        );
        add_env(
            "OPENSHELL_SUPERVISOR_METRICS_TLS_KEY",
            format!("{SERVER_PATH}/tls.key"),
        );
    }
    if config.tls_client_ca_secret_name.is_some() {
        add_env(
            "OPENSHELL_SUPERVISOR_METRICS_TLS_CLIENT_CA",
            format!("{CLIENT_CA_PATH}/ca.crt"),
        );
    }
    add_env(
        "OPENSHELL_SUPERVISOR_METRICS_REQUIRE_CLIENT_AUTH",
        config.require_client_auth.to_string(),
    );
    container.ports.get_or_insert_default().push(ContainerPort {
        name: Some("metrics".into()),
        container_port: i32::from(config.port),
        protocol: Some("TCP".into()),
        ..Default::default()
    });
    for (name, path, secret) in [
        (
            "metrics-server-tls",
            SERVER_PATH,
            &config.tls_cert_secret_name,
        ),
        (
            "metrics-client-ca",
            CLIENT_CA_PATH,
            &config.tls_client_ca_secret_name,
        ),
    ] {
        if let Some(secret) = secret {
            container
                .volume_mounts
                .get_or_insert_default()
                .push(VolumeMount {
                    name: name.into(),
                    mount_path: path.into(),
                    read_only: Some(true),
                    ..Default::default()
                });
            spec.volumes.get_or_insert_default().push(Volume {
                name: name.into(),
                secret: Some(SecretVolumeSource {
                    secret_name: Some(secret.clone()),
                    default_mode: Some(0o440),
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
    }
    pod
}

/// This policy only selects metrics-enabled dedicated control Pods. Their
/// per-pair runtime policy continues to admit the workload control connection.
/// The workload fence remains unchanged and forbids workload metrics access.
pub(crate) fn network_policy(
    namespace: &str,
    gateway_id: &str,
    config: &Config,
) -> Option<NetworkPolicy> {
    if !config.enabled {
        return None;
    }
    Some(NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(format!("openshell-{gateway_id}-supervisor-metrics")),
            namespace: Some(namespace.into()),
            labels: Some(BTreeMap::from([(
                "openshell.ai/managed-by".into(),
                "openshell".into(),
            )])),
            ..Default::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: LabelSelector {
                match_labels: Some(BTreeMap::from([
                    (METRICS_LABEL.into(), "enabled".into()),
                    ("openshell.ai/gateway-id".into(), gateway_id.into()),
                    ("openshell.ai/boundary-role".into(), "supervisor".into()),
                ])),
                ..Default::default()
            },
            policy_types: Some(vec!["Ingress".into()]),
            ingress: Some(vec![NetworkPolicyIngressRule {
                from: Some(vec![NetworkPolicyPeer {
                    namespace_selector: Some(LabelSelector {
                        match_labels: Some(BTreeMap::from([(
                            "kubernetes.io/metadata.name".into(),
                            config.scraper_namespace.clone(),
                        )])),
                        ..Default::default()
                    }),
                    pod_selector: Some(LabelSelector {
                        match_labels: Some(BTreeMap::from([(
                            "openshell.ai/supervisor-metrics-scraper".into(),
                            "true".into(),
                        )])),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ports: Some(vec![NetworkPolicyPort {
                    port: Some(IntOrString::Int(i32::from(config.port))),
                    protocol: Some("TCP".into()),
                    ..Default::default()
                }]),
            }]),
            ..Default::default()
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod() -> Pod {
        Pod {
            spec: Some(k8s_openapi::api::core::v1::PodSpec {
                containers: vec![k8s_openapi::api::core::v1::Container {
                    name: "supervisor".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn disabled_preserves_pod_and_adds_no_network_policy() {
        assert_eq!(configure_pod(pod(), &Config::default()), pod());
        assert!(network_policy("test", "gateway", &Config::default()).is_none());
    }

    #[test]
    fn mtls_mounts_only_metrics_material_and_publishes_scrape_port() {
        let config = Config {
            enabled: true,
            tls_cert_secret_name: Some("metrics-server".into()),
            tls_client_ca_secret_name: Some("metrics-scrapers".into()),
            require_client_auth: true,
            ..Default::default()
        };
        let pod = configure_pod(pod(), &config);
        let spec = pod.spec.unwrap();
        let container = &spec.containers[0];
        assert_eq!(
            container.ports.as_ref().unwrap()[0].name.as_deref(),
            Some("metrics")
        );
        let env = container.env.as_ref().unwrap();
        assert!(
            env.iter()
                .any(|v| v.name == "OPENSHELL_SUPERVISOR_METRICS_TLS_CERT"
                    && v.value.as_deref() == Some("/etc/openshell-metrics/server/tls.crt"))
        );
        assert!(env.iter().any(
            |v| v.name == "OPENSHELL_SUPERVISOR_METRICS_REQUIRE_CLIENT_AUTH"
                && v.value.as_deref() == Some("true")
        ));
        let volumes = spec.volumes.unwrap();
        assert_eq!(volumes.len(), 2);
        assert_eq!(
            volumes[0].secret.as_ref().unwrap().secret_name.as_deref(),
            Some("metrics-server")
        );
        assert_eq!(
            volumes[1].secret.as_ref().unwrap().secret_name.as_deref(),
            Some("metrics-scrapers")
        );
        let policy = network_policy("workspaces", "gateway", &config)
            .unwrap()
            .spec
            .unwrap();
        assert_eq!(
            policy.pod_selector.match_labels.unwrap()["openshell.ai/boundary-role"],
            "supervisor"
        );
        let ingress = &policy.ingress.unwrap()[0];
        assert_eq!(
            ingress.ports.as_ref().unwrap()[0].port,
            Some(IntOrString::Int(9091))
        );
        let peer = &ingress.from.as_ref().unwrap()[0];
        assert_eq!(
            peer.namespace_selector
                .as_ref()
                .unwrap()
                .match_labels
                .as_ref()
                .unwrap()["kubernetes.io/metadata.name"],
            "observability"
        );
        assert_eq!(
            peer.pod_selector
                .as_ref()
                .unwrap()
                .match_labels
                .as_ref()
                .unwrap()["openshell.ai/supervisor-metrics-scraper"],
            "true"
        );
    }

    #[test]
    fn validates_ports_and_tls_relationships() {
        let app = openshell_core::app_listener::AppListenerConfig::default();
        let mut config = Config {
            enabled: true,
            ..Default::default()
        };
        assert!(config.validate(5500, &app).is_ok());
        config.port = 5500;
        assert!(config.validate(5500, &app).is_err());
        config.port = 9091;
        config.require_client_auth = true;
        assert!(config.validate(5500, &app).is_err());
        config.tls_cert_secret_name = Some("metrics-server".into());
        assert!(config.validate(5500, &app).is_err());
        config.tls_client_ca_secret_name = Some("metrics-scrapers".into());
        assert!(config.validate(5500, &app).is_ok());
    }
}
