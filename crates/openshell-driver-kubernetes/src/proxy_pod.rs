// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes resources owned by the RFC 0012 proxy-pod topology.

use std::collections::BTreeMap;
use std::path::Path;

use k8s_openapi::ByteString;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicySpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference};
use kube::core::ObjectMeta;
use rcgen::{CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

use crate::isolation::{
    BOUNDARY_PAIR_LABEL, BOUNDARY_ROLE_LABEL, KubernetesProxyPodNetworkFence,
    KubernetesProxyPodNetworkFenceSpec,
};

pub const SANDBOX_SECRET_COMPONENT: &str = "sandbox-bootstrap";
pub const SUPERVISOR_SECRET_COMPONENT: &str = "supervisor-bootstrap";
pub const BOUNDARY_CONFIG_KEY: &str = "boundary.json";
pub const TOPOLOGY_PAYLOAD_KEY: &str = "topology.json";
pub const BOUNDARY_CERTIFICATE_KEY: &str = "tls.crt";
pub const BOUNDARY_PRIVATE_KEY: &str = "tls.key";
pub const BOUNDARY_CLIENT_CA_KEY: &str = "client-ca.crt";
pub const PROXY_CA_CERTIFICATE_KEY: &str = "proxy-ca.crt";
pub const PROXY_CA_PRIVATE_KEY: &str = "proxy-ca.key";
pub const SANDBOX_BOOTSTRAP_INPUT_PATH: &str = "/.openshell/bootstrap-input";
pub const BOUNDARY_CONFIG_PATH: &str = "/.openshell/state/bootstrap/boundary.json";
pub const BOUNDARY_CERTIFICATE_PATH: &str = "/.openshell/state/bootstrap/tls.crt";
pub const BOUNDARY_PRIVATE_KEY_PATH: &str = "/.openshell/state/bootstrap/tls.key";
pub const BOUNDARY_CLIENT_CA_PATH: &str = "/.openshell/state/bootstrap/client-ca.crt";
pub const TOPOLOGY_PAYLOAD_PATH: &str = "/.openshell/supervisor/topology.json";
pub const PROXY_CA_CERTIFICATE_PATH: &str = "/.openshell/supervisor/proxy-ca.crt";
pub const PROXY_CA_PRIVATE_KEY_PATH: &str = "/.openshell/supervisor/proxy-ca.key";
pub const CONTROL_HEALTH_SOCKET_PATH: &str = "/run/openshell/health.sock";

pub struct ProxyCaMaterial {
    pub certificate_pem: String,
    pub private_key_pem: String,
}

pub fn generate_proxy_ca_material() -> Result<ProxyCaMaterial, String> {
    let key = KeyPair::generate().map_err(|error| format!("generate proxy CA key: {error}"))?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "OpenShell Sandbox CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "OpenShell");
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let certificate = params
        .self_signed(&key)
        .map_err(|error| format!("generate proxy CA certificate: {error}"))?;
    Ok(ProxyCaMaterial {
        certificate_pem: certificate.pem(),
        private_key_pem: key.serialize_pem(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyPodNames {
    pub sandbox_secret: String,
    pub supervisor_secret: String,
    pub boundary_service: String,
    pub control_deployment: String,
    pub workload_policy: String,
    pub control_policy: String,
}

impl ProxyPodNames {
    #[must_use]
    pub fn new(sandbox_id: &str) -> Self {
        let suffix = sandbox_id.to_ascii_lowercase();
        Self {
            sandbox_secret: format!("os-sandbox-{suffix}"),
            supervisor_secret: format!("os-supervisor-{suffix}"),
            boundary_service: format!("os-boundary-{suffix}"),
            control_deployment: format!("os-supervisor-{suffix}"),
            workload_policy: format!("os-boundary-{suffix}"),
            control_policy: format!("os-supervisor-{suffix}"),
        }
    }

    /// Return stable companion names plus generation-specific immutable
    /// bootstrap Secret names.
    #[must_use]
    pub fn for_generation(sandbox_id: &str, generation: &str) -> Self {
        let mut names = Self::new(sandbox_id);
        let generation = generation
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(12)
            .collect::<String>()
            .to_ascii_lowercase();
        names.sandbox_secret = format!("{}-{generation}", names.sandbox_secret);
        names.supervisor_secret = format!("{}-{generation}", names.supervisor_secret);
        names
    }
}

#[must_use]
pub fn pair_label_value(sandbox_id: &str) -> String {
    sandbox_id.to_ascii_lowercase()
}

#[must_use]
pub fn workload_fence(
    namespace: &str,
    names: &ProxyPodNames,
    sandbox_id: &str,
    boundary_port: u16,
) -> KubernetesProxyPodNetworkFence {
    KubernetesProxyPodNetworkFenceSpec {
        namespace: namespace.to_string(),
        policy_name: names.workload_policy.clone(),
        pair_label_value: pair_label_value(sandbox_id),
        boundary_port,
    }
    .provision()
}

#[must_use]
pub fn boundary_service(
    namespace: &str,
    names: &ProxyPodNames,
    sandbox_id: &str,
    boundary_port: u16,
    owner: OwnerReference,
) -> Service {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": names.boundary_service,
            "namespace": namespace,
            "ownerReferences": [owner],
            "labels": common_labels(sandbox_id, "boundary-service"),
        },
        "spec": {
            "selector": pair_labels(sandbox_id, "workload"),
            "ports": [{"name": "boundary", "protocol": "TCP", "port": boundary_port, "targetPort": boundary_port}],
        }
    }))
    .expect("boundary Service renderer must produce a valid object")
}

#[allow(clippy::too_many_arguments, clippy::similar_names)]
#[must_use]
pub fn control_deployment(
    namespace: &str,
    names: &ProxyPodNames,
    sandbox_id: &str,
    sandbox_name: &str,
    gateway_id: &str,
    supervisor_image: &str,
    supervisor_pull_policy: &str,
    service_account_name: &str,
    control_uid: u32,
    control_gid: u32,
    image_pull_secrets: &[String],
    grpc_endpoint: &str,
    client_tls_secret_name: &str,
    main_process_spec: &str,
    log_level: &str,
    sa_token_ttl_secs: i64,
    https_proxy: Option<&str>,
    no_proxy: Option<&str>,
    proxy_auth_secret: Option<(&str, &str)>,
    proxy_auth_allow_insecure: bool,
    proxy_connect_by_hostname: bool,
    provider_spiffe_socket_path: Option<&str>,
    owner: OwnerReference,
) -> Deployment {
    let labels = control_labels(sandbox_id, gateway_id);
    let mut environment = vec![
        env_var(
            "OPENSHELL_ADMITTED_ISOLATION_BACKEND",
            crate::isolation::BACKEND_NAME,
        ),
        env_var("OPENSHELL_ENDPOINT", grpc_endpoint),
        env_var("OPENSHELL_SANDBOX_ID", sandbox_id),
        env_var("OPENSHELL_SANDBOX", sandbox_name),
        env_var("OPENSHELL_MAIN_PROCESS_SPEC", main_process_spec),
        env_var(
            "OPENSHELL_K8S_SA_TOKEN_FILE",
            "/var/run/secrets/openshell/token",
        ),
        env_var("OPENSHELL_SSH_SOCKET_PATH", "/run/openshell/ssh.sock"),
        env_var(openshell_core::sandbox_env::SSH_SOCKET_SHARED, "true"),
        env_var("OPENSHELL_PROXY_TLS_DIR", "/run/openshell/proxy-tls"),
        env_var(
            openshell_core::sandbox_env::PROXY_CA_CERT,
            PROXY_CA_CERTIFICATE_PATH,
        ),
        env_var(
            openshell_core::sandbox_env::PROXY_CA_KEY,
            PROXY_CA_PRIVATE_KEY_PATH,
        ),
        env_var("OPENSHELL_LOG_LEVEL", log_level),
        env_var(
            openshell_core::sandbox_env::TELEMETRY_ENABLED,
            openshell_core::telemetry::enabled_env_value(),
        ),
        env_var(
            openshell_core::sandbox_env::NETWORK_RUNTIME_CAPABILITIES,
            "",
        ),
    ];
    let mut volume_mounts = vec![
        serde_json::json!({"name": "bootstrap", "mountPath": "/.openshell/supervisor", "readOnly": true}),
        serde_json::json!({"name": "sa-token", "mountPath": "/var/run/secrets/openshell", "readOnly": true}),
        serde_json::json!({"name": "run", "mountPath": "/run/openshell"}),
        serde_json::json!({"name": "logs", "mountPath": "/var/log"}),
    ];
    let mut volumes = vec![
        serde_json::json!({"name": "bootstrap", "secret": {"secretName": names.supervisor_secret, "defaultMode": 0o440}}),
        serde_json::json!({"name": "sa-token", "projected": {"sources": [{"serviceAccountToken": {"audience": "openshell-gateway", "expirationSeconds": sa_token_ttl_secs, "path": "token"}}], "defaultMode": 0o440}}),
        serde_json::json!({"name": "run", "emptyDir": {}}),
        serde_json::json!({"name": "logs", "emptyDir": {}}),
    ];
    if !client_tls_secret_name.is_empty() {
        environment.extend([
            env_var("OPENSHELL_TLS_CA", "/var/run/secrets/openshell-tls/ca.crt"),
            env_var(
                "OPENSHELL_TLS_CERT",
                "/var/run/secrets/openshell-tls/tls.crt",
            ),
            env_var(
                "OPENSHELL_TLS_KEY",
                "/var/run/secrets/openshell-tls/tls.key",
            ),
        ]);
        volume_mounts.push(serde_json::json!({"name": "client-tls", "mountPath": "/var/run/secrets/openshell-tls", "readOnly": true}));
        volumes.push(serde_json::json!({"name": "client-tls", "secret": {"secretName": client_tls_secret_name, "defaultMode": 0o440}}));
    }
    let mut command = vec![
        "/openshell-supervisor".to_string(),
        "--topology-backend-name".to_string(),
        crate::isolation::BACKEND_NAME.to_string(),
        "--topology-payload-file".to_string(),
        TOPOLOGY_PAYLOAD_PATH.to_string(),
        "--workdir".to_string(),
        "/sandbox".to_string(),
        "--health-socket-path".to_string(),
        CONTROL_HEALTH_SOCKET_PATH.to_string(),
    ];
    if let Some(url) = https_proxy {
        command.extend(["--upstream-proxy".to_string(), url.to_string()]);
    }
    if let Some(hosts) = no_proxy {
        command.extend(["--upstream-no-proxy".to_string(), hosts.to_string()]);
    }
    if proxy_auth_secret.is_some() {
        command.extend([
            "--upstream-proxy-auth-file".to_string(),
            openshell_core::container_paths::UPSTREAM_PROXY_AUTH_MOUNT_PATH.to_string(),
        ]);
    }
    if proxy_auth_allow_insecure {
        command.push("--upstream-proxy-auth-allow-insecure".to_string());
    }
    if proxy_connect_by_hostname {
        command.push("--upstream-proxy-connect-by-hostname".to_string());
    }
    if let Some((secret_name, secret_key)) = proxy_auth_secret {
        let auth_path = Path::new(openshell_core::container_paths::UPSTREAM_PROXY_AUTH_MOUNT_PATH);
        volume_mounts.push(serde_json::json!({
            "name": "upstream-proxy-auth",
            "mountPath": auth_path.parent().and_then(Path::to_str).expect("auth path has parent"),
            "readOnly": true
        }));
        volumes.push(serde_json::json!({
            "name": "upstream-proxy-auth",
            "secret": {"secretName": secret_name, "defaultMode": 0o440, "items": [{
                "key": secret_key,
                "path": auth_path.file_name().and_then(|name| name.to_str()).expect("auth path has file name")
            }]}
        }));
    }
    if let Some(socket_path) = provider_spiffe_socket_path {
        environment.push(env_var(
            openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET,
            socket_path,
        ));
        volume_mounts.push(serde_json::json!({
            "name": "spiffe-workload-api",
            "mountPath": Path::new(socket_path).parent().and_then(Path::to_str).expect("SPIFFE socket has parent"),
            "readOnly": true
        }));
        volumes.push(serde_json::json!({
            "name": "spiffe-workload-api",
            "csi": {"driver": "csi.spiffe.io", "readOnly": true}
        }));
    }
    let mut container = serde_json::json!({
        "name": "supervisor",
        "image": supervisor_image,
        "command": command,
        "terminationMessagePolicy": "FallbackToLogsOnError",
        "env": environment,
        "readinessProbe": {
            "exec": {"command": [
                "/openshell-supervisor",
                "health",
                "--socket",
                CONTROL_HEALTH_SOCKET_PATH
            ]},
            "periodSeconds": 1,
            "failureThreshold": 3
        },
        "securityContext": {
            "runAsUser": control_uid,
            "runAsGroup": control_gid,
            "runAsNonRoot": true,
            "readOnlyRootFilesystem": true,
            "allowPrivilegeEscalation": false,
            "capabilities": {"drop": ["ALL"]}
        },
        "volumeMounts": volume_mounts,
    });
    if !supervisor_pull_policy.is_empty() {
        container["imagePullPolicy"] = serde_json::json!(supervisor_pull_policy);
    }
    serde_json::from_value(serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": names.control_deployment, "namespace": namespace, "ownerReferences": [owner], "labels": labels},
        "spec": {
            "replicas": 0,
            "strategy": {"type": "Recreate"},
            "selector": {"matchLabels": pair_labels(sandbox_id, "supervisor")},
            "template": {
                "metadata": {"labels": control_labels(sandbox_id, gateway_id), "annotations": {"openshell.ai/sandbox-id": sandbox_id}},
                "spec": {
                    "serviceAccountName": service_account_name,
                    "imagePullSecrets": image_pull_secrets.iter().map(|name| serde_json::json!({"name": name})).collect::<Vec<_>>(),
                    "automountServiceAccountToken": false,
                    "securityContext": {
                        "fsGroup": control_gid,
                        "fsGroupChangePolicy": "OnRootMismatch",
                        "seccompProfile": {"type": "RuntimeDefault"}
                    },
                    "restartPolicy": "Always",
                    "containers": [container],
                    "volumes": volumes
                }
            }
        }
    }))
    .expect("control Deployment renderer must produce a valid object")
}

#[must_use]
pub fn control_egress_policy(
    namespace: &str,
    names: &ProxyPodNames,
    sandbox_id: &str,
    owner: OwnerReference,
) -> NetworkPolicy {
    NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(names.control_policy.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner]),
            labels: Some(common_labels(sandbox_id, "control-egress")),
            ..Default::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: LabelSelector {
                match_labels: Some(pair_labels(sandbox_id, "supervisor")),
                ..Default::default()
            },
            policy_types: Some(vec!["Egress".to_string()]),
            // Control is the policy-enforcing egress principal. Namespace-wide
            // default-deny policies must not prevent its gateway/DNS/upstream dials.
            egress: Some(vec![NetworkPolicyEgressRule::default()]),
            ..Default::default()
        }),
        status: None,
    }
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn sandbox_bootstrap_secret(
    namespace: &str,
    names: &ProxyPodNames,
    sandbox_id: &str,
    boundary_config: Vec<u8>,
    boundary_certificate: Vec<u8>,
    boundary_private_key: Vec<u8>,
    boundary_client_ca: Vec<u8>,
    owner: OwnerReference,
) -> Secret {
    Secret {
        metadata: ObjectMeta {
            name: Some(names.sandbox_secret.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner]),
            labels: Some(common_labels(sandbox_id, SANDBOX_SECRET_COMPONENT)),
            ..Default::default()
        },
        data: Some(BTreeMap::from([
            (BOUNDARY_CONFIG_KEY.to_string(), ByteString(boundary_config)),
            (
                BOUNDARY_CERTIFICATE_KEY.to_string(),
                ByteString(boundary_certificate),
            ),
            (
                BOUNDARY_PRIVATE_KEY.to_string(),
                ByteString(boundary_private_key),
            ),
            (
                BOUNDARY_CLIENT_CA_KEY.to_string(),
                ByteString(boundary_client_ca),
            ),
        ])),
        immutable: Some(true),
        type_: Some("Opaque".to_string()),
        ..Default::default()
    }
}

#[must_use]
pub fn supervisor_bootstrap_secret(
    namespace: &str,
    names: &ProxyPodNames,
    sandbox_id: &str,
    topology_payload: Vec<u8>,
    proxy_ca_certificate: Vec<u8>,
    proxy_ca_private_key: Vec<u8>,
    owner: OwnerReference,
) -> Secret {
    Secret {
        metadata: ObjectMeta {
            name: Some(names.supervisor_secret.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner]),
            labels: Some(common_labels(sandbox_id, SUPERVISOR_SECRET_COMPONENT)),
            ..Default::default()
        },
        data: Some(BTreeMap::from([
            (
                TOPOLOGY_PAYLOAD_KEY.to_string(),
                ByteString(topology_payload),
            ),
            (
                PROXY_CA_CERTIFICATE_KEY.to_string(),
                ByteString(proxy_ca_certificate),
            ),
            (
                PROXY_CA_PRIVATE_KEY.to_string(),
                ByteString(proxy_ca_private_key),
            ),
        ])),
        immutable: Some(true),
        type_: Some("Opaque".to_string()),
        ..Default::default()
    }
}

#[must_use]
pub fn sandbox_owner_reference(
    name: &str,
    uid: &str,
    api_version: &str,
    controller: bool,
) -> OwnerReference {
    OwnerReference {
        api_version: api_version.to_string(),
        kind: "Sandbox".to_string(),
        name: name.to_string(),
        uid: uid.to_string(),
        controller: controller.then_some(true),
        // The driver's RBAC intentionally does not permit mutating Sandbox
        // finalizers. Kubernetes garbage collection does not require this bit,
        // and setting it would make admission fail under
        // OwnerReferencesPermissionEnforcement.
        block_owner_deletion: Some(false),
    }
}

fn pair_labels(sandbox_id: &str, role: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            BOUNDARY_PAIR_LABEL.to_string(),
            pair_label_value(sandbox_id),
        ),
        (BOUNDARY_ROLE_LABEL.to_string(), role.to_string()),
    ])
}

fn common_labels(sandbox_id: &str, component: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "openshell.ai/managed-by".to_string(),
            "openshell".to_string(),
        ),
        (
            "openshell.ai/sandbox-id".to_string(),
            sandbox_id.to_string(),
        ),
        ("openshell.ai/component".to_string(), component.to_string()),
    ])
}

fn control_labels(sandbox_id: &str, gateway_id: &str) -> BTreeMap<String, String> {
    let mut labels = common_labels(sandbox_id, "supervisor");
    labels.extend(pair_labels(sandbox_id, "supervisor"));
    labels.insert(
        "openshell.ai/gateway-id".to_string(),
        gateway_id.to_string(),
    );
    labels
}

fn env_var(name: &str, value: &str) -> serde_json::Value {
    serde_json::json!({"name": name, "value": value})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> OwnerReference {
        sandbox_owner_reference("demo", "uid-1", "agents.x-k8s.io/v1beta1", true)
    }

    #[test]
    fn service_selects_only_the_workload_boundary() {
        let names = ProxyPodNames::new("4b67c0d0-1111-2222-3333-444444444444");
        let service = boundary_service("sandbox", &names, "pair", 5500, owner());
        assert_eq!(
            service.spec.unwrap().selector.unwrap()[BOUNDARY_ROLE_LABEL],
            "workload"
        );
    }

    #[test]
    fn owner_reference_does_not_require_finalizer_mutation_permission() {
        assert_eq!(owner().block_owner_deletion, Some(false));
    }

    #[test]
    fn control_policy_explicitly_allows_control_egress() {
        let names = ProxyPodNames::new("pair");
        let policy = control_egress_policy("sandbox", &names, "pair", owner());
        let spec = policy.spec.unwrap();
        assert_eq!(spec.policy_types.unwrap(), ["Egress"]);
        assert_eq!(spec.egress.unwrap().len(), 1);
    }

    #[test]
    fn control_deployment_is_singleton_ready_and_unprivileged() {
        let names = ProxyPodNames::new("pair");
        let deployment = control_deployment(
            "sandbox",
            &names,
            "pair",
            "demo",
            "gateway",
            "supervisor:latest",
            "IfNotPresent",
            "sandbox-sa",
            1000,
            1000,
            &["registry-credentials".to_string()],
            "https://gateway:8080",
            "client-tls",
            "{}",
            "info",
            600,
            None,
            None,
            None,
            false,
            false,
            None,
            owner(),
        );
        let spec = deployment.spec.as_ref().unwrap();
        assert_eq!(
            spec.strategy
                .as_ref()
                .and_then(|strategy| strategy.type_.as_deref()),
            Some("Recreate")
        );
        let container = &spec.template.spec.as_ref().unwrap().containers[0];
        let pod_spec = spec.template.spec.as_ref().unwrap();
        assert_eq!(pod_spec.automount_service_account_token, Some(false));
        assert_eq!(
            pod_spec.image_pull_secrets.as_ref().unwrap()[0]
                .name
                .as_deref(),
            Some("registry-credentials")
        );
        let pod_security =
            serde_json::to_value(pod_spec.security_context.as_ref().unwrap()).unwrap();
        assert_eq!(pod_security["fsGroup"], 1000);
        assert_eq!(pod_security["seccompProfile"]["type"], "RuntimeDefault");
        let container_security =
            serde_json::to_value(container.security_context.as_ref().unwrap()).unwrap();
        assert_eq!(container_security["runAsUser"], 1000);
        assert_eq!(container_security["runAsNonRoot"], true);
        assert_eq!(container_security["readOnlyRootFilesystem"], true);
        assert_eq!(
            container_security["capabilities"]["drop"],
            serde_json::json!(["ALL"])
        );
        assert_eq!(
            container
                .readiness_probe
                .as_ref()
                .and_then(|probe| probe.exec.as_ref())
                .and_then(|exec| exec.command.as_ref()),
            Some(&vec![
                "/openshell-supervisor".to_string(),
                "health".to_string(),
                "--socket".to_string(),
                CONTROL_HEALTH_SOCKET_PATH.to_string(),
            ])
        );
        let command = container.command.as_ref().unwrap();
        assert!(
            command
                .windows(2)
                .any(|args| args == ["--health-socket-path", CONTROL_HEALTH_SOCKET_PATH])
        );
        let env = container.env.as_ref().unwrap();
        let env_value = |name: &str| {
            env.iter()
                .find(|variable| variable.name == name)
                .and_then(|variable| variable.value.as_deref())
        };
        assert_eq!(
            env_value(openshell_core::sandbox_env::SSH_SOCKET_SHARED),
            Some("true")
        );
        assert_eq!(
            env_value(openshell_core::sandbox_env::PROXY_CA_CERT),
            Some(PROXY_CA_CERTIFICATE_PATH)
        );
        assert_eq!(
            env_value(openshell_core::sandbox_env::PROXY_CA_KEY),
            Some(PROXY_CA_PRIVATE_KEY_PATH)
        );
        let mount = container
            .volume_mounts
            .as_ref()
            .unwrap()
            .iter()
            .find(|mount| mount.name == "bootstrap")
            .expect("durable supervisor material is mounted into supervisor");
        assert_eq!(mount.mount_path, "/.openshell/supervisor");
        assert_eq!(mount.read_only, Some(true));
    }

    #[test]
    fn bootstrap_secrets_are_immutable_and_split_by_trust_domain() {
        let names = ProxyPodNames::new("pair");
        let sandbox = sandbox_bootstrap_secret(
            "sandbox",
            &names,
            "pair",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            owner(),
        );
        assert_eq!(
            sandbox.metadata.labels.as_ref().unwrap()["openshell.ai/component"],
            SANDBOX_SECRET_COMPONENT
        );
        assert_eq!(sandbox.immutable, Some(true));
        let sandbox_keys = sandbox
            .data
            .unwrap()
            .into_keys()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            sandbox_keys,
            std::collections::BTreeSet::from([
                BOUNDARY_CERTIFICATE_KEY.to_string(),
                BOUNDARY_CLIENT_CA_KEY.to_string(),
                BOUNDARY_CONFIG_KEY.to_string(),
                BOUNDARY_PRIVATE_KEY.to_string(),
            ])
        );

        let supervisor = supervisor_bootstrap_secret(
            "sandbox",
            &names,
            "pair",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            owner(),
        );
        assert_eq!(
            supervisor.metadata.labels.as_ref().unwrap()["openshell.ai/component"],
            SUPERVISOR_SECRET_COMPONENT
        );
        assert_eq!(supervisor.immutable, Some(true));
        let supervisor_keys = supervisor
            .data
            .unwrap()
            .into_keys()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            supervisor_keys,
            std::collections::BTreeSet::from([
                PROXY_CA_CERTIFICATE_KEY.to_string(),
                PROXY_CA_PRIVATE_KEY.to_string(),
                TOPOLOGY_PAYLOAD_KEY.to_string(),
            ])
        );
    }

    #[test]
    fn generated_proxy_ca_material_is_pem_encoded() {
        let material = generate_proxy_ca_material().unwrap();
        assert!(
            material
                .certificate_pem
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
        assert!(material.private_key_pem.contains("PRIVATE KEY"));
    }
}
