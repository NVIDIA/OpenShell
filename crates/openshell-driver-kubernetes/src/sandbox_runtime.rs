// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes resources that place and protect the `OpenShell` sandbox runtime.

use std::collections::BTreeMap;
use std::path::Path;

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::{
    CSIVolumeSource, Capabilities, Container, EmptyDirVolumeSource, EnvVar, ExecAction, KeyToPath,
    LocalObjectReference, Pod, PodSchedulingGate, PodSecurityContext, PodSpec, Probe,
    ProjectedVolumeSource, Secret, SecretVolumeSource, SecurityContext, Service,
    ServiceAccountTokenProjection, ServicePort, ServiceSpec, Volume, VolumeMount, VolumeProjection,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::core::ObjectMeta;
use rcgen::{CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

use crate::isolation::{
    BOUNDARY_PAIR_LABEL, BOUNDARY_ROLE_LABEL, KubernetesSandboxRuntimeNetworkFence,
    KubernetesSandboxRuntimeNetworkFenceSpec,
};

pub const SANDBOX_SECRET_COMPONENT: &str = "sandbox-bootstrap";
pub const SUPERVISOR_SECRET_COMPONENT: &str = "supervisor-bootstrap";
pub const BOUNDARY_CONFIG_KEY: &str = "boundary.json";
pub const BACKEND_DESCRIPTOR_KEY: &str = "runtime-descriptor.json";
pub const BOUNDARY_CERTIFICATE_KEY: &str = "tls.crt";
pub const BOUNDARY_PRIVATE_KEY: &str = "tls.key";
pub const SUPERVISOR_AUTH_BUNDLE_KEY: &str = "auth.json";
pub const PROXY_CA_CERTIFICATE_KEY: &str = "proxy-ca.crt";
pub const PROXY_CA_PRIVATE_KEY: &str = "proxy-ca.key";
pub const SANDBOX_BOOTSTRAP_INPUT_PATH: &str = "/.openshell/bootstrap-input";
pub const BOUNDARY_CONFIG_PATH: &str = "/.openshell/state/bootstrap/boundary.json";
pub const BOUNDARY_CERTIFICATE_PATH: &str = "/.openshell/state/bootstrap/tls.crt";
pub const BOUNDARY_PRIVATE_KEY_PATH: &str = "/.openshell/state/bootstrap/tls.key";
pub const BACKEND_DESCRIPTOR_PATH: &str = "/.openshell/supervisor/runtime-descriptor.json";
pub const SUPERVISOR_AUTH_BUNDLE_PATH: &str = "/.openshell/supervisor/auth.json";
pub const PROXY_CA_CERTIFICATE_PATH: &str = "/.openshell/supervisor/proxy-ca.crt";
pub const PROXY_CA_PRIVATE_KEY_PATH: &str = "/.openshell/supervisor/proxy-ca.key";
pub const CONTROL_HEALTH_SOCKET_PATH: &str = "/run/openshell/health.sock";
pub const NAMESPACE_WORKLOAD_POLICY_NAME: &str = "openshell-sandbox-workloads";
pub const NAMESPACE_SUPERVISOR_EGRESS_POLICY_NAME: &str = "openshell-sandbox-supervisors";

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
pub struct SandboxRuntimeNames {
    pub sandbox_secret: String,
    pub supervisor_secret: String,
    pub boundary_service: String,
    pub supervisor_pod: String,
    pub workload_policy: String,
    pub supervisor_policy: String,
}

impl SandboxRuntimeNames {
    #[must_use]
    pub fn new(sandbox_id: &str) -> Self {
        let suffix = sandbox_id.to_ascii_lowercase();
        Self {
            sandbox_secret: format!("os-sandbox-{suffix}"),
            supervisor_secret: format!("os-supervisor-{suffix}"),
            boundary_service: format!("os-boundary-{suffix}"),
            supervisor_pod: format!("os-supervisor-{suffix}"),
            workload_policy: NAMESPACE_WORKLOAD_POLICY_NAME.to_string(),
            supervisor_policy: NAMESPACE_SUPERVISOR_EGRESS_POLICY_NAME.to_string(),
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
    names: &SandboxRuntimeNames,
    boundary_port: u16,
) -> KubernetesSandboxRuntimeNetworkFence {
    KubernetesSandboxRuntimeNetworkFenceSpec {
        namespace: namespace.to_string(),
        policy_name: names.workload_policy.clone(),
        supervisor_policy_name: names.supervisor_policy.clone(),
        boundary_port,
    }
    .provision()
}

#[must_use]
pub fn boundary_service(
    namespace: &str,
    names: &SandboxRuntimeNames,
    sandbox_id: &str,
    boundary_port: u16,
    owner: OwnerReference,
) -> Service {
    Service {
        metadata: ObjectMeta {
            name: Some(names.boundary_service.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner]),
            labels: Some(common_labels(sandbox_id, "boundary-service")),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(pair_labels(sandbox_id, "workload")),
            ports: Some(vec![ServicePort {
                name: Some("boundary".to_string()),
                protocol: Some("TCP".to_string()),
                port: i32::from(boundary_port),
                target_port: Some(IntOrString::Int(i32::from(boundary_port))),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments, clippy::similar_names)]
pub fn supervisor_pod(
    namespace: &str,
    names: &SandboxRuntimeNames,
    sandbox_id: &str,
    sandbox_name: &str,
    gateway_id: &str,
    supervisor_image: &str,
    supervisor_pull_policy: Option<crate::KubernetesImagePullPolicy>,
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
) -> Result<Pod, String> {
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
        volume_mount("bootstrap", "/.openshell/supervisor", true),
        volume_mount("sa-token", "/var/run/secrets/openshell", true),
        volume_mount("run", "/run/openshell", false),
        volume_mount("logs", "/var/log", false),
    ];
    let mut volumes = vec![
        secret_volume("bootstrap", &names.supervisor_secret, None),
        Volume {
            name: "sa-token".to_string(),
            projected: Some(ProjectedVolumeSource {
                default_mode: Some(0o440),
                sources: Some(vec![VolumeProjection {
                    service_account_token: Some(ServiceAccountTokenProjection {
                        audience: Some("openshell-gateway".to_string()),
                        expiration_seconds: Some(sa_token_ttl_secs),
                        path: "token".to_string(),
                    }),
                    ..Default::default()
                }]),
            }),
            ..Default::default()
        },
        empty_dir_volume("run"),
        empty_dir_volume("logs"),
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
        volume_mounts.push(volume_mount(
            "client-tls",
            "/var/run/secrets/openshell-tls",
            true,
        ));
        volumes.push(secret_volume("client-tls", client_tls_secret_name, None));
    }
    let mut command = vec![
        "/openshell-supervisor".to_string(),
        "--backend-descriptor-file".to_string(),
        BACKEND_DESCRIPTOR_PATH.to_string(),
        "--auth-bundle-file".to_string(),
        SUPERVISOR_AUTH_BUNDLE_PATH.to_string(),
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
        let mount_path = auth_path
            .parent()
            .and_then(Path::to_str)
            .ok_or_else(|| "upstream proxy authentication path has no UTF-8 parent".to_string())?;
        let item_path = auth_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                "upstream proxy authentication path has no UTF-8 file name".to_string()
            })?;
        volume_mounts.push(volume_mount("upstream-proxy-auth", mount_path, true));
        volumes.push(secret_volume(
            "upstream-proxy-auth",
            secret_name,
            Some(KeyToPath {
                key: secret_key.to_string(),
                path: item_path.to_string(),
                ..Default::default()
            }),
        ));
    }
    if let Some(socket_path) = provider_spiffe_socket_path {
        environment.push(env_var(
            openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET,
            socket_path,
        ));
        let mount_path = Path::new(socket_path)
            .parent()
            .and_then(Path::to_str)
            .ok_or_else(|| "SPIFFE socket path has no UTF-8 parent".to_string())?;
        volume_mounts.push(volume_mount("spiffe-workload-api", mount_path, true));
        volumes.push(Volume {
            name: "spiffe-workload-api".to_string(),
            csi: Some(CSIVolumeSource {
                driver: "csi.spiffe.io".to_string(),
                read_only: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        });
    }
    let mut container = Container {
        name: "supervisor".to_string(),
        image: Some(supervisor_image.to_string()),
        command: Some(command),
        termination_message_policy: Some("FallbackToLogsOnError".to_string()),
        env: Some(environment),
        readiness_probe: Some(Probe {
            exec: Some(ExecAction {
                command: Some(vec![
                    "/openshell-supervisor".to_string(),
                    "health".to_string(),
                    "--socket".to_string(),
                    CONTROL_HEALTH_SOCKET_PATH.to_string(),
                ]),
            }),
            period_seconds: Some(1),
            failure_threshold: Some(3),
            ..Default::default()
        }),
        security_context: Some(SecurityContext {
            run_as_user: Some(i64::from(control_uid)),
            run_as_group: Some(i64::from(control_gid)),
            run_as_non_root: Some(true),
            read_only_root_filesystem: Some(true),
            allow_privilege_escalation: Some(false),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".to_string()]),
                ..Default::default()
            }),
            ..Default::default()
        }),
        volume_mounts: Some(volume_mounts),
        ..Default::default()
    };
    if let Some(policy) = supervisor_pull_policy {
        container.image_pull_policy = Some(policy.as_kubernetes_str().to_string());
    }
    Ok(Pod {
        metadata: ObjectMeta {
            name: Some(names.supervisor_pod.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner]),
            labels: Some(labels),
            annotations: Some(BTreeMap::from([(
                "openshell.ai/sandbox-id".to_string(),
                sandbox_id.to_string(),
            )])),
            ..Default::default()
        },
        spec: Some(PodSpec {
            service_account_name: Some(service_account_name.to_string()),
            image_pull_secrets: Some(
                image_pull_secrets
                    .iter()
                    .map(|name| LocalObjectReference { name: name.clone() })
                    .collect(),
            ),
            automount_service_account_token: Some(false),
            scheduling_gates: Some(vec![PodSchedulingGate {
                name: "openshell.ai/bootstrap".to_string(),
            }]),
            security_context: Some(PodSecurityContext {
                fs_group: Some(i64::from(control_gid)),
                fs_group_change_policy: Some("OnRootMismatch".to_string()),
                seccomp_profile: Some(k8s_openapi::api::core::v1::SeccompProfile {
                    type_: "RuntimeDefault".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            restart_policy: Some("Never".to_string()),
            containers: vec![container],
            volumes: Some(volumes),
            ..Default::default()
        }),
        ..Default::default()
    })
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn sandbox_bootstrap_secret(
    namespace: &str,
    names: &SandboxRuntimeNames,
    sandbox_id: &str,
    boundary_config: Vec<u8>,
    boundary_certificate: Vec<u8>,
    boundary_private_key: Vec<u8>,
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
        ])),
        immutable: Some(true),
        type_: Some("Opaque".to_string()),
        ..Default::default()
    }
}

#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn supervisor_bootstrap_secret(
    namespace: &str,
    names: &SandboxRuntimeNames,
    sandbox_id: &str,
    backend_descriptor: Vec<u8>,
    supervisor_auth_bundle: Vec<u8>,
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
                BACKEND_DESCRIPTOR_KEY.to_string(),
                ByteString(backend_descriptor),
            ),
            (
                SUPERVISOR_AUTH_BUNDLE_KEY.to_string(),
                ByteString(supervisor_auth_bundle),
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

fn env_var(name: &str, value: &str) -> EnvVar {
    EnvVar {
        name: name.to_string(),
        value: Some(value.to_string()),
        ..Default::default()
    }
}

fn volume_mount(name: &str, mount_path: &str, read_only: bool) -> VolumeMount {
    VolumeMount {
        name: name.to_string(),
        mount_path: mount_path.to_string(),
        read_only: read_only.then_some(true),
        ..Default::default()
    }
}

fn secret_volume(name: &str, secret_name: &str, item: Option<KeyToPath>) -> Volume {
    Volume {
        name: name.to_string(),
        secret: Some(SecretVolumeSource {
            secret_name: Some(secret_name.to_string()),
            default_mode: Some(0o440),
            items: item.map(|item| vec![item]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn empty_dir_volume(name: &str) -> Volume {
    Volume {
        name: name.to_string(),
        empty_dir: Some(EmptyDirVolumeSource::default()),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> OwnerReference {
        sandbox_owner_reference("demo", "uid-1", "agents.x-k8s.io/v1beta1", false)
    }

    #[test]
    fn service_selects_only_the_workload_boundary() {
        let names = SandboxRuntimeNames::new("4b67c0d0-1111-2222-3333-444444444444");
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
    fn supervisor_pod_is_gated_non_restarting_and_unprivileged() {
        let names = SandboxRuntimeNames::new("pair");
        let pod = supervisor_pod(
            "sandbox",
            &names,
            "pair",
            "demo",
            "gateway",
            "supervisor:latest",
            Some(crate::KubernetesImagePullPolicy::IfNotPresent),
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
        )
        .expect("render supervisor Pod");
        let pod_spec = pod.spec.as_ref().expect("Pod spec");
        assert_eq!(
            pod.metadata
                .owner_references
                .as_ref()
                .expect("owner references")[0]
                .controller,
            None
        );
        let container = &pod_spec.containers[0];
        assert_eq!(container.image_pull_policy.as_deref(), Some("IfNotPresent"));
        assert_eq!(pod_spec.automount_service_account_token, Some(false));
        assert_eq!(pod_spec.restart_policy.as_deref(), Some("Never"));
        assert_eq!(
            pod_spec
                .scheduling_gates
                .as_ref()
                .and_then(|gates| gates.first())
                .map(|gate| gate.name.as_str()),
            Some("openshell.ai/bootstrap")
        );
        assert_eq!(
            pod_spec
                .image_pull_secrets
                .as_ref()
                .expect("image pull secrets")[0]
                .name
                .as_str(),
            "registry-credentials"
        );
        let pod_security = pod_spec
            .security_context
            .as_ref()
            .expect("Pod security context");
        assert_eq!(pod_security.fs_group, Some(1000));
        assert_eq!(
            pod_security
                .seccomp_profile
                .as_ref()
                .map(|profile| profile.type_.as_str()),
            Some("RuntimeDefault")
        );
        let container_security = container
            .security_context
            .as_ref()
            .expect("container security context");
        assert_eq!(container_security.run_as_user, Some(1000));
        assert_eq!(container_security.run_as_non_root, Some(true));
        assert_eq!(container_security.read_only_root_filesystem, Some(true));
        assert_eq!(
            container_security
                .capabilities
                .as_ref()
                .and_then(|capabilities| capabilities.drop.as_ref()),
            Some(&vec!["ALL".to_string()])
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
        let names = SandboxRuntimeNames::new("pair");
        let sandbox = sandbox_bootstrap_secret(
            "sandbox",
            &names,
            "pair",
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
                SUPERVISOR_AUTH_BUNDLE_KEY.to_string(),
                BACKEND_DESCRIPTOR_KEY.to_string(),
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
