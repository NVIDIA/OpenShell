// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes provisioning for the shared authenticated boundary protocol.
//!
//! This module deliberately contains no lifecycle, process, network, identity,
//! or wire implementation. The driver places the sandbox runtime, binds
//! immutable Kubernetes resource identities, and provisions TCP coordinates;
//! `openshell-isolation-interface` and `openshell-sandbox` provide the common
//! control and boundary behavior.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use k8s_openapi::api::networking::v1::{
    NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyIngressRule, NetworkPolicyPeer,
    NetworkPolicyPort, NetworkPolicySpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::core::ObjectMeta;
use openshell_isolation_interface::contract::{
    BackendError, ProvisioningEvidence, ResolvedWorkloadIdentity,
};
use openshell_sandbox_backend::boundary_protocol::{
    BoundaryConfig, BoundaryListener, GatewayVerificationKey, SandboxRuntimeDescriptor,
    SandboxTlsClientConfig, SandboxTlsServerConfig, SandboxTransport,
};
use serde::Serialize;

use crate::config::KubernetesControlConnection;

#[derive(Serialize)]
struct KubernetesOuterFenceEvidence<'a> {
    network_policy_uid: &'a str,
    network_policy_resource_version: &'a str,
    ingress_isolated: bool,
    egress_isolated: bool,
    egress_rule_count: u32,
    /// Present only for runtime-initiated control. Omitted otherwise so the
    /// supervisor-initiated evidence encoding and digest are unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_control_policy: Option<KubernetesControlPolicyEvidence<'a>>,
}

/// The stored per-pair control policy bound into this generation. The driver
/// supplies it only after verifying the stored object equals
/// [`runtime_control_policy`] for this pair and port, so its only added path
/// is the runtime's connection to its own supervisor.
#[derive(Serialize)]
struct KubernetesControlPolicyEvidence<'a> {
    network_policy_uid: &'a str,
    network_policy_resource_version: &'a str,
    port: u16,
    /// Namespace of a supervisor shared by sandboxes. Omitted for a
    /// dedicated supervisor so its evidence encoding is unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    supervisor_namespace: Option<&'a str>,
}

impl KubernetesControlPolicyEvidence<'_> {
    fn is_bound(&self) -> bool {
        !self.network_policy_uid.is_empty()
            && !self.network_policy_resource_version.is_empty()
            && self.port != 0
    }
}

impl KubernetesOuterFenceEvidence<'_> {
    fn project(&self, generation: &str) -> Result<ProvisioningEvidence, BackendError> {
        if self.network_policy_uid.is_empty()
            || self.network_policy_resource_version.is_empty()
            || !self.ingress_isolated
            || !self.egress_isolated
            || self.egress_rule_count != 0
        {
            return Err(BackendError::Descriptor(
                "Kubernetes provisioning evidence is incomplete".to_string(),
            ));
        }
        if self
            .runtime_control_policy
            .as_ref()
            .is_some_and(|control| !control.is_bound())
        {
            return Err(BackendError::Descriptor(
                "Kubernetes control policy evidence is incomplete".into(),
            ));
        }
        let encoded = serde_json::to_vec(self).map_err(|error| {
            BackendError::Descriptor(format!("encode Kubernetes outer fence evidence: {error}"))
        })?;
        let projection = ProvisioningEvidence::from_enforcement_evidence(generation, &encoded)?;
        projection.validate(generation)?;
        Ok(projection)
    }
}

/// Isolation backend implemented by the `OpenShell` sandbox runtime.
pub const BACKEND_NAME: &str = openshell_sandbox_backend::BACKEND_NAME;

/// Label that binds the workload and supervisor pods in one unique pair.
pub const BOUNDARY_PAIR_LABEL: &str = "openshell.ai/boundary-pair";

/// Label distinguishing the two pods in a sandbox generation.
pub const BOUNDARY_ROLE_LABEL: &str = "openshell.ai/boundary-role";

const WORKLOAD_ROLE: &str = "workload";
const SUPERVISOR_ROLE: &str = "supervisor";

/// Driver-owned inputs for the workload pod's Kubernetes network fence.
///
/// This is the first phase of sandbox-runtime provisioning. The driver applies the
/// returned labels to the respective pods and creates the returned policy. It
/// then observes the policy UID and resourceVersion and supplies both to
/// `KubernetesSandboxRuntimeBoundarySpec`.
pub struct KubernetesSandboxRuntimeNetworkFenceSpec {
    pub namespace: String,
    pub policy_name: String,
    pub supervisor_policy_name: String,
    pub boundary_port: u16,
}

/// Labels and policy needed to remove direct workload-pod egress.
pub struct KubernetesSandboxRuntimeNetworkFence {
    pub workload_labels: BTreeMap<String, String>,
    pub control_labels: BTreeMap<String, String>,
    pub workload_policy: NetworkPolicy,
    pub supervisor_policy: NetworkPolicy,
}

impl KubernetesSandboxRuntimeNetworkFenceSpec {
    /// Render the namespace-wide workload fence.
    ///
    /// Kubernetes `NetworkPolicy` is connection-aware: traffic returning over
    /// the control-initiated boundary connection is allowed even though the
    /// workload pod has no egress rules. The control pod remains responsible
    /// for opening policy-approved upstream connections.
    #[must_use]
    pub fn provision(self) -> KubernetesSandboxRuntimeNetworkFence {
        let workload_labels = role_labels(WORKLOAD_ROLE);
        let control_labels = role_labels(SUPERVISOR_ROLE);

        let workload_policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some(self.policy_name),
                namespace: Some(self.namespace.clone()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: LabelSelector {
                    match_labels: Some(workload_labels.clone()),
                    ..Default::default()
                },
                policy_types: Some(vec!["Ingress".to_string(), "Egress".to_string()]),
                // Any trusted OpenShell supervisor in this namespace may
                // reach a sandbox listener. The Sandbox Protocol enforces the
                // exact sandbox, generation, and Pod UID binding.
                ingress: Some(vec![NetworkPolicyIngressRule {
                    from: Some(vec![NetworkPolicyPeer {
                        pod_selector: Some(LabelSelector {
                            match_labels: Some(control_labels.clone()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }]),
                    ports: Some(vec![NetworkPolicyPort {
                        port: Some(IntOrString::Int(i32::from(self.boundary_port))),
                        protocol: Some("TCP".to_string()),
                        ..Default::default()
                    }]),
                }]),
                // An explicit empty list selects the pod for egress and allows
                // no new workload-initiated connections, including DNS and the
                // Kubernetes API. Reply traffic for allowed ingress remains
                // permitted by conforming NetworkPolicy implementations.
                egress: Some(Vec::new()),
            }),
        };

        // Namespace-wide default-deny policies are additive with this rule.
        // Select only OpenShell supervisor pods and explicitly allow their
        // policy-approved DNS and upstream connections.
        let supervisor_policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some(self.supervisor_policy_name),
                namespace: Some(self.namespace),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: LabelSelector {
                    match_labels: Some(control_labels.clone()),
                    ..Default::default()
                },
                policy_types: Some(vec!["Egress".to_string()]),
                egress: Some(vec![NetworkPolicyEgressRule::default()]),
                ..Default::default()
            }),
        };

        KubernetesSandboxRuntimeNetworkFence {
            workload_labels,
            control_labels,
            workload_policy,
            supervisor_policy,
        }
    }
}

fn role_labels(role: &str) -> BTreeMap<String, String> {
    BTreeMap::from([(BOUNDARY_ROLE_LABEL.to_string(), role.to_string())])
}

/// Labels selecting one role of one workload/supervisor pair.
#[must_use]
pub fn pair_role_labels(pair: &str, role: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (BOUNDARY_PAIR_LABEL.to_string(), pair.to_string()),
        (BOUNDARY_ROLE_LABEL.to_string(), role.to_string()),
    ])
}

/// Pod role the per-sandbox boundary Service selects for a connection mode.
#[must_use]
pub const fn boundary_service_role(mode: KubernetesControlConnection) -> &'static str {
    match mode {
        KubernetesControlConnection::SupervisorInitiated => WORKLOAD_ROLE,
        KubernetesControlConnection::RuntimeInitiated => SUPERVISOR_ROLE,
    }
}

/// Per-sandbox allowance for runtime-initiated control.
///
/// Policies are additive: this admits exactly one flow, from this pair's
/// workload Pod to this pair's supervisor Pod on the control port, at both
/// enforcement points. Egress is required because the namespace fence denies
/// all workload egress; ingress is required because supervisors may be
/// ingress-isolated (for example by the managed SSH ingress policy). The
/// selector matches only this pair, so the extra rules can name only the pair
/// itself. It never adds DNS, gateway, API-server, or address-block access and
/// leaves the namespace-wide policies untouched.
#[must_use]
pub fn runtime_control_policy(namespace: &str, name: &str, pair: &str, port: u16) -> NetworkPolicy {
    let pair_role = |role| {
        Some(vec![NetworkPolicyPeer {
            pod_selector: Some(LabelSelector {
                match_labels: Some(pair_role_labels(pair, role)),
                ..Default::default()
            }),
            ..Default::default()
        }])
    };
    let control_port = || {
        Some(vec![NetworkPolicyPort {
            port: Some(IntOrString::Int(i32::from(port))),
            protocol: Some("TCP".to_string()),
            ..Default::default()
        }])
    };
    NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: LabelSelector {
                match_labels: Some(BTreeMap::from([(
                    BOUNDARY_PAIR_LABEL.to_string(),
                    pair.to_string(),
                )])),
                ..Default::default()
            },
            policy_types: Some(vec!["Ingress".to_string(), "Egress".to_string()]),
            ingress: Some(vec![NetworkPolicyIngressRule {
                from: pair_role(WORKLOAD_ROLE),
                ports: control_port(),
            }]),
            egress: Some(vec![NetworkPolicyEgressRule {
                to: pair_role(SUPERVISOR_ROLE),
                ports: control_port(),
            }]),
        }),
    }
}

/// Per-sandbox allowance for runtime-initiated control to a shared supervisor.
///
/// It selects only this pair's workload Pod and admits one egress flow, to the
/// shared supervisor Pods in their namespace on the runtime port. The
/// namespace fence keeps denying every other workload connection. Which
/// session a connection reaches is decided by its routing preface and pinned
/// TLS identity, not by this policy.
#[must_use]
pub fn shared_runtime_control_policy(
    namespace: &str,
    name: &str,
    pair: &str,
    supervisor_namespace: &str,
    supervisor_selector: BTreeMap<String, String>,
    port: u16,
) -> NetworkPolicy {
    NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: LabelSelector {
                match_labels: Some(pair_role_labels(pair, WORKLOAD_ROLE)),
                ..Default::default()
            },
            policy_types: Some(vec!["Egress".to_string()]),
            egress: Some(vec![NetworkPolicyEgressRule {
                to: Some(vec![NetworkPolicyPeer {
                    namespace_selector: Some(LabelSelector {
                        match_labels: Some(BTreeMap::from([(
                            "kubernetes.io/metadata.name".to_string(),
                            supervisor_namespace.to_string(),
                        )])),
                        ..Default::default()
                    }),
                    pod_selector: Some(LabelSelector {
                        match_labels: Some(supervisor_selector),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ports: Some(vec![NetworkPolicyPort {
                    port: Some(IntOrString::Int(i32::from(port))),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                }]),
            }]),
            ..Default::default()
        }),
    }
}

/// The supervisor bound into a generation's resource claims.
pub enum KubernetesSupervisorClaim {
    /// UID of the generation's dedicated supervisor Pod.
    Pod(String),
    /// Route of the generation's session on the shared supervisor.
    Session(String),
}

/// Which side opens the Sandbox Protocol connection, with the verified
/// Kubernetes coordinates that mode needs.
pub enum KubernetesControlPath {
    /// The supervisor dials the workload's listener through the Service.
    SupervisorInitiated {
        boundary_listener: SocketAddr,
        control_authority: String,
        control_address: SocketAddr,
    },
    /// The workload runtime dials the supervisor through the Service.
    RuntimeInitiated {
        control_authority: String,
        /// Service address the runtime dials.
        supervisor_address: SocketAddr,
        /// Supervisor bind address.
        supervisor_listen: SocketAddr,
        /// Verified per-sandbox control policy coordinates.
        control_policy_uid: String,
        control_policy_resource_version: String,
    },
    /// The workload runtime dials the gateway's shared supervisor and names
    /// this generation's route before TLS.
    RuntimeInitiatedShared {
        control_authority: String,
        /// Shared Service address the runtime dials.
        supervisor_address: SocketAddr,
        supervisor_namespace: String,
        route: String,
        /// Verified per-sandbox shared control policy coordinates.
        control_policy_uid: String,
        control_policy_resource_version: String,
    },
}

/// Driver-owned inputs that bind one workload/supervisor pair to one boundary.
///
/// The driver constructs this only after Kubernetes has assigned every UID and
/// after it has observed the namespace workload-policy resource version. The
/// workload stays held until the matching boundary config and supervisor
/// resources have been installed.
pub struct KubernetesSandboxRuntimeBoundarySpec {
    pub boundary_id: String,
    pub generation: String,
    pub session_id: openshell_core::SandboxSessionId,
    pub session_rotation: openshell_core::jwt::SessionRotation,
    pub auth_epoch: openshell_core::jwt::CredentialEpoch,
    pub gateway_id: String,
    pub verification_keys: Vec<GatewayVerificationKey>,
    pub namespace_uid: String,
    pub sandbox_resource_uid: String,
    pub workload_pod_uid: String,
    pub workload_pod_uid_path: PathBuf,
    pub supervisor: KubernetesSupervisorClaim,
    pub egress_policy_uid: String,
    pub egress_policy_resource_version: String,
    pub control_path: KubernetesControlPath,
    pub sandbox_tls: SandboxTlsServerConfig,
    pub supervisor_tls: SandboxTlsClientConfig,
    pub host_gateway_ip: Option<IpAddr>,
    pub workload_identity: ResolvedWorkloadIdentity,
    pub child_env: HashMap<String, String>,
}

/// Protected workload-pod config and matching sandbox-runtime descriptor.
pub struct KubernetesSandboxRuntimeBoundaryProvisioning {
    pub boundary_config: BoundaryConfig,
    pub runtime_descriptor: SandboxRuntimeDescriptor,
}

impl KubernetesSandboxRuntimeBoundarySpec {
    /// Produce both sides of the common protocol from one observed Kubernetes
    /// resource set so a stale or recreated object cannot be attached.
    pub fn provision(self) -> Result<KubernetesSandboxRuntimeBoundaryProvisioning, BackendError> {
        let mut resource_claims = BTreeMap::from([
            ("kubernetes.namespace_uid".to_string(), self.namespace_uid),
            (
                "kubernetes.sandbox_resource_uid".to_string(),
                self.sandbox_resource_uid,
            ),
            (
                "kubernetes.workload_pod_uid".to_string(),
                self.workload_pod_uid,
            ),
            match self.supervisor {
                KubernetesSupervisorClaim::Pod(uid) => {
                    ("kubernetes.supervisor_pod_uid".to_string(), uid)
                }
                KubernetesSupervisorClaim::Session(route) => {
                    ("kubernetes.supervisor_session".to_string(), route)
                }
            },
            (
                "kubernetes.egress_policy_uid".to_string(),
                self.egress_policy_uid,
            ),
            (
                "kubernetes.egress_policy_resource_version".to_string(),
                self.egress_policy_resource_version,
            ),
        ]);
        let mut supervisor_namespace = None;
        let mut shared_port = None;
        let (listener, transport) = match self.control_path {
            KubernetesControlPath::SupervisorInitiated {
                boundary_listener,
                control_authority,
                control_address,
            } => (
                BoundaryListener::TlsTcp {
                    address: boundary_listener,
                    tls: self.sandbox_tls,
                },
                SandboxTransport::Tcp {
                    authority: control_authority,
                    addresses: vec![control_address],
                },
            ),
            KubernetesControlPath::RuntimeInitiated {
                control_authority,
                supervisor_address,
                supervisor_listen,
                control_policy_uid,
                control_policy_resource_version,
            } => {
                resource_claims.insert(
                    "kubernetes.control_policy_uid".to_string(),
                    control_policy_uid,
                );
                resource_claims.insert(
                    "kubernetes.control_policy_resource_version".to_string(),
                    control_policy_resource_version,
                );
                (
                    BoundaryListener::RuntimeInitiatedTlsTcp {
                        authority: control_authority.clone(),
                        addresses: vec![supervisor_address],
                        tls: self.sandbox_tls,
                        route: None,
                    },
                    SandboxTransport::RuntimeInitiatedTcp {
                        authority: control_authority,
                        listen_address: supervisor_listen,
                    },
                )
            }
            KubernetesControlPath::RuntimeInitiatedShared {
                control_authority,
                supervisor_address,
                supervisor_namespace: shared_namespace,
                route,
                control_policy_uid,
                control_policy_resource_version,
            } => {
                resource_claims.insert(
                    "kubernetes.control_policy_uid".to_string(),
                    control_policy_uid,
                );
                resource_claims.insert(
                    "kubernetes.control_policy_resource_version".to_string(),
                    control_policy_resource_version,
                );
                supervisor_namespace = Some(shared_namespace);
                shared_port = Some(supervisor_address.port());
                (
                    BoundaryListener::RuntimeInitiatedTlsTcp {
                        authority: control_authority.clone(),
                        addresses: vec![supervisor_address],
                        tls: self.sandbox_tls,
                        route: Some(route.clone()),
                    },
                    SandboxTransport::RuntimeInitiatedRouted {
                        authority: control_authority,
                        route,
                    },
                )
            }
        };
        let control_port = match &transport {
            SandboxTransport::RuntimeInitiatedTcp { listen_address, .. } => {
                Some(listen_address.port())
            }
            SandboxTransport::RuntimeInitiatedRouted { .. } => shared_port,
            _ => None,
        };
        let provisioning_evidence = KubernetesOuterFenceEvidence {
            network_policy_uid: &resource_claims["kubernetes.egress_policy_uid"],
            network_policy_resource_version: &resource_claims
                ["kubernetes.egress_policy_resource_version"],
            ingress_isolated: true,
            egress_isolated: true,
            egress_rule_count: 0,
            runtime_control_policy: control_port.map(|port| KubernetesControlPolicyEvidence {
                network_policy_uid: &resource_claims["kubernetes.control_policy_uid"],
                network_policy_resource_version: &resource_claims
                    ["kubernetes.control_policy_resource_version"],
                port,
                supervisor_namespace: supervisor_namespace.as_deref(),
            }),
        }
        .project(&self.generation)?;
        Ok(KubernetesSandboxRuntimeBoundaryProvisioning {
            boundary_config: BoundaryConfig {
                boundary_id: self.boundary_id.clone(),
                generation: self.generation.clone(),
                session_id: self.session_id,
                session_rotation: self.session_rotation,
                auth_epoch: self.auth_epoch,
                gateway_id: self.gateway_id,
                verification_keys: self.verification_keys,
                listener,
                resource_claims: resource_claims.clone(),
                resource_claim_files: BTreeMap::from([(
                    "kubernetes.workload_pod_uid".to_string(),
                    self.workload_pod_uid_path,
                )]),
                workload_identity: self.workload_identity.clone(),
                provisioning_evidence: provisioning_evidence.clone(),
                child_env: self.child_env,
            },
            runtime_descriptor: SandboxRuntimeDescriptor {
                boundary_id: self.boundary_id,
                generation: self.generation,
                session_id: self.session_id,
                workload_identity: self.workload_identity,
                transport,
                tls: self.supervisor_tls,
                host_gateway_ip: self.host_gateway_ip,
                resource_claims,
                provisioning_evidence,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outer_fence_projection_rejects_each_missing_native_fact() {
        for evidence in [
            KubernetesOuterFenceEvidence {
                network_policy_uid: "",
                network_policy_resource_version: "1",
                ingress_isolated: true,
                egress_isolated: true,
                egress_rule_count: 0,
                runtime_control_policy: None,
            },
            KubernetesOuterFenceEvidence {
                network_policy_uid: "uid",
                network_policy_resource_version: "",
                ingress_isolated: true,
                egress_isolated: true,
                egress_rule_count: 0,
                runtime_control_policy: None,
            },
            KubernetesOuterFenceEvidence {
                network_policy_uid: "uid",
                network_policy_resource_version: "1",
                ingress_isolated: false,
                egress_isolated: true,
                egress_rule_count: 0,
                runtime_control_policy: None,
            },
            KubernetesOuterFenceEvidence {
                network_policy_uid: "uid",
                network_policy_resource_version: "1",
                ingress_isolated: true,
                egress_isolated: false,
                egress_rule_count: 0,
                runtime_control_policy: None,
            },
            KubernetesOuterFenceEvidence {
                network_policy_uid: "uid",
                network_policy_resource_version: "1",
                ingress_isolated: true,
                egress_isolated: true,
                egress_rule_count: 1,
                runtime_control_policy: None,
            },
        ] {
            assert!(evidence.project("generation-1").is_err());
        }
    }

    fn spec() -> KubernetesSandboxRuntimeBoundarySpec {
        KubernetesSandboxRuntimeBoundarySpec {
            boundary_id: "sandbox-1".to_string(),
            generation: "generation-1".to_string(),
            session_id: openshell_core::SandboxSessionId::new(),
            session_rotation: openshell_core::jwt::SessionRotation::new(1).unwrap(),
            auth_epoch: openshell_core::jwt::CredentialEpoch::new(1).unwrap(),
            gateway_id: "gateway-1".to_string(),
            verification_keys: vec![GatewayVerificationKey {
                key_id: "key-1".to_string(),
                public_key_pem: "public-key".to_string(),
            }],
            namespace_uid: "namespace-uid".to_string(),
            sandbox_resource_uid: "sandbox-resource-uid".to_string(),
            workload_pod_uid: "pod-uid".to_string(),
            workload_pod_uid_path: PathBuf::from("/.openshell/pod-identity/uid"),
            supervisor: KubernetesSupervisorClaim::Pod("supervisor-pod-uid".to_string()),
            egress_policy_uid: "network-policy-uid".to_string(),
            egress_policy_resource_version: "1945".to_string(),
            control_path: KubernetesControlPath::SupervisorInitiated {
                boundary_listener: "0.0.0.0:5500".parse().expect("valid listener"),
                control_authority: "os-boundary-sandbox.default.svc:5500".to_string(),
                control_address: "10.42.0.7:5500".parse().expect("valid target"),
            },
            sandbox_tls: SandboxTlsServerConfig {
                certificate_chain_path: PathBuf::from("/run/boundary/tls.crt"),
                private_key_path: PathBuf::from("/run/boundary/tls.key"),
            },
            supervisor_tls: SandboxTlsClientConfig {
                server_name: "boundary.sandbox.openshell".to_string(),
                trust_anchor_pem: "test-ca".to_string(),
            },
            host_gateway_ip: Some("10.42.0.1".parse().expect("valid gateway IP")),
            workload_identity: ResolvedWorkloadIdentity::new(
                1000,
                1000,
                vec![1000],
                "kubernetes-config".to_string(),
                "sandbox:sandbox-resource-uid".to_string(),
            )
            .unwrap(),
            child_env: HashMap::new(),
        }
    }

    #[test]
    fn provisioning_binds_identical_kubernetes_resource_claims() {
        let provisioned = spec().provision().unwrap();

        assert_eq!(
            provisioned.boundary_config.resource_claims,
            provisioned.runtime_descriptor.resource_claims
        );
        assert_eq!(
            provisioned.runtime_descriptor.resource_claims["kubernetes.sandbox_resource_uid"],
            "sandbox-resource-uid"
        );
        assert_eq!(
            provisioned.runtime_descriptor.resource_claims["kubernetes.egress_policy_resource_version"],
            "1945"
        );
        assert_eq!(
            provisioned.boundary_config.provisioning_evidence,
            provisioned.runtime_descriptor.provisioning_evidence
        );
        assert!(
            provisioned
                .runtime_descriptor
                .provisioning_evidence
                .validate("generation-1")
                .is_ok()
        );
    }

    #[test]
    fn provisioning_uses_one_shared_tcp_protocol_across_pods() {
        let provisioned = spec().provision().unwrap();

        assert_eq!(
            provisioned.boundary_config.listener,
            BoundaryListener::TlsTcp {
                address: "0.0.0.0:5500".parse().expect("valid listener"),
                tls: SandboxTlsServerConfig {
                    certificate_chain_path: PathBuf::from("/run/boundary/tls.crt"),
                    private_key_path: PathBuf::from("/run/boundary/tls.key"),
                },
            }
        );
        assert_eq!(
            provisioned.runtime_descriptor.transport,
            SandboxTransport::Tcp {
                authority: "os-boundary-sandbox.default.svc:5500".to_string(),
                addresses: vec!["10.42.0.7:5500".parse().expect("valid target")],
            }
        );
        assert_eq!(
            provisioned.runtime_descriptor.tls,
            SandboxTlsClientConfig {
                server_name: "boundary.sandbox.openshell".to_string(),
                trust_anchor_pem: "test-ca".to_string(),
            }
        );
    }

    #[test]
    fn network_fence_denies_all_workload_initiated_egress() {
        let fence = KubernetesSandboxRuntimeNetworkFenceSpec {
            namespace: "sandbox-ns".to_string(),
            policy_name: "openshell-boundary-sandbox-1".to_string(),
            supervisor_policy_name: "openshell-sandbox-supervisors".to_string(),
            boundary_port: 5500,
        }
        .provision();

        let policy_spec = fence.workload_policy.spec.expect("policy has a spec");
        assert_eq!(
            policy_spec.policy_types,
            Some(vec!["Ingress".to_string(), "Egress".to_string()])
        );
        assert_eq!(policy_spec.egress, Some(Vec::new()));
        assert_eq!(
            policy_spec.pod_selector.match_labels,
            Some(fence.workload_labels)
        );
    }

    #[test]
    fn network_fence_allows_namespace_supervisors_to_boundary_port() {
        let fence = KubernetesSandboxRuntimeNetworkFenceSpec {
            namespace: "sandbox-ns".to_string(),
            policy_name: "openshell-boundary-sandbox-1".to_string(),
            supervisor_policy_name: "openshell-sandbox-supervisors".to_string(),
            boundary_port: 5500,
        }
        .provision();

        let policy_spec = fence.workload_policy.spec.expect("policy has a spec");
        let ingress = policy_spec
            .ingress
            .expect("policy has ingress rules")
            .pop()
            .expect("policy has one ingress rule");
        let peer = ingress
            .from
            .expect("rule has peers")
            .pop()
            .expect("rule has one peer");
        assert_eq!(
            peer.pod_selector
                .expect("peer has a pod selector")
                .match_labels,
            Some(fence.control_labels)
        );
        assert!(peer.namespace_selector.is_none());

        let port = ingress
            .ports
            .expect("rule has ports")
            .pop()
            .expect("rule has one port");
        assert_eq!(port.protocol.as_deref(), Some("TCP"));
        assert_eq!(port.port, Some(IntOrString::Int(5500)));
    }

    #[test]
    fn network_fence_keeps_supervisor_egress_available() {
        let fence = KubernetesSandboxRuntimeNetworkFenceSpec {
            namespace: "sandbox-ns".to_string(),
            policy_name: "openshell-sandbox-workloads".to_string(),
            supervisor_policy_name: "openshell-sandbox-supervisors".to_string(),
            boundary_port: 5500,
        }
        .provision();

        let policy_spec = fence
            .supervisor_policy
            .spec
            .expect("supervisor policy has a spec");
        assert_eq!(policy_spec.policy_types, Some(vec!["Egress".to_string()]));
        assert_eq!(
            policy_spec.pod_selector.match_labels,
            Some(fence.control_labels)
        );
        assert_eq!(
            policy_spec.egress,
            Some(vec![NetworkPolicyEgressRule::default()])
        );
    }
}
