// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes provisioning for the shared authenticated boundary protocol.
//!
//! This module deliberately contains no lifecycle, process, network, identity,
//! or wire implementation. The driver chooses the proxy-pod placement, binds
//! immutable Kubernetes resource identities, and provisions TCP coordinates;
//! `openshell-isolation-interface` and `openshell-sandbox` provide the common
//! control and boundary behavior.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use k8s_openapi::api::networking::v1::{
    NetworkPolicy, NetworkPolicyIngressRule, NetworkPolicyPeer, NetworkPolicyPort,
    NetworkPolicySpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::core::ObjectMeta;
use openshell_isolation_interface::boundary_protocol::{
    BoundaryClientTls, BoundaryConfig, BoundaryListener, BoundaryServerTls, BoundaryTopology,
    BoundaryTransport,
};
use openshell_isolation_interface::contract::{DriverFenceEvidence, ResolvedWorkloadIdentity};

/// Registered RFC 0012 backend name for the proxy-pod topology.
pub const BACKEND_NAME: &str = "kubernetes-proxy-pod";

/// Label that binds the workload and control pods in one unique pair.
pub const BOUNDARY_PAIR_LABEL: &str = "openshell.ai/boundary-pair";

/// Label distinguishing the two pods in a boundary pair.
pub const BOUNDARY_ROLE_LABEL: &str = "openshell.ai/boundary-role";

const WORKLOAD_ROLE: &str = "workload";
const SUPERVISOR_ROLE: &str = "supervisor";

/// Driver-owned inputs for the workload pod's Kubernetes network fence.
///
/// This is the first phase of proxy-pod provisioning. The driver applies the
/// returned labels to the respective pods and creates the returned policy. It
/// then observes the policy UID and resourceVersion and supplies both to
/// `KubernetesProxyPodBoundarySpec`.
pub struct KubernetesProxyPodNetworkFenceSpec {
    pub namespace: String,
    pub policy_name: String,
    /// A unique, Kubernetes-label-safe value generated for this pod pair.
    pub pair_label_value: String,
    pub boundary_port: u16,
}

/// Labels and policy needed to remove direct workload-pod egress.
pub struct KubernetesProxyPodNetworkFence {
    pub workload_labels: BTreeMap<String, String>,
    pub control_labels: BTreeMap<String, String>,
    pub workload_policy: NetworkPolicy,
}

impl KubernetesProxyPodNetworkFenceSpec {
    /// Render a default-deny workload fence with one control-to-boundary path.
    ///
    /// Kubernetes `NetworkPolicy` is connection-aware: traffic returning over
    /// the control-initiated boundary connection is allowed even though the
    /// workload pod has no egress rules. The control pod remains responsible
    /// for opening policy-approved upstream connections.
    #[must_use]
    pub fn provision(self) -> KubernetesProxyPodNetworkFence {
        let workload_labels = boundary_pair_labels(&self.pair_label_value, WORKLOAD_ROLE);
        let control_labels = boundary_pair_labels(&self.pair_label_value, SUPERVISOR_ROLE);

        let workload_policy = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some(self.policy_name),
                namespace: Some(self.namespace),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: LabelSelector {
                    match_labels: Some(workload_labels.clone()),
                    ..Default::default()
                },
                policy_types: Some(vec!["Ingress".to_string(), "Egress".to_string()]),
                // Only the exactly paired control pod in this namespace may
                // establish the authenticated boundary connection.
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
            status: None,
        };

        KubernetesProxyPodNetworkFence {
            workload_labels,
            control_labels,
            workload_policy,
        }
    }
}

fn boundary_pair_labels(pair: &str, role: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (BOUNDARY_PAIR_LABEL.to_string(), pair.to_string()),
        (BOUNDARY_ROLE_LABEL.to_string(), role.to_string()),
    ])
}

/// Driver-owned inputs that bind one workload/proxy pair to one boundary.
///
/// The driver constructs this only after Kubernetes has assigned every UID and
/// after it has observed the exact egress policy resource version. The workload
/// stays held until the matching boundary config and control topology have been
/// installed.
pub struct KubernetesProxyPodBoundarySpec {
    pub boundary_id: String,
    pub bootstrap_token: String,
    pub generation: String,
    pub session_epoch: String,
    pub namespace_uid: String,
    pub sandbox_resource_uid: String,
    pub workload_pod_uid: String,
    pub workload_pod_uid_path: PathBuf,
    pub control_deployment_uid: String,
    pub egress_policy_uid: String,
    pub egress_policy_resource_version: String,
    pub boundary_listener: SocketAddr,
    pub control_address: SocketAddr,
    pub sandbox_tls: BoundaryServerTls,
    pub supervisor_tls: BoundaryClientTls,
    pub host_gateway_ip: Option<IpAddr>,
    pub workload_identity: ResolvedWorkloadIdentity,
    pub child_env: HashMap<String, String>,
}

/// Protected workload-pod config and matching proxy-pod descriptor.
pub struct KubernetesProxyPodBoundaryProvisioning {
    pub boundary_config: BoundaryConfig,
    pub topology: BoundaryTopology,
}

impl KubernetesProxyPodBoundarySpec {
    /// Produce both sides of the common protocol from one observed Kubernetes
    /// resource set so a stale or recreated object cannot be attached.
    #[must_use]
    pub fn provision(self) -> KubernetesProxyPodBoundaryProvisioning {
        let resource_claims = BTreeMap::from([
            ("kubernetes.namespace_uid".to_string(), self.namespace_uid),
            (
                "kubernetes.sandbox_resource_uid".to_string(),
                self.sandbox_resource_uid,
            ),
            (
                "kubernetes.workload_pod_uid".to_string(),
                self.workload_pod_uid,
            ),
            (
                "kubernetes.control_deployment_uid".to_string(),
                self.control_deployment_uid,
            ),
            (
                "kubernetes.egress_policy_uid".to_string(),
                self.egress_policy_uid,
            ),
            (
                "kubernetes.egress_policy_resource_version".to_string(),
                self.egress_policy_resource_version,
            ),
        ]);
        let driver_fence = DriverFenceEvidence::Kubernetes {
            network_policy_uid: resource_claims["kubernetes.egress_policy_uid"].clone(),
            network_policy_resource_version:
                resource_claims["kubernetes.egress_policy_resource_version"].clone(),
            ingress_isolated: true,
            egress_isolated: true,
            egress_rule_count: 0,
        };
        KubernetesProxyPodBoundaryProvisioning {
            boundary_config: BoundaryConfig {
                boundary_id: self.boundary_id.clone(),
                generation: self.generation.clone(),
                session_epoch: self.session_epoch.clone(),
                bootstrap_token: self.bootstrap_token.clone(),
                listener: BoundaryListener::TlsTcp {
                    address: self.boundary_listener,
                    tls: self.sandbox_tls,
                },
                resource_claims: resource_claims.clone(),
                resource_claim_files: BTreeMap::from([(
                    "kubernetes.workload_pod_uid".to_string(),
                    self.workload_pod_uid_path,
                )]),
                workload_identity: self.workload_identity.clone(),
                driver_fence: driver_fence.clone(),
                child_env: self.child_env,
            },
            topology: BoundaryTopology {
                boundary_id: self.boundary_id,
                generation: self.generation,
                session_epoch: self.session_epoch,
                workload_identity: self.workload_identity,
                transport: BoundaryTransport::TlsTcp {
                    address: self.control_address,
                    tls: self.supervisor_tls,
                },
                host_gateway_ip: self.host_gateway_ip,
                resource_claims,
                driver_fence,
                bootstrap_token: self.bootstrap_token,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> KubernetesProxyPodBoundarySpec {
        KubernetesProxyPodBoundarySpec {
            boundary_id: "sandbox-1".to_string(),
            bootstrap_token: "a".repeat(64),
            generation: "generation-1".to_string(),
            session_epoch: "epoch-1".to_string(),
            namespace_uid: "namespace-uid".to_string(),
            sandbox_resource_uid: "sandbox-resource-uid".to_string(),
            workload_pod_uid: "pod-uid".to_string(),
            workload_pod_uid_path: PathBuf::from("/.openshell/pod-identity/uid"),
            control_deployment_uid: "control-deployment-uid".to_string(),
            egress_policy_uid: "network-policy-uid".to_string(),
            egress_policy_resource_version: "1945".to_string(),
            boundary_listener: "0.0.0.0:5500".parse().expect("valid listener"),
            control_address: "10.42.0.7:5500".parse().expect("valid target"),
            sandbox_tls: BoundaryServerTls {
                certificate_chain_path: PathBuf::from("/run/boundary/tls.crt"),
                private_key_path: PathBuf::from("/run/boundary/tls.key"),
                client_ca_certificate_path: PathBuf::from("/run/boundary/client-ca.crt"),
            },
            supervisor_tls: BoundaryClientTls {
                server_name: "boundary.sandbox.openshell".to_string(),
                ca_certificate_pem: "test-ca".to_string(),
                certificate_chain_pem: "test-client-cert".to_string(),
                private_key_pem: "test-client-key".to_string(),
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
        let provisioned = spec().provision();

        assert_eq!(
            provisioned.boundary_config.resource_claims,
            provisioned.topology.resource_claims
        );
        assert_eq!(
            provisioned.topology.resource_claims["kubernetes.sandbox_resource_uid"],
            "sandbox-resource-uid"
        );
        assert_eq!(
            provisioned.topology.resource_claims["kubernetes.egress_policy_resource_version"],
            "1945"
        );
        assert_eq!(
            provisioned.boundary_config.driver_fence,
            provisioned.topology.driver_fence
        );
        assert!(
            provisioned
                .topology
                .driver_fence
                .validate_for_backend(BACKEND_NAME)
                .is_ok()
        );
    }

    #[test]
    fn provisioning_uses_one_shared_tcp_protocol_across_pods() {
        let provisioned = spec().provision();

        assert_eq!(
            provisioned.boundary_config.listener,
            BoundaryListener::TlsTcp {
                address: "0.0.0.0:5500".parse().expect("valid listener"),
                tls: BoundaryServerTls {
                    certificate_chain_path: PathBuf::from("/run/boundary/tls.crt"),
                    private_key_path: PathBuf::from("/run/boundary/tls.key"),
                    client_ca_certificate_path: PathBuf::from("/run/boundary/client-ca.crt",),
                },
            }
        );
        assert_eq!(
            provisioned.topology.transport,
            BoundaryTransport::TlsTcp {
                address: "10.42.0.7:5500".parse().expect("valid target"),
                tls: BoundaryClientTls {
                    server_name: "boundary.sandbox.openshell".to_string(),
                    ca_certificate_pem: "test-ca".to_string(),
                    certificate_chain_pem: "test-client-cert".to_string(),
                    private_key_pem: "test-client-key".to_string(),
                },
            }
        );
    }

    #[test]
    fn network_fence_denies_all_workload_initiated_egress() {
        let fence = KubernetesProxyPodNetworkFenceSpec {
            namespace: "sandbox-ns".to_string(),
            policy_name: "openshell-boundary-sandbox-1".to_string(),
            pair_label_value: "pair-1".to_string(),
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
    fn network_fence_allows_only_paired_control_to_boundary_port() {
        let fence = KubernetesProxyPodNetworkFenceSpec {
            namespace: "sandbox-ns".to_string(),
            policy_name: "openshell-boundary-sandbox-1".to_string(),
            pair_label_value: "pair-1".to_string(),
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
}
