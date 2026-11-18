// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `KubeVirt` boundary provisioning for the shared authenticated boundary
//! protocol, modeled on the VM driver's `VmBoundarySpec`
//! (`crates/openshell-driver-vm/src/isolation/mod.rs`).
//!
//! Claims model (user decision, option A): the boundary claims the
//! `VirtualMachine`'s UID (stable across stop/start) and the generation,
//! plus the image identity. The outer-fence evidence carries the
//! `NetworkPolicy` UID that fences the virt-launcher pod's egress,
//! projected against the generation. The virt-launcher pod's own UID
//! cannot be claimed: `KubeVirt` creates that pod asynchronously, so its
//! UID does not exist when the boundary config is rendered.
//!
//! Image identity: the VM driver claims the image's registry digest;
//! the `KubeVirt` `PoC` claims the configured `guest_image` reference (a tag),
//! which is weaker. The production path is a digest-pinned guest image.
//!
//! Who verifies the fence:
//!
//! - the **driver** attests the fence by re-reading the `NetworkPolicy`
//!   each generation (`verify_fence`): it fails the start when the fence
//!   was deleted, its UID changed (replaced), or its spec drifted;
//! - the **boundary** checks the evidence's generation binding
//!   (`contract.rs:254 validate`);
//! - **descriptor/config evidence and claims consistency** is enforced at
//!   `isolation_protocol.rs:100` (the driver descriptor must match the
//!   provisioned boundary config exactly) and on confirmation
//!   (`runtime.rs:757`).
//!
//! Neither the boundary nor the supervisor can independently query the
//! cluster; the driver is the attestation authority for the fence.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;

use openshell_isolation_interface::contract::{
    BackendError, ProvisioningEvidence, ResolvedWorkloadIdentity,
};
use openshell_sandbox_backend::boundary_protocol::{
    BoundaryConfig, BoundaryListener, GatewayVerificationKey, SandboxRuntimeDescriptor,
    SandboxTlsClientConfig, SandboxTlsServerConfig, SandboxTransport,
};
use serde::Serialize;

/// Image identity note.
///
/// The VM driver claims the image's registry digest
/// (`bootstrap_image_cache_identity` in
/// `crates/openshell-driver-vm/src/driver.rs`). The `KubeVirt` `PoC` claims
/// the configured `guest_image` reference (a tag), which is weaker: a tag
/// does not identify an image. The production path is a digest-pinned
/// Resource-claim keys.
///
/// The generation marker is recognized by the shared `is_vm_guest`
/// predicate in `boundary_protocol` (user decision, option A: both
/// `vm.generation` and `kubevirt.generation` mark a VM guest).
pub const CLAIM_VM_UID: &str = "kubevirt.vm_uid";
pub const CLAIM_GENERATION: &str =
    openshell_sandbox_backend::boundary_protocol::KUBEVIRT_GENERATION_CLAIM;
pub const CLAIM_IMAGE_IDENTITY: &str = "kubevirt.image_identity";
/// How the guest workload runs, claimed in both the boundary config and
/// the descriptor so the supervisor's confirm refuses a mode mismatch
/// (a sandboxed guest presenting a root config, or the reverse).
pub const CLAIM_WORKLOAD_MODE: &str = "kubevirt.workload_mode";

/// The dedicated supervisor Pod's UID, claimed only in the dedicated
/// topology (mirrors the pod path's `kubernetes.supervisor_pod_uid`).
pub const CLAIM_SUPERVISOR_POD_UID: &str = "kubevirt.supervisor_pod_uid";

/// Where the guest init stages the boundary bootstrap artifacts. These are
/// the paths written into the `BoundaryConfig`'s TLS config and read by the
/// boundary at startup.
pub const GUEST_BOUNDARY_CONFIG_PATH: &str = "/.openshell/state/bootstrap/boundary.json";
pub const GUEST_BOUNDARY_CERTIFICATE_PATH: &str = "/.openshell/state/bootstrap/tls.crt";
pub const GUEST_BOUNDARY_PRIVATE_KEY_PATH: &str = "/.openshell/state/bootstrap/tls.key";

/// Native evidence that the virt-launcher `NetworkPolicy` fence exists and
/// belongs to this generation.
#[derive(Serialize)]
struct KubeVirtOuterFenceEvidence<'a> {
    generation: &'a str,
    network_policy_uid: &'a str,
    network_policy_resource_version: &'a str,
}

impl KubeVirtOuterFenceEvidence<'_> {
    fn project(&self) -> Result<ProvisioningEvidence, BackendError> {
        if self.generation.is_empty()
            || self.network_policy_uid.is_empty()
            || self.network_policy_resource_version.is_empty()
        {
            return Err(BackendError::Descriptor(
                "KubeVirt provisioning evidence is incomplete: the NetworkPolicy fence must \
                 exist with a UID and resourceVersion before the boundary config is rendered"
                    .to_string(),
            ));
        }
        let encoded = serde_json::to_vec(self).map_err(|error| {
            BackendError::Descriptor(format!("encode KubeVirt outer fence evidence: {error}"))
        })?;
        let projection =
            ProvisioningEvidence::from_enforcement_evidence(self.generation, &encoded)?;
        projection.validate(self.generation)?;
        Ok(projection)
    }
}

/// Where a `KubeVirt` boundary dials its supervisor, and what the fence
/// admits egress to.
///
/// Mirrors the pod path's two supervisor topologies: a dedicated supervisor
/// Pod per sandbox (the default), or a sandbox instance on the gateway's
/// shared supervisor.
#[derive(Clone, Debug)]
pub enum KubeVirtSupervisorTarget {
    /// This sandbox's dedicated supervisor Pod, fronted by its per-sandbox
    /// Service (`os-supervisor-<id>`) in the sandbox namespace.
    Dedicated {
        /// The per-sandbox Service's DNS authority
        /// (`os-supervisor-<id>.<ns>.svc:<port>`).
        authority: String,
        /// The Service's `ClusterIP` endpoint.
        address: SocketAddr,
        /// The supervisor Pod's UID, claimed as `kubevirt.supervisor_pod_uid`
        /// and re-bound on every start (a new generation gets a new Pod).
        supervisor_pod_uid: String,
        /// Labels selecting the supervisor Pod (the boundary pair's
        /// supervisor role); the fence's egress target.
        pod_selector: BTreeMap<String, String>,
        /// The boundary port the supervisor listens on.
        port: u16,
    },
    /// A sandbox instance on the gateway's shared supervisor, fronted by
    /// its Service.
    Shared {
        /// The shared supervisor Service's DNS authority
        /// (`{service}.{ns}.svc:{port}`).
        authority: String,
        /// The Service's `ClusterIP` endpoint.
        address: SocketAddr,
        /// Route handle for this sandbox instance.
        route: String,
        /// Namespace of the shared supervisor Service.
        namespace: String,
        /// The Service's `spec.selector` (pod labels).
        pod_selector: BTreeMap<String, String>,
        /// The runtime port.
        port: u16,
    },
}

impl KubeVirtSupervisorTarget {
    fn authority(&self) -> &str {
        match self {
            Self::Dedicated { authority, .. } | Self::Shared { authority, .. } => authority,
        }
    }

    fn address(&self) -> SocketAddr {
        match self {
            Self::Dedicated { address, .. } | Self::Shared { address, .. } => *address,
        }
    }

    fn port(&self) -> u16 {
        match self {
            Self::Dedicated { port, .. } | Self::Shared { port, .. } => *port,
        }
    }

    /// The egress `to` peers the fence admits: this sandbox's dedicated
    /// supervisor Pod (same namespace, pair-scoped selector) or the shared
    /// supervisor's Pods (cross-namespace, Service selector).
    fn fence_egress_to(&self) -> Vec<serde_json::Value> {
        let selector = |labels: &BTreeMap<String, String>| {
            labels
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::json!(v)))
                .collect::<serde_json::Map<String, serde_json::Value>>()
        };
        match self {
            Self::Dedicated { pod_selector, .. } => vec![serde_json::json!({
                "podSelector": {"matchLabels": selector(pod_selector)}
            })],
            Self::Shared {
                namespace,
                pod_selector,
                ..
            } => vec![serde_json::json!({
                "namespaceSelector": {
                    "matchLabels": {
                        "kubernetes.io/metadata.name": namespace
                    }
                },
                "podSelector": {"matchLabels": selector(pod_selector)}
            })],
        }
    }
}

/// Driver-owned inputs that bind one `KubeVirt` VM generation to one
/// supervisor boundary.
pub struct KubeVirtBoundarySpec {
    pub boundary_id: String,
    pub generation: String,
    pub session_id: openshell_core::SandboxSessionId,
    pub session_rotation: openshell_core::jwt::SessionRotation,
    pub auth_epoch: openshell_core::jwt::CredentialEpoch,
    pub gateway_id: String,
    pub verification_keys: Vec<GatewayVerificationKey>,
    /// The `VirtualMachine` object's UID, stable across stop/start.
    pub vm_uid: String,
    /// The guest image reference, claimed as the image identity.
    pub image_identity: String,
    /// UID of the `NetworkPolicy` that fences the virt-launcher pod's
    /// egress. Re-read and verified on every generation.
    pub network_policy_uid: String,
    /// resourceVersion of the fence `NetworkPolicy` at render time.
    pub network_policy_resource_version: String,
    /// Where the boundary dials its supervisor: the per-sandbox Service of
    /// a dedicated supervisor Pod, or the gateway-shared supervisor's
    /// Service with this sandbox's route handle.
    pub supervisor: KubeVirtSupervisorTarget,
    /// TLS client config the supervisor uses to authenticate the boundary.
    pub supervisor_tls: SandboxTlsClientConfig,
    /// The workload identity (uid/gid) the boundary runs as.
    pub workload_identity: ResolvedWorkloadIdentity,
    /// The workload mode ("root" | "sandboxed") — claimed and confirmed.
    pub workload_mode: crate::config::KubeVirtWorkloadMode,
    /// Environment the boundary passes to workload children.
    pub child_env: HashMap<String, String>,
}

/// The protected guest config and matching runtime descriptor for one
/// `KubeVirt` VM.
pub struct KubeVirtBoundaryProvisioning {
    pub boundary_config: BoundaryConfig,
    pub runtime_descriptor: SandboxRuntimeDescriptor,
}

impl KubeVirtBoundarySpec {
    /// Produce both sides of the common protocol from one set of immutable
    /// driver inputs so their identity claims cannot drift.
    pub fn provision(self) -> Result<KubeVirtBoundaryProvisioning, BackendError> {
        let mut resource_claims = BTreeMap::from([
            (CLAIM_VM_UID.to_string(), self.vm_uid.clone()),
            (CLAIM_GENERATION.to_string(), self.generation.clone()),
            (
                CLAIM_IMAGE_IDENTITY.to_string(),
                self.image_identity.clone(),
            ),
            (
                CLAIM_WORKLOAD_MODE.to_string(),
                self.workload_mode.to_string(),
            ),
        ]);
        // The dedicated topology claims the supervisor Pod's UID (mirroring
        // the pod path's `kubernetes.supervisor_pod_uid`); the shared
        // topology instead names its instance by the route handle carried in
        // the transport. No control-policy UID is claimed in either
        // topology (user decision).
        let listener_route = match &self.supervisor {
            KubeVirtSupervisorTarget::Dedicated {
                supervisor_pod_uid, ..
            } => {
                if supervisor_pod_uid.trim().is_empty() {
                    return Err(BackendError::Descriptor(
                        "KubeVirt boundary requires the dedicated supervisor Pod's UID; an \
                         empty claim would bind the boundary to no supervisor"
                            .to_string(),
                    ));
                }
                resource_claims.insert(
                    CLAIM_SUPERVISOR_POD_UID.to_string(),
                    supervisor_pod_uid.clone(),
                );
                None
            }
            KubeVirtSupervisorTarget::Shared { route, .. } => {
                if route.trim().is_empty() {
                    return Err(BackendError::Descriptor(
                        "KubeVirt boundary requires a shared-supervisor route handle; an \
                         empty route would route ambiguously"
                            .to_string(),
                    ));
                }
                Some(route.clone())
            }
        };
        let transport = match &self.supervisor {
            // A dedicated supervisor serves its one boundary on a plain
            // runtime-initiated TCP listener (the pod path's dedicated
            // transport); no route preface names an instance.
            KubeVirtSupervisorTarget::Dedicated {
                authority, port, ..
            } => SandboxTransport::RuntimeInitiatedTcp {
                authority: authority.clone(),
                listen_address: SocketAddr::from(([0, 0, 0, 0], *port)),
            },
            // The shared supervisor routes the connection to this sandbox's
            // instance by the preface route handle.
            KubeVirtSupervisorTarget::Shared {
                authority, route, ..
            } => SandboxTransport::RuntimeInitiatedRouted {
                authority: authority.clone(),
                route: route.clone(),
            },
        };
        let provisioning_evidence = KubeVirtOuterFenceEvidence {
            generation: &self.generation,
            network_policy_uid: &self.network_policy_uid,
            network_policy_resource_version: &self.network_policy_resource_version,
        }
        .project()?;
        let sandbox_tls = SandboxTlsServerConfig {
            certificate_chain_path: GUEST_BOUNDARY_CERTIFICATE_PATH.into(),
            private_key_path: GUEST_BOUNDARY_PRIVATE_KEY_PATH.into(),
        };
        Ok(KubeVirtBoundaryProvisioning {
            boundary_config: BoundaryConfig {
                boundary_id: self.boundary_id.clone(),
                generation: self.generation.clone(),
                session_id: self.session_id,
                session_rotation: self.session_rotation,
                auth_epoch: self.auth_epoch,
                gateway_id: self.gateway_id,
                verification_keys: self.verification_keys,
                listener: BoundaryListener::RuntimeInitiatedTlsTcp {
                    authority: self.supervisor.authority().to_string(),
                    addresses: vec![self.supervisor.address()],
                    tls: sandbox_tls,
                    route: listener_route,
                },
                resource_claims: resource_claims.clone(),
                resource_claim_files: BTreeMap::new(),
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
                host_gateway_ip: None,
                resource_claims,
                provisioning_evidence,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real descriptor/config consistency check from sandbox-backend
    /// (`isolation_protocol.rs` calls the same function), not a local copy.
    fn descriptor_matches_config(
        descriptor: &SandboxRuntimeDescriptor,
        config: &BoundaryConfig,
    ) -> Result<(), ()> {
        if openshell_sandbox_backend::boundary_protocol::descriptor_matches_config(
            descriptor, config,
        ) {
            Ok(())
        } else {
            Err(())
        }
    }

    fn shared_target() -> KubeVirtSupervisorTarget {
        KubeVirtSupervisorTarget::Shared {
            authority: "supervisor.openshell.svc:5500".to_string(),
            address: "10.43.0.10:5500".parse().unwrap(),
            route: "route-1".to_string(),
            namespace: "openshell".to_string(),
            pod_selector: BTreeMap::from([
                (
                    "app.kubernetes.io/name".to_string(),
                    "openshell-supervisor".to_string(),
                ),
                (
                    "app.kubernetes.io/component".to_string(),
                    "supervisor".to_string(),
                ),
            ]),
            port: 5500,
        }
    }

    fn dedicated_target() -> KubeVirtSupervisorTarget {
        KubeVirtSupervisorTarget::Dedicated {
            authority: "os-supervisor-sbx-1.openshell-e2e-ns.svc:5500".to_string(),
            address: "10.43.5.10:5500".parse().unwrap(),
            supervisor_pod_uid: "supervisor-pod-uid-1".to_string(),
            pod_selector: BTreeMap::from([
                (
                    "openshell.ai/boundary-pair".to_string(),
                    "sbx-1".to_string(),
                ),
                (
                    "openshell.ai/boundary-role".to_string(),
                    "supervisor".to_string(),
                ),
            ]),
            port: 5500,
        }
    }

    fn spec_with(supervisor: KubeVirtSupervisorTarget) -> KubeVirtBoundarySpec {
        KubeVirtBoundarySpec {
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
            vm_uid: "vm-uid-1".to_string(),
            image_identity: "openshell/sandbox-vm:test".to_string(),
            workload_mode: crate::config::KubeVirtWorkloadMode::Sandboxed,
            network_policy_uid: "np-uid-1".to_string(),
            network_policy_resource_version: "1945".to_string(),
            supervisor,
            supervisor_tls: SandboxTlsClientConfig {
                server_name: "boundary.sandbox.openshell".to_string(),
                trust_anchor_pem: "test-ca".to_string(),
            },
            workload_identity: ResolvedWorkloadIdentity::new(
                10001,
                10001,
                Vec::new(),
                "kubevirt-config".to_string(),
                format!("sandbox:{}", "vm-uid-1"),
            )
            .unwrap(),
            child_env: HashMap::new(),
        }
    }

    fn spec() -> KubeVirtBoundarySpec {
        spec_with(shared_target())
    }

    fn dedicated_spec() -> KubeVirtBoundarySpec {
        spec_with(dedicated_target())
    }

    #[test]
    fn provision_produces_matching_claims_and_evidence() {
        let provisioned = spec().provision().expect("provision");
        assert_eq!(
            provisioned.boundary_config.resource_claims[CLAIM_VM_UID],
            "vm-uid-1"
        );
        assert_eq!(
            provisioned.runtime_descriptor.resource_claims[CLAIM_VM_UID],
            "vm-uid-1"
        );
        // Evidence is bound to the generation and validates.
        provisioned
            .boundary_config
            .provisioning_evidence
            .validate("generation-1")
            .expect("evidence validates");
    }

    #[test]
    fn evidence_rejects_mismatched_generation() {
        let provisioned = spec().provision().expect("provision");
        assert!(
            provisioned
                .boundary_config
                .provisioning_evidence
                .validate("generation-2")
                .is_err()
        );
    }

    #[test]
    fn evidence_rejects_missing_fence() {
        let mut s = spec();
        s.network_policy_uid = String::new();
        assert!(s.provision().is_err(), "empty fence UID must fail closed");
    }

    #[test]
    fn evidence_rejects_missing_resource_version() {
        let mut s = spec();
        s.network_policy_resource_version = String::new();
        assert!(
            s.provision().is_err(),
            "empty fence resourceVersion must fail closed"
        );
    }

    #[test]
    fn evidence_rejects_replaced_fence() {
        // Render the boundary config from fence A and the descriptor from
        // fence B: the descriptor/config consistency check
        // (isolation_protocol.rs:100) must reject the mismatched pair.
        let original = spec().provision().expect("provision");
        let mut replaced = spec();
        replaced.network_policy_uid = "np-uid-2".to_string();
        let replacement = replaced.provision().expect("provision");
        assert!(
            descriptor_matches_config(&original.runtime_descriptor, &replacement.boundary_config)
                .is_err(),
            "a descriptor rendered against fence B must not match a config from fence A"
        );
    }

    #[test]
    fn evidence_rejects_stale_bootstrap_from_previous_generation() {
        let generation_1 = spec().provision().expect("provision");
        let mut s = spec();
        s.generation = "generation-2".to_string();
        let generation_2 = s.provision().expect("provision");
        assert!(
            generation_1
                .boundary_config
                .provisioning_evidence
                .validate("generation-2")
                .is_err()
        );
        assert!(
            descriptor_matches_config(
                &generation_2.runtime_descriptor,
                &generation_1.boundary_config
            )
            .is_err(),
            "a current descriptor must not match a stale previous-generation config"
        );
    }

    #[test]
    fn vm_uid_mismatch_rejected_by_descriptor_config_consistency() {
        let original = spec().provision().expect("provision");
        let mut replaced = spec();
        replaced.vm_uid = "vm-uid-2".to_string();
        replaced.workload_identity = ResolvedWorkloadIdentity::new(
            10001,
            10001,
            Vec::new(),
            "kubevirt-config".to_string(),
            "sandbox:vm-uid-2".to_string(),
        )
        .unwrap();
        let other = replaced.provision().expect("provision");
        assert!(
            descriptor_matches_config(&other.runtime_descriptor, &original.boundary_config)
                .is_err(),
            "a descriptor rendered for vm-uid-2 must not match a config from vm-uid-1"
        );
    }

    #[test]
    fn vm_uid_survives_stop_start_while_generation_advances() {
        // The VM UID is stable across stop/start; only the generation
        // advances. The claims carry the same vm_uid in both renders.
        let first = spec().provision().expect("provision");
        let mut s = spec();
        s.generation = "generation-2".to_string();
        let second = s.provision().expect("provision");
        assert_eq!(
            first.boundary_config.resource_claims[CLAIM_VM_UID],
            second.boundary_config.resource_claims[CLAIM_VM_UID]
        );
        assert_ne!(
            first.boundary_config.generation,
            second.boundary_config.generation
        );
        // Both generations' evidence validate against their own generation.
        first
            .boundary_config
            .provisioning_evidence
            .validate("generation-1")
            .expect("first generation validates");
        second
            .boundary_config
            .provisioning_evidence
            .validate("generation-2")
            .expect("second generation validates");
    }

    #[test]
    fn rendered_config_is_recognized_as_vm_guest() {
        let provisioned = spec().provision().expect("provision");
        assert!(
            openshell_sandbox_backend::boundary_protocol::is_vm_guest(
                &provisioned.boundary_config.resource_claims
            ),
            "the rendered KubeVirt boundary config must satisfy is_vm_guest"
        );
    }

    #[test]
    fn dedicated_provision_claims_the_supervisor_pod_uid() {
        let provisioned = dedicated_spec().provision().expect("provision");
        // Both sides carry the claim, so descriptor/config consistency
        // (isolation_protocol.rs) binds the boundary to this supervisor Pod.
        assert_eq!(
            provisioned.boundary_config.resource_claims[CLAIM_SUPERVISOR_POD_UID],
            "supervisor-pod-uid-1"
        );
        assert_eq!(
            provisioned.runtime_descriptor.resource_claims[CLAIM_SUPERVISOR_POD_UID],
            "supervisor-pod-uid-1"
        );
        assert!(
            descriptor_matches_config(
                &provisioned.runtime_descriptor,
                &provisioned.boundary_config
            )
            .is_ok()
        );
    }

    #[test]
    fn root_mode_bootstrap_renders_with_uid_zero_identity() {
        // B1: the root workload class must render a bootstrap end to end.
        // The standard ResolvedWorkloadIdentity::new refuses UID/GID zero,
        // so the privileged constructor is used; the identity and the mode
        // claim are checked.
        let auth = payload_tests::test_launch_authentication();
        let target = shared_target();
        let bootstrap = render_kubevirt_bootstrap(
            &auth,
            "sbx-1",
            "sandbox-1",
            "vm-uid-1",
            "openshell/sandbox-vm:test",
            "np-uid-1",
            "1945",
            serde_json::json!({}),
            &target,
            0,
            0,
            crate::config::KubeVirtWorkloadMode::Root,
        )
        .expect("root-mode bootstrap renders");
        // The descriptor carries the mode claim and the uid-0 identity.
        assert_eq!(
            bootstrap.runtime_descriptor.resource_claims[CLAIM_WORKLOAD_MODE],
            "root"
        );
        let identity = &bootstrap.runtime_descriptor.workload_identity;
        assert_eq!(identity.uid, 0, "root mode runs as uid 0");
        assert_eq!(identity.gid, 0, "root mode runs as gid 0");
    }

    #[test]
    fn workload_mode_claim_is_in_both_config_and_descriptor() {
        // The mode claim binds the sandbox class into the confirmed
        // evidence: the supervisor's descriptor check refuses a mode
        // mismatch in either direction.
        let provisioned = spec_with(shared_target()).provision().expect("provision");
        assert_eq!(
            provisioned.boundary_config.resource_claims[CLAIM_WORKLOAD_MODE],
            "sandboxed"
        );
        assert_eq!(
            provisioned.runtime_descriptor.resource_claims[CLAIM_WORKLOAD_MODE],
            "sandboxed"
        );
        // A root-mode config never matches a sandboxed descriptor.
        let mut root_spec = spec_with(shared_target());
        root_spec.workload_mode = crate::config::KubeVirtWorkloadMode::Root;
        let root = root_spec.provision().expect("provision");
        assert_eq!(
            root.boundary_config.resource_claims[CLAIM_WORKLOAD_MODE],
            "root"
        );
        assert!(
            !openshell_sandbox_backend::boundary_protocol::descriptor_matches_config(
                &root.runtime_descriptor,
                &provisioned.boundary_config
            ),
            "a root descriptor must not match a sandboxed config"
        );
    }

    #[test]
    fn shared_provision_carries_no_supervisor_pod_uid_claim() {
        let provisioned = spec().provision().expect("provision");
        assert!(
            !provisioned
                .boundary_config
                .resource_claims
                .contains_key(CLAIM_SUPERVISOR_POD_UID)
        );
        assert!(
            !provisioned
                .runtime_descriptor
                .resource_claims
                .contains_key(CLAIM_SUPERVISOR_POD_UID)
        );
    }

    #[test]
    fn dedicated_listener_omits_the_route_and_uses_plain_tcp_transport() {
        let provisioned = dedicated_spec().provision().expect("provision");
        match &provisioned.boundary_config.listener {
            BoundaryListener::RuntimeInitiatedTlsTcp { route, .. } => {
                assert!(
                    route.is_none(),
                    "a dedicated supervisor is not routed: {route:?}"
                );
            }
            other => panic!("expected RuntimeInitiatedTlsTcp listener, got {other:?}"),
        }
        // The dedicated descriptor transport mirrors the pod path's
        // dedicated KubernetesControlPath (isolation.rs): a plain
        // runtime-initiated TCP listener with no route preface.
        match &provisioned.runtime_descriptor.transport {
            SandboxTransport::RuntimeInitiatedTcp { listen_address, .. } => {
                assert_eq!(listen_address.port(), 5500);
            }
            other => panic!("expected RuntimeInitiatedTcp transport, got {other:?}"),
        }
    }

    #[test]
    fn shared_transport_stays_routed() {
        let provisioned = spec().provision().expect("provision");
        match &provisioned.runtime_descriptor.transport {
            SandboxTransport::RuntimeInitiatedRouted { route, .. } => {
                assert_eq!(route, "route-1");
            }
            other => panic!("expected RuntimeInitiatedRouted transport, got {other:?}"),
        }
    }

    fn with_dedicated_pod_uid(uid: &str) -> KubeVirtSupervisorTarget {
        let mut target = dedicated_target();
        if let KubeVirtSupervisorTarget::Dedicated {
            supervisor_pod_uid, ..
        } = &mut target
        {
            *supervisor_pod_uid = uid.to_string();
        }
        target
    }

    #[test]
    fn dedicated_rejects_an_empty_supervisor_pod_uid() {
        let Err(error) = spec_with(with_dedicated_pod_uid("")).provision() else {
            panic!("an empty pod UID must fail closed")
        };
        assert!(
            error.to_string().contains("supervisor Pod's UID"),
            "message should name the claim: {error}"
        );
    }

    #[test]
    fn dedicated_descriptor_does_not_match_a_config_for_another_supervisor_pod() {
        let original = dedicated_spec().provision().expect("provision");
        let replaced = spec_with(with_dedicated_pod_uid("supervisor-pod-uid-2"))
            .provision()
            .expect("provision");
        assert!(
            descriptor_matches_config(&replaced.runtime_descriptor, &original.boundary_config)
                .is_err(),
            "a descriptor rendered for another supervisor Pod must not match"
        );
    }

    #[test]
    fn dedicated_and_shared_configs_never_match() {
        let dedicated = dedicated_spec().provision().expect("provision");
        let shared = spec().provision().expect("provision");
        assert!(
            descriptor_matches_config(&shared.runtime_descriptor, &dedicated.boundary_config)
                .is_err(),
            "a shared descriptor must not match a dedicated config"
        );
        assert!(
            descriptor_matches_config(&dedicated.runtime_descriptor, &shared.boundary_config)
                .is_err(),
            "a dedicated descriptor must not match a shared config"
        );
    }

    #[test]
    fn guest_tls_paths_match_staging_constants() {
        let provisioned = spec().provision().expect("provision");
        match &provisioned.boundary_config.listener {
            BoundaryListener::RuntimeInitiatedTlsTcp { tls, .. } => {
                assert_eq!(
                    tls.certificate_chain_path,
                    std::path::Path::new(GUEST_BOUNDARY_CERTIFICATE_PATH)
                );
                assert_eq!(
                    tls.private_key_path,
                    std::path::Path::new(GUEST_BOUNDARY_PRIVATE_KEY_PATH)
                );
            }
            other => panic!("expected RuntimeInitiatedTlsTcp listener, got {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Virt-launcher egress fence
// ---------------------------------------------------------------------------

use kube::Client;
use kube::api::Api;
use kube::core::DynamicObject;

/// The fence's observed state: UID, resourceVersion, and the full spec
/// (for drift comparison).
#[derive(Debug, Clone)]
pub struct ObservedFence {
    pub uid: String,
    pub resource_version: String,
    pub spec: serde_json::Value,
}

/// The fence identity and shape the boundary evidence was rendered against.
#[derive(Debug, Clone)]
pub struct ExpectedFence {
    pub uid: String,
    pub resource_version: String,
    pub spec: serde_json::Value,
}

/// VM annotation persisting the fence expectation (UID and rendered spec)
/// the create-time evidence was rendered against.
///
/// The start path verifies the fence on every new generation with it:
/// deletion, UID change, and spec drift are Precondition errors; a
/// resourceVersion-only change is accepted and re-captured.
pub const FENCE_EXPECTATION_ANNOTATION: &str = "openshell.ai/kubevirt-fence-expectation";

impl ExpectedFence {
    /// Encode the expectation (UID + spec, not the volatile RV) as a VM
    /// annotation value.
    pub fn to_annotation(&self) -> Result<String, String> {
        serde_json::to_string(&serde_json::json!({
            "uid": self.uid,
            "spec": self.spec,
        }))
        .map_err(|error| format!("encode fence expectation: {error}"))
    }

    /// Decode a VM annotation value back into an expectation. The
    /// resourceVersion is not persisted (it changes on every label-only
    /// edit); the caller supplies the freshly rendered spec separately.
    pub fn from_annotation(value: &str) -> Result<Self, String> {
        let decoded: serde_json::Value = serde_json::from_str(value)
            .map_err(|error| format!("decode fence expectation: {error}"))?;
        Ok(Self {
            uid: decoded["uid"]
                .as_str()
                .ok_or("fence expectation has no uid")?
                .to_string(),
            resource_version: String::new(),
            spec: decoded["spec"].clone(),
        })
    }
}

impl ExpectedFence {
    /// Build from a freshly rendered fence JSON and the observed UID/RV.
    #[must_use]
    pub fn from_rendered(
        rendered: serde_json::Value,
        uid: String,
        resource_version: String,
    ) -> Self {
        Self {
            uid,
            resource_version,
            spec: rendered["spec"].clone(),
        }
    }
}

/// Render the virt-launcher fence `NetworkPolicy`.
///
/// The sandbox's only permitted egress is its supervisor on the boundary
/// port — the dedicated topology's own supervisor Pod (pair-scoped
/// selector, same namespace), or the shared supervisor's Pods (the
/// Service's own pod selector, read at render time — never hard-coded,
/// because the Helm chart's supervisor labels vary by release). No DNS, no
/// gateway: the boundary's in-guest DNS relay forwards through the
/// supervisor's network mediation, and the supervisor connection uses
/// driver-resolved addresses.
///
/// Ingress is deny-all (`policyTypes: [Ingress, Egress]` with no ingress
/// rules): the boundary dials out (`RuntimeInitiatedTlsTcp`), so the guest
/// needs no inbound connections. Serial console and virt-handler access go
/// through unix sockets on the node, not pod networking.
///
/// The policy carries the standard `OpenShell` ownership labels so the
/// driver's label-based cleanup and the demo's zero-leftovers check find
/// it.
#[must_use]
pub fn render_fence(
    namespace: &str,
    sandbox_id: &str,
    gateway_id: Option<&str>,
    target: &KubeVirtSupervisorTarget,
) -> serde_json::Value {
    let mut labels = BTreeMap::new();
    labels.insert(
        openshell_core::driver_utils::LABEL_MANAGED_BY.to_string(),
        openshell_core::driver_utils::LABEL_MANAGED_BY_VALUE.to_string(),
    );
    labels.insert(
        openshell_core::driver_utils::LABEL_SANDBOX_ID.to_string(),
        sandbox_id.to_string(),
    );
    if let Some(gw_id) = gateway_id {
        labels.insert(
            openshell_core::driver_utils::LABEL_GATEWAY_ID.to_string(),
            gw_id.to_string(),
        );
    }

    serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": fence_name(sandbox_id),
            "namespace": namespace,
            "labels": labels,
        },
        "spec": {
            "podSelector": {
                "matchLabels": {
                    "kubevirt.io": "virt-launcher",
                    openshell_core::driver_utils::LABEL_SANDBOX_ID: sandbox_id,
                }
            },
            "policyTypes": ["Ingress", "Egress"],
            "egress": [{
                "to": target.fence_egress_to(),
                "ports": [{
                    "port": target.port(),
                    "protocol": "TCP"
                }]
            }]
        }
    })
}

/// Render the `KubeVirt` control-ingress `NetworkPolicy` (L2).
///
/// The ONLY pods that may accept connections on the boundary port are this
/// pair's supervisor Pods, and the only admitted sources are this pair's
/// workload-role pods — the virt-launcher pod itself never accepts
/// boundary-port traffic. The pod path's pair-wide control policy applies
/// its ingress rule to the whole pair (workload pods there listen too);
/// the `KubeVirt` workload is a VM whose boundary dials out, so the ingress
/// half alone is needed and the fence already carries the egress half.
/// Residual, inherent to `NetworkPolicy`: a pod that forges the pair labels
/// can still REACH the supervisor's port, but cannot authenticate (the
/// supervisor verifies the boundary's pinned TLS and descriptor claims);
/// binding source identity needs namespace governance (pod creation
/// restricted to the driver's `ServiceAccount`).
#[must_use]
pub fn render_control_ingress(
    namespace: &str,
    sandbox_id: &str,
    pair: &str,
    port: u16,
) -> serde_json::Value {
    use std::collections::BTreeMap;
    let pair_role = |role: &str| {
        BTreeMap::from([
            ("openshell.ai/boundary-pair".to_string(), pair.to_string()),
            ("openshell.ai/boundary-role".to_string(), role.to_string()),
        ])
    };
    let selector = |labels: &BTreeMap<String, String>| {
        labels
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::json!(v)))
            .collect::<serde_json::Map<String, serde_json::Value>>()
    };
    let mut labels = BTreeMap::new();
    labels.insert(
        openshell_core::driver_utils::LABEL_MANAGED_BY.to_string(),
        openshell_core::driver_utils::LABEL_MANAGED_BY_VALUE.to_string(),
    );
    labels.insert(
        openshell_core::driver_utils::LABEL_SANDBOX_ID.to_string(),
        sandbox_id.to_string(),
    );
    serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": control_ingress_name(sandbox_id),
            "namespace": namespace,
            "labels": labels,
        },
        "spec": {
            "podSelector": {"matchLabels": selector(&pair_role("supervisor"))},
            "policyTypes": ["Ingress"],
            "ingress": [{
                "from": [{"podSelector": {"matchLabels": selector(&pair_role("workload"))}}],
                "ports": [{"port": port, "protocol": "TCP"}]
            }]
        }
    })
}

/// Name of the control-ingress `NetworkPolicy` for one sandbox (the same
/// name the pod path's control policy uses, so a namespace never carries
/// both shapes).
#[must_use]
pub fn control_ingress_name(sandbox_id: &str) -> String {
    format!("os-control-{}", sandbox_id.to_ascii_lowercase())
}

/// Name of the fence `NetworkPolicy` for one sandbox.
#[must_use]
pub fn fence_name(sandbox_id: &str) -> String {
    format!("openshell-kubevirt-fence-{sandbox_id}")
}

/// Read the fence's current state. `None` when the policy does not exist.
pub async fn observe_fence(
    client: &Client,
    namespace: &str,
    sandbox_id: &str,
) -> Result<Option<ObservedFence>, String> {
    let api: Api<DynamicObject> = Api::namespaced_with(
        client.clone(),
        namespace,
        &kube::api::ApiResource {
            group: "networking.k8s.io".to_string(),
            version: "v1".to_string(),
            api_version: "networking.k8s.io/v1".to_string(),
            kind: "NetworkPolicy".to_string(),
            plural: "networkpolicies".to_string(),
        },
    );
    let name = fence_name(sandbox_id);
    match api.get(&name).await {
        Ok(obj) => Ok(Some(ObservedFence {
            uid: obj.metadata.uid.unwrap_or_default(),
            resource_version: obj.metadata.resource_version.unwrap_or_default(),
            spec: obj
                .data
                .get("spec")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
        })),
        Err(kube::Error::Api(err)) if err.code == 404 => Ok(None),
        Err(err) => Err(err.to_string()),
    }
}

/// Pure fence verification (unit-testable without a cluster):
/// - deleted (None) → Err;
/// - UID changed (replaced policy) → Err;
/// - spec drift (podSelector, policyTypes, egress rules) → Err;
/// - resourceVersion-only change (a label or annotation from a controller)
///   → Ok with the new RV, so the driver re-captures it into the new
///   generation's evidence.
pub fn check_fence(
    observed: Option<&ObservedFence>,
    expected: &ExpectedFence,
    sandbox_id: &str,
) -> Result<ObservedFence, String> {
    let Some(observed) = observed else {
        return Err(format!(
            "the virt-launcher egress fence {} was deleted; the boundary \
             evidence was rendered against a fence that no longer exists",
            fence_name(sandbox_id)
        ));
    };
    if observed.uid != expected.uid {
        return Err(format!(
            "the virt-launcher egress fence was replaced (expected UID {}, got {}); \
             the boundary evidence was rendered against the old fence and cannot \
             be reused",
            expected.uid, observed.uid
        ));
    }
    if observed.spec != expected.spec {
        return Err(
            "the virt-launcher egress fence spec drifted from the rendered shape \
             (podSelector, policyTypes, or egress rules changed); the fence no \
             longer matches what the boundary evidence was rendered against"
                .to_string(),
        );
    }
    Ok(observed.clone())
}

/// Verify the fence on every new generation.
///
/// The async wrapper around [`check_fence`]. Returns the current
/// `ObservedFence` so the caller can re-capture the resourceVersion into
/// the new generation's evidence.
pub async fn verify_fence(
    client: &Client,
    namespace: &str,
    sandbox_id: &str,
    expected: &ExpectedFence,
) -> Result<ObservedFence, String> {
    let observed = observe_fence(client, namespace, sandbox_id).await?;
    check_fence(observed.as_ref(), expected, sandbox_id)
}

#[cfg(test)]
mod fence_tests {
    use super::*;

    pub(super) fn supervisor() -> KubeVirtSupervisorTarget {
        KubeVirtSupervisorTarget::Shared {
            authority: "openshell-supervisor.openshell.svc:5500".to_string(),
            address: "10.43.0.10:5500".parse().unwrap(),
            route: "route-1".to_string(),
            namespace: "openshell".to_string(),
            pod_selector: BTreeMap::from([
                (
                    "app.kubernetes.io/name".to_string(),
                    "openshell-supervisor".to_string(),
                ),
                (
                    "app.kubernetes.io/component".to_string(),
                    "supervisor".to_string(),
                ),
            ]),
            port: 5500,
        }
    }

    fn rendered_fence() -> serde_json::Value {
        render_fence("openshell-e2e-ns", "sbx-1", Some("gw"), &supervisor())
    }

    fn dedicated_fence() -> serde_json::Value {
        render_fence(
            "openshell-e2e-ns",
            "sbx-1",
            Some("gw"),
            &KubeVirtSupervisorTarget::Dedicated {
                authority: "os-supervisor-sbx-1.openshell-e2e-ns.svc:5500".to_string(),
                address: "10.43.5.10:5500".parse().unwrap(),
                supervisor_pod_uid: "supervisor-pod-uid-1".to_string(),
                pod_selector: BTreeMap::from([
                    (
                        "openshell.ai/boundary-pair".to_string(),
                        "sbx-1".to_string(),
                    ),
                    (
                        "openshell.ai/boundary-role".to_string(),
                        "supervisor".to_string(),
                    ),
                ]),
                port: 5500,
            },
        )
    }

    fn observed(uid: &str, rv: &str, spec: serde_json::Value) -> ObservedFence {
        ObservedFence {
            uid: uid.to_string(),
            resource_version: rv.to_string(),
            spec,
        }
    }

    #[test]
    fn fence_renders_deny_all_ingress_and_supervisor_only_egress() {
        let fence = rendered_fence();
        let policy_types = fence["spec"]["policyTypes"].as_array().unwrap();
        assert!(policy_types.contains(&serde_json::json!("Ingress")));
        assert!(policy_types.contains(&serde_json::json!("Egress")));
        // No ingress rules: deny-all ingress.
        assert!(fence["spec"]["ingress"].is_null());
        // The podSelector matches the virt-launcher pod.
        assert_eq!(
            fence["spec"]["podSelector"]["matchLabels"]["kubevirt.io"],
            "virt-launcher"
        );
        assert_eq!(
            fence["spec"]["podSelector"]["matchLabels"]["openshell.ai/sandbox-id"],
            "sbx-1"
        );
        // Egress allows only the supervisor's port, matched by the Service
        // selector (not hard-coded labels).
        assert_eq!(fence["spec"]["egress"][0]["ports"][0]["port"], 5500);
        assert_eq!(
            fence["spec"]["egress"][0]["to"][0]["podSelector"]["matchLabels"]["app.kubernetes.io/name"],
            "openshell-supervisor"
        );
        assert_eq!(
            fence["spec"]["egress"][0]["to"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
            "openshell"
        );
    }

    #[test]
    fn fence_carries_openshell_labels_for_cleanup() {
        let fence = rendered_fence();
        assert_eq!(
            fence["metadata"]["labels"]["openshell.ai/managed-by"],
            "openshell"
        );
        assert_eq!(
            fence["metadata"]["labels"]["openshell.ai/sandbox-id"],
            "sbx-1"
        );
        assert_eq!(fence["metadata"]["labels"]["openshell.ai/gateway-id"], "gw");
    }

    #[test]
    fn fence_name_is_derived_from_sandbox_id() {
        assert_eq!(fence_name("sbx-1"), "openshell-kubevirt-fence-sbx-1");
    }

    #[test]
    fn dedicated_fence_selects_only_this_sandboxes_supervisor_pod() {
        let fence = dedicated_fence();
        let policy_types = fence["spec"]["policyTypes"].as_array().unwrap();
        assert!(policy_types.contains(&serde_json::json!("Ingress")));
        assert!(policy_types.contains(&serde_json::json!("Egress")));
        // No ingress rules: deny-all ingress, same as the shared fence.
        assert!(fence["spec"]["ingress"].is_null());
        // The egress peer is a same-namespace podSelector (no
        // namespaceSelector): only this sandbox's dedicated supervisor Pod.
        let to = &fence["spec"]["egress"][0]["to"][0];
        assert!(
            to.get("namespaceSelector").is_none(),
            "a dedicated supervisor lives in the sandbox namespace: {to}"
        );
        assert_eq!(
            to["podSelector"]["matchLabels"]["openshell.ai/boundary-pair"],
            "sbx-1"
        );
        assert_eq!(
            to["podSelector"]["matchLabels"]["openshell.ai/boundary-role"],
            "supervisor"
        );
        assert_eq!(fence["spec"]["egress"][0]["ports"][0]["port"], 5500);
    }

    #[test]
    fn control_ingress_scopes_the_boundary_port_to_the_supervisor_pod() {
        // L2: only this pair's supervisor Pod accepts boundary-port
        // connections, and the policy carries no egress rules — the
        // virt-launcher never accepts boundary-port inbound, and its
        // egress allowance is the fence's job.
        let policy = render_control_ingress("openshell-e2e-ns", "sbx-1", "sbx-1", 5500);
        assert_eq!(
            policy["spec"]["podSelector"]["matchLabels"]["openshell.ai/boundary-role"],
            "supervisor",
            "the policy must select only the supervisor role"
        );
        assert_eq!(
            policy["spec"]["podSelector"]["matchLabels"]["openshell.ai/boundary-pair"],
            "sbx-1"
        );
        let policy_types = policy["spec"]["policyTypes"].as_array().unwrap();
        assert_eq!(policy_types, &vec![serde_json::json!("Ingress")]);
        assert!(policy["spec"]["egress"].is_null());
        let ingress = &policy["spec"]["ingress"][0];
        assert_eq!(
            ingress["from"][0]["podSelector"]["matchLabels"]["openshell.ai/boundary-role"],
            "workload",
            "only this pair's workload role may connect"
        );
        assert_eq!(ingress["ports"][0]["port"], 5500);
        assert_eq!(
            policy["metadata"]["labels"]["openshell.ai/sandbox-id"],
            "sbx-1"
        );
        assert_eq!(
            control_ingress_name("sbx-1"),
            "os-control-sbx-1",
            "the same name the pod path's control policy uses, so a namespace \
             never carries both shapes"
        );
    }

    #[test]
    fn dedicated_and_shared_fence_specs_differ() {
        // The two topologies render different egress targets, so a fence
        // created for one topology fails the other's start-time
        // verification (spec drift).
        let dedicated = dedicated_fence();
        let shared = rendered_fence();
        assert_ne!(dedicated["spec"], shared["spec"]);
    }

    #[test]
    fn check_fence_rejects_deleted() {
        let expected = ExpectedFence::from_rendered(rendered_fence(), "uid-1".into(), "1".into());
        let err = check_fence(None, &expected, "sbx-1").unwrap_err();
        assert!(err.contains("was deleted"));
    }

    #[test]
    fn check_fence_rejects_replaced_uid() {
        let expected = ExpectedFence::from_rendered(rendered_fence(), "uid-1".into(), "1".into());
        let replaced = observed("uid-2", "1", rendered_fence()["spec"].clone());
        let err = check_fence(Some(&replaced), &expected, "sbx-1").unwrap_err();
        assert!(err.contains("was replaced"));
    }

    #[test]
    fn check_fence_rejects_spec_drift() {
        let expected = ExpectedFence::from_rendered(rendered_fence(), "uid-1".into(), "1".into());
        let mut drifted = rendered_fence();
        drifted["spec"]["egress"][0]["ports"][0]["port"] = serde_json::json!(9999);
        let observed_drift = observed("uid-1", "1", drifted["spec"].clone());
        let err = check_fence(Some(&observed_drift), &expected, "sbx-1").unwrap_err();
        assert!(err.contains("spec drifted"));
    }

    #[test]
    fn check_fence_accepts_rv_only_change() {
        let expected = ExpectedFence::from_rendered(rendered_fence(), "uid-1".into(), "1".into());
        let rv_changed = observed("uid-1", "42", rendered_fence()["spec"].clone());
        let result =
            check_fence(Some(&rv_changed), &expected, "sbx-1").expect("RV-only change must pass");
        assert_eq!(result.resource_version, "42");
    }

    #[test]
    fn check_fence_accepts_unchanged() {
        let expected = ExpectedFence::from_rendered(rendered_fence(), "uid-1".into(), "1".into());
        let unchanged = observed("uid-1", "1", rendered_fence()["spec"].clone());
        check_fence(Some(&unchanged), &expected, "sbx-1").expect("unchanged must pass");
    }
}

// ---------------------------------------------------------------------------
// Cloud-init delivery
// ---------------------------------------------------------------------------

use base64::Engine as _;

/// Keys in the cloudInitNoCloud `userData` payload.
///
/// Carrying the boundary bootstrap artifacts (base64-encoded so the
/// shell-sourceable format is preserved). No gateway material appears in
/// the payload — no sandbox token, no gateway endpoint, no JWT.
pub const PAYLOAD_BOUNDARY_CONFIG: &str = "OPENSHELL_BOUNDARY_CONFIG_B64";
pub const PAYLOAD_BOUNDARY_CERTIFICATE: &str = "OPENSHELL_BOUNDARY_CERTIFICATE_B64";
pub const PAYLOAD_BOUNDARY_PRIVATE_KEY: &str = "OPENSHELL_BOUNDARY_PRIVATE_KEY_B64";
/// The workload uid/gid the boundary runs as (launch-capability-free args).
pub const PAYLOAD_WORKLOAD_UID: &str = "OPENSHELL_WORKLOAD_UID";
pub const PAYLOAD_WORKLOAD_GID: &str = "OPENSHELL_WORKLOAD_GID";

/// Render the cloudInitNoCloud `userData` payload.
///
/// Delivers the boundary bootstrap artifacts to the guest. The payload is
/// shell-sourceable; the guest init decodes the base64 values, stages
/// the files at the paths written in the `BoundaryConfig`, and runs
/// `openshell-sandbox launch-capability-free <uid> <gid> <config-path>`.
/// The uid/gid are derived from the same `ResolvedWorkloadIdentity` the
/// boundary config carries, so they cannot mismatch.
///
/// Assert (checkpoint 3): no gateway endpoint, no sandbox token, no JWT.
#[must_use]
pub fn render_guest_payload(
    artifacts: &crate::sandbox_runtime::BoundaryBootstrapArtifacts,
    workload_identity: &ResolvedWorkloadIdentity,
) -> String {
    let uid = workload_identity.uid;
    let gid = workload_identity.gid;
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    format!(
        "{PAYLOAD_BOUNDARY_CONFIG}={}\n\
         {PAYLOAD_BOUNDARY_CERTIFICATE}={}\n\
         {PAYLOAD_BOUNDARY_PRIVATE_KEY}={}\n\
         {PAYLOAD_WORKLOAD_UID}={uid}\n\
         {PAYLOAD_WORKLOAD_GID}={gid}\n",
        b64(&artifacts.config_json),
        b64(&artifacts.certificate_pem),
        b64(&artifacts.private_key_pem),
    )
}

#[cfg(test)]
mod payload_tests {
    use super::*;

    #[test]
    fn guest_payload_carries_no_gateway_material() {
        let artifacts = crate::sandbox_runtime::BoundaryBootstrapArtifacts {
            config_json: br#"{"boundary_id":"sbx","generation":"g1"}"#.to_vec(),
            certificate_pem: b"-----BEGIN CERTIFICATE-----".to_vec(),
            private_key_pem: b"-----BEGIN PRIVATE KEY-----".to_vec(),
        };
        let identity = ResolvedWorkloadIdentity::new(
            10001,
            10001,
            Vec::new(),
            "test".to_string(),
            "test".to_string(),
        )
        .unwrap();
        let payload = render_guest_payload(&artifacts, &identity);
        // No gateway material (checkpoint 3).
        assert!(!payload.contains("OPENSHELL_ENDPOINT"));
        assert!(!payload.contains("OPENSHELL_SANDBOX_TOKEN"));
        assert!(!payload.contains("OPENSHELL_SANDBOX_TOKEN_FILE"));
        assert!(!payload.contains("OPENSHELL_ENDPOINT="));
        assert!(!payload.contains("grpc_endpoint"));
        // The boundary artifacts and identity are present.
        assert!(payload.contains(PAYLOAD_BOUNDARY_CONFIG));
        assert!(payload.contains(PAYLOAD_BOUNDARY_CERTIFICATE));
        assert!(payload.contains(PAYLOAD_BOUNDARY_PRIVATE_KEY));
        assert!(payload.contains("OPENSHELL_WORKLOAD_UID=10001"));
        assert!(payload.contains("OPENSHELL_WORKLOAD_GID=10001"));
    }

    #[test]
    fn guest_payload_is_shell_sourceable() {
        let artifacts = crate::sandbox_runtime::BoundaryBootstrapArtifacts {
            config_json: b"{}".to_vec(),
            certificate_pem: b"cert".to_vec(),
            private_key_pem: b"key".to_vec(),
        };
        let identity = ResolvedWorkloadIdentity::new(
            1000,
            1000,
            Vec::new(),
            "test".to_string(),
            "test".to_string(),
        )
        .unwrap();
        let payload = render_guest_payload(&artifacts, &identity);
        // Every line is KEY=VALUE (base64 has no spaces or shell metachars).
        for line in payload.lines() {
            assert!(line.contains('='), "line must be KEY=VALUE: {line}");
            let value = line.split_once('=').unwrap().1;
            assert!(
                !value.contains(' ') && !value.contains('\'') && !value.contains('"'),
                "value must be shell-safe: {value}"
            );
        }
    }

    pub(super) fn test_launch_authentication() -> SandboxLaunchAuthentication {
        use openshell_core::jwt::{
            CredentialEpoch, SecretJwt, SessionRotation, SessionVerificationKey,
            SupervisorAuthBundle,
        };
        SandboxLaunchAuthentication {
            supervisor: SupervisorAuthBundle {
                session_id: openshell_core::SandboxSessionId::new(),
                runtime_generation: openshell_core::sandbox_generation::SandboxGenerationId::parse(
                    "generation-1",
                )
                .unwrap(),
                session_rotation: SessionRotation::new(1).unwrap(),
                auth_epoch: CredentialEpoch::new(1).unwrap(),
                gateway_token: SecretJwt::parse("gateway.token.value").unwrap(),
                gateway_expires_at: i64::MAX,
                sandbox_token: SecretJwt::parse("sandbox.token.value").unwrap(),
                sandbox_expires_at: i64::MAX,
                ssh_host_private_key: None,
                traces_otlp_headers: None,
                ocsf_otlp_headers: None,
                agent_otlp_headers: None,
                otlp_tls: Vec::new(),
                traces_otlp_tls: None,
                ocsf_otlp_tls: None,
                agent_otlp_tls: None,
            },
            gateway_id: "gateway-test".to_string(),
            verification_keys: vec![SessionVerificationKey {
                key_id: "test-key".to_string(),
                public_key_pem: b"public-key".to_vec(),
            }],
        }
    }

    #[test]
    fn decoded_guest_payload_carries_no_token_values() {
        // Decode the real rendered payload (the guest init's view) and
        // prove no gateway material survives into it: no token values, no
        // JWT fragments, no gateway endpoint — only the boundary config,
        // session TLS, and workload uid/gid.
        let auth = test_launch_authentication();
        let target = KubeVirtSupervisorTarget::Dedicated {
            authority: "os-supervisor-sbx-1.openshell-e2e-ns.svc:5500".to_string(),
            address: "10.43.5.10:5500".parse().unwrap(),
            supervisor_pod_uid: "supervisor-pod-uid-1".to_string(),
            pod_selector: BTreeMap::new(),
            port: 5500,
        };
        let bootstrap = render_kubevirt_bootstrap(
            &auth,
            "sbx-1",
            "sandbox-1",
            "vm-uid-1",
            "openshell/sandbox-vm:test",
            "np-uid-1",
            "1945",
            serde_json::json!({}),
            &target,
            10001,
            10001,
            crate::config::KubeVirtWorkloadMode::Sandboxed,
        )
        .expect("render");
        let decoded = bootstrap
            .guest_payload
            .lines()
            .filter(|line| line.starts_with("OPENSHELL_BOUNDARY_"))
            .filter_map(|line| line.split_once('=').map(|(_, value)| value))
            .map(|value| {
                String::from_utf8(
                    base64::engine::general_purpose::STANDARD
                        .decode(value)
                        .expect("boundary artifact values are base64"),
                )
                .expect("boundary artifacts are UTF-8")
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!decoded.contains("gateway.token.value"));
        assert!(!decoded.contains("sandbox.token.value"));
        assert!(!decoded.contains("172.18.0.1"));
        assert!(!decoded.contains("grpc_endpoint"));
        assert!(!decoded.contains("18085"));
        // The boundary artifacts themselves are present: the config (with
        // the gateway's public verification key — public material the
        // boundary needs) and the session certificate.
        assert!(decoded.contains("boundary_id"));
        assert!(decoded.contains("public-key"));
        assert!(decoded.contains("BEGIN CERTIFICATE"));
    }

    /// W3: the rendered descriptor's TLS must be the session material's
    /// `server_name` and `trust_anchor_pem` verbatim — the same fields the
    /// pod path passes to `SandboxTlsClientConfig`. The trust anchor is
    /// the session CA (a distinct certificate from the leaf the guest
    /// presents), and it must be non-empty PEM.
    #[test]
    fn descriptor_tls_uses_session_material_verbatim() {
        let auth = test_launch_authentication();
        let session_id = auth.supervisor.session_id;
        let supervisor = fence_tests::supervisor();
        let target = KubeVirtSupervisorTarget::Shared {
            authority: "openshell-supervisor.openshell.svc:5500".to_string(),
            address: "10.43.0.10:5500".parse().unwrap(),
            route: "route-1".to_string(),
            namespace: "openshell".to_string(),
            pod_selector: BTreeMap::new(),
            port: 5500,
        };
        let _ = supervisor;
        let bootstrap = render_kubevirt_bootstrap(
            &auth,
            "sbx-1",
            "sandbox-1",
            "vm-uid-1",
            "openshell/sandbox-vm:test",
            "np-uid-1",
            "1945",
            serde_json::json!({}),
            &target,
            10001,
            10001,
            crate::config::KubeVirtWorkloadMode::Sandboxed,
        )
        .expect("render");

        let tls = &bootstrap.runtime_descriptor.tls;
        // server_name is exactly what generate_sandbox_tls_material assigns
        // for this session (sandbox.<session_id>.openshell.internal).
        assert_eq!(
            tls.server_name,
            format!("sandbox.{session_id}.openshell.internal"),
            "server_name must be the session material's, verbatim"
        );
        // trust_anchor_pem is the session CA — non-empty certificate PEM.
        assert!(
            !tls.trust_anchor_pem.trim().is_empty(),
            "trust anchor must not be empty"
        );
        assert!(
            tls.trust_anchor_pem.contains("BEGIN CERTIFICATE"),
            "trust anchor must be certificate PEM: {}",
            tls.trust_anchor_pem
        );

        // The trust anchor is the CA, distinct from the leaf certificate
        // the guest presents (the payload's tls.crt): anchoring on the
        // chain would break the supervisor's verification.
        let payload = &bootstrap.guest_payload;
        let cert_line = payload
            .lines()
            .find(|line| line.starts_with(PAYLOAD_BOUNDARY_CERTIFICATE))
            .expect("payload carries the boundary certificate");
        let cert_b64 = cert_line.split_once('=').unwrap().1;
        let cert_pem = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(cert_b64)
                .expect("certificate decodes"),
        )
        .expect("certificate is UTF-8");
        assert_ne!(
            tls.trust_anchor_pem, cert_pem,
            "trust anchor must be the session CA, not the leaf certificate chain"
        );
    }
}

// ---------------------------------------------------------------------------
// Driver wiring: boundary bootstrap for create and start
// ---------------------------------------------------------------------------

use crate::sandbox_runtime::{boundary_launch_inputs, render_boundary_bootstrap};
use openshell_core::jwt::SandboxLaunchAuthentication;

/// Everything the driver needs to render one generation's boundary
/// bootstrap: the guest payload (cloud-init userData) and the fence
/// expectation (for the start-path re-check).
pub struct KubeVirtBootstrap {
    /// The shell-sourceable cloud-init userData delivering the boundary
    /// artifacts to the guest.
    pub guest_payload: String,
    /// The fence UID/resourceVersion the evidence was rendered against.
    /// On start, the driver re-reads the fence and compares.
    pub fence: ExpectedFence,
    /// The runtime descriptor for the shared supervisor's instance
    /// registration (W4: `shared_instance_secret`). Its `tls` is the
    /// session material's `server_name`/`trust_anchor_pem` verbatim.
    pub runtime_descriptor: SandboxRuntimeDescriptor,
}

/// Render one generation's `KubeVirt` boundary bootstrap. Used by both
/// create (initial) and start (re-render for the new generation).
///
/// The caller provides the launch authentication (from the gateway), the VM's
/// identity, the observed fence state, and the shared supervisor endpoint.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::similar_names)]
pub fn render_kubevirt_bootstrap(
    launch_authentication: &SandboxLaunchAuthentication,
    sandbox_id: &str,
    sandbox_name: &str,
    vm_uid: &str,
    guest_image: &str,
    fence_uid: &str,
    fence_resource_version: &str,
    fence_spec: serde_json::Value,
    target: &KubeVirtSupervisorTarget,
    workload_uid: u32,
    workload_gid: u32,
    workload_mode: crate::config::KubeVirtWorkloadMode,
) -> Result<KubeVirtBootstrap, String> {
    let launch_inputs = boundary_launch_inputs(launch_authentication)
        .map_err(|error| format!("boundary launch inputs: {error}"))?;

    let workload_identity = if workload_mode == crate::config::KubeVirtWorkloadMode::Root {
        // The privileged VM class runs the workload as root by design
        // (kernel separation is the boundary); the standard constructor
        // refuses UID/GID zero, which is the right invariant for every
        // other workload.
        ResolvedWorkloadIdentity::new_privileged(
            "kubevirt-config".to_string(),
            format!("sandbox:{vm_uid}"),
        )
    } else {
        ResolvedWorkloadIdentity::new(
            workload_uid,
            workload_gid,
            Vec::new(),
            "kubevirt-config".to_string(),
            format!("sandbox:{vm_uid}"),
        )
    }
    .map_err(|error| format!("workload identity: {error}"))?;

    let spec = KubeVirtBoundarySpec {
        boundary_id: sandbox_id.to_string(),
        generation: launch_authentication
            .supervisor
            .runtime_generation
            .to_string(),
        session_id: launch_inputs.session_id,
        session_rotation: launch_inputs.session_rotation,
        auth_epoch: launch_inputs.auth_epoch,
        gateway_id: launch_inputs.gateway_id,
        verification_keys: launch_inputs.verification_keys,
        vm_uid: vm_uid.to_string(),
        image_identity: guest_image.to_string(),
        workload_mode,
        network_policy_uid: fence_uid.to_string(),
        network_policy_resource_version: fence_resource_version.to_string(),
        // The supervisor target carries the topology: the per-sandbox
        // Service of a dedicated supervisor Pod, or the shared supervisor's
        // Service plus this sandbox's route handle.
        supervisor: target.clone(),
        // W3: the supervisor's TLS client config (how it authenticates the
        // boundary). The trust anchor is the session CA (from
        // generate_sandbox_tls_material, embedded in the certificate chain);
        // the server_name is the sandbox DNS name it assigned to the
        // session certificate.
        supervisor_tls: SandboxTlsClientConfig {
            server_name: launch_inputs.tls.server_name.clone(),
            trust_anchor_pem: launch_inputs.tls.trust_anchor_pem.clone(),
        },
        workload_identity: workload_identity.clone(),
        child_env: HashMap::new(),
    };
    let _ = sandbox_name;

    let provisioned = spec
        .provision()
        .map_err(|error| format!("KubeVirt boundary provisioning: {error}"))?;

    let bootstrap = render_boundary_bootstrap(&provisioned.boundary_config, &launch_inputs.tls)
        .map_err(|error| format!("boundary bootstrap rendering: {error}"))?;

    let guest_payload = render_guest_payload(&bootstrap, &workload_identity);

    let fence = ExpectedFence::from_rendered(
        fence_spec,
        fence_uid.to_string(),
        fence_resource_version.to_string(),
    );

    Ok(KubeVirtBootstrap {
        guest_payload,
        fence,
        runtime_descriptor: provisioned.runtime_descriptor,
    })
}

/// `ApiResource` for `NetworkPolicy` (shared with the fence functions).
pub fn fence_api_resource() -> kube::api::ApiResource {
    kube::api::ApiResource {
        group: "networking.k8s.io".to_string(),
        version: "v1".to_string(),
        api_version: "networking.k8s.io/v1".to_string(),
        kind: "NetworkPolicy".to_string(),
        plural: "networkpolicies".to_string(),
    }
}
