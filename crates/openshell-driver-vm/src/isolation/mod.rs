// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! VM provisioning for the shared authenticated boundary protocol.
//!
//! This module deliberately contains no lifecycle, process, network, or wire
//! implementation. The driver chooses the host transport and binds immutable
//! VM claims; `openshell-isolation-interface` and `openshell-sandbox` provide
//! the common control and boundary behavior.

use openshell_isolation_interface::contract::{
    BackendError, OuterFenceGuarantee, OuterFenceGuarantees, ResolvedWorkloadIdentity,
};
use openshell_sandbox_backend::GPU_RESOURCE_CLAIM;
use openshell_sandbox_backend::boundary_protocol::{
    BoundaryConfig, BoundaryListener, GatewayVerificationKey, SandboxRuntimeDescriptor,
    SandboxTlsClientConfig, SandboxTlsServerConfig, SandboxTransport,
};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

#[derive(Serialize)]
struct VmOuterFenceEvidence<'a> {
    generation: &'a str,
    network_device_count: u32,
}

impl VmOuterFenceEvidence<'_> {
    fn project(&self) -> Result<OuterFenceGuarantees, BackendError> {
        if self.generation.is_empty() {
            return Err(BackendError::Descriptor(
                "VM outer fence evidence is incomplete".to_string(),
            ));
        }
        let established = (self.network_device_count == 0).then_some([
            // A guest with no NIC has no kernel network path. Closing the
            // supervisor-owned channel revokes access, and controller loss
            // cannot introduce a device.
            OuterFenceGuarantee::DefaultDenyEgress,
            OuterFenceGuarantee::NoUnmanagedEgressPath,
            OuterFenceGuarantee::RevocationVerified,
            OuterFenceGuarantee::ControllerLossFailsClosed,
        ]);
        let encoded = serde_json::to_vec(self).map_err(|error| {
            BackendError::Descriptor(format!("encode VM outer fence evidence: {error}"))
        })?;
        let projection = OuterFenceGuarantees::from_enforcement_evidence(
            self.generation,
            established.into_iter().flatten(),
            &encoded,
        )?;
        projection.validate(self.generation)?;
        Ok(projection)
    }
}

/// Driver-owned inputs that bind one VM generation to one supervisor boundary.
pub struct VmBoundarySpec {
    pub boundary_id: String,
    pub generation: String,
    pub session_id: openshell_core::SandboxSessionId,
    pub session_rotation: openshell_core::jwt::SessionRotation,
    pub auth_epoch: openshell_core::jwt::CredentialEpoch,
    pub gateway_id: String,
    pub verification_keys: Vec<GatewayVerificationKey>,
    pub image_identity: String,
    pub transport: SandboxTransport,
    pub supervisor_tls: SandboxTlsClientConfig,
    pub sandbox_tls: SandboxTlsServerConfig,
    pub control_port: u32,
    pub agent_uid: u32,
    pub agent_gid: u32,
    pub child_env: HashMap<String, String>,
    pub gpu_requested: bool,
}

/// The protected guest config and matching host descriptor for one VM.
pub struct VmBoundaryProvisioning {
    pub boundary_config: BoundaryConfig,
    pub runtime_descriptor: SandboxRuntimeDescriptor,
}

impl VmBoundarySpec {
    /// Produce both sides of the common protocol from one set of immutable
    /// driver inputs so their identity claims cannot drift.
    pub fn provision(self) -> Result<VmBoundaryProvisioning, BackendError> {
        let workload_identity = ResolvedWorkloadIdentity::new(
            self.agent_uid,
            self.agent_gid,
            Vec::new(),
            "vm-config".to_string(),
            self.image_identity.clone(),
        )?;
        let mut resource_claims = BTreeMap::from([
            ("vm.generation".to_string(), self.generation.clone()),
            ("vm.image_identity".to_string(), self.image_identity),
        ]);
        if self.gpu_requested {
            resource_claims.insert(GPU_RESOURCE_CLAIM.to_string(), "true".to_string());
        }
        let outer_fence = VmOuterFenceEvidence {
            generation: &self.generation,
            network_device_count: 0,
        }
        .project()?;
        Ok(VmBoundaryProvisioning {
            boundary_config: BoundaryConfig {
                boundary_id: self.boundary_id.clone(),
                generation: self.generation.clone(),
                session_id: self.session_id,
                session_rotation: self.session_rotation,
                auth_epoch: self.auth_epoch,
                gateway_id: self.gateway_id,
                verification_keys: self.verification_keys,
                listener: BoundaryListener::Vsock {
                    control_port: self.control_port,
                    tls: self.sandbox_tls,
                },
                resource_claims: resource_claims.clone(),
                resource_claim_files: BTreeMap::new(),
                cdi_context: None,
                workload_identity: workload_identity.clone(),
                outer_fence: outer_fence.clone(),
                child_env: self.child_env,
            },
            runtime_descriptor: SandboxRuntimeDescriptor {
                boundary_id: self.boundary_id,
                generation: self.generation,
                session_id: self.session_id,
                workload_identity,
                transport: self.transport,
                tls: self.supervisor_tls,
                // The host-side control process is the network broker, so
                // reserved host aliases terminate at its loopback address
                // after crossing the authenticated boundary channel.
                host_gateway_ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                resource_claims,
                outer_fence,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_sandbox_backend::boundary_protocol::{
        SandboxTlsClientConfig, SandboxTlsServerConfig, SandboxTransport,
        generate_sandbox_tls_material,
    };

    #[test]
    fn outer_fence_projection_rejects_each_missing_native_fact() {
        assert!(
            VmOuterFenceEvidence {
                generation: "",
                network_device_count: 0,
            }
            .project()
            .is_err()
        );
        assert!(
            VmOuterFenceEvidence {
                generation: "generation-1",
                network_device_count: 1,
            }
            .project()
            .is_err()
        );
    }

    #[test]
    fn provisioning_binds_identical_resource_claims() {
        for gpu_requested in [false, true] {
            assert_provisioning_claims(gpu_requested);
        }
    }

    fn assert_provisioning_claims(gpu_requested: bool) {
        let session_id = openshell_core::SandboxSessionId::new();
        let material = generate_sandbox_tls_material(session_id).unwrap();
        let provisioned = VmBoundarySpec {
            boundary_id: "sandbox-1".to_string(),
            generation: "generation-1".to_string(),
            session_id,
            session_rotation: openshell_core::jwt::SessionRotation::new(1).unwrap(),
            auth_epoch: openshell_core::jwt::CredentialEpoch::new(1).unwrap(),
            gateway_id: "gateway-1".to_string(),
            verification_keys: vec![GatewayVerificationKey {
                key_id: "key-1".to_string(),
                public_key_pem: "public-key".to_string(),
            }],
            image_identity: "sha256:image".to_string(),
            transport: SandboxTransport::Vsock {
                guest_cid: 42,
                port: 5500,
            },
            supervisor_tls: SandboxTlsClientConfig {
                server_name: material.server_name,
                trust_anchor_pem: material.trust_anchor_pem,
            },
            sandbox_tls: SandboxTlsServerConfig {
                certificate_chain_path: "/.openshell/state/sandbox.crt".into(),
                private_key_path: "/.openshell/state/sandbox.key".into(),
            },
            control_port: 5500,
            agent_uid: 1000,
            agent_gid: 1000,
            child_env: HashMap::new(),
            gpu_requested,
        }
        .provision()
        .unwrap();

        assert_eq!(
            provisioned.boundary_config.resource_claims,
            provisioned.runtime_descriptor.resource_claims
        );
        assert_eq!(
            provisioned
                .runtime_descriptor
                .resource_claims
                .get(GPU_RESOURCE_CLAIM)
                .map(String::as_str),
            gpu_requested.then_some("true")
        );
        assert_eq!(
            provisioned.runtime_descriptor.resource_claims["vm.generation"],
            "generation-1"
        );
        assert_eq!(
            provisioned.runtime_descriptor.host_gateway_ip,
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            provisioned.boundary_config.outer_fence,
            provisioned.runtime_descriptor.outer_fence
        );
        assert!(
            provisioned
                .runtime_descriptor
                .outer_fence
                .validate("generation-1")
                .is_ok()
        );
    }
}
