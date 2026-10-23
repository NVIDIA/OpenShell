// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Docker provisioning for the shared authenticated boundary protocol.
//!
//! Docker owns only container placement, the protected socket, and immutable OCI resource
//! claims. Lifecycle, process, network, identity, and wire behavior live in
//! `openshell-isolation-interface` and `openshell-sandbox`.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::PathBuf;

use openshell_isolation_interface::contract::{
    BackendError, ProvisioningEvidence, ResolvedWorkloadIdentity,
};
use openshell_sandbox_backend::GPU_RESOURCE_CLAIM;
use openshell_sandbox_backend::boundary_protocol::{
    BoundaryConfig, BoundaryListener, GatewayVerificationKey, SandboxRuntimeDescriptor,
    SandboxTlsClientConfig, SandboxTlsServerConfig, SandboxTransport,
};
use serde::Serialize;

#[derive(Serialize)]
struct DockerOuterFenceEvidence<'a> {
    container_id: &'a str,
    network_mode: &'static str,
    unexpected_networks: &'a [String],
}

impl DockerOuterFenceEvidence<'_> {
    fn project(&self, generation: &str) -> Result<ProvisioningEvidence, BackendError> {
        if self.container_id.is_empty()
            || self.network_mode != "none"
            || !self.unexpected_networks.is_empty()
        {
            return Err(BackendError::Descriptor(
                "Docker provisioning evidence is incomplete".to_string(),
            ));
        }
        let encoded = serde_json::to_vec(self).map_err(|error| {
            BackendError::Descriptor(format!("encode Docker outer fence evidence: {error}"))
        })?;
        let projection = ProvisioningEvidence::from_enforcement_evidence(generation, &encoded)?;
        projection.validate(generation)?;
        Ok(projection)
    }
}

/// Bind the validated container fence to the generation being launched.
pub fn provisioning_evidence(
    container_id: &str,
    generation: &str,
) -> Result<ProvisioningEvidence, BackendError> {
    DockerOuterFenceEvidence {
        container_id,
        network_mode: "none",
        unexpected_networks: &[],
    }
    .project(generation)
}

/// Driver-owned inputs that bind one Docker container to one boundary.
pub struct DockerBoundarySpec {
    pub boundary_id: String,
    pub generation: String,
    pub session_id: openshell_core::SandboxSessionId,
    pub session_rotation: openshell_core::jwt::SessionRotation,
    pub auth_epoch: openshell_core::jwt::CredentialEpoch,
    pub gateway_id: String,
    pub verification_keys: Vec<GatewayVerificationKey>,
    pub container_id: String,
    pub image_identity: String,
    pub gpu_requested: bool,
    pub listener_socket: PathBuf,
    pub control_socket: PathBuf,
    pub sandbox_tls: SandboxTlsServerConfig,
    pub supervisor_tls: SandboxTlsClientConfig,
    pub host_gateway_ip: Option<IpAddr>,
    pub workload_identity: ResolvedWorkloadIdentity,
    pub child_env: HashMap<String, String>,
}

/// Protected container config and matching host descriptor.
pub struct DockerBoundaryProvisioning {
    pub boundary_config: BoundaryConfig,
    pub runtime_descriptor: SandboxRuntimeDescriptor,
}

impl DockerBoundarySpec {
    /// Produce both sides of the common protocol from the same immutable
    /// Docker coordinates so attach cannot bind a different container.
    pub fn provision(self) -> Result<DockerBoundaryProvisioning, BackendError> {
        let mut resource_claims = BTreeMap::from([
            ("docker.container_id".to_string(), self.container_id),
            ("docker.image_identity".to_string(), self.image_identity),
        ]);
        if self.gpu_requested {
            resource_claims.insert(GPU_RESOURCE_CLAIM.to_string(), "true".to_string());
        }
        let provisioning_evidence =
            provisioning_evidence(&resource_claims["docker.container_id"], &self.generation)?;
        Ok(DockerBoundaryProvisioning {
            boundary_config: BoundaryConfig {
                boundary_id: self.boundary_id.clone(),
                generation: self.generation.clone(),
                session_id: self.session_id,
                session_rotation: self.session_rotation,
                auth_epoch: self.auth_epoch,
                gateway_id: self.gateway_id,
                verification_keys: self.verification_keys,
                listener: BoundaryListener::RuntimeInitiatedUnix {
                    socket_path: self.listener_socket,
                    tls: self.sandbox_tls,
                },
                resource_claims: resource_claims.clone(),
                resource_claim_files: BTreeMap::new(),
                workload_identity: self.workload_identity.clone(),
                provisioning_evidence: provisioning_evidence.clone(),
                child_env: self.child_env,
                supervisor_recovery_timeout_secs: None,
            },
            runtime_descriptor: SandboxRuntimeDescriptor {
                boundary_id: self.boundary_id,
                generation: self.generation,
                session_id: self.session_id,
                workload_identity: self.workload_identity,
                transport: SandboxTransport::RuntimeInitiatedUnix {
                    socket_path: self.control_socket,
                },
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
        let unexpected_networks = vec!["bridge".to_string()];
        for evidence in [
            DockerOuterFenceEvidence {
                container_id: "",
                network_mode: "none",
                unexpected_networks: &[],
            },
            DockerOuterFenceEvidence {
                container_id: "container",
                network_mode: "bridge",
                unexpected_networks: &[],
            },
            DockerOuterFenceEvidence {
                container_id: "container",
                network_mode: "none",
                unexpected_networks: &unexpected_networks,
            },
        ] {
            assert!(evidence.project("generation-1").is_err());
        }
    }

    #[test]
    fn provisioning_binds_container_and_image_claims() {
        let session_id = openshell_core::SandboxSessionId::new();
        let tls =
            openshell_sandbox_backend::boundary_protocol::generate_sandbox_tls_material(session_id)
                .unwrap();
        let provisioned = DockerBoundarySpec {
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
            container_id: "sha256:container".to_string(),
            image_identity: "sha256:image".to_string(),
            gpu_requested: true,
            listener_socket: PathBuf::from("/run/openshell/boundary/control.sock"),
            control_socket: PathBuf::from("/host/control.sock"),
            sandbox_tls: SandboxTlsServerConfig {
                certificate_chain_path: PathBuf::from("/run/openshell/boundary/server.crt"),
                private_key_path: PathBuf::from("/run/openshell/boundary/server.key"),
            },
            supervisor_tls: SandboxTlsClientConfig {
                server_name: tls.server_name,
                trust_anchor_pem: tls.trust_anchor_pem,
            },
            host_gateway_ip: Some(IpAddr::from([127, 0, 0, 1])),
            workload_identity: ResolvedWorkloadIdentity::new(
                1000,
                1000,
                Vec::new(),
                "image".to_string(),
                "sha256:image".to_string(),
            )
            .unwrap(),
            child_env: HashMap::new(),
        }
        .provision()
        .unwrap();

        assert_eq!(
            provisioned.boundary_config.resource_claims,
            provisioned.runtime_descriptor.resource_claims
        );
        assert_eq!(
            provisioned.runtime_descriptor.resource_claims["docker.container_id"],
            "sha256:container"
        );
        assert_eq!(
            provisioned.runtime_descriptor.resource_claims[GPU_RESOURCE_CLAIM],
            "true"
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
}
