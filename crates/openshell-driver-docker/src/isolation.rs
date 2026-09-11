// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Docker provisioning for the shared authenticated boundary protocol.
//!
//! Docker owns only the container/socket topology and immutable OCI resource
//! claims. Lifecycle, process, network, identity, and wire behavior live in
//! `openshell-isolation-interface` and `openshell-sandbox`.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::PathBuf;

use openshell_isolation_interface::boundary_protocol::{
    BoundaryConfig, BoundaryListener, BoundaryTopology, GatewayVerificationKey,
    SandboxTlsClientConfig, SandboxTlsServerConfig, SandboxTransport,
};
use openshell_isolation_interface::contract::{DriverFenceEvidence, ResolvedWorkloadIdentity};

/// Driver-owned inputs that bind one Docker container to one boundary.
pub struct DockerBoundarySpec {
    pub boundary_id: String,
    pub generation: String,
    pub session_id: openshell_core::SandboxSessionId,
    pub gateway_id: String,
    pub verification_keys: Vec<GatewayVerificationKey>,
    pub container_id: String,
    pub image_identity: String,
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
    pub topology: BoundaryTopology,
}

impl DockerBoundarySpec {
    /// Produce both sides of the common protocol from the same immutable
    /// Docker coordinates so attach cannot bind a different container.
    #[must_use]
    pub fn provision(self) -> DockerBoundaryProvisioning {
        let resource_claims = BTreeMap::from([
            ("docker.container_id".to_string(), self.container_id),
            ("docker.image_identity".to_string(), self.image_identity),
        ]);
        let driver_fence = DriverFenceEvidence::Docker {
            container_id: resource_claims["docker.container_id"].clone(),
            network_mode: "none".to_string(),
            unexpected_networks: Vec::new(),
        };
        DockerBoundaryProvisioning {
            boundary_config: BoundaryConfig {
                boundary_id: self.boundary_id.clone(),
                generation: self.generation.clone(),
                session_id: self.session_id,
                gateway_id: self.gateway_id,
                verification_keys: self.verification_keys,
                listener: BoundaryListener::Unix {
                    socket_path: self.listener_socket,
                    tls: self.sandbox_tls,
                },
                resource_claims: resource_claims.clone(),
                resource_claim_files: BTreeMap::new(),
                workload_identity: self.workload_identity.clone(),
                driver_fence: driver_fence.clone(),
                child_env: self.child_env,
            },
            topology: BoundaryTopology {
                boundary_id: self.boundary_id,
                generation: self.generation,
                session_id: self.session_id,
                workload_identity: self.workload_identity,
                transport: SandboxTransport::Unix {
                    socket_path: self.control_socket,
                },
                tls: self.supervisor_tls,
                host_gateway_ip: self.host_gateway_ip,
                resource_claims,
                driver_fence,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioning_binds_container_and_image_claims() {
        let session_id = openshell_core::SandboxSessionId::new();
        let tls = openshell_isolation_interface::boundary_protocol::generate_sandbox_tls_material(
            session_id,
        )
        .unwrap();
        let provisioned = DockerBoundarySpec {
            boundary_id: "sandbox-1".to_string(),
            generation: "generation-1".to_string(),
            session_id,
            gateway_id: "gateway-1".to_string(),
            verification_keys: vec![GatewayVerificationKey {
                key_id: "key-1".to_string(),
                public_key_pem: "public-key".to_string(),
            }],
            container_id: "sha256:container".to_string(),
            image_identity: "sha256:image".to_string(),
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
        .provision();

        assert_eq!(
            provisioned.boundary_config.resource_claims,
            provisioned.topology.resource_claims
        );
        assert_eq!(
            provisioned.topology.resource_claims["docker.container_id"],
            "sha256:container"
        );
        assert_eq!(
            provisioned.boundary_config.driver_fence,
            provisioned.topology.driver_fence
        );
        assert!(
            provisioned
                .topology
                .driver_fence
                .validate_for_backend("docker")
                .is_ok()
        );
    }
}
