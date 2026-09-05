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
    BoundaryClientTls, BoundaryConfig, BoundaryListener, BoundaryServerTls, BoundaryTopology,
    BoundaryTransport,
};
use openshell_isolation_interface::contract::{DriverFenceEvidence, ResolvedWorkloadIdentity};

/// Driver-owned inputs that bind one Docker container to one boundary.
pub struct DockerBoundarySpec {
    pub boundary_id: String,
    pub bootstrap_token: String,
    pub generation: String,
    pub session_epoch: String,
    pub container_id: String,
    pub image_identity: String,
    pub listener_socket: PathBuf,
    pub control_socket: PathBuf,
    pub sandbox_tls: BoundaryServerTls,
    pub supervisor_tls: BoundaryClientTls,
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
                session_epoch: self.session_epoch.clone(),
                bootstrap_token: self.bootstrap_token.clone(),
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
                session_epoch: self.session_epoch,
                workload_identity: self.workload_identity,
                transport: BoundaryTransport::Unix {
                    socket_path: self.control_socket,
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

    #[test]
    fn provisioning_binds_container_and_image_claims() {
        let tls = openshell_isolation_interface::boundary_protocol::generate_boundary_mutual_tls_material()
            .unwrap();
        let provisioned = DockerBoundarySpec {
            boundary_id: "sandbox-1".to_string(),
            bootstrap_token: "a".repeat(64),
            generation: "generation-1".to_string(),
            session_epoch: "epoch-1".to_string(),
            container_id: "sha256:container".to_string(),
            image_identity: "sha256:image".to_string(),
            listener_socket: PathBuf::from("/run/openshell/boundary/control.sock"),
            control_socket: PathBuf::from("/host/control.sock"),
            sandbox_tls: BoundaryServerTls {
                certificate_chain_path: PathBuf::from("/run/openshell/boundary/server.crt"),
                private_key_path: PathBuf::from("/run/openshell/boundary/server.key"),
                client_ca_certificate_path: PathBuf::from("/run/openshell/boundary/client-ca.crt"),
            },
            supervisor_tls: BoundaryClientTls {
                server_name: tls.server_name,
                ca_certificate_pem: tls.ca_certificate_pem,
                certificate_chain_pem: tls.supervisor_certificate_pem,
                private_key_pem: tls.supervisor_private_key_pem,
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
