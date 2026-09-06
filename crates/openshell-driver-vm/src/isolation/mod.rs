// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! VM provisioning for the shared authenticated boundary protocol.
//!
//! This module deliberately contains no lifecycle, process, network, or wire
//! implementation. The driver chooses the host transport and binds immutable
//! VM claims; `openshell-isolation-interface` and `openshell-sandbox` provide
//! the common control and boundary behavior.

use openshell_isolation_interface::boundary_protocol::{
    BoundaryConfig, BoundaryListener, BoundaryServerTls, BoundaryTopology, BoundaryTransport,
};
use openshell_isolation_interface::contract::{
    BackendError, DriverFenceEvidence, ResolvedWorkloadIdentity,
};
use std::collections::{BTreeMap, HashMap};

/// Driver-owned inputs that bind one VM generation to one supervisor boundary.
pub struct VmBoundarySpec {
    pub boundary_id: String,
    pub bootstrap_token: String,
    pub generation: String,
    pub session_epoch: String,
    pub image_identity: String,
    pub transport: BoundaryTransport,
    pub sandbox_tls: BoundaryServerTls,
    pub control_port: u32,
    pub agent_uid: u32,
    pub agent_gid: u32,
    pub child_env: HashMap<String, String>,
}

/// The protected guest config and matching host descriptor for one VM.
pub struct VmBoundaryProvisioning {
    pub boundary_config: BoundaryConfig,
    pub topology: BoundaryTopology,
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
        let resource_claims = BTreeMap::from([
            ("vm.generation".to_string(), self.generation.clone()),
            ("vm.image_identity".to_string(), self.image_identity),
        ]);
        let driver_fence = DriverFenceEvidence::Vm {
            generation: self.generation.clone(),
            network_device_count: 0,
        };
        Ok(VmBoundaryProvisioning {
            boundary_config: BoundaryConfig {
                boundary_id: self.boundary_id.clone(),
                generation: self.generation.clone(),
                session_epoch: self.session_epoch.clone(),
                bootstrap_token: self.bootstrap_token.clone(),
                listener: BoundaryListener::Vsock {
                    control_port: self.control_port,
                    tls: self.sandbox_tls,
                },
                resource_claims: resource_claims.clone(),
                resource_claim_files: BTreeMap::new(),
                workload_identity: workload_identity.clone(),
                driver_fence: driver_fence.clone(),
                child_env: self.child_env,
            },
            topology: BoundaryTopology {
                boundary_id: self.boundary_id,
                generation: self.generation,
                session_epoch: self.session_epoch,
                workload_identity,
                transport: self.transport,
                // The host-side control process is the network broker, so
                // reserved host aliases terminate at its loopback address
                // after crossing the authenticated boundary channel.
                host_gateway_ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                resource_claims,
                driver_fence,
                bootstrap_token: self.bootstrap_token,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_isolation_interface::boundary_protocol::{
        BoundaryClientTls, generate_boundary_mutual_tls_material,
    };

    #[test]
    fn provisioning_binds_identical_resource_claims() {
        let material = generate_boundary_mutual_tls_material().unwrap();
        let provisioned = VmBoundarySpec {
            boundary_id: "sandbox-1".to_string(),
            bootstrap_token: "a".repeat(64),
            generation: "generation-1".to_string(),
            session_epoch: "epoch-1".to_string(),
            image_identity: "sha256:image".to_string(),
            transport: BoundaryTransport::Vsock {
                guest_cid: 42,
                control_port: 5500,
                tls: BoundaryClientTls {
                    server_name: material.server_name,
                    ca_certificate_pem: material.ca_certificate_pem,
                    certificate_chain_pem: material.supervisor_certificate_pem,
                    private_key_pem: material.supervisor_private_key_pem,
                },
            },
            sandbox_tls: BoundaryServerTls {
                certificate_chain_path: "/.openshell/state/sandbox.crt".into(),
                private_key_path: "/.openshell/state/sandbox.key".into(),
                client_ca_certificate_path: "/.openshell/state/client-ca.crt".into(),
            },
            control_port: 5500,
            agent_uid: 1000,
            agent_gid: 1000,
            child_env: HashMap::new(),
        }
        .provision()
        .unwrap();

        assert_eq!(
            provisioned.boundary_config.resource_claims,
            provisioned.topology.resource_claims
        );
        assert_eq!(
            provisioned.topology.resource_claims["vm.generation"],
            "generation-1"
        );
        assert_eq!(
            provisioned.topology.host_gateway_ip,
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            provisioned.boundary_config.driver_fence,
            provisioned.topology.driver_fence
        );
        assert!(
            provisioned
                .topology
                .driver_fence
                .validate_for_backend("vm")
                .is_ok()
        );
    }
}
