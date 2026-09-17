// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MXC provisioning for the common authenticated Sandbox Protocol.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;

use openshell_isolation_interface::contract::{
    BackendError, BinaryIdentity, DirectProxyConfiguration, OuterFenceGuarantees,
    ResolvedWorkloadIdentity,
};
use openshell_sandbox_backend::boundary_protocol::{
    BoundaryConfig, BoundaryListener, GatewayVerificationKey, SandboxRuntimeDescriptor,
    SandboxTlsClientConfig, SandboxTlsServerConfig, SandboxTransport,
};
use serde::Serialize;

#[derive(Serialize)]
struct MxcOuterFenceEvidence<'a> {
    generation: &'a str,
    containment: &'a str,
    default_deny_filesystem: bool,
    default_deny_egress: bool,
    loopback_proxy_only: bool,
    controller_loss_fails_closed: bool,
}

pub(crate) struct MxcBoundarySpec {
    pub boundary_id: String,
    pub generation: String,
    pub session_id: openshell_core::SandboxSessionId,
    pub session_rotation: openshell_core::jwt::SessionRotation,
    pub auth_epoch: openshell_core::jwt::CredentialEpoch,
    pub gateway_id: String,
    pub verification_keys: Vec<GatewayVerificationKey>,
    pub control_addr: SocketAddr,
    pub supervisor_tls: SandboxTlsClientConfig,
    pub sandbox_tls: SandboxTlsServerConfig,
    pub proxy_addr: SocketAddr,
    pub proxy_authorization: String,
    pub proxy_url: String,
    pub workload_binary: PathBuf,
    pub child_env: HashMap<String, String>,
}

pub(crate) struct MxcBoundaryProvisioning {
    pub boundary_config: BoundaryConfig,
    pub runtime_descriptor: SandboxRuntimeDescriptor,
}

impl MxcBoundarySpec {
    pub fn provision(self) -> Result<MxcBoundaryProvisioning, BackendError> {
        if !self.control_addr.ip().is_loopback()
            || !self.proxy_addr.ip().is_loopback()
            || self.control_addr.port() == 0
            || self.proxy_addr.port() == 0
        {
            return Err(BackendError::Descriptor(
                "MXC control and proxy listeners must use concrete loopback ports".to_string(),
            ));
        }
        let resource_digest = format!("mxc-processcontainer:{}", self.generation);
        // The common identity envelope is numeric for Unix backends. MXC binds
        // its AppContainer token through the source and resource digest while
        // using reserved nonzero numeric sentinels for the common fields.
        let workload_identity = ResolvedWorkloadIdentity::new(
            1,
            1,
            Vec::new(),
            "mxc-appcontainer".to_string(),
            resource_digest,
        )?;
        let resource_claims = BTreeMap::from([
            ("mxc.generation".to_string(), self.generation.clone()),
            (
                "mxc.appcontainer_profile".to_string(),
                self.boundary_id.clone(),
            ),
        ]);
        let evidence = serde_json::to_vec(&MxcOuterFenceEvidence {
            generation: &self.generation,
            containment: "process_container",
            default_deny_filesystem: true,
            default_deny_egress: true,
            loopback_proxy_only: true,
            controller_loss_fails_closed: true,
        })
        .map_err(|error| {
            BackendError::Descriptor(format!("encode MXC outer-fence evidence: {error}"))
        })?;
        let outer_fence = OuterFenceGuarantees::confirmed(&self.generation, &evidence)?;
        let direct_proxy = DirectProxyConfiguration {
            bind_addr: self.proxy_addr,
            authorization: self.proxy_authorization,
            binary_identity: BinaryIdentity {
                binary_path: self.workload_binary,
                binary_digest: None,
                ancestors: Vec::new(),
                cmdline_paths: Vec::new(),
            },
        };
        Ok(MxcBoundaryProvisioning {
            boundary_config: BoundaryConfig {
                boundary_id: self.boundary_id.clone(),
                generation: self.generation.clone(),
                session_id: self.session_id,
                session_rotation: self.session_rotation,
                auth_epoch: self.auth_epoch,
                gateway_id: self.gateway_id,
                verification_keys: self.verification_keys,
                listener: BoundaryListener::TlsTcp {
                    address: self.control_addr,
                    tls: self.sandbox_tls,
                },
                resource_claims: resource_claims.clone(),
                resource_claim_files: BTreeMap::new(),
                workload_identity: workload_identity.clone(),
                outer_fence: outer_fence.clone(),
                direct_proxy_url: Some(self.proxy_url),
                child_env: self.child_env,
            },
            runtime_descriptor: SandboxRuntimeDescriptor {
                boundary_id: self.boundary_id,
                generation: self.generation,
                session_id: self.session_id,
                workload_identity,
                transport: SandboxTransport::Tcp {
                    authority: self.control_addr.to_string(),
                    addresses: vec![self.control_addr],
                },
                tls: self.supervisor_tls,
                host_gateway_ip: Some(self.proxy_addr.ip()),
                direct_proxy: Some(direct_proxy),
                resource_claims,
                outer_fence,
            },
        })
    }
}
