// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Trusted launch metadata for an endpoint-registered Sandbox Protocol backend.

use std::collections::BTreeMap;
use std::net::IpAddr;

use openshell_core::SandboxSessionId;
use openshell_isolation_interface::contract::{
    BackendError, OuterFenceGuarantees, ResolvedWorkloadIdentity,
};
use serde::{Deserialize, Serialize};

use crate::boundary_protocol::{
    SandboxRuntimeDescriptor, SandboxTlsClientConfig, SandboxTransport,
};

/// Delivered by the trusted driver separately from its opaque backend payload.
/// Endpoint selection belongs to operator configuration, not launch data.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedLaunch {
    pub backend_name: String,
    pub sandbox_id: String,
    pub generation: String,
    pub session_id: SandboxSessionId,
    pub workload_identity: ResolvedWorkloadIdentity,
    pub tls: SandboxTlsClientConfig,
    #[serde(default)]
    pub host_gateway_ip: Option<IpAddr>,
    pub resource_claims: BTreeMap<String, String>,
    pub outer_fence: OuterFenceGuarantees,
}

impl DelegatedLaunch {
    /// Combine driver-owned identity and TLS with the operator-owned endpoint.
    pub fn runtime_descriptor(
        self,
        transport: SandboxTransport,
    ) -> Result<SandboxRuntimeDescriptor, BackendError> {
        validate_backend_name(&self.backend_name)?;
        let descriptor = SandboxRuntimeDescriptor {
            boundary_id: self.sandbox_id,
            generation: self.generation,
            session_id: self.session_id,
            workload_identity: self.workload_identity,
            transport,
            tls: self.tls,
            host_gateway_ip: self.host_gateway_ip,
            resource_claims: self.resource_claims,
            outer_fence: self.outer_fence,
        };
        crate::runtime::validate_runtime_coordinates(&descriptor)?;
        Ok(descriptor)
    }
}

/// Validate a non-reserved name for an endpoint-registered backend.
pub fn validate_backend_name(name: &str) -> Result<(), BackendError> {
    openshell_core::isolation_registration::validate_backend_name(name)
        .map_err(|error| BackendError::Descriptor(error.into()))
}
