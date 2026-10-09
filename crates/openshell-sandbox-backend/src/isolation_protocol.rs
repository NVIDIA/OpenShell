// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Negotiated control contract and boundary routing for the Sandbox Protocol.

use openshell_core::extension_protocol::negotiate_metadata;
use openshell_core::proto::extension::v1::{PeerMetadata, ProtocolVersion};

use crate::boundary_protocol::{BoundaryConfig, SandboxRuntimeDescriptor};
use crate::isolation_proto::OpenBoundaryRequest;
use crate::proto::{DelegatedBoundaryChunk, delegated_boundary_chunk::Payload};

pub const CONTRACT_CAPABILITY: &str = "openshell.isolation.contract";
const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };

/// The built-in runtime supports fresh launches; suspend/resume is optional.
#[must_use]
pub fn metadata(implementation: &str) -> PeerMetadata {
    let capabilities = vec![CONTRACT_CAPABILITY.to_string()];
    PeerMetadata {
        protocol_version: Some(PROTOCOL_VERSION),
        implementation_name: implementation.to_string(),
        implementation_version: openshell_core::VERSION.to_string(),
        supported_capabilities: capabilities.clone(),
        required_capabilities: capabilities,
    }
}

/// Use the shared extension rules: equal majors and both peers' requirements.
pub fn negotiate(local: &PeerMetadata, remote: Option<PeerMetadata>) -> Result<(), tonic::Status> {
    negotiate_metadata("isolation", "sandbox-protocol", local, remote)
        .map(drop)
        .map_err(|error| tonic::Status::failed_precondition(error.to_string()))
}

/// Check native driver coordinates against the protected runtime bootstrap.
/// This only opens a route; attach, confirm, and start retain their authority.
pub fn validate_open(
    request: &OpenBoundaryRequest,
    config: &BoundaryConfig,
) -> Result<(), tonic::Status> {
    if request.backend_name != crate::BACKEND_NAME
        || request.sandbox_id != config.boundary_id
        || request.generation_id != config.generation
        || request.session_id != config.session_id.to_string()
    {
        return Err(tonic::Status::permission_denied(
            "boundary launch identity does not match runtime",
        ));
    }
    let descriptor: SandboxRuntimeDescriptor =
        serde_json::from_slice(&request.driver_descriptor)
            .map_err(|_| tonic::Status::invalid_argument("invalid OpenShell runtime descriptor"))?;
    if descriptor.boundary_id != config.boundary_id
        || descriptor.generation != config.generation
        || descriptor.session_id != config.session_id
        || descriptor.workload_identity != config.workload_identity
        || descriptor.resource_claims != config.resource_claims
        || descriptor.outer_fence != config.outer_fence
    {
        return Err(tonic::Status::permission_denied(
            "driver descriptor does not match provisioned boundary",
        ));
    }
    Ok(())
}

#[must_use]
pub fn data_chunk(data: Vec<u8>) -> DelegatedBoundaryChunk {
    DelegatedBoundaryChunk {
        payload: Some(Payload::Data(data)),
    }
}

#[must_use]
pub fn boundary_chunk(boundary_id: &str) -> DelegatedBoundaryChunk {
    DelegatedBoundaryChunk {
        payload: Some(Payload::BoundaryId(boundary_id.to_string())),
    }
}

/// After binding, only data frames are legal in either stream direction.
pub fn chunk_data(chunk: DelegatedBoundaryChunk) -> Result<Vec<u8>, tonic::Status> {
    match chunk.payload {
        Some(Payload::Data(data)) => Ok(data),
        _ => Err(tonic::Status::invalid_argument(
            "only data frames are allowed after boundary binding",
        )),
    }
}
