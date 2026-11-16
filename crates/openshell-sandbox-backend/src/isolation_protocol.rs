// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Negotiated control contract and boundary routing for the Sandbox Protocol.

use openshell_core::extension_protocol::negotiate_metadata;
use openshell_core::proto::extension::v1::{PeerMetadata, ProtocolVersion};

use crate::backend_proto::OpenBoundaryRequest;
use crate::boundary_protocol::{BoundaryConfig, SandboxRuntimeDescriptor};
use crate::proto::{ExchangeFrame, exchange_frame::Payload};

pub const SANDBOX_PROTOCOL_CAPABILITY: &str = "openshell.sandbox.protocol";
/// Optional backend support for `SuspendBoundary` and `ResumeBoundary`.
pub const SUSPEND_RESUME_CAPABILITY: &str = "openshell.sandbox.suspend-resume";
/// Optional: the runtime accepts a gateway-granted supervisor takeover.
///
/// The grant travels on Attach (`supervisor_takeover`). A supervisor holding
/// one must not send it, or resume a workload it does not own, unless the
/// runtime advertises this; an older runtime keeps rejecting replacement
/// supervisors.
pub const SUPERVISOR_TAKEOVER_CAPABILITY: &str = "openshell.sandbox.supervisor-takeover";
const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion { major: 1, minor: 1 };

/// The built-in runtime supports fresh launches and supervisor takeover;
/// suspend/resume is optional.
#[must_use]
pub fn metadata(implementation: &str) -> PeerMetadata {
    let required = vec![SANDBOX_PROTOCOL_CAPABILITY.to_string()];
    PeerMetadata {
        protocol_version: Some(PROTOCOL_VERSION),
        implementation_name: implementation.to_string(),
        implementation_version: openshell_core::VERSION.to_string(),
        supported_capabilities: vec![
            SANDBOX_PROTOCOL_CAPABILITY.to_string(),
            SUPERVISOR_TAKEOVER_CAPABILITY.to_string(),
        ],
        required_capabilities: required,
    }
}

/// Supervisor metadata: the base contract is required, and the supervisor can
/// drive optional suspend/resume when a backend advertises it.
#[must_use]
pub fn supervisor_metadata(implementation: &str) -> PeerMetadata {
    let mut metadata = metadata(implementation);
    metadata
        .supported_capabilities
        .push(SUSPEND_RESUME_CAPABILITY.to_string());
    metadata
}

/// Use the shared extension rules: equal majors and both peers' requirements.
pub fn negotiate(local: &PeerMetadata, remote: Option<PeerMetadata>) -> Result<(), tonic::Status> {
    negotiate_peer(local, remote).map(drop)
}

/// Negotiate like [`negotiate`] and return the remote peer's normalized
/// metadata so callers can check its optional capabilities.
pub fn negotiate_peer(
    local: &PeerMetadata,
    remote: Option<PeerMetadata>,
) -> Result<PeerMetadata, tonic::Status> {
    negotiate_metadata("isolation", "sandbox-protocol", local, remote)
        .map_err(|error| tonic::Status::failed_precondition(error.to_string()))
}

/// Whether negotiated peer metadata advertises suspend/resume support.
#[must_use]
pub fn supports_suspend_resume(peer: &PeerMetadata) -> bool {
    peer.supported_capabilities
        .iter()
        .any(|capability| capability == SUSPEND_RESUME_CAPABILITY)
}

/// Check native driver coordinates against the protected runtime bootstrap.
///
/// The caller must first authenticate the bearer against the provisioned
/// sandbox and generation using `SandboxProtocolAuthenticator`.
/// This only opens a route; attach, confirm, and start retain their authority.
pub fn validate_open(
    request: &OpenBoundaryRequest,
    config: &BoundaryConfig,
) -> Result<(), tonic::Status> {
    if request.backend_name != crate::BACKEND_NAME
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
        || descriptor.provisioning_evidence != config.provisioning_evidence
    {
        return Err(tonic::Status::permission_denied(
            "driver descriptor does not match provisioned boundary",
        ));
    }
    Ok(())
}

#[must_use]
pub fn data_chunk(data: Vec<u8>) -> ExchangeFrame {
    ExchangeFrame {
        payload: Some(Payload::RelayData(data)),
    }
}

#[must_use]
pub fn exchange_frame(boundary_id: &str) -> ExchangeFrame {
    ExchangeFrame {
        payload: Some(Payload::BoundaryId(boundary_id.to_string())),
    }
}

/// Adapt a single typed frame for callers inspecting a local response.
pub fn chunk_data(chunk: ExchangeFrame) -> Result<Vec<u8>, tonic::Status> {
    let mut mode = match chunk.payload.as_ref() {
        Some(Payload::Request(_)) => crate::stream_adapter::Mode::Request,
        Some(Payload::Response(_)) => crate::stream_adapter::Mode::Response,
        Some(Payload::Stdin(_) | Payload::StdinClosed(_)) => crate::stream_adapter::Mode::Input,
        Some(Payload::Stdout(_) | Payload::Stderr(_) | Payload::Exit(_)) => {
            crate::stream_adapter::Mode::Output
        }
        Some(Payload::TcpOpenDecision(_)) => crate::stream_adapter::Mode::Decision,
        _ => crate::stream_adapter::Mode::Relay,
    };
    crate::stream_adapter::receive(&mut mode, chunk)
        .map_err(|error| tonic::Status::invalid_argument(error.to_string()))
}

/// A typed control request after the stream's boundary-binding frame.
pub fn request_chunk(
    request: &crate::boundary_protocol::RequestEnvelope,
) -> Result<ExchangeFrame, crate::boundary_protocol::FrameError> {
    use crate::protobuf::WireMessage;
    Ok(ExchangeFrame {
        payload: Some(Payload::Request(request.to_proto()?)),
    })
}

/// A typed control response, preserving the request's correlation ID.
pub fn response_chunk(
    response: &crate::boundary_protocol::ResponseEnvelope,
) -> Result<ExchangeFrame, crate::boundary_protocol::FrameError> {
    use crate::protobuf::WireMessage;
    Ok(ExchangeFrame {
        payload: Some(Payload::Response(response.to_proto()?)),
    })
}
