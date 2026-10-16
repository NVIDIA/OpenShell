// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Backend RPC bindings are generated from the public wire contracts.
mod openshell {
    pub mod extension {
        pub mod v1 {
            tonic::include_proto!("openshell.extension.v1");
        }
    }
    pub mod sandbox {
        pub mod backend {
            pub mod v1 {
                tonic::include_proto!("openshell.sandbox.backend.v1");
            }
        }
        pub mod protocol {
            pub mod v1 {
                tonic::include_proto!("openshell.sandbox.protocol.v1");
            }
        }
    }
}
pub use openshell::extension::v1::{PeerMetadata, ProtocolVersion};
pub use openshell::sandbox::{backend::v1 as control, protocol::v1 as boundary};

pub const BACKEND: &str = "example-v8";
pub const CAPABILITY: &str = "openshell.sandbox.protocol";

pub fn metadata() -> PeerMetadata {
    PeerMetadata {
        protocol_version: Some(ProtocolVersion { major: 1, minor: 0 }),
        implementation_name: BACKEND.into(),
        implementation_version: env!("CARGO_PKG_VERSION").into(),
        supported_capabilities: vec![CAPABILITY.into()],
        required_capabilities: vec![CAPABILITY.into()],
    }
}

/// Read one length-prefixed control request across arbitrary gRPC fragments.
pub async fn read_request(
    input: &mut tonic::Streaming<boundary::BoundaryChunk>,
) -> Result<openshell_sandbox_backend::boundary_protocol::RequestEnvelope, tonic::Status> {
    use boundary::boundary_chunk::Payload;
    use openshell_sandbox_backend::boundary_protocol as wire;
    use tonic::Status;
    let mut bytes = Vec::new();
    loop {
        if bytes.len() >= 4 {
            let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
            if length == 0 || length > wire::MAX_CONTROL_FRAME_BYTES {
                return Err(Status::invalid_argument("invalid frame length"));
            }
            if bytes.len() >= 4 + length {
                return wire::decode_frame(&bytes[..4 + length])
                    .map_err(|_| Status::invalid_argument("invalid request frame"));
            }
        }
        let chunk = input
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("incomplete request"))?;
        let Some(Payload::Data(data)) = chunk.payload else {
            return Err(Status::invalid_argument("data frame required"));
        };
        if bytes.len() + data.len() > wire::MAX_CONTROL_FRAME_BYTES + 4 {
            return Err(Status::resource_exhausted("request too large"));
        }
        bytes.extend_from_slice(&data);
    }
}

pub fn data(bytes: Vec<u8>) -> boundary::BoundaryChunk {
    boundary::BoundaryChunk {
        payload: Some(boundary::boundary_chunk::Payload::Data(bytes)),
    }
}

pub fn response(
    request_id: String,
    response: openshell_sandbox_backend::boundary_protocol::Response,
) -> Result<boundary::BoundaryChunk, tonic::Status> {
    use openshell_sandbox_backend::boundary_protocol as wire;
    wire::encode_frame(&wire::ResponseEnvelope {
        request_id,
        response,
    })
    .map(data)
    .map_err(|_| tonic::Status::internal("encode response"))
}

pub fn stream_frame(channel: u8, payload: &[u8]) -> boundary::BoundaryChunk {
    let mut bytes = vec![channel];
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    data(bytes)
}
