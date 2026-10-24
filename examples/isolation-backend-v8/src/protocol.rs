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

pub const BACKEND: &str = "js-sbx";
pub const CAPABILITY: &str = "openshell.sandbox.protocol";
pub const SUSPEND_RESUME: &str = "openshell.sandbox.suspend-resume";

pub fn metadata() -> PeerMetadata {
    PeerMetadata {
        protocol_version: Some(ProtocolVersion { major: 1, minor: 0 }),
        implementation_name: BACKEND.into(),
        implementation_version: env!("CARGO_PKG_VERSION").into(),
        supported_capabilities: vec![CAPABILITY.into(), SUSPEND_RESUME.into()],
        required_capabilities: vec![CAPABILITY.into()],
    }
}

// This example generates its own bindings. Bridge local Rust convenience types
// through protobuf encoding so it also exercises the independently generated API.
fn convert<T: prost::Message, U: prost::Message + Default>(value: T) -> Result<U, tonic::Status> {
    U::decode(value.encode_to_vec().as_slice())
        .map_err(|_| tonic::Status::invalid_argument("invalid protocol message"))
}

pub async fn read_request(
    input: &mut tonic::Streaming<boundary::ExchangeFrame>,
) -> Result<openshell_sandbox_backend::boundary_protocol::RequestEnvelope, tonic::Status> {
    use openshell_sandbox_backend::{boundary_protocol as wire, protobuf::WireMessage};
    use prost::Message;
    let chunk = input
        .message()
        .await?
        .ok_or_else(|| tonic::Status::invalid_argument("request required"))?;
    if chunk.encoded_len() > openshell_sandbox_backend::stream_adapter::MAX_MESSAGE_BYTES {
        return Err(tonic::Status::resource_exhausted("request too large"));
    }
    let Some(boundary::exchange_frame::Payload::Request(request)) = chunk.payload else {
        return Err(tonic::Status::invalid_argument("typed request required"));
    };
    wire::RequestEnvelope::from_proto(convert(request)?)
        .map_err(|error| tonic::Status::invalid_argument(error.to_string()))
}

pub async fn read_mediation_request(
    input: &mut tonic::Streaming<boundary::MediateFrame>,
) -> Result<openshell_sandbox_backend::boundary_protocol::RequestEnvelope, tonic::Status> {
    use openshell_sandbox_backend::{boundary_protocol as wire, protobuf::WireMessage};
    use prost::Message;
    let frame = input
        .message()
        .await?
        .ok_or_else(|| tonic::Status::invalid_argument("request required"))?;
    if frame.encoded_len() > openshell_sandbox_backend::stream_adapter::MAX_MESSAGE_BYTES {
        return Err(tonic::Status::resource_exhausted("request too large"));
    }
    let Some(boundary::mediate_frame::Payload::Request(request)) = frame.payload else {
        return Err(tonic::Status::invalid_argument("OpenMediation required"));
    };
    let request = wire::RequestEnvelope::from_proto(convert(request)?)
        .map_err(|error| tonic::Status::invalid_argument(error.to_string()))?;
    if !matches!(request.request, wire::Request::OpenMediation) {
        return Err(tonic::Status::invalid_argument(
            "only OpenMediation is allowed on Mediate",
        ));
    }
    Ok(request)
}

pub fn mediation_response(
    request_id: String,
    value: openshell_sandbox_backend::boundary_protocol::Response,
) -> Result<boundary::MediateFrame, tonic::Status> {
    let frame = response(request_id, value)?;
    let Some(boundary::exchange_frame::Payload::Response(value)) = frame.payload else {
        unreachable!();
    };
    Ok(boundary::MediateFrame {
        payload: Some(boundary::mediate_frame::Payload::Response(value)),
    })
}

pub fn response(
    request_id: String,
    response: openshell_sandbox_backend::boundary_protocol::Response,
) -> Result<boundary::ExchangeFrame, tonic::Status> {
    use openshell_sandbox_backend::{boundary_protocol as wire, protobuf::WireMessage};
    let value = wire::ResponseEnvelope {
        request_id,
        response,
    }
    .to_proto()
    .map_err(|error| tonic::Status::internal(error.to_string()))?;
    Ok(boundary::ExchangeFrame {
        payload: Some(boundary::exchange_frame::Payload::Response(convert(value)?)),
    })
}

pub fn stream_frame(channel: u8, payload: &[u8]) -> Result<boundary::ExchangeFrame, tonic::Status> {
    use boundary::exchange_frame::Payload;
    use openshell_sandbox_backend::{
        boundary_protocol as wire,
        protobuf::{self, WireMessage},
    };
    if payload.len() > wire::MAX_STREAM_FRAME_BYTES {
        return Err(tonic::Status::resource_exhausted("output frame too large"));
    }
    let payload = match channel {
        wire::STREAM_STDOUT => Payload::Stdout(payload.to_vec()),
        wire::STREAM_STDERR => Payload::Stderr(payload.to_vec()),
        wire::STREAM_EXIT => {
            let value = protobuf::decode::<wire::ExitStatusWire>(payload)
                .and_then(|v| v.to_proto())
                .map_err(|error| tonic::Status::internal(error.to_string()))?;
            Payload::Exit(convert(value)?)
        }
        _ => {
            return Err(tonic::Status::invalid_argument(
                "unsupported output channel",
            ));
        }
    };
    Ok(boundary::ExchangeFrame {
        payload: Some(payload),
    })
}
