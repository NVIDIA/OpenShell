// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Backend RPC bindings generated from the public wire contracts, plus the
//! conversions between them and the shared typed boundary protocol.
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

use openshell_sandbox_backend::{boundary_protocol as wire, protobuf::WireMessage};

pub const BACKEND: &str = "sandbox-shim";
pub const CAPABILITY: &str = "openshell.sandbox.protocol";

pub fn metadata(substrate: &str) -> PeerMetadata {
    PeerMetadata {
        protocol_version: Some(ProtocolVersion { major: 1, minor: 0 }),
        implementation_name: format!("{BACKEND}/{substrate}"),
        implementation_version: env!("CARGO_PKG_VERSION").into(),
        supported_capabilities: vec![CAPABILITY.into()],
        required_capabilities: vec![CAPABILITY.into()],
    }
}

// The example generates its own bindings. Bridge the shared Rust wire types
// through protobuf encoding so it exercises the independently generated API.
fn convert<T: prost::Message, U: prost::Message + Default>(value: T) -> Result<U, tonic::Status> {
    U::decode(value.encode_to_vec().as_slice())
        .map_err(|_| tonic::Status::invalid_argument("invalid protocol message"))
}

fn check_size(message: &impl prost::Message) -> Result<(), tonic::Status> {
    if message.encoded_len() > openshell_sandbox_backend::stream_adapter::MAX_MESSAGE_BYTES {
        return Err(tonic::Status::resource_exhausted("request too large"));
    }
    Ok(())
}

pub async fn read_request(
    input: &mut tonic::Streaming<boundary::ExchangeFrame>,
) -> Result<wire::RequestEnvelope, tonic::Status> {
    let chunk = input
        .message()
        .await?
        .ok_or_else(|| tonic::Status::invalid_argument("request required"))?;
    check_size(&chunk)?;
    let Some(boundary::exchange_frame::Payload::Request(request)) = chunk.payload else {
        return Err(tonic::Status::invalid_argument("typed request required"));
    };
    wire::RequestEnvelope::from_proto(convert(request)?)
        .map_err(|error| tonic::Status::invalid_argument(error.to_string()))
}

pub async fn read_mediation_request(
    input: &mut tonic::Streaming<boundary::MediateFrame>,
) -> Result<wire::RequestEnvelope, tonic::Status> {
    let frame = input
        .message()
        .await?
        .ok_or_else(|| tonic::Status::invalid_argument("request required"))?;
    check_size(&frame)?;
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

fn response_proto(
    request_id: String,
    response: wire::Response,
) -> Result<boundary::ResponseEnvelope, tonic::Status> {
    let value = wire::ResponseEnvelope {
        request_id,
        response,
    }
    .to_proto()
    .map_err(|error| tonic::Status::internal(error.to_string()))?;
    convert(value)
}

pub fn response(
    request_id: String,
    response: wire::Response,
) -> Result<boundary::ExchangeFrame, tonic::Status> {
    Ok(boundary::ExchangeFrame {
        payload: Some(boundary::exchange_frame::Payload::Response(response_proto(
            request_id, response,
        )?)),
    })
}

pub fn mediation_response(
    request_id: String,
    response: wire::Response,
) -> Result<boundary::MediateFrame, tonic::Status> {
    Ok(boundary::MediateFrame {
        payload: Some(boundary::mediate_frame::Payload::Response(response_proto(
            request_id, response,
        )?)),
    })
}

pub fn exit_frame(status: wire::ExitStatusWire) -> Result<boundary::ExchangeFrame, tonic::Status> {
    let value = status
        .to_proto()
        .map_err(|error| tonic::Status::internal(error.to_string()))?;
    Ok(boundary::ExchangeFrame {
        payload: Some(boundary::exchange_frame::Payload::Exit(convert(value)?)),
    })
}

/// Encode a binary identity for a DNS query on the Mediate stream.
pub fn binary_identity(
    identity: &Result<
        openshell_isolation_interface::contract::BinaryIdentity,
        openshell_isolation_interface::contract::ResolveError,
    >,
) -> boundary::BinaryIdentity {
    use boundary::binary_identity::Result as R;
    let executable = |value: &openshell_isolation_interface::contract::ExecutableIdentity| {
        boundary::ExecutableIdentity {
            path: value.path.display().to_string(),
            digest: value.digest.map(|digest| digest.to_string()),
        }
    };
    boundary::BinaryIdentity {
        result: Some(match identity {
            Ok(identity) => R::Resolved(boundary::ResolvedBinaryIdentity {
                executable: Some(executable(&identity.executable)),
                ancestors: identity.ancestors.iter().map(executable).collect(),
                cmdline_paths: identity
                    .cmdline_paths
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect(),
            }),
            Err(error) => R::Failed(error.to_string()),
        }),
    }
}
