// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Generate only the public wire contracts; this example links no OpenShell crates.
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

pub const BACKEND: &str = "example-wasmtime";
pub const CAPABILITY: &str = "openshell.example.wasi-prototype";

pub fn metadata() -> PeerMetadata {
    PeerMetadata {
        protocol_version: Some(ProtocolVersion { major: 1, minor: 0 }),
        implementation_name: BACKEND.into(),
        implementation_version: env!("CARGO_PKG_VERSION").into(),
        supported_capabilities: vec![CAPABILITY.into()],
        required_capabilities: vec![CAPABILITY.into()],
    }
}
