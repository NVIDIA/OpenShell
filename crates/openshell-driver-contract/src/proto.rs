// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generated protocol buffer code for `sandbox_runtime.proto`.

/// Encoded `FileDescriptorSet` of the protos in this module, for implementers
/// that read or write the protobuf JSON form of the documents.
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(env!("OPENSHELL_DRIVER_CONTRACT_DESCRIPTOR_PATH"));

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    unused_imports,
    unused_qualifications,
    rust_2018_idioms
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/openshell.rs"));
}

pub mod sandbox_runtime {
    pub use super::generated::openshell::sandbox::runtime::v1;
}
