// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generated protocol buffer code for the compute-driver contract.
//!
//! Covers `compute_driver.proto`, `sandbox_runtime.proto`, and the protos they
//! import. `openshell-core` compiles the remaining protos and refers to these
//! types by extern path.

/// Encoded `FileDescriptorSet` of the protos in this module.
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!(env!("OPENSHELL_DRIVER_SDK_DESCRIPTOR_PATH"));

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

pub mod datamodel {
    pub use super::generated::openshell::datamodel::v1;
}

pub mod sandbox {
    pub use super::generated::openshell::sandbox::v1;
}

pub mod compute {
    pub use super::generated::openshell::compute::v1;
}

pub mod extension {
    pub use super::generated::openshell::extension::v1;
}

pub mod sandbox_runtime {
    pub use super::generated::openshell::sandbox::runtime::v1;
}
