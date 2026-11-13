// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generated protocol buffer code for the compute-driver contract.
//!
//! Covers `compute_driver.proto` and the protos it imports. `openshell-core`
//! compiles the remaining protos and refers to these types by extern path.

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
