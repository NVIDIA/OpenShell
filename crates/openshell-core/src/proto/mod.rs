// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generated protocol buffer code.
//!
//! This module re-exports the generated protobuf types and service definitions.

#![allow(unexpected_cfgs)]

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
    #[cfg(bazel)]
    include!(env!("OPENSHELL_PROTO_PATH"));

    #[cfg(not(bazel))]
    include!(concat!(env!("OUT_DIR"), "/openshell.rs"));
}

pub use self::generated::openshell::v1 as openshell;

// Cross-package references from packages nested under `openshell.*.v1` can be
// generated as `super::super::v1::*`. Keep that path available as an alias for
// the root `openshell.v1` package.
#[doc(hidden)]
pub mod v1 {
    pub use super::openshell::*;
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

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    unused_imports,
    unused_qualifications,
    rust_2018_idioms
)]
pub mod credentials {
    #[cfg(bazel)]
    pub use super::generated::openshell::credentials::v1;

    #[cfg(not(bazel))]
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/openshell.credentials.v1.rs"));
    }
}

pub mod test {
    pub use super::generated::openshell::test::v1::*;
}

pub mod inference {
    pub use super::generated::openshell::inference::v1;
}

pub mod middleware {
    pub use super::generated::openshell::middleware::v1;
}

pub mod gateway_interceptor {
    pub use super::generated::openshell::gateway_interceptor::v1;
}

pub use datamodel::v1::*;
pub use gateway_interceptor::v1::*;
pub use inference::v1::*;
pub use middleware::v1::*;
pub use openshell::*;
pub use sandbox::v1::*;
pub use test::ObjectForTest;
