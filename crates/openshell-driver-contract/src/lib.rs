// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The documents a compute driver hands to the supervisor and the sandbox
//! boundary.
//!
//! The driver writes the runtime descriptor and the boundary configuration; the
//! supervisor and the sandbox boundary read and validate them. This crate is the
//! one place both sides depend on, so neither depends on the other's crate.
//!
//! - [`model`] has the types, with no I/O.
//! - [`write`] is the driver side. It is behind the `write` feature, so readers do
//!   not build the certificate generation code.
//! - [`read`] is the supervisor and sandbox side.
//!
//! The model types are also re-exported at the crate root.
//!
//! The encoding the types produce with `serde` is legacy: it accepts no new
//! fields and is removed when its replacement has shipped.

pub mod model;
pub mod read;
#[cfg(feature = "write")]
pub mod write;

pub use model::*;
pub use read::validate_resource_claims;
#[cfg(feature = "write")]
pub use write::generate_sandbox_tls_material;
