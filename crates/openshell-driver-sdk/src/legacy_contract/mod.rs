// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The current, Rust-defined form of what a compute driver hands to the
//! supervisor and the sandbox boundary.
//!
//! # Legacy
//!
//! This module describes a format that is expected to be replaced by a
//! language-neutral specification. It exists so that drivers can stop depending
//! on `openshell-core` and `openshell-sandbox-backend` today. It accepts no new
//! fields and is removed when the replacement format has shipped and the
//! supported releases no longer read this one. See `rfc/` for the migration.
//!
//! The documents are serialized as JSON by their `serde` implementations.
//! Readers reject unknown fields, so a writer must not add any.

/// Stable isolation backend name implemented by `openshell-sandbox`. Reserved:
/// no externally registered backend may use it.
pub const BUILTIN_BACKEND_NAME: &str = "openshell-sandbox";

/// Resource claim set by compute drivers when the workload requests GPU access.
pub const GPU_RESOURCE_CLAIM: &str = "openshell.gpu";

/// Resource claim set when the runtime may retain supplementary groups in
/// addition to the image-derived workload identity.
pub const ALLOW_EXTRA_SUPPLEMENTARY_GROUPS_RESOURCE_CLAIM: &str =
    "openshell.identity.allow_extra_supplementary_groups";

/// Memory-backed parent used for supervisor CA material.
pub const SUPERVISOR_CA_RUNTIME_ROOT: &str = "/run/openshell-supervisor-ca";

/// Workload-visible directory for the supervisor's public HTTPS interception
/// certificate and combined trust bundle.
///
/// Keeping the material below the mount root lets runtimes that cannot assign
/// tmpfs ownership create this child as the unprivileged sandbox identity.
pub const SUPERVISOR_CA_RUNTIME_DIR: &str = "/run/openshell-supervisor-ca/material";

#[cfg(feature = "legacy-contract")]
pub mod boundary;
#[cfg(feature = "legacy-contract")]
pub mod identity;

#[cfg(feature = "legacy-contract")]
pub use boundary::*;
#[cfg(feature = "legacy-contract")]
pub use identity::*;
