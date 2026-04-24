// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenShell Core - shared library for OpenShell components.
//!
//! This crate provides:
//! - Protocol buffer definitions and generated code
//! - Configuration management
//! - Common error types
//! - Build version metadata

pub mod config;
pub mod error;
pub mod forward;
pub mod image;
pub mod inference;
pub mod net;
pub mod paths;
pub mod proto;
pub mod settings;

pub use config::{ComputeDriverKind, Config, TlsConfig};
pub use error::{ComputeDriverError, Error, Result};

/// Build version string derived from git metadata.
///
/// For local builds this is computed by `build.rs` via `git describe` using
/// the guess-next-dev scheme (e.g. `0.0.4-dev.6+g2bf9969`). In Docker/CI
/// builds where `.git` is absent, falls back to `CARGO_PKG_VERSION` which
/// is already set correctly by the build pipeline's sed patch.
pub const VERSION: &str = match option_env!("OPENSHELL_GIT_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};
