// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Narrow shared contract for `OpenShell` compute drivers.
//!
//! This crate holds the items that both core (the gateway, supervisor, and the
//! Kubernetes driver) and the desktop drivers depend on. `openshell-core`
//! re-exports every item defined here, so each item has exactly one definition.
//! It depends only on workspace crates and crates.io.

pub mod compute;
pub mod container_paths;
pub mod driver_mounts;
#[cfg(unix)]
pub mod e2fsprogs;
pub mod error;
pub mod extension_protocol;
#[cfg(unix)]
pub mod external_driver_socket;
pub mod image;
pub mod progress;
pub mod proto;
pub mod sandbox_env;
pub mod sandbox_generation;
pub mod sandbox_session;
pub mod time;

/// Build version string derived from git metadata.
///
/// For local builds this is computed by `build.rs` from the exact release tag
/// or the latest merged stable tag using the guess-next-dev scheme (e.g.
/// `0.0.4-dev.6+g2bf9969ab`). In Docker/CI builds where `.git` is absent, it
/// falls back to `CARGO_PKG_VERSION`, which the build pipeline already stamps.
pub const VERSION: &str = match option_env!("OPENSHELL_GIT_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

#[cfg(test)]
#[path = "../build_version.rs"]
mod build_version;
