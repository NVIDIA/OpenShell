// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows implementation of the in-MXC `OpenShell` sandbox boundary.
//!
//! The dedicated MXC sandbox executable calls this library. It implements Windows
//! process operations, containment confirmation, and loopback forwarding over
//! the shared authenticated Sandbox Protocol. It does not provision MXC, link
//! the compute driver, evaluate network policy, or embed the host supervisor.

#[cfg(target_os = "windows")]
pub mod audit;
#[cfg(target_os = "windows")]
pub mod backend;
#[cfg(target_os = "windows")]
mod identity;
#[cfg(target_os = "windows")]
pub mod launch;

/// Exact admission name for the MXC isolation backend; never a Linux fallback.
pub const BACKEND_NAME: &str = "openshell-mxc";
#[cfg(target_os = "windows")]
mod runtime;

/// Run the Windows boundary using driver-protected bootstrap material.
///
/// # Errors
///
/// Returns an error if bootstrap validation, authentication setup, or listener
/// initialization fails. Untrusted workloads start only after confirmation.
#[cfg(target_os = "windows")]
pub fn run(config_path: &std::path::Path) -> Result<(), String> {
    runtime::run_boundary(config_path)
}
