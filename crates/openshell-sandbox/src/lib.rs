// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Capability-free in-workload sandbox boundary.

pub mod boundary_exec;
pub mod boundary_io;
mod boundary_server;
pub mod child_env;
pub(crate) mod delegated;
#[cfg(unix)]
pub mod identity;
pub mod main_session;
pub mod managed_children;
#[cfg(target_os = "linux")]
mod network_broker;
pub mod process;
mod pty;
pub mod sandbox;

/// Results of actively qualifying the admitted workload runtime before the
/// sandbox consumes protected bootstrap material.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "qualification preserves independently exercised security results"
)]
pub struct RuntimeQualification {
    pub seccomp: openshell_isolation_interface::contract::SeccompEvidence,
    pub landlock_abi: u32,
    pub landlock_allow_deny: bool,
    pub udp_dns_round_trip: bool,
    pub tcp_dns_round_trip: bool,
    pub tcp_allow_round_trip: bool,
    pub tcp_deny_round_trip: bool,
}

/// Placeholder used when compiling the package on a non-Linux host.
///
/// The sandbox binary rejects execution on those hosts before constructing a
/// qualification, but retaining the type keeps the library API portable for
/// workspace-wide checks.
#[cfg(not(target_os = "linux"))]
#[derive(Clone, Copy, Debug)]
pub struct RuntimeQualification;

/// Run the authenticated boundary-local sandbox.
///
/// # Errors
///
/// Returns an error when the protected bootstrap is invalid or the boundary
/// listener cannot be established.
pub fn run(
    config_path: &std::path::Path,
    qualification: RuntimeQualification,
) -> miette::Result<()> {
    boundary_server::run_boundary(config_path, qualification)
        .map_err(|error| miette::miette!(error))
}
