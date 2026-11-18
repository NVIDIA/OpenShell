// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Capability-free in-workload sandbox boundary.

// Crate-scoped: Cargo rejects mixing `[lints] workspace = true` with a
// crate-specific lint table (see #5188).
#![warn(clippy::undocumented_unsafe_blocks)]
#![cfg_attr(test, allow(clippy::undocumented_unsafe_blocks))]

#[cfg(target_os = "linux")]
mod accept_errors;
pub mod binary_pins;
#[cfg(target_os = "linux")]
pub mod boundary_exec;
#[cfg(target_os = "linux")]
pub mod boundary_io;
mod boundary_server;
#[cfg(target_os = "linux")]
pub mod child_env;
pub mod container_log;
#[cfg(target_os = "linux")]
pub(crate) mod delegated;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub mod main_session;
#[cfg(target_os = "linux")]
pub mod managed_children;
#[cfg(target_os = "linux")]
mod network_broker;
#[cfg(target_os = "linux")]
pub mod network_relay;
#[cfg(all(target_os = "linux", feature = "perf-harness"))]
pub mod perf;
#[cfg(target_os = "linux")]
pub mod process;
#[cfg(target_os = "linux")]
mod provider_files;
#[cfg(target_os = "linux")]
mod pty;
#[cfg(target_os = "linux")]
pub mod sandbox;
#[cfg(target_os = "linux")]
pub mod sftp;

/// Results of actively qualifying the admitted workload runtime.
///
/// Produced before the sandbox consumes protected bootstrap material.
/// The workload-mode resource claim key, shared with the Kubernetes
/// driver's boundary spec (`kubevirt.workload_mode`).
pub const WORKLOAD_MODE_CLAIM: &str = "kubevirt.workload_mode";
/// The claim value for the privileged (root-workload) VM class.
pub const PRIVILEGED_WORKLOAD_MODE: &str = "root";
/// The claim value for the sandboxed (default) class.
pub const SANDBOXED_WORKLOAD_MODE: &str = "sandboxed";

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "qualification preserves independently exercised security results"
)]
pub struct RuntimeQualification {
    pub seccomp: openshell_sandbox_backend::boundary_protocol::SeccompEvidence,
    /// Marks the privileged (root-workload) qualification: the in-guest
    /// enforcement evidence is advisory, and the seccomp-based network
    /// broker and provider files are unavailable.
    pub privileged: bool,
    pub landlock_abi: u32,
    pub landlock_allow_deny: bool,
    pub udp_dns_round_trip: bool,
    pub tcp_dns_round_trip: bool,
    pub tcp_allow_round_trip: bool,
    pub tcp_deny_round_trip: bool,
    pub socket_loopback_confinement: bool,
}

#[cfg(target_os = "linux")]
impl RuntimeQualification {
    /// A qualification for the privileged (root-workload) mode: the
    /// enforcement evidence fields are advisory (root can forge them),
    /// the seccomp-based network broker is unavailable, and no Landlock
    /// is applied. The boundary still runs the authenticated tunnel,
    /// exec/PTY/SSH relay, and status reporting.
    pub fn privileged() -> Self {
        Self {
            seccomp: openshell_sandbox_backend::boundary_protocol::SeccompEvidence {
                new_listener: false,
                notification_round_trip: false,
                id_validation: false,
                addfd_send: false,
                retained_socket_operation: false,
                proc_fd_identity: false,
                task_memory_read: false,
            },
            privileged: true,
            landlock_abi: 0,
            landlock_allow_deny: false,
            udp_dns_round_trip: false,
            tcp_dns_round_trip: false,
            tcp_allow_round_trip: false,
            tcp_deny_round_trip: false,
            socket_loopback_confinement: false,
        }
    }
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

#[cfg(target_os = "linux")]
mod native_api;
