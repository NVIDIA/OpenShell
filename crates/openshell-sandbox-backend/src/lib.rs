// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` Sandbox Protocol and its concrete RFC 0012 backend.
//!
//! [`OpenShellRuntimeBackend`] is the supervisor-side implementation of the
//! generic `IsolationBackend` interface. The workload-side `openshell-sandbox`
//! runtime serves the same protocol using the generated server and shared wire
//! types in this crate.

pub mod boundary_protocol;
pub mod mediation;
mod runtime;
pub mod sandbox_auth;

pub use runtime::OpenShellRuntimeBackend;

/// Stable isolation backend name implemented by `openshell-sandbox`.
pub const BACKEND_NAME: &str = "openshell-sandbox";

/// Workload-visible directory for the supervisor's public HTTPS interception
/// certificate and combined trust bundle.
pub const SUPERVISOR_CA_RUNTIME_DIR: &str = "/run/openshell-supervisor-ca";

/// Generated gRPC transport envelope for the OpenShell Sandbox Protocol.
#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    unused_imports,
    unused_qualifications,
    rust_2018_idioms
)]
pub mod proto {
    tonic::include_proto!("openshell.sandbox.protocol.v1");
}
