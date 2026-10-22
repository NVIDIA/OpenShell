// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Concrete supervisor-side client for the Isolation Backend and Sandbox Protocol RPCs.
//!
//! [`OpenShellRuntimeBackend`] connects to the in-tree runtime or a registered
//! external backend. Its concrete lifecycle and process handles issue RPCs;
//! they are not backend implementation traits. The workload-side
//! `openshell-sandbox` runtime implements the generated server services.

mod audit;
pub mod boundary_protocol;
pub mod delegated;
pub mod isolation_protocol;
pub mod mediation;
pub mod protobuf;
mod runtime;
mod runtime_initiated;
pub mod runtime_routed;
pub mod sandbox_auth;
pub mod stream_adapter;

pub use openshell_core::proto::sandbox::backend::v1 as backend_proto;
pub use runtime::{
    BoundBoundary, BoundaryExec, BoundaryLoopbackConnector, BoundaryProcess, BoundaryTerminal,
    ConfirmedBoundary, ExecSession, NetworkMediationSource, OpenShellRuntimeBackend,
    ProcessAttachment, ReadyBoundary, RunningBoundary,
};
pub use runtime::{BoundaryTransport, BoundaryTransportConnector, validate_runtime_coordinates};

/// Stable isolation backend name implemented by `openshell-sandbox`.
pub const BACKEND_NAME: &str = openshell_core::isolation_registration::BUILTIN_BACKEND_NAME;

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

/// Generated gRPC transport envelope for the `OpenShell` Sandbox Protocol.
pub mod proto {
    pub use openshell_core::proto::sandbox::protocol::v1::*;
}

#[cfg(feature = "test-support")]
pub use runtime::test_support;
