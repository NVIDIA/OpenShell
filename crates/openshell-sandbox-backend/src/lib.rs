// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(unsafe_code)]

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
    BoundBoundary, BoundaryExec, BoundaryLaunchOutcome, BoundaryLoopbackConnector, BoundaryProcess,
    BoundaryTakeover, BoundaryTerminal, ConfirmedBoundary, ExecSession,
    MAX_RESTORE_REFERENCE_BYTES, NetworkMediationSource, OpenShellRuntimeBackend,
    ProcessAttachment, ReadyBoundary, ResumeLaunch, RunningBoundary,
};
pub use runtime::{BoundaryTransport, BoundaryTransportConnector, validate_runtime_coordinates};

pub use openshell_driver_sdk::legacy_contract::{
    ALLOW_EXTRA_SUPPLEMENTARY_GROUPS_RESOURCE_CLAIM, BUILTIN_BACKEND_NAME as BACKEND_NAME,
    GPU_RESOURCE_CLAIM, SUPERVISOR_CA_RUNTIME_DIR, SUPERVISOR_CA_RUNTIME_ROOT,
};

/// Generated gRPC transport envelope for the `OpenShell` Sandbox Protocol.
pub mod proto {
    pub use openshell_core::proto::sandbox::protocol::v1::*;
}

#[cfg(feature = "test-support")]
pub use runtime::test_support;
