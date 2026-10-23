// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-side control of a supervisor shared by many sandboxes.
//!
//! One shared supervisor hosts the sandbox instances (one running generation
//! of a stable Sandbox each) of a gateway. The gateway owns which instances
//! it hosts and serves that set to it over the private
//! `openshell.supervisor.host.v1` stream, which the supervisor opens with a
//! gateway-minted supervisor token. This crate holds everything about that
//! control relationship that is not specific to a compute platform:
//!
//! - [`controller`]: the desired set, its revision fencing, the host
//!   sessions, and the observations they report.
//! - [`registration`] and [`status`]: the launch material one assignment
//!   carries and the status the host reports, with their validation and wire
//!   mapping.
//! - [`coordinator`]: the gateway-owned [`SharedSupervision`] a compute
//!   driver is handed: validated persist-before-assign launches, recovery
//!   from durable records, and interpretation of observations.
//! - [`credential`]: delivery of the supervisor token with retry.
//!
//! The private wire protocol is generated in `openshell-core` and re-exported
//! as [`proto`]. The supervisor process consumes the registration and status
//! types; it never links the controller or coordinator.

pub mod controller;
pub mod coordinator;
pub mod credential;
pub mod registration;
pub mod status;

/// The private gateway-to-shared-supervisor protocol
/// (`openshell.supervisor.host.v1`).
pub mod proto {
    pub use openshell_core::proto::supervisor_host::v1::*;
}

pub use controller::{
    AssignmentError, ConnectedMember, HOST_HEARTBEAT_INTERVAL, HostIdentity, InstanceOwner,
    MAX_ASSIGNED_INSTANCES, MAX_REPORTED_INSTANCES, MemberView, ObservedInstance,
    POOL_HEARTBEAT_INTERVAL, PoolView, SupervisorCredential, SupervisorHostController,
};
pub use coordinator::{
    InstancePlacement, InstanceSupervision, LaunchError, PlacementFuture, PlacementRequest,
    RecoverableInstance, RecoveryBaseline, RecoveryOutcome, SharedSupervision,
};
pub use credential::deliver_credentials;
pub use registration::{
    INSTANCE_REMOVAL_GRACE, MAX_LAUNCH_MATERIAL_BYTES, ProxyCaMaterial, RegistrationError,
    RegistrationTraceContext, SandboxInstanceRegistration, SecretPem,
};
pub use status::{SandboxInstancePhaseReport, SandboxInstanceStatusReport};
