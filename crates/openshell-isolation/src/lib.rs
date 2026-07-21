// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `OpenShell` **Isolation Backend** runtime contract (RFC 0012).
//!
//! An isolation backend establishes and enforces an agent's isolation boundary;
//! the supervisor role drives it through one contract. The supervisor-facing
//! contract lives in [`contract`]: an object-safe, runtime-selectable factory
//! plus a fixed chain of boxed lifecycle states the supervisor advances without
//! branching on where the boundary sits. The same calls work whether the
//! boundary lives in the agent's container (the in-pod backend) or further out
//! (a microVM, a node daemon, a separate pod).
//!
//! # The isolation envelope
//!
//! The boundary spans four [dimensions](IsolationDimension): network,
//! filesystem (Landlock), syscall (seccomp), and binary identity. A valid
//! backend establishes standing enforcement before untrusted code runs and
//! ensures the launch-time controls are in force before each process's first
//! untrusted instruction. Binary identity is resolved by the backend for every
//! accepted connection and delivered on
//! [`contract::MediatedConnection`]; network and exec are operated at runtime
//! through [`contract::MediationIngress`], [`contract::BoundaryExec`], and
//! [`contract::BoundaryPortForward`].
//!
//! # Ordering is a security property
//!
//! The lifecycle states run in order: attach -> Bound -> confirm -> Ready ->
//! start_agent -> Running. Nothing untrusted runs inside the boundary until it
//! is confirmed ready. This is enforced *by construction*: each transition
//! consumes the prior state by value, and no state type has a public
//! constructor, so the supervisor cannot skip a stage or run a workload before
//! [`contract::ReadyBoundary`] exists.
//!
//! [`AgentSpec`] is shared between the workload definition the supervisor
//! submits and the [`contract::SandboxContext`] that `attach` binds to a
//! boundary.

/// The four dimensions of the isolation envelope (RFC 0012).
///
/// A valid backend establishes all four before the agent runs. The variants are
/// a machine-readable inventory for an admission layer; the runtime contract in
/// [`contract`] carries all four by shape rather than enumerating them per call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IsolationDimension {
    /// Network namespace, routing, and proxy mediation.
    Network,
    /// Filesystem confinement (Landlock), established at the pre-exec ceiling.
    Filesystem,
    /// Syscall confinement (seccomp), established at the pre-exec ceiling.
    Syscall,
    /// Binary identity, resolved by the backend per accepted connection and
    /// delivered on the mediated connection.
    BinaryIdentity,
}

impl IsolationDimension {
    /// Every dimension of the isolation envelope: a machine-readable inventory
    /// for an admission layer that needs to iterate the dimensions a backend
    /// must satisfy.
    pub const ALL: [Self; 4] = [
        Self::Network,
        Self::Filesystem,
        Self::Syscall,
        Self::BinaryIdentity,
    ];
}

/// The agent workload to run inside the boundary.
///
/// Carried by [`contract::SandboxContext`] so a backend's `start_agent` takes no
/// spec; the bound boundary already carries what runs inside it.
#[derive(Debug, Clone)]
pub struct AgentSpec {
    /// Entrypoint program.
    pub program: String,
    /// Entrypoint arguments.
    pub args: Vec<String>,
    /// Working directory for the entrypoint, if any.
    pub workdir: Option<String>,
    /// Wall-clock timeout for the entrypoint in seconds (0 = no timeout).
    pub timeout_secs: u64,
    /// Whether the entrypoint runs interactively (inherits the parent pgrp).
    pub interactive: bool,
}

pub mod contract;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolation_dimensions_inventory_is_complete() {
        assert_eq!(IsolationDimension::ALL.len(), 4);
        assert!(IsolationDimension::ALL.contains(&IsolationDimension::Network));
        assert!(IsolationDimension::ALL.contains(&IsolationDimension::BinaryIdentity));
    }
}
