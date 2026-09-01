// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `OpenShell` **Isolation Backend** runtime contract (RFC 0012).
//!
//! An isolation backend establishes and enforces a workload's isolation boundary;
//! the supervisor role drives it through one contract. The supervisor-facing
//! contract lives in [`contract`]: an object-safe, runtime-selectable backend
//! plus a fixed chain of boxed lifecycle states the supervisor advances without
//! branching on where the boundary sits. The same calls work whether the
//! boundary lives in the agent's container (the in-pod backend) or further out
//! (a microVM, a node daemon, a separate pod).
//!
//! The backend establishes standing enforcement before untrusted code runs and
//! ensures launch-time controls are in force before each process's first
//! untrusted instruction. It also exposes process operations and supplies
//! workload egress to supervisor-owned network mediation.
//!
//! # Ordering is a security property
//!
//! The lifecycle states run in order: attach -> Bound -> confirm -> Ready ->
//! `start_agent` -> Running. Nothing untrusted runs inside the boundary until it
//! is confirmed ready. This is enforced *by construction*: each transition
//! consumes the prior state by value, and no state type has a public
//! constructor, so the supervisor cannot skip a stage or run a workload before
//! [`contract::ReadyBoundary`] exists.
//!
//! [`AgentSpec`] is shared between the workload definition the supervisor
//! submits and the [`contract::SandboxContext`] that `attach` binds to a
//! boundary.

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
