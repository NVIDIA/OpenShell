// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Shared data and validation for the Isolation Backend RPC contracts.
//!
//! The backend extension interface is defined by `proto/isolation_backend.proto`
//! and `proto/sandbox_protocol.proto`. The supervisor uses the concrete RPC
//! client in `openshell-sandbox-backend`; backends implement the generated
//! services without implementing a parallel Rust backend trait.
//!
//! [`contract`] retains validated workload identities, confirmation evidence,
//! process specifications, and local byte-stream types shared by client and
//! server. Confirmation and generation checks remain mandatory before launch.

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
