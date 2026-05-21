// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Finding types emitted by verification queries.
//!
//! The prover answers four formal questions about a proposed policy and
//! emits one finding category per "yes" answer. Findings are categorical
//! (not severity-graded): the reviewer reads the category name and the
//! structured evidence to decide. The auto-approval gate is binary —
//! delta empty = candidate for auto-approval; any finding = human review.
//!
//! Categories:
//!
//! - `credential_reach_expansion` — a binary gained credentialed reach to
//!   a (host, port) it could not reach before.
//! - `capability_expansion` — on a (binary, host, port) that already had
//!   credentialed reach, a new HTTP method was added.
//! - `l7_bypass_credentialed` — a binary using a wire protocol the L7
//!   proxy cannot inspect (`git-remote-https`, `ssh`, `nc`) gained reach
//!   to a host where a credential is in scope.
//! - `link_local_reach` — any reach to a link-local IP range
//!   (`169.254.0.0/16`, `fe80::/10`), unconditional. Cloud metadata
//!   endpoints serve credentials regardless of the sandbox's own
//!   credential state.

/// Stable category names. Used as the `query` field on [`Finding`] and
/// in the per-path key used by `finding_delta`.
pub mod category {
    pub const CREDENTIAL_REACH_EXPANSION: &str = "credential_reach_expansion";
    pub const CAPABILITY_EXPANSION: &str = "capability_expansion";
    pub const L7_BYPASS_CREDENTIALED: &str = "l7_bypass_credentialed";
    pub const LINK_LOCAL_REACH: &str = "link_local_reach";
}

/// A concrete path through which the prover observed a tracked property.
///
/// One `ExfilPath` per (binary, host, port, category) tuple — plus
/// `method` for `capability_expansion` so the gateway's per-path delta
/// surfaces the specific method that was added.
#[derive(Debug, Clone)]
pub struct ExfilPath {
    pub binary: String,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub mechanism: String,
    pub policy_name: String,
    /// Category name (see `category::*` constants).
    pub category: String,
    /// HTTP method, populated only for `capability_expansion` paths.
    /// Empty string for the other categories.
    pub method: String,
}

/// Concrete evidence attached to a [`Finding`].
#[derive(Debug, Clone)]
pub enum FindingPath {
    Exfil(ExfilPath),
}

/// A single verification finding.
///
/// `query` is the category name (one of the `category::*` constants).
/// Each finding carries one or more `paths` with the structured evidence
/// the reviewer needs to decide. There is no severity field — the
/// category itself is the signal.
#[derive(Debug, Clone)]
pub struct Finding {
    pub query: String,
    pub title: String,
    pub description: String,
    pub paths: Vec<FindingPath>,
    pub remediation: Vec<String>,
    pub accepted: bool,
    pub accepted_reason: String,
}
