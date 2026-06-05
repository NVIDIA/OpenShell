// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cross-component denial event type.
//!
//! `DenialEvent` is emitted by the supervisor's networking proxy (on L4/L7
//! deny) and by the supervisor's bypass monitor (on direct-connect attempts
//! that bypass the proxy). It is consumed by the networking-side denial
//! aggregator that deduplicates and flushes summaries to the gateway.
//!
//! It lives in `openshell-core` because both supervisor leaves
//! (`openshell-supervisor-network` and `openshell-supervisor-process`)
//! produce it and need a shared type without depending on each other.

/// A single denial event emitted by the proxy or the bypass monitor.
#[derive(Debug, Clone)]
pub struct DenialEvent {
    /// Destination host that was denied.
    pub host: String,
    /// Destination port that was denied.
    pub port: u16,
    /// Binary path that initiated the connection (if resolved).
    pub binary: String,
    /// Ancestor binary paths from process tree walk.
    pub ancestors: Vec<String>,
    /// Reason for denial (e.g. "no matching policy", "internal address").
    pub deny_reason: String,
    /// Denial stage: "connect", "forward", "ssrf", "l7", "bypass".
    pub denial_stage: String,
    /// L7 request method (if this is an L7 denial).
    pub l7_method: Option<String>,
    /// L7 target path.
    pub l7_path: Option<String>,
}
