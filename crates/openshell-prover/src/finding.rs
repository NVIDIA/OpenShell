// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Finding types emitted by verification queries.

use std::fmt;

/// Severity level for a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiskLevel {
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A concrete path through which data can be exfiltrated.
#[derive(Debug, Clone)]
pub struct ExfilPath {
    pub binary: String,
    pub endpoint_host: String,
    pub endpoint_port: u32,
    pub mechanism: String,
    pub policy_name: String,
    /// One of `"l4_only"`, `"l7_allows_write"`, `"l7_bypassed"`.
    pub l7_status: String,
}

/// A path that allows writing despite read-only intent.
#[derive(Debug, Clone)]
pub struct WriteBypassPath {
    pub binary: String,
    pub endpoint_host: String,
    pub endpoint_port: u32,
    pub policy_name: String,
    pub policy_intent: String,
    /// One of `"l4_only"`, `"l7_bypass_protocol"`, `"credential_write_scope"`.
    pub bypass_reason: String,
    pub credential_actions: Vec<String>,
}

/// Concrete evidence attached to a [`Finding`].
#[derive(Debug, Clone)]
pub enum FindingPath {
    Exfil(ExfilPath),
    WriteBypass(WriteBypassPath),
}

/// A single verification finding.
#[derive(Debug, Clone)]
pub struct Finding {
    pub query: String,
    pub title: String,
    pub description: String,
    pub risk: RiskLevel,
    pub paths: Vec<FindingPath>,
    pub remediation: Vec<String>,
    pub accepted: bool,
    pub accepted_reason: String,
}
