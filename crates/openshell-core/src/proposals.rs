// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared state controlling agent-driven policy proposals.
//!
//! Initialised once during sandbox start from the `agent_policy_proposals_enabled`
//! setting and updated by the policy poll loop or authoritative sidecar control
//! when the setting changes. Read by the `policy.local` route handler and by
//! the skills installer to gate the agent-controlled mutation surface.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Shared handle for the agent-driven policy proposal surface.
///
/// Clones point at the same atomic value, so the sandbox orchestrator can pass
/// this into the process and network supervisors and then update it from the
/// settings poll loop or sidecar control.
#[derive(Clone, Debug)]
pub struct AgentProposals {
    enabled: Arc<AtomicBool>,
}

impl AgentProposals {
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(enabled)),
        }
    }

    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn swap_enabled(&self, enabled: bool) -> bool {
        self.enabled.swap(enabled, Ordering::Relaxed)
    }
}

impl Default for AgentProposals {
    fn default() -> Self {
        Self::new(false)
    }
}
