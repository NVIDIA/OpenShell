// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configured MCP selectors shared by routing and passive endpoint reporting.

use miette::Result;
use openshell_core::proto::{NetworkEndpoint, SandboxPolicy};

/// Collect configured MCP endpoints, without substituting observed hosts for
/// configured globs. Callers validate the policy before installing this inventory.
///
/// # Errors
///
/// Returns an error if the Cedar policy cannot be compiled or Cedar support is
/// unavailable in this build.
pub fn configured_mcp_endpoints(policy: &SandboxPolicy) -> Result<Vec<NetworkEndpoint>> {
    if !policy.is_cedar() {
        return Ok(policy
            .network_policies
            .values()
            .flat_map(|rule| &rule.endpoints)
            .filter(|endpoint| openshell_core::mcp::is_mcp_protocol(&endpoint.protocol))
            .cloned()
            .collect());
    }
    #[cfg(feature = "cedar")]
    {
        openshell_policy_cedar_adapter::endpoint_status::configured_mcp_endpoints(policy)
    }
    #[cfg(not(feature = "cedar"))]
    Err(miette::miette!("Cedar policy support is unavailable"))
}
