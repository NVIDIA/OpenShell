// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Composition of optional policy backends for the supervisor binary.

use miette::Result;
use openshell_core::proto::SandboxPolicy;
use openshell_policy_runtime_interface::PolicyEngine;
use openshell_supervisor_network::opa::OpaEngine;
use std::sync::Arc;

pub fn from_proto(policy: &SandboxPolicy) -> Result<PolicyEngine> {
    if policy.is_cedar() {
        #[cfg(feature = "experimental")]
        return Ok(
            Arc::new(openshell_policy_cedar_runtime::CedarOnlyEngine::from_proto(
                policy,
            )?)
            .into(),
        );
        #[cfg(not(feature = "experimental"))]
        return Err(miette::miette!(
            "Cedar policy support is not enabled in this supervisor build"
        ));
    }
    Ok(Arc::new(OpaEngine::from_proto(policy)?).into())
}
