// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Compute launch input identity. Policy safety remains the admission owner's duty.

use crate::policy_identity::deterministic_policy_hash;
use crate::proto::SandboxLaunchPolicy;
use prost::Message;

/// Check the complete bounded input before a driver changes retained resources.
/// This does not authorize a policy or replace backend-specific admission.
pub fn validate_launch_policy(
    input: &SandboxLaunchPolicy,
    generation: &str,
) -> Result<(), &'static str> {
    if crate::sandbox_generation::SandboxGenerationId::parse(generation).is_err()
        || input.generation_id != generation
        || input.generation_id.is_empty()
    {
        return Err("launch policy generation does not match the compute launch");
    }
    let policy = input
        .policy
        .as_ref()
        .ok_or("launch policy document is missing")?;
    if policy.encoded_len() > 262_144 {
        return Err("launch policy exceeds the policy size limit");
    }
    if deterministic_policy_hash(policy) != input.policy_hash {
        return Err("launch policy hash does not match its document");
    }
    Ok(())
}
