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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_input_requires_matching_generation_document_hash_and_size() {
        let generation = uuid::Uuid::new_v4().to_string();
        let policy = crate::proto::SandboxPolicy::default();
        let valid = SandboxLaunchPolicy {
            generation_id: generation.clone(),
            policy_hash: deterministic_policy_hash(&policy),
            policy: Some(policy),
        };
        assert!(validate_launch_policy(&valid, &generation).is_ok());
        for mutation in 0..5 {
            let mut input = valid.clone();
            match mutation {
                0 => input.generation_id = uuid::Uuid::new_v4().to_string(),
                1 => input.policy = None,
                2 => input.policy_hash = "wrong".into(),
                3 => {
                    let policy = input.policy.as_mut().unwrap();
                    policy.filesystem = Some(crate::proto::FilesystemPolicy {
                        read_write: vec!["/".repeat(262_145)],
                        ..Default::default()
                    });
                    input.policy_hash = deterministic_policy_hash(policy);
                }
                _ => input.generation_id.clear(),
            }
            assert!(
                validate_launch_policy(&input, &generation).is_err(),
                "mutation {mutation}"
            );
        }
        let mut invalid = valid;
        invalid.generation_id = "invalid/generation".into();
        assert!(validate_launch_policy(&invalid, "invalid/generation").is_err());
    }
}
