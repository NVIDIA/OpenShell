// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration containment, assuming the same image identity resolution and
//! execution environment. This does not attest successful Landlock installation.

use super::{
    CheckResult, ContainmentPolicy, Counterexample, ExceedsEvidence, ReasonCode, unsupported,
};
use openshell_policy_schema::LandlockCompatibility;

pub(super) fn unsupported_reason(policy: &ContainmentPolicy) -> Option<String> {
    if let Some(process) = &policy.process {
        for identity in [&process.run_as_user, &process.run_as_group] {
            // Omission remains unresolved: Docker/Podman may use OCI Config.User.
            // Only runtime-supported sandbox identities plus root (to diagnose
            // escalation) are understood; arbitrary account names are not.
            if !identity.is_empty()
                && !matches!(identity.as_str(), "sandbox" | "root" | "0")
                && !identity
                    .parse::<u32>()
                    .is_ok_and(|id| (1..u32::MAX).contains(&id))
            {
                return Some(format!("uses unsupported process identity '{identity}'"));
            }
        }
    }
    None
}

pub(super) fn check(
    boundary: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
) -> Option<CheckResult> {
    let boundary_user = boundary
        .process
        .as_ref()
        .map_or("", |process| process.run_as_user.as_str());
    let candidate_user = candidate
        .process
        .as_ref()
        .map_or("", |process| process.run_as_user.as_str());
    let boundary_group = boundary
        .process
        .as_ref()
        .map_or("", |process| process.run_as_group.as_str());
    let candidate_group = candidate
        .process
        .as_ref()
        .map_or("", |process| process.run_as_group.as_str());
    for (field, boundary, candidate) in [
        ("run_as_user", boundary_user, candidate_user),
        ("run_as_group", boundary_group, candidate_group),
    ] {
        if boundary == candidate {
            continue;
        }
        let root = |identity: &str| matches!(identity, "root" | "0");
        if root(boundary) && root(candidate) {
            continue;
        }
        if !boundary.is_empty() && !root(boundary) && root(candidate) {
            return Some(CheckResult::Exceeds(ExceedsEvidence(
                Counterexample::Process {
                    field,
                    boundary: boundary.to_owned(),
                    candidate: candidate.to_owned(),
                },
            )));
        }
        return Some(unsupported(
            ReasonCode::UnsupportedPolicyShape,
            format!(
                "process {field} changes from '{boundary}' to '{candidate}'; identity resolution and ordering require execution-environment evidence"
            ),
        ));
    }
    if boundary
        .landlock
        .as_ref()
        .is_some_and(|policy| policy.compatibility == LandlockCompatibility::HardRequirement)
        && !candidate
            .landlock
            .as_ref()
            .is_some_and(|policy| policy.compatibility == LandlockCompatibility::HardRequirement)
    {
        return Some(CheckResult::Exceeds(ExceedsEvidence(
            Counterexample::Landlock {
                boundary: "hard_requirement".to_owned(),
                candidate: "best_effort".to_owned(),
            },
        )));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containment::{CheckOptions, check_within_boundary, parse_policy_str};

    fn result(boundary: &str, candidate: &str) -> CheckResult {
        check_within_boundary(
            &parse_policy_str(&format!("version: 1\n{boundary}")).unwrap(),
            &parse_policy_str(&format!("version: 1\n{candidate}")).unwrap(),
            CheckOptions {
                timeout: std::time::Duration::from_secs(10),
            },
        )
    }

    #[test]
    fn process_matches_and_root_escalations() {
        let sandbox = "process: {run_as_user: sandbox, run_as_group: sandbox}";
        assert!(matches!(result(sandbox, sandbox), CheckResult::Within(_)));
        for candidate in [
            "process: {run_as_user: root, run_as_group: sandbox}",
            "process: {run_as_user: sandbox, run_as_group: '0'}",
        ] {
            assert!(matches!(
                result(sandbox, candidate),
                CheckResult::Exceeds(_)
            ));
        }
        for candidate in [
            "process: {run_as_user: '1001', run_as_group: sandbox}",
            "process: {}",
            "",
        ] {
            assert!(matches!(
                result(sandbox, candidate),
                CheckResult::Unsupported(_)
            ));
        }
        assert!(matches!(result("", sandbox), CheckResult::Unsupported(_)));
    }

    #[test]
    fn landlock_compatibility_and_defaults() {
        let hard = "landlock: {compatibility: hard_requirement}";
        for soft in ["", "landlock: {}", "landlock: {compatibility: best_effort}"] {
            assert!(matches!(result(soft, hard), CheckResult::Within(_)));
            assert!(matches!(result(hard, soft), CheckResult::Exceeds(_)));
            assert!(matches!(result(soft, soft), CheckResult::Within(_)));
        }
        assert!(matches!(result(hard, hard), CheckResult::Within(_)));
    }

    #[test]
    fn unknown_fields_and_identities_fail_closed() {
        for policy in ["process: {capabilities: all}", "landlock: {disabled: true}"] {
            assert!(parse_policy_str(&format!("version: 1\n{policy}")).is_err());
        }
        let unsupported_identity = "process: {run_as_user: nobody}";
        assert!(matches!(
            result(unsupported_identity, unsupported_identity),
            CheckResult::Unsupported(_)
        ));
        assert!(parse_policy_str("version: 1\nlandlock: {compatibility: disabled}").is_err());
    }
}
