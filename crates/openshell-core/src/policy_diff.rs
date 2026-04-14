// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy diff utility for comparing two `SandboxPolicy` protos.
//!
//! Produces a structured diff of network policy rules — the only field
//! that changes at runtime via `openshell policy set`.

use crate::proto::SandboxPolicy;

/// Result of comparing two policies.
pub struct PolicyDiff {
    /// Network rule names present in the new policy but not in the current policy.
    pub added_network_rules: Vec<String>,
    /// Network rule names present in the current policy but not in the new policy.
    pub removed_network_rules: Vec<String>,
}

impl PolicyDiff {
    /// Compare `current` and `proposed` sandbox policies.
    ///
    /// Only network policy rules are diffed since filesystem, landlock, and
    /// process fields are immutable after sandbox creation and validated
    /// separately by `validate_static_fields_unchanged`.
    pub fn diff(current: &SandboxPolicy, proposed: &SandboxPolicy) -> Self {
        let mut added: Vec<String> = proposed
            .network_policies
            .keys()
            .filter(|k| !current.network_policies.contains_key(*k))
            .cloned()
            .collect();
        added.sort();

        let mut removed: Vec<String> = current
            .network_policies
            .keys()
            .filter(|k| !proposed.network_policies.contains_key(*k))
            .cloned()
            .collect();
        removed.sort();

        Self {
            added_network_rules: added,
            removed_network_rules: removed,
        }
    }

    /// Returns true if there are no differences.
    pub fn is_empty(&self) -> bool {
        self.added_network_rules.is_empty() && self.removed_network_rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{NetworkBinary, NetworkEndpoint, NetworkPolicyRule};

    fn make_policy(rule_names: &[&str]) -> SandboxPolicy {
        let mut policy = SandboxPolicy::default();
        for name in rule_names {
            policy.network_policies.insert(
                name.to_string(),
                NetworkPolicyRule {
                    name: name.to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: "example.com".to_string(),
                        port: 443,
                        ..Default::default()
                    }],
                    binaries: vec![NetworkBinary {
                        path: "/usr/bin/curl".to_string(),
                        ..Default::default()
                    }],
                },
            );
        }
        policy
    }

    #[test]
    fn diff_detects_added_rules() {
        let current = make_policy(&["rule_a"]);
        let proposed = make_policy(&["rule_a", "rule_b", "rule_c"]);
        let diff = PolicyDiff::diff(&current, &proposed);
        assert_eq!(diff.added_network_rules, vec!["rule_b", "rule_c"]);
        assert!(diff.removed_network_rules.is_empty());
        assert!(!diff.is_empty());
    }

    #[test]
    fn diff_detects_removed_rules() {
        let current = make_policy(&["rule_a", "rule_b", "rule_c"]);
        let proposed = make_policy(&["rule_a"]);
        let diff = PolicyDiff::diff(&current, &proposed);
        assert!(diff.added_network_rules.is_empty());
        assert_eq!(diff.removed_network_rules, vec!["rule_b", "rule_c"]);
        assert!(!diff.is_empty());
    }

    #[test]
    fn diff_detects_added_and_removed() {
        let current = make_policy(&["rule_a", "rule_b"]);
        let proposed = make_policy(&["rule_b", "rule_c"]);
        let diff = PolicyDiff::diff(&current, &proposed);
        assert_eq!(diff.added_network_rules, vec!["rule_c"]);
        assert_eq!(diff.removed_network_rules, vec!["rule_a"]);
        assert!(!diff.is_empty());
    }

    #[test]
    fn diff_no_changes() {
        let current = make_policy(&["rule_a", "rule_b"]);
        let proposed = make_policy(&["rule_a", "rule_b"]);
        let diff = PolicyDiff::diff(&current, &proposed);
        assert!(diff.is_empty());
    }

    #[test]
    fn diff_empty_policies() {
        let current = SandboxPolicy::default();
        let proposed = SandboxPolicy::default();
        let diff = PolicyDiff::diff(&current, &proposed);
        assert!(diff.is_empty());
    }

    #[test]
    fn diff_adding_to_empty() {
        let current = SandboxPolicy::default();
        let proposed = make_policy(&["rule_a"]);
        let diff = PolicyDiff::diff(&current, &proposed);
        assert_eq!(diff.added_network_rules, vec!["rule_a"]);
        assert!(diff.removed_network_rules.is_empty());
    }
}
