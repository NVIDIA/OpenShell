// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `firewall_rule` object.

use serde::{Deserialize, Serialize};

/// OCSF Firewall Rule object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRule {
    /// Rule name (e.g., "default-egress", "bypass-detect").
    pub name: String,

    /// Rule type / engine (e.g., "mechanistic", "opa", "nftables").
    ///
    /// Kept as `String` because this is a project-specific extension field
    /// (not OCSF-enumerated) with runtime-dynamic values from the policy engine.
    #[serde(rename = "type")]
    pub rule_type: String,

    /// Version of the policy the rule belongs to, as evaluated for this event.
    ///
    /// `OpenShell` sets this to the supervisor's policy engine generation: a
    /// counter the engine advances whenever it replaces its active
    /// configuration. Policy activation events record the same counter in
    /// `unmapped.active_generation`, so a consumer can resolve the policy
    /// behind each decision without relying on timestamps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl FirewallRule {
    /// Create a new firewall rule.
    #[must_use]
    pub fn new(name: &str, rule_type: &str) -> Self {
        Self {
            name: name.to_string(),
            rule_type: rule_type.to_string(),
            version: None,
        }
    }

    /// Record the policy generation under which the rule was evaluated.
    #[must_use]
    pub fn with_policy_generation(mut self, generation: u64) -> Self {
        self.version = Some(generation.to_string());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firewall_rule_serialization() {
        let rule = FirewallRule::new("default-egress", "mechanistic");
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(json["name"], "default-egress");
        assert_eq!(json["type"], "mechanistic");
        assert!(
            json.get("version").is_none(),
            "version is omitted when no generation is recorded"
        );
    }

    #[test]
    fn test_firewall_rule_policy_generation_serializes_as_version() {
        let rule = FirewallRule::new("github_api", "opa").with_policy_generation(7);
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(json["name"], "github_api");
        assert_eq!(json["version"], "7");

        let round_trip: FirewallRule = serde_json::from_value(json).unwrap();
        assert_eq!(round_trip, rule);
    }
}
