// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `firewall_rule` object.

use serde::{Deserialize, Serialize};

/// OCSF Firewall Rule object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRule {
    /// Rule name (e.g., "default-egress", "bypass-detect").
    pub name: String,

    /// Rule type / engine (e.g., "mechanistic", "opa", "iptables").
    ///
    /// Kept as `String` because this is a project-specific extension field
    /// (not OCSF-enumerated) with runtime-dynamic values from the policy engine.
    #[serde(rename = "type")]
    pub rule_type: String,
}

impl FirewallRule {
    /// Create a new firewall rule.
    #[must_use]
    pub fn new(name: &str, rule_type: &str) -> Self {
        Self {
            name: name.to_string(),
            rule_type: rule_type.to_string(),
        }
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
    }
}
