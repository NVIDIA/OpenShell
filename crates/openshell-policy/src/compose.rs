// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy layer composition helpers.

use openshell_core::proto::{NetworkPolicyRule, SandboxPolicy};

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderPolicyLayer {
    pub rule_name: String,
    pub rule: NetworkPolicyRule,
}

#[must_use]
pub fn provider_rule_name(provider_name: &str) -> String {
    let sanitized = provider_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();

    if sanitized.is_empty() {
        "_provider_unnamed".to_string()
    } else {
        format!("_provider_{sanitized}")
    }
}

/// Compose a normal sandbox policy from user-authored policy plus provider
/// policy layers.
///
/// The returned policy is derived data. It preserves the source policy's
/// static fields and user-authored network policies, then concatenates each
/// provider rule under a reserved `_provider_*` key. Existing user keys are not
/// overwritten; a numeric suffix is added if needed.
#[must_use]
pub fn compose_effective_policy(
    source_policy: &SandboxPolicy,
    provider_layers: &[ProviderPolicyLayer],
) -> SandboxPolicy {
    let mut effective = source_policy.clone();

    for layer in provider_layers {
        let key = unique_provider_rule_key(&effective, &layer.rule_name);
        let mut rule = layer.rule.clone();
        if rule.name.is_empty() {
            rule.name.clone_from(&key);
        }
        effective.network_policies.insert(key, rule);
    }

    effective
}

fn unique_provider_rule_key(policy: &SandboxPolicy, preferred: &str) -> String {
    if !policy.network_policies.contains_key(preferred) {
        return preferred.to_string();
    }

    for suffix in 2_u32.. {
        let candidate = format!("{preferred}_{suffix}");
        if !policy.network_policies.contains_key(&candidate) {
            return candidate;
        }
    }

    unreachable!("unbounded suffix search must find an unused provider policy key")
}

#[cfg(test)]
mod tests {
    use super::{ProviderPolicyLayer, compose_effective_policy, provider_rule_name};
    use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule, SandboxPolicy};

    fn rule(name: &str, host: &str) -> NetworkPolicyRule {
        NetworkPolicyRule {
            name: name.to_string(),
            endpoints: vec![NetworkEndpoint {
                host: host.to_string(),
                port: 443,
                protocol: "rest".to_string(),
                tls: String::new(),
                enforcement: "enforce".to_string(),
                access: "read-write".to_string(),
                rules: Vec::new(),
                allowed_ips: Vec::new(),
                ports: Vec::new(),
                deny_rules: Vec::new(),
                allow_encoded_slash: false,
                ..Default::default()
            }],
            binaries: Vec::new(),
        }
    }

    #[test]
    fn provider_rule_name_sanitizes_provider_names() {
        assert_eq!(provider_rule_name("my-github"), "_provider_my_github");
        assert_eq!(provider_rule_name("Work GitHub!"), "_provider_work_github");
        assert_eq!(provider_rule_name("..."), "_provider_unnamed");
    }

    #[test]
    fn compose_concatenates_provider_rules_without_overwriting_user_rules() {
        let mut source = SandboxPolicy::default();
        source.network_policies.insert(
            "custom_github".to_string(),
            rule("custom_github", "api.github.com"),
        );
        source.network_policies.insert(
            "_provider_work_github".to_string(),
            rule("_provider_work_github", "example.com"),
        );

        let effective = compose_effective_policy(
            &source,
            &[ProviderPolicyLayer {
                rule_name: "_provider_work_github".to_string(),
                rule: rule("_provider_work_github", "github.com"),
            }],
        );

        assert!(effective.network_policies.contains_key("custom_github"));
        assert!(
            effective
                .network_policies
                .contains_key("_provider_work_github")
        );
        assert!(
            effective
                .network_policies
                .contains_key("_provider_work_github_2")
        );
        assert_eq!(source.network_policies.len(), 2);
        assert_eq!(effective.network_policies.len(), 3);
    }
}
