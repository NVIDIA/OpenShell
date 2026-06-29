// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy layer composition helpers.

use openshell_core::proto::{NetworkPolicyRule, SandboxPolicy};

pub const PROVIDER_RULE_NAME_PREFIX: &str = "_provider_";

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderPolicyLayer {
    pub rule_name: String,
    pub rule: NetworkPolicyRule,
}

#[must_use]
pub fn is_provider_rule_name(rule_name: &str) -> bool {
    rule_name.starts_with(PROVIDER_RULE_NAME_PREFIX)
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
        format!("{PROVIDER_RULE_NAME_PREFIX}unnamed")
    } else {
        format!("{PROVIDER_RULE_NAME_PREFIX}{sanitized}")
    }
}

pub fn strip_provider_rule_names(policy: &mut SandboxPolicy) -> bool {
    let original_len = policy.network_policies.len();
    policy
        .network_policies
        .retain(|key, _| !is_provider_rule_name(key));
    policy.network_policies.len() != original_len
}

/// Compose a normal sandbox policy from user-authored policy plus provider
/// policy layers.
///
/// The returned policy is derived data. It preserves the source policy's
/// static fields and user-authored network policies, then concatenates each
/// provider rule under a reserved `_provider_*` key. Existing keys are not
/// overwritten; a numeric suffix is added if provider rule names collide.
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
    use super::{
        PROVIDER_RULE_NAME_PREFIX, ProviderPolicyLayer, compose_effective_policy,
        is_provider_rule_name, provider_rule_name, strip_provider_rule_names,
    };
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
    fn provider_rule_name_prefix_identifies_reserved_keys() {
        assert_eq!(PROVIDER_RULE_NAME_PREFIX, "_provider_");
        assert!(is_provider_rule_name("_provider_work_github"));
        assert!(is_provider_rule_name("_provider_work_github_2"));
        assert!(is_provider_rule_name("_provider_"));
        assert!(!is_provider_rule_name("provider_work_github"));
        assert!(!is_provider_rule_name("custom_provider_work_github"));
    }

    #[test]
    fn strip_provider_rule_names_removes_only_reserved_keys() {
        let mut policy = SandboxPolicy::default();
        policy.network_policies.insert(
            "_provider_work_github".to_string(),
            rule("_provider_work_github", "api.github.com"),
        );
        policy.network_policies.insert(
            "sandbox_only".to_string(),
            rule("sandbox_only", "sandbox.example.com"),
        );

        assert!(strip_provider_rule_names(&mut policy));
        assert!(
            !policy
                .network_policies
                .contains_key("_provider_work_github")
        );
        assert!(policy.network_policies.contains_key("sandbox_only"));
        assert!(!strip_provider_rule_names(&mut policy));
    }

    #[test]
    fn compose_concatenates_provider_rules_without_overwriting_user_rules() {
        let mut source = SandboxPolicy::default();
        source.network_policies.insert(
            "custom_github".to_string(),
            rule("custom_github", "api.github.com"),
        );

        let effective = compose_effective_policy(
            &source,
            &[
                ProviderPolicyLayer {
                    rule_name: "_provider_work_github".to_string(),
                    rule: rule("_provider_work_github", "github.com"),
                },
                ProviderPolicyLayer {
                    rule_name: "_provider_work_github".to_string(),
                    rule: rule("_provider_work_github", "github.example.com"),
                },
            ],
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
        assert_eq!(
            effective
                .network_policies
                .get("custom_github")
                .unwrap()
                .endpoints[0]
                .host,
            "api.github.com"
        );
        assert_eq!(source.network_policies.len(), 1);
        assert_eq!(effective.network_policies.len(), 3);
    }
}
