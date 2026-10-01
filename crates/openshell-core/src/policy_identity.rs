// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Canonical policy encoding and deterministic policy hashes.

use crate::proto::{
    NetworkEndpoint, NetworkMiddlewareConfig, NetworkPolicyRule, ProviderProfile,
    SandboxPolicy as ProtoSandboxPolicy,
};
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[allow(clippy::cast_possible_truncation)]
const fn canonical_size(value: usize) -> [u8; 8] {
    // Every supported Rust pointer width fits in u64, so encoding a collection
    // length or index needs no fallible conversion.
    (value as u64).to_le_bytes()
}

fn append_canonical_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&canonical_size(value.len()));
    out.extend_from_slice(value);
}

fn append_canonical_message<M: Message>(out: &mut Vec<u8>, value: &M) {
    append_canonical_bytes(out, &value.encode_to_vec());
}

fn append_sorted_message_map<M: Message>(
    out: &mut Vec<u8>,
    label: &[u8],
    values: &HashMap<String, M>,
) {
    append_canonical_bytes(out, label);
    let mut entries = values.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(key, _)| key.as_str());
    out.extend_from_slice(&canonical_size(entries.len()));
    for (key, value) in entries {
        append_canonical_bytes(out, key.as_bytes());
        append_canonical_message(out, value);
    }
}

fn append_sorted_string_map(out: &mut Vec<u8>, label: &[u8], values: &HashMap<String, String>) {
    append_canonical_bytes(out, label);
    let mut entries = values.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(key, _)| key.as_str());
    out.extend_from_slice(&canonical_size(entries.len()));
    for (key, value) in entries {
        append_canonical_bytes(out, key.as_bytes());
        append_canonical_bytes(out, value.as_bytes());
    }
}

fn clear_endpoint_maps(endpoints: &mut [NetworkEndpoint]) {
    for endpoint in endpoints {
        endpoint.graphql_persisted_queries.clear();
        for rule in &mut endpoint.rules {
            if let Some(allow) = &mut rule.allow {
                allow.query.clear();
                allow.params.clear();
            }
        }
        for deny in &mut endpoint.deny_rules {
            deny.query.clear();
            deny.params.clear();
        }
    }
}

fn append_endpoint_maps(out: &mut Vec<u8>, endpoints: &[NetworkEndpoint]) {
    for (endpoint_index, endpoint) in endpoints.iter().enumerate() {
        out.extend_from_slice(&canonical_size(endpoint_index));
        append_sorted_message_map(
            out,
            b"graphql_persisted_queries",
            &endpoint.graphql_persisted_queries,
        );
        for (rule_index, rule) in endpoint.rules.iter().enumerate() {
            out.extend_from_slice(&canonical_size(rule_index));
            if let Some(allow) = &rule.allow {
                append_sorted_message_map(out, b"allow_query", &allow.query);
                append_sorted_message_map(out, b"allow_params", &allow.params);
            }
        }
        for (rule_index, deny) in endpoint.deny_rules.iter().enumerate() {
            out.extend_from_slice(&canonical_size(rule_index));
            append_sorted_message_map(out, b"deny_query", &deny.query);
            append_sorted_message_map(out, b"deny_params", &deny.params);
        }
    }
}

/// Encode a policy rule without depending on randomized protobuf map order.
pub fn canonical_rule_bytes(rule: &NetworkPolicyRule) -> Vec<u8> {
    let mut map_free = rule.clone();
    clear_endpoint_maps(&mut map_free.endpoints);

    let mut out = Vec::new();
    append_canonical_message(&mut out, &map_free);
    append_endpoint_maps(&mut out, &rule.endpoints);
    out
}

/// Encode a provider profile without depending on randomized protobuf map order.
pub fn canonical_provider_profile_bytes(profile: &ProviderProfile) -> Vec<u8> {
    let mut map_free = profile.clone();
    map_free.annotations.clear();
    clear_endpoint_maps(&mut map_free.endpoints);

    let mut out = Vec::new();
    append_canonical_message(&mut out, &map_free);
    append_sorted_string_map(&mut out, b"annotations", &profile.annotations);
    append_endpoint_maps(&mut out, &profile.endpoints);
    out
}

fn canonical_struct_bytes(value: &prost_types::Struct) -> Vec<u8> {
    let mut out = Vec::new();
    let mut fields = value.fields.iter().collect::<Vec<_>>();
    fields.sort_by_key(|(key, _)| key.as_str());
    out.extend_from_slice(&canonical_size(fields.len()));
    for (key, value) in fields {
        append_canonical_bytes(&mut out, key.as_bytes());
        append_canonical_bytes(&mut out, &canonical_value_bytes(value));
    }
    out
}

fn canonical_value_bytes(value: &prost_types::Value) -> Vec<u8> {
    use prost_types::value::Kind;

    let mut out = Vec::new();
    match &value.kind {
        None => out.push(0),
        Some(Kind::NullValue(value)) => {
            out.push(1);
            out.extend_from_slice(&value.to_le_bytes());
        }
        Some(Kind::NumberValue(value)) => {
            out.push(2);
            out.extend_from_slice(&value.to_bits().to_le_bytes());
        }
        Some(Kind::StringValue(value)) => {
            out.push(3);
            append_canonical_bytes(&mut out, value.as_bytes());
        }
        Some(Kind::BoolValue(value)) => {
            out.push(4);
            out.push(u8::from(*value));
        }
        Some(Kind::StructValue(value)) => {
            out.push(5);
            append_canonical_bytes(&mut out, &canonical_struct_bytes(value));
        }
        Some(Kind::ListValue(value)) => {
            out.push(6);
            out.extend_from_slice(&canonical_size(value.values.len()));
            for item in &value.values {
                append_canonical_bytes(&mut out, &canonical_value_bytes(item));
            }
        }
    }
    out
}

fn canonical_middleware_bytes(middleware: &NetworkMiddlewareConfig) -> Vec<u8> {
    let mut map_free = middleware.clone();
    map_free.config = None;
    let mut out = Vec::new();
    append_canonical_message(&mut out, &map_free);
    if let Some(config) = &middleware.config {
        append_canonical_bytes(&mut out, &canonical_struct_bytes(config));
    }
    out
}

fn canonical_policy_bytes(policy: &ProtoSandboxPolicy) -> Vec<u8> {
    let mut map_free = policy.clone();
    map_free.network_policies.clear();
    map_free.network_middlewares.clear();
    let mut out = Vec::new();
    append_canonical_message(&mut out, &map_free);

    let mut policy_entries = policy.network_policies.iter().collect::<Vec<_>>();
    policy_entries.sort_by_key(|(key, _)| key.as_str());
    append_canonical_bytes(&mut out, b"network_policies");
    out.extend_from_slice(&canonical_size(policy_entries.len()));
    for (key, rule) in policy_entries {
        append_canonical_bytes(&mut out, key.as_bytes());
        append_canonical_bytes(&mut out, &canonical_rule_bytes(rule));
    }

    let mut middleware_entries = policy.network_middlewares.iter().collect::<Vec<_>>();
    middleware_entries.sort_by_key(|(key, _)| key.as_str());
    append_canonical_bytes(&mut out, b"network_middlewares");
    out.extend_from_slice(&canonical_size(middleware_entries.len()));
    for (key, middleware) in middleware_entries {
        append_canonical_bytes(&mut out, key.as_bytes());
        append_canonical_bytes(&mut out, &canonical_middleware_bytes(middleware));
    }
    out
}

/// Compute a deterministic SHA-256 hash of a `SandboxPolicy`, recursively
/// sorting every protobuf map while preserving repeated-field order.
pub fn deterministic_policy_hash(policy: &ProtoSandboxPolicy) -> String {
    format!("{:x}", Sha256::digest(canonical_policy_bytes(policy)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{GraphqlOperation, L7Allow, L7DenyRule, L7QueryMatcher, L7Rule};

    fn matcher(glob: &str) -> L7QueryMatcher {
        L7QueryMatcher {
            glob: glob.to_string(),
            ..Default::default()
        }
    }

    fn endpoint_with_maps() -> NetworkEndpoint {
        let mut allow = L7Allow::default();
        allow.query.insert("x".into(), matcher("1"));
        allow.query.insert("y".into(), matcher("2"));
        allow.params.insert("p".into(), matcher("3"));
        allow.params.insert("q".into(), matcher("4"));
        let mut deny = L7DenyRule::default();
        deny.query.insert("x".into(), matcher("1"));
        deny.query.insert("y".into(), matcher("2"));
        let mut endpoint = NetworkEndpoint {
            host: "h".into(),
            rules: vec![L7Rule { allow: Some(allow) }],
            deny_rules: vec![deny],
            ..Default::default()
        };
        endpoint
            .graphql_persisted_queries
            .insert("a".into(), GraphqlOperation::default());
        endpoint
            .graphql_persisted_queries
            .insert("b".into(), GraphqlOperation::default());
        endpoint
    }

    fn profile_with_maps() -> ProviderProfile {
        let mut profile = ProviderProfile {
            id: "example".into(),
            endpoints: vec![endpoint_with_maps()],
            ..Default::default()
        };
        for i in 0..8 {
            profile
                .annotations
                .insert(format!("example.com/{i}"), i.to_string());
        }
        profile
    }

    #[test]
    fn rule_bytes_keep_their_encoding() {
        let rule = NetworkPolicyRule {
            endpoints: vec![endpoint_with_maps()],
            ..Default::default()
        };
        assert_eq!(
            format!("{:x}", Sha256::digest(canonical_rule_bytes(&rule))),
            "7f10cf8b6715748d89a0e6232036f9de0c666506b953c525149a2bd52a1891b8"
        );
    }

    #[test]
    fn provider_profile_bytes_ignore_map_order() {
        let wire = profile_with_maps().encode_to_vec();
        let expected = canonical_provider_profile_bytes(&profile_with_maps());
        let mut raw = std::collections::HashSet::new();
        for _ in 0..64 {
            let decoded = ProviderProfile::decode(wire.as_slice()).unwrap();
            raw.insert(decoded.encode_to_vec());
            assert_eq!(canonical_provider_profile_bytes(&decoded), expected);
        }
        // Raw protobuf encoding is what made revisions unstable.
        assert!(raw.len() > 1);
    }

    #[test]
    fn provider_profile_bytes_track_content() {
        let base = canonical_provider_profile_bytes(&profile_with_maps());

        let mut annotated = profile_with_maps();
        annotated
            .annotations
            .insert("example.com/0".into(), "changed".into());
        assert_ne!(canonical_provider_profile_bytes(&annotated), base);

        let mut queried = profile_with_maps();
        queried.endpoints[0].rules[0]
            .allow
            .as_mut()
            .unwrap()
            .query
            .insert("z".into(), matcher("5"));
        assert_ne!(canonical_provider_profile_bytes(&queried), base);
    }
}
