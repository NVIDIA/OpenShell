// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Canonical policy encoding and deterministic policy hashes.

use crate::proto::{
    NetworkEndpoint, NetworkMiddlewareConfig, NetworkPolicyRule,
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

/// Remove every protobuf map nested inside an endpoint so prost encodes it deterministically.
fn clear_endpoint_maps(endpoint: &mut NetworkEndpoint) {
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

/// Append the maps removed by [`clear_endpoint_maps`] in sorted key order.
fn append_sorted_endpoint_maps(out: &mut Vec<u8>, endpoint: &NetworkEndpoint) {
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

/// Encode a policy rule without depending on randomized protobuf map order.
pub fn canonical_rule_bytes(rule: &NetworkPolicyRule) -> Vec<u8> {
    let mut map_free = rule.clone();
    for endpoint in &mut map_free.endpoints {
        clear_endpoint_maps(endpoint);
    }

    let mut out = Vec::new();
    append_canonical_message(&mut out, &map_free);
    for (endpoint_index, endpoint) in rule.endpoints.iter().enumerate() {
        out.extend_from_slice(&canonical_size(endpoint_index));
        append_sorted_endpoint_maps(&mut out, endpoint);
    }
    out
}

fn append_sorted_rule_map(
    out: &mut Vec<u8>,
    label: &[u8],
    rules: &HashMap<String, NetworkPolicyRule>,
) {
    let mut entries = rules.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(key, _)| key.as_str());
    append_canonical_bytes(out, label);
    out.extend_from_slice(&canonical_size(entries.len()));
    for (key, rule) in entries {
        append_canonical_bytes(out, key.as_bytes());
        append_canonical_bytes(out, &canonical_rule_bytes(rule));
    }
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
    map_free.provider_credential_rules.clear();
    for endpoint in &mut map_free.endpoint_settings {
        clear_endpoint_maps(endpoint);
    }
    let mut out = Vec::new();
    append_canonical_message(&mut out, &map_free);

    append_sorted_rule_map(&mut out, b"network_policies", &policy.network_policies);

    let mut middleware_entries = policy.network_middlewares.iter().collect::<Vec<_>>();
    middleware_entries.sort_by_key(|(key, _)| key.as_str());
    append_canonical_bytes(&mut out, b"network_middlewares");
    out.extend_from_slice(&canonical_size(middleware_entries.len()));
    for (key, middleware) in middleware_entries {
        append_canonical_bytes(&mut out, key.as_bytes());
        append_canonical_bytes(&mut out, &canonical_middleware_bytes(middleware));
    }

    // The Cedar-only sections below are appended only when populated so that
    // every policy hash computed before these fields existed stays unchanged.
    if !policy.provider_credential_rules.is_empty() {
        append_sorted_rule_map(
            &mut out,
            b"provider_credential_rules",
            &policy.provider_credential_rules,
        );
    }
    if !policy.endpoint_settings.is_empty() {
        append_canonical_bytes(&mut out, b"endpoint_settings");
        out.extend_from_slice(&canonical_size(policy.endpoint_settings.len()));
        for (endpoint_index, endpoint) in policy.endpoint_settings.iter().enumerate() {
            out.extend_from_slice(&canonical_size(endpoint_index));
            append_sorted_endpoint_maps(&mut out, endpoint);
        }
    }
    out
}

/// Compute a deterministic SHA-256 hash of a `SandboxPolicy`, recursively
/// sorting every protobuf map while preserving repeated-field order.
pub fn deterministic_policy_hash(policy: &ProtoSandboxPolicy) -> String {
    format!("{:x}", Sha256::digest(canonical_policy_bytes(policy)))
}

/// Derive token-grant authorities from a provider record and its complete profile rule.
///
/// The record identity separates providers whose names sanitize to the same policy
/// key. Hashing the rule content and endpoint position prevents a refreshed profile
/// from using grants through an older policy generation. Generated names and
/// provenance are excluded so both gateway construction paths derive the same value.
pub fn provider_token_grant_owners(provider_id: &str, rule: &NetworkPolicyRule) -> Vec<String> {
    let mut authority = rule.clone();
    authority.name.clear();
    clear_rule_token_grant_provenance(&mut authority);
    let rule_bytes = canonical_rule_bytes(&authority);
    authority
        .endpoints
        .iter()
        .enumerate()
        .map(|(index, _)| {
            token_grant_owner(
                b"openshell:provider-token-grant-owner:v1",
                provider_id.as_bytes(),
                &rule_bytes,
                index,
            )
        })
        .collect()
}

/// Stamp endpoint authorities for a complete gateway-global policy replacement.
///
/// Global policy suppresses provider profile authorization rules. Its own endpoint
/// authorities must therefore be used for grants, while the original credential
/// host, port, and path selectors continue to limit where a token may be sent.
/// The complete policy hash invalidates every stamp when the global policy changes.
pub fn stamp_global_token_grant_owners(policy: &mut ProtoSandboxPolicy) {
    let mut authority = policy.clone();
    for rule in authority.network_policies.values_mut() {
        for endpoint in &mut rule.endpoints {
            endpoint.token_grant_owner.clear();
            endpoint.provider_credentialed = false;
        }
    }
    let policy_hash = deterministic_policy_hash(&authority);
    for (name, rule) in &mut policy.network_policies {
        for (index, endpoint) in rule.endpoints.iter_mut().enumerate() {
            endpoint.token_grant_owner = token_grant_owner(
                b"openshell:global-token-grant-owner:v1",
                policy_hash.as_bytes(),
                name.as_bytes(),
                index,
            );
        }
    }
}

fn clear_rule_token_grant_provenance(rule: &mut NetworkPolicyRule) {
    for endpoint in &mut rule.endpoints {
        endpoint.token_grant_owner.clear();
        endpoint.provider_credentialed = false;
        endpoint.advisor_proposed = false;
    }
}

fn token_grant_owner(domain: &[u8], identity: &[u8], policy: &[u8], index: usize) -> String {
    let mut input = Vec::new();
    append_canonical_bytes(&mut input, domain);
    append_canonical_bytes(&mut input, identity);
    append_canonical_bytes(&mut input, policy);
    input.extend_from_slice(&canonical_size(index));
    format!("grant-owner:v1:{:x}", Sha256::digest(input))
}

#[cfg(test)]
mod policy_hash_tests {
    use super::*;
    use crate::proto::{GraphqlOperation, NetworkBinary};

    const ROUND_TRIPS: usize = 50;

    fn provider_rule(host: &str) -> NetworkPolicyRule {
        NetworkPolicyRule {
            endpoints: vec![NetworkEndpoint {
                host: host.into(),
                path: "/v1/**".into(),
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/client".into(),
            }],
            ..Default::default()
        }
    }

    fn operation(name: &str) -> GraphqlOperation {
        GraphqlOperation {
            operation_type: "query".into(),
            operation_name: name.into(),
            fields: vec![name.to_ascii_lowercase()],
        }
    }

    fn cedar_policy_with_provider_rules() -> ProtoSandboxPolicy {
        ProtoSandboxPolicy {
            cedar_policy_source: "permit(principal, action, resource);".into(),
            provider_credential_rules: HashMap::from([
                ("alpha".into(), provider_rule("alpha.example.test")),
                ("beta".into(), provider_rule("beta.example.test")),
            ]),
            ..Default::default()
        }
    }

    fn cedar_policy_with_endpoint_settings() -> ProtoSandboxPolicy {
        ProtoSandboxPolicy {
            cedar_policy_source: "permit(principal, action, resource);".into(),
            endpoint_settings: vec![NetworkEndpoint {
                host: "graphql.example.test".into(),
                graphql_persisted_queries: HashMap::from([
                    ("GetUser".into(), operation("GetUser")),
                    ("ListRepos".into(), operation("ListRepos")),
                ]),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    /// Hash the policy after each of many protobuf round-trips, which reshuffle
    /// `HashMap` iteration order, and return the distinct hashes observed.
    fn round_trip_hashes(policy: &ProtoSandboxPolicy) -> std::collections::BTreeSet<String> {
        let mut hashes = std::collections::BTreeSet::new();
        let mut current = policy.clone();
        for _ in 0..ROUND_TRIPS {
            current = ProtoSandboxPolicy::decode(current.encode_to_vec().as_slice())
                .expect("policy round-trips through protobuf");
            hashes.insert(deterministic_policy_hash(&current));
        }
        hashes
    }

    #[test]
    fn provider_credential_rules_hash_is_stable_across_round_trips() {
        let hashes = round_trip_hashes(&cedar_policy_with_provider_rules());
        assert_eq!(hashes.len(), 1, "distinct hashes observed: {hashes:?}");
    }

    #[test]
    fn endpoint_settings_persisted_queries_hash_is_stable_across_round_trips() {
        let hashes = round_trip_hashes(&cedar_policy_with_endpoint_settings());
        assert_eq!(hashes.len(), 1, "distinct hashes observed: {hashes:?}");
    }

    #[test]
    fn cedar_map_insertion_order_does_not_change_hash() {
        let forward = cedar_policy_with_provider_rules();
        let mut reversed = ProtoSandboxPolicy {
            provider_credential_rules: HashMap::new(),
            ..forward.clone()
        };
        let mut entries = forward.provider_credential_rules.iter().collect::<Vec<_>>();
        entries.sort_by_key(|(key, _)| key.as_str());
        for (key, rule) in entries.into_iter().rev() {
            reversed
                .provider_credential_rules
                .insert(key.clone(), rule.clone());
        }
        assert_eq!(
            deterministic_policy_hash(&forward),
            deterministic_policy_hash(&reversed)
        );

        let forward = cedar_policy_with_endpoint_settings();
        let mut reversed = forward.clone();
        let queries = &mut reversed.endpoint_settings[0].graphql_persisted_queries;
        let mut entries = std::mem::take(queries).into_iter().collect::<Vec<_>>();
        entries.sort_by(|(left, _), (right, _)| left.cmp(right));
        queries.extend(entries.into_iter().rev());
        assert_eq!(
            deterministic_policy_hash(&forward),
            deterministic_policy_hash(&reversed)
        );
    }

    #[test]
    fn cedar_map_value_changes_change_hash() {
        let original = cedar_policy_with_provider_rules();
        let mut changed = original.clone();
        changed
            .provider_credential_rules
            .get_mut("beta")
            .expect("beta rule")
            .endpoints[0]
            .path = "/v2/**".into();
        assert_ne!(
            deterministic_policy_hash(&original),
            deterministic_policy_hash(&changed)
        );

        let original = cedar_policy_with_endpoint_settings();
        let mut changed = original.clone();
        changed.endpoint_settings[0]
            .graphql_persisted_queries
            .get_mut("GetUser")
            .expect("GetUser operation")
            .operation_type = "mutation".into();
        assert_ne!(
            deterministic_policy_hash(&original),
            deterministic_policy_hash(&changed)
        );
    }

    #[test]
    fn policies_without_cedar_fields_keep_legacy_canonical_bytes() {
        // Mirrors the canonical encoding that shipped before the Cedar-only
        // sections were added, so hashes persisted by older gateways still match.
        fn legacy_canonical_policy_bytes(policy: &ProtoSandboxPolicy) -> Vec<u8> {
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

        let yaml_policy = ProtoSandboxPolicy {
            network_policies: HashMap::from([
                ("alpha".into(), provider_rule("alpha.example.test")),
                ("beta".into(), provider_rule("beta.example.test")),
            ]),
            network_middlewares: HashMap::from([(
                "audit".into(),
                NetworkMiddlewareConfig {
                    name: "audit".into(),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        assert_eq!(
            canonical_policy_bytes(&yaml_policy),
            legacy_canonical_policy_bytes(&yaml_policy)
        );
        assert_eq!(
            canonical_policy_bytes(&ProtoSandboxPolicy::default()),
            legacy_canonical_policy_bytes(&ProtoSandboxPolicy::default())
        );
    }
}

#[cfg(test)]
mod token_grant_owner_tests {
    use super::*;
    use crate::proto::NetworkBinary;

    fn profile_rule() -> NetworkPolicyRule {
        NetworkPolicyRule {
            endpoints: vec![
                NetworkEndpoint {
                    host: "api.example.test".into(),
                    path: "/public/**".into(),
                    ..Default::default()
                },
                NetworkEndpoint {
                    host: "api.example.test".into(),
                    path: "/private/**".into(),
                    ..Default::default()
                },
            ],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/client".into(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn provider_owner_changes_with_identity_profile_or_endpoint_position() {
        let rule = profile_rule();
        let original = provider_token_grant_owners("provider-a", &rule);
        assert_ne!(original[0], original[1]);
        assert_ne!(original, provider_token_grant_owners("provider-b", &rule));

        let mut changed = rule.clone();
        changed.endpoints.swap(0, 1);
        assert!(
            !provider_token_grant_owners("provider-a", &changed)
                .iter()
                .any(|owner| original.contains(owner))
        );
        changed = rule.clone();
        changed.binaries[0].path = "/usr/bin/other-client".into();
        assert_ne!(
            original,
            provider_token_grant_owners("provider-a", &changed)
        );
        changed = rule;
        changed.endpoints[0].access = 3;
        assert_ne!(
            original,
            provider_token_grant_owners("provider-a", &changed)
        );
    }

    #[test]
    fn provider_owner_ignores_generated_names_and_untrusted_provenance() {
        let mut rule = profile_rule();
        let owners = provider_token_grant_owners("provider-a", &rule);
        rule.name = "_provider_colliding_name_2".into();
        for endpoint in &mut rule.endpoints {
            endpoint.token_grant_owner = "forged".into();
            endpoint.provider_credentialed = true;
            endpoint.advisor_proposed = true;
        }
        assert_eq!(owners, provider_token_grant_owners("provider-a", &rule));
    }

    #[test]
    fn global_owner_rebinds_on_policy_change_without_mutating_provenance() {
        let mut policy = ProtoSandboxPolicy {
            network_policies: HashMap::from([("global".into(), profile_rule())]),
            ..Default::default()
        };
        let endpoint = &mut policy.network_policies.get_mut("global").unwrap().endpoints[0];
        endpoint.advisor_proposed = true;
        endpoint.provider_credentialed = true;
        stamp_global_token_grant_owners(&mut policy);
        let first = policy.network_policies["global"].endpoints[0].clone();
        assert!(first.advisor_proposed && first.provider_credentialed);
        stamp_global_token_grant_owners(&mut policy);
        assert_eq!(first, policy.network_policies["global"].endpoints[0]);

        policy.network_policies.get_mut("global").unwrap().binaries[0].path =
            "/usr/bin/replacement".into();
        stamp_global_token_grant_owners(&mut policy);
        assert_ne!(
            first.token_grant_owner,
            policy.network_policies["global"].endpoints[0].token_grant_owner
        );
    }
}
