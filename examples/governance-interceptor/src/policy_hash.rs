// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::proto::{ProviderProfile, SandboxPolicy};
use prost::Message;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::proto_json::decode_message_to_json;

pub(crate) const HASH_ALGORITHM: &str = "openshell-governance-protojson-sha256-v2";
const HASH_PREFIX: &str = "sha256:v2:";
const SANDBOX_POLICY_TYPE: &str = "openshell.sandbox.v1.SandboxPolicy";
const PROVIDER_PROFILE_TYPE: &str = "openshell.v1.ProviderProfile";
const POLICY_DOMAIN: &str = "openshell-governance-policy";
const PROFILE_DOMAIN: &str = "openshell-governance-provider-profile";
const PROFILE_SNAPSHOT_DOMAIN: &str = "openshell-governance-provider-profile-snapshot";

pub(crate) fn canonical_policy_hash(policy: &SandboxPolicy) -> Result<String, String> {
    canonical_message_hash(SANDBOX_POLICY_TYPE, policy, POLICY_DOMAIN)
}

pub(crate) fn canonical_profile_hash(profile: &ProviderProfile) -> Result<String, String> {
    canonical_message_hash(PROVIDER_PROFILE_TYPE, profile, PROFILE_DOMAIN)
}

pub(crate) fn canonical_profile_snapshot_revision(
    profiles: &[ProviderProfile],
) -> Result<String, String> {
    let mut canonical_profiles = profiles
        .iter()
        .map(|profile| {
            Ok((
                profile.id.as_bytes(),
                canonical_message_bytes(PROVIDER_PROFILE_TYPE, profile)?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    canonical_profiles.sort_by(|left, right| left.0.cmp(right.0));

    let mut hasher = Sha256::new();
    hasher.update(HASH_ALGORITHM.as_bytes());
    hash_framed(&mut hasher, PROFILE_SNAPSHOT_DOMAIN.as_bytes())?;
    hash_framed(&mut hasher, PROVIDER_PROFILE_TYPE.as_bytes())?;
    hash_framed(
        &mut hasher,
        &u64::try_from(canonical_profiles.len())
            .map_err(|_| "provider profile count exceeds hash framing limit")?
            .to_be_bytes(),
    )?;
    for (id, canonical) in canonical_profiles {
        hash_framed(&mut hasher, id)?;
        hash_framed(&mut hasher, &canonical)?;
    }
    Ok(format!("{HASH_PREFIX}{}", hex_encode(&hasher.finalize())))
}

pub(crate) fn is_v2_digest(value: &str) -> bool {
    value.strip_prefix(HASH_PREFIX).is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn canonical_message_hash<M>(type_name: &str, message: &M, domain: &str) -> Result<String, String>
where
    M: Message,
{
    let canonical = canonical_message_bytes(type_name, message)?;
    let mut hasher = Sha256::new();
    hasher.update(HASH_ALGORITHM.as_bytes());
    hash_framed(&mut hasher, domain.as_bytes())?;
    hash_framed(&mut hasher, type_name.as_bytes())?;
    hash_framed(&mut hasher, &canonical)?;
    Ok(format!("{HASH_PREFIX}{}", hex_encode(&hasher.finalize())))
}

fn canonical_message_bytes<M>(type_name: &str, message: &M) -> Result<Vec<u8>, String>
where
    M: Message,
{
    let value = decode_message_to_json(type_name, message)?;
    let mut bytes = Vec::new();
    write_canonical_json(&value, &mut bytes)?;
    Ok(bytes)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            output.push(b'{');
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)
                    .map_err(|err| format!("serialize canonical JSON object key: {err}"))?;
                output.push(b':');
                write_canonical_json(&object[key], output)?;
            }
            output.push(b'}');
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        _ => serde_json::to_writer(output, value)
            .map_err(|err| format!("serialize canonical JSON scalar: {err}"))?,
    }
    Ok(())
}

fn hash_framed(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), String> {
    let length = u64::try_from(bytes.len()).map_err(|_| "hash input exceeds framing limit")?;
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use openshell_core::proto::{
        GraphqlOperation, L7Allow, L7DenyRule, L7QueryMatcher, L7Rule, NetworkEndpoint,
        NetworkPolicyRule,
    };

    use super::*;

    #[test]
    fn policy_hash_is_recursive_and_preserves_repeated_order() {
        let left = policy_with_nested_maps(false);
        let right = policy_with_nested_maps(true);
        assert_eq!(
            canonical_policy_hash(&left).unwrap(),
            canonical_policy_hash(&right).unwrap()
        );

        let mut reordered = right;
        reordered.network_policies.get_mut("api").unwrap().endpoints[0].rules[0]
            .allow
            .as_mut()
            .unwrap()
            .fields
            .reverse();
        assert_ne!(
            canonical_policy_hash(&left).unwrap(),
            canonical_policy_hash(&reordered).unwrap()
        );
    }

    #[test]
    fn profile_hash_and_snapshot_revision_ignore_map_and_profile_order() {
        let left_profile = ProviderProfile {
            id: "alpha".to_string(),
            annotations: map(false, [("zeta", "last"), ("alpha", "first")]),
            endpoints: vec![
                policy_with_nested_maps(false)
                    .network_policies
                    .remove("api")
                    .unwrap()
                    .endpoints
                    .remove(0),
            ],
            ..ProviderProfile::default()
        };
        let right_profile = ProviderProfile {
            id: "alpha".to_string(),
            annotations: map(true, [("zeta", "last"), ("alpha", "first")]),
            endpoints: vec![
                policy_with_nested_maps(true)
                    .network_policies
                    .remove("api")
                    .unwrap()
                    .endpoints
                    .remove(0),
            ],
            ..ProviderProfile::default()
        };
        assert_eq!(
            canonical_profile_hash(&left_profile).unwrap(),
            canonical_profile_hash(&right_profile).unwrap()
        );

        let beta = ProviderProfile {
            id: "beta".to_string(),
            ..ProviderProfile::default()
        };
        assert_eq!(
            canonical_profile_snapshot_revision(&[left_profile, beta.clone()]).unwrap(),
            canonical_profile_snapshot_revision(&[beta, right_profile]).unwrap()
        );
    }

    #[test]
    fn digest_format_is_explicitly_v2() {
        let digest = canonical_policy_hash(&SandboxPolicy::default()).unwrap();
        assert!(is_v2_digest(&digest));
        assert!(!is_v2_digest("sha256:deadbeef"));
        assert!(!is_v2_digest(&format!("{HASH_PREFIX}{}", "A".repeat(64))));
    }

    fn policy_with_nested_maps(reverse: bool) -> SandboxPolicy {
        let allow = L7Allow {
            query: map(reverse, [("state", "open"), ("label", "bug")]),
            params: map(reverse, [("name", "search"), ("kind", "tool")]),
            fields: vec!["repository".to_string(), "issues".to_string()],
            ..L7Allow::default()
        };
        let deny = L7DenyRule {
            query: map(reverse, [("private", "true"), ("admin", "true")]),
            params: map(reverse, [("name", "delete"), ("kind", "tool")]),
            ..L7DenyRule::default()
        };
        let endpoint = NetworkEndpoint {
            host: "api.example.com".to_string(),
            port: 443,
            rules: vec![L7Rule { allow: Some(allow) }],
            deny_rules: vec![deny],
            graphql_persisted_queries: map(
                reverse,
                [("query-b", "LookupB"), ("query-a", "LookupA")],
            ),
            ..NetworkEndpoint::default()
        };
        let rules = if reverse {
            [("unused", "unused.example.com"), ("api", "api.example.com")]
        } else {
            [("api", "api.example.com"), ("unused", "unused.example.com")]
        };
        SandboxPolicy {
            version: 1,
            network_policies: rules
                .into_iter()
                .map(|(name, host)| {
                    let endpoints = if name == "api" {
                        vec![endpoint.clone()]
                    } else {
                        vec![NetworkEndpoint {
                            host: host.to_string(),
                            port: 443,
                            ..NetworkEndpoint::default()
                        }]
                    };
                    (
                        name.to_string(),
                        NetworkPolicyRule {
                            name: name.to_string(),
                            endpoints,
                            ..NetworkPolicyRule::default()
                        },
                    )
                })
                .collect(),
            ..SandboxPolicy::default()
        }
    }

    trait MapValue: Sized {
        fn from_test_value(value: &str) -> Self;
    }

    impl MapValue for String {
        fn from_test_value(value: &str) -> Self {
            value.to_string()
        }
    }

    impl MapValue for L7QueryMatcher {
        fn from_test_value(value: &str) -> Self {
            Self {
                glob: value.to_string(),
                ..Self::default()
            }
        }
    }

    impl MapValue for GraphqlOperation {
        fn from_test_value(value: &str) -> Self {
            Self {
                operation_type: "query".to_string(),
                operation_name: value.to_string(),
                fields: vec![value.to_string()],
            }
        }
    }

    fn map<V, const N: usize>(reverse: bool, entries: [(&str, &str); N]) -> HashMap<String, V>
    where
        V: MapValue,
    {
        let mut entries = entries;
        if reverse {
            entries.reverse();
        }
        entries
            .into_iter()
            .map(|(key, value)| (key.to_string(), V::from_test_value(value)))
            .collect()
    }
}
