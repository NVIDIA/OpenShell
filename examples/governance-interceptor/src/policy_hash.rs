// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::proto::SandboxPolicy;
use prost::Message as _;
use sha2::{Digest, Sha256};

/// Compute a deterministic SHA-256 hash of a sandbox policy.
///
/// Protobuf binary encoding is not canonical for maps, so this hashes scalar
/// fields directly and sorts `network_policies` by key before hashing each
/// encoded rule.
pub(crate) fn deterministic_policy_hash(policy: &SandboxPolicy) -> String {
    let mut hasher = Sha256::new();
    hasher.update(policy.version.to_le_bytes());
    if let Some(filesystem) = &policy.filesystem {
        hasher.update(filesystem.encode_to_vec());
    }
    if let Some(landlock) = &policy.landlock {
        hasher.update(landlock.encode_to_vec());
    }
    if let Some(process) = &policy.process {
        hasher.update(process.encode_to_vec());
    }
    let mut entries: Vec<_> = policy.network_policies.iter().collect();
    entries.sort_by_key(|(key, _)| key.as_str());
    for (key, value) in entries {
        hasher.update(key.as_bytes());
        hasher.update(value.encode_to_vec());
    }
    hex_encode(&hasher.finalize())
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
    use super::*;
    use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};

    #[test]
    fn sorts_network_policy_map_keys() {
        let left = policy_with_network_rules(&[
            ("beta", "beta.example.com"),
            ("alpha", "alpha.example.com"),
        ]);
        let right = policy_with_network_rules(&[
            ("alpha", "alpha.example.com"),
            ("beta", "beta.example.com"),
        ]);
        assert_eq!(
            deterministic_policy_hash(&left),
            deterministic_policy_hash(&right)
        );

        let changed = policy_with_network_rules(&[
            ("alpha", "alpha.example.com"),
            ("beta", "changed.example.com"),
        ]);
        assert_ne!(
            deterministic_policy_hash(&left),
            deterministic_policy_hash(&changed)
        );
    }

    fn policy_with_network_rules(rules: &[(&str, &str)]) -> SandboxPolicy {
        SandboxPolicy {
            version: 1,
            network_policies: rules
                .iter()
                .map(|(key, host)| {
                    (
                        (*key).to_string(),
                        NetworkPolicyRule {
                            name: (*key).to_string(),
                            endpoints: vec![NetworkEndpoint {
                                host: (*host).to_string(),
                                port: 443,
                                ..NetworkEndpoint::default()
                            }],
                            ..NetworkPolicyRule::default()
                        },
                    )
                })
                .collect(),
            ..SandboxPolicy::default()
        }
    }
}
