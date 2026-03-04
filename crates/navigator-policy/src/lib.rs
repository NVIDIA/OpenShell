// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared sandbox policy parsing and defaults for NemoClaw.
//!
//! Provides bidirectional YAML↔proto conversion for sandbox policies, with a
//! built-in default policy embedded from `dev-sandbox-policy.yaml`.
//!
//! The serde types here are the **single canonical representation** of the YAML
//! policy schema. Both parsing (YAML→proto) and serialization (proto→YAML) use
//! these types, ensuring round-trip fidelity.

use std::collections::BTreeMap;

use miette::{IntoDiagnostic, Result, WrapErr};
use navigator_core::proto::{
    self, FilesystemPolicy, InferenceApiPattern, L7Allow, L7Rule, LandlockPolicy, NetworkBinary,
    NetworkEndpoint, NetworkPolicyRule, ProcessPolicy, SandboxPolicy,
};
use serde::{Deserialize, Serialize};

/// Built-in default sandbox policy YAML (embedded at compile time).
const DEFAULT_SANDBOX_POLICY_YAML: &str = include_str!("../../../dev-sandbox-policy.yaml");

// ---------------------------------------------------------------------------
// YAML serde types (canonical — used for both parsing and serialization)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inference: Option<InferenceDef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    filesystem_policy: Option<FilesystemDef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    landlock: Option<LandlockDef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    process: Option<ProcessDef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    network_policies: BTreeMap<String, NetworkPolicyRuleDef>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilesystemDef {
    #[serde(default)]
    include_workdir: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    read_only: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    read_write: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LandlockDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    compatibility: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    run_as_user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    run_as_group: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InferenceDef {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allowed_routes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    api_patterns: Vec<InferenceApiPatternDef>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InferenceApiPatternDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    path_glob: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    protocol: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    kind: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkPolicyRuleDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    endpoints: Vec<NetworkEndpointDef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    binaries: Vec<NetworkBinaryDef>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkEndpointDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    host: String,
    port: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    protocol: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    tls: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    enforcement: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    access: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rules: Vec<L7RuleDef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allowed_ips: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct L7RuleDef {
    allow: L7AllowDef,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct L7AllowDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    command: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkBinaryDef {
    path: String,
    /// Deprecated: ignored. Kept for backward compat with existing YAML files.
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    harness: bool,
}

// ---------------------------------------------------------------------------
// YAML → proto conversion
// ---------------------------------------------------------------------------

fn to_proto(raw: PolicyFile) -> SandboxPolicy {
    let network_policies = raw
        .network_policies
        .into_iter()
        .map(|(key, rule)| {
            let proto_rule = NetworkPolicyRule {
                name: if rule.name.is_empty() {
                    key.clone()
                } else {
                    rule.name
                },
                endpoints: rule
                    .endpoints
                    .into_iter()
                    .map(|e| NetworkEndpoint {
                        host: e.host,
                        port: e.port,
                        protocol: e.protocol,
                        tls: e.tls,
                        enforcement: e.enforcement,
                        access: e.access,
                        rules: e
                            .rules
                            .into_iter()
                            .map(|r| L7Rule {
                                allow: Some(L7Allow {
                                    method: r.allow.method,
                                    path: r.allow.path,
                                    command: r.allow.command,
                                }),
                            })
                            .collect(),
                        allowed_ips: e.allowed_ips,
                    })
                    .collect(),
                binaries: rule
                    .binaries
                    .into_iter()
                    .map(|b| NetworkBinary {
                        path: b.path,
                        ..Default::default()
                    })
                    .collect(),
            };
            (key, proto_rule)
        })
        .collect();

    SandboxPolicy {
        version: raw.version,
        filesystem: raw.filesystem_policy.map(|fs| FilesystemPolicy {
            include_workdir: fs.include_workdir,
            read_only: fs.read_only,
            read_write: fs.read_write,
        }),
        landlock: raw.landlock.map(|ll| LandlockPolicy {
            compatibility: ll.compatibility,
        }),
        process: raw.process.map(|p| ProcessPolicy {
            run_as_user: p.run_as_user,
            run_as_group: p.run_as_group,
        }),
        network_policies,
        inference: raw.inference.map(|inf| proto::InferencePolicy {
            allowed_routes: inf.allowed_routes,
            api_patterns: inf
                .api_patterns
                .into_iter()
                .map(|p| InferenceApiPattern {
                    method: p.method,
                    path_glob: p.path_glob,
                    protocol: p.protocol,
                    kind: p.kind,
                })
                .collect(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Proto → YAML conversion
// ---------------------------------------------------------------------------

fn from_proto(policy: &SandboxPolicy) -> PolicyFile {
    let inference = policy.inference.as_ref().map(|inf| InferenceDef {
        allowed_routes: inf.allowed_routes.clone(),
        api_patterns: inf
            .api_patterns
            .iter()
            .map(|p| InferenceApiPatternDef {
                method: p.method.clone(),
                path_glob: p.path_glob.clone(),
                protocol: p.protocol.clone(),
                kind: p.kind.clone(),
            })
            .collect(),
    });

    let filesystem_policy = policy.filesystem.as_ref().map(|fs| FilesystemDef {
        include_workdir: fs.include_workdir,
        read_only: fs.read_only.clone(),
        read_write: fs.read_write.clone(),
    });

    let landlock = policy.landlock.as_ref().map(|ll| LandlockDef {
        compatibility: ll.compatibility.clone(),
    });

    let process = policy.process.as_ref().and_then(|p| {
        if p.run_as_user.is_empty() && p.run_as_group.is_empty() {
            None
        } else {
            Some(ProcessDef {
                run_as_user: p.run_as_user.clone(),
                run_as_group: p.run_as_group.clone(),
            })
        }
    });

    let network_policies = policy
        .network_policies
        .iter()
        .map(|(key, rule)| {
            let yaml_rule = NetworkPolicyRuleDef {
                name: rule.name.clone(),
                endpoints: rule
                    .endpoints
                    .iter()
                    .map(|e| NetworkEndpointDef {
                        host: e.host.clone(),
                        port: e.port,
                        protocol: e.protocol.clone(),
                        tls: e.tls.clone(),
                        enforcement: e.enforcement.clone(),
                        access: e.access.clone(),
                        rules: e
                            .rules
                            .iter()
                            .map(|r| {
                                let a = r.allow.clone().unwrap_or_default();
                                L7RuleDef {
                                    allow: L7AllowDef {
                                        method: a.method,
                                        path: a.path,
                                        command: a.command,
                                    },
                                }
                            })
                            .collect(),
                        allowed_ips: e.allowed_ips.clone(),
                    })
                    .collect(),
                binaries: rule
                    .binaries
                    .iter()
                    .map(|b| NetworkBinaryDef {
                        path: b.path.clone(),
                        harness: false,
                    })
                    .collect(),
            };
            (key.clone(), yaml_rule)
        })
        .collect();

    PolicyFile {
        version: policy.version,
        inference,
        filesystem_policy,
        landlock,
        process,
        network_policies,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a sandbox policy from a YAML string.
pub fn parse_sandbox_policy(yaml: &str) -> Result<SandboxPolicy> {
    let raw: PolicyFile = serde_yaml::from_str(yaml)
        .into_diagnostic()
        .wrap_err("failed to parse sandbox policy YAML")?;
    Ok(to_proto(raw))
}

/// Serialize a proto sandbox policy to a YAML string.
///
/// This is the inverse of [`parse_sandbox_policy`] — the output uses the
/// canonical YAML field names (e.g. `filesystem_policy`, not `filesystem`)
/// and is round-trippable through `parse_sandbox_policy`.
pub fn serialize_sandbox_policy(policy: &SandboxPolicy) -> Result<String> {
    let yaml_repr = from_proto(policy);
    serde_yaml::to_string(&yaml_repr)
        .into_diagnostic()
        .wrap_err("failed to serialize policy to YAML")
}

/// Load a sandbox policy with the standard resolution order:
///
/// 1. `cli_path` argument (e.g. from a `--policy` flag)
/// 2. `NEMOCLAW_SANDBOX_POLICY` environment variable
/// 3. Built-in default (`dev-sandbox-policy.yaml`)
pub fn load_sandbox_policy(cli_path: Option<&str>) -> Result<SandboxPolicy> {
    let contents = if let Some(p) = cli_path {
        let path = std::path::Path::new(p);
        std::fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read sandbox policy from {}", path.display()))?
    } else if let Ok(policy_path) = std::env::var("NEMOCLAW_SANDBOX_POLICY") {
        let path = std::path::Path::new(&policy_path);
        std::fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read sandbox policy from {}", path.display()))?
    } else {
        DEFAULT_SANDBOX_POLICY_YAML.to_string()
    };
    parse_sandbox_policy(&contents)
}

/// Return the built-in default sandbox policy.
pub fn default_sandbox_policy() -> SandboxPolicy {
    // The embedded YAML is known-good; unwrap is safe.
    parse_sandbox_policy(DEFAULT_SANDBOX_POLICY_YAML)
        .expect("built-in dev-sandbox-policy.yaml must be valid")
}

/// Clear `run_as_user` / `run_as_group` from the policy's process section.
///
/// Call this when a custom image is specified, since the image may lack the
/// default "sandbox" user/group.
pub fn clear_process_identity(policy: &mut SandboxPolicy) {
    if let Some(ref mut process) = policy.process {
        process.run_as_user = String::new();
        process.run_as_group = String::new();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: parse the built-in default policy YAML → proto → YAML → proto
    /// and verify the two proto representations are identical.
    #[test]
    fn round_trip_default_policy() {
        let proto1 = parse_sandbox_policy(DEFAULT_SANDBOX_POLICY_YAML)
            .expect("failed to parse default policy");

        let yaml_str =
            serialize_sandbox_policy(&proto1).expect("failed to serialize policy to YAML");

        let proto2 = parse_sandbox_policy(&yaml_str).expect("failed to re-parse serialized policy");

        assert_eq!(proto1.version, proto2.version);
        assert_eq!(proto1.filesystem, proto2.filesystem);
        assert_eq!(proto1.landlock, proto2.landlock);
        assert_eq!(proto1.process, proto2.process);
        assert_eq!(proto1.inference, proto2.inference);

        // Compare network policies (proto HashMap ordering may differ, so
        // compare key-by-key).
        assert_eq!(
            proto1.network_policies.len(),
            proto2.network_policies.len(),
            "network policy count mismatch"
        );
        for (key, rule1) in &proto1.network_policies {
            let rule2 = proto2
                .network_policies
                .get(key)
                .unwrap_or_else(|| panic!("missing network policy key: {key}"));
            assert_eq!(rule1, rule2, "network policy mismatch for key: {key}");
        }
    }

    /// Verify that the serialized YAML uses `filesystem_policy` (not
    /// `filesystem`) so it can be fed back to `parse_sandbox_policy`.
    #[test]
    fn serialized_yaml_uses_filesystem_policy_key() {
        let proto = default_sandbox_policy();
        let yaml = serialize_sandbox_policy(&proto).expect("serialize failed");
        assert!(
            yaml.contains("filesystem_policy:"),
            "expected `filesystem_policy:` in YAML output, got:\n{yaml}"
        );
        assert!(
            !yaml.contains("\nfilesystem:"),
            "unexpected bare `filesystem:` key in YAML output"
        );
    }

    /// Verify that `allowed_ips` survives the round-trip.
    #[test]
    fn round_trip_preserves_allowed_ips() {
        let yaml = r#"
version: 1
network_policies:
  internal:
    name: internal
    endpoints:
      - host: db.internal.corp
        port: 5432
        allowed_ips:
          - "10.0.5.0/24"
          - "10.0.6.0/24"
    binaries:
      - path: /usr/bin/curl
"#;
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");

        let ep1 = &proto1.network_policies["internal"].endpoints[0];
        let ep2 = &proto2.network_policies["internal"].endpoints[0];
        assert_eq!(ep1.allowed_ips, ep2.allowed_ips);
        assert_eq!(ep1.allowed_ips, vec!["10.0.5.0/24", "10.0.6.0/24"]);
    }

    /// Verify that the network policy `name` field survives the round-trip.
    #[test]
    fn round_trip_preserves_policy_name() {
        let yaml = r#"
version: 1
network_policies:
  my_api:
    name: my-custom-api-name
    endpoints:
      - host: api.example.com
        port: 443
    binaries:
      - path: /usr/bin/curl
"#;
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        assert_eq!(proto1.network_policies["my_api"].name, "my-custom-api-name");

        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");
        assert_eq!(proto2.network_policies["my_api"].name, "my-custom-api-name");
    }

    /// Verify that `api_patterns` on inference survives the round-trip.
    #[test]
    fn round_trip_preserves_api_patterns() {
        let yaml = r#"
version: 1
inference:
  allowed_routes:
    - local
  api_patterns:
    - method: POST
      path_glob: "/v1/chat/completions"
      protocol: openai_chat_completions
      kind: chat_completion
"#;
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        assert_eq!(proto1.inference.as_ref().unwrap().api_patterns.len(), 1);

        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");

        let patterns1 = &proto1.inference.as_ref().unwrap().api_patterns;
        let patterns2 = &proto2.inference.as_ref().unwrap().api_patterns;
        assert_eq!(patterns1.len(), patterns2.len());
        assert_eq!(patterns1[0].method, patterns2[0].method);
        assert_eq!(patterns1[0].path_glob, patterns2[0].path_glob);
        assert_eq!(patterns1[0].protocol, patterns2[0].protocol);
        assert_eq!(patterns1[0].kind, patterns2[0].kind);
    }
}
