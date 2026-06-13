// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared sandbox policy parsing and defaults for `OpenShell`.
//!
//! Provides bidirectional YAML↔proto conversion for sandbox policies.
//! YAML schema types and pure parsing logic live in `openshell-policy-schema`;
//! this crate adds the proto conversion layer on top.

mod compose;
mod merge;

use miette::Result;
use openshell_core::proto::{
    FilesystemPolicy, GraphqlOperation, L7Allow, L7DenyRule, L7QueryMatcher, L7Rule,
    LandlockPolicy, NetworkBinary, NetworkEndpoint, NetworkPolicyRule, ProcessPolicy,
    SandboxPolicy,
};
use openshell_policy_schema::{
    FilesystemDef, GraphqlOperationDef, L7AllowDef, L7DenyRuleDef, L7RuleDef, LandlockDef,
    NetworkBinaryDef, NetworkEndpointDef, NetworkPolicyRuleDef, PolicyFile, ProcessDef,
    QueryAnyDef, QueryMatcherDef,
};

pub use compose::{ProviderPolicyLayer, compose_effective_policy, provider_rule_name};
pub use merge::{
    PolicyMergeError, PolicyMergeOp, PolicyMergeResult, PolicyMergeWarning, generated_rule_name,
    merge_policy, policy_covers_rule,
};

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
                    .map(|e| {
                        // Normalize port/ports: ports takes precedence, else
                        // single port is promoted to ports array.
                        let normalized_ports: Vec<u32> = if !e.ports.is_empty() {
                            e.ports.into_iter().map(u32::from).collect()
                        } else if e.port > 0 {
                            vec![u32::from(e.port)]
                        } else {
                            vec![]
                        };
                        NetworkEndpoint {
                            host: e.host,
                            path: e.path,
                            port: normalized_ports.first().copied().unwrap_or(0),
                            ports: normalized_ports,
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
                                        operation_type: r.allow.operation_type,
                                        operation_name: r.allow.operation_name,
                                        fields: r.allow.fields,
                                        query: r
                                            .allow
                                            .query
                                            .into_iter()
                                            .map(|(key, matcher)| {
                                                let proto = match matcher {
                                                    QueryMatcherDef::Glob(glob) => {
                                                        L7QueryMatcher { glob, any: vec![] }
                                                    }
                                                    QueryMatcherDef::Any(any) => L7QueryMatcher {
                                                        glob: String::new(),
                                                        any: any.any,
                                                    },
                                                };
                                                (key, proto)
                                            })
                                            .collect(),
                                    }),
                                })
                                .collect(),
                            allowed_ips: e.allowed_ips,
                            deny_rules: e
                                .deny_rules
                                .into_iter()
                                .map(|d| L7DenyRule {
                                    method: d.method,
                                    path: d.path,
                                    command: d.command,
                                    operation_type: d.operation_type,
                                    operation_name: d.operation_name,
                                    fields: d.fields,
                                    query: d
                                        .query
                                        .into_iter()
                                        .map(|(key, matcher)| {
                                            let proto = match matcher {
                                                QueryMatcherDef::Glob(glob) => {
                                                    L7QueryMatcher { glob, any: vec![] }
                                                }
                                                QueryMatcherDef::Any(any) => L7QueryMatcher {
                                                    glob: String::new(),
                                                    any: any.any,
                                                },
                                            };
                                            (key, proto)
                                        })
                                        .collect(),
                                })
                                .collect(),
                            allow_encoded_slash: e.allow_encoded_slash,
                            websocket_credential_rewrite: e.websocket_credential_rewrite,
                            request_body_credential_rewrite: e.request_body_credential_rewrite,
                            // Advisor provenance is internal runtime state, not
                            // a user-authored policy schema field.
                            advisor_proposed: false,
                            persisted_queries: e.persisted_queries,
                            graphql_persisted_queries: e
                                .graphql_persisted_queries
                                .into_iter()
                                .map(|(key, op)| {
                                    (
                                        key,
                                        GraphqlOperation {
                                            operation_type: op.operation_type,
                                            operation_name: op.operation_name,
                                            fields: op.fields,
                                        },
                                    )
                                })
                                .collect(),
                            graphql_max_body_bytes: e.graphql_max_body_bytes,
                        }
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
    }
}

// ---------------------------------------------------------------------------
// Proto → YAML conversion
// ---------------------------------------------------------------------------

fn from_proto(policy: &SandboxPolicy) -> PolicyFile {
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
                    .map(|e| {
                        // Use compact form: if ports has exactly 1 element,
                        // emit port (scalar). If >1, emit ports (array).
                        // Proto uses u32; YAML uses u16. Clamp at boundary.
                        let clamp = |v: u32| -> u16 { v.min(65535) as u16 };
                        let (port, ports) = if e.ports.len() > 1 {
                            (0, e.ports.iter().map(|&p| clamp(p)).collect())
                        } else {
                            (clamp(e.ports.first().copied().unwrap_or(e.port)), vec![])
                        };
                        NetworkEndpointDef {
                            host: e.host.clone(),
                            path: e.path.clone(),
                            port,
                            ports,
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
                                            operation_type: a.operation_type,
                                            operation_name: a.operation_name,
                                            fields: a.fields,
                                            query: a
                                                .query
                                                .into_iter()
                                                .map(|(key, matcher)| {
                                                    let yaml_matcher = if matcher.any.is_empty() {
                                                        QueryMatcherDef::Glob(matcher.glob)
                                                    } else {
                                                        QueryMatcherDef::Any(QueryAnyDef {
                                                            any: matcher.any,
                                                        })
                                                    };
                                                    (key, yaml_matcher)
                                                })
                                                .collect(),
                                        },
                                    }
                                })
                                .collect(),
                            allowed_ips: e.allowed_ips.clone(),
                            deny_rules: e
                                .deny_rules
                                .iter()
                                .map(|d| L7DenyRuleDef {
                                    method: d.method.clone(),
                                    path: d.path.clone(),
                                    command: d.command.clone(),
                                    operation_type: d.operation_type.clone(),
                                    operation_name: d.operation_name.clone(),
                                    fields: d.fields.clone(),
                                    query: d
                                        .query
                                        .iter()
                                        .map(|(key, matcher)| {
                                            let yaml_matcher = if matcher.any.is_empty() {
                                                QueryMatcherDef::Glob(matcher.glob.clone())
                                            } else {
                                                QueryMatcherDef::Any(QueryAnyDef {
                                                    any: matcher.any.clone(),
                                                })
                                            };
                                            (key.clone(), yaml_matcher)
                                        })
                                        .collect(),
                                })
                                .collect(),
                            allow_encoded_slash: e.allow_encoded_slash,
                            websocket_credential_rewrite: e.websocket_credential_rewrite,
                            request_body_credential_rewrite: e.request_body_credential_rewrite,
                            persisted_queries: e.persisted_queries.clone(),
                            graphql_persisted_queries: e
                                .graphql_persisted_queries
                                .iter()
                                .map(|(key, op)| {
                                    (
                                        key.clone(),
                                        GraphqlOperationDef {
                                            operation_type: op.operation_type.clone(),
                                            operation_name: op.operation_name.clone(),
                                            fields: op.fields.clone(),
                                        },
                                    )
                                })
                                .collect(),
                            graphql_max_body_bytes: e.graphql_max_body_bytes,
                        }
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
    openshell_policy_schema::parse_policy(yaml).map(to_proto)
}

/// Serialize a proto sandbox policy to a YAML string.
///
/// This is the inverse of [`parse_sandbox_policy`] — the output uses the
/// canonical YAML field names (e.g. `filesystem_policy`, not `filesystem`)
/// and is round-trippable through `parse_sandbox_policy`.
pub fn serialize_sandbox_policy(policy: &SandboxPolicy) -> Result<String> {
    openshell_policy_schema::serialize_policy(&from_proto(policy))
}

/// Convert a proto sandbox policy into the canonical policy JSON representation.
///
/// The shape mirrors the YAML schema used by [`serialize_sandbox_policy`], so
/// automation can use the same documented field names in either format.
pub fn sandbox_policy_to_json_value(policy: &SandboxPolicy) -> Result<serde_json::Value> {
    openshell_policy_schema::policy_to_json_value(&from_proto(policy))
}

/// Serialize a proto sandbox policy to a pretty-printed JSON string.
pub fn serialize_sandbox_policy_json(policy: &SandboxPolicy) -> Result<String> {
    openshell_policy_schema::serialize_policy_json(&from_proto(policy))
}

/// Load a sandbox policy from an explicit source.
///
/// Resolution order:
/// 1. `cli_path` argument (e.g. from a `--policy` flag)
/// 2. `OPENSHELL_SANDBOX_POLICY` environment variable
///
/// Returns `Ok(None)` when no policy source is configured, allowing the
/// caller to omit the policy and let the server / sandbox apply its own
/// default.
pub fn load_sandbox_policy(cli_path: Option<&str>) -> Result<Option<SandboxPolicy>> {
    Ok(openshell_policy_schema::load_policy(cli_path)?.map(to_proto))
}

pub use openshell_policy_schema::{CONTAINER_POLICY_PATH, LEGACY_CONTAINER_POLICY_PATH};

/// Return a restrictive default policy suitable for sandboxes that have no
/// explicit policy configured.
///
/// This policy grants filesystem access to standard system paths, runs as the
/// `sandbox` user, enables Landlock in best-effort mode, and **blocks all
/// network access** (no network policies, no inference routing).
pub fn restrictive_default_policy() -> SandboxPolicy {
    to_proto(openshell_policy_schema::restrictive_default())
}

/// Ensure the policy has `run_as_user: sandbox` and `run_as_group: sandbox`.
///
/// If the process section is missing, or either field is empty, this fills in
/// the required `"sandbox"` value. Call this before validation so that
/// policies without an explicit process section get the correct default.
pub fn ensure_sandbox_process_identity(policy: &mut SandboxPolicy) {
    let process = policy.process.get_or_insert_with(ProcessPolicy::default);
    if process.run_as_user.is_empty() {
        process.run_as_user = "sandbox".into();
    }
    if process.run_as_group.is_empty() {
        process.run_as_group = "sandbox".into();
    }
}

// ---------------------------------------------------------------------------
// Policy safety validation
// ---------------------------------------------------------------------------

pub use openshell_policy_schema::PolicyViolation;

/// Validate that a sandbox policy does not contain unsafe content.
///
/// Delegates to [`openshell_policy_schema::validate_policy`] via [`from_proto`].
/// See that function for the full list of checks performed.
pub fn validate_sandbox_policy(
    policy: &SandboxPolicy,
) -> std::result::Result<(), Vec<PolicyViolation>> {
    openshell_policy_schema::validate_policy(&from_proto(policy))
}

/// Normalize a filesystem path by collapsing redundant separators
/// and removing trailing slashes, without requiring the path to exist on disk.
///
/// This is a lexical normalization only — it does NOT resolve symlinks or
/// check the filesystem.
pub fn normalize_path(path: &str) -> String {
    openshell_policy_schema::normalize_path(path)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the serialized YAML uses `filesystem_policy` (not
    /// `filesystem`) so it can be fed back to `parse_sandbox_policy`.
    #[test]
    fn serialized_yaml_uses_filesystem_policy_key() {
        let proto = restrictive_default_policy();
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

    /// Verify that JSON serialization uses the same canonical schema keys as YAML.
    #[test]
    fn serialized_json_uses_policy_schema_keys() {
        let proto = parse_sandbox_policy(
            r"
version: 1
network_policies:
  github:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: https
    binaries:
      - path: /usr/bin/curl
",
        )
        .expect("parse failed");
        let json = sandbox_policy_to_json_value(&proto).expect("serialize failed");

        assert_eq!(json["version"], serde_json::json!(1));
        assert!(json.get("filesystem").is_none());
        assert!(json.get("network_policies").is_some());
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
        let yaml = r"
version: 1
network_policies:
  my_api:
    name: my-custom-api-name
    endpoints:
      - host: api.example.com
        port: 443
    binaries:
      - path: /usr/bin/curl
";
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        assert_eq!(proto1.network_policies["my_api"].name, "my-custom-api-name");

        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");
        assert_eq!(proto2.network_policies["my_api"].name, "my-custom-api-name");
    }

    #[test]
    fn restrictive_default_has_no_network_policies() {
        let policy = restrictive_default_policy();
        assert!(
            policy.network_policies.is_empty(),
            "restrictive default must block all network"
        );
    }

    #[test]
    fn restrictive_default_has_filesystem_policy() {
        let policy = restrictive_default_policy();
        let fs = policy.filesystem.expect("must have filesystem policy");
        assert!(fs.include_workdir);
        assert!(
            fs.read_only.iter().any(|p| p == "/usr"),
            "read_only should contain /usr"
        );
        assert!(
            fs.read_write.iter().any(|p| p == "/sandbox"),
            "read_write should contain /sandbox"
        );
        assert!(
            fs.read_write.iter().any(|p| p == "/tmp"),
            "read_write should contain /tmp"
        );
    }

    #[test]
    fn restrictive_default_has_process_identity() {
        let policy = restrictive_default_policy();
        let proc = policy.process.expect("must have process policy");
        assert_eq!(proc.run_as_user, "sandbox");
        assert_eq!(proc.run_as_group, "sandbox");
    }

    #[test]
    fn restrictive_default_has_landlock() {
        let policy = restrictive_default_policy();
        let ll = policy.landlock.expect("must have landlock policy");
        assert_eq!(ll.compatibility, "best_effort");
    }

    #[test]
    fn restrictive_default_version_is_one() {
        let policy = restrictive_default_policy();
        assert_eq!(policy.version, 1);
    }

    #[test]
    fn parse_minimal_policy_yaml() {
        let yaml = "version: 1\n";
        let policy = parse_sandbox_policy(yaml).expect("should parse");
        assert_eq!(policy.version, 1);
        assert!(policy.network_policies.is_empty());
        assert!(policy.filesystem.is_none());
    }

    #[test]
    fn parse_policy_with_network_rules() {
        let yaml = r"
version: 1
network_policies:
  test:
    name: test_policy
    endpoints:
      - { host: example.com, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
";
        let policy = parse_sandbox_policy(yaml).expect("should parse");
        assert_eq!(policy.network_policies.len(), 1);
        let rule = &policy.network_policies["test"];
        assert_eq!(rule.name, "test_policy");
        assert_eq!(rule.endpoints.len(), 1);
        assert_eq!(rule.endpoints[0].host, "example.com");
        assert_eq!(rule.endpoints[0].port, 443);
        assert_eq!(rule.binaries.len(), 1);
        assert_eq!(rule.binaries[0].path, "/usr/bin/curl");
    }

    #[test]
    fn parse_l7_query_matchers_and_round_trip() {
        let yaml = r#"
version: 1
network_policies:
  query_test:
    name: query_test
    endpoints:
      - host: api.example.com
        port: 8080
        protocol: rest
        rules:
          - allow:
              method: GET
              path: /download
              query:
                slug: "my-*"
                tag:
                  any: ["foo-*", "bar-*"]
    binaries:
      - path: /usr/bin/curl
"#;
        let proto = parse_sandbox_policy(yaml).expect("parse failed");
        let allow = proto.network_policies["query_test"].endpoints[0].rules[0]
            .allow
            .as_ref()
            .expect("allow");
        assert_eq!(allow.query["slug"].glob, "my-*");
        assert_eq!(allow.query["slug"].any, Vec::<String>::new());
        assert_eq!(allow.query["tag"].any, vec!["foo-*", "bar-*"]);
        assert!(allow.query["tag"].glob.is_empty());

        let yaml_out = serialize_sandbox_policy(&proto).expect("serialize failed");
        let proto_round_trip = parse_sandbox_policy(&yaml_out).expect("re-parse failed");
        let allow_round_trip = proto_round_trip.network_policies["query_test"].endpoints[0].rules
            [0]
        .allow
        .as_ref()
        .expect("allow");
        assert_eq!(allow_round_trip.query["slug"].glob, "my-*");
        assert_eq!(allow_round_trip.query["tag"].any, vec!["foo-*", "bar-*"]);
    }

    #[test]
    fn parse_rejects_unknown_fields() {
        let yaml = "version: 1\nbogus_field: true\n";
        assert!(parse_sandbox_policy(yaml).is_err());
    }

    #[test]
    fn ensure_sandbox_process_identity_fills_defaults() {
        let mut policy = restrictive_default_policy();
        policy.process = None;
        ensure_sandbox_process_identity(&mut policy);
        let proc = policy.process.unwrap();
        assert_eq!(proc.run_as_user, "sandbox");
        assert_eq!(proc.run_as_group, "sandbox");
    }

    #[test]
    fn ensure_sandbox_process_identity_fills_empty_strings() {
        let mut policy = restrictive_default_policy();
        policy.process = Some(ProcessPolicy {
            run_as_user: String::new(),
            run_as_group: String::new(),
        });
        ensure_sandbox_process_identity(&mut policy);
        let proc = policy.process.unwrap();
        assert_eq!(proc.run_as_user, "sandbox");
        assert_eq!(proc.run_as_group, "sandbox");
    }

    #[test]
    fn ensure_sandbox_process_identity_preserves_sandbox() {
        let mut policy = restrictive_default_policy();
        ensure_sandbox_process_identity(&mut policy);
        let proc = policy.process.unwrap();
        assert_eq!(proc.run_as_user, "sandbox");
        assert_eq!(proc.run_as_group, "sandbox");
    }

    #[test]
    fn container_policy_path_is_expected() {
        assert_eq!(CONTAINER_POLICY_PATH, "/etc/openshell/policy.yaml");
    }

    #[test]
    fn legacy_container_policy_path_is_expected() {
        assert_eq!(LEGACY_CONTAINER_POLICY_PATH, "/etc/navigator/policy.yaml");
    }

    // ---- validate_sandbox_policy delegation smoke tests ----
    //
    // Full validation logic lives in openshell_policy_schema::validate_policy.
    // These tests verify that violations survive the from_proto roundtrip for
    // each of the three field categories the validator inspects.

    #[test]
    fn validate_sandbox_policy_surfaces_process_violation() {
        let mut policy = restrictive_default_policy();
        policy.process = Some(ProcessPolicy {
            run_as_user: "root".into(),
            run_as_group: "sandbox".into(),
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(violations.iter().any(|v| matches!(
            v,
            PolicyViolation::InvalidProcessIdentity {
                field: "run_as_user",
                ..
            }
        )));
    }

    #[test]
    fn validate_sandbox_policy_surfaces_filesystem_violation() {
        let mut policy = restrictive_default_policy();
        policy.filesystem = Some(FilesystemPolicy {
            include_workdir: true,
            read_only: vec!["/usr/../etc/shadow".into()],
            read_write: vec![],
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::PathTraversal { .. }))
        );
    }

    #[test]
    fn validate_sandbox_policy_surfaces_network_violation() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "bad".into(),
            NetworkPolicyRule {
                name: "bad-rule".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "*.com".into(),
                    port: 443,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::TldWildcard { .. }))
        );
    }

    #[test]
    fn normalize_path_collapses_separators() {
        assert_eq!(normalize_path("/usr//lib"), "/usr/lib");
        assert_eq!(normalize_path("/usr/./lib"), "/usr/lib");
        assert_eq!(normalize_path("/tmp/"), "/tmp");
    }

    #[test]
    fn normalize_path_preserves_parent_dir() {
        // normalize_path preserves ".." — validation catches it separately
        assert_eq!(normalize_path("/usr/../etc"), "/usr/../etc");
    }

    #[test]
    fn policy_violation_display() {
        let v = PolicyViolation::InvalidProcessIdentity {
            field: "run_as_user",
            value: "root".into(),
        };
        let s = format!("{v}");
        assert!(s.contains("root"));
        assert!(s.contains("run_as_user"));
        assert!(s.contains("sandbox"));
    }

    // ---- Multi-port and host wildcard tests ----

    #[test]
    fn parse_ports_array() {
        let yaml = r"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - { host: api.example.com, ports: [80, 443] }
    binaries:
      - { path: /usr/bin/curl }
";
        let policy = parse_sandbox_policy(yaml).expect("should parse");
        let ep = &policy.network_policies["test"].endpoints[0];
        assert_eq!(ep.ports, vec![80, 443]);
        // port should be set to first element for backwards compat
        assert_eq!(ep.port, 80);
    }

    #[test]
    fn parse_single_port_normalized_to_ports() {
        let yaml = r"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - { host: api.example.com, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
";
        let policy = parse_sandbox_policy(yaml).expect("should parse");
        let ep = &policy.network_policies["test"].endpoints[0];
        assert_eq!(ep.ports, vec![443]);
        assert_eq!(ep.port, 443);
    }

    #[test]
    fn round_trip_preserves_endpoint_path() {
        let yaml = r#"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - host: api.example.com
        port: 443
        path: "/graphql"
        protocol: graphql
        rules:
          - allow:
              operation_type: query
    binaries:
      - { path: /usr/bin/curl }
"#;
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");

        let ep1 = &proto1.network_policies["test"].endpoints[0];
        let ep2 = &proto2.network_policies["test"].endpoints[0];
        assert_eq!(ep1.path, "/graphql");
        assert_eq!(ep1.path, ep2.path);
    }

    #[test]
    fn round_trip_preserves_multi_port() {
        let yaml = r"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - host: api.example.com
        ports:
          - 80
          - 443
    binaries:
      - { path: /usr/bin/curl }
";
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");

        let ep1 = &proto1.network_policies["test"].endpoints[0];
        let ep2 = &proto2.network_policies["test"].endpoints[0];
        assert_eq!(ep1.ports, ep2.ports);
        assert_eq!(ep1.ports, vec![80, 443]);
    }

    #[test]
    fn serialize_single_port_uses_compact_form() {
        let yaml = r"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - { host: api.example.com, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
";
        let proto = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto).expect("serialize failed");
        // Should use compact `port: 443` form, not `ports: [443]`
        assert!(
            yaml_out.contains("port: 443"),
            "Single port should serialize as compact form, got:\n{yaml_out}"
        );
        assert!(
            !yaml_out.contains("ports:"),
            "Single port should not produce ports array, got:\n{yaml_out}"
        );
    }

    #[test]
    fn parse_wildcard_host() {
        let yaml = r#"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - { host: "*.example.com", port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#;
        let policy = parse_sandbox_policy(yaml).expect("should parse");
        let ep = &policy.network_policies["test"].endpoints[0];
        assert_eq!(ep.host, "*.example.com");
    }

    #[test]
    fn round_trip_preserves_wildcard_host() {
        let yaml = r#"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - host: "*.example.com"
        port: 443
    binaries:
      - { path: /usr/bin/curl }
"#;
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");
        assert_eq!(
            proto1.network_policies["test"].endpoints[0].host,
            proto2.network_policies["test"].endpoints[0].host
        );
    }

    #[test]
    fn parse_deny_rules_from_yaml() {
        let yaml = r#"
version: 1
network_policies:
  github:
    name: github
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        access: read-write
        deny_rules:
          - method: POST
            path: "/repos/*/pulls/*/reviews"
          - method: PUT
            path: "/repos/*/branches/*/protection"
    binaries:
      - path: /usr/bin/curl
"#;
        let proto = parse_sandbox_policy(yaml).expect("parse failed");
        let ep = &proto.network_policies["github"].endpoints[0];
        assert_eq!(ep.deny_rules.len(), 2);
        assert_eq!(ep.deny_rules[0].method, "POST");
        assert_eq!(ep.deny_rules[0].path, "/repos/*/pulls/*/reviews");
        assert_eq!(ep.deny_rules[1].method, "PUT");
        assert_eq!(ep.deny_rules[1].path, "/repos/*/branches/*/protection");
    }

    #[test]
    fn round_trip_preserves_deny_rules() {
        let yaml = r#"
version: 1
network_policies:
  github:
    name: github
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        access: full
        deny_rules:
          - method: POST
            path: "/repos/*/pulls/*/reviews"
          - method: DELETE
            path: "/repos/*/branches/*/protection"
            query:
              force: "true"
    binaries:
      - path: /usr/bin/curl
"#;
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");

        let ep1 = &proto1.network_policies["github"].endpoints[0];
        let ep2 = &proto2.network_policies["github"].endpoints[0];
        assert_eq!(ep1.deny_rules.len(), ep2.deny_rules.len());
        assert_eq!(ep2.deny_rules[0].method, "POST");
        assert_eq!(ep2.deny_rules[0].path, "/repos/*/pulls/*/reviews");
        assert_eq!(ep2.deny_rules[1].method, "DELETE");
        assert_eq!(ep2.deny_rules[1].query["force"].glob, "true");
    }

    #[test]
    fn parse_deny_rules_with_query_any() {
        let yaml = r#"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        access: full
        deny_rules:
          - method: POST
            path: /action
            query:
              type:
                any: ["admin-*", "root-*"]
    binaries:
      - path: /usr/bin/curl
"#;
        let proto = parse_sandbox_policy(yaml).expect("parse failed");
        let deny = &proto.network_policies["test"].endpoints[0].deny_rules[0];
        assert_eq!(deny.query["type"].any, vec!["admin-*", "root-*"]);
    }

    #[test]
    fn round_trip_preserves_graphql_policy_fields() {
        let yaml = r"
version: 1
network_policies:
  github_graphql:
    name: github_graphql
    endpoints:
      - host: api.github.com
        port: 443
        protocol: graphql
        enforcement: enforce
        persisted_queries: allow_registered
        graphql_max_body_bytes: 131072
        graphql_persisted_queries:
          abc123:
            operation_type: query
            operation_name: Viewer
            fields: [viewer]
        rules:
          - allow:
              operation_type: query
              fields: [viewer, repository]
          - allow:
              operation_type: mutation
              operation_name: Issue*
              fields: [createIssue]
        deny_rules:
          - operation_type: mutation
            fields: [deleteRepository]
    binaries:
      - path: /usr/bin/curl
";
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");

        let ep = &proto2.network_policies["github_graphql"].endpoints[0];
        assert_eq!(ep.protocol, "graphql");
        assert_eq!(ep.persisted_queries, "allow_registered");
        assert_eq!(ep.graphql_max_body_bytes, 131_072);
        assert_eq!(
            ep.graphql_persisted_queries["abc123"].operation_type,
            "query"
        );
        assert_eq!(ep.rules[0].allow.as_ref().unwrap().operation_type, "query");
        assert_eq!(ep.rules[1].allow.as_ref().unwrap().operation_name, "Issue*");
        assert_eq!(ep.deny_rules[0].operation_type, "mutation");
        assert_eq!(ep.deny_rules[0].fields, vec!["deleteRepository"]);
    }

    #[test]
    fn round_trip_preserves_websocket_credential_rewrite() {
        let yaml = r"
version: 1
network_policies:
  discord_gateway:
    name: discord_gateway
    endpoints:
      - host: gateway.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
        websocket_credential_rewrite: true
    binaries:
      - path: /usr/bin/node
";
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");

        let ep = &proto2.network_policies["discord_gateway"].endpoints[0];
        assert_eq!(ep.protocol, "rest");
        assert!(ep.websocket_credential_rewrite);
        assert!(yaml_out.contains("websocket_credential_rewrite: true"));
    }

    #[test]
    fn round_trip_preserves_request_body_credential_rewrite() {
        let yaml = r"
version: 1
network_policies:
  slack_api:
    name: slack_api
    endpoints:
      - host: slack.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-write
        request_body_credential_rewrite: true
    binaries:
      - path: /usr/bin/node
";
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");

        let ep = &proto2.network_policies["slack_api"].endpoints[0];
        assert_eq!(ep.protocol, "rest");
        assert!(ep.request_body_credential_rewrite);
        assert!(yaml_out.contains("request_body_credential_rewrite: true"));
    }

    #[test]
    fn websocket_credential_rewrite_defaults_false() {
        let yaml = r"
version: 1
network_policies:
  gateway:
    endpoints:
      - host: gateway.example.com
        port: 443
        protocol: rest
        access: full
    binaries:
      - path: /usr/bin/node
";
        let proto = parse_sandbox_policy(yaml).expect("parse failed");
        let ep = &proto.network_policies["gateway"].endpoints[0];
        assert!(!ep.websocket_credential_rewrite);
        assert!(!ep.request_body_credential_rewrite);
    }

    #[test]
    fn parse_rejects_unknown_fields_in_deny_rule() {
        let yaml = r"
version: 1
network_policies:
  test:
    endpoints:
      - host: example.com
        port: 443
        deny_rules:
          - method: POST
            path: /foo
            bogus: true
";
        assert!(parse_sandbox_policy(yaml).is_err());
    }

    #[test]
    fn rejects_port_above_65535() {
        let yaml = r"
version: 1
network_policies:
  test:
    endpoints:
      - host: example.com
        port: 70000
";
        assert!(
            parse_sandbox_policy(yaml).is_err(),
            "port >65535 should fail to parse"
        );
    }
}
