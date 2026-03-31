// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared sandbox policy parsing and defaults for OpenShell.
//!
//! Provides bidirectional YAML↔proto conversion for sandbox policies.
//!
//! The serde types here are the **single canonical representation** of the YAML
//! policy schema. Both parsing (YAML→proto) and serialization (proto→YAML) use
//! these types, ensuring round-trip fidelity.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::Path;

use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::proto::{
    FilesystemPolicy, L7Allow, L7QueryMatcher, L7Rule, LandlockPolicy, NetworkBinary,
    NetworkEndpoint, NetworkPolicyRule, ProcessPolicy, SandboxPolicy,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// YAML serde types (canonical — used for both parsing and serialization)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
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
    /// Single port (backwards compat). Mutually exclusive with `ports`.
    #[serde(default, skip_serializing_if = "is_zero")]
    port: u32,
    /// Multiple ports. When non-empty, this endpoint covers all listed ports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ports: Vec<u32>,
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

fn is_zero(v: &u32) -> bool {
    *v == 0
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    query: BTreeMap<String, QueryMatcherDef>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum QueryMatcherDef {
    Glob(String),
    Any(QueryAnyDef),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryAnyDef {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    any: Vec<String>,
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
                    .map(|e| {
                        // Normalize port/ports: ports takes precedence, else
                        // single port is promoted to ports array.
                        let normalized_ports = if !e.ports.is_empty() {
                            e.ports
                        } else if e.port > 0 {
                            vec![e.port]
                        } else {
                            vec![]
                        };
                        NetworkEndpoint {
                            host: e.host,
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
                        let (port, ports) = if e.ports.len() > 1 {
                            (0, e.ports.clone())
                        } else {
                            (e.ports.first().copied().unwrap_or(e.port), vec![])
                        };
                        NetworkEndpointDef {
                            host: e.host.clone(),
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
                                            query: a
                                                .query
                                                .into_iter()
                                                .map(|(key, matcher)| {
                                                    let yaml_matcher = if !matcher.any.is_empty() {
                                                        QueryMatcherDef::Any(QueryAnyDef {
                                                            any: matcher.any,
                                                        })
                                                    } else {
                                                        QueryMatcherDef::Glob(matcher.glob)
                                                    };
                                                    (key, yaml_matcher)
                                                })
                                                .collect(),
                                        },
                                    }
                                })
                                .collect(),
                            allowed_ips: e.allowed_ips.clone(),
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
    let contents = if let Some(p) = cli_path {
        let path = Path::new(p);
        std::fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read sandbox policy from {}", path.display()))?
    } else if let Ok(policy_path) = std::env::var("OPENSHELL_SANDBOX_POLICY") {
        let path = Path::new(&policy_path);
        std::fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read sandbox policy from {}", path.display()))?
    } else {
        return Ok(None);
    };
    parse_sandbox_policy(&contents).map(Some)
}

/// Well-known path where a sandbox container image can ship a policy YAML file.
///
/// When the gateway provides no policy at sandbox creation time, the sandbox
/// supervisor probes this path before falling back to the restrictive default.
pub const CONTAINER_POLICY_PATH: &str = "/etc/openshell/policy.yaml";

/// Legacy path used before the navigator → openshell rename.
///
/// Existing community sandbox images still ship their policy at this path.
/// The sandbox supervisor tries [`CONTAINER_POLICY_PATH`] first, then falls
/// back to this legacy path for backward compatibility.
pub const LEGACY_CONTAINER_POLICY_PATH: &str = "/etc/navigator/policy.yaml";

/// Return a restrictive default policy suitable for sandboxes that have no
/// explicit policy configured.
///
/// This policy grants filesystem access to standard system paths, runs as the
/// `sandbox` user, enables Landlock in best-effort mode, and **blocks all
/// network access** (no network policies, no inference routing).
pub fn restrictive_default_policy() -> SandboxPolicy {
    SandboxPolicy {
        version: 1,
        filesystem: Some(FilesystemPolicy {
            include_workdir: true,
            read_only: vec![
                "/usr".into(),
                "/lib".into(),
                "/proc".into(),
                "/dev/urandom".into(),
                "/app".into(),
                "/etc".into(),
                "/var/log".into(),
            ],
            read_write: vec!["/sandbox".into(), "/tmp".into(), "/dev/null".into()],
        }),
        landlock: Some(LandlockPolicy {
            compatibility: "best_effort".into(),
        }),
        process: Some(ProcessPolicy {
            run_as_user: "sandbox".into(),
            run_as_group: "sandbox".into(),
        }),
        network_policies: HashMap::new(),
    }
}

/// Ensure the policy has `run_as_user: sandbox` and `run_as_group: sandbox`.
///
/// If the process section is missing, or either field is empty, this fills in
/// the required `"sandbox"` value. Call this before validation so that
/// policies without an explicit process section get the correct default.
pub fn ensure_sandbox_process_identity(policy: &mut SandboxPolicy) {
    let process = policy
        .process
        .get_or_insert_with(|| ProcessPolicy::default());
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

/// Maximum number of filesystem paths (`read_only` + `read_write` combined).
const MAX_FILESYSTEM_PATHS: usize = 256;

/// Maximum length of any single filesystem path string.
const MAX_PATH_LENGTH: usize = 4096;

/// A safety violation found in a sandbox policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyViolation {
    /// `run_as_user` or `run_as_group` is not "sandbox".
    InvalidProcessIdentity { field: &'static str, value: String },
    /// A filesystem path contains `..` components.
    PathTraversal { path: String },
    /// A filesystem path is not absolute (does not start with `/`).
    RelativePath { path: String },
    /// A read-write filesystem path is overly broad (e.g. `/`).
    OverlyBroadPath { path: String },
    /// A filesystem path exceeds the maximum allowed length.
    FieldTooLong { path: String, length: usize },
    /// Too many filesystem paths in the policy.
    TooManyPaths { count: usize },
}

impl fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProcessIdentity { field, value } => {
                write!(f, "{field} must be 'sandbox', got '{value}'")
            }
            Self::PathTraversal { path } => {
                write!(f, "path contains '..' traversal component: {path}")
            }
            Self::RelativePath { path } => {
                write!(f, "path must be absolute (start with '/'): {path}")
            }
            Self::OverlyBroadPath { path } => {
                write!(f, "read-write path is overly broad: {path}")
            }
            Self::FieldTooLong { path, length } => {
                write!(
                    f,
                    "path exceeds maximum length ({length} > {MAX_PATH_LENGTH}): {path}"
                )
            }
            Self::TooManyPaths { count } => {
                write!(
                    f,
                    "too many filesystem paths ({count} > {MAX_FILESYSTEM_PATHS})"
                )
            }
        }
    }
}

/// Validate that a sandbox policy does not contain unsafe content.
///
/// Returns `Ok(())` if the policy is safe, or `Err(violations)` listing all
/// safety violations found. Callers decide how to handle violations (hard
/// error vs. logged warning).
///
/// Checks performed:
/// - `run_as_user` / `run_as_group` must be "sandbox"
/// - Filesystem paths must be absolute (start with `/`)
/// - Filesystem paths must not contain `..` components
/// - Read-write paths must not be overly broad (just `/`)
/// - Individual path lengths must not exceed [`MAX_PATH_LENGTH`]
/// - Total path count must not exceed [`MAX_FILESYSTEM_PATHS`]
pub fn validate_sandbox_policy(
    policy: &SandboxPolicy,
) -> std::result::Result<(), Vec<PolicyViolation>> {
    let mut violations = Vec::new();

    // Check process identity — must be "sandbox".
    // `ensure_sandbox_process_identity` should be called before this to
    // fill in defaults; anything other than "sandbox" is rejected.
    if let Some(ref process) = policy.process {
        if process.run_as_user != "sandbox" {
            violations.push(PolicyViolation::InvalidProcessIdentity {
                field: "run_as_user",
                value: process.run_as_user.clone(),
            });
        }
        if process.run_as_group != "sandbox" {
            violations.push(PolicyViolation::InvalidProcessIdentity {
                field: "run_as_group",
                value: process.run_as_group.clone(),
            });
        }
    }

    // Check filesystem paths
    if let Some(ref fs) = policy.filesystem {
        let total_paths = fs.read_only.len() + fs.read_write.len();
        if total_paths > MAX_FILESYSTEM_PATHS {
            violations.push(PolicyViolation::TooManyPaths { count: total_paths });
        }

        for path_str in fs.read_only.iter().chain(fs.read_write.iter()) {
            if path_str.len() > MAX_PATH_LENGTH {
                violations.push(PolicyViolation::FieldTooLong {
                    path: truncate_for_display(path_str),
                    length: path_str.len(),
                });
                continue;
            }

            let path = Path::new(path_str);

            if !path.has_root() {
                violations.push(PolicyViolation::RelativePath {
                    path: path_str.clone(),
                });
            }

            if path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                violations.push(PolicyViolation::PathTraversal {
                    path: path_str.clone(),
                });
            }
        }

        // Only reject "/" as read-write (overly broad)
        for path_str in &fs.read_write {
            let normalized = path_str.trim_end_matches('/');
            if normalized.is_empty() {
                // Path is "/" or "///" etc.
                violations.push(PolicyViolation::OverlyBroadPath {
                    path: path_str.clone(),
                });
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

/// Truncate a string for safe inclusion in error messages.
fn truncate_for_display(s: &str) -> String {
    if s.len() <= 80 {
        s.to_string()
    } else {
        format!("{}...", &s[..77])
    }
}

/// Normalize a filesystem path by collapsing redundant separators
/// and removing trailing slashes, without requiring the path to exist on disk.
///
/// This is a lexical normalization only — it does NOT resolve symlinks or
/// check the filesystem.
pub fn normalize_path(path: &str) -> String {
    use std::path::Component;

    let p = Path::new(path);
    let mut normalized = std::path::PathBuf::new();
    for component in p.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            #[allow(clippy::path_buf_push_overwrite)]
            Component::RootDir => normalized.push("/"),
            Component::CurDir => {} // skip "."
            Component::ParentDir => {
                // Keep ".." — validation will catch it separately
                normalized.push("..");
            }
            Component::Normal(c) => normalized.push(c),
        }
    }
    normalized.to_string_lossy().to_string()
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
        let yaml = r#"
version: 1
network_policies:
  test:
    name: test_policy
    endpoints:
      - { host: example.com, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#;
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

    // ---- Policy validation tests ----

    #[test]
    fn validate_rejects_root_run_as_user() {
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
    fn validate_rejects_uid_zero() {
        let mut policy = restrictive_default_policy();
        policy.process = Some(ProcessPolicy {
            run_as_user: "0".into(),
            run_as_group: "0".into(),
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert_eq!(violations.len(), 2);
    }

    #[test]
    fn validate_rejects_non_sandbox_user() {
        let mut policy = restrictive_default_policy();
        policy.process = Some(ProcessPolicy {
            run_as_user: "nobody".into(),
            run_as_group: "nogroup".into(),
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert_eq!(violations.len(), 2);
        assert!(
            violations
                .iter()
                .all(|v| matches!(v, PolicyViolation::InvalidProcessIdentity { .. }))
        );
    }

    #[test]
    fn validate_accepts_sandbox_identity() {
        let policy = restrictive_default_policy();
        assert!(validate_sandbox_policy(&policy).is_ok());
    }

    #[test]
    fn validate_rejects_path_traversal() {
        let mut policy = restrictive_default_policy();
        policy.filesystem = Some(FilesystemPolicy {
            include_workdir: true,
            read_only: vec!["/usr/../etc/shadow".into()],
            read_write: vec!["/tmp".into()],
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::PathTraversal { .. }))
        );
    }

    #[test]
    fn validate_rejects_relative_paths() {
        let mut policy = restrictive_default_policy();
        policy.filesystem = Some(FilesystemPolicy {
            include_workdir: true,
            read_only: vec!["usr/lib".into()],
            read_write: vec!["/tmp".into()],
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::RelativePath { .. }))
        );
    }

    #[test]
    fn validate_rejects_overly_broad_read_write_path() {
        let mut policy = restrictive_default_policy();
        policy.filesystem = Some(FilesystemPolicy {
            include_workdir: true,
            read_only: vec!["/usr".into()],
            read_write: vec!["/".into()],
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::OverlyBroadPath { .. }))
        );
    }

    #[test]
    fn validate_accepts_valid_policy() {
        let policy = restrictive_default_policy();
        assert!(validate_sandbox_policy(&policy).is_ok());
    }

    #[test]
    fn validate_accepts_empty_process() {
        let policy = SandboxPolicy {
            version: 1,
            process: None,
            filesystem: None,
            landlock: None,
            network_policies: HashMap::new(),
        };
        assert!(validate_sandbox_policy(&policy).is_ok());
    }

    #[test]
    fn validate_rejects_empty_run_as_user() {
        let mut policy = restrictive_default_policy();
        policy.process = Some(ProcessPolicy {
            run_as_user: String::new(),
            run_as_group: String::new(),
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert_eq!(violations.len(), 2);
    }

    #[test]
    fn validate_rejects_too_many_paths() {
        let mut policy = restrictive_default_policy();
        let many_paths: Vec<String> = (0..300).map(|i| format!("/path/{i}")).collect();
        policy.filesystem = Some(FilesystemPolicy {
            include_workdir: true,
            read_only: many_paths,
            read_write: vec!["/tmp".into()],
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::TooManyPaths { .. }))
        );
    }

    #[test]
    fn validate_rejects_path_too_long() {
        let mut policy = restrictive_default_policy();
        let long_path = format!("/{}", "a".repeat(5000));
        policy.filesystem = Some(FilesystemPolicy {
            include_workdir: true,
            read_only: vec![long_path],
            read_write: vec!["/tmp".into()],
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::FieldTooLong { .. }))
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
        let yaml = r#"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - { host: api.example.com, ports: [80, 443] }
    binaries:
      - { path: /usr/bin/curl }
"#;
        let policy = parse_sandbox_policy(yaml).expect("should parse");
        let ep = &policy.network_policies["test"].endpoints[0];
        assert_eq!(ep.ports, vec![80, 443]);
        // port should be set to first element for backwards compat
        assert_eq!(ep.port, 80);
    }

    #[test]
    fn parse_single_port_normalized_to_ports() {
        let yaml = r#"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - { host: api.example.com, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#;
        let policy = parse_sandbox_policy(yaml).expect("should parse");
        let ep = &policy.network_policies["test"].endpoints[0];
        assert_eq!(ep.ports, vec![443]);
        assert_eq!(ep.port, 443);
    }

    #[test]
    fn round_trip_preserves_multi_port() {
        let yaml = r#"
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
"#;
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
        let yaml = r#"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - { host: api.example.com, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#;
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
}
