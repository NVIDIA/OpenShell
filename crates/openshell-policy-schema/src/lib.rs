// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! YAML schema types and pure-Rust parsing for `OpenShell` sandbox policies.
//!
//! This crate is intentionally dependency-light: `serde`, `serde_yml`,
//! `serde_json`, and `miette`. It has **no** dependency on `openshell-core`,
//! `tonic`, or `prost`, making it usable from projects that only need YAML
//! parsing and serialization without pulling in gRPC infrastructure.
//!
//! The types here are the **single canonical representation** of the YAML
//! policy schema. Both parsing (YAML→types) and serialization (types→YAML)
//! use these types, ensuring round-trip fidelity.

use std::collections::BTreeMap;
use std::path::Path;

use miette::{IntoDiagnostic, Result, WrapErr};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// YAML serde types (canonical — used for both parsing and serialization)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem_policy: Option<FilesystemDef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub landlock: Option<LandlockDef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessDef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub network_policies: BTreeMap<String, NetworkPolicyRuleDef>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemDef {
    #[serde(default)]
    pub include_workdir: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_only: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_write: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandlockDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub compatibility: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub run_as_user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub run_as_group: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyRuleDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<NetworkEndpointDef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub binaries: Vec<NetworkBinaryDef>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkEndpointDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// Single port (backwards compat). Mutually exclusive with `ports`.
    /// Uses `u16` to reject invalid values >65535 at parse time.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub port: u16,
    /// Multiple ports. When non-empty, this endpoint covers all listed ports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tls: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub enforcement: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<L7RuleDef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_rules: Vec<L7DenyRuleDef>,
    /// When true, percent-encoded `/` (`%2F`) is preserved in path segments
    /// rather than rejected by the L7 path canonicalizer. Required for
    /// upstreams like GitLab that embed `%2F` in namespaced resource paths.
    /// Defaults to false (strict).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_encoded_slash: bool,
    /// When true, client-to-server WebSocket text messages on this REST
    /// endpoint rewrite credential placeholders after an allowed 101 upgrade.
    /// Defaults to false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub websocket_credential_rewrite: bool,
    /// When true, supported textual REST request bodies rewrite credential
    /// placeholders before forwarding upstream. Defaults to false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub request_body_credential_rewrite: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub persisted_queries: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub graphql_persisted_queries: BTreeMap<String, GraphqlOperationDef>,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub graphql_max_body_bytes: u32,
}

// Signature dictated by serde's `skip_serializing_if`, which requires `&T`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(v: &u16) -> bool {
    *v == 0
}

// Signature dictated by serde's `skip_serializing_if`, which requires `&T`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphqlOperationDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L7RuleDef {
    pub allow: L7AllowDef,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L7AllowDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub command: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub query: BTreeMap<String, QueryMatcherDef>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum QueryMatcherDef {
    Glob(String),
    Any(QueryAnyDef),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryAnyDef {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L7DenyRuleDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub command: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub query: BTreeMap<String, QueryMatcherDef>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkBinaryDef {
    pub path: String,
    /// Deprecated: ignored. Kept for backward compat with existing YAML files.
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    pub harness: bool,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

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

/// Maximum number of filesystem paths (`read_only` + `read_write` combined).
pub(crate) const MAX_FILESYSTEM_PATHS: usize = 256;

/// Maximum length of any single filesystem path string.
pub(crate) const MAX_PATH_LENGTH: usize = 4096;

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

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
// Policy safety validation types
// ---------------------------------------------------------------------------

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
    /// A network endpoint uses a TLD wildcard (e.g. `*.com`).
    TldWildcard { policy_name: String, host: String },
}

impl std::fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
            Self::TldWildcard { policy_name, host } => {
                write!(
                    f,
                    "network policy '{policy_name}': TLD wildcard '{host}' is not allowed; \
                     use subdomain wildcards like '*.example.com' instead"
                )
            }
        }
    }
}

/// Truncate a string for safe inclusion in error messages.
pub(crate) fn truncate_for_display(s: &str) -> String {
    if s.len() <= 80 {
        s.to_string()
    } else {
        format!("{}...", &s[..77])
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a sandbox policy from a YAML string.
pub fn parse_policy(yaml: &str) -> Result<PolicyFile> {
    let raw: PolicyFile = serde_yml::from_str(yaml)
        .into_diagnostic()
        .wrap_err("failed to parse sandbox policy YAML")?;
    Ok(raw)
}

/// Serialize a sandbox policy to a YAML string.
///
/// This is the inverse of [`parse_policy`] — the output uses the
/// canonical YAML field names (e.g. `filesystem_policy`, not `filesystem`)
/// and is round-trippable through `parse_policy`.
pub fn serialize_policy(policy: &PolicyFile) -> Result<String> {
    serde_yml::to_string(policy)
        .into_diagnostic()
        .wrap_err("failed to serialize policy to YAML")
}

/// Convert a sandbox policy into the canonical policy JSON representation.
///
/// The shape mirrors the YAML schema used by [`serialize_policy`], so
/// automation can use the same documented field names in either format.
pub fn policy_to_json_value(policy: &PolicyFile) -> Result<serde_json::Value> {
    serde_json::to_value(policy)
        .into_diagnostic()
        .wrap_err("failed to serialize policy to JSON")
}

/// Serialize a sandbox policy to a pretty-printed JSON string.
pub fn serialize_policy_json(policy: &PolicyFile) -> Result<String> {
    let json_repr = policy_to_json_value(policy)?;
    serde_json::to_string_pretty(&json_repr)
        .into_diagnostic()
        .wrap_err("failed to serialize policy to JSON")
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
pub fn load_policy(cli_path: Option<&str>) -> Result<Option<PolicyFile>> {
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
    parse_policy(&contents).map(Some)
}

/// Return a restrictive default policy suitable for sandboxes that have no
/// explicit policy configured.
///
/// This policy grants filesystem access to standard system paths, runs as the
/// `sandbox` user, enables Landlock in best-effort mode, and **blocks all
/// network access** (no network policies, no inference routing).
pub fn restrictive_default() -> PolicyFile {
    PolicyFile {
        version: 1,
        filesystem_policy: Some(FilesystemDef {
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
        landlock: Some(LandlockDef {
            compatibility: "best_effort".into(),
        }),
        process: Some(ProcessDef {
            run_as_user: "sandbox".into(),
            run_as_group: "sandbox".into(),
        }),
        network_policies: BTreeMap::new(),
    }
}

/// Ensure the policy has `run_as_user: sandbox` and `run_as_group: sandbox`.
///
/// If the process section is missing, or either field is empty, this fills in
/// the required `"sandbox"` value. Call this before validation so that
/// policies without an explicit process section get the correct default.
pub fn ensure_sandbox_process_identity(policy: &mut PolicyFile) {
    let process = policy.process.get_or_insert_with(ProcessDef::default);
    if process.run_as_user.is_empty() {
        process.run_as_user = "sandbox".into();
    }
    if process.run_as_group.is_empty() {
        process.run_as_group = "sandbox".into();
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
/// - Network endpoint hosts must not use TLD wildcards (e.g. `*.com`)
pub fn validate_policy(policy: &PolicyFile) -> std::result::Result<(), Vec<PolicyViolation>> {
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
    if let Some(ref fs) = policy.filesystem_policy {
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

    // Check network policy endpoint hosts for TLD wildcards.
    for (key, rule) in &policy.network_policies {
        let name = if rule.name.is_empty() {
            key.clone()
        } else {
            rule.name.clone()
        };
        for ep in &rule.endpoints {
            if ep.host.contains('*') && (ep.host.starts_with("*.") || ep.host.starts_with("**.")) {
                let label_count = ep.host.split('.').count();
                if label_count <= 2 {
                    violations.push(PolicyViolation::TldWildcard {
                        policy_name: name.clone(),
                        host: ep.host.clone(),
                    });
                }
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the serialized YAML uses `filesystem_policy` (not
    /// `filesystem`) so it can be fed back to `parse_policy`.
    #[test]
    fn serialized_yaml_uses_filesystem_policy_key() {
        let policy = restrictive_default();
        let yaml = serialize_policy(&policy).expect("serialize failed");
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
        let policy = parse_policy(
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
        let json = policy_to_json_value(&policy).expect("serialize failed");

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
        let p1 = parse_policy(yaml).expect("parse failed");
        let yaml_out = serialize_policy(&p1).expect("serialize failed");
        let p2 = parse_policy(&yaml_out).expect("re-parse failed");

        let ep1 = &p1.network_policies["internal"].endpoints[0];
        let ep2 = &p2.network_policies["internal"].endpoints[0];
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
        let p1 = parse_policy(yaml).expect("parse failed");
        assert_eq!(p1.network_policies["my_api"].name, "my-custom-api-name");

        let yaml_out = serialize_policy(&p1).expect("serialize failed");
        let p2 = parse_policy(&yaml_out).expect("re-parse failed");
        assert_eq!(p2.network_policies["my_api"].name, "my-custom-api-name");
    }

    #[test]
    fn restrictive_default_has_no_network_policies() {
        let policy = restrictive_default();
        assert!(
            policy.network_policies.is_empty(),
            "restrictive default must block all network"
        );
    }

    #[test]
    fn restrictive_default_has_filesystem_policy() {
        let policy = restrictive_default();
        let fs = policy
            .filesystem_policy
            .expect("must have filesystem policy");
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
        let policy = restrictive_default();
        let proc = policy.process.expect("must have process policy");
        assert_eq!(proc.run_as_user, "sandbox");
        assert_eq!(proc.run_as_group, "sandbox");
    }

    #[test]
    fn restrictive_default_has_landlock() {
        let policy = restrictive_default();
        let ll = policy.landlock.expect("must have landlock policy");
        assert_eq!(ll.compatibility, "best_effort");
    }

    #[test]
    fn restrictive_default_version_is_one() {
        let policy = restrictive_default();
        assert_eq!(policy.version, 1);
    }

    #[test]
    fn parse_minimal_policy_yaml() {
        let yaml = "version: 1\n";
        let policy = parse_policy(yaml).expect("should parse");
        assert_eq!(policy.version, 1);
        assert!(policy.network_policies.is_empty());
        assert!(policy.filesystem_policy.is_none());
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
        let policy = parse_policy(yaml).expect("should parse");
        assert_eq!(policy.network_policies.len(), 1);
        let rule = &policy.network_policies["test"];
        assert_eq!(rule.name, "test_policy");
        assert_eq!(rule.endpoints.len(), 1);
        assert_eq!(rule.endpoints[0].host, "example.com");
        assert_eq!(rule.endpoints[0].port, 443);
        assert_eq!(rule.binaries.len(), 1);
        assert_eq!(rule.binaries[0].path, "/usr/bin/curl");
    }

    // In the schema crate QueryMatcherDef is an enum; the original test accessed
    // proto fields `.glob` / `.any` directly on L7QueryMatcher structs.
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
        let policy = parse_policy(yaml).expect("parse failed");
        let query = &policy.network_policies["query_test"].endpoints[0].rules[0]
            .allow
            .query;
        assert!(
            matches!(&query["slug"], QueryMatcherDef::Glob(g) if g == "my-*"),
            "expected Glob(my-*)"
        );
        assert!(
            matches!(&query["tag"], QueryMatcherDef::Any(a) if a.any == vec!["foo-*", "bar-*"]),
            "expected Any([foo-*, bar-*])"
        );

        let yaml_out = serialize_policy(&policy).expect("serialize failed");
        let policy2 = parse_policy(&yaml_out).expect("re-parse failed");
        let query2 = &policy2.network_policies["query_test"].endpoints[0].rules[0]
            .allow
            .query;
        assert!(matches!(&query2["slug"], QueryMatcherDef::Glob(g) if g == "my-*"));
        assert!(
            matches!(&query2["tag"], QueryMatcherDef::Any(a) if a.any == vec!["foo-*", "bar-*"])
        );
    }

    #[test]
    fn parse_rejects_unknown_fields() {
        let yaml = "version: 1\nbogus_field: true\n";
        assert!(parse_policy(yaml).is_err());
    }

    #[test]
    fn ensure_sandbox_process_identity_fills_defaults() {
        let mut policy = restrictive_default();
        policy.process = None;
        ensure_sandbox_process_identity(&mut policy);
        let proc = policy.process.unwrap();
        assert_eq!(proc.run_as_user, "sandbox");
        assert_eq!(proc.run_as_group, "sandbox");
    }

    #[test]
    fn ensure_sandbox_process_identity_fills_empty_strings() {
        let mut policy = restrictive_default();
        policy.process = Some(ProcessDef {
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
        let mut policy = restrictive_default();
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
        let mut policy = restrictive_default();
        policy.process = Some(ProcessDef {
            run_as_user: "root".into(),
            run_as_group: "sandbox".into(),
        });
        let violations = validate_policy(&policy).unwrap_err();
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
        let mut policy = restrictive_default();
        policy.process = Some(ProcessDef {
            run_as_user: "0".into(),
            run_as_group: "0".into(),
        });
        let violations = validate_policy(&policy).unwrap_err();
        assert_eq!(violations.len(), 2);
    }

    #[test]
    fn validate_rejects_non_sandbox_user() {
        let mut policy = restrictive_default();
        policy.process = Some(ProcessDef {
            run_as_user: "nobody".into(),
            run_as_group: "nogroup".into(),
        });
        let violations = validate_policy(&policy).unwrap_err();
        assert_eq!(violations.len(), 2);
        assert!(
            violations
                .iter()
                .all(|v| matches!(v, PolicyViolation::InvalidProcessIdentity { .. }))
        );
    }

    #[test]
    fn validate_accepts_sandbox_identity() {
        let policy = restrictive_default();
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn validate_rejects_path_traversal() {
        let mut policy = restrictive_default();
        policy.filesystem_policy = Some(FilesystemDef {
            include_workdir: true,
            read_only: vec!["/usr/../etc/shadow".into()],
            read_write: vec!["/tmp".into()],
        });
        let violations = validate_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::PathTraversal { .. }))
        );
    }

    #[test]
    fn validate_rejects_relative_paths() {
        let mut policy = restrictive_default();
        policy.filesystem_policy = Some(FilesystemDef {
            include_workdir: true,
            read_only: vec!["usr/lib".into()],
            read_write: vec!["/tmp".into()],
        });
        let violations = validate_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::RelativePath { .. }))
        );
    }

    #[test]
    fn validate_rejects_overly_broad_read_write_path() {
        let mut policy = restrictive_default();
        policy.filesystem_policy = Some(FilesystemDef {
            include_workdir: true,
            read_only: vec!["/usr".into()],
            read_write: vec!["/".into()],
        });
        let violations = validate_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::OverlyBroadPath { .. }))
        );
    }

    #[test]
    fn validate_accepts_valid_policy() {
        let policy = restrictive_default();
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn validate_accepts_empty_process() {
        let policy = PolicyFile {
            version: 1,
            process: None,
            filesystem_policy: None,
            landlock: None,
            network_policies: BTreeMap::new(),
        };
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn validate_rejects_empty_run_as_user() {
        let mut policy = restrictive_default();
        policy.process = Some(ProcessDef {
            run_as_user: String::new(),
            run_as_group: String::new(),
        });
        let violations = validate_policy(&policy).unwrap_err();
        assert_eq!(violations.len(), 2);
    }

    #[test]
    fn validate_rejects_too_many_paths() {
        let mut policy = restrictive_default();
        let many_paths: Vec<String> = (0..300).map(|i| format!("/path/{i}")).collect();
        policy.filesystem_policy = Some(FilesystemDef {
            include_workdir: true,
            read_only: many_paths,
            read_write: vec!["/tmp".into()],
        });
        let violations = validate_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::TooManyPaths { .. }))
        );
    }

    #[test]
    fn validate_rejects_path_too_long() {
        let mut policy = restrictive_default();
        let long_path = format!("/{}", "a".repeat(5000));
        policy.filesystem_policy = Some(FilesystemDef {
            include_workdir: true,
            read_only: vec![long_path],
            read_write: vec!["/tmp".into()],
        });
        let violations = validate_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::FieldTooLong { .. }))
        );
    }

    // The original tests constructed NetworkPolicyRule/NetworkEndpoint proto
    // structs directly. Here we parse YAML instead, since NetworkPolicyRuleDef
    // and NetworkEndpointDef do not implement Default.
    #[test]
    fn validate_rejects_tld_wildcard() {
        let mut policy = restrictive_default();
        policy.network_policies.insert(
            "bad".into(),
            parse_policy(
                "version: 1\nnetwork_policies:\n  bad:\n    name: bad-rule\n    endpoints:\n      - host: \"*.com\"\n        port: 443\n",
            )
            .unwrap()
            .network_policies
            .remove("bad")
            .unwrap(),
        );
        let violations = validate_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::TldWildcard { .. }))
        );
    }

    #[test]
    fn validate_rejects_double_star_tld_wildcard() {
        let mut policy = restrictive_default();
        policy.network_policies.insert(
            "bad".into(),
            parse_policy(
                "version: 1\nnetwork_policies:\n  bad:\n    name: bad-rule\n    endpoints:\n      - host: \"**.org\"\n        port: 443\n",
            )
            .unwrap()
            .network_policies
            .remove("bad")
            .unwrap(),
        );
        let violations = validate_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::TldWildcard { .. }))
        );
    }

    #[test]
    fn validate_accepts_subdomain_wildcard() {
        let mut policy = restrictive_default();
        policy.network_policies.insert(
            "ok".into(),
            parse_policy(
                "version: 1\nnetwork_policies:\n  ok:\n    name: ok-rule\n    endpoints:\n      - host: \"*.example.com\"\n        port: 443\n",
            )
            .unwrap()
            .network_policies
            .remove("ok")
            .unwrap(),
        );
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn validate_accepts_explicit_domain() {
        let mut policy = restrictive_default();
        policy.network_policies.insert(
            "ok".into(),
            parse_policy(
                "version: 1\nnetwork_policies:\n  ok:\n    name: ok-rule\n    endpoints:\n      - host: example.com\n        port: 443\n",
            )
            .unwrap()
            .network_policies
            .remove("ok")
            .unwrap(),
        );
        assert!(validate_policy(&policy).is_ok());
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

    // In the schema crate there is no port normalization (that happens in
    // to_proto in openshell-policy). When only `ports` is specified, `port`
    // stays 0; when only `port` is specified, `ports` stays empty.
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
        let policy = parse_policy(yaml).expect("should parse");
        let ep = &policy.network_policies["test"].endpoints[0];
        assert_eq!(ep.ports, vec![80, 443]);
        assert_eq!(ep.port, 0); // no normalization in schema crate
    }

    #[test]
    fn parse_single_port() {
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
        let policy = parse_policy(yaml).expect("should parse");
        let ep = &policy.network_policies["test"].endpoints[0];
        assert_eq!(ep.port, 443);
        assert!(ep.ports.is_empty()); // no normalization in schema crate
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
        let p1 = parse_policy(yaml).expect("parse failed");
        let yaml_out = serialize_policy(&p1).expect("serialize failed");
        let p2 = parse_policy(&yaml_out).expect("re-parse failed");

        let ep1 = &p1.network_policies["test"].endpoints[0];
        let ep2 = &p2.network_policies["test"].endpoints[0];
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
        let p1 = parse_policy(yaml).expect("parse failed");
        let yaml_out = serialize_policy(&p1).expect("serialize failed");
        let p2 = parse_policy(&yaml_out).expect("re-parse failed");

        let ep1 = &p1.network_policies["test"].endpoints[0];
        let ep2 = &p2.network_policies["test"].endpoints[0];
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
        let policy = parse_policy(yaml).expect("parse failed");
        let yaml_out = serialize_policy(&policy).expect("serialize failed");
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
        let policy = parse_policy(yaml).expect("should parse");
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
        let p1 = parse_policy(yaml).expect("parse failed");
        let yaml_out = serialize_policy(&p1).expect("serialize failed");
        let p2 = parse_policy(&yaml_out).expect("re-parse failed");
        assert_eq!(
            p1.network_policies["test"].endpoints[0].host,
            p2.network_policies["test"].endpoints[0].host
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
        let policy = parse_policy(yaml).expect("parse failed");
        let ep = &policy.network_policies["github"].endpoints[0];
        assert_eq!(ep.deny_rules.len(), 2);
        assert_eq!(ep.deny_rules[0].method, "POST");
        assert_eq!(ep.deny_rules[0].path, "/repos/*/pulls/*/reviews");
        assert_eq!(ep.deny_rules[1].method, "PUT");
        assert_eq!(ep.deny_rules[1].path, "/repos/*/branches/*/protection");
    }

    // In the original, deny_rules[1].query["force"].glob accessed a proto
    // L7QueryMatcher field. Here we match on QueryMatcherDef::Glob instead.
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
        let p1 = parse_policy(yaml).expect("parse failed");
        let yaml_out = serialize_policy(&p1).expect("serialize failed");
        let p2 = parse_policy(&yaml_out).expect("re-parse failed");

        let ep1 = &p1.network_policies["github"].endpoints[0];
        let ep2 = &p2.network_policies["github"].endpoints[0];
        assert_eq!(ep1.deny_rules.len(), ep2.deny_rules.len());
        assert_eq!(ep2.deny_rules[0].method, "POST");
        assert_eq!(ep2.deny_rules[0].path, "/repos/*/pulls/*/reviews");
        assert_eq!(ep2.deny_rules[1].method, "DELETE");
        assert!(
            matches!(&ep2.deny_rules[1].query["force"], QueryMatcherDef::Glob(g) if g == "true")
        );
    }

    // In the original, deny_rules[0].query["type"].any accessed a proto field.
    // Here we match on QueryMatcherDef::Any instead.
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
        let policy = parse_policy(yaml).expect("parse failed");
        let deny = &policy.network_policies["test"].endpoints[0].deny_rules[0];
        assert!(
            matches!(&deny.query["type"], QueryMatcherDef::Any(a) if a.any == vec!["admin-*", "root-*"])
        );
    }

    // In the original, rules[0].allow.as_ref().unwrap() was needed because
    // L7Rule.allow is Option<L7Allow> in proto. In schema, L7RuleDef.allow
    // is L7AllowDef directly (not an Option).
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
        let p1 = parse_policy(yaml).expect("parse failed");
        let yaml_out = serialize_policy(&p1).expect("serialize failed");
        let p2 = parse_policy(&yaml_out).expect("re-parse failed");

        let ep = &p2.network_policies["github_graphql"].endpoints[0];
        assert_eq!(ep.protocol, "graphql");
        assert_eq!(ep.persisted_queries, "allow_registered");
        assert_eq!(ep.graphql_max_body_bytes, 131_072);
        assert_eq!(
            ep.graphql_persisted_queries["abc123"].operation_type,
            "query"
        );
        assert_eq!(ep.rules[0].allow.operation_type, "query");
        assert_eq!(ep.rules[1].allow.operation_name, "Issue*");
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
        let p1 = parse_policy(yaml).expect("parse failed");
        let yaml_out = serialize_policy(&p1).expect("serialize failed");
        let p2 = parse_policy(&yaml_out).expect("re-parse failed");

        let ep = &p2.network_policies["discord_gateway"].endpoints[0];
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
        let p1 = parse_policy(yaml).expect("parse failed");
        let yaml_out = serialize_policy(&p1).expect("serialize failed");
        let p2 = parse_policy(&yaml_out).expect("re-parse failed");

        let ep = &p2.network_policies["slack_api"].endpoints[0];
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
        let policy = parse_policy(yaml).expect("parse failed");
        let ep = &policy.network_policies["gateway"].endpoints[0];
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
        assert!(parse_policy(yaml).is_err());
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
            parse_policy(yaml).is_err(),
            "port >65535 should fail to parse"
        );
    }
}
