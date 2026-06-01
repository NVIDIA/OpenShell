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

#[derive(Debug, Serialize, Deserialize)]
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

    let p = std::path::Path::new(path);
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
