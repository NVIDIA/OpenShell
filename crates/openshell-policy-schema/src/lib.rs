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
