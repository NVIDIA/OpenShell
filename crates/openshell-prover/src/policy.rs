// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy YAML parsing into prover-specific types.
//!
//! We parse the policy YAML directly (rather than going through the proto
//! types) because the prover needs fields like `access`, `protocol`, and
//! individual L7 rules that the proto representation strips.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use miette::{IntoDiagnostic, Result, WrapErr};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Policy intent
// ---------------------------------------------------------------------------

/// The inferred access intent for an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyIntent {
    L4Only,
    ReadOnly,
    ReadWrite,
    Full,
    Custom,
}

impl std::fmt::Display for PolicyIntent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::L4Only => write!(f, "l4_only"),
            Self::ReadOnly => write!(f, "read_only"),
            Self::ReadWrite => write!(f, "read_write"),
            Self::Full => write!(f, "full"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

/// HTTP methods considered to be write operations.
pub const WRITE_METHODS: &[&str] = &["POST", "PUT", "PATCH", "DELETE"];

/// All standard HTTP methods.
const ALL_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];

// ---------------------------------------------------------------------------
// Serde types — mirrors the YAML schema
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct PolicyFile {
    #[allow(dead_code)]
    version: Option<u32>,
    #[serde(default)]
    filesystem_policy: Option<FilesystemDef>,
    #[serde(default)]
    network_policies: Option<BTreeMap<String, NetworkPolicyRuleDef>>,
    // Ignored fields the prover does not need.
    #[serde(default)]
    #[allow(dead_code)]
    landlock: Option<serde_yml::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    process: Option<serde_yml::Value>,
}

#[derive(Debug, Deserialize)]
struct FilesystemDef {
    #[serde(default = "default_true")]
    include_workdir: bool,
    #[serde(default)]
    read_only: Vec<String>,
    #[serde(default)]
    read_write: Vec<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct NetworkPolicyRuleDef {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    endpoints: Vec<EndpointDef>,
    #[serde(default)]
    binaries: Vec<BinaryDef>,
}

#[derive(Debug, Deserialize)]
struct EndpointDef {
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: u32,
    #[serde(default)]
    ports: Vec<u32>,
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    tls: String,
    #[serde(default)]
    enforcement: String,
    #[serde(default)]
    access: String,
    #[serde(default)]
    rules: Vec<L7RuleDef>,
    #[serde(default)]
    allowed_ips: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct L7RuleDef {
    allow: L7AllowDef,
}

#[derive(Debug, Deserialize)]
struct L7AllowDef {
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    command: String,
}

#[derive(Debug, Deserialize)]
struct BinaryDef {
    path: String,
}

// ---------------------------------------------------------------------------
// Public model types
// ---------------------------------------------------------------------------

/// A single L7 rule (method + path) on an endpoint.
#[derive(Debug, Clone)]
pub struct L7Rule {
    pub method: String,
    pub path: String,
    pub command: String,
}

/// A network endpoint in the policy.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub host: String,
    pub port: u32,
    pub ports: Vec<u32>,
    pub protocol: String,
    pub tls: String,
    pub enforcement: String,
    pub access: String,
    pub rules: Vec<L7Rule>,
    pub allowed_ips: Vec<String>,
}

impl Endpoint {
    /// Whether this endpoint has L7 (protocol-level) enforcement.
    pub fn is_l7_enforced(&self) -> bool {
        !self.protocol.is_empty()
    }

    /// The inferred access intent.
    pub fn intent(&self) -> PolicyIntent {
        if self.protocol.is_empty() {
            return PolicyIntent::L4Only;
        }
        match self.access.as_str() {
            "read-only" => PolicyIntent::ReadOnly,
            "read-write" => PolicyIntent::ReadWrite,
            "full" => PolicyIntent::Full,
            _ => {
                if self.rules.is_empty() {
                    return PolicyIntent::Custom;
                }
                let methods: HashSet<String> =
                    self.rules.iter().map(|r| r.method.to_uppercase()).collect();
                let read_only: HashSet<String> = ["GET", "HEAD", "OPTIONS"]
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect();
                if methods.is_subset(&read_only) {
                    PolicyIntent::ReadOnly
                } else if !methods.contains("DELETE") {
                    PolicyIntent::ReadWrite
                } else {
                    PolicyIntent::Full
                }
            }
        }
    }

    /// The effective list of ports for this endpoint.
    pub fn effective_ports(&self) -> Vec<u32> {
        if !self.ports.is_empty() {
            return self.ports.clone();
        }
        if self.port > 0 {
            return vec![self.port];
        }
        vec![]
    }

    /// The set of HTTP methods this endpoint allows. Empty means all (L4-only).
    pub fn allowed_methods(&self) -> HashSet<String> {
        if self.protocol.is_empty() {
            return HashSet::new(); // L4-only: all traffic passes
        }
        match self.access.as_str() {
            "read-only" => ["GET", "HEAD", "OPTIONS"]
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            "read-write" => ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"]
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            "full" => ALL_METHODS.iter().map(|s| (*s).to_owned()).collect(),
            _ => {
                if !self.rules.is_empty() {
                    let mut methods = HashSet::new();
                    for r in &self.rules {
                        let m = r.method.to_uppercase();
                        if m == "*" {
                            return ALL_METHODS.iter().map(|s| (*s).to_owned()).collect();
                        }
                        methods.insert(m);
                    }
                    return methods;
                }
                HashSet::new()
            }
        }
    }
}

/// A binary path entry in a network policy rule.
#[derive(Debug, Clone)]
pub struct Binary {
    pub path: String,
}

/// A named network policy rule containing endpoints and binaries.
#[derive(Debug, Clone)]
pub struct NetworkPolicyRule {
    pub name: String,
    pub endpoints: Vec<Endpoint>,
    pub binaries: Vec<Binary>,
}

/// Filesystem access policy.
#[derive(Debug, Clone)]
pub struct FilesystemPolicy {
    pub include_workdir: bool,
    pub read_only: Vec<String>,
    pub read_write: Vec<String>,
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            include_workdir: true,
            read_only: Vec::new(),
            read_write: Vec::new(),
        }
    }
}

impl FilesystemPolicy {
    /// All readable paths (union of `read_only` and `read_write`), with workdir
    /// added when `include_workdir` is true and not already present.
    pub fn readable_paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = self
            .read_only
            .iter()
            .chain(self.read_write.iter())
            .cloned()
            .collect();
        if self.include_workdir && !paths.iter().any(|p| p == "/sandbox") {
            paths.push("/sandbox".to_owned());
        }
        paths
    }
}

/// The top-level policy model used by the prover.
#[derive(Debug, Clone)]
pub struct PolicyModel {
    pub version: u32,
    pub filesystem_policy: FilesystemPolicy,
    pub network_policies: BTreeMap<String, NetworkPolicyRule>,
}

impl Default for PolicyModel {
    fn default() -> Self {
        Self {
            version: 1,
            filesystem_policy: FilesystemPolicy::default(),
            network_policies: BTreeMap::new(),
        }
    }
}

impl PolicyModel {
    /// All (policy_name, endpoint) pairs.
    pub fn all_endpoints(&self) -> Vec<(&str, &Endpoint)> {
        let mut result = Vec::new();
        for (name, rule) in &self.network_policies {
            for ep in &rule.endpoints {
                result.push((name.as_str(), ep));
            }
        }
        result
    }

    /// Deduplicated list of all binary paths across all policies.
    pub fn all_binaries(&self) -> Vec<&Binary> {
        let mut seen = HashSet::new();
        let mut result = Vec::new();
        for rule in self.network_policies.values() {
            for b in &rule.binaries {
                if seen.insert(&b.path) {
                    result.push(b);
                }
            }
        }
        result
    }

    /// All (binary, policy_name, endpoint) triples.
    pub fn binary_endpoint_pairs(&self) -> Vec<(&Binary, &str, &Endpoint)> {
        let mut result = Vec::new();
        for (name, rule) in &self.network_policies {
            for b in &rule.binaries {
                for ep in &rule.endpoints {
                    result.push((b, name.as_str(), ep));
                }
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse an OpenShell policy YAML file into a [`PolicyModel`].
pub fn parse_policy(path: &Path) -> Result<PolicyModel> {
    let contents = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading policy file {}", path.display()))?;
    parse_policy_str(&contents)
}

/// Parse a policy YAML string into a [`PolicyModel`].
pub fn parse_policy_str(yaml: &str) -> Result<PolicyModel> {
    let raw: PolicyFile = serde_yml::from_str(yaml)
        .into_diagnostic()
        .wrap_err("parsing policy YAML")?;

    let fs = match raw.filesystem_policy {
        Some(fs_def) => FilesystemPolicy {
            include_workdir: fs_def.include_workdir,
            read_only: fs_def.read_only,
            read_write: fs_def.read_write,
        },
        None => FilesystemPolicy::default(),
    };

    let mut network_policies = BTreeMap::new();
    if let Some(np) = raw.network_policies {
        for (key, rule_raw) in np {
            let endpoints = rule_raw
                .endpoints
                .into_iter()
                .map(|ep_raw| {
                    let rules = ep_raw
                        .rules
                        .into_iter()
                        .map(|r| L7Rule {
                            method: r.allow.method,
                            path: r.allow.path,
                            command: r.allow.command,
                        })
                        .collect();
                    Endpoint {
                        host: ep_raw.host,
                        port: ep_raw.port,
                        ports: ep_raw.ports,
                        protocol: ep_raw.protocol,
                        tls: ep_raw.tls,
                        enforcement: ep_raw.enforcement,
                        access: ep_raw.access,
                        rules,
                        allowed_ips: ep_raw.allowed_ips,
                    }
                })
                .collect();

            let binaries = rule_raw
                .binaries
                .into_iter()
                .map(|b| Binary { path: b.path })
                .collect();

            let name = rule_raw.name.unwrap_or_else(|| key.clone());
            network_policies.insert(
                key,
                NetworkPolicyRule {
                    name,
                    endpoints,
                    binaries,
                },
            );
        }
    }

    Ok(PolicyModel {
        version: raw.version.unwrap_or(1),
        filesystem_policy: fs,
        network_policies,
    })
}
