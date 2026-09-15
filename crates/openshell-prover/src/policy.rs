// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy YAML parsing into prover-specific types.
//!
//! We parse the policy YAML directly (rather than going through the proto
//! types) because the prover needs fields like `access`, `protocol`, and
//! individual L7 rules that the proto representation strips.

use openshell_policy_schema::{
    AccessPreset, L7Allow as AuthoredAllow, NetworkEndpoint as AuthoredEndpoint, ParseLimits,
    ParseProfile, PolicyDocument,
};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

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
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::L4Only => "l4_only",
            Self::ReadOnly => "read_only",
            Self::ReadWrite => "read_write",
            Self::Full => "full",
            Self::Custom => "custom",
        })
    }
}

/// HTTP methods considered to be write operations.
pub const WRITE_METHODS: &[&str] = &["POST", "PUT", "PATCH", "DELETE"];

const ALL_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];

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
    pub port: u16,
    pub ports: Vec<u16>,
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
        !self.protocol.is_empty() && !self.protocol.eq_ignore_ascii_case("tcp")
    }

    /// The inferred access intent.
    pub fn intent(&self) -> PolicyIntent {
        if !self.is_l7_enforced() {
            return PolicyIntent::L4Only;
        }
        match AccessPreset::parse(&self.access) {
            Some(AccessPreset::ReadOnly) => PolicyIntent::ReadOnly,
            Some(AccessPreset::ReadWrite) => PolicyIntent::ReadWrite,
            Some(AccessPreset::Full) => PolicyIntent::Full,
            None => {
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
    pub fn effective_ports(&self) -> Vec<u16> {
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
        if !self.is_l7_enforced() {
            return HashSet::new(); // L4-only: all traffic passes
        }
        if let Some(preset) = AccessPreset::parse(&self.access) {
            let methods = preset.methods(&self.protocol);
            if methods.contains(&"*") {
                ALL_METHODS
                    .iter()
                    .map(|method| (*method).to_owned())
                    .collect()
            } else {
                methods.iter().map(|method| (*method).to_owned()).collect()
            }
        } else {
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
#[derive(Debug, Clone, Default)]
pub struct FilesystemPolicy {
    pub include_workdir: bool,
    pub read_only: Vec<String>,
    pub read_write: Vec<String>,
}

/// Symbol used when the prover does not know the image-resolved workspace.
///
/// Keeping this distinct from `/sandbox` prevents the model from inventing a
/// literal compatibility workspace for images that declare another workdir.
pub const WORKDIR_PATH_SYMBOL: &str = "<OCI_WORKDIR>";

impl FilesystemPolicy {
    /// All readable paths (union of `read_only` and `read_write`), with workdir
    /// added when `include_workdir` is true and not already present. When the
    /// resolved workdir is unavailable, retain it as a symbolic path.
    pub fn readable_paths(&self, resolved_workdir: Option<&str>) -> Vec<String> {
        let mut paths: Vec<String> = self
            .read_only
            .iter()
            .chain(self.read_write.iter())
            .cloned()
            .collect();
        let workdir = resolved_workdir.unwrap_or(WORKDIR_PATH_SYMBOL);
        if self.include_workdir && !paths.iter().any(|path| path == workdir) {
            paths.push(workdir.to_owned());
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
    /// All (`policy_name`, endpoint) pairs.
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

    /// All (binary, `policy_name`, endpoint) triples.
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

/// Parse an `OpenShell` policy YAML file into a `PolicyModel`.
pub fn parse_policy(path: &Path) -> miette::Result<PolicyModel> {
    let document = openshell_policy_schema::parse_policy_file(
        path,
        ParseProfile::RuntimeStrict,
        ParseLimits::default(),
    )?;
    Ok(project_policy(document))
}

/// Parse a policy YAML string into a `PolicyModel`.
pub fn parse_policy_str(yaml: &str) -> miette::Result<PolicyModel> {
    let document = openshell_policy_schema::parse_policy(yaml, ParseProfile::RuntimeStrict)?;
    Ok(project_policy(document))
}

fn project_policy(document: PolicyDocument) -> PolicyModel {
    let filesystem = document.effective_filesystem_policy();
    let filesystem_policy = FilesystemPolicy {
        include_workdir: filesystem.include_workdir,
        read_only: filesystem.read_only,
        read_write: filesystem.read_write,
    };

    let network_policies = document
        .network_policies
        .into_iter()
        .map(|(key, rule)| {
            let name = rule.effective_name(&key).to_owned();
            let endpoints = rule.endpoints.into_iter().map(project_endpoint).collect();
            let binaries = rule
                .binaries
                .into_iter()
                .map(|binary| Binary { path: binary.path })
                .collect();
            (
                key,
                NetworkPolicyRule {
                    name,
                    endpoints,
                    binaries,
                },
            )
        })
        .collect();

    PolicyModel {
        version: document.version,
        filesystem_policy,
        network_policies,
    }
}

fn project_endpoint(endpoint: AuthoredEndpoint) -> Endpoint {
    let rules = endpoint
        .rules
        .into_iter()
        .map(|rule| project_allow(rule.allow))
        .collect();
    Endpoint {
        host: endpoint.host,
        port: endpoint.port,
        ports: endpoint.ports,
        protocol: endpoint.protocol,
        tls: endpoint.tls,
        enforcement: endpoint.enforcement,
        access: endpoint.access,
        rules,
        allowed_ips: endpoint.allowed_ips,
    }
}

fn project_allow(allow: AuthoredAllow) -> L7Rule {
    L7Rule {
        method: allow.method,
        path: allow.path,
        command: allow.command,
    }
}
