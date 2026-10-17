// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Engine-neutral network policy inputs, results, and generation guards.
//!
//! Both [`crate::opa::OpaEngine`] (YAML policies) and
//! [`crate::cedar_only::CedarOnlyEngine`] (Cedar policies) speak these types,
//! so decision points never depend on which engine a sandbox uses. Endpoint
//! configs, policy DNS records, and middleware configs are typed Rust data:
//! the Cedar engine builds them from the policy proto and its analysis, and
//! the OPA engine converts its Rego query results into them at one boundary
//! (`crate::opa`). Nothing downstream of that boundary depends on the policy
//! language.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use miette::Result;
use openshell_policy::L7Protocol;
use serde::Deserialize;
use tokio::sync::watch;

/// The `protocol` of a policy endpoint.
///
/// Built from the authored or normalized protocol label. The label is kept
/// as a closed set so unrecognized spellings are rejected where they matter
/// (the L7 config parser) instead of silently selecting a wire profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(from = "String")]
pub enum EndpointProtocol {
    /// No protocol: a connect-only endpoint.
    #[default]
    None,
    /// Explicit native TCP, which is never inspected.
    Tcp,
    /// An inspected L7 protocol.
    L7(L7Protocol),
    /// A label no engine recognizes.
    Unknown,
}

impl EndpointProtocol {
    /// Returns the inspected L7 protocol, if this is one.
    pub fn l7(self) -> Option<L7Protocol> {
        match self {
            Self::L7(protocol) => Some(protocol),
            _ => None,
        }
    }
}

impl From<&str> for EndpointProtocol {
    fn from(label: &str) -> Self {
        if label.is_empty() {
            Self::None
        } else if label.eq_ignore_ascii_case("tcp") {
            Self::Tcp
        } else {
            L7Protocol::parse(label).map_or(Self::Unknown, Self::L7)
        }
    }
}

impl From<String> for EndpointProtocol {
    fn from(label: String) -> Self {
        Self::from(label.as_str())
    }
}

/// The `tls` setting of a policy endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(from = "String")]
pub enum TlsSetting {
    /// Unset: TLS is detected and terminated automatically.
    #[default]
    Auto,
    /// Explicit opt-out of TLS termination.
    Skip,
    /// A value the runtime does not accept.
    Unknown,
}

impl From<&str> for TlsSetting {
    fn from(label: &str) -> Self {
        match label {
            "" => Self::Auto,
            "skip" => Self::Skip,
            _ => Self::Unknown,
        }
    }
}

impl From<String> for TlsSetting {
    fn from(label: String) -> Self {
        Self::from(label.as_str())
    }
}

impl TlsSetting {
    /// Reads a proto `NetworkTlsMode` value.
    pub fn from_proto(value: i32) -> Self {
        openshell_policy::network_tls_mode_to_str(value).map_or(Self::Unknown, Self::from)
    }
}

/// The `enforcement` setting of a policy endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(from = "String")]
pub enum EnforcementSetting {
    /// Unset: the runtime default (audit) applies.
    #[default]
    Default,
    /// Deny violations.
    Enforce,
    /// Log violations and forward the request.
    Audit,
    /// A value the runtime does not accept.
    Unknown,
}

impl From<&str> for EnforcementSetting {
    fn from(label: &str) -> Self {
        match label {
            "" => Self::Default,
            "enforce" => Self::Enforce,
            "audit" => Self::Audit,
            _ => Self::Unknown,
        }
    }
}

impl From<String> for EnforcementSetting {
    fn from(label: String) -> Self {
        Self::from(label.as_str())
    }
}

/// The `access` preset of a policy endpoint.
///
/// Presets are expanded into rules by the engine; the runtime only rejects
/// an unknown value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(from = "String")]
pub enum AccessSetting {
    /// No preset.
    #[default]
    None,
    ReadOnly,
    ReadWrite,
    Full,
    /// A value the runtime does not accept.
    Unknown,
}

impl From<&str> for AccessSetting {
    fn from(label: &str) -> Self {
        match label {
            "" => Self::None,
            "read-only" => Self::ReadOnly,
            "read-write" => Self::ReadWrite,
            "full" => Self::Full,
            _ => Self::Unknown,
        }
    }
}

impl From<String> for AccessSetting {
    fn from(label: String) -> Self {
        Self::from(label.as_str())
    }
}

/// The GraphQL operation selectors of one L7 rule.
///
/// The other selectors (method, path, query, params, command) are evaluated
/// by the policy engine alone, so they are not carried here.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default)]
pub struct GraphqlRuleSelectors {
    pub operation_type: String,
    pub operation_name: String,
    pub fields: Vec<String>,
}

impl GraphqlRuleSelectors {
    /// Returns whether any GraphQL selector is set.
    pub fn is_set(&self) -> bool {
        !self.operation_type.is_empty()
            || !self.operation_name.is_empty()
            || !self.fields.is_empty()
    }
}

/// One `rules` or `deny_rules` entry of a policy endpoint.
///
/// An allow rule wraps its selectors in `allow`; a deny rule carries them
/// directly. Both forms are accepted for either list.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default)]
pub struct L7Rule {
    pub allow: Option<GraphqlRuleSelectors>,
    #[serde(flatten)]
    pub selectors: GraphqlRuleSelectors,
}

impl L7Rule {
    /// Returns the rule's GraphQL selectors, unwrapping `allow` when present.
    pub fn graphql_selectors(&self) -> &GraphqlRuleSelectors {
        self.allow.as_ref().unwrap_or(&self.selectors)
    }
}

/// A registered GraphQL operation of `graphql_persisted_queries`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default)]
pub struct GraphqlPersistedQuery {
    pub operation_type: String,
    pub operation_name: String,
    pub fields: Vec<String>,
}

/// One policy endpoint's connection and L7 settings, as the runtime reads them.
///
/// This is the engine-neutral shape of a policy endpoint that matched a
/// connection: the L7 config parser (`crate::l7::parse_l7_config`), the TLS
/// mode and credential guard readers, and the SSRF allowlist read it. The
/// OPA engine produces it from its Rego data; the Cedar engine builds it from
/// provider endpoints, endpoint settings, and its `HttpRequest` analysis.
/// Fields absent from the policy take their defaults.
#[allow(
    clippy::struct_excessive_bools,
    reason = "Endpoint config mirrors independent policy schema toggles."
)]
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default)]
pub struct EndpointConfig {
    pub host: String,
    pub ports: Vec<u16>,
    /// Endpoint path glob; empty for every path.
    pub path: String,
    pub protocol: EndpointProtocol,
    pub tls: TlsSetting,
    pub enforcement: EnforcementSetting,
    pub access: AccessSetting,
    pub rules: Vec<L7Rule>,
    pub deny_rules: Vec<L7Rule>,
    /// CIDR ranges or addresses the endpoint may resolve to.
    pub allowed_ips: Vec<String>,
    pub allow_encoded_slash: bool,
    pub websocket_credential_rewrite: bool,
    pub request_body_credential_rewrite: bool,
    pub allow_uninspected_credentials: bool,
    pub provider_credentialed: bool,
    /// Set by the Cedar engine for a `websocket-graphql` endpoint; a YAML
    /// endpoint opts in through its GraphQL rules instead.
    pub websocket_graphql_policy: bool,
    /// Opaque MCP endpoint identity; empty for other endpoints.
    pub endpoint_id: String,
    /// Hash of the canonical policy that supplied the endpoint. Both engines
    /// set it for every endpoint so grant reporting binds a request to the
    /// policy it was selected under.
    pub policy_hash: String,
    /// Credential signing mode label; empty for none.
    pub credential_signing: String,
    pub signing_service: String,
    pub signing_region: String,
    /// Persisted-query mode label; empty for the default.
    pub persisted_queries: String,
    pub graphql_persisted_queries: BTreeMap<String, GraphqlPersistedQuery>,
    /// Zero for the runtime default.
    pub graphql_max_body_bytes: u64,
    /// Zero for the runtime default.
    pub json_rpc_max_body_bytes: u64,
    /// Canonical MCP protocol revision labels; the parser requires a
    /// non-empty, strictly ordered list for an MCP endpoint.
    pub mcp_versions: Vec<String>,
    /// `None` takes the MCP default (strict).
    pub mcp_strict_tool_names: Option<bool>,
}

/// One policy endpoint as policy DNS reads it: its host selector, ports,
/// transport, and resolution allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default)]
pub struct DnsRecord {
    pub host: String,
    pub ports: Vec<u16>,
    pub protocol: EndpointProtocol,
    pub allowed_ips: Vec<String>,
}

/// One `network_middlewares` entry of a policy revision.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MiddlewareConfig {
    /// The entry's key under `network_middlewares`, which names the chain
    /// stage.
    pub policy_key: String,
    /// The implementation to run, such as `openshell/regex`.
    pub middleware: String,
    pub order: i32,
    pub config: prost_types::Struct,
    /// Failure handling label; empty for the default.
    pub on_error: String,
    /// The hosts the stage applies to; `None` selects no host.
    pub endpoints: Option<MiddlewareEndpointSelector>,
}

/// The host selector of a [`MiddlewareConfig`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default)]
pub struct MiddlewareEndpointSelector {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

/// Network action returned by a network policy decision.
///
/// - `Allow`: endpoint + binary explicitly matched in a network policy
/// - `Deny`: no matching policy
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkAction {
    Allow { matched_policy: Option<String> },
    Deny { reason: String },
}

/// Endpoint identity and metadata captured with one policy generation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MatchedEndpoint {
    pub policy_name: String,
    pub endpoint_index: usize,
    pub endpoint: DnsRecord,
}

/// Policy-DNS eligible endpoint metadata captured from one policy generation.
///
/// This is policy data only. It deliberately contains no process identity or
/// network authorization decision.
#[derive(Debug, Clone)]
pub struct PolicyDnsEligibilitySnapshot {
    pub endpoints: Vec<MatchedEndpoint>,
    pub generation: u64,
    /// The generation is a fail-closed quarantine, so every name is refused.
    pub fail_closed: bool,
}

/// Atomic policy result used to authorize and materialize one egress request.
#[derive(Debug, Clone)]
pub struct EgressAuthorization {
    pub action: NetworkAction,
    pub endpoint_configs: Vec<EndpointConfig>,
    pub matched_endpoints: Vec<MatchedEndpoint>,
    pub exact_declared_endpoint_host: bool,
    pub generation: u64,
    /// For a Cedar sandbox's allowed connection, how its resolved addresses
    /// are checked; `None` for YAML, whose endpoint configs carry
    /// `allowed_ips` instead.
    pub cedar_destination: Option<crate::cedar_only::CedarDestination>,
}

/// Input for a network access policy evaluation.
pub struct NetworkInput {
    pub host: String,
    pub port: u16,
    pub binary_path: PathBuf,
    pub binary_sha256: String,
    /// Ancestor binary paths from process tree walk (parent, grandparent, ...).
    pub ancestors: Vec<PathBuf>,
    /// Absolute paths extracted from `/proc/<pid>/cmdline` of the socket-owning
    /// process and its ancestors. Captures script paths (e.g. `/usr/local/bin/claude`)
    /// that don't appear in `/proc/<pid>/exe` because the interpreter (node) is the exe.
    pub cmdline_paths: Vec<PathBuf>,
}

/// Generation guard captured when an HTTP tunnel or request path starts.
#[derive(Clone, Debug)]
pub struct PolicyGenerationGuard {
    captured_generation: u64,
    current_generation: Arc<AtomicU64>,
    generation_rx: watch::Receiver<u64>,
}

/// Builds a [`PolicyGenerationGuard`] for any state holding a plain
/// `Arc<AtomicU64>` generation counter and matching `watch::Sender<u64>`.
///
/// `OpaEngine`, `CedarOnlyEngine`, and the Cedar middleware state all use
/// this shape, so the guard itself (and callers that only read it, e.g.
/// DNS-staleness checks) don't need to know which one produced it.
///
/// # Errors
///
/// Returns an error if `current_generation_value` differs from
/// `expected_generation`.
pub(crate) fn generation_guard_for(
    expected_generation: u64,
    current_generation_value: u64,
    current_generation: &Arc<AtomicU64>,
    generation_tx: &watch::Sender<u64>,
) -> Result<PolicyGenerationGuard> {
    if current_generation_value != expected_generation {
        return Err(miette::miette!(
            "policy changed before HTTP relay started [expected_generation:{expected_generation} current_generation:{current_generation_value}]"
        ));
    }
    Ok(PolicyGenerationGuard {
        captured_generation: current_generation_value,
        current_generation: Arc::clone(current_generation),
        generation_rx: generation_tx.subscribe(),
    })
}

impl PolicyGenerationGuard {
    pub fn captured_generation(&self) -> u64 {
        self.captured_generation
    }

    pub fn current_generation(&self) -> u64 {
        self.current_generation.load(Ordering::Acquire)
    }

    pub fn is_stale(&self) -> bool {
        self.current_generation() != self.captured_generation
    }

    pub fn ensure_current(&self) -> Result<()> {
        if self.is_stale() {
            return Err(miette::miette!(
                "policy generation is stale [captured_generation:{} current_generation:{}]",
                self.captured_generation(),
                self.current_generation(),
            ));
        }
        Ok(())
    }

    /// Wait until the policy generation changes.
    ///
    /// Relay boundaries use this to close even an idle or raw stream as soon
    /// as a new generation (including fail-closed quarantine) is published.
    pub async fn wait_until_stale(&self) {
        let mut receiver = self.generation_rx.clone();
        while !self.is_stale() {
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}
