// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cedar as the sole, authoritative network policy engine for a sandbox.
//!
//! [`CedarOnlyEngine`] evaluates an authored `.cedar` policy directly. It is
//! selected instead of [`crate::opa::OpaEngine`], never alongside it:
//! a sandbox's `SandboxPolicy.cedar_policy_source` being non-empty is what
//! makes a sandbox use this engine instead of OPA, decided once at policy
//! load (see `crates/openshell-supervisor/src/lib.rs::load_policy`).
//!
//! CONNECT-time matching (host/binary/ancestor) is covered directly by
//! [`openshell_policy_cedar::CedarEngine::evaluate_network`].
//! Per-request L7 enforcement is covered by
//! [`openshell_policy_cedar::CedarEngine::evaluate_l7`] via
//! [`CedarL7TunnelEngine`], the handle each inspected tunnel's
//! [`crate::opa::TunnelPolicyEngine`] delegates to. [`l7_endpoint_configs_for`] populates
//! `EgressAuthorization::endpoint_configs` for every endpoint an
//! `HttpRequest` policy names, so the proxy routes an allowed CONNECT into
//! L7 inspection instead of unconditional passthrough. The Cedar engine
//! rejects at load any `HttpRequest` policy it could not route this way.
//! `EgressAuthorization::matched_endpoints` stays empty; that feeds the
//! transparent-TCP policy-DNS adapter, which no current driver uses. DNS
//! eligibility is covered separately by
//! [`CedarOnlyEngine::policy_dns_eligibility_snapshot`].
//!
//! Provider credentials work the same way as for YAML sandboxes, except that
//! providers never grant access: the gateway delivers attached providers'
//! rules in `SandboxPolicy.provider_credential_rules`, and for a connection
//! Cedar allows, each matching provider endpoint contributes its credential
//! settings (credential marker, rewrite options, request signing) to
//! `endpoint_configs` and to the credential guard. Whether the connection is
//! inspected per request is still Cedar's decision.
//!
//! Every read of the generation counter happens under the engine lock, and
//! [`CedarOnlyEngine::commit`] advances it under the write lock, so a
//! decision is always reported against the generation of the policy that
//! made it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use miette::Result;
use openshell_core::proto::SandboxPolicy as ProtoSandboxPolicy;
use openshell_policy_cedar::{CedarEngine, Decision, L7Request, NetworkRequest, normalize_host};
use tokio::sync::watch;

use crate::opa::{
    EgressAuthorization, MatchedEndpoint, NetworkAction, NetworkInput, PolicyDnsEligibilitySnapshot,
};
use crate::opa::{PolicyGenerationGuard, generation_guard_for};

/// User and group entity id sent with every Cedar request.
///
/// Process identity is fixed per sandbox and enforced by the runtime, not
/// by network policy, so requests carry a constant identity that satisfies
/// the schema's `Process` shape. Policies that test `principal.user` see
/// this value.
const PLACEHOLDER_IDENTITY: &str = "sandbox";

/// Builds the Cedar CONNECT request for one egress attempt.
fn network_request_from_input(input: &NetworkInput) -> NetworkRequest {
    NetworkRequest {
        user: PLACEHOLDER_IDENTITY.to_string(),
        group: PLACEHOLDER_IDENTITY.to_string(),
        host: input.host.clone(),
        port: input.port,
        binary_path: input.binary_path.to_string_lossy().into_owned(),
        ancestors: input
            .ancestors
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect(),
    }
}

/// The active Cedar policy and the provider settings delivered with it.
///
/// Swapped as one unit on reload so a decision never pairs one revision's
/// Cedar policy with another revision's provider settings.
#[derive(Debug)]
struct LoadedPolicy {
    cedar: CedarEngine,
    providers: Vec<ProviderEndpoint>,
}

impl LoadedPolicy {
    fn from_proto(policy: &ProtoSandboxPolicy) -> Result<Self> {
        let cedar = CedarEngine::from_policy_str(&policy.cedar_policy_source)
            .map_err(|e| miette::miette!("{e}"))?;
        let mut providers = Vec::new();
        for rule in policy.provider_credential_rules.values() {
            for endpoint in &rule.endpoints {
                providers.push(ProviderEndpoint::from_proto(endpoint));
            }
        }
        Ok(Self { cedar, providers })
    }

    /// Builds the endpoint configs for an allowed connection to `host:port`.
    ///
    /// Each matching provider endpoint contributes its settings, with its
    /// own L7 rules removed and its protocol replaced by Cedar's inspection
    /// decision. When Cedar inspects the endpoint and no provider endpoint
    /// covers every path, a path-less config keeps the remaining paths
    /// inspected.
    fn endpoint_configs(&self, host: &str, port: u16) -> Result<Vec<regorus::Value>> {
        let protocol = self
            .cedar
            .l7_protocol(host, port)
            .map(openshell_policy_cedar::L7Protocol::as_str);
        let host = normalize_host(host);
        let mut configs: Vec<serde_json::Value> = self
            .providers
            .iter()
            .filter(|endpoint| endpoint.matches(&host, port))
            .map(|endpoint| with_cedar_inspection(endpoint.config.clone(), protocol))
            .collect();
        let covers_every_path = configs.iter().any(|config| config.get("path").is_none());
        if let Some(protocol) = protocol
            && !covers_every_path
        {
            configs.push(serde_json::json!({
                "protocol": protocol,
                "enforcement": ENFORCEMENT_ENFORCE,
            }));
        }
        configs
            .into_iter()
            .map(|config| {
                serde_json::from_value::<regorus::Value>(config)
                    .map_err(|e| miette::miette!("failed to build Cedar L7 endpoint config: {e}"))
            })
            .collect()
    }
}

impl LoadedPolicy {
    /// Returns whether a `NetworkConnect` permit scope names `host:port` exactly.
    fn declares_endpoint(&self, host: &str, port: u16) -> bool {
        let host = normalize_host(host);
        self.cedar
            .dns_endpoints()
            .iter()
            .any(|endpoint| endpoint.host == host && endpoint.ports.contains(&port))
    }
}

/// One attached provider endpoint, used only for its credential settings.
#[derive(Debug, Clone)]
struct ProviderEndpoint {
    /// Lowercased host or host glob; empty for a host-less `allowed_ips` endpoint.
    host: String,
    ports: Vec<u16>,
    /// The endpoint in the shape the L7 config parser reads.
    config: serde_json::Value,
}

impl ProviderEndpoint {
    fn from_proto(endpoint: &openshell_core::proto::NetworkEndpoint) -> Self {
        let ports = if endpoint.ports.is_empty() {
            vec![endpoint.port]
        } else {
            endpoint.ports.clone()
        };
        Self {
            host: endpoint.host.to_ascii_lowercase(),
            ports: ports
                .into_iter()
                .filter_map(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
                .collect(),
            // MCP endpoint identity is irrelevant here: Cedar never selects
            // MCP inspection, so no policy hash is needed.
            config: crate::opa::endpoint_policy_value(endpoint, ""),
        }
    }

    /// Matches like the Rego `endpoint_matches_request` rule.
    fn matches(&self, host: &str, port: u16) -> bool {
        if !self.ports.contains(&port) {
            return false;
        }
        if self.host.is_empty() {
            return self
                .config
                .get("allowed_ips")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|ips| !ips.is_empty());
        }
        if self.host.contains('*') {
            openshell_core::host_pattern::host_matches(&self.host, host).unwrap_or(false)
        } else {
            self.host == host
        }
    }
}

/// Endpoint settings that describe per-request rules or inspection mode.
///
/// Removed from provider endpoints: on a Cedar sandbox, Cedar's
/// `HttpRequest` policies are the per-request rules and decide inspection.
const PROVIDER_RULE_KEYS: &[&str] = &[
    "protocol",
    "enforcement",
    "access",
    "rules",
    "deny_rules",
    "persisted_queries",
    "graphql_persisted_queries",
    "mcp_versions",
    "mcp_strict_tool_names",
    "mcp_allow_all_known_mcp_methods",
    "endpoint_id",
    "policy_hash",
];

/// Replaces a provider endpoint's rules and protocol with Cedar's decision.
fn with_cedar_inspection(
    mut config: serde_json::Value,
    protocol: Option<&str>,
) -> serde_json::Value {
    if let Some(fields) = config.as_object_mut() {
        for key in PROVIDER_RULE_KEYS {
            fields.remove(*key);
        }
        if let Some(protocol) = protocol {
            fields.insert("protocol".to_string(), protocol.into());
            fields.insert("enforcement".to_string(), ENFORCEMENT_ENFORCE.into());
        }
    }
    config
}

/// The Cedar text and provider rules a [`LoadedPolicy`] was built from.
///
/// Compared on reload so an unchanged policy keeps the current generation.
#[derive(Debug, Clone, PartialEq)]
struct PolicyInputs {
    source: String,
    /// Provider rules sorted by key; protobuf maps have no stable order.
    provider_rules: Vec<(String, openshell_core::proto::NetworkPolicyRule)>,
}

impl PolicyInputs {
    fn from_proto(policy: &ProtoSandboxPolicy) -> Self {
        let mut provider_rules: Vec<_> = policy
            .provider_credential_rules
            .iter()
            .map(|(key, rule)| (key.clone(), rule.clone()))
            .collect();
        provider_rules.sort_by(|left, right| left.0.cmp(&right.0));
        Self {
            source: policy.cedar_policy_source.clone(),
            provider_rules,
        }
    }
}

/// Builds a policy holding only Cedar text, for callers without provider rules.
fn policy_from_source(policy_src: &str) -> ProtoSandboxPolicy {
    ProtoSandboxPolicy {
        cedar_policy_source: policy_src.to_string(),
        ..Default::default()
    }
}

/// Cedar-backed, fully authoritative network policy evaluator.
///
/// No hidden fallback to OPA: a sandbox either uses this engine for every
/// network decision, or [`crate::opa::OpaEngine`] for every network
/// decision, chosen once at policy load.
#[derive(Debug)]
pub struct CedarOnlyEngine {
    /// Shared with every [`CedarL7TunnelEngine`] handed out by
    /// [`Self::l7_handle`].
    engine: Arc<RwLock<LoadedPolicy>>,
    /// What the active policy was built from, so a reload with unchanged
    /// inputs keeps the generation. Advancing it would close every inspected
    /// tunnel on each policy-poll reconciliation, even one unrelated to this
    /// sandbox's policy (for example a middleware registry change).
    inputs: RwLock<PolicyInputs>,
    generation: Arc<AtomicU64>,
    generation_tx: watch::Sender<u64>,
    /// Set while a fail-closed quarantine is active: every connection is
    /// denied with this reason, and no name is eligible for policy DNS.
    /// Changed only while the engine write lock is held.
    fail_closed_reason: RwLock<Option<String>>,
}

impl CedarOnlyEngine {
    /// Builds the engine from a policy's Cedar text and provider rules.
    ///
    /// # Errors
    ///
    /// Returns an error if the Cedar text fails to parse, fails schema
    /// validation, or uses a policy shape Cedar cannot enforce exactly.
    pub fn from_proto(policy: &ProtoSandboxPolicy) -> Result<Self> {
        let loaded = LoadedPolicy::from_proto(policy)?;
        let (generation_tx, _) = watch::channel(0);
        Ok(Self {
            engine: Arc::new(RwLock::new(loaded)),
            inputs: RwLock::new(PolicyInputs::from_proto(policy)),
            generation: Arc::new(AtomicU64::new(0)),
            generation_tx,
            fail_closed_reason: RwLock::new(None),
        })
    }

    /// Builds the engine from Cedar text alone, with no provider rules.
    ///
    /// # Errors
    ///
    /// Returns an error if `policy_src` fails to load (see [`Self::from_proto`]).
    pub fn from_policy_str(policy_src: &str) -> Result<Self> {
        Self::from_proto(&policy_from_source(policy_src))
    }

    /// Returns the active policy generation, advanced by each committed reload.
    #[must_use]
    pub fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Builds the L7 decision handle for a tunnel pinned at `captured_generation`.
    pub(crate) fn l7_handle(&self, captured_generation: u64) -> CedarL7TunnelEngine {
        CedarL7TunnelEngine {
            engine: Arc::clone(&self.engine),
            generation: Arc::clone(&self.generation),
            captured_generation,
        }
    }

    /// Pins `expected_generation` for a long-lived operation.
    ///
    /// # Errors
    ///
    /// Returns an error if `expected_generation` is already stale.
    pub fn generation_guard(&self, expected_generation: u64) -> Result<PolicyGenerationGuard> {
        generation_guard_for(
            expected_generation,
            self.current_generation(),
            &self.generation,
            &self.generation_tx,
        )
    }

    /// Runs `operation` only while `expected_generation` is current.
    ///
    /// Holds the engine read lock across the check and `operation`, so no
    /// reload can commit between them. `operation` must not block.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned.
    pub fn with_current_generation<T>(
        &self,
        expected_generation: u64,
        operation: impl FnOnce(u64) -> T,
    ) -> Result<Option<T>> {
        let _engine = self.read_engine()?;
        let current_generation = self.current_generation();
        if current_generation != expected_generation {
            return Ok(None);
        }
        Ok(Some(operation(current_generation)))
    }

    fn read_engine(&self) -> Result<std::sync::RwLockReadGuard<'_, LoadedPolicy>> {
        self.engine
            .read()
            .map_err(|_| miette::miette!("Cedar engine lock poisoned"))
    }

    /// Rebuilds the engine from a freshly reloaded policy and advances the
    /// generation counter. Call this directly alongside wherever
    /// `OpaEngine::reload*` would be called for a YAML-sourced sandbox.
    ///
    /// A no-op (generation unchanged) when `policy_src` is byte-identical
    /// to what's already loaded — see the `source` field doc.
    ///
    /// # Errors
    ///
    /// Returns an error if `policy_src` fails to load (see
    /// [`Self::from_policy_str`]). On error, the
    /// previous policy and generation stay active (last-known-good,
    /// matching `OpaEngine`'s reload failure behavior).
    pub fn reload_from_policy_str(&self, policy_src: &str) -> Result<()> {
        let staged = self.stage(&policy_from_source(policy_src))?;
        self.commit(staged)
    }

    /// Parses and validates `policy` without activating it.
    ///
    /// Lets a caller validate the Cedar policy before committing any other
    /// engine's reload, so a rejected Cedar policy leaves every engine on
    /// the previous revision. Pass the result to [`Self::commit`].
    ///
    /// # Errors
    ///
    /// Returns an error if `policy` fails to load (see [`Self::from_proto`]),
    /// or the engine lock is poisoned.
    pub fn stage(&self, policy: &ProtoSandboxPolicy) -> Result<StagedCedarPolicy> {
        let inputs = PolicyInputs::from_proto(policy);
        let unchanged = *self
            .inputs
            .read()
            .map_err(|_| miette::miette!("Cedar engine lock poisoned"))?
            == inputs;
        if unchanged {
            return Ok(StagedCedarPolicy(None));
        }
        let loaded = LoadedPolicy::from_proto(policy)?;
        Ok(StagedCedarPolicy(Some((loaded, inputs))))
    }

    /// Activates a policy returned by [`Self::stage`] and advances the generation.
    ///
    /// Also ends any fail-closed quarantine. A no-op when the staged source
    /// matched the active one and no quarantine was active.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned.
    pub fn commit(&self, staged: StagedCedarPolicy) -> Result<()> {
        let mut guard = self.write_engine()?;
        let was_fail_closed = self.write_fail_closed_reason()?.take().is_some();
        let Some((loaded, inputs)) = staged.0 else {
            if was_fail_closed {
                self.advance_generation();
            }
            return Ok(());
        };
        *guard = loaded;
        *self
            .inputs
            .write()
            .map_err(|_| miette::miette!("Cedar engine lock poisoned"))? = inputs;
        self.advance_generation();
        Ok(())
    }

    /// Publishes a deny-all quarantine generation without activating any
    /// part of a rejected candidate policy.
    ///
    /// The active Cedar policy stays loaded for a later
    /// [`Self::exit_fail_closed`] or valid reload, but every new connection
    /// is denied with `reason`. Advancing the generation closes every pinned
    /// tunnel. Mirrors `OpaEngine::enter_fail_closed`.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned.
    pub fn enter_fail_closed(&self, reason: impl Into<String>) -> Result<u64> {
        let _guard = self.write_engine()?;
        *self.write_fail_closed_reason()? = Some(reason.into());
        Ok(self.advance_generation())
    }

    /// Reactivates the active policy after a quarantine.
    ///
    /// Returns the current generation, advanced only if a quarantine ended.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned.
    pub fn exit_fail_closed(&self) -> Result<u64> {
        let _guard = self.write_engine()?;
        if self.write_fail_closed_reason()?.take().is_some() {
            Ok(self.advance_generation())
        } else {
            Ok(self.current_generation())
        }
    }

    /// Returns the quarantine reason while a fail-closed quarantine is active.
    #[must_use]
    pub fn fail_closed_reason(&self) -> Option<String> {
        self.fail_closed_reason
            .read()
            .ok()
            .and_then(|reason| reason.clone())
    }

    fn write_engine(&self) -> Result<std::sync::RwLockWriteGuard<'_, LoadedPolicy>> {
        self.engine
            .write()
            .map_err(|_| miette::miette!("Cedar engine lock poisoned"))
    }

    fn write_fail_closed_reason(&self) -> Result<std::sync::RwLockWriteGuard<'_, Option<String>>> {
        self.fail_closed_reason
            .write()
            .map_err(|_| miette::miette!("Cedar fail-closed state lock poisoned"))
    }

    fn read_fail_closed_reason(&self) -> Result<Option<String>> {
        Ok(self
            .fail_closed_reason
            .read()
            .map_err(|_| miette::miette!("Cedar fail-closed state lock poisoned"))?
            .clone())
    }

    /// Advances the generation. Callers hold the engine write lock, so a
    /// reader that observes the new generation under the read lock also sees
    /// the state that produced it.
    fn advance_generation(&self) -> u64 {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.generation_tx.send_replace(generation);
        generation
    }

    /// Returns the Landlock path grants the loaded policy authorizes.
    ///
    /// See [`openshell_policy_cedar::CedarEngine::filesystem_grants`].
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned.
    pub fn filesystem_grants(&self) -> Result<openshell_policy_cedar::FilesystemGrants> {
        Ok(self.read_engine()?.cedar.filesystem_grants().clone())
    }
}

/// A validated Cedar policy waiting for [`CedarOnlyEngine::commit`].
///
/// Empty when the staged source matched the active policy.
#[derive(Debug)]
pub struct StagedCedarPolicy(Option<(LoadedPolicy, PolicyInputs)>);

/// Value of an L7 endpoint config's `enforcement` key that makes the relay
/// deny requests the policy does not allow. Any other value means audit-only
/// (see `crate::l7::parse_l7_config`). Cedar decisions are always enforced.
const ENFORCEMENT_ENFORCE: &str = "enforce";

impl CedarOnlyEngine {
    /// Authorizes one egress request against the active Cedar policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned, or Cedar fails to
    /// evaluate the request. Callers deny the connection on error.
    pub fn authorize_egress(&self, input: &NetworkInput) -> Result<EgressAuthorization> {
        let request = network_request_from_input(input);
        let guard = self.read_engine()?;
        let generation = self.current_generation();
        if let Some(reason) = self.read_fail_closed_reason()? {
            return Ok(EgressAuthorization {
                action: NetworkAction::Deny { reason },
                endpoint_configs: Vec::new(),
                matched_endpoints: Vec::new(),
                exact_declared_endpoint_host: false,
                generation,
            });
        }
        let decision = guard
            .cedar
            .evaluate_network(&request)
            .map_err(|e| miette::miette!("{e}"))?;

        let action = match decision {
            Decision::Allow { matched_policies } => NetworkAction::Allow {
                matched_policy: matched_policies.into_iter().next(),
            },
            Decision::Deny { matched_policies } => NetworkAction::Deny {
                reason: if matched_policies.is_empty() {
                    "no Cedar policy permits this endpoint/binary".to_string()
                } else {
                    format!("denied by Cedar policy (forbid matched: {matched_policies:?})")
                },
            },
        };

        let allowed = matches!(action, NetworkAction::Allow { .. });
        // Without these, an allowed CONNECT is relayed without inspection
        // and without provider credential settings.
        let endpoint_configs = if allowed {
            guard.endpoint_configs(&request.host, request.port)?
        } else {
            Vec::new()
        };
        // Matches the YAML path: an allowed connection to a host the policy
        // names exactly (not through a glob) may resolve to private
        // addresses. For Cedar, that is a `NetworkConnect` permit whose scope
        // names this `host:port`.
        let exact_declared_endpoint_host =
            allowed && guard.declares_endpoint(&request.host, request.port);

        Ok(EgressAuthorization {
            action,
            endpoint_configs,
            // Feeds the transparent-TCP policy-DNS correlation, which no
            // current driver uses; see the module docs.
            matched_endpoints: Vec::<MatchedEndpoint>::new(),
            exact_declared_endpoint_host,
            generation,
        })
    }

    /// Returns the endpoint settings the credential guard checks for `host:port`.
    ///
    /// The same configs [`Self::authorize_egress`] returns for an allowed
    /// connection, including every path-scoped provider endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned or a config cannot be built.
    pub fn credential_guards(&self, host: &str, port: u16) -> Result<Vec<regorus::Value>> {
        self.read_engine()?.endpoint_configs(host, port)
    }

    /// Returns the endpoints eligible for policy-gated DNS resolution.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned.
    pub fn policy_dns_eligibility_snapshot(&self) -> Result<PolicyDnsEligibilitySnapshot> {
        let guard = self.read_engine()?;
        let generation = self.current_generation();
        if self.read_fail_closed_reason()?.is_some() {
            return Ok(PolicyDnsEligibilitySnapshot {
                endpoints: Vec::new(),
                generation,
                fail_closed: true,
            });
        }
        let endpoints = guard
            .cedar
            .dns_endpoints()
            .iter()
            .enumerate()
            .filter_map(|(endpoint_index, authorized)| {
                let value = serde_json::json!({
                    "host": authorized.host,
                    "ports": authorized.ports,
                });
                let endpoint = serde_json::from_value::<regorus::Value>(value).ok()?;
                Some(MatchedEndpoint {
                    policy_name: "cedar".to_string(),
                    endpoint_index,
                    endpoint,
                })
            })
            .collect();

        Ok(PolicyDnsEligibilitySnapshot {
            endpoints,
            generation,
            fail_closed: false,
        })
    }
}

/// Per-tunnel L7 decision handle for a Cedar-sourced sandbox.
///
/// Unlike OPA's [`crate::opa::TunnelPolicyEngine`], this needs no actual
/// per-tunnel engine clone — `Authorizer`/`PolicySet` are immutable, so
/// concurrent evaluation is just concurrent `RwLock::read()` calls, same as
/// [`CedarOnlyEngine::authorize_egress`]. Only `captured_generation` is
/// per-tunnel state.
#[derive(Debug)]
pub(crate) struct CedarL7TunnelEngine {
    engine: Arc<RwLock<LoadedPolicy>>,
    generation: Arc<AtomicU64>,
    captured_generation: u64,
}

impl CedarL7TunnelEngine {
    /// Evaluates one L7 request and returns `(allowed, deny_reason)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the tunnel's generation is stale, the engine lock
    /// is poisoned, or Cedar fails to evaluate the request.
    pub(crate) fn evaluate_request(
        &self,
        ctx: &crate::l7::relay::L7EvalContext,
        request: &crate::l7::L7RequestInfo,
    ) -> Result<(bool, String)> {
        // Compare under the read lock: a reload advances the generation
        // under the write lock, so this request is judged by the policy
        // generation the tunnel was pinned to, never a newer one.
        let guard = self
            .engine
            .read()
            .map_err(|_| miette::miette!("Cedar engine lock poisoned"))?;
        let current_generation = self.generation.load(Ordering::Acquire);
        if current_generation != self.captured_generation {
            return Err(miette::miette!(
                "L7 tunnel policy generation is stale [captured_generation:{} current_generation:{current_generation}]",
                self.captured_generation,
            ));
        }

        let jsonrpc_method = request
            .jsonrpc
            .as_ref()
            .and_then(|info| info.calls.first())
            .map(|call| call.method.clone())
            .unwrap_or_default();
        let l7_request = L7Request {
            user: PLACEHOLDER_IDENTITY.to_string(),
            group: PLACEHOLDER_IDENTITY.to_string(),
            binary_path: ctx.binary_path.clone(),
            ancestors: ctx.ancestors.clone(),
            host: ctx.host.clone(),
            port: ctx.port,
            // `request.action` carries the HTTP method for REST/GraphQL and
            // is empty for a JSON-RPC-family request (jsonrpc_method covers
            // that case instead) — same disambiguation-by-empty-string
            // convention as the rest of the HttpRequest schema.
            method: if jsonrpc_method.is_empty() {
                request.action.clone()
            } else {
                String::new()
            },
            path: request.target.clone(),
            command: String::new(),
            jsonrpc_method,
        };

        let allowed = guard
            .cedar
            .evaluate_l7(&l7_request)
            .map_err(|e| miette::miette!("{e}"))?
            .is_allow();
        let reason = if allowed {
            String::new()
        } else {
            "denied by Cedar HttpRequest policy".to_string()
        };
        Ok((allowed, reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l7::L7RequestInfo;
    use crate::l7::relay::L7EvalContext;

    const POLICY: &str = r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when {
    context.binary_path == "/usr/bin/curl"
};

permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when {
    context.binary_path == "/usr/bin/curl"
    && context.method == "GET"
    && context.path == "/v1/status"
};
"#;

    fn ctx() -> L7EvalContext {
        L7EvalContext {
            host: "api.example.com".to_string(),
            port: 443,
            binary_path: "/usr/bin/curl".to_string(),
            ..Default::default()
        }
    }

    fn request(action: &str, target: &str) -> L7RequestInfo {
        L7RequestInfo {
            action: action.to_string(),
            target: target.to_string(),
            query_params: std::collections::HashMap::new(),
            graphql: None,
            jsonrpc: None,
        }
    }

    #[test]
    fn authorize_egress_populates_endpoint_configs_for_an_l7_endpoint() {
        // Without this, query_l7_route_snapshot (proxy.rs) always sees an
        // empty endpoint_configs and routes every allowed CONNECT to
        // unconditional passthrough — the HttpRequest permit above would
        // then never actually be consulted for a real connection.
        let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
        let input = NetworkInput {
            host: "api.example.com".to_string(),
            port: 443,
            binary_path: "/usr/bin/curl".into(),
            binary_sha256: "deadbeef".to_string(),
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
        };
        let authorization = engine.authorize_egress(&input).expect("request evaluates");
        assert!(
            matches!(authorization.action, NetworkAction::Allow { .. }),
            "{:?}",
            authorization.action
        );
        assert_eq!(authorization.endpoint_configs.len(), 1);
        let config = crate::l7::parse_l7_config(&authorization.endpoint_configs[0])
            .expect("config must parse");
        assert_eq!(config.protocol, openshell_policy::L7Protocol::Rest);
    }

    #[test]
    fn authorize_egress_omits_endpoint_configs_for_a_connect_only_endpoint() {
        const CONNECT_ONLY_POLICY: &str = r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"pypi.org:443"
)
when { context.binary_path == "/usr/bin/curl" };
"#;
        let engine = CedarOnlyEngine::from_policy_str(CONNECT_ONLY_POLICY).expect("policy parses");
        let input = NetworkInput {
            host: "pypi.org".to_string(),
            port: 443,
            binary_path: "/usr/bin/curl".into(),
            binary_sha256: "deadbeef".to_string(),
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
        };
        let authorization = engine.authorize_egress(&input).expect("request evaluates");
        assert!(
            matches!(authorization.action, NetworkAction::Allow { .. }),
            "{:?}",
            authorization.action
        );
        assert!(authorization.endpoint_configs.is_empty());
    }

    #[test]
    fn l7_override_allows_the_permitted_request() {
        let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
        let generation = engine.current_generation();
        let handle = engine.l7_handle(generation);
        let (allowed, _) = handle
            .evaluate_request(&ctx(), &request("GET", "/v1/status"))
            .expect("request evaluates");
        assert!(allowed);
    }

    #[test]
    fn l7_override_denies_a_different_path() {
        let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
        let generation = engine.current_generation();
        let handle = engine.l7_handle(generation);
        let (allowed, reason) = handle
            .evaluate_request(&ctx(), &request("GET", "/v1/admin"))
            .expect("request evaluates");
        assert!(!allowed);
        assert!(!reason.is_empty());
    }

    #[test]
    fn l7_override_fails_closed_when_tunnel_generation_is_stale() {
        let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
        let captured_generation = engine.current_generation();
        let handle = engine.l7_handle(captured_generation);
        // A reload with genuinely different policy text must still advance
        // the generation — only a byte-identical reload is a no-op.
        let changed_policy = format!("{POLICY}\n// a trailing comment to change the source\n");
        engine
            .reload_from_policy_str(&changed_policy)
            .expect("reload with changed policy advances the generation");

        let result = handle.evaluate_request(&ctx(), &request("GET", "/v1/status"));
        assert!(
            result.is_err(),
            "stale tunnel must fail closed, not silently re-evaluate"
        );
    }

    #[test]
    fn reload_with_identical_policy_source_is_a_no_op() {
        // An unconditional generation bump here would invalidate every
        // in-flight L7 tunnel whenever a policy poll reconciliation pass
        // fires for a reason unrelated to this sandbox's Cedar policy (e.g.
        // middleware registry reconciliation) — not just a real change.
        let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
        let generation_before = engine.current_generation();
        engine
            .reload_from_policy_str(POLICY)
            .expect("reload succeeds");
        assert_eq!(
            engine.current_generation(),
            generation_before,
            "reloading byte-identical policy text must not advance the generation"
        );
    }

    fn plumbing_opa_engine() -> Arc<crate::opa::OpaEngine> {
        // No network policies: the Rego engine alone would deny every L7
        // request, so an Allow below can only come from Cedar.
        Arc::new(
            crate::opa::OpaEngine::from_strings(
                include_str!("../data/sandbox-policy.rego"),
                "network_policies: {}",
            )
            .expect("restrictive OPA engine builds"),
        )
    }

    #[test]
    fn tunnel_engine_delegates_l7_decisions_to_cedar() {
        let cedar = Arc::new(CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses"));
        let plumbing = plumbing_opa_engine();
        let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));

        let tunnel = engine
            .tunnel_engine(&plumbing, cedar.current_generation())
            .expect("tunnel builds");

        let (allowed, _) = tunnel
            .evaluate_request(&ctx(), &request("GET", "/v1/status"))
            .expect("request evaluates");
        assert!(
            allowed,
            "Cedar must decide, not the empty-policy OPA engine"
        );
    }

    #[test]
    fn tunnel_engine_tracks_the_cedar_generation() {
        let cedar = Arc::new(CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses"));
        let plumbing = plumbing_opa_engine();
        let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));
        let tunnel = engine
            .tunnel_engine(&plumbing, cedar.current_generation())
            .expect("tunnel builds");

        // A change to the plumbing engine (for example a middleware registry
        // swap) must not close a Cedar tunnel.
        plumbing
            .replace_middleware_registry(
                openshell_supervisor_middleware::MiddlewareRegistry::default(),
            )
            .expect("registry swap");
        assert!(!tunnel.is_stale());

        // A Cedar reload must.
        cedar
            .reload_from_policy_str(&format!("{POLICY}\n// changed\n"))
            .expect("reload");
        assert!(tunnel.is_stale());
    }

    #[test]
    fn tunnel_engine_rejects_a_stale_cedar_generation() {
        let cedar = Arc::new(CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses"));
        let plumbing = plumbing_opa_engine();
        let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));
        let decided_at = cedar.current_generation();
        cedar
            .reload_from_policy_str(&format!("{POLICY}\n// changed\n"))
            .expect("reload");

        assert!(engine.tunnel_engine(&plumbing, decided_at).is_err());
    }

    const CONNECT_ONLY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
"#;

    fn provider_policy(
        cedar: &str,
        endpoints: Vec<openshell_core::proto::NetworkEndpoint>,
    ) -> ProtoSandboxPolicy {
        let mut policy = policy_from_source(cedar);
        policy.provider_credential_rules.insert(
            "_provider_work".to_string(),
            openshell_core::proto::NetworkPolicyRule {
                name: "_provider_work".to_string(),
                endpoints,
                ..Default::default()
            },
        );
        policy
    }

    fn credentialed_endpoint() -> openshell_core::proto::NetworkEndpoint {
        openshell_core::proto::NetworkEndpoint {
            host: "api.example.com".to_string(),
            port: 443,
            protocol: "rest".to_string(),
            access: openshell_core::proto::NetworkAccessPreset::ReadOnly as i32,
            provider_credentialed: true,
            request_body_credential_rewrite: true,
            ..Default::default()
        }
    }

    fn curl_input(host: &str) -> NetworkInput {
        NetworkInput {
            host: host.to_string(),
            port: 443,
            binary_path: "/usr/bin/curl".into(),
            binary_sha256: String::new(),
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
        }
    }

    #[test]
    fn provider_settings_apply_with_cedar_inspection() {
        let engine =
            CedarOnlyEngine::from_proto(&provider_policy(POLICY, vec![credentialed_endpoint()]))
                .expect("policy loads");
        let authorization = engine
            .authorize_egress(&curl_input("api.example.com"))
            .expect("request evaluates");
        assert_eq!(authorization.endpoint_configs.len(), 1);
        let config = crate::l7::parse_l7_config(&authorization.endpoint_configs[0])
            .expect("config must parse");
        assert_eq!(config.protocol, openshell_policy::L7Protocol::Rest);
        assert!(config.provider_credentialed);
        assert!(config.request_body_credential_rewrite);
        let raw = serde_json::to_value(&authorization.endpoint_configs[0]).expect("serialize");
        assert!(
            raw.get("access").is_none(),
            "provider L7 rules must not apply on a Cedar sandbox"
        );
    }

    #[test]
    fn uninspected_credentialed_endpoint_is_refused_at_connect() {
        // Cedar allows the connection but has no HttpRequest policy for it,
        // so it would be relayed without inspection.
        let engine = CedarOnlyEngine::from_proto(&provider_policy(
            CONNECT_ONLY,
            vec![credentialed_endpoint()],
        ))
        .expect("policy loads");
        let guards = engine
            .credential_guards("api.example.com", 443)
            .expect("guards evaluate");
        assert_eq!(guards.len(), 1);
        let guard = crate::l7::parse_endpoint_credential_guard(&guards[0]);
        assert!(guard.provider_credentialed);
        assert!(guard.blocks_connect());
    }

    #[test]
    fn provider_rules_grant_no_access() {
        let mut other = credentialed_endpoint();
        other.host = "other.example.com".to_string();
        let engine = CedarOnlyEngine::from_proto(&provider_policy(POLICY, vec![other]))
            .expect("policy loads");
        let authorization = engine
            .authorize_egress(&curl_input("other.example.com"))
            .expect("request evaluates");
        assert!(
            matches!(authorization.action, NetworkAction::Deny { .. }),
            "{:?}",
            authorization.action
        );
        assert!(authorization.endpoint_configs.is_empty());
    }

    #[test]
    fn path_scoped_provider_endpoint_keeps_other_paths_inspected() {
        let mut scoped = credentialed_endpoint();
        scoped.path = "/v1/**".to_string();
        let engine = CedarOnlyEngine::from_proto(&provider_policy(POLICY, vec![scoped]))
            .expect("policy loads");
        let configs = engine
            .credential_guards("api.example.com", 443)
            .expect("configs build");
        assert_eq!(configs.len(), 2, "path-scoped config plus a path-less one");
        assert!(configs.iter().all(|config| {
            crate::l7::parse_l7_config(config)
                .is_some_and(|config| config.protocol == openshell_policy::L7Protocol::Rest)
        }));
    }

    #[test]
    fn reload_tracks_provider_rule_changes() {
        let engine =
            CedarOnlyEngine::from_proto(&provider_policy(POLICY, vec![credentialed_endpoint()]))
                .expect("policy loads");
        let generation = engine.current_generation();

        let unchanged = engine
            .stage(&provider_policy(POLICY, vec![credentialed_endpoint()]))
            .expect("stage");
        engine.commit(unchanged).expect("commit");
        assert_eq!(engine.current_generation(), generation);

        let changed = engine.stage(&policy_from_source(POLICY)).expect("stage");
        engine.commit(changed).expect("commit");
        assert_eq!(engine.current_generation(), generation + 1);
        assert_eq!(
            engine
                .credential_guards("api.example.com", 443)
                .expect("configs")
                .len(),
            1,
            "only Cedar's own inspection config remains"
        );
    }

    #[test]
    fn exact_declared_host_follows_the_permit_scope() {
        let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
        assert!(
            engine
                .authorize_egress(&curl_input("api.example.com"))
                .expect("request evaluates")
                .exact_declared_endpoint_host
        );

        let glob = CedarOnlyEngine::from_policy_str(
            r#"permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
               when { resource.host like "*.example.com" };"#,
        )
        .expect("policy parses");
        let authorization = glob
            .authorize_egress(&curl_input("api.example.com"))
            .expect("request evaluates");
        assert!(matches!(authorization.action, NetworkAction::Allow { .. }));
        assert!(!authorization.exact_declared_endpoint_host);
    }
}
