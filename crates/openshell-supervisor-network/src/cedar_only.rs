// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cedar as the sole, authoritative network policy engine for a sandbox.
//!
//! Unlike [`crate::cedar_shadow`] (which *compiles* Cedar from an existing
//! YAML/proto policy, purely for comparison), [`CedarOnlyEngine`] parses an
//! **authored** `.cedar` policy directly — no YAML, no OPA, no compiler.
//! It's selected instead of [`crate::opa::OpaEngine`], never alongside it:
//! a sandbox's `SandboxPolicy.cedar_policy_source` being non-empty is what
//! makes a sandbox use this engine instead of OPA, decided once at policy
//! load (see `crates/openshell-supervisor/src/lib.rs::load_policy`).
//!
//! CONNECT-time matching (host/binary/ancestor) is covered directly by
//! [`openshell_policy_cedar::CedarNetworkEngine::evaluate_network`].
//! Per-request L7 enforcement is covered by
//! [`openshell_policy_cedar::CedarNetworkEngine::evaluate_l7`] via
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
//! Every read of the generation counter happens under the engine lock, and
//! [`CedarOnlyEngine::commit`] advances it under the write lock, so a
//! decision is always reported against the generation of the policy that
//! made it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use miette::Result;
use openshell_policy_cedar::{CedarNetworkEngine, L7Request, NetworkDecision};
use tokio::sync::watch;

use crate::cedar_shadow::{PLACEHOLDER_IDENTITY, network_request_from_input};
use crate::opa::{
    EgressAuthorization, MatchedEndpoint, NetworkAction, NetworkInput, PolicyDnsEligibilitySnapshot,
};
use crate::opa::{PolicyGenerationGuard, generation_guard_for};

/// Cedar-backed, fully authoritative network policy evaluator.
///
/// No hidden fallback to OPA: a sandbox either uses this engine for every
/// network decision, or [`crate::opa::OpaEngine`] for every network
/// decision, chosen once at policy load.
#[derive(Debug)]
pub struct CedarOnlyEngine {
    /// Shared with every [`CedarL7TunnelEngine`] handed out by
    /// [`Self::l7_handle`].
    engine: Arc<RwLock<CedarNetworkEngine>>,
    /// The currently-loaded policy source, so [`Self::reload_from_policy_str`]
    /// can no-op on an unchanged reload instead of unconditionally advancing
    /// the generation. An unconditional bump here would invalidate every
    /// in-flight L7 tunnel on every policy-poll reconciliation pass — even
    /// one triggered by something unrelated to this sandbox's Cedar policy
    /// (e.g. middleware registry reconciliation) — not just a real change.
    source: RwLock<String>,
    generation: Arc<AtomicU64>,
    generation_tx: watch::Sender<u64>,
}

impl CedarOnlyEngine {
    /// Parses and validates `policy_src` (`.cedar` syntax) and builds the engine.
    ///
    /// # Errors
    ///
    /// Returns an error if `policy_src` fails to parse, fails schema
    /// validation, or uses a policy shape Cedar cannot enforce exactly.
    pub fn from_policy_str(policy_src: &str) -> Result<Self> {
        let engine =
            CedarNetworkEngine::from_policy_str(policy_src).map_err(|e| miette::miette!("{e}"))?;
        let (generation_tx, _) = watch::channel(0);
        Ok(Self {
            engine: Arc::new(RwLock::new(engine)),
            source: RwLock::new(policy_src.to_string()),
            generation: Arc::new(AtomicU64::new(0)),
            generation_tx,
        })
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

    fn read_engine(&self) -> Result<std::sync::RwLockReadGuard<'_, CedarNetworkEngine>> {
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
        let staged = self.stage(policy_src)?;
        self.commit(staged)
    }

    /// Parses and validates `policy_src` without activating it.
    ///
    /// Lets a caller validate the Cedar policy before committing any other
    /// engine's reload, so a rejected Cedar policy leaves every engine on
    /// the previous revision. Pass the result to [`Self::commit`].
    ///
    /// # Errors
    ///
    /// Returns an error if `policy_src` fails to load (see
    /// [`Self::from_policy_str`]), or the engine lock is poisoned.
    pub fn stage(&self, policy_src: &str) -> Result<StagedCedarPolicy> {
        let unchanged = self
            .source
            .read()
            .map_err(|_| miette::miette!("Cedar engine lock poisoned"))?
            .as_str()
            == policy_src;
        if unchanged {
            return Ok(StagedCedarPolicy(None));
        }
        let engine =
            CedarNetworkEngine::from_policy_str(policy_src).map_err(|e| miette::miette!("{e}"))?;
        Ok(StagedCedarPolicy(Some((engine, policy_src.to_string()))))
    }

    /// Activates a policy returned by [`Self::stage`] and advances the generation.
    ///
    /// A no-op when the staged source matched the active one.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned.
    pub fn commit(&self, staged: StagedCedarPolicy) -> Result<()> {
        let Some((engine, source)) = staged.0 else {
            return Ok(());
        };
        let mut guard = self
            .engine
            .write()
            .map_err(|_| miette::miette!("Cedar engine lock poisoned"))?;
        *guard = engine;
        *self
            .source
            .write()
            .map_err(|_| miette::miette!("Cedar engine lock poisoned"))? = source;
        // Advanced while the engine write lock is held, so a reader that
        // observes the new generation under the read lock also sees the new
        // policy.
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.generation_tx.send_replace(generation);
        Ok(())
    }

    /// Returns the Landlock path grants the loaded policy authorizes.
    ///
    /// See [`openshell_policy_cedar::CedarNetworkEngine::filesystem_grants`].
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned.
    pub fn filesystem_grants(
        &self,
    ) -> Result<openshell_policy_cedar::filesystem::FilesystemPolicyInput> {
        Ok(self.read_engine()?.filesystem_grants().clone())
    }
}

/// A validated Cedar policy waiting for [`CedarOnlyEngine::commit`].
///
/// Empty when the staged source matched the active policy.
#[derive(Debug)]
pub struct StagedCedarPolicy(Option<(CedarNetworkEngine, String)>);

/// Value of an L7 endpoint config's `enforcement` key that makes the relay
/// deny requests the policy does not allow. Any other value means audit-only
/// (see `crate::l7::parse_l7_config`). Cedar decisions are always enforced.
const ENFORCEMENT_ENFORCE: &str = "enforce";

/// Builds the `endpoint_configs` the proxy's `query_l7_route_snapshot`
/// needs to select L7 inspection over passthrough for `(host, port)`.
///
/// Without this, a Cedar-sourced sandbox's `HttpRequest` policies are never
/// consulted: `query_l7_route_snapshot` only inspects when
/// `EgressAuthorization::endpoint_configs` is non-empty, and every allowed
/// CONNECT would otherwise fall through to unconditional passthrough.
///
/// # Errors
///
/// Returns an error if the config cannot be built. The caller fails the
/// CONNECT rather than letting it pass through uninspected.
fn l7_endpoint_configs_for(
    guard: &CedarNetworkEngine,
    host: &str,
    port: u16,
) -> Result<Vec<regorus::Value>> {
    let Some(protocol) = guard.l7_protocol(host, port) else {
        return Ok(Vec::new());
    };
    let json = serde_json::json!({
        "protocol": protocol.as_str(),
        "enforcement": ENFORCEMENT_ENFORCE,
    });
    let config = serde_json::from_value::<regorus::Value>(json)
        .map_err(|e| miette::miette!("failed to build Cedar L7 endpoint config: {e}"))?;
    Ok(vec![config])
}

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
        let decision = guard
            .evaluate_network(&request)
            .map_err(|e| miette::miette!("{e}"))?;

        let action = match decision {
            NetworkDecision::Allow { matched_policies } => NetworkAction::Allow {
                matched_policy: matched_policies.into_iter().next(),
            },
            NetworkDecision::Deny { matched_policies } => NetworkAction::Deny {
                reason: if matched_policies.is_empty() {
                    "no Cedar policy permits this endpoint/binary".to_string()
                } else {
                    format!("denied by Cedar policy (forbid matched: {matched_policies:?})")
                },
            },
            NetworkDecision::Unsupported { reason } => NetworkAction::Deny { reason },
        };

        let endpoint_configs = if matches!(action, NetworkAction::Allow { .. }) {
            l7_endpoint_configs_for(&guard, &request.host, request.port)?
        } else {
            Vec::new()
        };

        Ok(EgressAuthorization {
            action,
            endpoint_configs,
            // Feeds the transparent-TCP policy-DNS correlation, which no
            // current driver uses; see the module docs.
            matched_endpoints: Vec::<MatchedEndpoint>::new(),
            exact_declared_endpoint_host: false,
            generation,
        })
    }

    /// Returns the endpoints eligible for policy-gated DNS resolution.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned.
    pub fn policy_dns_eligibility_snapshot(&self) -> Result<PolicyDnsEligibilitySnapshot> {
        let guard = self.read_engine()?;
        let generation = self.current_generation();
        let endpoints = guard
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
    engine: Arc<RwLock<CedarNetworkEngine>>,
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

        let (allowed, _matched) = guard
            .evaluate_l7(&l7_request)
            .map_err(|e| miette::miette!("{e}"))?;
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
}
