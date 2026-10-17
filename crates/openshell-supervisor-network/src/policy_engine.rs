// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The authoritative policy engine for a sandbox's network decisions.
//!
//! A sandbox's policy is either YAML, enforced by [`OpaEngine`], or Cedar,
//! enforced by [`CedarOnlyEngine`]. The choice is made once at startup from
//! the policy format and never changes. [`PolicyEngine`] is the single type
//! every network decision point (CONNECT, forward proxy, policy DNS, L7
//! relay setup, and middleware selection) receives, so decision code cannot
//! reach the wrong engine.
//!
//! Each variant owns everything its sandbox needs. A Cedar sandbox's
//! middleware configs, services, and their generation live in its
//! [`CedarOnlyEngine`] (see `crate::network_middleware`), so a Cedar
//! sandbox constructs no OPA engine and evaluates no Rego.

use std::fmt;
use std::sync::Arc;

use miette::Result;
use openshell_supervisor_middleware::{ChainEntry, ChainRunner, MiddlewareRegistry};

use crate::cedar_only::{CedarL7TunnelEngine, CedarOnlyEngine};
use crate::l7::websocket::WebSocketAssemblyBudget;
use crate::network_middleware::{ActiveMiddleware, MiddlewareConfigs};
use crate::opa::{OpaEngine, RegoTunnelEvaluator};
use crate::policy_types::{
    EgressAuthorization, NetworkInput, PolicyDnsEligibilitySnapshot, PolicyGenerationGuard,
};

/// The engine whose decisions are authoritative for one sandbox.
///
/// Cloning is cheap and shares the underlying engine.
#[derive(Clone)]
pub enum PolicyEngine {
    /// A YAML-authored policy, evaluated by Rego.
    Opa(Arc<OpaEngine>),
    /// A Cedar-authored policy, evaluated by Cedar.
    Cedar(Arc<CedarOnlyEngine>),
}

impl PolicyEngine {
    /// Authorizes one egress request against one policy generation.
    ///
    /// # Errors
    ///
    /// Returns an error only for an evaluator-internal failure. A policy
    /// denial is `Ok` with a deny action.
    pub fn authorize_egress(&self, input: &NetworkInput) -> Result<EgressAuthorization> {
        match self {
            Self::Opa(engine) => engine.authorize_egress(input),
            Self::Cedar(engine) => engine.authorize_egress(input),
        }
    }

    /// Returns the active policy generation, advanced by each reload.
    #[must_use]
    pub fn current_generation(&self) -> u64 {
        match self {
            Self::Opa(engine) => engine.current_generation(),
            Self::Cedar(engine) => engine.current_generation(),
        }
    }

    /// Pins `expected_generation` for a long-lived operation.
    ///
    /// # Errors
    ///
    /// Returns an error if `expected_generation` is already stale.
    pub fn generation_guard(&self, expected_generation: u64) -> Result<PolicyGenerationGuard> {
        match self {
            Self::Opa(engine) => engine.generation_guard(expected_generation),
            Self::Cedar(engine) => engine.generation_guard(expected_generation),
        }
    }

    /// Runs `operation` only while `expected_generation` is current.
    ///
    /// The check and `operation` run under the engine's reload lock, so no
    /// reload can land between them. `operation` must not block.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned.
    pub fn with_current_generation<T>(
        &self,
        expected_generation: u64,
        operation: impl FnOnce(u64) -> T,
    ) -> Result<Option<T>> {
        match self {
            Self::Opa(engine) => engine.with_current_generation(expected_generation, operation),
            Self::Cedar(engine) => engine.with_current_generation(expected_generation, operation),
        }
    }

    /// Pins the generation that each committed runtime configuration advances.
    ///
    /// The policy poll loop uses it to tell whether the configuration it
    /// installed is still the active one. For YAML this is the policy
    /// generation. For Cedar it is the middleware generation, which advances
    /// on every committed reload, service registry change, and quarantine
    /// entry or exit, while the Cedar policy generation advances only when
    /// the policy itself changes or a quarantine starts or ends.
    ///
    /// # Errors
    ///
    /// Returns an error if the generation changes while it is pinned.
    pub fn configuration_generation_guard(&self) -> Result<PolicyGenerationGuard> {
        match self {
            Self::Opa(engine) => engine.generation_guard(engine.current_generation()),
            Self::Cedar(engine) => {
                let middleware = engine.middleware();
                middleware.generation_guard(middleware.current_generation())
            }
        }
    }

    /// Returns whether egress authorization requires a binary identity.
    #[must_use]
    pub fn binary_identity_required(&self) -> bool {
        match self {
            Self::Opa(engine) => engine.binary_identity_required(),
            Self::Cedar(_) => true,
        }
    }

    /// Returns the buffering budget for WebSocket frames under inspection.
    #[must_use]
    pub fn websocket_assembly_budget(&self) -> WebSocketAssemblyBudget {
        match self {
            Self::Opa(engine) => engine.websocket_assembly_budget(),
            Self::Cedar(engine) => engine.websocket_assembly_budget(),
        }
    }

    /// Returns the endpoints eligible for policy-gated DNS resolution.
    ///
    /// # Errors
    ///
    /// Returns an error only for an evaluator-internal failure.
    pub fn policy_dns_eligibility_snapshot(&self) -> Result<PolicyDnsEligibilitySnapshot> {
        match self {
            Self::Opa(engine) => engine.policy_dns_eligibility_snapshot(),
            Self::Cedar(engine) => engine.policy_dns_eligibility_snapshot(),
        }
    }

    /// Publishes a deny-all quarantine generation on the authoritative engine.
    ///
    /// # Errors
    ///
    /// Returns an error if an engine lock is poisoned.
    pub fn enter_fail_closed(&self, reason: impl Into<String>) -> Result<u64> {
        match self {
            Self::Opa(engine) => engine.enter_fail_closed(reason),
            Self::Cedar(engine) => engine.enter_fail_closed(reason),
        }
    }

    /// Ends a quarantine on the authoritative engine, keeping its active policy.
    ///
    /// # Errors
    ///
    /// Returns an error if an engine lock is poisoned.
    pub fn exit_fail_closed(&self) -> Result<u64> {
        match self {
            Self::Opa(engine) => engine.exit_fail_closed(),
            Self::Cedar(engine) => engine.exit_fail_closed(),
        }
    }

    /// Returns the quarantine reason while a quarantine is active.
    #[must_use]
    pub fn fail_closed_reason(&self) -> Option<String> {
        match self {
            Self::Opa(engine) => engine.fail_closed_reason(),
            Self::Cedar(engine) => engine.fail_closed_reason(),
        }
    }

    /// Returns the endpoint settings the credential guard checks for a request.
    ///
    /// The guard refuses an uninspected connection to an endpoint that
    /// carries provider credentials.
    ///
    /// # Errors
    ///
    /// Returns an error only for an evaluator-internal failure.
    pub fn endpoint_credential_guards(
        &self,
        input: &NetworkInput,
    ) -> Result<Vec<crate::policy_types::EndpointConfig>> {
        match self {
            Self::Opa(engine) => engine.query_endpoint_credential_guards(input),
            Self::Cedar(engine) => engine.credential_guards(&input.host, input.port),
        }
    }

    /// Returns the generation the middleware chain and services come from.
    ///
    /// For YAML this is the policy generation. For Cedar it is the
    /// middleware generation, which moves independently of the Cedar policy
    /// generation.
    #[must_use]
    pub fn middleware_generation(&self) -> u64 {
        match self {
            Self::Opa(engine) => engine.current_generation(),
            Self::Cedar(engine) => engine.middleware().current_generation(),
        }
    }

    /// Returns the ordered middleware chain for an admitted destination and
    /// the middleware generation it was selected from.
    ///
    /// # Errors
    ///
    /// Returns an error if selection fails or an engine lock is poisoned.
    pub fn query_middleware_chain_with_generation(
        &self,
        input: &NetworkInput,
    ) -> Result<(Vec<ChainEntry>, u64)> {
        match self {
            Self::Opa(engine) => engine.query_middleware_chain_with_generation(input),
            Self::Cedar(engine) => engine.middleware().select_with_generation(&input.host),
        }
    }

    /// Returns the middleware services in effect now.
    ///
    /// # Errors
    ///
    /// Returns an error if an engine lock is poisoned.
    pub(crate) fn middleware_runner(&self) -> Result<ChainRunner> {
        match self {
            Self::Opa(engine) => engine.middleware_runner(),
            Self::Cedar(engine) => engine.middleware().runner(),
        }
    }

    /// Replaces the middleware service registry and advances the middleware
    /// generation, so subsequent requests use the new service set.
    ///
    /// # Errors
    ///
    /// Returns an error if an engine lock is poisoned.
    pub fn replace_middleware_registry(&self, registry: MiddlewareRegistry) -> Result<()> {
        match self {
            Self::Opa(engine) => engine.replace_middleware_registry(registry),
            Self::Cedar(engine) => engine.middleware().replace_registry(registry),
        }
    }

    /// Returns where a passthrough tunnel starting now selects its middleware.
    ///
    /// A Cedar tunnel keeps the middleware configs and services in effect
    /// now, the snapshot [`Self::tunnel_engine`] gives an inspected tunnel,
    /// so a middleware-only reload does not change its chain mid-tunnel. A
    /// YAML tunnel selects from the live engine (see
    /// [`PassthroughMiddleware`]).
    ///
    /// # Errors
    ///
    /// Returns an error if an engine lock is poisoned.
    pub fn passthrough_middleware(&self) -> Result<PassthroughMiddleware<'_>> {
        match self {
            Self::Opa(_) => Ok(PassthroughMiddleware::Live(self)),
            Self::Cedar(engine) => Ok(PassthroughMiddleware::Snapshot(
                engine.middleware().snapshot()?,
            )),
        }
    }

    /// Builds the per-tunnel L7 evaluator for a decision at `expected_generation`.
    ///
    /// For a YAML policy, the tunnel clones the compiled Rego policy and is
    /// pinned under one lock. For a Cedar policy, the tunnel is pinned to
    /// Cedar's generation, its L7 decisions come from Cedar, and it keeps the
    /// middleware configs and services in effect now.
    ///
    /// # Errors
    ///
    /// Returns an error if `expected_generation` is stale or an engine lock
    /// is poisoned.
    pub fn tunnel_engine(&self, expected_generation: u64) -> Result<TunnelPolicyEngine> {
        match self {
            Self::Opa(engine) => engine.clone_engine_for_tunnel(expected_generation),
            Self::Cedar(engine) => {
                let generation_guard = engine.generation_guard(expected_generation)?;
                let middleware = engine.middleware().snapshot()?;
                Ok(TunnelPolicyEngine {
                    generation_guard,
                    middleware_runner: middleware.runner,
                    websocket_assembly_budget: engine.websocket_assembly_budget(),
                    evaluator: TunnelEvaluator::Cedar {
                        l7: engine.l7_handle(expected_generation),
                        middleware: middleware.configs,
                    },
                })
            }
        }
    }

    /// Returns the engine name recorded on OCSF events (`opa` or `cedar`).
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Opa(_) => "opa",
            Self::Cedar(_) => "cedar",
        }
    }
}

impl fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PolicyEngine").field(&self.label()).finish()
    }
}

impl From<Arc<OpaEngine>> for PolicyEngine {
    fn from(engine: Arc<OpaEngine>) -> Self {
        Self::Opa(engine)
    }
}

impl From<Arc<CedarOnlyEngine>> for PolicyEngine {
    fn from(engine: Arc<CedarOnlyEngine>) -> Self {
        Self::Cedar(engine)
    }
}

/// Where a passthrough tunnel selects its middleware chain from.
///
/// Built by [`PolicyEngine::passthrough_middleware`] when the tunnel starts
/// and consulted for each request the tunnel relays.
pub enum PassthroughMiddleware<'a> {
    /// A YAML sandbox selects from the live engine. Its middleware
    /// generation is its policy generation, so a middleware change stales
    /// the tunnel's guard and the tunnel closes at the next request boundary.
    Live(&'a PolicyEngine),
    /// A Cedar sandbox keeps the configs and services in effect when the
    /// tunnel started, as an inspected tunnel does, because its middleware
    /// generation moves independently of the Cedar generation its guard
    /// is pinned to.
    Snapshot(ActiveMiddleware),
}

impl PassthroughMiddleware<'_> {
    /// Returns the chain for `input` and the services to run it with.
    ///
    /// Returns `None` when the tunnel must close instead: its policy
    /// generation is stale, or, for a live selection, the middleware
    /// changed between the selection and the check.
    ///
    /// # Errors
    ///
    /// Returns an error if selection fails or an engine lock is poisoned.
    pub(crate) fn select(
        &self,
        input: &NetworkInput,
        generation_guard: &PolicyGenerationGuard,
    ) -> Result<Option<(Vec<ChainEntry>, ChainRunner)>> {
        match self {
            Self::Live(engine) => {
                let (chain, generation) = engine.query_middleware_chain_with_generation(input)?;
                if generation != engine.middleware_generation() || generation_guard.is_stale() {
                    return Ok(None);
                }
                Ok(Some((chain, engine.middleware_runner()?)))
            }
            Self::Snapshot(active) => {
                if generation_guard.is_stale() {
                    return Ok(None);
                }
                Ok(Some((
                    active.configs.select(&input.host)?,
                    active.runner.clone(),
                )))
            }
        }
    }
}

impl fmt::Debug for PassthroughMiddleware<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Live(_) => "live",
            Self::Snapshot(_) => "snapshot",
        };
        f.debug_tuple("PassthroughMiddleware").field(&kind).finish()
    }
}

/// Per-tunnel L7 policy evaluator bound to the policy generation captured
/// when the tunnel was established.
///
/// Built by [`PolicyEngine::tunnel_engine`]. It keeps the middleware chain
/// configs and services in effect when the tunnel started.
pub struct TunnelPolicyEngine {
    generation_guard: PolicyGenerationGuard,
    middleware_runner: ChainRunner,
    websocket_assembly_budget: WebSocketAssemblyBudget,
    evaluator: TunnelEvaluator,
}

/// The engine-specific half of a [`TunnelPolicyEngine`].
enum TunnelEvaluator {
    /// A YAML sandbox's tunnel evaluates its own clone of the Rego policy.
    Rego(Box<RegoTunnelEvaluator>),
    /// A Cedar sandbox's tunnel evaluates Cedar and selects middleware in
    /// Rust from the configs in effect when it started.
    Cedar {
        l7: CedarL7TunnelEngine,
        middleware: MiddlewareConfigs,
    },
}

impl TunnelPolicyEngine {
    /// Builds a YAML sandbox's tunnel around a clone of its Rego policy.
    pub(crate) fn rego(
        generation_guard: PolicyGenerationGuard,
        middleware_runner: ChainRunner,
        websocket_assembly_budget: WebSocketAssemblyBudget,
        evaluator: RegoTunnelEvaluator,
    ) -> Self {
        Self {
            generation_guard,
            middleware_runner,
            websocket_assembly_budget,
            evaluator: TunnelEvaluator::Rego(Box::new(evaluator)),
        }
    }

    pub fn captured_generation(&self) -> u64 {
        self.generation_guard.captured_generation()
    }

    pub fn current_generation(&self) -> u64 {
        self.generation_guard.current_generation()
    }

    pub fn is_stale(&self) -> bool {
        self.generation_guard.is_stale()
    }

    pub fn generation_guard(&self) -> &PolicyGenerationGuard {
        &self.generation_guard
    }

    pub(crate) fn middleware_runner(&self) -> &ChainRunner {
        &self.middleware_runner
    }

    pub(crate) fn websocket_assembly_budget(&self) -> WebSocketAssemblyBudget {
        self.websocket_assembly_budget.clone()
    }

    /// Test-only: a YAML tunnel's Rego evaluator.
    ///
    /// # Panics
    ///
    /// Panics for a Cedar tunnel, which has no Rego engine.
    #[cfg(test)]
    pub(crate) fn rego_evaluator_for_tests(&self) -> &RegoTunnelEvaluator {
        match &self.evaluator {
            TunnelEvaluator::Rego(rego) => rego,
            TunnelEvaluator::Cedar { .. } => panic!("a Cedar tunnel has no Rego engine"),
        }
    }

    /// Query the ordered middleware chain for a destination within this tunnel.
    ///
    /// # Errors
    ///
    /// Returns an error if selection fails.
    pub fn query_middleware_chain(&self, input: &NetworkInput) -> Result<Vec<ChainEntry>> {
        match &self.evaluator {
            TunnelEvaluator::Rego(rego) => rego.query_middleware_chain(input),
            TunnelEvaluator::Cedar { middleware, .. } => middleware.select(&input.host),
        }
    }

    /// Evaluates one L7 request and returns `(allowed, deny_reason)`.
    ///
    /// For a Cedar-sourced sandbox the decision comes from Cedar; otherwise
    /// from this tunnel's Rego policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the tunnel's policy generation is stale or the
    /// evaluation fails. Callers treat an error as a denial.
    pub fn evaluate_request(
        &self,
        ctx: &crate::l7::relay::L7EvalContext,
        request: &crate::l7::L7RequestInfo,
    ) -> Result<(bool, String)> {
        match &self.evaluator {
            TunnelEvaluator::Cedar { l7, .. } => l7.evaluate_request(ctx, request),
            TunnelEvaluator::Rego(rego) => {
                if self.is_stale() {
                    return Err(miette::miette!(
                        "L7 tunnel policy generation is stale [captured_generation:{} current_generation:{}]",
                        self.captured_generation(),
                        self.current_generation(),
                    ));
                }
                rego.evaluate_request(ctx, request)
            }
        }
    }

    /// Returns the token-grant owners whose own endpoint admits one request.
    ///
    /// For a Cedar-sourced sandbox the owners come from Cedar; see
    /// [`CedarL7TunnelEngine::admitted_token_grant_owners`].
    ///
    /// # Errors
    ///
    /// Returns an error if the tunnel's policy generation is stale or the
    /// evaluation fails. Callers inject no token on error.
    pub(crate) fn admitted_token_grant_owners(
        &self,
        ctx: &crate::l7::relay::L7EvalContext,
        request: &crate::l7::L7RequestInfo,
    ) -> Result<std::collections::HashSet<String>> {
        if self.is_stale() {
            return Err(miette::miette!(
                "policy changed before token grant selection"
            ));
        }
        match &self.evaluator {
            TunnelEvaluator::Cedar { l7, .. } => l7.admitted_token_grant_owners(ctx, request),
            TunnelEvaluator::Rego(rego) => rego.admitted_token_grant_owners(ctx, request),
        }
    }
}
