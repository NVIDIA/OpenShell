// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contracts implemented by policy backends and consumed by the supervisor.

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use miette::Result;
use openshell_core::proto::SandboxPolicy;
use openshell_supervisor_middleware::{ChainEntry, ChainRunner, MiddlewareRegistry};

use crate::l7::L7RequestInfo;
use crate::l7::websocket::WebSocketAssemblyBudget;
use crate::network_middleware::ActiveMiddleware;
use crate::policy_types::{
    EgressAuthorization, EndpointConfig, NetworkInput, PolicyDnsEligibilitySnapshot,
    PolicyGenerationGuard,
};

/// Policy-visible connection identity, without relay credentials or I/O state.
#[derive(Clone, Debug, Default)]
pub struct L7PolicyContext {
    pub host: String,
    pub port: u16,
    pub policy_name: String,
    pub binary_path: String,
    pub ancestors: Vec<String>,
    pub cmdline_paths: Vec<String>,
}

/// An immutable address authorizer captured with an egress decision.
///
/// Implementations must evaluate against that decision's policy generation.
/// Networking always rejects loopback, link-local, metadata, and unspecified
/// addresses before calling `rejection`. Explicit proxy host-gateway aliases
/// use separate pinned validation and `allows_gateway`. A backend may further
/// restrict addresses; it cannot relax networking's safety floor.
pub trait ResolvedAddressPolicy: fmt::Debug + Send + Sync {
    fn rejection(&self, host: &str, ip: IpAddr) -> Option<String>;
    fn blocks_control_plane(&self, host: &str) -> bool;
    fn ip_constrained(&self) -> bool;
    /// Trusted gateway aliases bypass provider ranges, but still need policy permission.
    fn allows_gateway(&self, ip: IpAddr) -> std::result::Result<bool, String>;
}

#[derive(Clone, Debug)]
pub struct DestinationPolicy(Arc<dyn ResolvedAddressPolicy>);

impl DestinationPolicy {
    pub fn new(policy: impl ResolvedAddressPolicy + 'static) -> Self {
        Self(Arc::new(policy))
    }
    pub fn rejection(&self, host: &str, ip: IpAddr) -> Option<String> {
        self.0.rejection(host, ip)
    }
    pub fn blocks_control_plane(&self, host: &str) -> bool {
        self.0.blocks_control_plane(host)
    }
    pub fn ip_constrained(&self) -> bool {
        self.0.ip_constrained()
    }
    pub fn allows_gateway(&self, ip: IpAddr) -> std::result::Result<bool, String> {
        self.0.allows_gateway(ip)
    }
}

impl PartialEq for DestinationPolicy {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for DestinationPolicy {}

/// Validated candidate whose commit publishes policy, middleware, and credentials atomically.
pub trait PreparedPolicy: Send {
    fn commit(
        self: Box<Self>,
        registry: Option<MiddlewareRegistry>,
        commit_credentials: &mut dyn FnMut(),
    ) -> Result<PolicyGenerationGuard>;
}

pub trait RequestPolicy: Send + Sync {
    fn query_middleware_chain(&self, input: &NetworkInput) -> Result<Vec<ChainEntry>>;
    fn evaluate_request(
        &self,
        ctx: &L7PolicyContext,
        request: &L7RequestInfo,
    ) -> Result<(bool, String)>;
    fn admitted_token_grant_owners(
        &self,
        ctx: &L7PolicyContext,
        request: &L7RequestInfo,
    ) -> Result<HashSet<String>>;
}

/// Runtime behavior of one policy language. Backends own their reload and snapshot semantics.
pub trait PolicyBackend: Send + Sync {
    fn label(&self) -> &'static str;
    fn authorize_egress(&self, input: &NetworkInput) -> Result<EgressAuthorization>;
    fn current_generation(&self) -> u64;
    fn generation_guard(&self, expected: u64) -> Result<PolicyGenerationGuard>;
    fn with_current_generation(
        &self,
        expected: u64,
        operation: &mut dyn FnMut(u64),
    ) -> Result<bool>;
    fn configuration_generation_guard(&self) -> Result<PolicyGenerationGuard>;
    fn binary_identity_required(&self) -> bool;
    fn websocket_assembly_budget(&self) -> WebSocketAssemblyBudget;
    fn policy_dns_eligibility_snapshot(&self) -> Result<PolicyDnsEligibilitySnapshot>;
    fn enter_fail_closed(&self, reason: String) -> Result<u64>;
    fn exit_fail_closed(&self) -> Result<u64>;
    fn fail_closed_reason(&self) -> Option<String>;
    fn endpoint_credential_guards(&self, input: &NetworkInput) -> Result<Vec<EndpointConfig>>;
    fn middleware_generation(&self) -> u64;
    fn query_middleware_chain_with_generation(
        &self,
        input: &NetworkInput,
    ) -> Result<(Vec<ChainEntry>, u64)>;
    fn middleware_runner(&self) -> Result<ChainRunner>;
    fn replace_middleware_registry(&self, registry: MiddlewareRegistry) -> Result<()>;
    fn passthrough_snapshot(&self) -> Result<Option<ActiveMiddleware>>;
    fn tunnel_engine(&self, expected: u64) -> Result<TunnelPolicyEngine>;
    fn effective_filesystem(
        &self,
        policy: &SandboxPolicy,
    ) -> Result<openshell_core::policy_l7::EffectiveFilesystem>;
    fn stage<'a>(
        &'a self,
        policy: &SandboxPolicy,
        pid: u32,
    ) -> Result<Box<dyn PreparedPolicy + 'a>>;
    fn resolve_binary_symlinks(&self, policy: &SandboxPolicy, pid: u32) -> Result<()>;
    fn forward_middleware_generation(&self, policy_generation: u64) -> u64;
}

#[derive(Clone)]
pub struct PolicyEngine(Arc<dyn PolicyBackend>);

impl<T: PolicyBackend + 'static> From<Arc<T>> for PolicyEngine {
    fn from(engine: Arc<T>) -> Self {
        Self(engine)
    }
}

impl fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PolicyEngine").field(&self.label()).finish()
    }
}

impl std::ops::Deref for PolicyEngine {
    type Target = dyn PolicyBackend;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl PolicyEngine {
    pub fn enter_fail_closed(&self, reason: impl Into<String>) -> Result<u64> {
        self.0.enter_fail_closed(reason.into())
    }
    pub fn with_current_generation<T>(
        &self,
        expected: u64,
        operation: impl FnOnce(u64) -> T,
    ) -> Result<Option<T>> {
        let mut operation = Some(operation);
        let mut result = None;
        self.0
            .with_current_generation(expected, &mut |generation| {
                result =
                    Some(operation.take().expect("backend invokes the callback once")(generation));
            })?;
        Ok(result)
    }
    pub fn passthrough_middleware(&self) -> Result<PassthroughMiddleware<'_>> {
        Ok(self.0.passthrough_snapshot()?.map_or_else(
            || PassthroughMiddleware::Live(self),
            PassthroughMiddleware::Snapshot,
        ))
    }
}

pub enum PassthroughMiddleware<'a> {
    Live(&'a PolicyEngine),
    Snapshot(ActiveMiddleware),
}

impl fmt::Debug for PassthroughMiddleware<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Live(_) => "Live",
            Self::Snapshot(_) => "Snapshot",
        })
    }
}

impl PassthroughMiddleware<'_> {
    pub fn select(
        &self,
        input: &NetworkInput,
        guard: &PolicyGenerationGuard,
    ) -> Result<Option<(Vec<ChainEntry>, ChainRunner)>> {
        match self {
            Self::Live(engine) => {
                let (chain, generation) = engine.query_middleware_chain_with_generation(input)?;
                if generation != engine.middleware_generation() || guard.is_stale() {
                    return Ok(None);
                }
                Ok(Some((chain, engine.middleware_runner()?)))
            }
            Self::Snapshot(active) => {
                if guard.is_stale() {
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

pub struct TunnelPolicyEngine {
    generation_guard: PolicyGenerationGuard,
    middleware_runner: ChainRunner,
    websocket_assembly_budget: WebSocketAssemblyBudget,
    evaluator: Box<dyn RequestPolicy>,
}

impl TunnelPolicyEngine {
    pub fn new(
        generation_guard: PolicyGenerationGuard,
        middleware_runner: ChainRunner,
        websocket_assembly_budget: WebSocketAssemblyBudget,
        evaluator: impl RequestPolicy + 'static,
    ) -> Self {
        Self {
            generation_guard,
            middleware_runner,
            websocket_assembly_budget,
            evaluator: Box::new(evaluator),
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
    pub fn middleware_runner(&self) -> &ChainRunner {
        &self.middleware_runner
    }
    pub fn websocket_assembly_budget(&self) -> WebSocketAssemblyBudget {
        self.websocket_assembly_budget.clone()
    }
    pub fn query_middleware_chain(&self, input: &NetworkInput) -> Result<Vec<ChainEntry>> {
        self.evaluator.query_middleware_chain(input)
    }
    pub fn evaluate_request(
        &self,
        ctx: &L7PolicyContext,
        request: &L7RequestInfo,
    ) -> Result<(bool, String)> {
        self.generation_guard.ensure_current()?;
        self.evaluator.evaluate_request(ctx, request)
    }
    pub fn admitted_token_grant_owners(
        &self,
        ctx: &L7PolicyContext,
        request: &L7RequestInfo,
    ) -> Result<HashSet<String>> {
        self.generation_guard.ensure_current()?;
        self.evaluator.admitted_token_grant_owners(ctx, request)
    }
}
