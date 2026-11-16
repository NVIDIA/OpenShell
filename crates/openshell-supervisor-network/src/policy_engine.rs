// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! YAML runtime adapter. Backend selection belongs to supervisor composition.

use miette::Result;
use openshell_core::proto::SandboxPolicy;
use openshell_policy_runtime_interface::{
    L7PolicyContext, PolicyBackend, PreparedPolicy, RequestPolicy,
};
use openshell_supervisor_middleware::{ChainEntry, ChainRunner, MiddlewareRegistry};

use crate::l7::L7RequestInfo;
use crate::l7::websocket::WebSocketAssemblyBudget;
use crate::network_middleware::ActiveMiddleware;
use crate::opa::{OpaEngine, RegoTunnelEvaluator};
use crate::policy_types::{
    EgressAuthorization, EndpointConfig, NetworkInput, PolicyDnsEligibilitySnapshot,
    PolicyGenerationGuard,
};

pub use openshell_policy_runtime_interface::{
    PassthroughMiddleware, PolicyEngine, TunnelPolicyEngine,
};

struct PreparedOpaPolicy<'a> {
    engine: &'a OpaEngine,
    candidate: OpaEngine,
}

impl PreparedPolicy for PreparedOpaPolicy<'_> {
    fn commit(
        self: Box<Self>,
        registry: Option<MiddlewareRegistry>,
        commit_credentials: &mut dyn FnMut(),
    ) -> Result<PolicyGenerationGuard> {
        self.engine
            .commit_prepared_configuration(self.candidate, registry, commit_credentials)
    }
}

impl PolicyBackend for OpaEngine {
    fn label(&self) -> &'static str {
        "opa"
    }
    fn authorize_egress(&self, input: &NetworkInput) -> Result<EgressAuthorization> {
        self.authorize_egress(input)
    }
    fn current_generation(&self) -> u64 {
        self.current_generation()
    }
    fn generation_guard(&self, expected: u64) -> Result<PolicyGenerationGuard> {
        self.generation_guard(expected)
    }
    fn with_current_generation(
        &self,
        expected: u64,
        operation: &mut dyn FnMut(u64),
    ) -> Result<bool> {
        self.with_current_generation(expected, operation)
            .map(|result| result.is_some())
    }
    fn configuration_generation_guard(&self) -> Result<PolicyGenerationGuard> {
        self.generation_guard(self.current_generation())
    }
    fn binary_identity_required(&self) -> bool {
        self.binary_identity_required()
    }
    fn websocket_assembly_budget(&self) -> WebSocketAssemblyBudget {
        self.websocket_assembly_budget()
    }
    fn policy_dns_eligibility_snapshot(&self) -> Result<PolicyDnsEligibilitySnapshot> {
        self.policy_dns_eligibility_snapshot()
    }
    fn enter_fail_closed(&self, reason: String) -> Result<u64> {
        self.enter_fail_closed(reason)
    }
    fn exit_fail_closed(&self) -> Result<u64> {
        self.exit_fail_closed()
    }
    fn fail_closed_reason(&self) -> Option<String> {
        self.fail_closed_reason()
    }
    fn endpoint_credential_guards(&self, input: &NetworkInput) -> Result<Vec<EndpointConfig>> {
        self.query_endpoint_credential_guards(input)
    }
    fn middleware_generation(&self) -> u64 {
        self.current_generation()
    }
    fn query_middleware_chain_with_generation(
        &self,
        input: &NetworkInput,
    ) -> Result<(Vec<ChainEntry>, u64)> {
        self.query_middleware_chain_with_generation(input)
    }
    fn middleware_runner(&self) -> Result<ChainRunner> {
        self.middleware_runner()
    }
    fn replace_middleware_registry(&self, registry: MiddlewareRegistry) -> Result<()> {
        self.replace_middleware_registry(registry)
    }
    fn passthrough_snapshot(&self) -> Result<Option<ActiveMiddleware>> {
        Ok(None)
    }
    fn tunnel_engine(&self, expected: u64) -> Result<TunnelPolicyEngine> {
        self.clone_engine_for_tunnel(expected)
    }
    fn effective_filesystem(
        &self,
        policy: &SandboxPolicy,
    ) -> Result<openshell_policy::EffectiveFilesystem> {
        openshell_policy::effective_filesystem(policy).map_err(|error| miette::miette!("{error}"))
    }
    fn stage<'a>(
        &'a self,
        policy: &SandboxPolicy,
        pid: u32,
    ) -> Result<Box<dyn PreparedPolicy + 'a>> {
        if policy.is_cedar() {
            return Err(miette::miette!(
                "cannot switch policy formats; previous policy remains active"
            ));
        }
        Ok(Box::new(PreparedOpaPolicy {
            engine: self,
            candidate: Self::from_proto_with_pid(policy, pid)?,
        }))
    }
    fn resolve_binary_symlinks(&self, policy: &SandboxPolicy, pid: u32) -> Result<()> {
        self.reload_from_proto_with_pid(policy, pid).map(drop)
    }
    fn forward_middleware_generation(&self, policy_generation: u64) -> u64 {
        policy_generation
    }
}

impl RequestPolicy for RegoTunnelEvaluator {
    fn query_middleware_chain(&self, input: &NetworkInput) -> Result<Vec<ChainEntry>> {
        self.query_middleware_chain(input)
    }
    fn evaluate_request(
        &self,
        ctx: &L7PolicyContext,
        request: &L7RequestInfo,
    ) -> Result<(bool, String)> {
        self.evaluate_request(ctx, request)
    }
    fn admitted_token_grant_owners(
        &self,
        ctx: &L7PolicyContext,
        request: &L7RequestInfo,
    ) -> Result<std::collections::HashSet<String>> {
        self.admitted_token_grant_owners(ctx, request)
    }
}
