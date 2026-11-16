// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of the shared runtime contract; no transport dependencies.

use miette::Result;
use openshell_core::proto::SandboxPolicy;
use openshell_policy_runtime_interface::{
    L7PolicyContext, PolicyBackend, PreparedPolicy, RequestPolicy, TunnelPolicyEngine,
};
use openshell_supervisor_middleware::{ChainEntry, ChainRunner, MiddlewareRegistry};

use crate::cedar_only::{CedarL7TunnelEngine, CedarOnlyEngine, StagedCedarPolicy};
use crate::l7::L7RequestInfo;
use crate::l7::websocket::WebSocketAssemblyBudget;
use crate::network_middleware::{ActiveMiddleware, MiddlewareConfigs};
use crate::policy_types::{
    EgressAuthorization, EndpointConfig, NetworkInput, PolicyDnsEligibilitySnapshot,
    PolicyGenerationGuard,
};

struct PreparedCedarPolicy<'a> {
    engine: &'a CedarOnlyEngine,
    candidate: StagedCedarPolicy,
}

impl PreparedPolicy for PreparedCedarPolicy<'_> {
    fn commit(
        self: Box<Self>,
        registry: Option<MiddlewareRegistry>,
        commit_credentials: &mut dyn FnMut(),
    ) -> Result<PolicyGenerationGuard> {
        self.engine
            .commit_configuration(self.candidate, registry, commit_credentials)
    }
}

impl PolicyBackend for CedarOnlyEngine {
    fn label(&self) -> &'static str {
        "cedar"
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
        self.middleware()
            .generation_guard(self.middleware().current_generation())
    }
    fn binary_identity_required(&self) -> bool {
        true
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
        self.credential_guards(&input.host, input.port)
    }
    fn middleware_generation(&self) -> u64 {
        self.middleware().current_generation()
    }
    fn query_middleware_chain_with_generation(
        &self,
        input: &NetworkInput,
    ) -> Result<(Vec<ChainEntry>, u64)> {
        self.middleware().select_with_generation(&input.host)
    }
    fn middleware_runner(&self) -> Result<ChainRunner> {
        self.middleware().runner()
    }
    fn replace_middleware_registry(&self, registry: MiddlewareRegistry) -> Result<()> {
        self.middleware().replace_registry(registry)
    }
    fn passthrough_snapshot(&self) -> Result<Option<ActiveMiddleware>> {
        self.middleware().snapshot().map(Some)
    }
    fn tunnel_engine(&self, expected: u64) -> Result<TunnelPolicyEngine> {
        let guard = self.generation_guard(expected)?;
        let middleware = self.middleware().snapshot()?;
        Ok(TunnelPolicyEngine::new(
            guard,
            middleware.runner,
            self.websocket_assembly_budget(),
            CedarRequestPolicy {
                l7: self.l7_handle(expected),
                middleware: middleware.configs,
            },
        ))
    }
    fn effective_filesystem(
        &self,
        _policy: &SandboxPolicy,
    ) -> Result<openshell_policy::EffectiveFilesystem> {
        self.effective_filesystem()
    }
    fn stage<'a>(
        &'a self,
        policy: &SandboxPolicy,
        pid: u32,
    ) -> Result<Box<dyn PreparedPolicy + 'a>> {
        if !policy.is_cedar() {
            return Err(miette::miette!(
                "cannot switch policy formats; previous policy remains active"
            ));
        }
        Ok(Box::new(PreparedCedarPolicy {
            engine: self,
            candidate: self.stage(policy, pid)?,
        }))
    }
    fn resolve_binary_symlinks(&self, _policy: &SandboxPolicy, pid: u32) -> Result<()> {
        self.resolve_binary_symlinks(pid)
    }
    fn forward_middleware_generation(&self, _policy_generation: u64) -> u64 {
        self.middleware().current_generation()
    }
}

struct CedarRequestPolicy {
    l7: CedarL7TunnelEngine,
    middleware: MiddlewareConfigs,
}

impl RequestPolicy for CedarRequestPolicy {
    fn query_middleware_chain(&self, input: &NetworkInput) -> Result<Vec<ChainEntry>> {
        self.middleware.select(&input.host)
    }
    fn evaluate_request(
        &self,
        ctx: &L7PolicyContext,
        request: &L7RequestInfo,
    ) -> Result<(bool, String)> {
        self.l7.evaluate_request(ctx, request)
    }
    fn admitted_token_grant_owners(
        &self,
        ctx: &L7PolicyContext,
        request: &L7RequestInfo,
    ) -> Result<std::collections::HashSet<String>> {
        self.l7.admitted_token_grant_owners(ctx, request)
    }
}
