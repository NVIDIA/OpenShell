// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The Cedar engine's interface in builds without the `cedar` feature.
//!
//! None of these types can be constructed: [`CedarOnlyEngine::from_proto`]
//! rejects every policy, so a supervisor built without Cedar fails closed on
//! a Cedar policy and every Cedar branch of the proxy is unreachable.

#![allow(
    clippy::uninhabited_references,
    reason = "no value of these types exists, so no reference to one does"
)]

use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::IpNet;
use miette::Result;
use openshell_core::proto::SandboxPolicy as ProtoSandboxPolicy;
use openshell_supervisor_middleware::MiddlewareRegistry;

use crate::l7::L7RequestInfo;
use crate::l7::relay::L7EvalContext;
use crate::l7::websocket::WebSocketAssemblyBudget;
use crate::network_middleware::MiddlewareState;
use crate::policy_types::{
    EgressAuthorization, EndpointConfig, NetworkInput, PolicyDnsEligibilitySnapshot,
    PolicyGenerationGuard,
};

/// The provider `allowed_ips` ranges of one endpoint, or why they do not parse.
pub(crate) type ProviderRanges = std::result::Result<Vec<IpNet>, String>;

/// A Cedar policy engine, which this build cannot construct.
#[derive(Debug)]
pub enum CedarOnlyEngine {}

impl CedarOnlyEngine {
    /// Rejects every policy: this supervisor was built without Cedar.
    ///
    /// # Errors
    ///
    /// Always.
    pub fn from_proto(_policy: &ProtoSandboxPolicy) -> Result<Self> {
        Err(miette::miette!(
            "Cedar policy support is not enabled in this supervisor build"
        ))
    }

    pub fn authorize_egress(&self, _input: &NetworkInput) -> Result<EgressAuthorization> {
        match *self {}
    }

    pub fn current_generation(&self) -> u64 {
        match *self {}
    }

    pub(crate) fn websocket_assembly_budget(&self) -> WebSocketAssemblyBudget {
        match *self {}
    }

    pub(crate) fn middleware(&self) -> &MiddlewareState {
        match *self {}
    }

    pub(crate) fn l7_handle(&self, _captured_generation: u64) -> CedarL7TunnelEngine {
        match *self {}
    }

    pub fn generation_guard(&self, _expected_generation: u64) -> Result<PolicyGenerationGuard> {
        match *self {}
    }

    pub fn with_current_generation<T>(
        &self,
        _expected_generation: u64,
        _operation: impl FnOnce(u64) -> T,
    ) -> Result<Option<T>> {
        match *self {}
    }

    pub fn stage(
        &self,
        _policy: &ProtoSandboxPolicy,
        _entrypoint_pid: u32,
    ) -> Result<StagedCedarPolicy> {
        match *self {}
    }

    pub fn commit_configuration(
        &self,
        _staged: StagedCedarPolicy,
        _registry: Option<MiddlewareRegistry>,
        _commit_credentials: impl FnOnce(),
    ) -> Result<PolicyGenerationGuard> {
        match *self {}
    }

    pub fn resolve_binary_symlinks(&self, _entrypoint_pid: u32) -> Result<()> {
        match *self {}
    }

    pub fn enter_fail_closed(&self, _reason: impl Into<String>) -> Result<u64> {
        match *self {}
    }

    pub fn exit_fail_closed(&self) -> Result<u64> {
        match *self {}
    }

    pub fn fail_closed_reason(&self) -> Option<String> {
        match *self {}
    }

    pub fn credential_guards(&self, _host: &str, _port: u16) -> Result<Vec<EndpointConfig>> {
        match *self {}
    }

    pub fn effective_filesystem(&self) -> Result<openshell_policy::EffectiveFilesystem> {
        match *self {}
    }

    pub fn policy_dns_eligibility_snapshot(&self) -> Result<PolicyDnsEligibilitySnapshot> {
        match *self {}
    }
}

/// A staged Cedar policy, which this build cannot construct.
#[derive(Debug)]
pub enum StagedCedarPolicy {}

/// The L7 view of a [`CedarOnlyEngine`], which this build cannot construct.
#[derive(Clone)]
pub(crate) enum CedarL7TunnelEngine {}

impl CedarL7TunnelEngine {
    pub(crate) fn evaluate_request(
        &self,
        _ctx: &L7EvalContext,
        _request: &L7RequestInfo,
    ) -> Result<(bool, String)> {
        match *self {}
    }

    pub(crate) fn admitted_token_grant_owners(
        &self,
        _ctx: &L7EvalContext,
        _request: &L7RequestInfo,
    ) -> Result<HashSet<String>> {
        match *self {}
    }
}

/// A Cedar destination check, which this build cannot construct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CedarDestination {}

impl CedarDestination {
    pub(crate) fn provider_ranges(&self) -> &[ProviderRanges] {
        match *self {}
    }

    pub(crate) fn address_conditions(&self) -> &[Vec<IpNet>] {
        match *self {}
    }

    pub(crate) fn unconstrained_permit(&self) -> bool {
        match *self {}
    }

    pub(crate) fn names_endpoint(&self) -> bool {
        match *self {}
    }

    pub(crate) fn allows(&self, _ip: IpAddr) -> std::result::Result<bool, String> {
        match *self {}
    }
}
