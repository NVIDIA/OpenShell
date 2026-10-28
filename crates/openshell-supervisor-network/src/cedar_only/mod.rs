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
//! [`crate::policy_engine::TunnelPolicyEngine`] delegates to. [`l7_endpoint_configs_for`] populates
//! `EgressAuthorization::endpoint_configs` for every endpoint an
//! `HttpRequest` policy names, exactly in its scope or as a host glob in its
//! conditions, so the proxy routes an allowed CONNECT into L7 inspection
//! instead of unconditional passthrough. A host glob inspects every host it
//! matches, selected with the host matcher YAML endpoints and policy DNS
//! use. The Cedar engine rejects at load any `HttpRequest` policy it could
//! not route this way.
//! DNS eligibility is covered by
//! [`CedarOnlyEngine::policy_dns_eligibility_snapshot`], one record per host
//! and transport, named by its index under the policy name `cedar`. An
//! endpoint a `@transport("tcp")` permit names is native TCP, and its record
//! carries `protocol: tcp`, as a YAML `protocol: tcp` endpoint's does.
//! `EgressAuthorization::matched_endpoints` lists the records that cover an
//! allowed connection's host and port, with the same indices, so the
//! transparent TCP listener can correlate a decision with the policy DNS
//! mapping it dialed, as it does for YAML.
//!
//! Provider credentials work the same way as for YAML sandboxes, except that
//! providers never grant access: the gateway delivers attached providers'
//! rules in `SandboxPolicy.provider_credential_rules`, and for a connection
//! Cedar allows, each matching provider endpoint contributes its credential
//! settings (credential marker, rewrite options, request signing) to
//! `endpoint_configs` and to the credential guard. Whether the connection is
//! inspected per request is still Cedar's decision.
//!
//! Endpoint settings that are configuration rather than access control
//! (`tls: skip`, `allow_encoded_slash`, body limits, MCP revisions, and
//! GraphQL persisted queries) come from `SandboxPolicy.endpoint_settings`,
//! authored in the middleware file. They are merged into the endpoint
//! configs of connections Cedar allows (see
//! [`LoadedPolicy::endpoint_configs`]), and hash-only GraphQL persisted
//! queries are resolved through their registry before Cedar evaluates them,
//! as the Rego rules do.
//!
//! `@path` gives one `host:port` a different protocol and enforcement per
//! path. Each inspected path gets its own endpoint config, and each request
//! is evaluated with the inspection of the config the relay selects for it
//! (see [`LoadedPolicy::route_request`]). WebSocket messages arrive as
//! `WEBSOCKET_TEXT` requests on their upgrade path; for a
//! `websocket-graphql` endpoint the relay classifies them first and supplies
//! their GraphQL operations.
//!
//! Token grants follow the YAML rule too: an owner's grant is admitted only
//! for a request Cedar allows and the owner's own provider endpoint admits
//! under its own rules. The provider rules are compiled to Cedar (see
//! `crate::cedar_provider_rules`) and evaluated with the same request, so
//! no Rego is involved (see
//! [`CedarL7TunnelEngine::admitted_token_grant_owners`]).
//!
//! Destination addresses follow YAML `allowed_ips`: a permit may require
//! `context.destination_ip` to lie in fixed ranges. A connection is allowed
//! at CONNECT time when Cedar allows it for some address, and the decision
//! carries a [`CedarDestination`] that the proxy applies to each resolved
//! address (see `proxy::destination`). Policy DNS records carry each
//! permit's ranges as `allowed_ips`, so answers are filtered as YAML filters
//! them. Provider endpoints grant no access, so their `allowed_ips` only
//! narrow: each matching provider endpoint's ranges must also admit every
//! resolved address, as they restrict a YAML provider endpoint's
//! connections, but they never admit a private address Cedar's own rules
//! reject. A host-less provider endpoint, which YAML matches by its
//! `allowed_ips` alone, matches no connection.
//!
//! Every read of the generation counter happens under the engine lock, and
//! [`CedarOnlyEngine::commit`] advances it under the write lock, so a
//! decision is always reported against the generation of the policy that
//! made it.
//!
//! Network middleware is selected without Rego: the engine owns a
//! `MiddlewareState` holding the policy's `network_middlewares`, the
//! connected service registry, and a middleware generation of its own (see
//! `crate::network_middleware`). [`CedarOnlyEngine::commit_configuration`]
//! publishes the Cedar policy, the middleware, and the caller's provider
//! credentials together, or nothing, so a Cedar sandbox needs no OPA engine
//! at all. A quarantine advances both generations, so the configuration
//! guard the policy poll loop pins becomes stale as it does for YAML.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use miette::Result;
use openshell_core::proto::{NetworkPolicyRule, SandboxPolicy as ProtoSandboxPolicy};
use openshell_policy_cedar::{Decision, NetworkConnectRequest};
use tokio::sync::watch;

use crate::network_middleware::{MiddlewareConfigs, MiddlewareState};
use crate::policy_types::{
    EgressAuthorization, EndpointConfig, NetworkAction, NetworkInput, PolicyDnsEligibilitySnapshot,
    PolicyGenerationGuard, generation_guard_for,
};
use openshell_supervisor_middleware::MiddlewareRegistry;

mod destination;
mod l7;
mod routes;
#[cfg(test)]
mod tests;

pub use destination::CedarDestination;
pub(crate) use l7::CedarL7TunnelEngine;
use routes::LoadedPolicy;
pub(crate) use routes::ProviderRanges;

/// User and group entity id sent with every Cedar request.
///
/// Process identity is fixed per sandbox and enforced by the runtime, not
/// by network policy, so requests carry a constant identity that satisfies
/// the schema's `Process` shape. Analysis rejects policies that read
/// `principal.user` or `principal.group`, so no decision depends on it.
const PLACEHOLDER_IDENTITY: &str = "sandbox";

/// Policy name of every Cedar policy DNS record and matched endpoint.
///
/// Cedar policies have no YAML-style names, so records are told apart by
/// their index alone.
const CEDAR_POLICY_NAME: &str = "cedar";

/// Builds the Cedar CONNECT request for one egress attempt.
fn network_request_from_input(input: &NetworkInput) -> NetworkConnectRequest {
    NetworkConnectRequest {
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
        // Filled from the loaded policy's aliases and globs; see
        // `BinaryAliases` and `BinaryGlobs`.
        binary_aliases: Vec::new(),
        binary_globs: Vec::new(),
        destination_ip: None,
    }
}

/// The Cedar text, provider rules, and endpoint settings a [`LoadedPolicy`]
/// was built from.
///
/// Compared on reload so an unchanged policy keeps the current generation.
#[derive(Debug, Clone, PartialEq)]
struct PolicyInputs {
    source: String,
    /// Provider rules sorted by key; protobuf maps have no stable order.
    provider_rules: Vec<(String, NetworkPolicyRule)>,
    /// Endpoint settings, in order: a later entry overrides an earlier one.
    endpoint_settings: Vec<openshell_core::proto::NetworkEndpoint>,
}

impl PolicyInputs {
    /// The provider rules, keyed as the policy delivered them.
    fn provider_rule_map(&self) -> HashMap<String, NetworkPolicyRule> {
        self.provider_rules.iter().cloned().collect()
    }

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
            endpoint_settings: policy.endpoint_settings.clone(),
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
    /// Sandbox-wide admission survives policy reloads and is shared by forward
    /// requests and CONNECT tunnels.
    websocket_assembly_budget: crate::l7::websocket::WebSocketAssemblyBudget,
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
    /// The policy's `network_middlewares` and the connected services, with
    /// a generation independent of the policy generation.
    middleware: MiddlewareState,
}

impl CedarOnlyEngine {
    /// Builds the engine from a policy's Cedar text, provider rules,
    /// endpoint settings, and network middlewares.
    ///
    /// The engine starts with no middleware services connected; see
    /// [`crate::policy_engine::PolicyEngine::replace_middleware_registry`].
    ///
    /// The policy gets the validation every gateway-delivered policy gets
    /// (see [`crate::policy_validation::validate_sandbox_policy`]), as
    /// `OpaEngine::from_proto` validates a YAML policy, and the engine is
    /// built from the canonical form the validator returns.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy fails validation, or its Cedar text
    /// fails to parse, fails schema validation, or uses a policy shape Cedar
    /// cannot enforce exactly.
    pub fn from_proto(policy: &ProtoSandboxPolicy) -> Result<Self> {
        let validated = crate::policy_validation::validate_sandbox_policy_report(policy)?;
        let policy = validated.policy;
        let loaded = LoadedPolicy::from_proto(&policy, validated.cedar, 0)?;
        let (generation_tx, _) = watch::channel(0);
        Ok(Self {
            websocket_assembly_budget: crate::l7::websocket::WebSocketAssemblyBudget::default(),
            engine: Arc::new(RwLock::new(loaded)),
            inputs: RwLock::new(PolicyInputs::from_proto(&policy)),
            generation: Arc::new(AtomicU64::new(0)),
            generation_tx,
            fail_closed_reason: RwLock::new(None),
            middleware: MiddlewareState::new(MiddlewareConfigs::from_proto(&policy)),
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

    pub(crate) fn websocket_assembly_budget(
        &self,
    ) -> crate::l7::websocket::WebSocketAssemblyBudget {
        self.websocket_assembly_budget.clone()
    }

    /// Returns the sandbox's middleware configs, services, and generation.
    pub(crate) fn middleware(&self) -> &MiddlewareState {
        &self.middleware
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

    /// Test-only: the analysis warnings the active policy loaded with.
    ///
    /// # Panics
    ///
    /// Panics if the engine lock is poisoned.
    #[cfg(test)]
    fn warnings_for_tests(&self) -> Vec<openshell_policy_cedar::AnalysisWarning> {
        self.read_engine()
            .expect("engine lock")
            .cedar
            .warnings()
            .to_vec()
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
        let staged = self.stage(&policy_from_source(policy_src), 0)?;
        self.commit(staged)
    }

    /// Validates and parses `policy` without activating it.
    ///
    /// Lets a caller validate the Cedar policy before committing any other
    /// engine's reload, so a rejected Cedar policy leaves every engine on
    /// the previous revision. Pass the result to [`Self::commit`].
    ///
    /// The policy gets the same validation as in [`Self::from_proto`], and
    /// the staged policy is built from the canonical form the validator
    /// returns. Its binary paths are resolved in the root filesystem of
    /// `entrypoint_pid`, as `OpaEngine::reload_from_proto_with_pid` resolves
    /// a YAML policy's. A pid of 0 keeps the one the active policy was
    /// resolved with, if any (see [`Self::resolve_binary_symlinks`]).
    ///
    /// # Errors
    ///
    /// Returns an error if `policy` fails validation or fails to load (see
    /// [`Self::from_proto`]), or the engine lock is poisoned.
    pub fn stage(
        &self,
        policy: &ProtoSandboxPolicy,
        entrypoint_pid: u32,
    ) -> Result<StagedCedarPolicy> {
        let validated = crate::policy_validation::validate_sandbox_policy_report(policy)?;
        let policy = validated.policy;
        let entrypoint_pid = match entrypoint_pid {
            0 => self.read_engine()?.entrypoint_pid,
            pid => pid,
        };
        let middleware = MiddlewareConfigs::from_proto(&policy);
        let inputs = PolicyInputs::from_proto(&policy);
        let unchanged = *self.read_inputs()? == inputs;
        if unchanged {
            return Ok(StagedCedarPolicy {
                policy: None,
                entrypoint_pid,
                middleware,
            });
        }
        let loaded = LoadedPolicy::from_proto(&policy, validated.cedar, entrypoint_pid)?;
        Ok(StagedCedarPolicy {
            policy: Some((loaded, inputs)),
            entrypoint_pid,
            middleware,
        })
    }

    /// Activates a policy returned by [`Self::stage`], with its middleware.
    ///
    /// Equivalent to [`Self::commit_configuration`] with no new middleware
    /// services and no credentials to publish.
    ///
    /// # Errors
    ///
    /// See [`Self::commit_configuration`].
    pub fn commit(&self, staged: StagedCedarPolicy) -> Result<()> {
        self.commit_configuration(staged, None, || {}).map(drop)
    }

    /// Activates a staged policy, its middleware, and the caller's
    /// credentials as one runtime configuration, or changes nothing.
    ///
    /// Fallible preparation runs before publication: the staged policy
    /// (or, when the inputs were unchanged, a copy of the
    /// active one) is resolved for the entrypoint process (see
    /// [`Self::prepare_policy`]). Then, under the middleware write lock, the
    /// engine's own locks are acquired and startup resolution is rechecked.
    /// Only then does the middleware generation advance, so pinned middleware
    /// readers are stale; the Cedar policy is swapped in and its generation
    /// advances when the policy or the authored middleware configs changed,
    /// which closes inspected tunnels, as one OPA generation does for YAML;
    /// `commit_credentials` runs; and only then do the new middleware configs
    /// and, when given, `registry` become visible. Middleware readers stay
    /// blocked throughout. A commit that changes neither, such as registry
    /// reconciliation, keeps the Cedar generation and open tunnels.
    ///
    /// `commit_credentials` must be infallible and must not call back into
    /// this engine.
    ///
    /// Returns a guard on the middleware generation this commit published.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider rules fail to compile for the
    /// entrypoint process, or a lock is poisoned. In either case the policy,
    /// the middleware, and the credentials all stay on the previous revision,
    /// no guard becomes stale, and `commit_credentials` is not called.
    pub fn commit_configuration(
        &self,
        staged: StagedCedarPolicy,
        registry: Option<MiddlewareRegistry>,
        commit_credentials: impl FnOnce(),
    ) -> Result<PolicyGenerationGuard> {
        let StagedCedarPolicy {
            policy,
            entrypoint_pid,
            middleware,
        } = staged;
        let prepared = self.prepare_policy(policy, entrypoint_pid)?;
        self.middleware.commit(
            middleware,
            registry,
            || self.prepare_publication(prepared),
            |(locks, prepared), middleware_changed| {
                self.publish_policy(locks, prepared, middleware_changed);
                commit_credentials();
            },
        )
    }

    /// Resolves the policy a commit will activate, for the entrypoint process.
    ///
    /// A policy staged before the entrypoint process was known is resolved
    /// for it here. When the staged inputs matched the active policy's, the
    /// active policy is resolved again once the entrypoint process is known,
    /// as a YAML reload rebuilds its engine and resolves every binary path
    /// again: a symlink retargeted since the last resolution must not keep
    /// its old alias. Takes only read locks, and none across the resolution.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider rules fail to compile for the
    /// entrypoint process, or the engine lock is poisoned.
    fn prepare_policy(
        &self,
        policy: Option<(LoadedPolicy, PolicyInputs)>,
        entrypoint_pid: u32,
    ) -> Result<PreparedPolicy> {
        let entrypoint_pid = match entrypoint_pid {
            0 => self.read_engine()?.entrypoint_pid,
            pid => pid,
        };
        match policy {
            Some((loaded, inputs)) => {
                let loaded = if loaded.entrypoint_pid == entrypoint_pid {
                    loaded
                } else {
                    loaded.resolved_for(&inputs.provider_rule_map(), entrypoint_pid)?
                };
                Ok(PreparedPolicy::Replaced(loaded, inputs))
            }
            None if entrypoint_pid != 0 => {
                // The read lock is held across the resolution, which reads
                // the entrypoint's root filesystem; the swap compares the
                // result against the active policy again under the write lock.
                let active = self.read_engine()?;
                let rules = self.read_inputs()?.provider_rule_map();
                let resolved = active.resolved_for(&rules, entrypoint_pid)?;
                Ok(PreparedPolicy::Resolved(resolved))
            }
            None => Ok(PreparedPolicy::Unchanged),
        }
    }

    /// Acquires every lock a publish writes, in the engine's lock order.
    ///
    /// # Errors
    ///
    /// Returns an error if any of them is poisoned.
    fn write_locks(&self) -> Result<WriteLocks<'_>> {
        Ok(WriteLocks {
            engine: self.write_engine()?,
            inputs: self
                .inputs
                .write()
                .map_err(|_| miette::miette!("Cedar engine lock poisoned"))?,
            fail_closed_reason: self.write_fail_closed_reason()?,
        })
    }

    /// Rechecks startup resolution under the publication lock. This remains
    /// fallible preparation, before middleware or credentials are published.
    fn prepare_publication(
        &self,
        prepared: PreparedPolicy,
    ) -> Result<(WriteLocks<'_>, PreparedPolicy)> {
        let locks = self.write_locks()?;
        let prepared = match prepared {
            PreparedPolicy::Replaced(loaded, inputs)
                if loaded.entrypoint_pid == 0 && locks.engine.entrypoint_pid != 0 =>
            {
                let loaded = loaded
                    .resolved_for(&inputs.provider_rule_map(), locks.engine.entrypoint_pid)?;
                PreparedPolicy::Replaced(loaded, inputs)
            }
            prepared => prepared,
        };
        Ok((locks, prepared))
    }

    /// Swaps `prepared` into the active policy and ends any quarantine.
    ///
    /// The generation advances when the policy or its middleware configs
    /// changed, when a resolved alias or the entrypoint process changed, or
    /// when a quarantine ended. Infallible: every lock is already held.
    fn publish_policy(
        &self,
        locks: WriteLocks<'_>,
        prepared: PreparedPolicy,
        middleware_changed: bool,
    ) {
        let WriteLocks {
            mut engine,
            mut inputs,
            mut fail_closed_reason,
        } = locks;
        let was_fail_closed = fail_closed_reason.take().is_some();
        let changed = match prepared {
            PreparedPolicy::Unchanged => false,
            PreparedPolicy::Resolved(resolved) => {
                let changed = engine.resolution_differs(&resolved);
                *engine = resolved;
                changed
            }
            PreparedPolicy::Replaced(loaded, new_inputs) => {
                *engine = loaded;
                *inputs = new_inputs;
                true
            }
        };
        if changed || middleware_changed || was_fail_closed {
            self.advance_generation();
        }
    }

    /// Resolves the active policy's binary paths in the root filesystem of
    /// the entrypoint process, once it is known.
    ///
    /// The Cedar counterpart of rebuilding the OPA engine with
    /// `OpaEngine::reload_from_proto_with_pid` when the entrypoint starts:
    /// each path policies test in `context.binary_aliases`, and each
    /// provider rule binary used to select token-grant owners, is resolved
    /// as YAML resolves its binary paths. A no-op for 0 or for the pid the
    /// policy was already resolved with; otherwise advances the generation.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned, or the provider rules
    /// fail to load for the entrypoint process; the active policy is
    /// unchanged then.
    pub fn resolve_binary_symlinks(&self, entrypoint_pid: u32) -> Result<()> {
        let mut guard = self.write_engine()?;
        if entrypoint_pid == 0 || guard.entrypoint_pid == entrypoint_pid {
            return Ok(());
        }
        let rules = self.read_inputs()?.provider_rule_map();
        let resolved = guard.resolved_for(&rules, entrypoint_pid)?;
        if guard.resolution_differs(&resolved) {
            *guard = resolved;
            self.advance_generation();
        }
        Ok(())
    }

    fn read_inputs(&self) -> Result<std::sync::RwLockReadGuard<'_, PolicyInputs>> {
        self.inputs
            .read()
            .map_err(|_| miette::miette!("Cedar engine lock poisoned"))
    }

    /// Publishes a deny-all quarantine generation without activating any
    /// part of a rejected candidate policy.
    ///
    /// The active Cedar policy stays loaded for a later
    /// [`Self::exit_fail_closed`] or valid reload, but every new connection
    /// is denied with `reason`. A quarantine is a configuration change: the
    /// Cedar generation advances, which closes every pinned tunnel, and so
    /// does the middleware generation, which stales the configuration guard
    /// the policy poll loop watches (see
    /// [`crate::policy_engine::PolicyEngine::configuration_generation_guard`]),
    /// as `OpaEngine::enter_fail_closed` stales both with its one counter.
    ///
    /// Returns the new Cedar generation.
    ///
    /// # Errors
    ///
    /// Returns an error if a lock is poisoned.
    pub fn enter_fail_closed(&self, reason: impl Into<String>) -> Result<u64> {
        let reason = reason.into();
        // Lock order: middleware, then engine, as a commit takes them.
        self.middleware.change_configuration(|| {
            let _guard = self.write_engine()?;
            *self.write_fail_closed_reason()? = Some(reason);
            Ok((self.advance_generation(), true))
        })
    }

    /// Reactivates the active policy after a quarantine.
    ///
    /// Returns the current Cedar generation, advanced only if a quarantine
    /// ended; the middleware generation advances with it, so the
    /// configuration guard pinned during the quarantine becomes stale.
    ///
    /// # Errors
    ///
    /// Returns an error if a lock is poisoned.
    pub fn exit_fail_closed(&self) -> Result<u64> {
        self.middleware.change_configuration(|| {
            let _guard = self.write_engine()?;
            if self.write_fail_closed_reason()?.take().is_some() {
                Ok((self.advance_generation(), true))
            } else {
                Ok((self.current_generation(), false))
            }
        })
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
}

/// A validated Cedar policy waiting for [`CedarOnlyEngine::commit`].
#[derive(Debug)]
pub struct StagedCedarPolicy {
    /// `None` when the staged inputs matched the active policy's.
    policy: Option<(LoadedPolicy, PolicyInputs)>,
    /// The entrypoint process the policy is to be resolved for; 0 if unknown.
    entrypoint_pid: u32,
    /// The candidate's `network_middlewares`, activated with the policy.
    middleware: MiddlewareConfigs,
}

impl StagedCedarPolicy {
    /// Test-only: makes resolving this policy for the entrypoint process
    /// fail at commit, as provider rules that do not compile for it would.
    ///
    /// # Panics
    ///
    /// Panics if the staged inputs matched the active policy's.
    #[cfg(test)]
    fn fail_binary_resolution_for_tests(&mut self) {
        let (loaded, _) = self.policy.as_mut().expect("a changed policy is staged");
        loaded.fail_resolution = true;
    }
}

/// The policy a commit swaps in, resolved before any lock is taken.
#[derive(Debug)]
enum PreparedPolicy {
    /// The staged inputs matched the active policy's, and the entrypoint
    /// process is not known yet.
    Unchanged,
    /// The active policy, resolved again for the entrypoint process.
    Resolved(LoadedPolicy),
    /// A changed policy and the inputs it was built from.
    Replaced(LoadedPolicy, PolicyInputs),
}

/// Every lock a publish writes, acquired under the middleware write lock.
struct WriteLocks<'a> {
    engine: std::sync::RwLockWriteGuard<'a, LoadedPolicy>,
    inputs: std::sync::RwLockWriteGuard<'a, PolicyInputs>,
    fail_closed_reason: std::sync::RwLockWriteGuard<'a, Option<String>>,
}

impl CedarOnlyEngine {
    /// Authorizes one egress request against the active Cedar policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned, or Cedar fails to
    /// evaluate the request. Callers deny the connection on error.
    pub fn authorize_egress(&self, input: &NetworkInput) -> Result<EgressAuthorization> {
        let mut request = network_request_from_input(input);
        let guard = self.read_engine()?;
        let generation = self.current_generation();
        if let Some(reason) = self.read_fail_closed_reason()? {
            return Ok(EgressAuthorization {
                action: NetworkAction::Deny { reason },
                endpoint_configs: Vec::new(),
                matched_endpoints: Vec::new(),
                exact_declared_endpoint_host: false,
                generation,
                cedar_destination: None,
            });
        }
        request.binary_aliases = guard
            .binary_aliases
            .matching(&request.binary_path, &request.ancestors)?;
        request.binary_globs = guard
            .binary_globs
            .matching(&request.binary_path, &request.ancestors)?;
        // Decided before the host resolves: an allow means Cedar allows some
        // address, and `cedar_destination` checks each resolved one.
        let evaluation = guard
            .cedar
            .authorize_network(&request)
            .map_err(|e| miette::miette!("{e}"))?;

        let action = match evaluation.decision.clone() {
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
            guard.endpoint_configs(&request.host, request.port)
        } else {
            Vec::new()
        };
        // Matches the YAML path: an allowed connection to a host a matching
        // policy names exactly (not through a glob) may resolve to private
        // addresses. For Cedar, that is an allowing permit that names this
        // `host:port`.
        let exact_declared_endpoint_host = allowed && evaluation.names_endpoint;
        // Correlates the decision with the policy DNS mapping a transparent
        // connection dialed; see the module docs.
        let matched_endpoints = if allowed {
            guard.matched_endpoints(&request.host, request.port)
        } else {
            Vec::new()
        };

        let cedar_destination = allowed.then(|| CedarDestination {
            engine: Arc::clone(&guard.cedar),
            provider_ranges: guard.provider_ranges(&request.host, request.port),
            request,
            evaluation,
        });

        Ok(EgressAuthorization {
            action,
            endpoint_configs,
            matched_endpoints,
            exact_declared_endpoint_host,
            generation,
            cedar_destination,
        })
    }

    /// Returns the endpoint settings the credential guard checks for `host:port`.
    ///
    /// The same configs [`Self::authorize_egress`] returns for an allowed
    /// connection, including every path-scoped provider endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned.
    pub fn credential_guards(&self, host: &str, port: u16) -> Result<Vec<EndpointConfig>> {
        Ok(self.read_engine()?.endpoint_configs(host, port))
    }

    /// Returns the filesystem access the active policy grants, from its
    /// loaded engine (see [`openshell_policy::effective_filesystem`]).
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned.
    pub fn effective_filesystem(&self) -> Result<openshell_policy::EffectiveFilesystem> {
        Ok(openshell_policy::cedar::engine_filesystem(
            &self.read_engine()?.cedar,
        ))
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
        Ok(PolicyDnsEligibilitySnapshot {
            endpoints: guard.dns_records(),
            generation,
            fail_closed: false,
        })
    }
}
