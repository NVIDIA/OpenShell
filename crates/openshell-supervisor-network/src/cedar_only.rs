// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Rust guideline compliant 2026-10-01

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
//! Same CONNECT-time-only scope as the rest of this crate's Cedar work:
//! `openshell_policy_cedar::CedarNetworkEngine` covers host/binary/ancestor
//! matching, not L7. `EgressAuthorization::{endpoint_configs,matched_endpoints}`
//! are always empty from this engine — those feed L7 config lookup and the
//! not-yet-landed policy-DNS adapter, both out of scope here.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use miette::Result;
use openshell_policy_cedar::{CedarNetworkEngine, NetworkDecision};
use tokio::sync::watch;

use crate::cedar_shadow::network_request_from_input;
use crate::opa::{EgressAuthorization, MatchedEndpoint, NetworkAction, NetworkInput};
use crate::opa::{PolicyGenerationGuard, generation_guard_for};

/// Cedar-backed, fully authoritative network policy evaluator.
///
/// No hidden fallback to OPA: a sandbox either uses this engine for every
/// network decision, or [`crate::opa::OpaEngine`] for every network
/// decision, chosen once at policy load.
pub struct CedarOnlyEngine {
    engine: RwLock<CedarNetworkEngine>,
    generation: Arc<AtomicU64>,
    generation_tx: watch::Sender<u64>,
}

impl CedarOnlyEngine {
    /// Parses `policy_src` (`.cedar` syntax) against the canonical schema
    /// and builds the engine.
    ///
    /// # Errors
    ///
    /// Returns an error if `policy_src` fails to parse.
    pub fn from_policy_str(policy_src: &str) -> Result<Self> {
        let engine =
            CedarNetworkEngine::from_policy_str(policy_src).map_err(|e| miette::miette!("{e}"))?;
        let (generation_tx, _) = watch::channel(0);
        Ok(Self {
            engine: RwLock::new(engine),
            generation: Arc::new(AtomicU64::new(0)),
            generation_tx,
        })
    }

    /// Rebuilds the engine from a freshly reloaded policy and advances the
    /// generation counter. Call this directly alongside wherever
    /// `OpaEngine::reload*` would be called for a YAML-sourced sandbox.
    ///
    /// # Errors
    ///
    /// Returns an error if `policy_src` fails to parse. On error, the
    /// previous policy and generation stay active (last-known-good,
    /// matching `OpaEngine`'s reload failure behavior).
    pub fn reload_from_policy_str(&self, policy_src: &str) -> Result<()> {
        let engine =
            CedarNetworkEngine::from_policy_str(policy_src).map_err(|e| miette::miette!("{e}"))?;
        let mut guard = self
            .engine
            .write()
            .map_err(|_| miette::miette!("Cedar engine lock poisoned"))?;
        *guard = engine;
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.generation_tx.send_replace(generation);
        Ok(())
    }

    /// Extracts the filesystem paths this engine's policy set permits for
    /// reading and/or writing, for building the domain `FilesystemPolicy`
    /// consumed by Landlock. See
    /// [`openshell_policy_cedar::CedarNetworkEngine::extract_authorized_paths`].
    ///
    /// # Errors
    ///
    /// Returns an error if any policy `forbid`s a `FilesystemPath`.
    pub fn extract_authorized_paths(
        &self,
    ) -> Result<openshell_policy_cedar::filesystem::FilesystemPolicyInput> {
        let guard = self
            .engine
            .read()
            .map_err(|_| miette::miette!("Cedar engine lock poisoned"))?;
        guard
            .extract_authorized_paths()
            .map_err(|e| miette::miette!("{e}"))
    }
}

impl crate::opa::NetworkPolicyEngine for CedarOnlyEngine {
    fn authorize_egress(&self, input: &NetworkInput) -> Result<EgressAuthorization> {
        let request = network_request_from_input(input);
        let generation = self.current_generation();

        let guard = self
            .engine
            .read()
            .map_err(|_| miette::miette!("Cedar engine lock poisoned"))?;
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

        Ok(EgressAuthorization {
            action,
            // L7 config lookup and the policy-DNS adapter are out of scope
            // for Cedar-sourced sandboxes in this phase (see module docs).
            endpoint_configs: Vec::new(),
            matched_endpoints: Vec::<MatchedEndpoint>::new(),
            exact_declared_endpoint_host: false,
            generation,
        })
    }

    fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn generation_guard(&self, expected_generation: u64) -> Result<PolicyGenerationGuard> {
        generation_guard_for(
            expected_generation,
            self.current_generation(),
            &self.generation,
            &self.generation_tx,
        )
    }

    fn binary_identity_required(&self) -> bool {
        true
    }

    fn websocket_assembly_budget(&self) -> crate::l7::websocket::WebSocketAssemblyBudget {
        crate::l7::websocket::WebSocketAssemblyBudget::default()
    }
}
