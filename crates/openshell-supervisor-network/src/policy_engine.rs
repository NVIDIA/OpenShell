// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The authoritative policy engine for a sandbox's network decisions.
//!
//! A sandbox's policy is either YAML, enforced by [`OpaEngine`], or Cedar,
//! enforced by [`CedarOnlyEngine`]. The choice is made once at startup from
//! the policy format and never changes. [`PolicyEngine`] is the single type
//! every network decision point (CONNECT, forward proxy, policy DNS, and L7
//! relay setup) receives, so decision code cannot reach the wrong engine.
//!
//! A Cedar-sourced sandbox still owns an `OpaEngine` built from an empty
//! network policy. It serves only middleware chain resolution and per-tunnel
//! plumbing, never an authorization decision. [`PolicyEngine::tunnel_engine`]
//! is the one place the two meet: it builds the per-tunnel evaluator from
//! that plumbing engine, but pins it to the authoritative engine's
//! generation and routes its L7 decisions to Cedar.

use std::fmt;
use std::sync::Arc;

use miette::Result;

use crate::cedar_only::CedarOnlyEngine;
use crate::l7::websocket::WebSocketAssemblyBudget;
use crate::opa::{
    EgressAuthorization, NetworkInput, OpaEngine, PolicyDnsEligibilitySnapshot,
    PolicyGenerationGuard, TunnelPolicyEngine,
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
            Self::Cedar(_) => WebSocketAssemblyBudget::default(),
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

    /// Returns the endpoint settings the credential guard checks for a request.
    ///
    /// The guard refuses an uninspected connection to an endpoint that
    /// carries provider credentials.
    ///
    /// # Errors
    ///
    /// Returns an error only for an evaluator-internal failure.
    pub fn endpoint_credential_guards(&self, input: &NetworkInput) -> Result<Vec<regorus::Value>> {
        match self {
            Self::Opa(engine) => engine.query_endpoint_credential_guards(input),
            Self::Cedar(engine) => engine.credential_guards(&input.host, input.port),
        }
    }

    /// Builds the per-tunnel L7 evaluator for a decision at `expected_generation`.
    ///
    /// For a YAML policy, `plumbing` is this engine, and the tunnel is
    /// cloned and pinned under one lock. For a Cedar policy, `plumbing` is
    /// the sandbox's empty-policy OPA engine: it supplies middleware, while
    /// the tunnel's staleness tracks Cedar's generation and its L7
    /// decisions come from Cedar.
    ///
    /// # Errors
    ///
    /// Returns an error if `expected_generation` is stale or an engine lock
    /// is poisoned.
    pub fn tunnel_engine(
        &self,
        plumbing: &OpaEngine,
        expected_generation: u64,
    ) -> Result<TunnelPolicyEngine> {
        match self {
            Self::Opa(engine) => engine.clone_engine_for_tunnel(expected_generation),
            Self::Cedar(engine) => {
                let guard = engine.generation_guard(expected_generation)?;
                // The plumbing engine's own generation is unrelated to the
                // Cedar decision, so clone it at whatever it currently is.
                let tunnel = plumbing.clone_engine_for_tunnel(plumbing.current_generation())?;
                Ok(tunnel.with_cedar(guard, engine.l7_handle(expected_generation)))
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
