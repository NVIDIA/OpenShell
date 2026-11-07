// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Re-check established connections when the policy generation advances.
//!
//! Every policy reload, middleware registry replacement, and fail-closed
//! transition advances one sandbox-wide generation. Relays pin the generation
//! that authorized them. Without a revalidator, a pinned guard becomes stale as
//! soon as the generation moves, so approving an endpoint for one host closes
//! every open connection in the sandbox.
//!
//! A [`PolicyRevalidator`] lets a pinned guard follow the generation instead.
//! When the generation moves, the guard re-evaluates the connection's original
//! policy input against the live engine. If the resulting
//! [`ConnectionPolicyContract`] equals the contract that authorized the
//! connection, the guard re-pins to the new generation and the relay keeps
//! running. Any difference, an evaluation error, or an intervening fail-closed
//! quarantine makes the guard stale permanently, and the relay closes exactly
//! as it did before.
//!
//! # What the contract must cover
//!
//! The contract must contain every policy input a relay consults after setup,
//! otherwise a connection could outlive a change that should have narrowed it:
//!
//! - The L4 decision and matched policy name.
//! - `endpoint_configs`, in order. The first entry selects the TLS mode and
//!   `allowed_ips`; the list feeds L7 route selection.
//! - `matched_endpoints`: the complete endpoint objects of every policy whose
//!   binaries admit the caller and whose endpoints match the host and port.
//!   Per-request Rego rules (`allow_request`, `deny_request`,
//!   `request_deny_reason`, `allowed_token_grant_owners`, and the protocol
//!   helpers they call) read only these endpoints, so an unchanged list means
//!   every per-request decision is unchanged. This is why a tunnel's cloned
//!   evaluator remains valid after it re-pins.
//! - `exact_declared_endpoint_host`, which selects SSRF handling.
//! - The middleware chain selected for the host and, when it is non-empty, the
//!   middleware registry epoch, because tunnels hold a clone of the runner.
//!
//! Endpoint objects carry `policy_hash`, the hash of the complete canonical
//! policy. It changes on every reload and only binds endpoint-status
//! observations to an inventory, so it is excluded from the comparison. A
//! re-pinned MCP tunnel therefore keeps its original hash, and its later
//! observations are rejected by the new inventory until the client reconnects.
//! That affects status reporting only, never authorization.
//!
//! # Provider credentials
//!
//! Relays resolve provider credentials from the live provider state for every
//! request and WebSocket message, under their own revision guard. What a later
//! request cannot undo is an upstream session that an earlier request already
//! authenticated, such as an upgraded WebSocket. A relay that can inject
//! credentials therefore pins the provider credential installation as well,
//! and closes when it changes, exactly as it did before revalidation. Raw TCP
//! and TLS passthrough relays never inject credentials and do not pin it.
//! The pin covers the whole installation, not just this endpoint's providers;
//! narrowing it is possible but needs per-endpoint credential fingerprints.

use super::{MatchedEndpoint, NetworkAction, NetworkInput, OpaEngine};
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_supervisor_middleware::ChainEntry;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use tracing::debug;

/// Endpoint keys that are policy metadata rather than policy semantics.
///
/// `policy_hash` hashes the complete canonical policy, so it differs after
/// every reload even when this endpoint did not change.
const NON_SEMANTIC_ENDPOINT_KEYS: &[&str] = &["policy_hash"];

/// Upper bound on back-to-back reloads a single staleness check will follow.
///
/// Each round re-evaluates against the live engine. If reloads keep landing
/// while a check runs, the guard gives up and reports stale, which is the
/// pre-revalidation behavior.
const MAX_REVALIDATION_ROUNDS: usize = 4;

/// Policy facts that decide how an established connection is relayed.
///
/// Two contracts compare equal only when a connection authorized under one
/// would be authorized and relayed identically under the other. See the
/// module documentation for why each field is present.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionPolicyContract {
    action: NetworkAction,
    endpoint_configs: Vec<regorus::Value>,
    /// `(policy_name, endpoint)` pairs. The endpoint index is deliberately
    /// omitted: inserting an unrelated endpoint earlier in the same policy
    /// shifts indexes without changing what this connection may do.
    matched_endpoints: Vec<(String, regorus::Value)>,
    exact_declared_endpoint_host: bool,
    middleware_chain: Vec<ChainEntry>,
    /// Present only when the chain is non-empty; a registry swap cannot affect
    /// a connection that runs no middleware.
    middleware_registry_epoch: Option<u64>,
}

/// The authorization facts an adapter captured for one connection.
pub struct AuthorizedConnection<'a> {
    pub action: &'a NetworkAction,
    pub endpoint_configs: &'a [regorus::Value],
    pub matched_endpoints: &'a [MatchedEndpoint],
    pub exact_declared_endpoint_host: bool,
}

impl ConnectionPolicyContract {
    pub(super) fn new(
        authorized: &AuthorizedConnection<'_>,
        middleware_chain: Vec<ChainEntry>,
        middleware_registry_epoch: u64,
    ) -> Self {
        let middleware_registry_epoch =
            (!middleware_chain.is_empty()).then_some(middleware_registry_epoch);
        Self {
            action: authorized.action.clone(),
            endpoint_configs: authorized
                .endpoint_configs
                .iter()
                .map(semantic_endpoint)
                .collect(),
            matched_endpoints: authorized
                .matched_endpoints
                .iter()
                .map(|endpoint| {
                    (
                        endpoint.policy_name.clone(),
                        semantic_endpoint(&endpoint.endpoint),
                    )
                })
                .collect(),
            exact_declared_endpoint_host: authorized.exact_declared_endpoint_host,
            middleware_chain,
            middleware_registry_epoch,
        }
    }
}

/// Copy an endpoint object without keys that change on every reload.
fn semantic_endpoint(value: &regorus::Value) -> regorus::Value {
    let mut value = value.clone();
    let has_metadata = matches!(
        &value,
        regorus::Value::Object(fields)
            if NON_SEMANTIC_ENDPOINT_KEYS
                .iter()
                .any(|key| fields.contains_key(&regorus::Value::from(*key)))
    );
    if has_metadata && let Ok(fields) = value.as_object_mut() {
        for key in NON_SEMANTIC_ENDPOINT_KEYS {
            fields.remove(&regorus::Value::from(*key));
        }
    }
    value
}

/// Re-evaluates one connection's policy contract after a generation change.
///
/// Shared by every clone of the guards pinned for that connection. Once a
/// re-evaluation finds a different contract the revalidator is invalidated for
/// good, so restoring the earlier policy cannot revive a connection that was
/// already observed under a policy that excluded it.
#[derive(Debug)]
pub struct PolicyRevalidator {
    engine: Weak<OpaEngine>,
    input: NetworkInput,
    baseline: ConnectionPolicyContract,
    credentials: Option<CredentialPin>,
    invalidated: AtomicBool,
}

/// The provider credential installation a relay may have injected from.
#[derive(Debug)]
struct CredentialPin {
    state: ProviderCredentialState,
    revision: u64,
    installation_id: String,
}

impl CredentialPin {
    fn capture(state: &ProviderCredentialState) -> Self {
        let snapshot = state.snapshot();
        Self {
            state: state.clone(),
            revision: snapshot.revision,
            installation_id: snapshot.installation_id.clone(),
        }
    }

    fn is_current(&self) -> bool {
        let snapshot = self.state.snapshot();
        snapshot.revision == self.revision && snapshot.installation_id == self.installation_id
    }
}

impl PolicyRevalidator {
    /// Capture the contract that authorized a connection at
    /// `authorized_generation`.
    ///
    /// Pass the relay's provider credential state when the relay can inject
    /// credentials; the connection then also closes when that installation
    /// changes. See the module documentation.
    ///
    /// Returns `None` for denials, and when the engine has already moved past
    /// `authorized_generation` (the caller's pin fails in that case anyway). A
    /// guard without a revalidator keeps the strict close-on-change behavior.
    pub fn capture(
        engine: &Arc<OpaEngine>,
        input: NetworkInput,
        authorized: &AuthorizedConnection<'_>,
        authorized_generation: u64,
        credentials: Option<&ProviderCredentialState>,
    ) -> Option<Arc<Self>> {
        if !matches!(authorized.action, NetworkAction::Allow { .. }) {
            return None;
        }
        let (middleware_chain, middleware_registry_epoch) = engine
            .middleware_selection_at(&input, authorized_generation)
            .ok()
            .flatten()?;
        Some(Arc::new(Self {
            engine: Arc::downgrade(engine),
            baseline: ConnectionPolicyContract::new(
                authorized,
                middleware_chain,
                middleware_registry_epoch,
            ),
            input,
            credentials: credentials.map(CredentialPin::capture),
            invalidated: AtomicBool::new(false),
        }))
    }

    pub(super) fn is_invalidated(&self) -> bool {
        self.invalidated.load(Ordering::Acquire)
    }

    /// Re-evaluate against the live engine.
    ///
    /// Returns the generation at which the unchanged contract was evaluated,
    /// or `None` (permanently) when the contract no longer holds.
    fn revalidate(&self, captured_generation: u64) -> Option<u64> {
        if self.is_invalidated() {
            return None;
        }
        let outcome = self.evaluate(captured_generation);
        if outcome.is_none() {
            self.invalidated.store(true, Ordering::Release);
        }
        outcome
    }

    fn evaluate(&self, captured_generation: u64) -> Option<u64> {
        if !self
            .credentials
            .as_ref()
            .is_none_or(CredentialPin::is_current)
        {
            return None;
        }
        let engine = self.engine.upgrade()?;
        // A quarantine is a hard stop even if a later generation restores the
        // previous policy before this connection noticed. Evaluation errors
        // also fail closed.
        if engine.fail_closed_after(captured_generation) {
            return None;
        }
        let (contract, generation) = engine.connection_policy_contract(&self.input).ok()?;
        (contract == self.baseline).then_some(generation)
    }

    /// Advance a shared pin while the contract still holds.
    ///
    /// Returns `true` once `pin` equals the live generation.
    pub(super) fn follow(&self, pin: &AtomicU64, live: &AtomicU64) -> bool {
        for _ in 0..MAX_REVALIDATION_ROUNDS {
            let captured = pin.load(Ordering::Acquire);
            if captured == live.load(Ordering::Acquire) {
                return !self.is_invalidated();
            }
            let Some(generation) = self.revalidate(captured) else {
                debug!(
                    host = %self.input.host,
                    port = self.input.port,
                    captured_generation = captured,
                    "Policy change affects established connection; closing"
                );
                return false;
            };
            // Clones of a guard share the pin; never move it backwards.
            let pinned = pin.fetch_max(generation, Ordering::AcqRel).max(generation);
            debug!(
                host = %self.input.host,
                port = self.input.port,
                previous_generation = captured,
                pinned_generation = pinned,
                "Policy change does not affect established connection; re-pinned"
            );
        }
        pin.load(Ordering::Acquire) == live.load(Ordering::Acquire) && !self.is_invalidated()
    }
}
