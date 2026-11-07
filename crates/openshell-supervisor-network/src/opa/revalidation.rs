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
//! policy input against **every** generation published since its pin, not
//! only the latest. A connection can sleep through several reloads, since the
//! generation watch only delivers the newest value, and one of those reloads
//! may have excluded it even if a later one restored its rules. The engine
//! keeps a bounded history of recent generations for this; a connection whose
//! pin has left the history closes.
//!
//! If the [`ConnectionPolicyContract`] under each of those generations equals
//! the contract that authorized the connection, the guard re-pins to the
//! newest and the relay keeps running. Any difference, an evaluation error, or
//! a fail-closed quarantine among them (which denies everything) makes the
//! guard stale permanently, and the relay closes exactly as it did before.
//!
//! # What the contract must cover
//!
//! The contract must contain every policy input a relay consults after setup,
//! otherwise a connection could outlive a change that should have narrowed it:
//!
//! - The L4 decision and matched policy name.
//! - `matched_endpoints`, in order: the complete endpoint objects of every
//!   policy whose binaries admit the caller and whose endpoints match the host
//!   and port. Per-request Rego rules (`allow_request`, `deny_request`,
//!   `request_deny_reason`, `allowed_token_grant_owners`, and the protocol
//!   helpers they call) read only these endpoints, so an unchanged list means
//!   every per-request decision is unchanged. This is why a tunnel's cloned
//!   evaluator remains valid after it re-pins.
//! - `exact_declared_endpoint_host`, which selects SSRF handling.
//! - The middleware chain selected for the host and, when it is non-empty, the
//!   middleware registry epoch, because tunnels hold a clone of the runner.
//!
//! Relays also read `endpoint_configs`: its first entry selects the TLS mode
//! and `allowed_ips`, and the list feeds L7 route selection. It is not compared
//! separately because Rego derives it from the same endpoints, in the same
//! order, as `matched_endpoints`: it is the matched endpoints that carry
//! extended configuration. An unchanged matched list therefore means unchanged
//! configs.
//!
//! Endpoint objects carry `policy_hash`, the hash of the complete canonical
//! policy. It changes on every reload and only binds endpoint-status
//! observations to an inventory, so it is excluded from the comparison. The
//! revalidator instead records the hash of the generation the connection is
//! pinned to, which is the policy its endpoint-status observations belong to.
//!
//! # Provider credentials
//!
//! Relays resolve provider credentials from the live provider state for every
//! request and WebSocket message, under their own revision guard. What a later
//! request cannot undo is an upstream session that an earlier request already
//! authenticated, such as an upgraded WebSocket.
//!
//! HTTP-family relays therefore carry a credential pin on a connection handle
//! that records which credentials the connection injected, and at which
//! version (see `CredentialUseMarker` in `openshell-core`). The credential
//! state owns one version per credential and changes it exactly when that
//! credential's content changes. Every static secret goes through
//! `SecretResolver`, which reports the environment key and version of each
//! value it hands out, and every token grant goes through `inject_or_report`,
//! which reports the grant's identity before adding the header. Until the
//! first use the pin is inert: the connection has never carried a credential
//! upstream, so a credential change cannot leave it holding a stale one.
//!
//! After that, the connection closes only when a credential it used is no
//! longer at the version it used: rotated, reconfigured, removed, or already
//! superseded when it was sent. Changes to other providers' credentials leave
//! it open. A use that cannot be attributed to one credential is recorded as
//! stale and closes the connection on the next check. Raw TCP and TLS
//! passthrough relays never inject credentials and carry no pin.

use super::{EgressAuthorization, NetworkAction, NetworkInput, OpaEngine, PolicyGenerationGuard};
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
/// Compare contracts with [`Self::relays_identically_to`]. The type
/// deliberately has no `==`: its equality is a policy judgement, not
/// structural identity, and the method is written so that adding a field
/// fails to compile until the comparison handles it. See the module
/// documentation for why each field is present.
#[derive(Debug, Clone)]
pub struct ConnectionPolicyContract {
    action: NetworkAction,
    /// `(policy_name, endpoint)` pairs, in order. `endpoint_configs` is derived
    /// from these, so it is not kept; see the module documentation. The
    /// endpoint index is deliberately omitted: inserting an unrelated endpoint
    /// earlier in the same policy shifts indexes without changing what this
    /// connection may do.
    matched_endpoints: Vec<(String, regorus::Value)>,
    exact_declared_endpoint_host: bool,
    middleware_chain: Vec<ChainEntry>,
    /// Present only when the chain is non-empty; a registry swap cannot affect
    /// a connection that runs no middleware.
    middleware_registry_epoch: Option<u64>,
    /// The complete-policy hash stamped into this generation's endpoints, or
    /// empty for policies that carry none. Metadata, not compared: it is what
    /// endpoint-status observations of a re-pinned connection belong to.
    policy_hash: String,
}

impl ConnectionPolicyContract {
    /// Built only by the engine, from one generation's authorization and
    /// middleware selection, so a baseline and its re-checks share one path.
    pub(super) fn new(
        authorization: &EgressAuthorization,
        middleware_chain: Vec<ChainEntry>,
        middleware_registry_epoch: u64,
    ) -> Self {
        let middleware_registry_epoch =
            (!middleware_chain.is_empty()).then_some(middleware_registry_epoch);
        Self {
            action: authorization.action.clone(),
            matched_endpoints: authorization
                .matched_endpoints
                .iter()
                .map(|endpoint| {
                    (
                        endpoint.policy_name.clone(),
                        semantic_endpoint(&endpoint.endpoint),
                    )
                })
                .collect(),
            exact_declared_endpoint_host: authorization.exact_declared_endpoint_host,
            middleware_chain,
            middleware_registry_epoch,
            policy_hash: stamped_policy_hash(authorization),
        }
    }

    fn allows(&self) -> bool {
        matches!(self.action, NetworkAction::Allow { .. })
    }

    /// Whether a connection authorized under `other` is authorized and
    /// relayed identically under `self`.
    ///
    /// The destructuring patterns name every field without `..`, so a new
    /// field in the contract must be added here before the crate compiles.
    /// Forgetting one would let connections survive changes to it.
    pub fn relays_identically_to(&self, other: &Self) -> bool {
        let Self {
            action,
            matched_endpoints,
            exact_declared_endpoint_host,
            middleware_chain,
            middleware_registry_epoch,
            // Changes on every reload; see `NON_SEMANTIC_ENDPOINT_KEYS`.
            policy_hash: _,
        } = self;
        let Self {
            action: other_action,
            matched_endpoints: other_matched_endpoints,
            exact_declared_endpoint_host: other_exact_declared_endpoint_host,
            middleware_chain: other_middleware_chain,
            middleware_registry_epoch: other_middleware_registry_epoch,
            policy_hash: _,
        } = other;
        action == other_action
            && matched_endpoints == other_matched_endpoints
            && exact_declared_endpoint_host == other_exact_declared_endpoint_host
            && same_middleware_chain(middleware_chain, other_middleware_chain)
            && middleware_registry_epoch == other_middleware_registry_epoch
    }
}

/// Whether two selected chains run the same stages in the same order with
/// the same settings.
///
/// Compares every [`ChainEntry`] field explicitly instead of relying on a
/// derived `==` on the shared type, for the same exhaustiveness reason as
/// [`ConnectionPolicyContract::relays_identically_to`].
fn same_middleware_chain(left: &[ChainEntry], right: &[ChainEntry]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            let ChainEntry {
                name,
                implementation,
                order,
                config,
                on_error,
            } = left;
            let ChainEntry {
                name: other_name,
                implementation: other_implementation,
                order: other_order,
                config: other_config,
                on_error: other_on_error,
            } = right;
            name == other_name
                && implementation == other_implementation
                && order == other_order
                && config == other_config
                && on_error == other_on_error
        })
}

/// The complete-policy hash proto conversion stamps into every endpoint of a
/// generation, taken from any endpoint this authorization matched. Empty when
/// the policy carries none, as YAML policies do.
fn stamped_policy_hash(authorization: &EgressAuthorization) -> String {
    authorization
        .matched_endpoints
        .iter()
        .map(|endpoint| &endpoint.endpoint)
        .find_map(|endpoint| match &endpoint["policy_hash"] {
            regorus::Value::String(hash) if !hash.is_empty() => Some(hash.to_string()),
            _ => None,
        })
        .unwrap_or_default()
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
    /// The newest generation this connection is pinned to, starting with the
    /// one that authorized it, and that generation's stamped policy hash.
    pinned_policy: std::sync::Mutex<(u64, String)>,
}

/// What a relay's credentials must still match for it to stay open.
///
/// Only tracked handles (see `ProviderCredentialState::with_use_tracking`)
/// can say which credentials a connection used. Every production relay gets
/// one; a pin on an untracked handle reports stale, so a caller that forgets
/// to track closes on the next reload rather than never.
#[derive(Debug)]
struct CredentialPin(ProviderCredentialState);

impl CredentialPin {
    /// False once a credential this connection injected is no longer at the
    /// version it injected.
    fn is_current(&self) -> bool {
        self.0.credential_uses_current()
    }
}

impl PolicyRevalidator {
    /// Capture the contract that authorized a connection with `input` at
    /// `authorized_generation`.
    ///
    /// The baseline is evaluated by the same function as every re-check, from
    /// that generation's recorded policy. Pass the relay's provider credential
    /// handle when the relay can inject credentials; see the module
    /// documentation.
    ///
    /// Returns `None` for denials, and when the generation has left the
    /// history. A guard without a revalidator keeps the strict
    /// close-on-change behavior.
    pub(crate) fn capture(
        engine: &Arc<OpaEngine>,
        input: NetworkInput,
        authorized_generation: u64,
        credentials: Option<&ProviderCredentialState>,
    ) -> Option<Arc<Self>> {
        let baseline = engine
            .connection_contract_at(&input, authorized_generation)
            .ok()
            .flatten()
            .filter(ConnectionPolicyContract::allows)?;
        let pinned_policy =
            std::sync::Mutex::new((authorized_generation, baseline.policy_hash.clone()));
        Some(Arc::new(Self {
            engine: Arc::downgrade(engine),
            baseline,
            input,
            credentials: credentials.map(|state| CredentialPin(state.clone())),
            invalidated: AtomicBool::new(false),
            pinned_policy,
        }))
    }

    pub(super) fn is_invalidated(&self) -> bool {
        self.invalidated.load(Ordering::Acquire)
    }

    /// Re-evaluate against every generation published since
    /// `captured_generation`.
    ///
    /// Returns the generation the connection was checked up to, or `None`
    /// (permanently) when its contract did not hold throughout.
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
        // Every generation since the pin, not only the latest: a reload that
        // would have closed this connection must close it even if a later one
        // restored its rules before it woke. That includes fail-closed
        // quarantines, whose generations deny everything. Evaluation errors
        // and generations no longer in the history fail closed.
        let (contracts, current) = engine
            .connection_contracts_since(&self.input, captured_generation)
            .ok()
            .flatten()?;
        if !contracts
            .iter()
            .all(|contract| contract.relays_identically_to(&self.baseline))
        {
            return None;
        }
        if let Some(newest) = contracts.last() {
            self.record_repin(current, &newest.policy_hash);
        }
        Some(current)
    }

    fn record_repin(&self, generation: u64, policy_hash: &str) {
        let mut pinned = self
            .pinned_policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pinned.0 < generation {
            *pinned = (generation, policy_hash.to_owned());
        }
    }

    /// The stamped policy hash of `pinned_generation`, the generation that
    /// authorized this connection or one it re-pinned to, if its policy carries
    /// one. Endpoint-status observations of the connection belong to that
    /// policy: it authorized the connection, or its contract was shown
    /// identical there.
    pub(super) fn pinned_policy_hash(&self, pinned_generation: u64) -> Option<String> {
        let pinned = self
            .pinned_policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (generation, hash) = &*pinned;
        (*generation == pinned_generation && !hash.is_empty()).then(|| hash.clone())
    }

    /// Advance a shared pin while the contract still holds.
    ///
    /// Each round checks only the generations published since the previous
    /// one. Returns `true` once `pin` equals the live generation.
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

impl OpaEngine {
    /// Pin `generation` for an established connection with `input`, re-pinning
    /// through later generations that leave its contract intact.
    ///
    /// The single entry point for relays and their tests. Fails if
    /// `generation` is no longer current. `credentials` is the connection's
    /// tracked provider handle when the relay can inject credentials.
    pub(crate) fn revalidating_generation_guard(
        self: &Arc<Self>,
        input: NetworkInput,
        generation: u64,
        credentials: Option<&ProviderCredentialState>,
    ) -> miette::Result<PolicyGenerationGuard> {
        let guard = self.generation_guard(generation)?;
        let revalidator = PolicyRevalidator::capture(self, input, generation, credentials);
        Ok(guard.with_revalidator(revalidator))
    }
}
