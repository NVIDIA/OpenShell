// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pluggable policy-provider subsystem.
//!
//! The gateway today resolves an effective policy and accepts policy mutations
//! through inline calls to [`crate::persistence::Store`] from the gRPC layer.
//! This module promotes that surface into a trait + registry so an alternate
//! provider (next session: `AttestedPolicyProvider`, which consumes signed
//! projections from a Runtime Policy Verifier daemon) can refuse the mutator
//! methods while still serving an `Authoritative` effective policy at
//! admission time. See the Attested Policy Projection RFC and
//! `runtime-policy-verifier/docs/app-implementation-plan.md` W-B.
//!
//! Structure intentionally mirrors `openshell-providers::ProviderPlugin` /
//! `ProviderRegistry`: a trait, a `dyn`-safe registry keyed by canonical
//! policy-type id (`type` in TOML, matching `ProviderPlugin`'s selector
//! convention), and an error type with an `Unsupported { policy_type,
//! operation }` variant that maps to `tonic::Status::unimplemented` at the
//! gRPC edge.

mod local;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::persistence::PersistenceError;

pub use local::LocalPolicyProvider;

/// Policy-type id for the in-process, store-backed policy provider.
pub const LOCAL_POLICY_TYPE_ID: &str = "local";

/// Policy-type id for the (forthcoming) Attested Policy Projection provider.
///
/// Declared here so config validation can produce a friendly "policy type
/// not yet available" error rather than the generic "unknown policy type"
/// error a follow-up implementer's typo would produce.
pub const ATTESTED_POLICY_TYPE_ID: &str = "attested";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by [`PolicyProvider`] implementations.
///
/// `Unsupported` mirrors `openshell_providers::ProviderError::UnsupportedProvider`
/// — it carries enough context for the gRPC layer to surface the refusal as a
/// `Status::unimplemented` reply naming both the policy type and the
/// operation it refused.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The active policy provider does not implement this operation. The
    /// default trait impl of `set_policy` / `update_policy` /
    /// `delete_policy` returns this so a provider only needs to override
    /// the operations it supports. The `policy_type` field carries the
    /// provider's `id()` — the same string the config selector uses — so
    /// audit and error messages can name it precisely.
    #[error("policy type '{policy_type}' does not support operation '{operation}'")]
    Unsupported {
        policy_type: &'static str,
        operation: &'static str,
    },

    /// Wraps a persistence-layer failure produced by the local provider.
    /// The gRPC layer maps this back to the same status it would have
    /// produced before the provider seam existed.
    #[error("policy persistence error: {0}")]
    Persistence(#[from] PersistenceError),
}

/// Context describing the canonical sandbox-scoped policy replacement
/// requested by a CLI `openshell policy set` (or equivalent gRPC
/// `UpdateConfig` call with `policy` set and no `merge_operations`).
#[derive(Debug, Clone)]
pub struct SetSandboxPolicyCtx {
    pub sandbox_id: String,
    pub sandbox_name: String,
    pub expected_resource_version: u64,
    pub policy: openshell_core::proto::SandboxPolicy,
}

/// Context describing the canonical sandbox-scoped policy merge requested by
/// a CLI `openshell policy update` (gRPC `UpdateConfig` with
/// `merge_operations`).
#[derive(Debug, Clone)]
pub struct UpdateSandboxPolicyCtx {
    pub sandbox_id: String,
    pub sandbox_name: String,
    pub merge_operations: Vec<openshell_policy::PolicyMergeOp>,
    /// The baseline `spec.policy` for the sandbox, used to enforce
    /// static-field-unchanged checks during the merge.
    pub baseline_policy: Option<openshell_core::proto::SandboxPolicy>,
}

/// Context describing a global-policy delete (`openshell policy delete
/// --global`).
#[derive(Debug, Clone)]
pub struct DeleteGlobalPolicyCtx {
    /// Sentinel sandbox id used by the store layer for global policy
    /// revisions. The handler passes its own constant so this module does not
    /// need to know which constant the policy gRPC module chose.
    pub global_policy_sandbox_id: String,
}

/// Outcome of a successful policy mutation. Mirrors the fields of
/// `UpdateConfigResponse` so the gRPC layer can build the reply without
/// reaching back into the store.
#[derive(Debug, Clone, Default)]
pub struct PolicyMutationOutcome {
    pub version: u32,
    pub policy_hash: String,
    pub settings_revision: u64,
    pub deleted: bool,
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Pluggable policy provider.
///
/// Each provider answers two questions:
///   1. What is the effective policy for this sandbox at admission time?
///      (`get_effective_policy`)
///   2. Will it accept a policy mutation from the gateway's control plane?
///      (`set_policy`, `update_policy`, `delete_policy` — default `Unsupported`)
///
/// The default mutator impls returning `Unsupported` are load-bearing: a
/// provider that should refuse `openshell policy set | update | delete`
/// (e.g. the forthcoming `AttestedPolicyProvider`, which is fed by an
/// off-host signed bundle and has no notion of in-band mutation) inherits
/// the refusal automatically.
///
/// **v0 scope note.** For the local provider this trait is a gating + thin-
/// persistence seam: `set_policy` writes the revision row and is the single
/// place that decides "yes, this mutation is allowed"; `update_policy` and
/// `delete_policy` are pure gates whose work (merge-with-retry, settings-map
/// mutation, audit emission) remains in the gRPC handler. The shape is wide
/// enough to absorb the full attested-provider semantics in the next session
/// without changing the trait again.
#[async_trait]
pub trait PolicyProvider: Send + Sync + std::fmt::Debug {
    /// Canonical policy-type id, e.g. `"local"` or `"attested"`. Must match
    /// the string the registry uses to look this provider up and the
    /// `[openshell.policy] type = ...` value in the gateway config.
    fn id(&self) -> &'static str;

    /// Return the effective policy for `sandbox_id`. The store-backed local
    /// provider returns the latest revision recorded for that sandbox (or
    /// `None` if no revision exists yet); the attested provider will return
    /// the projected policy carried by the latest verified envelope.
    async fn get_effective_policy(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<openshell_core::proto::SandboxPolicy>, PolicyError>;

    /// Replace the policy for a sandbox. Default: `Unsupported`.
    async fn set_policy(
        &self,
        _ctx: &SetSandboxPolicyCtx,
    ) -> Result<PolicyMutationOutcome, PolicyError> {
        Err(PolicyError::Unsupported {
            policy_type: self.id(),
            operation: "set_policy",
        })
    }

    /// Apply a sequence of incremental merge operations to a sandbox's
    /// policy. Default: `Unsupported`.
    async fn update_policy(
        &self,
        _ctx: &UpdateSandboxPolicyCtx,
    ) -> Result<PolicyMutationOutcome, PolicyError> {
        Err(PolicyError::Unsupported {
            policy_type: self.id(),
            operation: "update_policy",
        })
    }

    /// Delete the global policy. The local provider implements this against
    /// the global-policy sandbox-id sentinel; remote providers may refuse.
    /// Default: `Unsupported`.
    async fn delete_policy(
        &self,
        _ctx: &DeleteGlobalPolicyCtx,
    ) -> Result<PolicyMutationOutcome, PolicyError> {
        Err(PolicyError::Unsupported {
            policy_type: self.id(),
            operation: "delete_policy",
        })
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Resolves policy-type-id strings to a registered [`PolicyProvider`].
/// Mirrors `openshell_providers::ProviderRegistry` so future providers can
/// be added without changing the wiring at startup.
#[derive(Default)]
pub struct PolicyProviderRegistry {
    providers: HashMap<&'static str, Arc<dyn PolicyProvider>>,
}

impl std::fmt::Debug for PolicyProviderRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyProviderRegistry")
            .field("providers", &self.providers.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl PolicyProviderRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<P>(&mut self, provider: P)
    where
        P: PolicyProvider + 'static,
    {
        self.providers.insert(provider.id(), Arc::new(provider));
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<Arc<dyn PolicyProvider>> {
        self.providers.get(id).cloned()
    }

    /// Registered policy-type ids, sorted. Used for diagnostic messages
    /// when a configured policy type is not found; kept on the registry
    /// surface even though no caller exercises it in v0 because it mirrors
    /// `ProviderRegistry::known_types` and the next session's
    /// `AttestedPolicyProvider` integration will consume it.
    #[allow(dead_code)] // see doc comment
    #[must_use]
    pub fn known_policy_types(&self) -> Vec<&'static str> {
        let mut ids: Vec<_> = self.providers.keys().copied().collect();
        ids.sort_unstable();
        ids
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A bare-bones provider with no method overrides. Used to confirm the
    /// trait's default `Unsupported` impls fire for the three mutators.
    #[derive(Debug)]
    struct StubProvider;

    #[async_trait]
    impl PolicyProvider for StubProvider {
        fn id(&self) -> &'static str {
            "stub"
        }

        async fn get_effective_policy(
            &self,
            _sandbox_id: &str,
        ) -> Result<Option<openshell_core::proto::SandboxPolicy>, PolicyError> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn stub_provider_set_policy_returns_unsupported() {
        let p = StubProvider;
        let err = p
            .set_policy(&SetSandboxPolicyCtx {
                sandbox_id: "sb".into(),
                sandbox_name: "sb".into(),
                expected_resource_version: 0,
                policy: openshell_core::proto::SandboxPolicy::default(),
            })
            .await
            .expect_err("default impl must error");
        assert!(matches!(
            err,
            PolicyError::Unsupported {
                policy_type: "stub",
                operation: "set_policy"
            }
        ));
    }

    #[tokio::test]
    async fn stub_provider_update_policy_returns_unsupported() {
        let p = StubProvider;
        let err = p
            .update_policy(&UpdateSandboxPolicyCtx {
                sandbox_id: "sb".into(),
                sandbox_name: "sb".into(),
                merge_operations: vec![],
                baseline_policy: None,
            })
            .await
            .expect_err("default impl must error");
        assert!(matches!(
            err,
            PolicyError::Unsupported {
                policy_type: "stub",
                operation: "update_policy"
            }
        ));
    }

    #[tokio::test]
    async fn stub_provider_delete_policy_returns_unsupported() {
        let p = StubProvider;
        let err = p
            .delete_policy(&DeleteGlobalPolicyCtx {
                global_policy_sandbox_id: "__global__".into(),
            })
            .await
            .expect_err("default impl must error");
        assert!(matches!(
            err,
            PolicyError::Unsupported {
                policy_type: "stub",
                operation: "delete_policy"
            }
        ));
    }

    #[test]
    fn registry_lookup_returns_registered_provider() {
        let mut reg = PolicyProviderRegistry::new();
        reg.register(StubProvider);
        let resolved = reg.get("stub").expect("registered provider resolves");
        assert_eq!(resolved.id(), "stub");
        assert!(reg.get("nonexistent").is_none());
        assert_eq!(reg.known_policy_types(), vec!["stub"]);
    }
}
