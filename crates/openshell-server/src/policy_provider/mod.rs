// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pluggable policy-provider subsystem.
//!
//! The gateway today resolves an effective policy and accepts policy
//! mutations through inline calls to [`crate::persistence::Store`] from the
//! gRPC layer. This module promotes that surface into a trait so an
//! alternate provider can refuse the mutator methods while still serving
//! an authoritative effective policy at admission time.
//!
//! The error type carries an `Unsupported { policy_type, operation }`
//! variant that maps to `tonic::Status::unimplemented` at the gRPC edge.
//! Resolution of `[openshell.policy] type` to the concrete provider lives
//! at the call site (`crate::resolve_policy_provider`) — a direct `match`
//! suffices for the small number of provider shapes.

mod local;

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
/// Each provider answers three questions:
///   1. What is the effective policy for this sandbox at admission time?
///      (`get_effective_policy`)
///   2. Will it accept any mutation to policy state — the canonical
///      mutator RPCs **and** the draft-chunk approval surface?
///      (`permits_mutation` — default `Unsupported`; coarse gate)
///   3. Will it accept this *specific* mutation? (`set_policy`,
///      `update_policy`, `delete_policy` — default `Unsupported`)
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
    /// the `[openshell.policy] type = ...` value in the gateway config —
    /// the resolver matches on this string when selecting the provider.
    fn id(&self) -> &'static str;

    /// Return the effective policy for `sandbox_id`. The store-backed local
    /// provider returns the latest revision recorded for that sandbox (or
    /// `None` if no revision exists yet); the attested provider will return
    /// the projected policy carried by the latest verified envelope.
    async fn get_effective_policy(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<openshell_core::proto::SandboxPolicy>, PolicyError>;

    /// Coarse gate: does this provider permit any mutation to policy state?
    ///
    /// "Mutation" here means **both** the canonical RPC mutators
    /// (`set_policy`, `update_policy`, `delete_policy`) and the draft-chunk
    /// approval surface added by the agentic approval loop (the `*DraftChunk`
    /// handlers in `grpc/policy.rs`). The gRPC layer calls this first — before
    /// any DB read or write — so an alternate provider can refuse the entire
    /// write surface without per-RPC trait methods. Default: `Unsupported`.
    ///
    /// Rationale: per-op overrides (`set_policy` etc.) remain the natural
    /// extension point for *what work happens* once a mutation is permitted;
    /// `permits_mutation` is the coarse gate that lets the forthcoming
    /// `AttestedPolicyProvider` (whose authoritative policy is fed by an
    /// off-host signed bundle and has no in-band mutation semantics at all)
    /// refuse everything by inheriting this default. See the APP
    /// implementation plan W-B section ("permits_mutation") for the design
    /// alternatives that were considered and rejected.
    async fn permits_mutation(&self) -> Result<(), PolicyError> {
        Err(PolicyError::Unsupported {
            policy_type: self.id(),
            operation: "mutation",
        })
    }

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
    async fn stub_provider_permits_mutation_returns_unsupported() {
        let p = StubProvider;
        let err = p
            .permits_mutation()
            .await
            .expect_err("default impl must error");
        assert!(matches!(
            err,
            PolicyError::Unsupported {
                policy_type: "stub",
                operation: "mutation"
            }
        ));
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

}
