// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Rust guideline compliant 2026-09-30

//! Shadow-mode Cedar network policy evaluator.
//!
//! Wraps [`openshell_policy_cedar::CedarNetworkEngine`], built from the same
//! `ProtoSandboxPolicy` as the authoritative [`crate::opa::OpaEngine`]. OPA
//! decides every real connection; this evaluator runs concurrently, off the
//! hot connection-setup path, purely for comparison logging. See
//! `architecture/plans/cedar-policy-engine-rfc-draft.md` for scope and
//! rationale, and `openshell_policy_cedar::compile` for why this only
//! covers the CONNECT-time (host/binary) decision, not L7.
//!
//! Only reuses the two data-preparation steps that affect the fields this
//! evaluator reads (`network_policies.*.{endpoints,binaries}`,
//! `runtime.require_binary_identity`):
//! [`crate::opa::proto_to_opa_data_json`] and
//! [`crate::opa::inject_runtime_policy_data`]. L7 validation, protocol
//! normalization, and access-preset expansion only affect
//! `rules`/`deny_rules`/`protocol`, which
//! [`openshell_policy_cedar::compile::compile_normalized_data`] never
//! reads.

use std::sync::RwLock;

use miette::Result;
use openshell_core::proto::SandboxPolicy as ProtoSandboxPolicy;
use openshell_policy_cedar::{CedarNetworkEngine, NetworkDecision, NetworkRequest};

use crate::opa::{NetworkInput, inject_runtime_policy_data, proto_to_opa_data_json};

/// Placeholder principal identity for generated Cedar requests.
///
/// The CONNECT-time decision this evaluator shadows
/// (`network_policy_for_request` in `sandbox-policy.rego`) never compares
/// process identity — that's a separate Rego concept
/// (`binary_identity_required`) already captured via
/// `require_binary_identity` in the generated policy's `when` clause. These
/// values exist only to satisfy the Cedar schema's `Process` entity shape.
const PLACEHOLDER_IDENTITY: &str = "sandbox";

/// Name of the environment variable that opts a sandbox into Cedar
/// shadow-mode network evaluation.
///
/// Unset (the default) disables it entirely, with zero added cost: no
/// `ShadowCedarEngine` is constructed and no comparison task ever spawns.
///
/// This is deliberately an env var, not a `gateway.toml` field: shadow mode
/// is an internal experiment for building evidence toward
/// `architecture/plans/cedar-policy-engine-rfc-draft.md`, not yet a
/// supported operator-facing feature. A real config surface should replace
/// this before shadow mode leaves that experimental status.
pub const SHADOW_MODE_ENV_VAR: &str = "OPENSHELL_ENABLE_CEDAR_SHADOW_MODE";

/// True if [`SHADOW_MODE_ENV_VAR`] is set to `1` or `true` (case-insensitive).
#[must_use]
pub fn shadow_mode_enabled() -> bool {
    std::env::var(SHADOW_MODE_ENV_VAR)
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

/// Cedar-backed shadow evaluator for the network CONNECT decision.
///
/// Rebuilt whenever the authoritative `OpaEngine`'s policy reloads (see
/// [`Self::rebuild_from_proto_with_pid`]), via a plain sibling call next to
/// each real `OpaEngine::reload*` call — no separate channel plumbing.
pub struct ShadowCedarEngine {
    engine: RwLock<CedarNetworkEngine>,
}

impl ShadowCedarEngine {
    /// Builds a shadow engine from the same proto policy an `OpaEngine` is
    /// built from.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy's normalized data fails to parse, or
    /// if Cedar policy generation fails — both indicate a bug in this
    /// crate's compiler, not a caller-input error, since `OpaEngine`
    /// already validated the same proto.
    pub fn from_proto(proto: &ProtoSandboxPolicy) -> Result<Self> {
        Self::from_proto_with_pid(proto, 0)
    }

    /// Same as [`Self::from_proto`], with symlink resolution for binary
    /// paths (mirrors `OpaEngine::from_proto_with_pid`).
    ///
    /// # Errors
    ///
    /// See [`Self::from_proto`].
    pub fn from_proto_with_pid(proto: &ProtoSandboxPolicy, entrypoint_pid: u32) -> Result<Self> {
        let engine = build_engine(proto, entrypoint_pid)?;
        Ok(Self {
            engine: RwLock::new(engine),
        })
    }

    /// Rebuilds the shadow engine from a freshly reloaded policy. Call this
    /// directly alongside every real `OpaEngine::reload*` call.
    ///
    /// # Errors
    ///
    /// See [`Self::from_proto`]. On error, the previous policy stays
    /// loaded: a stale-but-valid shadow comparison is more informative than
    /// failing shadow evaluation outright, and this never affects the real
    /// (OPA) decision either way.
    pub fn rebuild_from_proto_with_pid(
        &self,
        proto: &ProtoSandboxPolicy,
        entrypoint_pid: u32,
    ) -> Result<()> {
        let engine = build_engine(proto, entrypoint_pid)?;
        let mut guard = self
            .engine
            .write()
            .map_err(|_| miette::miette!("Cedar shadow engine lock poisoned"))?;
        *guard = engine;
        Ok(())
    }

    /// Evaluates one network-connect request, off the hot path.
    ///
    /// # Errors
    ///
    /// Returns an error only if the shadow engine's internal lock is
    /// poisoned or the request cannot be represented in the Cedar schema —
    /// never a policy-content mismatch (that's
    /// [`NetworkDecision::Unsupported`]).
    pub fn evaluate_network(&self, input: &NetworkInput) -> Result<NetworkDecision> {
        let request = NetworkRequest {
            user: PLACEHOLDER_IDENTITY.to_string(),
            group: PLACEHOLDER_IDENTITY.to_string(),
            host: input.host.clone(),
            port: input.port,
            protocol: String::new(),
            binary_path: input.binary_path.to_string_lossy().into_owned(),
            ancestors: input
                .ancestors
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
            method: String::new(),
            path: String::new(),
            command: String::new(),
        };

        let guard = self
            .engine
            .read()
            .map_err(|_| miette::miette!("Cedar shadow engine lock poisoned"))?;
        guard
            .evaluate_network(&request)
            .map_err(|e| miette::miette!("{e}"))
    }
}

fn build_engine(proto: &ProtoSandboxPolicy, entrypoint_pid: u32) -> Result<CedarNetworkEngine> {
    let data_json_str = proto_to_opa_data_json(proto, entrypoint_pid);
    let mut data: serde_json::Value = serde_json::from_str(&data_json_str).map_err(|_| {
        miette::miette!("internal: failed to parse proto JSON for Cedar shadow compiler")
    })?;
    // Shadow mode always evaluates as if binary identity is required: OPA's
    // `from_proto*` constructors don't expose a "trusted runtime" override
    // either, so there's no caller-supplied value to thread through here.
    inject_runtime_policy_data(&mut data, true);

    let compiled = openshell_policy_cedar::compile::compile_normalized_data(&data)
        .map_err(|e| miette::miette!("Cedar shadow compiler error: {e}"))?;
    CedarNetworkEngine::from_compiled(compiled).map_err(|e| miette::miette!("{e}"))
}
