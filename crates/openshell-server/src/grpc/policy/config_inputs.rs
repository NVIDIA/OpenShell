// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Store state shared by the sandbox configuration and provider environment
//! builders.
//!
//! Both builders read the provider catalog, provider records, global settings,
//! and the latest sandbox policy. Loading them once per build attempt lets one
//! attempt hand both components the same view of those sources. The reads are
//! independent, not one database transaction, and credential values are
//! resolved later by the provider builder alone.

use std::collections::BTreeSet;

use openshell_core::proto::Sandbox;
use tonic::Status;

use super::super::StoredSettings;
use super::super::provider::{ProviderEnvironmentRecord, load_provider_environment_records};
use super::{
    GLOBAL_POLICY_SANDBOX_ID, decode_policy_from_global_settings, frozen, load_global_settings,
    load_sandbox_settings,
};
use crate::ServerState;
use crate::persistence::{ObjectId, ObjectName, ObjectWorkspace, PolicyRecord};
use crate::policy_store::PolicyStoreExt as _;
use crate::provider_profile_sources::EffectiveProviderProfileCatalog;

/// Inputs captured for one sandbox and one build attempt.
///
/// Callers must authorize access to `sandbox` before loading. Load again for
/// every later build or retry so a newer source is never hidden.
pub struct SandboxConfigInputs {
    pub(super) sandbox: Sandbox,
    pub(super) catalog: EffectiveProviderProfileCatalog,
    /// Records in `spec.providers` order, which the provider revision hashes.
    pub(super) provider_records: Vec<ProviderEnvironmentRecord>,
    pub(super) global_settings: StoredSettings,
    pub(super) sandbox_settings: Result<StoredSettings, Status>,
    pub(super) global_policy_version: u32,
    /// Observed for its version metadata even under a global policy, whose
    /// dormant sandbox payload is never decoded.
    pub(super) latest_policy: Option<PolicyRecord>,
    /// Frozen providers whose current authorization no longer matches the
    /// captured one. Always empty for live sandboxes.
    pub(super) withheld_providers: BTreeSet<String>,
    pub(super) frozen: Option<crate::storage_proto::StoredFrozenSandboxPolicy>,
}

impl SandboxConfigInputs {
    pub fn sandbox(&self) -> &Sandbox {
        &self.sandbox
    }
}

/// Load the inputs both configuration builders share. Independent reads run
/// concurrently; a failure here fails every component built from them.
pub async fn load_sandbox_config_inputs(
    state: &ServerState,
    sandbox: Sandbox,
) -> Result<SandboxConfigInputs, Status> {
    // Keep the captured-input resolver's state machine off every caller's
    // stack; configuration, readiness and credential RPCs share this boundary.
    Box::pin(async move {
        let store = state.store.as_ref();
        let frozen = store
            .get_sandbox_frozen_policy(sandbox.object_id())
            .await
            .map_err(|error| Status::internal(format!("fetch frozen policy failed: {error}")))?;
        let pending = frozen.as_ref().is_some_and(|state| state.policy.is_none());
        let inputs = load_inputs(state, sandbox.clone(), frozen).await;
        // Capture is the only allowed mode transition. Recheck after every live
        // authorization/composition read, including errors from now-obsolete inputs.
        if pending
            && let Some(captured) = store
                .get_sandbox_frozen_policy(sandbox.object_id())
                .await
                .map_err(|error| Status::internal(format!("fetch frozen policy failed: {error}")))?
            && captured.policy.is_some()
        {
            return load_inputs(state, sandbox, Some(captured)).await;
        }
        inputs
    })
    .await
}

async fn load_inputs(
    state: &ServerState,
    sandbox: Sandbox,
    frozen: Option<crate::storage_proto::StoredFrozenSandboxPolicy>,
) -> Result<SandboxConfigInputs, Status> {
    let store = state.store.as_ref();
    if let Some(captured) = frozen.as_ref().and_then(|state| state.policy.as_ref()) {
        // A frozen sandbox reads its captured catalog and provider identities,
        // and never the live policy history.
        let (context, global_settings, sandbox_settings) = tokio::try_join!(
            frozen::provider_context_from_snapshot(state, &sandbox, captured),
            load_global_settings(store),
            async {
                Ok::<_, Status>(
                    load_sandbox_settings(store, sandbox.object_workspace(), sandbox.object_name())
                        .await,
                )
            },
        )?;
        let global_policy_version = captured.global_policy_version;
        return Ok(SandboxConfigInputs {
            sandbox,
            catalog: context.catalog,
            provider_records: context.records,
            global_settings,
            sandbox_settings,
            global_policy_version,
            latest_policy: None,
            withheld_providers: context.withheld_providers,
            frozen,
        });
    }
    let workspace = sandbox.object_workspace();
    let provider_names = sandbox
        .spec
        .as_ref()
        .map(|spec| spec.providers.as_slice())
        .unwrap_or_default();
    let (catalog, provider_records, global_settings, latest_policy, sandbox_settings) = tokio::try_join!(
        state
            .provider_profile_sources
            .snapshot_catalog(store, workspace),
        load_provider_environment_records(store, workspace, provider_names),
        load_global_settings(store),
        async {
            store
                .get_latest_policy(sandbox.object_id())
                .await
                .map_err(|e| Status::internal(format!("fetch policy history failed: {e}")))
        },
        async {
            Ok::<_, Status>(load_sandbox_settings(store, workspace, sandbox.object_name()).await)
        },
    )?;
    let global_policy_version = if decode_policy_from_global_settings(&global_settings)?.is_some() {
        store
            .get_latest_policy(GLOBAL_POLICY_SANDBOX_ID)
            .await
            .ok()
            .flatten()
            .map_or(0, |record| u32::try_from(record.version).unwrap_or(0))
    } else {
        0
    };
    Ok(SandboxConfigInputs {
        sandbox,
        catalog,
        provider_records,
        global_settings,
        sandbox_settings,
        global_policy_version,
        latest_policy,
        withheld_providers: BTreeSet::new(),
        frozen,
    })
}
