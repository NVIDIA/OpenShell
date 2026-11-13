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

use std::sync::Arc;

use openshell_core::proto::Sandbox;
use tonic::Status;

use super::super::StoredSettings;
use super::super::provider::{ProviderEnvironmentRecord, load_provider_environment_records};
use super::load_global_settings;
use crate::ServerState;
use crate::persistence::{ObjectId, ObjectWorkspace, PolicyRecord};
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
    /// Observed for its version metadata even under a global policy, whose
    /// dormant sandbox payload is never decoded.
    pub(super) latest_policy: Option<PolicyRecord>,
}

impl SandboxConfigInputs {
    pub fn sandbox(&self) -> &Sandbox {
        &self.sandbox
    }
}

/// Load the inputs both configuration builders share. Independent reads run
/// concurrently; a failure here fails every component built from them.
///
/// A child is checked against its parent's live record first, so every build
/// refuses it or serves it only providers its parent still has, whether or
/// not a sync has reached it.
pub async fn load_sandbox_config_inputs(
    state: &Arc<ServerState>,
    mut sandbox: Sandbox,
) -> Result<SandboxConfigInputs, Status> {
    let parent_loaded = Box::pin(super::super::sandbox::admit_child(state, &mut sandbox)).await?;
    let store = state.store.as_ref();
    let workspace = sandbox.object_workspace();
    let provider_names = sandbox
        .spec
        .as_ref()
        .map(|spec| spec.providers.as_slice())
        .unwrap_or_default();
    let (catalog, provider_records, global_settings, latest_policy) = tokio::try_join!(
        state
            .provider_profile_sources
            .snapshot_catalog(store, workspace),
        load_provider_environment_records(store, &state.refresh, workspace, provider_names),
        load_global_settings(store),
        async {
            store
                .get_latest_policy(sandbox.object_id())
                .await
                .map_err(|e| Status::internal(format!("fetch policy history failed: {e}")))
        },
    )?;
    if let Some(parent_loaded) = parent_loaded {
        super::super::sandbox::refuse_child_behind_parent(
            state,
            &sandbox,
            &parent_loaded,
            latest_policy.as_ref(),
        )?;
    }
    Ok(SandboxConfigInputs {
        sandbox,
        catalog,
        provider_records,
        global_settings,
        latest_policy,
    })
}
