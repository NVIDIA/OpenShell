// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Store state shared by the sandbox configuration and provider environment
//! builders.
//!
//! Both builders read the provider catalog, provider records, global settings,
//! and the latest sandbox policy. Loading them once per build attempt lets one
//! attempt hand both components the same view of those sources. The reads are
//! independent, not one database transaction. In versioned mode credential
//! values, versions and expiry are captured once after policy validation.
//! Legacy mode retains lazy resolution in the provider builder.

use openshell_core::proto::{Provider, Sandbox};
use tonic::Status;

use super::super::StoredSettings;
use super::super::provider::{ProviderEnvironmentRecord, load_provider_environment_records};
use super::load_global_settings;
use crate::ServerState;
use crate::persistence::{ObjectId, ObjectType, ObjectWorkspace, PolicyRecord};
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
    /// Failed/cancelled captures can still deliver policy, but never values.
    pub(super) credential_capture_error: Option<Status>,
}

impl SandboxConfigInputs {
    pub fn sandbox(&self) -> &Sandbox {
        &self.sandbox
    }

    /// Load and validate metadata without backend credential I/O. Push builds
    /// budget this stage separately from the shared value/version capture.
    pub(crate) async fn load_metadata(
        state: &ServerState,
        sandbox: Sandbox,
    ) -> Result<Self, Status> {
        load_sandbox_config_metadata_inputs(state, sandbox).await
    }

    /// Capture once before either snapshot is assembled. Both builders retain
    /// this exact generation, even if another refresh commits in between them.
    pub(crate) async fn capture_credentials(&mut self, state: &ServerState) -> Result<(), Status> {
        if !state.credentials.is_versioned() {
            return Ok(());
        }
        let now_ms = crate::persistence::current_time_ms();
        // Stage locally so cancellation or a later provider failure cannot
        // expose a partial capture as complete omission/readiness evidence.
        let mut captured = Vec::with_capacity(self.provider_records.len());
        for record in &self.provider_records {
            captured.push(std::sync::Arc::new(
                state
                    .credentials
                    .resolve_provider_handles(&record.provider, now_ms)
                    .await?,
            ));
        }
        for (record, captured) in self.provider_records.iter_mut().zip(captured) {
            record.resolved_credentials = Some(captured);
        }
        verify_captured_provider_bindings(state, self).await
    }

    pub(crate) fn mark_credentials_unresolved(&mut self, error: Status) {
        for record in &mut self.provider_records {
            record.resolved_credentials = None;
        }
        self.credential_capture_error = Some(error);
    }

    pub(crate) fn credential_capture_error(&self) -> Option<&Status> {
        self.credential_capture_error.as_ref()
    }
}

/// Load the inputs both configuration builders share. Independent reads run
/// concurrently; a failure here fails every component built from them.
pub async fn load_sandbox_config_inputs(
    state: &ServerState,
    sandbox: Sandbox,
) -> Result<SandboxConfigInputs, Status> {
    let mut inputs = SandboxConfigInputs::load_metadata(state, sandbox).await?;
    inputs.capture_credentials(state).await?;
    Ok(inputs)
}

async fn load_sandbox_config_metadata_inputs(
    state: &ServerState,
    sandbox: Sandbox,
) -> Result<SandboxConfigInputs, Status> {
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
    let inputs = SandboxConfigInputs {
        sandbox,
        catalog,
        provider_records,
        global_settings,
        latest_policy,
        credential_capture_error: None,
    };
    if state.credentials.is_versioned() {
        // Settle selection and policy errors before any secret I/O. The
        // captured result is later used for both revision and payload, never
        // paired with a second resolution from a different generation.
        super::provider_environment_target(&inputs)?;
        super::super::provider::validate_provider_environment_selection(
            &inputs.catalog,
            &inputs.provider_records,
        )?;
    }
    Ok(inputs)
}

/// Recheck immutable provider identity and its authorization binding, not the
/// value generation. An ordinary refresh may advance versions while this
/// capture remains coherent; a replacement/reconfiguration must fail closed.
pub(super) async fn verify_captured_provider_bindings(
    state: &ServerState,
    inputs: &SandboxConfigInputs,
) -> Result<(), Status> {
    if !state.credentials.is_versioned() {
        return Ok(());
    }
    for record in &inputs.provider_records {
        let current = state
            .store
            .get_by_name(
                Provider::object_type(),
                inputs.sandbox.object_workspace(),
                &record.name,
            )
            .await
            .map_err(|_| Status::internal("provider binding verification failed"))?
            .ok_or_else(|| Status::aborted("provider binding changed; rebuild configuration"))?;
        let same_identity = current.id == record.object_id;
        let same_revision = current.resource_version == record.resource_version;
        if !same_identity || !same_revision {
            return Err(Status::aborted(
                "provider binding changed; rebuild configuration",
            ));
        }
        if inputs.credential_capture_error.is_some() {
            // No values need authorization; still verify provider row identity
            // and revision above, even for an unresolved configuration.
            continue;
        }
        let captured = record.resolved_credentials.as_ref().ok_or_else(|| {
            Status::failed_precondition("provider credential capture is incomplete")
        })?;
        state
            .credentials
            .validate_provider_capture(&record.provider, captured)
            .await?;
    }
    Ok(())
}
