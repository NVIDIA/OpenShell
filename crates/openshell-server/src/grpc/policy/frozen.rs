// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Durable, non-secret authorization captured with first configuration acceptance.

use super::{
    Digest, EffectiveProviderProfileCatalog, EffectiveSetting, GetSandboxConfigResponse, HashMap,
    ObjectId, ObjectListQuery, ObjectName, ObjectWorkspace, PolicySource, ProtoSandboxPolicy,
    Provider, Sandbox, SandboxConfigInputs, ServerState, SettingScope, SettingValue, Sha256,
    StaticCredentialEndpointBinding, Status, Store, StoredProviderCredentialRefreshState,
    compute_provider_env_revision_from_records_and_policy_bindings, deterministic_policy_hash,
    setting_value, settings, validate_and_canonicalize_policy, validate_policy_safety,
};
use openshell_core::GetResourceVersion;
use openshell_core::proto::{FrozenSandboxPolicy, FrozenSandboxProvider, ProviderProfile};
use std::collections::BTreeSet;

pub(in crate::grpc) struct ProviderContext {
    pub catalog: EffectiveProviderProfileCatalog,
    pub records: Vec<super::super::provider::ProviderEnvironmentRecord>,
    pub withheld_providers: BTreeSet<String>,
}

impl ProviderContext {
    pub(super) fn revision(
        &self,
        bindings: &HashMap<String, Vec<StaticCredentialEndpointBinding>>,
        global_policy: Option<&ProtoSandboxPolicy>,
    ) -> Result<u64, Status> {
        provider_env_revision(
            &self.catalog,
            &self.records,
            &self.withheld_providers,
            bindings,
            global_policy,
        )
    }
}

pub(super) fn provider_env_revision(
    catalog: &EffectiveProviderProfileCatalog,
    records: &[super::super::provider::ProviderEnvironmentRecord],
    withheld_providers: &BTreeSet<String>,
    bindings: &HashMap<String, Vec<StaticCredentialEndpointBinding>>,
    global_policy: Option<&ProtoSandboxPolicy>,
) -> Result<u64, Status> {
    let revision = compute_provider_env_revision_from_records_and_policy_bindings(
        catalog,
        records,
        bindings,
        global_policy,
    )?;
    if withheld_providers.is_empty() {
        return Ok(revision);
    }
    // A replacement can have the same resource version and no static keys.
    // Polling must still revoke its previously installed dynamic grants.
    let mut hasher = Sha256::new();
    hasher.update(b"openshell-frozen-withheld-providers-v1");
    hasher.update(revision.to_le_bytes());
    for name in withheld_providers {
        hasher.update(name.len().to_le_bytes());
        hasher.update(name.as_bytes());
    }
    let digest = hasher.finalize();
    Ok(u64::from_le_bytes(digest[..8].try_into().map_err(
        |_| Status::internal("provider env revision digest too short"),
    )?))
}

pub(in crate::grpc) fn snapshot(sandbox: &Sandbox) -> Option<&FrozenSandboxPolicy> {
    sandbox.status.as_ref()?.frozen_policy.as_deref()
}

pub(super) fn requested(sandbox: &Sandbox) -> bool {
    sandbox.spec.as_ref().is_some_and(|spec| spec.frozen)
}

pub(in crate::grpc) fn ensure_mutable(sandbox: &Sandbox) -> Result<(), Status> {
    if snapshot(sandbox).is_some() {
        return Err(Status::failed_precondition(format!(
            "sandbox '{}' is frozen; delete and recreate it to change its policy or providers",
            sandbox.object_name()
        )));
    }
    Ok(())
}

pub(in crate::grpc) async fn ensure_mutable_by_id(store: &Store, id: &str) -> Result<(), Status> {
    let sandbox = store
        .get_message::<Sandbox>(id)
        .await
        .map_err(|error| Status::internal(format!("fetch sandbox failed: {error}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    ensure_mutable(&sandbox)
}

pub(super) async fn names(state: &ServerState) -> Result<Vec<String>, Status> {
    let sandboxes = state
        .store
        .collect_messages::<Sandbox>(ObjectListQuery::AllWorkspaces)
        .await
        .map_err(|error| Status::internal(format!("list frozen sandboxes failed: {error}")))?;
    let mut names: Vec<_> = sandboxes
        .iter()
        .filter(|sandbox| snapshot(sandbox).is_some())
        .map(|sandbox| format!("{}/{}", sandbox.object_workspace(), sandbox.object_name()))
        .collect();
    names.sort();
    Ok(names)
}

pub(super) fn policy(snapshot: &FrozenSandboxPolicy) -> Result<ProtoSandboxPolicy, Status> {
    let policy = snapshot
        .policy
        .as_ref()
        .ok_or_else(|| Status::failed_precondition("frozen policy snapshot is missing"))?;
    let canonical = validate_and_canonicalize_policy(policy.clone())?;
    if deterministic_policy_hash(&canonical) != snapshot.policy_hash {
        return Err(Status::failed_precondition(
            "frozen policy is incompatible or its identity changed; recreate the sandbox",
        ));
    }
    validate_policy_safety(&canonical)?;
    Ok(canonical)
}

pub(in crate::grpc) async fn provider_context(
    state: &ServerState,
    sandbox: &Sandbox,
) -> Result<ProviderContext, Status> {
    let workspace = sandbox.object_workspace();
    let Some(frozen) = snapshot(sandbox) else {
        let catalog = state
            .provider_profile_sources
            .snapshot_catalog(state.store.as_ref(), workspace)
            .await?;
        let names = sandbox
            .spec
            .as_ref()
            .map_or(&[][..], |spec| spec.providers.as_slice());
        let records = super::super::provider::load_provider_environment_records(
            state.store.as_ref(),
            workspace,
            names,
        )
        .await?;
        return Ok(ProviderContext {
            catalog,
            records,
            withheld_providers: BTreeSet::new(),
        });
    };

    // The captured catalog, rather than today's live source, defines how both
    // fresh credential values and the frozen endpoint authority are interpreted.
    let profiles: Vec<ProviderProfile> = frozen
        .providers
        .iter()
        .filter_map(|provider| provider.profile.clone())
        .collect();
    let catalog = EffectiveProviderProfileCatalog::from_frozen_profiles(&profiles)?;
    let mut records = Vec::with_capacity(frozen.providers.len());
    let mut withheld_providers = BTreeSet::new();
    for captured in &frozen.providers {
        let current = state
            .store
            .get_message_by_name::<Provider>(workspace, &captured.provider)
            .await
            .map_err(|error| Status::internal(format!("fetch frozen provider failed: {error}")))?;
        let mut provider = current.unwrap_or_default();
        let same_identity = provider.object_id() == captured.provider_id;
        let resource_version = provider.get_resource_version();
        let mut refresh_states = if same_identity {
            crate::provider_refresh::list_refresh_states_for_provider(
                state.store.as_ref(),
                provider.object_id(),
            )
            .await?
        } else {
            Vec::new()
        };
        let epochs = authorization_epochs(&refresh_states)?;
        if !same_identity
            || provider.r#type != captured.r#type
            || provider.profile_workspace != captured.profile_workspace
            || provider.config != captured.config
            || epochs != captured.refresh_authorization_epochs
        {
            // Keep the captured interpretation, but deliver no credential under
            // a replaced provider or a different authorization. Clearing values
            // also revokes already-installed credentials on the next snapshot.
            provider.credentials.clear();
            provider.credential_handles.clear();
            provider.credential_expiration_times.clear();
            refresh_states.clear();
            withheld_providers.insert(captured.provider.clone());
            provider.r#type.clone_from(&captured.r#type);
            provider
                .profile_workspace
                .clone_from(&captured.profile_workspace);
            provider.config.clone_from(&captured.config);
        }
        let metadata = provider.metadata.get_or_insert_with(Default::default);
        metadata.name.clone_from(&captured.provider);
        metadata.id.clone_from(&captured.provider_id);
        metadata.workspace = workspace.to_string();
        records.push(super::super::provider::ProviderEnvironmentRecord {
            name: captured.provider.clone(),
            object_id: captured.provider_id.clone(),
            resource_version,
            provider,
            refresh_states,
        });
    }
    Ok(ProviderContext {
        catalog,
        records,
        withheld_providers,
    })
}

fn authorization_epochs(
    states: &[StoredProviderCredentialRefreshState],
) -> Result<HashMap<String, String>, Status> {
    let mut epochs = HashMap::new();
    for state in states {
        if state
            .metadata
            .as_ref()
            .is_some_and(|meta| meta.deletion_time.is_some())
        {
            continue;
        }
        epochs.insert(
            state.credential_key.clone(),
            crate::provider_refresh::effective_authorization_epoch(state)?.to_string(),
        );
    }
    Ok(epochs)
}

pub(super) fn capture(
    config: &GetSandboxConfigResponse,
    inputs: &SandboxConfigInputs,
    now_ms: i64,
) -> Result<FrozenSandboxPolicy, Status> {
    let mut providers = Vec::with_capacity(inputs.provider_records.len());
    for record in &inputs.provider_records {
        let provider = &record.provider;
        providers.push(FrozenSandboxProvider {
            provider: record.name.clone(),
            provider_id: record.object_id.clone(),
            r#type: provider.r#type.clone(),
            profile_workspace: provider.profile_workspace.clone(),
            config: provider.config.clone(),
            profile: inputs
                .catalog
                .get_profile_for_scope(&provider.r#type, &provider.profile_workspace),
            refresh_authorization_epochs: authorization_epochs(&record.refresh_states)?,
        });
    }
    Ok(FrozenSandboxPolicy {
        policy: config.policy.clone(),
        version: config.version,
        policy_hash: config.policy_hash.clone(),
        frozen_time: openshell_core::time::timestamp_from_millis(now_ms).ok(),
        policy_source: config.policy_source,
        global_policy_version: config.global_policy_version,
        providers,
    })
}

pub(super) fn uses_global_policy(sandbox: &Sandbox, source: PolicySource) -> bool {
    snapshot(sandbox).map_or(source == PolicySource::Global, |snapshot| {
        snapshot.policy_source == i32::from(PolicySource::Global)
    })
}

pub(super) fn disable_proposals(
    sandbox: &Sandbox,
    settings: &mut HashMap<String, EffectiveSetting>,
) {
    if requested(sandbox) || snapshot(sandbox).is_some() {
        settings.insert(
            settings::AGENT_POLICY_PROPOSALS_ENABLED_KEY.to_string(),
            EffectiveSetting {
                value: Some(SettingValue {
                    value: Some(setting_value::Value::BoolValue(false)),
                }),
                scope: i32::from(SettingScope::Sandbox),
            },
        );
    }
}
