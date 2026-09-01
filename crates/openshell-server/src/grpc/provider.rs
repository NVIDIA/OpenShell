// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider CRUD operations and environment resolution.

#![allow(clippy::result_large_err)] // gRPC handlers return Result<Response<_>, Status>

#[cfg(test)]
use crate::credentials::RefreshMaterialScope;
use crate::persistence::{
    ObjectId, ObjectLabels, ObjectName, ObjectType, Store, WriteCondition, generate_name,
};
use crate::provider_profile_sources::{
    EffectiveProviderProfileCatalog, ProviderProfileSources, profile_response_payload,
    profile_storage_payload, stored_profile_resource_version,
};
use openshell_core::metadata::ObjectWorkspace;
use openshell_core::proto::{
    CredentialHandle, Provider, ProviderCredentialRefreshStrategy,
    ProviderCredentialTokenGrantAudienceOverride, ProviderCredentialTokenGrantType,
    ProviderProfile, ProviderProfileCredential, Sandbox, StaticCredentialBinding,
    StaticCredentialEndpointBinding, StoredProviderCredentialRefreshState,
};
use openshell_core::telemetry::{
    LifecycleOperation, ProviderProfile as TelemetryProviderProfile, TelemetryOutcome,
};
use openshell_policy::ProviderPolicyLayer;
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use tonic::Status;
use tracing::warn;

use super::validation::{validate_provider_fields, validate_provider_mutable_fields};
use super::{
    MAX_MAP_KEY_LEN, MAX_MAP_VALUE_LEN, MAX_PAGE_SIZE, MAX_PROVIDER_CONFIG_ENTRIES, clamp_limit,
};

const GATEWAY_SPIFFE_WORKLOAD_API_SOCKET: &str = "OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET";

// ---------------------------------------------------------------------------
// CRUD helpers
// ---------------------------------------------------------------------------

/// Redact credential values from a provider before returning it in a gRPC
/// response.  Key names are preserved so callers can display credential counts
/// and key listings.  Internal server paths (inference routing, sandbox env
/// injection) read credentials from the store directly and are unaffected.
fn redact_provider_credentials(mut provider: Provider) -> Provider {
    for value in provider.credentials.values_mut() {
        *value = "REDACTED".to_string();
    }
    for key in provider.credential_handles.keys() {
        provider
            .credentials
            .entry(key.clone())
            .or_insert_with(|| "REDACTED".to_string());
    }
    provider.credential_handles.clear();
    provider
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct ProviderEnvironment {
    pub environment: HashMap<String, String>,
    pub credential_expires_at_ms: HashMap<String, i64>,
    pub dynamic_credentials: HashMap<String, ProviderProfileCredential>,
    pub static_credential_bindings: HashMap<String, StaticCredentialBinding>,
    pub static_credential_keys: HashSet<String>,
}

/// Immutable provider records used to build one provider-environment response.
///
/// The persistence metadata is kept alongside the decoded provider so callers
/// can derive both the revision and credential identities from the exact same
/// records used to resolve environment values and dynamic grants.
#[derive(Debug, Clone)]
pub(super) struct ProviderEnvironmentRecord {
    pub name: String,
    pub object_id: String,
    pub resource_version: u64,
    pub provider: Provider,
    pub refresh_states: Vec<StoredProviderCredentialRefreshState>,
}

impl ProviderEnvironment {
    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.environment.is_empty()
    }

    #[cfg(test)]
    fn get(&self, key: &str) -> Option<&String> {
        self.environment.get(key)
    }

    #[cfg(test)]
    fn contains_key(&self, key: &str) -> bool {
        self.environment.contains_key(key)
    }
}

#[cfg(test)]
pub(super) async fn create_provider_record(
    store: &Store,
    workspace: &str,
    provider: Provider,
) -> Result<Provider, Status> {
    let catalog = ProviderProfileSources::with_default_sources()
        .snapshot_catalog(store, workspace)
        .await?;
    create_provider_record_with_catalog(store, &catalog, workspace, provider).await
}

#[cfg(test)]
pub(super) async fn create_provider_record_with_catalog(
    store: &Store,
    catalog: &EffectiveProviderProfileCatalog,
    workspace: &str,
    provider: Provider,
) -> Result<Provider, Status> {
    create_provider_record_validating(store, workspace, catalog, provider, None).await
}

async fn create_provider_record_validating(
    store: &Store,
    workspace: &str,
    catalog: &EffectiveProviderProfileCatalog,
    mut provider: Provider,
    credentials: Option<&crate::credentials::CredentialRuntime>,
) -> Result<Provider, Status> {
    use crate::persistence::{ObjectName, current_time_ms};

    // Initialize metadata if not present
    if provider.metadata.is_none() {
        let now_ms = current_time_ms();
        provider.metadata = Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: generate_name(),
            created_at_ms: now_ms,
            labels: HashMap::new(),
            resource_version: 0,
            annotations: HashMap::new(),
            workspace: workspace.to_string(),
            deletion_timestamp_ms: 0,
        });
    }

    // Auto-generate name if empty
    if let Some(metadata) = provider.metadata.as_mut() {
        if metadata.name.is_empty() {
            metadata.name = generate_name();
        }
        if metadata.id.is_empty() {
            metadata.id = uuid::Uuid::new_v4().to_string();
        }
    }

    // Ensure metadata is present and valid (must be non-None with non-empty id/name)
    super::validation::validate_object_metadata(provider.metadata.as_ref(), "provider")?;

    if provider.r#type.trim().is_empty() {
        return Err(Status::invalid_argument("provider.type is required"));
    }
    if !provider.credential_handles.is_empty() {
        return Err(Status::invalid_argument(
            "provider.credential_handles is internal gateway state and cannot be supplied",
        ));
    }

    if !provider.profile_workspace.is_empty() && provider.profile_workspace != workspace {
        return Err(Status::invalid_argument(
            "profile_workspace must be empty (global) or match the provider workspace",
        ));
    }
    if provider.credentials.is_empty()
        && !provider_type_allows_empty_credentials(
            catalog,
            &provider.r#type,
            &provider.profile_workspace,
        )
    {
        return Err(Status::invalid_argument(
            "provider.credentials must not be empty",
        ));
    }

    // Validate field sizes before any I/O.
    validate_provider_fields(&provider)?;

    // Generate UUID for database row and update metadata.id to match
    let provider_id = uuid::Uuid::new_v4().to_string();
    let mut provider = provider;
    if let Some(metadata) = provider.metadata.as_mut() {
        metadata.id.clone_from(&provider_id);
    }

    let credentials_to_store = provider.credentials.clone();
    store_provider_credentials_if_configured(
        credentials,
        &mut provider,
        &credentials_to_store,
        &HashMap::new(),
    )
    .await?;
    validate_provider_fields(&provider)?;

    // Create with MustCreate condition to prevent duplicate creation race
    let labels_map = provider.object_labels();
    let labels_json = if labels_map.as_ref().is_none_or(HashMap::is_empty) {
        None
    } else {
        Some(
            serde_json::to_string(&labels_map)
                .map_err(|e| Status::internal(format!("failed to serialize labels: {e}")))?,
        )
    };
    let write_result = store
        .put_if(
            Provider::object_type(),
            &provider_id,
            provider.object_name(),
            workspace,
            &provider.encode_to_vec(),
            labels_json.as_deref(),
            WriteCondition::MustCreate,
        )
        .await;

    let result = match write_result {
        Ok(result) => result,
        Err(e) => {
            if !provider.credential_handles.is_empty()
                && let Some(credentials) = credentials
            {
                let _ = credentials
                    .delete_provider_credential_handles(
                        provider.object_name(),
                        provider.object_workspace(),
                        provider.object_id(),
                        &provider.credential_handles,
                    )
                    .await;
            }
            if matches!(
                e,
                crate::persistence::PersistenceError::UniqueViolation { .. }
            ) {
                return Err(Status::already_exists("provider already exists"));
            }
            return Err(Status::internal(format!("persist provider failed: {e}")));
        }
    };

    if let Some(metadata) = provider.metadata.as_mut() {
        metadata.resource_version = result.resource_version;
    }

    Ok(redact_provider_credentials(provider))
}

pub(super) async fn get_provider_record(
    store: &Store,
    workspace: &str,
    name: &str,
) -> Result<Provider, Status> {
    if name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    store
        .get_message_by_name::<Provider>(workspace, name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
        .ok_or_else(|| Status::not_found("provider not found"))
        .map(redact_provider_credentials)
}

pub(super) async fn list_provider_records(
    store: &Store,
    workspace: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Provider>, Status> {
    let providers: Vec<Provider> = store
        .list_messages(workspace, limit, offset)
        .await
        .map_err(|e| Status::internal(format!("list providers failed: {e}")))?;

    Ok(providers
        .into_iter()
        .map(redact_provider_credentials)
        .collect())
}

#[cfg(test)]
pub(super) async fn update_provider_record(
    store: &Store,
    workspace: &str,
    provider: Provider,
) -> Result<Provider, Status> {
    let catalog = ProviderProfileSources::with_default_sources()
        .snapshot_catalog(store, workspace)
        .await?;
    update_provider_record_with_catalog(store, &catalog, workspace, provider).await
}

pub(super) async fn update_provider_record_with_catalog(
    store: &Store,
    catalog: &EffectiveProviderProfileCatalog,
    workspace: &str,
    provider: Provider,
) -> Result<Provider, Status> {
    update_provider_record_validating(store, workspace, catalog, provider, None).await
}

async fn reject_refresh_owned_credential_updates(
    store: &Store,
    provider_id: &str,
    credential_updates: &HashMap<String, String>,
) -> Result<(), Status> {
    if credential_updates.is_empty() {
        return Ok(());
    }

    let mut refresh_owned_keys = HashSet::new();
    for refresh_state in
        crate::provider_refresh::list_refresh_states_for_provider(store, provider_id).await?
    {
        let strategy =
            ProviderCredentialRefreshStrategy::try_from(refresh_state.strategy).unwrap_or_default();
        if !crate::provider_refresh::is_gateway_mintable_strategy(strategy) {
            continue;
        }

        for key in std::iter::once(refresh_state.credential_key)
            .chain(refresh_state.additional_output_keys.into_values())
        {
            if credential_updates.contains_key(&key) {
                refresh_owned_keys.insert(key);
            }
        }
    }

    if refresh_owned_keys.is_empty() {
        return Ok(());
    }

    let mut refresh_owned_keys: Vec<_> = refresh_owned_keys.into_iter().collect();
    refresh_owned_keys.sort();
    Err(Status::failed_precondition(format!(
        "credentials managed by provider refresh cannot be updated or deleted with provider update: {}; use provider refresh rotate, configure, or delete",
        refresh_owned_keys.join(", ")
    )))
}

async fn update_provider_record_validating(
    store: &Store,
    workspace: &str,
    catalog: &EffectiveProviderProfileCatalog,
    provider: Provider,
    credentials: Option<&crate::credentials::CredentialRuntime>,
) -> Result<Provider, Status> {
    use crate::persistence::{ObjectId, ObjectName};

    if provider.object_name().is_empty() {
        return Err(Status::invalid_argument("provider.name is required"));
    }

    // Extract expected version from provider metadata
    let expected_resource_version = provider.metadata.as_ref().map_or(0, |m| m.resource_version);

    // Resolve provider ID from name for CAS update
    let existing = store
        .get_message_by_name::<Provider>(workspace, provider.object_name())
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?;

    let Some(existing) = existing else {
        return Err(Status::not_found("provider not found"));
    };

    // Provider type is immutable after creation. Reject if the caller
    // sends a non-empty type that differs from the existing one.
    let incoming_type = provider.r#type.trim();
    if !incoming_type.is_empty() && !incoming_type.eq_ignore_ascii_case(existing.r#type.trim()) {
        return Err(Status::invalid_argument(
            "provider type cannot be changed; delete and recreate the provider",
        ));
    }
    if !provider.profile_workspace.is_empty()
        && provider.profile_workspace != existing.profile_workspace
    {
        return Err(Status::invalid_argument(
            "profile_workspace cannot be changed; delete and recreate the provider",
        ));
    }
    if !provider.credential_handles.is_empty() {
        return Err(Status::invalid_argument(
            "provider.credential_handles is internal gateway state and cannot be supplied",
        ));
    }

    reject_refresh_owned_credential_updates(store, existing.object_id(), &provider.credentials)
        .await?;

    let current_version = existing.metadata.as_ref().map_or(0, |m| m.resource_version);

    let cas_version = if expected_resource_version == 0 {
        current_version
    } else {
        expected_resource_version
    };

    // Apply merge to create candidate
    let mut candidate = existing.clone();
    let existing_handles = existing.credential_handles.clone();
    let removed_credential_handles = credential_handles_removed_by_update(&existing, &provider);
    let updated_credential_values = provider
        .credentials
        .iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<HashMap<_, _>>();
    candidate.credentials = merge_map(candidate.credentials, provider.credentials);
    candidate.config = merge_map(candidate.config, provider.config);
    candidate.credential_expires_at_ms = merge_i64_map(
        candidate.credential_expires_at_ms,
        provider.credential_expires_at_ms,
    );

    // Validate BEFORE writing to prevent persisting invalid state.
    // Validate only the mutable fields (credentials/config) plus metadata and
    // attached-sandbox invariants. The immutable name/type are carried forward
    // from `existing` and re-running full `validate_provider_fields` here would
    // strand legacy records whose stored type predates current limits. See
    // #1347.
    super::validation::validate_object_metadata(candidate.metadata.as_ref(), "provider")?;
    let credential_update = prepare_provider_credential_update(
        credentials,
        candidate.object_name(),
        candidate.object_workspace(),
        candidate.object_id(),
        &removed_credential_handles,
        &updated_credential_values,
        &existing_handles,
    )
    .await?;
    for key in credential_update.pre_stored_handles.keys() {
        candidate.credential_handles.remove(key);
        candidate.credentials.remove(key);
    }
    for key in credential_update.deferred_store_values.keys() {
        candidate.credentials.remove(key);
    }
    if credentials.is_some_and(crate::credentials::CredentialRuntime::stores_provider_credentials) {
        for key in updated_credential_values.keys() {
            candidate.credentials.remove(key);
        }
    }
    for key in removed_credential_handles.keys() {
        candidate.credential_handles.remove(key);
    }
    candidate
        .credential_handles
        .extend(credential_update.pre_stored_handles.clone());

    let cas_result = async {
        validate_provider_mutable_fields(&candidate)?;
        if let Some(profile) = get_provider_type_profile_for_scope(
            catalog,
            &candidate.r#type,
            &candidate.profile_workspace,
        ) {
            validate_provider_credentials(&profile, &candidate, &updated_credential_values)?;
        }
        validate_provider_update_against_attached_sandboxes_with_catalog(
            store, catalog, workspace, &candidate,
        )
        .await?;

        let labels_map = candidate.object_labels();
        let labels_json = if labels_map.as_ref().is_none_or(HashMap::is_empty) {
            None
        } else {
            Some(
                serde_json::to_string(&labels_map)
                    .map_err(|e| Status::internal(format!("serialize labels failed: {e}")))?,
            )
        };

        store
            .put_if(
                Provider::object_type(),
                candidate.object_id(),
                candidate.object_name(),
                workspace,
                &candidate.encode_to_vec(),
                labels_json.as_deref(),
                WriteCondition::MatchResourceVersion(cas_version),
            )
            .await
            .map_err(provider_update_persistence_error_to_status)
    }
    .await;

    let result = match cas_result {
        Ok(result) => result,
        Err(err) => {
            cleanup_pre_stored_provider_credentials(
                credentials,
                candidate.object_name(),
                candidate.object_workspace(),
                candidate.object_id(),
                &credential_update.pre_stored_handles,
            )
            .await;
            return Err(err);
        }
    };

    finish_provider_credential_update(
        credentials,
        candidate.object_name(),
        candidate.object_workspace(),
        candidate.object_id(),
        credential_update,
        &removed_credential_handles,
        &existing_handles,
    )
    .await?;

    // Update resource_version from successful write
    if let Some(metadata) = candidate.metadata.as_mut() {
        metadata.resource_version = result.resource_version;
    }

    Ok(redact_provider_credentials(candidate))
}

#[cfg(test)]
pub(super) async fn delete_provider_record(
    store: &Store,
    workspace: &str,
    name: &str,
) -> Result<bool, Status> {
    let credentials = crate::credentials::CredentialRuntime::from_config(
        &openshell_core::Config::new(None).with_credential_drivers(["test-static"]),
    )
    .map_err(|err| Status::internal(format!("create test credential runtime failed: {err}")))?;
    delete_provider_record_with_credentials(store, workspace, &credentials, name).await
}

pub(super) async fn delete_provider_record_with_credentials(
    store: &Store,
    workspace: &str,
    credentials: &crate::credentials::CredentialRuntime,
    name: &str,
) -> Result<bool, Status> {
    if name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    let Some(provider) = store
        .get_message_by_name::<Provider>(workspace, name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
    else {
        return Ok(false);
    };

    let blocking_sandboxes = sandboxes_using_provider(store, workspace, name).await?;
    if !blocking_sandboxes.is_empty() {
        return Err(Status::failed_precondition(format!(
            "provider '{name}' is attached to sandbox(es): {}",
            blocking_sandboxes.join(", ")
        )));
    }

    crate::provider_refresh::delete_refresh_states_for_provider_with_credentials(
        store,
        credentials,
        provider.object_id(),
    )
    .await?;

    credentials
        .delete_provider_credential_handles(
            provider.object_name(),
            provider.object_workspace(),
            provider.object_id(),
            &provider.credential_handles,
        )
        .await?;

    store
        .delete_by_name(Provider::object_type(), workspace, name)
        .await
        .map_err(|e| Status::internal(format!("delete provider failed: {e}")))
}

/// Iterate over every `Sandbox` in the store and collect items produced by
/// `f`.  `f` receives each decoded sandbox; returning `Some(T)` includes the
/// value in the output, `None` skips it.
///
/// This is the shared pagination kernel used by all sandbox-scan helpers.
async fn scan_sandboxes<T, F>(store: &Store, workspace: &str, f: F) -> Result<Vec<T>, Status>
where
    F: FnMut(Sandbox) -> Option<T>,
{
    scan_sandboxes_inner(store, Some(workspace), f).await
}

async fn scan_sandboxes_all<T, F>(store: &Store, f: F) -> Result<Vec<T>, Status>
where
    F: FnMut(Sandbox) -> Option<T>,
{
    scan_sandboxes_inner(store, None, f).await
}

async fn scan_sandboxes_inner<T, F>(
    store: &Store,
    workspace: Option<&str>,
    mut f: F,
) -> Result<Vec<T>, Status>
where
    F: FnMut(Sandbox) -> Option<T>,
{
    let mut out = Vec::new();
    let mut offset = 0u32;
    loop {
        let records = if let Some(ws) = workspace {
            store.list(Sandbox::object_type(), ws, 1000, offset).await
        } else {
            store
                .list_by_type(Sandbox::object_type(), 1000, offset)
                .await
        }
        .map_err(|e| Status::internal(format!("list sandboxes failed: {e}")))?;
        if records.is_empty() {
            break;
        }
        offset = offset
            .checked_add(
                u32::try_from(records.len())
                    .map_err(|_| Status::internal("sandbox page size exceeded u32"))?,
            )
            .ok_or_else(|| Status::internal("sandbox pagination offset overflow"))?;
        for record in records {
            let sandbox = Sandbox::decode(record.payload.as_slice())
                .map_err(|e| Status::internal(format!("decode sandbox failed: {e}")))?;
            if let Some(item) = f(sandbox) {
                out.push(item);
            }
        }
    }
    Ok(out)
}

async fn providers_using_profile(
    store: &Store,
    workspace: &str,
    profile_id: &str,
) -> Result<Vec<String>, Status> {
    let is_platform_scope = workspace.is_empty();
    let mut offset = 0u32;
    let mut blocking = Vec::new();
    loop {
        let records = if is_platform_scope {
            store
                .list_by_type(Provider::object_type(), 1000, offset)
                .await
        } else {
            store
                .list(Provider::object_type(), workspace, 1000, offset)
                .await
        }
        .map_err(|e| Status::internal(format!("list providers failed: {e}")))?;
        if records.is_empty() {
            break;
        }
        offset = offset
            .checked_add(
                u32::try_from(records.len())
                    .map_err(|_| Status::internal("provider page size exceeded u32"))?,
            )
            .ok_or_else(|| Status::internal("provider pagination offset overflow"))?;
        for record in records {
            let provider = Provider::decode(record.payload.as_slice())
                .map_err(|e| Status::internal(format!("decode provider failed: {e}")))?;
            if provider.profile_workspace != workspace
                || normalize_profile_id(&provider.r#type).as_deref() != Some(profile_id)
            {
                continue;
            }
            let label = if is_platform_scope {
                format!("{}/{}", provider.object_workspace(), provider.object_name())
            } else {
                provider.object_name().to_string()
            };
            blocking.push(label);
        }
    }
    blocking.sort();
    blocking.dedup();
    Ok(blocking)
}

async fn sandboxes_using_provider(
    store: &Store,
    workspace: &str,
    provider_name: &str,
) -> Result<Vec<String>, Status> {
    let provider_name = provider_name.to_string();
    let mut names = scan_sandboxes(store, workspace, |sandbox| {
        let spec = sandbox.spec.as_ref()?;
        if spec.providers.iter().any(|n| n == &provider_name) {
            Some(sandbox.object_name().to_string())
        } else {
            None
        }
    })
    .await?;
    names.sort();
    names.dedup();
    Ok(names)
}

async fn sandboxes_using_provider_records(
    store: &Store,
    workspace: &str,
    provider_name: &str,
) -> Result<Vec<Sandbox>, Status> {
    let provider_name = provider_name.to_string();
    scan_sandboxes(store, workspace, |sandbox| {
        let spec = sandbox.spec.as_ref()?;
        if spec.providers.iter().any(|n| n == &provider_name) {
            Some(sandbox)
        } else {
            None
        }
    })
    .await
}

/// Merge an incoming map into an existing map.
///
/// - If `incoming` is empty, return `existing` unchanged (no-op).
/// - Otherwise, upsert all incoming entries into `existing`.
/// - Entries with an empty-string value are removed (delete semantics).
fn merge_map(
    mut existing: HashMap<String, String>,
    incoming: HashMap<String, String>,
) -> HashMap<String, String> {
    if incoming.is_empty() {
        return existing;
    }
    for (key, value) in incoming {
        if value.is_empty() {
            existing.remove(&key);
        } else {
            existing.insert(key, value);
        }
    }
    existing
}

fn merge_i64_map(
    mut existing: HashMap<String, i64>,
    incoming: HashMap<String, i64>,
) -> HashMap<String, i64> {
    if incoming.is_empty() {
        return existing;
    }
    for (key, value) in incoming {
        if value <= 0 {
            existing.remove(&key);
        } else {
            existing.insert(key, value);
        }
    }
    existing
}

fn credential_handles_removed_by_update(
    existing: &Provider,
    incoming: &Provider,
) -> HashMap<String, CredentialHandle> {
    incoming
        .credentials
        .iter()
        .filter(|(_, value)| value.is_empty())
        .filter_map(|(key, _)| {
            existing
                .credential_handles
                .get(key)
                .cloned()
                .map(|handle| (key.clone(), handle))
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
struct ProviderCredentialUpdate {
    pre_stored_handles: HashMap<String, CredentialHandle>,
    deferred_store_values: HashMap<String, String>,
    replaced_handles: HashMap<String, CredentialHandle>,
}

async fn prepare_provider_credential_update(
    credentials: Option<&crate::credentials::CredentialRuntime>,
    provider_name: &str,
    workspace: &str,
    provider_id: &str,
    _removed_handles: &HashMap<String, CredentialHandle>,
    updated_values: &HashMap<String, String>,
    existing_handles: &HashMap<String, CredentialHandle>,
) -> Result<ProviderCredentialUpdate, Status> {
    let Some(credentials) = credentials else {
        return Ok(ProviderCredentialUpdate::default());
    };
    if !credentials.stores_provider_credentials() || updated_values.is_empty() {
        return Ok(ProviderCredentialUpdate::default());
    }

    let mut update = ProviderCredentialUpdate::default();
    let mut values_requiring_new_handles = HashMap::new();
    for (credential_key, value) in updated_values {
        match existing_handles.get(credential_key) {
            Some(existing_handle) if credentials.storage_owns_handle(existing_handle) => {
                update
                    .deferred_store_values
                    .insert(credential_key.clone(), value.clone());
            }
            Some(replaced_handle) => {
                values_requiring_new_handles.insert(credential_key.clone(), value.clone());
                update
                    .replaced_handles
                    .insert(credential_key.clone(), replaced_handle.clone());
            }
            None => {
                values_requiring_new_handles.insert(credential_key.clone(), value.clone());
            }
        }
    }

    if !values_requiring_new_handles.is_empty() {
        update.pre_stored_handles = credentials
            .store_provider_credentials(
                provider_name,
                workspace,
                provider_id,
                &values_requiring_new_handles,
                &HashMap::new(),
            )
            .await?;
    }

    Ok(update)
}

async fn finish_provider_credential_update(
    credentials: Option<&crate::credentials::CredentialRuntime>,
    provider_name: &str,
    workspace: &str,
    provider_id: &str,
    update: ProviderCredentialUpdate,
    removed_handles: &HashMap<String, CredentialHandle>,
    existing_handles: &HashMap<String, CredentialHandle>,
) -> Result<(), Status> {
    let Some(credentials) = credentials else {
        return Ok(());
    };
    if !credentials.stores_provider_credentials() {
        return Ok(());
    }

    if !update.deferred_store_values.is_empty() {
        credentials
            .store_provider_credentials(
                provider_name,
                workspace,
                provider_id,
                &update.deferred_store_values,
                existing_handles,
            )
            .await?;
    }

    let mut handles_to_delete = removed_handles.clone();
    handles_to_delete.extend(update.replaced_handles);
    if !handles_to_delete.is_empty() {
        credentials
            .delete_provider_credential_handles(
                provider_name,
                workspace,
                provider_id,
                &handles_to_delete,
            )
            .await?;
    }

    Ok(())
}

// TODO(credential-drivers): A gateway crash between CAS success and
// finish_provider_credential_update leaves replaced/removed credential handles
// orphaned in the backing store. This best-effort cleanup only covers pre-CAS
// failures. A background reconciliation loop should be added to detect and
// reclaim orphaned handles.
async fn cleanup_pre_stored_provider_credentials(
    credentials: Option<&crate::credentials::CredentialRuntime>,
    provider_name: &str,
    workspace: &str,
    provider_id: &str,
    handles: &HashMap<String, CredentialHandle>,
) {
    if handles.is_empty() {
        return;
    }
    let Some(credentials) = credentials else {
        return;
    };
    if let Err(err) = credentials
        .delete_provider_credential_handles(provider_name, workspace, provider_id, handles)
        .await
    {
        warn!(
            provider_name = %provider_name,
            error = %err,
            "failed to clean up staged provider credentials after provider update failure"
        );
    }
}

fn provider_update_persistence_error_to_status(
    err: crate::persistence::PersistenceError,
) -> Status {
    if let crate::persistence::PersistenceError::Conflict {
        current_resource_version,
    } = err
    {
        Status::aborted(format!(
            "provider was modified concurrently (current resource_version: {})",
            current_resource_version.unwrap_or(0)
        ))
    } else {
        Status::internal(format!("update provider failed: {err}"))
    }
}

async fn store_provider_credentials_if_configured(
    credentials: Option<&crate::credentials::CredentialRuntime>,
    provider: &mut Provider,
    values_to_store: &HashMap<String, String>,
    existing_handles: &HashMap<String, CredentialHandle>,
) -> Result<(), Status> {
    let Some(credentials) = credentials else {
        return Ok(());
    };
    if !credentials.stores_provider_credentials() || values_to_store.is_empty() {
        return Ok(());
    }

    let provider_name = provider.object_name().to_string();
    let workspace = provider.object_workspace().to_string();
    let provider_id = provider.object_id().to_string();
    let stored_handles = credentials
        .store_provider_credentials(
            &provider_name,
            &workspace,
            &provider_id,
            values_to_store,
            existing_handles,
        )
        .await?;

    for key in stored_handles.keys() {
        provider.credentials.remove(key);
    }
    provider.credential_handles.extend(stored_handles);
    Ok(())
}

// ---------------------------------------------------------------------------
// Provider environment resolution
// ---------------------------------------------------------------------------

/// Resolve provider credentials into environment variables.
///
/// For each provider name in the list, fetches the provider from the store and
/// collects credential key-value pairs. Returns a map of environment variables
/// to inject into the sandbox. Credential keys must be unique across attached
/// providers so one provider cannot silently overwrite another provider's token.
#[cfg(test)]
pub(super) async fn resolve_provider_environment(
    store: &Store,
    workspace: &str,
    provider_names: &[String],
) -> Result<ProviderEnvironment, Status> {
    let catalog = ProviderProfileSources::with_default_sources()
        .snapshot_catalog(store, workspace)
        .await?;
    resolve_provider_environment_with_catalog(store, &catalog, workspace, provider_names).await
}

#[cfg(test)]
pub(super) async fn resolve_provider_environment_with_catalog(
    store: &Store,
    catalog: &EffectiveProviderProfileCatalog,
    workspace: &str,
    provider_names: &[String],
) -> Result<ProviderEnvironment, Status> {
    let credentials = crate::credentials::CredentialRuntime::from_config(
        &openshell_core::Config::new(None).with_credential_drivers(["test-static"]),
    )
    .map_err(|err| Status::internal(format!("initialize credential runtime failed: {err}")))?;
    resolve_provider_environment_with_credentials(
        store,
        catalog,
        workspace,
        provider_names,
        &credentials,
    )
    .await
}

#[cfg(test)]
pub(super) async fn resolve_provider_environment_with_credentials(
    store: &Store,
    catalog: &EffectiveProviderProfileCatalog,
    workspace: &str,
    provider_names: &[String],
    credentials: &crate::credentials::CredentialRuntime,
) -> Result<ProviderEnvironment, Status> {
    let records = load_provider_environment_records(store, workspace, provider_names).await?;
    resolve_provider_environment_from_records_with_credentials(
        store,
        catalog,
        &records,
        credentials,
    )
    .await
}

pub(super) async fn load_provider_environment_records(
    store: &Store,
    workspace: &str,
    provider_names: &[String],
) -> Result<Vec<ProviderEnvironmentRecord>, Status> {
    let mut records = Vec::with_capacity(provider_names.len());
    for name in provider_names {
        let record = store
            .get_by_name(Provider::object_type(), workspace, name)
            .await
            .map_err(|e| Status::internal(format!("failed to fetch provider '{name}': {e}")))?
            .ok_or_else(|| Status::failed_precondition(format!("provider '{name}' not found")))?;
        let provider = Provider::decode(record.payload.as_slice())
            .map_err(|e| Status::internal(format!("failed to decode provider '{name}': {e}")))?;
        let refresh_states =
            crate::provider_refresh::list_refresh_states_for_provider(store, &record.id).await?;
        records.push(ProviderEnvironmentRecord {
            name: name.clone(),
            object_id: record.id,
            resource_version: record.resource_version,
            provider,
            refresh_states,
        });
    }
    Ok(records)
}

#[cfg(test)]
pub(super) async fn resolve_provider_environment_from_records(
    store: &Store,
    catalog: &EffectiveProviderProfileCatalog,
    records: &[ProviderEnvironmentRecord],
) -> Result<ProviderEnvironment, Status> {
    let credentials = crate::credentials::CredentialRuntime::from_config(
        &openshell_core::Config::new(None).with_credential_drivers(["test-static"]),
    )
    .map_err(|err| Status::internal(format!("initialize credential runtime failed: {err}")))?;
    resolve_provider_environment_from_records_with_policy_bindings_and_credentials(
        store,
        catalog,
        records,
        &HashMap::new(),
        &credentials,
        None,
    )
    .await
}

#[cfg(test)]
pub(super) async fn resolve_provider_environment_from_records_with_credentials(
    store: &Store,
    catalog: &EffectiveProviderProfileCatalog,
    records: &[ProviderEnvironmentRecord],
    credentials: &crate::credentials::CredentialRuntime,
) -> Result<ProviderEnvironment, Status> {
    resolve_provider_environment_from_records_with_policy_bindings_and_credentials(
        store,
        catalog,
        records,
        &HashMap::new(),
        credentials,
        None,
    )
    .await
}

#[cfg(test)]
pub(super) async fn resolve_provider_environment_from_records_with_policy_bindings(
    store: &Store,
    catalog: &EffectiveProviderProfileCatalog,
    records: &[ProviderEnvironmentRecord],
    policy_bindings: &HashMap<String, Vec<StaticCredentialEndpointBinding>>,
) -> Result<ProviderEnvironment, Status> {
    let credentials = crate::credentials::CredentialRuntime::from_config(
        &openshell_core::Config::new(None).with_credential_drivers(["test-static"]),
    )
    .map_err(|err| Status::internal(format!("initialize credential runtime failed: {err}")))?;
    resolve_provider_environment_from_records_with_policy_bindings_and_credentials(
        store,
        catalog,
        records,
        policy_bindings,
        &credentials,
        None,
    )
    .await
}

pub(super) async fn resolve_provider_environment_from_records_with_policy_bindings_and_credentials(
    store: &Store,
    catalog: &EffectiveProviderProfileCatalog,
    records: &[ProviderEnvironmentRecord],
    policy_bindings: &HashMap<String, Vec<StaticCredentialEndpointBinding>>,
    credentials: &crate::credentials::CredentialRuntime,
    sandbox_id: Option<&str>,
) -> Result<ProviderEnvironment, Status> {
    if records.is_empty() {
        return Ok(ProviderEnvironment::default());
    }

    let mut env = HashMap::new();
    let mut expires = HashMap::new();
    let mut static_credential_bindings = HashMap::new();
    let mut static_credential_keys = HashSet::new();
    let now_ms = crate::persistence::current_time_ms();
    validate_provider_environment_records_unique_at(store, catalog, records, now_ms).await?;
    let registry = openshell_providers::ProviderRegistry::new();

    for record in records {
        let name = &record.name;
        let provider = &record.provider;
        let mut provider_env = HashMap::new();
        let profile = get_provider_type_profile_for_scope(
            catalog,
            &provider.r#type,
            &provider.profile_workspace,
        );
        let accepted_stored_credential_keys = profile.as_ref().map(|profile| {
            profile
                .credentials
                .iter()
                .flat_map(|credential| credential.accepted_stored_keys())
                .map(str::to_string)
                .collect::<HashSet<_>>()
        });
        let profile_endpoints_are_active = profile
            .as_ref()
            .is_none_or(|profile| provider_profile_endpoints_are_active(profile, provider));
        let profile_proto = profile.as_ref().map(ProviderTypeProfile::to_proto);
        let broker_only_credential_keys = profile_proto
            .as_ref()
            .map(broker_only_provider_credential_keys)
            .unwrap_or_default();
        let profile_endpoints = profile_proto.as_ref().map(|profile| {
            if !profile_endpoints_are_active {
                return Vec::new();
            }
            profile
                .endpoints
                .iter()
                .flat_map(|endpoint| {
                    endpoint_ports(endpoint.port, &endpoint.ports)
                        .into_iter()
                        .map(move |port| StaticCredentialEndpointBinding {
                            host: endpoint.host.clone(),
                            port,
                            path: endpoint.path.clone(),
                        })
                })
                .collect::<Vec<_>>()
        });
        let policy_endpoints = policy_bindings.get(name);
        let effective_endpoints = match (&profile_endpoints, policy_endpoints) {
            (Some(profile_endpoints), Some(_policy_endpoints)) if !profile_endpoints.is_empty() => {
                return Err(Status::failed_precondition(format!(
                    "provider '{name}' profile already defines credential endpoints; \
                     remove credential_binding from the sandbox policy endpoint"
                )));
            }
            (Some(profile_endpoints), Some(policy_endpoints)) => {
                debug_assert!(profile_endpoints.is_empty());
                Some(policy_endpoints)
            }
            (Some(profile_endpoints), None) => Some(profile_endpoints),
            (None, Some(_)) => {
                return Err(Status::failed_precondition(format!(
                    "provider '{name}' has no provider profile; policy credential binding \
                     requires an endpointless provider profile"
                )));
            }
            (None, None) => None,
        };
        let has_no_usable_endpoint = effective_endpoints.is_some_and(Vec::is_empty);
        let refresh_epochs = refresh_authorization_epochs_by_key(record)?;

        for (key, value) in &provider.credentials {
            if accepted_stored_credential_keys
                .as_ref()
                .is_some_and(|accepted| !accepted.contains(key))
            {
                warn!(
                    provider_name = %name,
                    key = %key,
                    "withholding provider credential not declared by resolved profile"
                );
                continue;
            }
            if is_non_injectable_provider_credential(provider, key)
                || broker_only_credential_keys.contains(key)
            {
                warn!(
                    provider_name = %name,
                    key = %key,
                    "skipping non-injectable provider credential"
                );
                continue;
            }
            if is_valid_env_key(key) {
                if has_no_usable_endpoint {
                    // Static credentials need a complete binding. Do not send
                    // endpointless profile credentials as invalid metadata,
                    // because one rejected key would revoke every unrelated
                    // static credential in the supervisor snapshot.
                    warn!(
                        provider_name = %name,
                        key = %key,
                        "withholding static provider credential from endpointless profile"
                    );
                    continue;
                }
                let expires_at_ms = provider
                    .credential_expires_at_ms
                    .get(key)
                    .copied()
                    .unwrap_or_default();
                if expires_at_ms > 0 && expires_at_ms <= now_ms {
                    warn!(
                        provider_name = %name,
                        key = %key,
                        expires_at_ms,
                        "skipping expired provider credential"
                    );
                    continue;
                }
                if expires_at_ms > 0 {
                    expires.entry(key.clone()).or_insert(expires_at_ms);
                }
                provider_env.insert(key.clone(), value.clone());
                static_credential_keys.insert(key.clone());
                if let Some(endpoints) = effective_endpoints {
                    if record.object_id.is_empty() {
                        return Err(Status::failed_precondition(format!(
                            "provider '{name}' has no stable object identity"
                        )));
                    }
                    static_credential_bindings.insert(
                        key.clone(),
                        static_credential_binding(
                            sandbox_id,
                            record,
                            key,
                            endpoints,
                            refresh_epochs.get(key).map(String::as_str),
                        ),
                    );
                }
            } else {
                warn!(
                    provider_name = %name,
                    key = %key,
                    "skipping credential with invalid env var key"
                );
            }
        }

        let resolved_refs = credentials
            .resolve_provider_handles(provider, now_ms)
            .await?;
        for (key, value) in resolved_refs.values {
            if accepted_stored_credential_keys
                .as_ref()
                .is_some_and(|accepted| !accepted.contains(&key))
            {
                warn!(
                    provider_name = %name,
                    key = %key,
                    "withholding provider credential handle not declared by resolved profile"
                );
                continue;
            }
            if is_non_injectable_provider_credential(provider, &key)
                || broker_only_credential_keys.contains(&key)
            {
                warn!(
                    provider_name = %name,
                    key = %key,
                    "skipping non-injectable provider credential handle"
                );
                continue;
            }
            if is_valid_env_key(&key) {
                if has_no_usable_endpoint {
                    warn!(
                        provider_name = %name,
                        key = %key,
                        "withholding static provider credential handle from endpointless profile"
                    );
                    continue;
                }
                if let Some(expires_at_ms) = resolved_refs
                    .expires_at_ms
                    .get(&key)
                    .copied()
                    .filter(|expires_at_ms| *expires_at_ms > 0)
                {
                    expires.entry(key.clone()).or_insert(expires_at_ms);
                }
                provider_env.insert(key.clone(), value);
                static_credential_keys.insert(key.clone());
                if let Some(endpoints) = effective_endpoints {
                    if record.object_id.is_empty() {
                        return Err(Status::failed_precondition(format!(
                            "provider '{name}' has no stable object identity"
                        )));
                    }
                    static_credential_bindings.insert(
                        key.clone(),
                        static_credential_binding(
                            sandbox_id,
                            record,
                            &key,
                            endpoints,
                            refresh_epochs.get(&key).map(String::as_str),
                        ),
                    );
                }
            } else {
                warn!(
                    provider_name = %name,
                    key = %key,
                    "skipping credential handle with invalid env var key"
                );
            }
        }

        // Build each provider's emitted environment independently so another
        // provider's earlier output cannot change how this provider classifies
        // or populates its own keys. Cross-provider credential/config
        // collisions have already been rejected by the validation above.
        inject_provider_plugin_environment(catalog, provider, &registry, &mut provider_env);
        for (key, value) in provider_env {
            env.entry(key).or_insert(value);
        }
    }

    Ok(ProviderEnvironment {
        environment: env,
        credential_expires_at_ms: expires,
        dynamic_credentials: resolve_dynamic_credentials_from_records(catalog, records),
        static_credential_bindings,
        static_credential_keys,
    })
}

fn refresh_authorization_epochs_by_key(
    record: &ProviderEnvironmentRecord,
) -> Result<HashMap<String, String>, Status> {
    let mut epochs = HashMap::new();
    for state in &record.refresh_states {
        if state
            .metadata
            .as_ref()
            .is_some_and(|metadata| metadata.deletion_timestamp_ms != 0)
        {
            continue;
        }
        if !crate::provider_refresh::is_gateway_mintable_strategy(
            ProviderCredentialRefreshStrategy::try_from(state.strategy).unwrap_or_default(),
        ) {
            continue;
        }
        let epoch = crate::provider_refresh::effective_authorization_epoch(state)?.to_string();
        for key in
            std::iter::once(&state.credential_key).chain(state.additional_output_keys.values())
        {
            if let Some(previous) = epochs.insert(key.clone(), epoch.clone())
                && previous != epoch
            {
                return Err(Status::failed_precondition(
                    "multiple provider refresh authorizations claim one credential key",
                ));
            }
        }
    }
    Ok(epochs)
}

fn static_credential_binding(
    sandbox_id: Option<&str>,
    record: &ProviderEnvironmentRecord,
    key: &str,
    endpoints: &[StaticCredentialEndpointBinding],
    authorization_epoch: Option<&str>,
) -> StaticCredentialBinding {
    let workload_credential_handle = sandbox_id
        .zip(authorization_epoch)
        .map(|(sandbox_id, epoch)| {
            derive_workload_credential_handle(sandbox_id, &record.object_id, key, epoch, endpoints)
        })
        .unwrap_or_default();
    let credential_identity = if workload_credential_handle.is_empty() {
        format!("{}:{key}", record.object_id)
    } else {
        format!("refresh:{workload_credential_handle}")
    };
    StaticCredentialBinding {
        endpoints: endpoints.to_vec(),
        credential_identity,
        workload_credential_handle,
    }
}

fn derive_workload_credential_handle(
    sandbox_id: &str,
    provider_id: &str,
    credential_key: &str,
    authorization_epoch: &str,
    endpoints: &[StaticCredentialEndpointBinding],
) -> String {
    let mut endpoints = endpoints
        .iter()
        .map(|endpoint| {
            let host = endpoint
                .host
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            let path = match endpoint.path.trim() {
                "" | "**" | "/**" => "/**".to_string(),
                path => path.to_string(),
            };
            (host, endpoint.port, path)
        })
        .collect::<Vec<_>>();
    endpoints.sort();
    endpoints.dedup();

    let mut hasher = Sha256::new();
    hash_handle_component(&mut hasher, b"openshell-workload-credential-handle-v1");
    hash_handle_component(&mut hasher, sandbox_id.as_bytes());
    hash_handle_component(&mut hasher, provider_id.as_bytes());
    hash_handle_component(&mut hasher, credential_key.as_bytes());
    hash_handle_component(&mut hasher, authorization_epoch.as_bytes());
    for (host, port, path) in endpoints {
        hash_handle_component(&mut hasher, host.as_bytes());
        hash_handle_component(&mut hasher, &port.to_le_bytes());
        hash_handle_component(&mut hasher, path.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn hash_handle_component(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(value.len().to_le_bytes());
    hasher.update(value);
}

/// Resolve dynamic credentials (token grants) from the same records used for
/// the provider-environment revision and static credential bindings.
fn resolve_dynamic_credentials_from_records(
    catalog: &EffectiveProviderProfileCatalog,
    records: &[ProviderEnvironmentRecord],
) -> HashMap<String, ProviderProfileCredential> {
    let mut dynamic_creds = HashMap::new();
    for record in records {
        let provider = &record.provider;
        let Some(profile) = get_provider_type_profile_for_scope(
            catalog,
            &provider.r#type,
            &provider.profile_workspace,
        ) else {
            continue;
        };
        insert_dynamic_credentials_for_profile(
            &mut dynamic_creds,
            &profile.to_proto(),
            &record.name,
        );
    }
    dynamic_creds
}

fn insert_dynamic_credentials_for_profile(
    dynamic_creds: &mut HashMap<String, ProviderProfileCredential>,
    profile: &ProviderProfile,
    provider_name: &str,
) {
    for credential in &profile.credentials {
        if credential.token_grant.is_none() {
            continue;
        }
        for endpoint in &profile.endpoints {
            for port in endpoint_ports(endpoint.port, &endpoint.ports) {
                insert_dynamic_credentials_for_endpoint(
                    dynamic_creds,
                    &endpoint.host,
                    port,
                    &endpoint.path,
                    provider_name,
                    &credential.name,
                    credential,
                );
            }
        }
    }
}

fn endpoint_ports(port: u32, ports: &[u32]) -> Vec<u32> {
    if ports.is_empty() {
        if port == 0 { Vec::new() } else { vec![port] }
    } else {
        ports.iter().copied().filter(|port| *port != 0).collect()
    }
}

fn dynamic_credential_key(
    host: &str,
    port: u32,
    path: &str,
    provider_name: &str,
    credential_name: &str,
) -> String {
    format!(
        "{}\t{port}\t{}\t{}:{}",
        host.to_ascii_lowercase(),
        path,
        provider_name,
        credential_name
    )
}

fn insert_dynamic_credentials_for_endpoint(
    dynamic_creds: &mut HashMap<String, ProviderProfileCredential>,
    endpoint_host: &str,
    endpoint_port: u32,
    endpoint_path: &str,
    provider_name: &str,
    credential_name: &str,
    credential: &ProviderProfileCredential,
) {
    let default_key = dynamic_credential_key(
        endpoint_host,
        endpoint_port,
        endpoint_path,
        provider_name,
        credential_name,
    );
    dynamic_creds.insert(default_key, resolved_dynamic_credential(credential, None));

    let Some(token_grant) = credential.token_grant.as_ref() else {
        return;
    };

    for override_config in &token_grant.audience_overrides {
        if !token_grant_override_matches_endpoint(override_config, endpoint_host, endpoint_port) {
            continue;
        }

        let override_host = if override_config.host.is_empty() {
            endpoint_host
        } else {
            override_config.host.as_str()
        };
        let override_port = if override_config.port == 0 {
            endpoint_port
        } else {
            override_config.port
        };
        let override_path = if override_config.path.is_empty() {
            endpoint_path
        } else {
            override_config.path.as_str()
        };
        let override_key = dynamic_credential_key(
            override_host,
            override_port,
            override_path,
            provider_name,
            credential_name,
        );
        dynamic_creds.insert(
            override_key,
            resolved_dynamic_credential(credential, Some(override_config)),
        );
    }
}

fn resolved_dynamic_credential(
    credential: &ProviderProfileCredential,
    override_config: Option<&ProviderCredentialTokenGrantAudienceOverride>,
) -> ProviderProfileCredential {
    let mut credential = credential.clone();
    if let Some(token_grant) = credential.token_grant.as_mut() {
        if let Some(override_config) = override_config {
            if !override_config.audience.is_empty() {
                token_grant.audience.clone_from(&override_config.audience);
            }
            if !override_config.scopes.is_empty() {
                token_grant.scopes.clone_from(&override_config.scopes);
            }
        }
        token_grant.audience_overrides.clear();
    }
    credential
}

fn token_grant_override_matches_endpoint(
    override_config: &ProviderCredentialTokenGrantAudienceOverride,
    endpoint_host: &str,
    endpoint_port: u32,
) -> bool {
    let host_matches = override_config.host.is_empty()
        || host_pattern_matches(&override_config.host, endpoint_host)
        || host_pattern_matches(endpoint_host, &override_config.host);
    let port_matches = override_config.port == 0 || override_config.port == endpoint_port;
    host_matches && port_matches
}

fn host_pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    if pattern == host {
        return true;
    }
    if !pattern.contains('*') {
        return false;
    }

    let pattern_labels: Vec<&str> = pattern.split('.').collect();
    let host_labels: Vec<&str> = host.split('.').collect();
    host_pattern_labels_match(&pattern_labels, &host_labels)
}

fn host_pattern_labels_match(pattern: &[&str], host: &[&str]) -> bool {
    match pattern.split_first() {
        None => host.is_empty(),
        Some((label, rest)) if *label == "**" => {
            host_pattern_labels_match(rest, host)
                || (!host.is_empty() && host_pattern_labels_match(pattern, &host[1..]))
        }
        Some((label, rest)) if *label == "*" => {
            !host.is_empty() && host_pattern_labels_match(rest, &host[1..])
        }
        Some((literal, rest)) => {
            host.first().is_some_and(|label| label == literal)
                && host_pattern_labels_match(rest, &host[1..])
        }
    }
}

fn dynamic_token_grant_match_score(host: &str, path: &str) -> u32 {
    host_pattern_specificity(host) + endpoint_path_specificity(path)
}

fn host_pattern_specificity(pattern: &str) -> u32 {
    let wildcard_penalty = count_as_u32(pattern.matches('*').count());
    let label_count = count_as_u32(pattern.split('.').filter(|label| !label.is_empty()).count());
    let literal_chars = count_as_u32(pattern.chars().filter(|ch| *ch != '*').count());
    100_000u32
        .saturating_sub(wildcard_penalty.saturating_mul(10_000))
        .saturating_add(label_count.saturating_mul(100))
        .saturating_add(literal_chars)
}

fn endpoint_path_specificity(path: &str) -> u32 {
    if path.is_empty() || path == "**" {
        return 0;
    }
    1_000_000u32.saturating_add(count_as_u32(path.chars().filter(|ch| *ch != '*').count()))
}

fn count_as_u32(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

fn host_patterns_can_overlap(first: &str, second: &str) -> bool {
    let first = first.to_ascii_lowercase();
    let second = second.to_ascii_lowercase();
    if !first.contains('*') {
        return host_pattern_matches(&second, &first);
    }
    if !second.contains('*') {
        return host_pattern_matches(&first, &second);
    }
    let first_labels: Vec<&str> = first.split('.').collect();
    let second_labels: Vec<&str> = second.split('.').collect();
    host_pattern_labels_can_overlap(&first_labels, &second_labels)
}

fn host_pattern_labels_can_overlap(first: &[&str], second: &[&str]) -> bool {
    match (first.split_first(), second.split_first()) {
        (None, None) => true,
        (None, Some((label, rest))) if *label == "**" => {
            host_pattern_labels_can_overlap(first, rest)
        }
        (Some((label, rest)), None) if *label == "**" => {
            host_pattern_labels_can_overlap(rest, second)
        }
        (None, _) | (_, None) => false,
        (Some((label, rest)), _) if *label == "**" => {
            host_pattern_labels_can_overlap(rest, second)
                || host_pattern_labels_can_overlap(first, &second[1..])
        }
        (_, Some((label, rest))) if *label == "**" => {
            host_pattern_labels_can_overlap(first, rest)
                || host_pattern_labels_can_overlap(&first[1..], second)
        }
        (Some((first_label, first_rest)), Some((second_label, second_rest))) => {
            (*first_label == "*" || *second_label == "*" || first_label == second_label)
                && host_pattern_labels_can_overlap(first_rest, second_rest)
        }
    }
}

fn path_patterns_can_overlap(first: &str, second: &str) -> bool {
    if path_matches_all(first) || path_matches_all(second) {
        return true;
    }
    if !first.contains('*') {
        return endpoint_path_matches(second, first);
    }
    if !second.contains('*') {
        return endpoint_path_matches(first, second);
    }
    match (path_prefix_pattern(first), path_prefix_pattern(second)) {
        (Some(first_prefix), Some(second_prefix)) => {
            first_prefix == second_prefix
                || first_prefix.starts_with(&format!("{second_prefix}/"))
                || second_prefix.starts_with(&format!("{first_prefix}/"))
        }
        _ => true,
    }
}

fn path_matches_all(path: &str) -> bool {
    path.is_empty() || path == "**" || path == "/**"
}

fn path_prefix_pattern(path: &str) -> Option<&str> {
    path.strip_suffix("/**")
}

fn endpoint_path_matches(pattern: &str, path: &str) -> bool {
    openshell_core::endpoint_path::matches(pattern, path)
}

#[cfg(test)]
pub async fn validate_provider_environment_keys_unique(
    store: &Store,
    workspace: &str,
    provider_names: &[String],
) -> Result<(), Status> {
    let catalog = ProviderProfileSources::with_default_sources()
        .snapshot_catalog(store, workspace)
        .await?;
    validate_provider_environment_keys_unique_with_catalog(
        store,
        &catalog,
        workspace,
        provider_names,
    )
    .await
}

pub async fn validate_provider_environment_keys_unique_with_catalog(
    store: &Store,
    catalog: &EffectiveProviderProfileCatalog,
    workspace: &str,
    provider_names: &[String],
) -> Result<(), Status> {
    validate_provider_environment_keys_unique_at(
        store,
        catalog,
        workspace,
        provider_names,
        None,
        crate::persistence::current_time_ms(),
    )
    .await
}

pub async fn validate_provider_credential_key_available_for_attached_sandboxes_with_catalog(
    store: &Store,
    catalog: &EffectiveProviderProfileCatalog,
    workspace: &str,
    provider: &Provider,
    credential_key: &str,
) -> Result<(), Status> {
    let mut candidate = provider.clone();
    candidate
        .credentials
        .entry(credential_key.to_string())
        .or_insert_with(|| "pending".to_string());
    candidate.credential_expires_at_ms.remove(credential_key);
    validate_provider_update_against_attached_sandboxes_with_catalog(
        store, catalog, workspace, &candidate,
    )
    .await
}

pub async fn validate_provider_update_against_attached_sandboxes(
    store: &Store,
    workspace: &str,
    provider: &Provider,
) -> Result<(), Status> {
    let catalog = ProviderProfileSources::with_default_sources()
        .snapshot_catalog(store, workspace)
        .await?;
    validate_provider_update_against_attached_sandboxes_with_catalog(
        store, &catalog, workspace, provider,
    )
    .await
}

pub async fn validate_provider_update_against_attached_sandboxes_with_catalog(
    store: &Store,
    catalog: &EffectiveProviderProfileCatalog,
    workspace: &str,
    provider: &Provider,
) -> Result<(), Status> {
    let provider_name = provider.object_name().to_string();
    for sandbox in sandboxes_using_provider_records(store, workspace, &provider_name).await? {
        let sandbox_name = sandbox.object_name().to_string();
        let Some(spec) = sandbox.spec.as_ref() else {
            continue;
        };
        validate_provider_environment_keys_unique_at(
            store,
            catalog,
            workspace,
            &spec.providers,
            Some(provider),
            crate::persistence::current_time_ms(),
        )
        .await
        .map_err(|err| {
            Status::failed_precondition(format!(
                "provider update would create credential env key conflict on sandbox '{sandbox_name}': {}",
                err.message()
            ))
        })?;
    }
    Ok(())
}

async fn validate_provider_environment_keys_unique_at(
    store: &Store,
    catalog: &EffectiveProviderProfileCatalog,
    workspace: &str,
    provider_names: &[String],
    candidate_provider: Option<&Provider>,
    now_ms: i64,
) -> Result<(), Status> {
    let mut seen_credentials = HashMap::<String, String>::new();
    let mut seen_plugin_config = HashMap::<String, String>::new();
    let mut dynamic_bindings = Vec::new();
    for name in provider_names {
        let provider = match candidate_provider {
            Some(candidate) if candidate.object_name() == name.as_str() => candidate.clone(),
            _ => store
                .get_message_by_name::<Provider>(workspace, name)
                .await
                .map_err(|e| Status::internal(format!("failed to fetch provider '{name}': {e}")))?
                .ok_or_else(|| {
                    Status::failed_precondition(format!("provider '{name}' not found"))
                })?,
        };
        let provider_name = provider.object_name().to_string();
        validate_provider_environment_key_ownership(
            &mut seen_credentials,
            &mut seen_plugin_config,
            &provider_name,
            active_provider_environment_keys(store, catalog, &provider, now_ms).await?,
            provider_plugin_environment_keys(catalog, &provider),
        )?;
        dynamic_bindings.extend(dynamic_token_grant_bindings_for_provider_with_catalog(
            catalog, &provider,
        ));
    }
    validate_dynamic_token_grant_bindings_unambiguous(&dynamic_bindings)?;
    Ok(())
}

async fn validate_provider_environment_records_unique_at(
    store: &Store,
    catalog: &EffectiveProviderProfileCatalog,
    records: &[ProviderEnvironmentRecord],
    now_ms: i64,
) -> Result<(), Status> {
    let mut seen_credentials = HashMap::<String, String>::new();
    let mut seen_plugin_config = HashMap::<String, String>::new();
    let mut dynamic_bindings = Vec::new();
    for record in records {
        let provider = &record.provider;
        validate_provider_environment_key_ownership(
            &mut seen_credentials,
            &mut seen_plugin_config,
            &record.name,
            active_provider_environment_keys_for_identity(
                store,
                catalog,
                provider,
                &record.object_id,
                now_ms,
            )
            .await?,
            provider_plugin_environment_keys(catalog, provider),
        )?;
        dynamic_bindings.extend(dynamic_token_grant_bindings_for_provider_with_catalog(
            catalog, provider,
        ));
    }
    validate_dynamic_token_grant_bindings_unambiguous(&dynamic_bindings)?;
    Ok(())
}

fn provider_plugin_environment_keys(
    catalog: &EffectiveProviderProfileCatalog,
    provider: &Provider,
) -> Vec<String> {
    let mut plugin_environment = HashMap::new();
    let registry = openshell_providers::ProviderRegistry::new();
    inject_provider_plugin_environment(catalog, provider, &registry, &mut plugin_environment);
    plugin_environment.into_keys().collect()
}

fn inject_provider_plugin_environment(
    catalog: &EffectiveProviderProfileCatalog,
    provider: &Provider,
    registry: &openshell_providers::ProviderRegistry,
    environment: &mut HashMap<String, String>,
) {
    if let Some(profile) =
        get_provider_type_profile_for_scope(catalog, &provider.r#type, &provider.profile_workspace)
    {
        registry.inject_env_for_profile_id(provider, &profile.id, environment);
    } else {
        // Preserve config projection for legacy records when their profile
        // source is temporarily unavailable.
        registry.inject_env(provider, environment);
    }
}

fn validate_provider_environment_key_ownership(
    seen_credentials: &mut HashMap<String, String>,
    seen_plugin_config: &mut HashMap<String, String>,
    provider_name: &str,
    credential_keys: Vec<String>,
    plugin_config_keys: Vec<String>,
) -> Result<(), Status> {
    for key in credential_keys {
        if let Some(first_provider) = seen_credentials.get(&key) {
            if first_provider != provider_name {
                return Err(Status::failed_precondition(format!(
                    "credential env key '{key}' is provided by both provider '{first_provider}' and provider '{provider_name}'; use provider-specific env names"
                )));
            }
        } else {
            seen_credentials.insert(key.clone(), provider_name.to_string());
        }
        if let Some(config_provider) = seen_plugin_config.get(&key)
            && config_provider != provider_name
        {
            return Err(provider_credential_config_key_collision(
                &key,
                provider_name,
                config_provider,
            ));
        }
    }

    for key in plugin_config_keys {
        if let Some(credential_provider) = seen_credentials.get(&key)
            && credential_provider != provider_name
        {
            return Err(provider_credential_config_key_collision(
                &key,
                credential_provider,
                provider_name,
            ));
        }
        seen_plugin_config
            .entry(key)
            .or_insert_with(|| provider_name.to_string());
    }
    Ok(())
}

fn provider_credential_config_key_collision(
    key: &str,
    credential_provider: &str,
    config_provider: &str,
) -> Status {
    Status::failed_precondition(format!(
        "credential env key '{key}' from provider '{credential_provider}' conflicts with provider-generated config from provider '{config_provider}'; use provider-specific env names"
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DynamicTokenGrantBinding {
    provider_name: String,
    credential_name: String,
    host: String,
    port: u32,
    path: String,
    score: u32,
}

fn dynamic_token_grant_bindings_for_provider_with_catalog(
    catalog: &EffectiveProviderProfileCatalog,
    provider: &Provider,
) -> Vec<DynamicTokenGrantBinding> {
    let provider_name = provider.object_name().to_string();
    let Some(profile) =
        get_provider_type_profile_for_scope(catalog, &provider.r#type, &provider.profile_workspace)
    else {
        return Vec::new();
    };
    dynamic_token_grant_bindings_for_profile(&provider_name, &profile.to_proto())
}

fn dynamic_token_grant_bindings_for_profile(
    provider_name: &str,
    profile: &ProviderProfile,
) -> Vec<DynamicTokenGrantBinding> {
    let mut bindings = Vec::new();
    for credential in &profile.credentials {
        if credential.token_grant.is_none() {
            continue;
        }
        for endpoint in &profile.endpoints {
            for port in endpoint_ports(endpoint.port, &endpoint.ports) {
                push_dynamic_token_grant_bindings_for_endpoint(
                    &mut bindings,
                    provider_name,
                    credential,
                    &endpoint.host,
                    port,
                    &endpoint.path,
                );
            }
        }
    }
    bindings
}

fn push_dynamic_token_grant_bindings_for_endpoint(
    bindings: &mut Vec<DynamicTokenGrantBinding>,
    provider_name: &str,
    credential: &ProviderProfileCredential,
    endpoint_host: &str,
    endpoint_port: u32,
    endpoint_path: &str,
) {
    push_dynamic_token_grant_binding(
        bindings,
        provider_name,
        &credential.name,
        endpoint_host,
        endpoint_port,
        endpoint_path,
    );

    let Some(token_grant) = credential.token_grant.as_ref() else {
        return;
    };

    for override_config in &token_grant.audience_overrides {
        if !token_grant_override_matches_endpoint(override_config, endpoint_host, endpoint_port) {
            continue;
        }
        let override_host = if override_config.host.is_empty() {
            endpoint_host
        } else {
            override_config.host.as_str()
        };
        let override_port = if override_config.port == 0 {
            endpoint_port
        } else {
            override_config.port
        };
        let override_path = if override_config.path.is_empty() {
            endpoint_path
        } else {
            override_config.path.as_str()
        };
        push_dynamic_token_grant_binding(
            bindings,
            provider_name,
            &credential.name,
            override_host,
            override_port,
            override_path,
        );
    }
}

fn push_dynamic_token_grant_binding(
    bindings: &mut Vec<DynamicTokenGrantBinding>,
    provider_name: &str,
    credential_name: &str,
    host: &str,
    port: u32,
    path: &str,
) {
    let candidate = DynamicTokenGrantBinding {
        provider_name: provider_name.to_string(),
        credential_name: credential_name.to_string(),
        host: host.to_ascii_lowercase(),
        port,
        path: path.to_string(),
        score: dynamic_token_grant_match_score(host, path),
    };
    if !bindings.iter().any(|binding| binding == &candidate) {
        bindings.push(candidate);
    }
}

fn validate_dynamic_token_grant_bindings_unambiguous(
    bindings: &[DynamicTokenGrantBinding],
) -> Result<(), Status> {
    for (index, first) in bindings.iter().enumerate() {
        for second in bindings.iter().skip(index + 1) {
            if first.provider_name == second.provider_name
                && first.credential_name == second.credential_name
            {
                continue;
            }
            if first.port == second.port
                && first.score == second.score
                && host_patterns_can_overlap(&first.host, &second.host)
                && path_patterns_can_overlap(&first.path, &second.path)
            {
                return Err(Status::failed_precondition(format!(
                    "dynamic token grants for '{}:{}' and '{}:{}' are ambiguous for {}:{} path selectors '{}' and '{}'; make one host/path selector more specific or attach only one matching provider",
                    first.provider_name,
                    first.credential_name,
                    second.provider_name,
                    second.credential_name,
                    first.host,
                    first.port,
                    first.path,
                    second.path
                )));
            }
        }
    }
    Ok(())
}

async fn active_provider_environment_keys(
    store: &Store,
    catalog: &EffectiveProviderProfileCatalog,
    provider: &Provider,
    now_ms: i64,
) -> Result<Vec<String>, Status> {
    active_provider_environment_keys_for_identity(
        store,
        catalog,
        provider,
        provider.object_id(),
        now_ms,
    )
    .await
}

async fn active_provider_environment_keys_for_identity(
    store: &Store,
    catalog: &EffectiveProviderProfileCatalog,
    provider: &Provider,
    provider_identity: &str,
    now_ms: i64,
) -> Result<Vec<String>, Status> {
    let broker_only_credential_keys =
        broker_only_provider_credential_keys_for_provider(catalog, provider);
    let mut keys = active_provider_credential_keys(provider, now_ms, &broker_only_credential_keys);
    if !provider_identity.is_empty() {
        for state in
            crate::provider_refresh::list_refresh_states_for_provider(store, provider_identity)
                .await?
        {
            // The primary key plus every co-minted output key this refresh owns,
            // so a configured-but-not-yet-minted refresh reserves all of them.
            keys.extend(
                std::iter::once(state.credential_key)
                    .chain(state.additional_output_keys.into_values())
                    .filter(|key| !broker_only_credential_keys.contains(key))
                    .filter(|key| is_valid_env_key(key)),
            );
        }
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

fn active_provider_credential_keys(
    provider: &Provider,
    now_ms: i64,
    broker_only_credential_keys: &HashSet<String>,
) -> Vec<String> {
    let mut keys: Vec<String> = provider
        .credentials
        .keys()
        .filter(|key| !is_non_injectable_provider_credential(provider, key))
        .filter(|key| !broker_only_credential_keys.contains(*key))
        .filter(|key| is_valid_env_key(key))
        .filter(|key| provider_credential_not_expired(provider, key, now_ms))
        .cloned()
        .collect();
    keys.extend(
        provider
            .credential_handles
            .keys()
            .filter(|key| !is_non_injectable_provider_credential(provider, key))
            .filter(|key| !broker_only_credential_keys.contains(*key))
            .filter(|key| is_valid_env_key(key))
            .filter(|key| provider_credential_not_expired(provider, key, now_ms))
            .cloned(),
    );
    keys
}

fn broker_only_provider_credential_keys_for_provider(
    catalog: &EffectiveProviderProfileCatalog,
    provider: &Provider,
) -> HashSet<String> {
    get_provider_type_profile_for_scope(catalog, &provider.r#type, &provider.profile_workspace)
        .as_ref()
        .map(ProviderTypeProfile::to_proto)
        .map(|profile| broker_only_provider_credential_keys(&profile))
        .unwrap_or_default()
}

fn broker_only_provider_credential_keys(profile: &ProviderProfile) -> HashSet<String> {
    profile
        .credentials
        .iter()
        .filter_map(|credential| credential.token_grant.as_ref())
        .filter(|token_grant| {
            ProviderCredentialTokenGrantType::try_from(token_grant.grant_type).is_ok_and(
                |grant_type| grant_type == ProviderCredentialTokenGrantType::TokenExchange,
            )
        })
        .filter_map(|token_grant| token_grant.subject_token.as_ref())
        .filter(|subject_token| subject_token.source.trim() == "provider_credential")
        .filter_map(|subject_token| {
            let key = subject_token.credential.trim();
            (!key.is_empty()).then(|| key.to_string())
        })
        .collect()
}

fn provider_credential_not_expired(provider: &Provider, key: &str, now_ms: i64) -> bool {
    provider
        .credential_expires_at_ms
        .get(key)
        .is_none_or(|expires_at_ms| *expires_at_ms <= 0 || *expires_at_ms > now_ms)
}

fn is_non_injectable_provider_credential(provider: &Provider, key: &str) -> bool {
    openshell_core::inference::normalize_inference_provider_type(&provider.r#type)
        == Some("google-vertex-ai")
        && key == "GOOGLE_SERVICE_ACCOUNT_KEY"
}

pub(super) fn is_valid_env_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first == b'_' || first.is_ascii_alphabetic()) {
        return false;
    }
    bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

// ---------------------------------------------------------------------------
// Trait impls for persistence
// ---------------------------------------------------------------------------

impl ObjectType for Provider {
    fn object_type() -> &'static str {
        "provider"
    }
}

// ---------------------------------------------------------------------------
// Handler wrappers called from the trait impl in mod.rs
// ---------------------------------------------------------------------------

use crate::ServerState;
use openshell_core::proto::{
    ConfigureProviderRefreshRequest, ConfigureProviderRefreshResponse, CreateProviderRequest,
    DeleteProviderProfileRequest, DeleteProviderProfileResponse, DeleteProviderRefreshRequest,
    DeleteProviderRefreshResponse, DeleteProviderRequest, DeleteProviderResponse,
    ExchangeProviderSubjectTokenRequest, ExchangeProviderSubjectTokenResponse,
    GetProviderProfileRequest, GetProviderRefreshStatusRequest, GetProviderRefreshStatusResponse,
    GetProviderRequest, ImportProviderProfilesRequest, ImportProviderProfilesResponse,
    LintProviderProfilesRequest, LintProviderProfilesResponse, ListProviderProfilesRequest,
    ListProviderProfilesResponse, ListProvidersRequest, ListProvidersResponse,
    ProviderProfileDiagnostic, ProviderProfileImportItem, ProviderProfileResponse,
    ProviderResponse, RotateProviderCredentialRequest, RotateProviderCredentialResponse,
    StoredProviderProfile, UpdateProviderProfilesRequest, UpdateProviderProfilesResponse,
    UpdateProviderRequest,
};
use openshell_core::spiffe::{
    JwtSvidParseError, SpiffeJwtClaims, parse_unverified_jwt_svid_claims,
    trust_domain as spiffe_trust_domain, workload_api_endpoint,
};
use openshell_providers::{
    CredentialRefreshProfile, ProfileValidationDiagnostic, ProviderTypeProfile,
    normalize_profile_id, normalize_provider_type, strategy_output_env_key, strategy_output_spec,
    strategy_primary_env_key, validate_profile_set,
};
use std::sync::{Arc, LazyLock, RwLock};
use tonic::{Request, Response};

use crate::auth::principal::Principal;
use crate::auth::workspace_authz::{MinWorkspaceRole, authorize_workspace, require_platform_admin};
use openshell_core::oauth::{
    self, TokenExchangeParams, effective_client_assertion_type, effective_token_type,
};
const DEFAULT_INTERMEDIATE_TOKEN_CACHE_TTL_SECONDS: i64 = 300;
const MAX_INTERMEDIATE_TOKEN_CACHE_TTL_SECONDS: i64 = 3600;
const INTERMEDIATE_TOKEN_CACHE_EXPIRY_SKEW_SECONDS: i64 = 30;
const MAX_INTERMEDIATE_TOKEN_CACHE_ENTRIES: usize = 1024;

static TOKEN_EXCHANGE_HTTP_CLIENT: LazyLock<Result<reqwest::Client, String>> =
    LazyLock::new(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(30))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| {
                format!("provider token exchange HTTP client configuration failed: {err}")
            })
    });
static INTERMEDIATE_TOKEN_CACHE: LazyLock<IntermediateTokenCache> =
    LazyLock::new(IntermediateTokenCache::new);

fn token_exchange_http_client() -> Result<&'static reqwest::Client, Status> {
    TOKEN_EXCHANGE_HTTP_CLIENT
        .as_ref()
        .map_err(|err| Status::internal(err.clone()))
}

#[derive(Clone)]
struct CachedIntermediateToken {
    access_token: String,
    token_type: String,
    expires_at_ms: i64,
}

struct IntermediateTokenCache {
    tokens: Arc<RwLock<HashMap<String, CachedIntermediateToken>>>,
}

impl IntermediateTokenCache {
    fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn get(&self, key: &str) -> Option<oauth::OAuthTokenResponse> {
        let now_ms = crate::persistence::current_time_ms();
        let tokens = self.tokens.read().ok()?;
        let cached = tokens.get(key)?;
        if cached.expires_at_ms <= now_ms {
            return None;
        }
        Some(oauth::OAuthTokenResponse {
            access_token: cached.access_token.clone(),
            expires_in: cached.expires_at_ms.saturating_sub(now_ms) / 1000,
            token_type: cached.token_type.clone(),
        })
    }

    fn set(&self, key: String, token: &oauth::OAuthTokenResponse, expires_at_ms: i64) {
        if let Ok(mut tokens) = self.tokens.write() {
            let now_ms = crate::persistence::current_time_ms();
            tokens.retain(|_, cached| cached.expires_at_ms > now_ms);
            if tokens.len() >= MAX_INTERMEDIATE_TOKEN_CACHE_ENTRIES
                && let Some(evict_key) = tokens
                    .iter()
                    .min_by_key(|(_, cached)| cached.expires_at_ms)
                    .map(|(k, _)| k.clone())
            {
                tokens.remove(&evict_key);
            }
            tokens.insert(
                key,
                CachedIntermediateToken {
                    access_token: token.access_token.clone(),
                    token_type: token.token_type.clone(),
                    expires_at_ms,
                },
            );
        }
    }
}

async fn authorize_and_resolve_profile_workspace(
    state: &Arc<ServerState>,
    principal: &Principal,
    workspace: &str,
    min_workspace_role: MinWorkspaceRole,
) -> Result<super::workspace::ResolvedWorkspace, Status> {
    if workspace.is_empty() {
        require_platform_admin(&state.admin_role, principal)?;
        Ok(super::workspace::ResolvedWorkspace {
            name: String::new(),
            terminating: false,
        })
    } else {
        let authz = authorize_workspace(
            &state.store,
            &state.admin_role,
            principal,
            workspace,
            min_workspace_role,
        )
        .await?;
        super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace).await
    }
}

pub(super) async fn handle_create_provider(
    state: &Arc<ServerState>,
    request: Request<CreateProviderRequest>,
) -> Result<Response<ProviderResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &req.workspace,
        MinWorkspaceRole::Admin,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
        .await?
        .ensure_active()?;
    let Some(mut provider) = req.provider else {
        emit_provider_lifecycle(
            "custom",
            LifecycleOperation::Create,
            TelemetryOutcome::Failure,
        );
        return Err(Status::invalid_argument("provider is required"));
    };
    if let Some(metadata) = provider.metadata.as_mut() {
        metadata.workspace.clone_from(&workspace);
    }
    if !provider.credential_handles.is_empty() {
        return Err(Status::invalid_argument(
            "provider.credential_handles is internal gateway state and cannot be supplied",
        ));
    }
    let provider_type = provider.r#type.clone();
    let _sandbox_sync_guard = state.compute.sandbox_sync_guard().await;
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), &workspace)
        .await?;
    let profile = resolve_provider_create_profile(&catalog, &mut provider)?;
    validate_provider_create_credentials(&profile, &provider)?;
    if state.credentials.stores_provider_credentials() && !provider.credentials.is_empty() {
        state.compute.ensure_workspace(&workspace).await?;
    }
    let result = create_provider_record_validating(
        state.store.as_ref(),
        &workspace,
        &catalog,
        provider,
        Some(&state.credentials),
    )
    .await;
    match result {
        Ok(provider) => {
            emit_provider_lifecycle(
                &provider.r#type,
                LifecycleOperation::Create,
                TelemetryOutcome::Success,
            );
            Ok(Response::new(ProviderResponse {
                provider: Some(provider),
            }))
        }
        Err(err) => {
            emit_provider_lifecycle(
                &provider_type,
                LifecycleOperation::Create,
                TelemetryOutcome::Failure,
            );
            Err(err)
        }
    }
}

pub(super) async fn handle_get_provider(
    state: &Arc<ServerState>,
    request: Request<GetProviderRequest>,
) -> Result<Response<ProviderResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &req.workspace,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
        .await?
        .name;
    let provider = get_provider_record(state.store.as_ref(), &workspace, &req.name).await?;

    Ok(Response::new(ProviderResponse {
        provider: Some(provider),
    }))
}

pub(super) async fn handle_list_providers(
    state: &Arc<ServerState>,
    request: Request<ListProvidersRequest>,
) -> Result<Response<ListProvidersResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    if request.all_workspaces && !request.workspace.is_empty() {
        return Err(Status::invalid_argument(
            "all_workspaces and workspace are mutually exclusive",
        ));
    }
    let limit = clamp_limit(request.limit, 100, MAX_PAGE_SIZE);

    let providers = if request.all_workspaces {
        require_platform_admin(&state.admin_role, &principal)?;
        let all: Vec<Provider> = state
            .store
            .list_all_messages(limit, request.offset)
            .await
            .map_err(|e| Status::internal(format!("list providers failed: {e}")))?;
        all.into_iter().map(redact_provider_credentials).collect()
    } else {
        let authz = authorize_workspace(
            &state.store,
            &state.admin_role,
            &principal,
            &request.workspace,
            MinWorkspaceRole::User,
        )
        .await?;
        let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
            .await?
            .name;
        list_provider_records(state.store.as_ref(), &workspace, limit, request.offset).await?
    };

    Ok(Response::new(ListProvidersResponse { providers }))
}

/// Return provider profiles visible in the given workspace scope.
///
/// Workspace-scoped profiles come from the store (user-managed, stored with the
/// workspace key). Builtin/static profiles are always visible regardless of
/// workspace.
pub(super) async fn handle_list_provider_profiles(
    state: &Arc<ServerState>,
    request: Request<ListProviderProfilesRequest>,
) -> Result<Response<ListProviderProfilesResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    let workspace = authorize_and_resolve_profile_workspace(
        state,
        &principal,
        &request.workspace,
        MinWorkspaceRole::User,
    )
    .await?
    .name;
    let limit = clamp_limit(request.limit, 100, MAX_PAGE_SIZE) as usize;
    let offset = request.offset as usize;
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), &workspace)
        .await?;
    let profiles = catalog
        .list_all_scoped_profiles()
        .into_iter()
        .map(|(_, profile)| profile)
        .skip(offset)
        .take(limit)
        .collect();

    Ok(Response::new(ListProviderProfilesResponse { profiles }))
}

pub(super) async fn handle_get_provider_profile(
    state: &Arc<ServerState>,
    request: Request<GetProviderProfileRequest>,
) -> Result<Response<ProviderProfileResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    let workspace = authorize_and_resolve_profile_workspace(
        state,
        &principal,
        &req.workspace,
        MinWorkspaceRole::User,
    )
    .await?
    .name;
    let id = req.id;
    let id = normalize_profile_id_request(&id)?;
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), &workspace)
        .await?;
    let profile = catalog
        .get_profile(&id)
        .ok_or_else(|| Status::not_found("provider profile not found"))?;

    Ok(Response::new(ProviderProfileResponse {
        profile: Some(profile),
    }))
}

pub(super) async fn handle_import_provider_profiles(
    state: &Arc<ServerState>,
    request: Request<ImportProviderProfilesRequest>,
) -> Result<Response<ImportProviderProfilesResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    let workspace = authorize_and_resolve_profile_workspace(
        state,
        &principal,
        &request.workspace,
        MinWorkspaceRole::Admin,
    )
    .await?
    .ensure_active()?;
    let (profiles, mut diagnostics) = profiles_from_import_items(&request.profiles);
    add_empty_profile_set_diagnostic(&profiles, &mut diagnostics);
    let _sandbox_sync_guard = state.compute.sandbox_sync_guard().await;
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), &workspace)
        .await?;
    diagnostics.extend(
        profile_conflict_diagnostics(state.store.as_ref(), &catalog, &workspace, &profiles).await?,
    );
    diagnostics.extend(validate_profile_set(&profiles));
    if !has_errors(&diagnostics) {
        diagnostics.extend(
            profile_attached_sandbox_diagnostics(
                state.store.as_ref(),
                &catalog,
                &workspace,
                &profiles,
                "import",
            )
            .await?,
        );
    }

    if has_errors(&diagnostics) {
        return Ok(Response::new(ImportProviderProfilesResponse {
            diagnostics: diagnostics.into_iter().map(proto_diagnostic).collect(),
            profiles: Vec::new(),
            imported: false,
        }));
    }

    let mut imported = Vec::with_capacity(profiles.len());
    for (_, profile) in profiles {
        let mut stored = stored_provider_profile_for_workspace(profile.to_proto(), &workspace);
        let profile_labels = stored.object_labels();
        let profile_labels_json = if profile_labels.as_ref().is_none_or(HashMap::is_empty) {
            None
        } else {
            Some(
                serde_json::to_string(&profile_labels)
                    .map_err(|e| Status::internal(format!("failed to serialize labels: {e}")))?,
            )
        };
        let result = state
            .store
            .put_if(
                StoredProviderProfile::object_type(),
                stored.object_id(),
                stored.object_name(),
                &workspace,
                &stored.encode_to_vec(),
                profile_labels_json.as_deref(),
                WriteCondition::MustCreate,
            )
            .await
            .map_err(|e| Status::internal(format!("persist provider profile failed: {e}")))?;
        if let Some(metadata) = stored.metadata.as_mut() {
            metadata.resource_version = result.resource_version;
        }
        let resource_version = stored_profile_resource_version(&stored);
        imported.push(profile_response_payload(
            stored.profile.unwrap_or_default(),
            resource_version,
        ));
    }

    Ok(Response::new(ImportProviderProfilesResponse {
        diagnostics: diagnostics.into_iter().map(proto_diagnostic).collect(),
        profiles: imported,
        imported: true,
    }))
}

pub(super) async fn handle_update_provider_profiles(
    state: &Arc<ServerState>,
    request: Request<UpdateProviderProfilesRequest>,
) -> Result<Response<UpdateProviderProfilesResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    let workspace = authorize_and_resolve_profile_workspace(
        state,
        &principal,
        &request.workspace,
        MinWorkspaceRole::Admin,
    )
    .await?
    .ensure_active()?;
    let items = request.profile.into_iter().collect::<Vec<_>>();
    let (profiles, mut diagnostics) = profiles_from_import_items(&items);
    add_empty_profile_set_diagnostic(&profiles, &mut diagnostics);
    let target_id = normalize_profile_id_request(&request.id)?;
    let _sandbox_sync_guard = state.compute.sandbox_sync_guard().await;
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), &workspace)
        .await?;
    diagnostics.extend(
        profile_update_target_diagnostics(
            state.store.as_ref(),
            &catalog,
            &workspace,
            &profiles,
            &target_id,
        )
        .await?,
    );
    diagnostics.extend(validate_profile_set(&profiles));
    let expected_resource_version = if request.expected_resource_version != 0 {
        Some(request.expected_resource_version)
    } else {
        profiles
            .first()
            .map(|(_, profile)| profile.resource_version)
            .filter(|version| *version != 0)
    };
    if expected_resource_version.is_none() && !profiles.is_empty() {
        let (source, profile) = &profiles[0];
        diagnostics.push(ProfileValidationDiagnostic {
            source: source.clone(),
            profile_id: profile.id.clone(),
            field: "resource_version".to_string(),
            message: "custom provider profile update requires a non-zero resource_version; export the current profile before editing it".to_string(),
            severity: "error".to_string(),
        });
    }
    if !has_errors(&diagnostics) {
        diagnostics.extend(
            profile_attached_sandbox_diagnostics(
                state.store.as_ref(),
                &catalog,
                &workspace,
                &profiles,
                "update",
            )
            .await?,
        );
    }

    if has_errors(&diagnostics) {
        return Ok(Response::new(UpdateProviderProfilesResponse {
            diagnostics: diagnostics.into_iter().map(proto_diagnostic).collect(),
            profile: None,
            updated: false,
        }));
    }

    let expected_resource_version = expected_resource_version.unwrap_or_default();
    let (_, profile) = profiles
        .into_iter()
        .next()
        .ok_or_else(|| Status::internal("validated provider profile update is missing"))?;
    let mut stored = state
        .store
        .get_message_by_name::<StoredProviderProfile>(&workspace, &target_id)
        .await
        .map_err(|e| Status::internal(format!("fetch provider profile failed: {e}")))?
        .ok_or_else(|| Status::not_found("provider profile not found"))?;
    let current_version = stored
        .metadata
        .as_ref()
        .map_or(0, |metadata| metadata.resource_version);
    if current_version != expected_resource_version {
        return Err(Status::aborted(format!(
            "provider profile was modified concurrently (current resource_version: {current_version})"
        )));
    }

    stored.profile = Some(profile_storage_payload(profile.to_proto()));
    let labels_json = stored
        .object_labels()
        .filter(|labels| !labels.is_empty())
        .map(|labels| {
            serde_json::to_string(&labels)
                .map_err(|e| Status::internal(format!("serialize labels failed: {e}")))
        })
        .transpose()?;
    let result = state
        .store
        .put_if(
            StoredProviderProfile::object_type(),
            stored.object_id(),
            stored.object_name(),
            &workspace,
            &stored.encode_to_vec(),
            labels_json.as_deref(),
            WriteCondition::MatchResourceVersion(expected_resource_version),
        )
        .await
        .map_err(|e| super::persistence_error_to_status(e, "update provider profile"))?;
    if let Some(metadata) = stored.metadata.as_mut() {
        metadata.resource_version = result.resource_version;
    }
    let resource_version = stored_profile_resource_version(&stored);
    let profile = profile_response_payload(stored.profile.unwrap_or_default(), resource_version);

    Ok(Response::new(UpdateProviderProfilesResponse {
        diagnostics: Vec::new(),
        profile: Some(profile),
        updated: true,
    }))
}

pub(super) async fn handle_lint_provider_profiles(
    state: &Arc<ServerState>,
    request: Request<LintProviderProfilesRequest>,
) -> Result<Response<LintProviderProfilesResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    let workspace = authorize_and_resolve_profile_workspace(
        state,
        &principal,
        &request.workspace,
        MinWorkspaceRole::User,
    )
    .await?
    .name;
    let (profiles, mut diagnostics) = profiles_from_import_items(&request.profiles);
    add_empty_profile_set_diagnostic(&profiles, &mut diagnostics);
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), &workspace)
        .await?;
    diagnostics.extend(
        profile_conflict_diagnostics(state.store.as_ref(), &catalog, &workspace, &profiles).await?,
    );
    diagnostics.extend(validate_profile_set(&profiles));
    let valid = !has_errors(&diagnostics);

    Ok(Response::new(LintProviderProfilesResponse {
        diagnostics: diagnostics.into_iter().map(proto_diagnostic).collect(),
        valid,
    }))
}

pub(super) async fn handle_delete_provider_profile(
    state: &Arc<ServerState>,
    request: Request<DeleteProviderProfileRequest>,
) -> Result<Response<DeleteProviderProfileResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    let workspace = authorize_and_resolve_profile_workspace(
        state,
        &principal,
        &req.workspace,
        MinWorkspaceRole::Admin,
    )
    .await?
    .name;
    let id = req.id;
    let id = normalize_profile_id_request(&id)?;
    let _sandbox_sync_guard = state.compute.sandbox_sync_guard().await;
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), &workspace)
        .await?;
    if let Some(source_id) = catalog.static_source_for_profile(&id) {
        return Err(Status::failed_precondition(format!(
            "provider profile '{id}' is managed by source '{source_id}' and cannot be deleted"
        )));
    }

    let existing = state
        .store
        .get_message_by_name::<StoredProviderProfile>(&workspace, &id)
        .await
        .map_err(|e| Status::internal(format!("fetch provider profile failed: {e}")))?;
    if existing.is_none() {
        return Err(Status::not_found("provider profile not found"));
    }

    let blocking_providers = providers_using_profile(state.store.as_ref(), &workspace, &id).await?;
    if !blocking_providers.is_empty() {
        return Err(Status::failed_precondition(format!(
            "provider profile '{id}' is in use by providers: {}",
            blocking_providers.join(", ")
        )));
    }

    let deleted = state
        .store
        .delete_by_name(StoredProviderProfile::object_type(), &workspace, &id)
        .await
        .map_err(|e| Status::internal(format!("delete provider profile failed: {e}")))?;

    Ok(Response::new(DeleteProviderProfileResponse { deleted }))
}

pub(super) fn get_provider_type_profile_for_scope(
    catalog: &EffectiveProviderProfileCatalog,
    id: &str,
    profile_workspace: &str,
) -> Option<ProviderTypeProfile> {
    catalog.get_type_profile_for_scope(id, profile_workspace)
}

pub(super) fn provider_profile_endpoints_are_active(
    profile: &ProviderTypeProfile,
    provider: &Provider,
) -> bool {
    if profile.source != "builtin" {
        return true;
    }
    let Some(inference_profile) = openshell_core::inference::profile_for(&profile.id) else {
        return true;
    };
    if !matches!(inference_profile.provider_type, "openai" | "anthropic") {
        return true;
    }

    let configured_base_url = inference_profile
        .base_url_config_keys
        .iter()
        .find_map(|key| provider.config.get(*key))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());
    configured_base_url.is_none_or(|configured| {
        configured
            .trim_end_matches('/')
            .eq_ignore_ascii_case(inference_profile.default_base_url.trim_end_matches('/'))
    })
}

#[cfg(test)]
pub(super) async fn get_provider_type_profile(
    store: &Store,
    workspace: &str,
    id: &str,
) -> Result<Option<ProviderTypeProfile>, Status> {
    // Query stored profiles scoped to the requested workspace.
    let stored: Vec<StoredProviderProfile> = store
        .list_messages(workspace, 10_000, 0)
        .await
        .map_err(|e| Status::internal(format!("list provider profiles failed: {e}")))?;
    let id_norm = normalize_profile_id(id);
    for sp in &stored {
        if let Some(profile) = sp.profile.as_ref()
            && normalize_profile_id(&profile.id) == id_norm
        {
            return Ok(Some(ProviderTypeProfile::from_proto(profile)));
        }
    }
    // Fall back to builtin profiles (workspace-agnostic).
    let catalog = ProviderProfileSources::with_default_sources()
        .snapshot_catalog(store, workspace)
        .await?;
    if let Some(profile) = catalog.get_type_profile(id) {
        // Only return builtins that are not user-managed (i.e., always available).
        if catalog.static_source_for_profile(id).is_some() {
            return Ok(Some(profile));
        }
    }
    Ok(None)
}

fn provider_refresh_defaults(
    catalog: &EffectiveProviderProfileCatalog,
    provider: &Provider,
    credential_key: &str,
) -> Option<CredentialRefreshProfile> {
    let profile = get_provider_type_profile_for_scope(
        catalog,
        &provider.r#type,
        &provider.profile_workspace,
    )?;
    profile
        .credentials
        .iter()
        .find(|credential| {
            credential.name == credential_key
                || credential
                    .env_vars
                    .iter()
                    .any(|env_var| env_var == credential_key)
        })
        .and_then(|credential| credential.refresh.clone())
}

/// Resolve the env keys a refresh co-mints (beyond its primary credential) from
/// the provider's profile `additional_outputs`. Returns semantic output id ->
/// env key. Empty when the provider type has no profile or the credential
/// declares no additional outputs.
fn resolved_additional_output_keys(
    catalog: &EffectiveProviderProfileCatalog,
    provider: &Provider,
    credential_key: &str,
) -> HashMap<String, String> {
    let Some(profile) =
        get_provider_type_profile_for_scope(catalog, &provider.r#type, &provider.profile_workspace)
    else {
        return HashMap::new();
    };
    profile.resolved_additional_output_keys(credential_key)
}

/// Validate that a strategy which pins canonical env keys (today only
/// `aws_sts_assume_role`) is configured against a matching profile binding.
///
/// For such strategies the `SigV4` signer resolves credentials by fixed env
/// name, so a caller must not be able to configure the refresh on an arbitrary
/// credential key or on a provider whose profile does not declare it. This
/// requires: (1) a profile refresh declaration for `credential_key` whose
/// strategy matches, (2) `credential_key` equal to the canonical primary env
/// key, and (3) every required strategy output resolved to its canonical env key
/// via the profile's `additional_outputs`. Unconstrained strategies pass through.
fn validate_strategy_profile_binding(
    strategy: ProviderCredentialRefreshStrategy,
    credential_key: &str,
    refresh_defaults: Option<&CredentialRefreshProfile>,
    additional_output_keys: &HashMap<String, String>,
) -> Result<(), Status> {
    let Some(expected_primary) = strategy_primary_env_key(strategy) else {
        return Ok(());
    };
    let strategy_name = crate::provider_refresh::refresh_strategy_name(strategy as i32);
    let refresh_defaults = refresh_defaults.ok_or_else(|| {
        Status::failed_precondition(format!(
            "strategy '{strategy_name}' requires a provider profile that declares this refresh on credential {expected_primary}"
        ))
    })?;
    if refresh_defaults.strategy != strategy {
        return Err(Status::failed_precondition(format!(
            "provider profile declares strategy '{}' for {credential_key}, not '{strategy_name}'",
            crate::provider_refresh::refresh_strategy_name(refresh_defaults.strategy as i32)
        )));
    }
    if credential_key != expected_primary {
        return Err(Status::failed_precondition(format!(
            "strategy '{strategy_name}' requires credential_key {expected_primary}, got {credential_key}"
        )));
    }
    let (required_outputs, _optional_outputs) = strategy_output_spec(strategy);
    for output in required_outputs {
        let expected_env = strategy_output_env_key(strategy, output).unwrap_or_default();
        if additional_output_keys.get(*output).map(String::as_str) != Some(expected_env) {
            return Err(Status::failed_precondition(format!(
                "strategy '{strategy_name}' requires profile additional output '{output}' bound to {expected_env}"
            )));
        }
    }
    Ok(())
}

fn validate_refresh_material(
    material: &HashMap<String, String>,
    refresh_defaults: Option<&CredentialRefreshProfile>,
) -> Result<(), Status> {
    let Some(refresh_defaults) = refresh_defaults else {
        return Ok(());
    };
    for required in refresh_defaults
        .material
        .iter()
        .filter(|item| item.required)
    {
        if material
            .get(&required.name)
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(Status::invalid_argument(format!(
                "{} material is required by the provider profile",
                required.name
            )));
        }
    }
    Ok(())
}

fn provider_type_allows_empty_credentials(
    catalog: &EffectiveProviderProfileCatalog,
    provider_type: &str,
    profile_workspace: &str,
) -> bool {
    let Some(profile) =
        get_provider_type_profile_for_scope(catalog, provider_type, profile_workspace)
    else {
        return false;
    };
    profile.allows_empty_provider_credentials()
}

fn resolve_provider_create_profile(
    catalog: &EffectiveProviderProfileCatalog,
    provider: &mut Provider,
) -> Result<ProviderTypeProfile, Status> {
    let requested_type = provider.r#type.trim();
    if requested_type.is_empty() {
        return Err(Status::invalid_argument("provider.type is required"));
    }
    let profile = get_provider_type_profile_for_scope(
        catalog,
        requested_type,
        &provider.profile_workspace,
    )
    .ok_or_else(|| {
        Status::invalid_argument(format!(
            "provider profile '{requested_type}' was not found in the requested scope; import a matching profile before creating this provider"
        ))
    })?;
    provider.r#type.clone_from(&profile.id);
    Ok(profile)
}

fn validate_provider_create_credentials(
    profile: &ProviderTypeProfile,
    provider: &Provider,
) -> Result<(), Status> {
    validate_provider_credentials(profile, provider, &HashMap::new())
}

fn validate_provider_credentials(
    profile: &ProviderTypeProfile,
    provider: &Provider,
    pending_credentials: &HashMap<String, String>,
) -> Result<(), Status> {
    let declared_keys = profile
        .credentials
        .iter()
        .flat_map(|credential| credential.accepted_stored_keys())
        .collect::<HashSet<_>>();
    let mut unknown_keys = provider
        .credentials
        .keys()
        .chain(provider.credential_handles.keys())
        .chain(pending_credentials.keys())
        .filter(|key| !declared_keys.contains(key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    unknown_keys.sort();
    unknown_keys.dedup();
    if !unknown_keys.is_empty() {
        return Err(Status::invalid_argument(format!(
            "provider credentials are not declared by profile '{}': {}",
            profile.id,
            unknown_keys.join(", ")
        )));
    }

    validate_required_static_credentials(profile, provider, pending_credentials)
}

fn validate_required_static_credentials(
    profile: &ProviderTypeProfile,
    provider: &Provider,
    pending_credentials: &HashMap<String, String>,
) -> Result<(), Status> {
    let mut missing = Vec::new();
    for credential in profile.required_static_credentials() {
        let accepted_keys = credential.accepted_stored_keys();
        let supplied = accepted_keys.iter().any(|key| {
            provider
                .credentials
                .get(*key)
                .is_some_and(|value| !value.trim().is_empty())
                || provider.credential_handles.contains_key(*key)
                || pending_credentials
                    .get(*key)
                    .is_some_and(|value| !value.trim().is_empty())
        });
        if !supplied {
            missing.push(
                accepted_keys
                    .first()
                    .map_or_else(|| credential.name.clone(), |key| (*key).to_string()),
            );
        }
    }
    if !missing.is_empty() {
        return Err(Status::invalid_argument(format!(
            "provider profile '{}' requires static credentials: {}",
            profile.id,
            missing.join(", ")
        )));
    }
    Ok(())
}

fn normalize_profile_id_request(id: &str) -> Result<String, Status> {
    if id.trim().is_empty() {
        return Err(Status::invalid_argument("id is required"));
    }
    normalize_profile_id(id).ok_or_else(|| {
        Status::invalid_argument("id must be lowercase kebab-case using only a-z, 0-9, and '-'")
    })
}

fn profiles_from_import_items(
    items: &[ProviderProfileImportItem],
) -> (
    Vec<(String, ProviderTypeProfile)>,
    Vec<ProfileValidationDiagnostic>,
) {
    let mut profiles = Vec::new();
    let mut diagnostics = Vec::new();
    for item in items {
        let source = item.source.clone();
        let Some(profile) = item.profile.as_ref() else {
            diagnostics.push(ProfileValidationDiagnostic {
                source,
                profile_id: String::new(),
                field: "profile".to_string(),
                message: "provider profile is required".to_string(),
                severity: "error".to_string(),
            });
            continue;
        };
        for (index, endpoint) in profile.endpoints.iter().enumerate() {
            if endpoint.credential_binding.is_some() {
                diagnostics.push(ProfileValidationDiagnostic {
                    source: source.clone(),
                    profile_id: profile.id.clone(),
                    field: format!("endpoints[{index}].credential_binding"),
                    message: "credential_binding references a concrete sandbox provider and is only valid in sandbox policy".to_string(),
                    severity: "error".to_string(),
                });
            }
        }
        profiles.push((source, ProviderTypeProfile::from_proto(profile)));
    }
    (profiles, diagnostics)
}

fn add_empty_profile_set_diagnostic(
    profiles: &[(String, ProviderTypeProfile)],
    diagnostics: &mut Vec<ProfileValidationDiagnostic>,
) {
    if profiles.is_empty() && diagnostics.is_empty() {
        diagnostics.push(ProfileValidationDiagnostic {
            source: String::new(),
            profile_id: String::new(),
            field: "profiles".to_string(),
            message: "at least one provider profile is required".to_string(),
            severity: "error".to_string(),
        });
    }
}

async fn profile_conflict_diagnostics(
    store: &Store,
    catalog: &EffectiveProviderProfileCatalog,
    workspace: &str,
    profiles: &[(String, ProviderTypeProfile)],
) -> Result<Vec<ProfileValidationDiagnostic>, Status> {
    let mut diagnostics = Vec::new();
    for (source, profile) in profiles {
        let Some(id) = normalize_profile_id(&profile.id) else {
            continue;
        };
        if let Some(source_id) = catalog.static_source_for_profile(&id) {
            diagnostics.push(ProfileValidationDiagnostic {
                source: source.clone(),
                profile_id: id.clone(),
                field: "id".to_string(),
                message: format!(
                    "provider profile '{id}' is managed by source '{source_id}' and cannot be overwritten"
                ),
                severity: "error".to_string(),
            });
            continue;
        }
        if store
            .get_message_by_name::<StoredProviderProfile>(workspace, &id)
            .await
            .map_err(|e| Status::internal(format!("fetch provider profile failed: {e}")))?
            .is_some()
        {
            diagnostics.push(ProfileValidationDiagnostic {
                source: source.clone(),
                profile_id: id.clone(),
                field: "id".to_string(),
                message: format!("custom provider profile '{id}' already exists"),
                severity: "error".to_string(),
            });
        } else if !workspace.is_empty()
            && store
                .get_message_by_name::<StoredProviderProfile>("", &id)
                .await
                .map_err(|e| Status::internal(format!("fetch provider profile failed: {e}")))?
                .is_some()
        {
            diagnostics.push(ProfileValidationDiagnostic {
                source: source.clone(),
                profile_id: id.clone(),
                field: "id".to_string(),
                message: format!(
                    "profile '{id}' shadows a platform-scoped profile in this workspace"
                ),
                severity: "warning".to_string(),
            });
        }
    }
    Ok(diagnostics)
}

async fn profile_update_target_diagnostics(
    store: &Store,
    catalog: &EffectiveProviderProfileCatalog,
    workspace: &str,
    profiles: &[(String, ProviderTypeProfile)],
    target_id: &str,
) -> Result<Vec<ProfileValidationDiagnostic>, Status> {
    let mut diagnostics = Vec::new();
    if profiles.len() == 1 {
        let (source, profile) = &profiles[0];
        if let Some(payload_id) = normalize_profile_id(&profile.id)
            && payload_id != target_id
        {
            diagnostics.push(ProfileValidationDiagnostic {
                source: source.clone(),
                profile_id: profile.id.clone(),
                field: "id".to_string(),
                message: format!(
                    "provider profile update target '{target_id}' does not match payload id '{payload_id}'"
                ),
                severity: "error".to_string(),
            });
        }
    }
    if let Some(source_id) = catalog.static_source_for_profile(target_id) {
        diagnostics.push(ProfileValidationDiagnostic {
            source: target_id.to_string(),
            profile_id: target_id.to_string(),
            field: "id".to_string(),
            message: format!(
                "provider profile '{target_id}' is managed by source '{source_id}' and cannot be updated"
            ),
            severity: "error".to_string(),
        });
        return Ok(diagnostics);
    }
    if store
        .get_message_by_name::<StoredProviderProfile>(workspace, target_id)
        .await
        .map_err(|e| Status::internal(format!("fetch provider profile failed: {e}")))?
        .is_none()
    {
        diagnostics.push(ProfileValidationDiagnostic {
            source: target_id.to_string(),
            profile_id: target_id.to_string(),
            field: "id".to_string(),
            message: format!("custom provider profile '{target_id}' does not exist"),
            severity: "error".to_string(),
        });
    }
    for (source, profile) in profiles {
        let Some(id) = normalize_profile_id(&profile.id) else {
            continue;
        };
        if let Some(source_id) = catalog.static_source_for_profile(&id) {
            diagnostics.push(ProfileValidationDiagnostic {
                source: source.clone(),
                profile_id: id.clone(),
                field: "id".to_string(),
                message: format!(
                    "provider profile '{id}' is managed by source '{source_id}' and cannot be updated"
                ),
                severity: "error".to_string(),
            });
        }
    }
    Ok(diagnostics)
}

async fn profile_attached_sandbox_diagnostics(
    store: &Store,
    catalog: &EffectiveProviderProfileCatalog,
    workspace: &str,
    profiles: &[(String, ProviderTypeProfile)],
    operation: &str,
) -> Result<Vec<ProfileValidationDiagnostic>, Status> {
    let mut candidate_profiles = HashMap::<String, (String, ProviderTypeProfile)>::new();
    for (source, profile) in profiles {
        let Some(id) = normalize_profile_id(&profile.id) else {
            continue;
        };
        candidate_profiles.insert(id, (source.clone(), profile.clone()));
    }
    if candidate_profiles.is_empty() {
        return Ok(Vec::new());
    }

    let is_platform_scope = workspace.is_empty();

    let sandboxes = if is_platform_scope {
        scan_sandboxes_all(store, |sandbox| {
            sandbox
                .spec
                .as_ref()
                .is_some_and(|spec| !spec.providers.is_empty())
                .then_some(sandbox)
        })
        .await?
    } else {
        scan_sandboxes(store, workspace, |sandbox| {
            sandbox
                .spec
                .as_ref()
                .is_some_and(|spec| !spec.providers.is_empty())
                .then_some(sandbox)
        })
        .await?
    };
    let mut diagnostics = Vec::new();
    let validate_policy_composition =
        super::policy::provider_policy_composition_enabled(store).await?;
    for sandbox in sandboxes {
        let sandbox_name = sandbox.object_name().to_string();
        let sandbox_workspace = sandbox.object_workspace().to_string();
        let spec = sandbox.spec.as_ref().expect("filtered by scan_sandboxes");
        let base_policy = super::policy::current_base_policy_for_sandbox(store, &sandbox).await?;
        let mut bindings = Vec::new();
        let mut provider_layers = Vec::new();
        let mut imported_profiles_used = Vec::<(String, String)>::new();

        for provider_name in &spec.providers {
            let provider_ws = if is_platform_scope {
                &sandbox_workspace
            } else {
                workspace
            };
            let Some(provider) = store
                .get_message_by_name::<Provider>(provider_ws, provider_name)
                .await
                .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
            else {
                continue;
            };
            let requested_profile_id = normalize_profile_id(&provider.r#type)
                .unwrap_or_else(|| provider.r#type.trim().to_string());
            let profile_id = if candidate_profiles.contains_key(&requested_profile_id) {
                requested_profile_id
            } else {
                normalize_provider_type(&provider.r#type)
                    .filter(|alias| candidate_profiles.contains_key(*alias))
                    .map_or(requested_profile_id, str::to_string)
            };
            let scope_mismatch = (is_platform_scope && !provider.profile_workspace.is_empty())
                || (!is_platform_scope && provider.profile_workspace.is_empty());
            if scope_mismatch {
                bindings.extend(dynamic_token_grant_bindings_for_provider_with_catalog(
                    catalog, &provider,
                ));
                if validate_policy_composition
                    && let Some(profile) = get_provider_type_profile_for_scope(
                        catalog,
                        &provider.r#type,
                        &provider.profile_workspace,
                    )
                {
                    let rule_name = openshell_policy::provider_rule_name(provider.object_name());
                    provider_layers.push(ProviderPolicyLayer {
                        rule: profile.network_policy_rule(&rule_name),
                        rule_name,
                    });
                }
                continue;
            }
            if let Some((source, profile)) = candidate_profiles.get(&profile_id) {
                let has_static_credentials = provider
                    .credentials
                    .keys()
                    .any(|key| !is_non_injectable_provider_credential(&provider, key));
                let has_usable_endpoint = profile.to_proto().endpoints.iter().any(|endpoint| {
                    !endpoint_ports(endpoint.port, &endpoint.ports).is_empty()
                        && !endpoint.host.trim().is_empty()
                });
                let has_policy_binding = super::policy::policy_has_credential_binding_for_provider(
                    &base_policy,
                    provider_name,
                );
                if has_static_credentials && !has_usable_endpoint && !has_policy_binding {
                    diagnostics.push(ProfileValidationDiagnostic {
                        source: source.clone(),
                        profile_id: profile_id.clone(),
                        field: "endpoints".to_string(),
                        message: format!(
                            "{operation} would leave static provider credentials without an authorized endpoint on sandbox '{sandbox_name}'"
                        ),
                        severity: "error".to_string(),
                    });
                }
                if has_usable_endpoint && has_policy_binding {
                    diagnostics.push(ProfileValidationDiagnostic {
                        source: source.clone(),
                        profile_id: profile_id.clone(),
                        field: "endpoints".to_string(),
                        message: format!(
                            "{operation} would give provider '{provider_name}' both profile endpoint bindings and sandbox policy credential bindings on sandbox '{sandbox_name}'"
                        ),
                        severity: "error".to_string(),
                    });
                }
                bindings.extend(dynamic_token_grant_bindings_for_profile(
                    provider.object_name(),
                    &profile.to_proto(),
                ));
                if validate_policy_composition {
                    let rule_name = openshell_policy::provider_rule_name(provider.object_name());
                    provider_layers.push(ProviderPolicyLayer {
                        rule: profile.network_policy_rule(&rule_name),
                        rule_name,
                    });
                }
                let used = (source.clone(), profile_id.clone());
                if !imported_profiles_used.contains(&used) {
                    imported_profiles_used.push(used);
                }
            } else {
                bindings.extend(dynamic_token_grant_bindings_for_provider_with_catalog(
                    catalog, &provider,
                ));
                if validate_policy_composition
                    && let Some(profile) = get_provider_type_profile_for_scope(
                        catalog,
                        &provider.r#type,
                        &provider.profile_workspace,
                    )
                {
                    let rule_name = openshell_policy::provider_rule_name(provider.object_name());
                    provider_layers.push(ProviderPolicyLayer {
                        rule: profile.network_policy_rule(&rule_name),
                        rule_name,
                    });
                }
            }
        }

        if imported_profiles_used.is_empty() {
            continue;
        }
        if let Err(err) = validate_dynamic_token_grant_bindings_unambiguous(&bindings) {
            for (source, profile_id) in &imported_profiles_used {
                diagnostics.push(ProfileValidationDiagnostic {
                    source: source.clone(),
                    profile_id: profile_id.clone(),
                    field: "credentials.token_grant.audience_overrides".to_string(),
                    message: format!(
                        "{operation} would create ambiguous dynamic token grants on sandbox '{sandbox_name}': {}",
                        err.message()
                    ),
                    severity: "error".to_string(),
                });
            }
        }
        if validate_policy_composition
            && let Err(error) =
                super::policy::validate_candidate_effective_policy(&base_policy, &provider_layers)
        {
            for (source, profile_id) in &imported_profiles_used {
                diagnostics.push(ProfileValidationDiagnostic {
                    source: source.clone(),
                    profile_id: profile_id.clone(),
                    field: "endpoints".to_string(),
                    message: format!(
                        "{operation} would create ambiguous network endpoints on sandbox \
                         '{sandbox_name}': {}",
                        error.message()
                    ),
                    severity: "error".to_string(),
                });
            }
        }
    }

    Ok(diagnostics)
}

fn stored_provider_profile_for_workspace(
    profile: ProviderProfile,
    workspace: &str,
) -> StoredProviderProfile {
    use crate::persistence::current_time_ms;
    let now_ms = current_time_ms();
    let profile = profile_storage_payload(profile);
    StoredProviderProfile {
        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: profile.id.clone(),
            created_at_ms: now_ms,
            labels: HashMap::new(),
            resource_version: 0,
            annotations: HashMap::new(),
            workspace: workspace.to_string(),
            deletion_timestamp_ms: 0,
        }),
        profile: Some(profile),
    }
}

#[cfg(test)]
fn stored_provider_profile(profile: ProviderProfile) -> StoredProviderProfile {
    stored_provider_profile_for_workspace(profile, "default")
}

fn proto_diagnostic(diagnostic: ProfileValidationDiagnostic) -> ProviderProfileDiagnostic {
    ProviderProfileDiagnostic {
        source: diagnostic.source,
        profile_id: diagnostic.profile_id,
        field: diagnostic.field,
        message: diagnostic.message,
        severity: diagnostic.severity,
    }
}

fn has_errors(diagnostics: &[ProfileValidationDiagnostic]) -> bool {
    diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == "error")
}

pub(super) async fn handle_update_provider(
    state: &Arc<ServerState>,
    request: Request<UpdateProviderRequest>,
) -> Result<Response<ProviderResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &req.workspace,
        MinWorkspaceRole::Admin,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
        .await?
        .name;
    let Some(mut provider) = req.provider else {
        emit_provider_lifecycle(
            "custom",
            LifecycleOperation::Update,
            TelemetryOutcome::Failure,
        );
        return Err(Status::invalid_argument("provider is required"));
    };
    let provider_type = provider.r#type.clone();
    provider
        .credential_expires_at_ms
        .extend(req.credential_expires_at_ms);
    if state.credentials.stores_provider_credentials() && !provider.credentials.is_empty() {
        state.compute.ensure_workspace(&workspace).await?;
    }
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), &workspace)
        .await?;
    let result = update_provider_record_validating(
        state.store.as_ref(),
        &workspace,
        &catalog,
        provider,
        Some(&state.credentials),
    )
    .await;
    match result {
        Ok(provider) => {
            emit_provider_lifecycle(
                &provider.r#type,
                LifecycleOperation::Update,
                TelemetryOutcome::Success,
            );
            Ok(Response::new(ProviderResponse {
                provider: Some(provider),
            }))
        }
        Err(err) => {
            emit_provider_lifecycle(
                &provider_type,
                LifecycleOperation::Update,
                TelemetryOutcome::Failure,
            );
            Err(err)
        }
    }
}

pub(super) async fn handle_exchange_provider_subject_token(
    state: &Arc<ServerState>,
    request: Request<ExchangeProviderSubjectTokenRequest>,
) -> Result<Response<ExchangeProviderSubjectTokenResponse>, Status> {
    let req = request.get_ref().clone();
    let principal = crate::auth::guard::enforce_sandbox_scope(&request, &req.sandbox_id)?;
    crate::auth::guard::ensure_sandbox_principal_scope(&principal, &req.sandbox_id)?;
    drop(request);

    if req.provider.trim().is_empty() {
        return Err(Status::invalid_argument("provider is required"));
    }
    if req.credential_key.trim().is_empty() {
        return Err(Status::invalid_argument("credential_key is required"));
    }
    if req.supervisor_jwt_svid.trim().is_empty() {
        return Err(Status::invalid_argument("supervisor_jwt_svid is required"));
    }

    let sandbox = state
        .store
        .get_message::<Sandbox>(&req.sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let workspace = sandbox.object_workspace().to_string();
    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::internal("sandbox has no spec"))?;
    if !spec
        .providers
        .iter()
        .any(|provider| provider == &req.provider)
    {
        return Err(Status::permission_denied(
            "provider is not attached to this sandbox",
        ));
    }

    let provider = state
        .store
        .get_message_by_name::<Provider>(&workspace, &req.provider)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
        .ok_or_else(|| Status::not_found("provider not found"))?;
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), &workspace)
        .await?;
    let profile = get_provider_type_profile_for_scope(
        &catalog,
        &provider.r#type,
        &provider.profile_workspace,
    )
    .ok_or_else(|| Status::failed_precondition("provider profile not found"))?;
    let profile_proto = profile.to_proto();
    let credential = profile_proto
        .credentials
        .iter()
        .find(|credential| credential.name == req.credential_key)
        .ok_or_else(|| {
            Status::failed_precondition("credential not declared by provider profile")
        })?;
    let token_grant = credential
        .token_grant
        .as_ref()
        .ok_or_else(|| Status::failed_precondition("credential does not declare token_grant"))?;
    let grant_type = ProviderCredentialTokenGrantType::try_from(token_grant.grant_type)
        .unwrap_or(ProviderCredentialTokenGrantType::ClientCredentials);
    if grant_type != ProviderCredentialTokenGrantType::TokenExchange {
        return Err(Status::failed_precondition(
            "credential token_grant is not token_exchange",
        ));
    }
    let subject_token = token_grant
        .subject_token
        .as_ref()
        .ok_or_else(|| Status::failed_precondition("token_exchange subject_token is missing"))?;
    if subject_token.source != "provider_credential" {
        return Err(Status::failed_precondition(
            "unsupported subject_token source",
        ));
    }
    if !profile_proto
        .credentials
        .iter()
        .any(|credential| credential.name == subject_token.credential)
    {
        return Err(Status::failed_precondition(
            "subject token credential not declared by provider profile",
        ));
    }
    let stored_subject_token =
        resolve_subject_token_credential(&state.credentials, &provider, &subject_token.credential)
            .await?;

    let jwt_svid_audience =
        effective_jwt_svid_audience(&token_grant.token_endpoint, &token_grant.jwt_svid_audience);
    let gateway_jwt_svid = fetch_gateway_jwt_svid(&jwt_svid_audience).await?;
    let gateway_claims = parse_unverified_spiffe_claims(&gateway_jwt_svid)?;
    validate_gateway_jwt_svid_claims(&gateway_claims, &jwt_svid_audience)?;
    let supervisor_claims = validate_supervisor_jwt_svid(
        &req.supervisor_jwt_svid,
        &gateway_claims,
        &jwt_svid_audience,
    )
    .await?;

    let intermediate_cache_key = intermediate_token_cache_key(IntermediateTokenCacheKeyInput {
        provider: &provider,
        dynamic_credential: &req.credential_key,
        subject_credential: &subject_token.credential,
        token_endpoint: &token_grant.token_endpoint,
        client_assertion_type: effective_client_assertion_type(&token_grant.client_assertion_type),
        subject_token_type: effective_token_type(&subject_token.subject_token_type),
        audience: &supervisor_claims.sub,
        requested_token_type: effective_token_type(&token_grant.requested_token_type),
        supervisor_subject: &supervisor_claims.sub,
        gateway_subject: &gateway_claims.sub,
    });
    if let Some(cached) = INTERMEDIATE_TOKEN_CACHE.get(&intermediate_cache_key) {
        return Ok(Response::new(ExchangeProviderSubjectTokenResponse {
            access_token: cached.access_token,
            expires_in: cached.expires_in,
            token_type: cached.token_type,
        }));
    }

    let token_response = perform_intermediate_token_exchange(
        &token_grant.token_endpoint,
        &gateway_jwt_svid,
        &token_grant.client_assertion_type,
        &stored_subject_token,
        &subject_token.subject_token_type,
        &supervisor_claims.sub,
        &token_grant.requested_token_type,
    )
    .await
    .inspect_err(|status| {
        warn!(
            sandbox_id = %req.sandbox_id,
            provider = %req.provider,
            credential_key = %req.credential_key,
            subject_credential = %subject_token.credential,
            client_assertion_type = %effective_client_assertion_type(&token_grant.client_assertion_type),
            gateway_svid_issuer = %gateway_claims.iss,
            gateway_svid_subject = %gateway_claims.sub,
            gateway_svid_audience = ?gateway_claims.aud,
            supervisor_svid_issuer = %supervisor_claims.iss,
            supervisor_svid_subject = %supervisor_claims.sub,
            supervisor_svid_audience = ?supervisor_claims.aud,
            status = ?status.code(),
            error = %status.message(),
            "intermediate provider token exchange failed"
        );
    })?;
    let cache_expires_at_ms = intermediate_token_cache_expires_at_ms(
        &token_response,
        token_grant.cache_ttl_seconds,
        provider_credential_expires_at_ms(&provider, &subject_token.credential),
        supervisor_claims.exp,
    );
    if cache_expires_at_ms > crate::persistence::current_time_ms() {
        INTERMEDIATE_TOKEN_CACHE.set(intermediate_cache_key, &token_response, cache_expires_at_ms);
    }

    Ok(Response::new(ExchangeProviderSubjectTokenResponse {
        access_token: token_response.access_token,
        expires_in: token_response.expires_in,
        token_type: token_response.token_type,
    }))
}

async fn resolve_subject_token_credential(
    credentials: &crate::credentials::CredentialRuntime,
    provider: &Provider,
    credential_key: &str,
) -> Result<String, Status> {
    if let Some(value) = provider
        .credentials
        .get(credential_key)
        .filter(|value| !value.is_empty())
    {
        ensure_subject_token_credential_not_expired(provider, credential_key)?;
        return Ok(value.clone());
    }

    if provider.credential_handles.contains_key(credential_key) {
        let resolved = credentials
            .resolve_provider_handles(provider, crate::persistence::current_time_ms())
            .await?;
        if let Some(value) = resolved
            .values
            .get(credential_key)
            .filter(|value| !value.is_empty())
        {
            return Ok(value.clone());
        }
    }

    Err(Status::failed_precondition(
        "subject token credential is not configured",
    ))
}

fn ensure_subject_token_credential_not_expired(
    provider: &Provider,
    credential_key: &str,
) -> Result<(), Status> {
    let expires_at_ms = provider_credential_expires_at_ms(provider, credential_key);
    if expires_at_ms > 0 && expires_at_ms <= crate::persistence::current_time_ms() {
        return Err(Status::failed_precondition(
            "subject token credential has expired",
        ));
    }
    Ok(())
}

fn provider_credential_expires_at_ms(provider: &Provider, credential_key: &str) -> i64 {
    provider
        .credential_expires_at_ms
        .get(credential_key)
        .copied()
        .unwrap_or_default()
}

struct IntermediateTokenCacheKeyInput<'a> {
    provider: &'a Provider,
    dynamic_credential: &'a str,
    subject_credential: &'a str,
    token_endpoint: &'a str,
    client_assertion_type: &'a str,
    subject_token_type: &'a str,
    audience: &'a str,
    requested_token_type: &'a str,
    supervisor_subject: &'a str,
    gateway_subject: &'a str,
}

fn intermediate_token_cache_key(input: IntermediateTokenCacheKeyInput<'_>) -> String {
    let provider_id = input
        .provider
        .metadata
        .as_ref()
        .map(|metadata| metadata.id.as_str())
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| input.provider.object_name());
    let provider_resource_version = input
        .provider
        .metadata
        .as_ref()
        .map_or(0, |metadata| metadata.resource_version);
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        provider_id,
        provider_resource_version,
        input.dynamic_credential,
        input.subject_credential,
        input.token_endpoint,
        input.client_assertion_type,
        input.subject_token_type,
        input.audience,
        input.requested_token_type,
        input.supervisor_subject,
        input.gateway_subject
    )
}

fn intermediate_token_cache_expires_at_ms(
    token: &oauth::OAuthTokenResponse,
    cache_ttl_seconds: i64,
    subject_token_expires_at_ms: i64,
    supervisor_svid_exp_seconds: i64,
) -> i64 {
    let now_ms = crate::persistence::current_time_ms();
    let mut ttl_seconds = if token.expires_in > 0 {
        token
            .expires_in
            .min(MAX_INTERMEDIATE_TOKEN_CACHE_TTL_SECONDS)
    } else {
        DEFAULT_INTERMEDIATE_TOKEN_CACHE_TTL_SECONDS
    };
    if cache_ttl_seconds > 0 {
        ttl_seconds = ttl_seconds.min(cache_ttl_seconds);
    }
    ttl_seconds = ttl_seconds
        .saturating_sub(INTERMEDIATE_TOKEN_CACHE_EXPIRY_SKEW_SECONDS)
        .max(1);
    let mut expires_at_ms = now_ms.saturating_add(ttl_seconds.saturating_mul(1000));
    expires_at_ms = cap_cache_expiry_ms(expires_at_ms, jwt_exp_ms(&token.access_token));
    expires_at_ms = cap_cache_expiry_ms(expires_at_ms, Some(subject_token_expires_at_ms));
    expires_at_ms = cap_cache_expiry_ms(
        expires_at_ms,
        (supervisor_svid_exp_seconds > 0).then(|| supervisor_svid_exp_seconds.saturating_mul(1000)),
    );
    expires_at_ms
}

fn cap_cache_expiry_ms(current_expires_at_ms: i64, cap_expires_at_ms: Option<i64>) -> i64 {
    let Some(cap_expires_at_ms) = cap_expires_at_ms.filter(|value| *value > 0) else {
        return current_expires_at_ms;
    };
    current_expires_at_ms.min(
        cap_expires_at_ms
            .saturating_sub(INTERMEDIATE_TOKEN_CACHE_EXPIRY_SKEW_SECONDS.saturating_mul(1000)),
    )
}

fn jwt_exp_ms(token: &str) -> Option<i64> {
    use base64::Engine as _;
    let payload = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims = serde_json::from_slice::<serde_json::Value>(&decoded).ok()?;
    claims
        .get("exp")?
        .as_i64()
        .map(|exp| exp.saturating_mul(1000))
}

async fn fetch_gateway_jwt_svid(audience: &str) -> Result<String, Status> {
    let socket_path = std::env::var(GATEWAY_SPIFFE_WORKLOAD_API_SOCKET)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            Status::failed_precondition(format!(
                "{GATEWAY_SPIFFE_WORKLOAD_API_SOCKET} is required for provider token exchange"
            ))
        })?;
    let endpoint = workload_api_endpoint(std::path::Path::new(&socket_path));
    let client = spiffe::WorkloadApiClient::connect_to(&endpoint)
        .await
        .map_err(|e| {
            Status::failed_precondition(format!("SPIFFE Workload API unavailable: {e}"))
        })?;
    client
        .fetch_jwt_token([audience], None)
        .await
        .map_err(|e| Status::failed_precondition(format!("failed to fetch gateway JWT-SVID: {e}")))
}

fn validate_gateway_jwt_svid_claims(
    claims: &SpiffeJwtClaims,
    expected_audience: &str,
) -> Result<(), Status> {
    if !claims.aud.contains(expected_audience) {
        return Err(Status::failed_precondition(
            "gateway SVID audience does not match token grant audience",
        ));
    }
    if spiffe_trust_domain(&claims.sub).is_none() {
        return Err(Status::failed_precondition(
            "gateway SVID subject is not a SPIFFE ID",
        ));
    }
    if claims.exp > 0 && claims.exp.saturating_mul(1000) <= crate::persistence::current_time_ms() {
        return Err(Status::failed_precondition("gateway SVID has expired"));
    }
    Ok(())
}

async fn validate_supervisor_jwt_svid(
    token: &str,
    gateway_claims: &SpiffeJwtClaims,
    expected_audience: &str,
) -> Result<SpiffeJwtClaims, Status> {
    let unverified = parse_unverified_spiffe_claims(token)?;
    if unverified.iss != gateway_claims.iss {
        return Err(Status::permission_denied(
            "supervisor SVID issuer does not match gateway SVID issuer",
        ));
    }
    if !unverified.aud.contains(expected_audience) {
        return Err(Status::permission_denied(
            "supervisor SVID audience does not match token grant audience",
        ));
    }
    let supervisor_trust_domain = spiffe_trust_domain(&unverified.sub)
        .ok_or_else(|| Status::permission_denied("supervisor SVID subject is not a SPIFFE ID"))?;
    let gateway_trust_domain = spiffe_trust_domain(&gateway_claims.sub)
        .ok_or_else(|| Status::failed_precondition("gateway SVID subject is not a SPIFFE ID"))?;
    if supervisor_trust_domain != gateway_trust_domain {
        return Err(Status::permission_denied(
            "supervisor SVID trust domain does not match gateway SVID trust domain",
        ));
    }

    let socket_path = std::env::var(GATEWAY_SPIFFE_WORKLOAD_API_SOCKET)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            Status::failed_precondition(format!(
                "{GATEWAY_SPIFFE_WORKLOAD_API_SOCKET} is required for supervisor JWT-SVID validation"
            ))
        })?;
    let endpoint = workload_api_endpoint(std::path::Path::new(&socket_path));
    let client = spiffe::WorkloadApiClient::connect_to(&endpoint)
        .await
        .map_err(|e| {
            Status::failed_precondition(format!("SPIFFE Workload API unavailable: {e}"))
        })?;
    let bundles = client
        .fetch_jwt_bundles()
        .await
        .map_err(|e| Status::internal(format!("SPIFFE JWT bundle fetch failed: {e}")))?;
    spiffe::JwtSvid::parse_and_validate(token, &bundles, &[expected_audience])
        .map_err(|e| Status::permission_denied(format!("invalid supervisor JWT-SVID: {e}")))?;
    Ok(unverified)
}

fn parse_unverified_spiffe_claims(token: &str) -> Result<SpiffeJwtClaims, Status> {
    parse_unverified_jwt_svid_claims(token).map_err(jwt_svid_parse_error_status)
}

fn jwt_svid_parse_error_status(error: JwtSvidParseError) -> Status {
    Status::permission_denied(error.to_string())
}

async fn perform_intermediate_token_exchange(
    token_endpoint: &str,
    gateway_jwt_svid: &str,
    client_assertion_type: &str,
    subject_token: &str,
    subject_token_type: &str,
    audience: &str,
    requested_token_type: &str,
) -> Result<oauth::OAuthTokenResponse, Status> {
    let client = token_exchange_http_client()?;
    oauth::post_oauth_token_exchange(
        client,
        token_endpoint,
        &TokenExchangeParams {
            client_assertion: gateway_jwt_svid,
            client_assertion_type,
            subject_token,
            subject_token_type,
            audience,
            scopes: &[],
            requested_token_type,
        },
    )
    .await
    .map_err(|e| Status::failed_precondition(e.to_string()))
}

fn effective_jwt_svid_audience(token_endpoint: &str, jwt_svid_audience: &str) -> String {
    if !jwt_svid_audience.trim().is_empty() {
        return jwt_svid_audience.to_string();
    }
    derive_issuer_from_token_endpoint(token_endpoint)
}

fn derive_issuer_from_token_endpoint(token_endpoint: &str) -> String {
    if let Some(realms_idx) = token_endpoint.find("/realms/") {
        let after_realms = &token_endpoint[realms_idx + "/realms/".len()..];
        if let Some(slash_idx) = after_realms.find('/') {
            let realm_end = realms_idx + "/realms/".len() + slash_idx;
            return token_endpoint[..realm_end].to_string();
        }
    }
    token_endpoint.to_string()
}

pub(super) async fn handle_get_provider_refresh_status(
    state: &Arc<ServerState>,
    request: Request<GetProviderRefreshStatusRequest>,
) -> Result<Response<GetProviderRefreshStatusResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &request.workspace,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
        .await?
        .name;
    if request.provider.trim().is_empty() {
        return Err(Status::invalid_argument("provider is required"));
    }
    let provider = state
        .store
        .get_message_by_name::<Provider>(&workspace, &request.provider)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
        .ok_or_else(|| Status::not_found("provider not found"))?;

    let states = if request.credential_key.trim().is_empty() {
        crate::provider_refresh::list_refresh_states_for_provider(
            state.store.as_ref(),
            provider.object_id(),
        )
        .await?
    } else {
        crate::provider_refresh::get_refresh_state(
            state.store.as_ref(),
            &workspace,
            provider.object_id(),
            request.credential_key.trim(),
        )
        .await?
        .into_iter()
        .collect()
    };

    Ok(Response::new(GetProviderRefreshStatusResponse {
        credentials: states
            .iter()
            .map(crate::provider_refresh::refresh_status_from_state)
            .collect(),
    }))
}

pub(super) async fn handle_configure_provider_refresh(
    state: &Arc<ServerState>,
    request: Request<ConfigureProviderRefreshRequest>,
) -> Result<Response<ConfigureProviderRefreshResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &request.workspace,
        MinWorkspaceRole::Admin,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
        .await?
        .name;
    let provider_name = request.provider.trim();
    let credential_key = request.credential_key.trim();
    if provider_name.is_empty() {
        return Err(Status::invalid_argument("provider is required"));
    }
    if credential_key.is_empty() {
        return Err(Status::invalid_argument("credential_key is required"));
    }
    if !is_valid_env_key(credential_key) {
        return Err(Status::invalid_argument(
            "credential_key must be a valid environment variable name",
        ));
    }
    let strategy = ProviderCredentialRefreshStrategy::try_from(request.strategy)
        .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified);
    if strategy == ProviderCredentialRefreshStrategy::Unspecified {
        return Err(Status::invalid_argument("refresh strategy is required"));
    }
    if !crate::provider_refresh::is_gateway_mintable_strategy(strategy) {
        return Err(Status::invalid_argument(format!(
            "refresh strategy '{}' is not gateway-mintable; update current credentials with provider update instead",
            crate::provider_refresh::refresh_strategy_name(strategy as i32)
        )));
    }
    if request.material.len() > MAX_PROVIDER_CONFIG_ENTRIES {
        return Err(Status::invalid_argument(format!(
            "material exceeds maximum entries ({} > {MAX_PROVIDER_CONFIG_ENTRIES})",
            request.material.len()
        )));
    }
    for (key, value) in &request.material {
        if key.len() > MAX_MAP_KEY_LEN {
            return Err(Status::invalid_argument(format!(
                "material key exceeds maximum length ({} > {MAX_MAP_KEY_LEN})",
                key.len()
            )));
        }
        if value.len() > MAX_MAP_VALUE_LEN {
            return Err(Status::invalid_argument(format!(
                "material value exceeds maximum length ({} > {MAX_MAP_VALUE_LEN})",
                value.len()
            )));
        }
    }
    if request.secret_material_keys.len() > MAX_PROVIDER_CONFIG_ENTRIES {
        return Err(Status::invalid_argument(format!(
            "secret_material_keys exceeds maximum entries ({} > {MAX_PROVIDER_CONFIG_ENTRIES})",
            request.secret_material_keys.len()
        )));
    }
    for key in &request.secret_material_keys {
        if key.len() > MAX_MAP_KEY_LEN {
            return Err(Status::invalid_argument(format!(
                "secret_material_keys entry exceeds maximum length ({} > {MAX_MAP_KEY_LEN})",
                key.len()
            )));
        }
    }
    if request
        .material
        .get("token_url")
        .is_some_and(|value| !value.trim().is_empty())
        || request
            .material
            .get("token_uri")
            .is_some_and(|value| !value.trim().is_empty())
    {
        return Err(Status::invalid_argument(
            "refresh token endpoints must be defined by the provider profile, not material",
        ));
    }
    // The STS endpoint is always resolved from the region in production. Reject
    // any caller-supplied override so an AWS-signed AssumeRole request cannot be
    // redirected at an arbitrary service (CWE-918). Tests inject a mock endpoint
    // through test-only code paths, not this boundary.
    if request.material.contains_key("sts_endpoint_url") {
        return Err(Status::invalid_argument(
            "sts_endpoint_url material is not permitted",
        ));
    }
    // Explicit AWS source credentials are all-or-nothing. Reject a partial pair
    // early so a lone key can't later fall through to the gateway's ambient
    // identity at mint time (CWE-20).
    let has_source_access_key = request
        .material
        .get("aws_access_key_id")
        .is_some_and(|value| !value.trim().is_empty());
    let has_source_secret_key = request
        .material
        .get("aws_secret_access_key")
        .is_some_and(|value| !value.trim().is_empty());
    if has_source_access_key != has_source_secret_key {
        return Err(Status::invalid_argument(
            "aws_access_key_id and aws_secret_access_key must both be set or both omitted",
        ));
    }
    // An optional session token supports temporary source credentials (SSO or a
    // prior AssumeRole). It only makes sense alongside the source key pair.
    let has_source_session_token = request
        .material
        .get("aws_session_token")
        .is_some_and(|value| !value.trim().is_empty());
    if has_source_session_token && !has_source_access_key {
        return Err(Status::invalid_argument(
            "aws_session_token requires aws_access_key_id and aws_secret_access_key",
        ));
    }
    if request
        .expires_at_ms
        .is_some_and(|expires_at_ms| expires_at_ms < 0)
    {
        return Err(Status::invalid_argument(
            "expires_at_ms must be greater than or equal to 0",
        ));
    }

    // Serialize the reserve-then-persist sequence against other configurations
    // and sandbox mutations. The collision validation below and the refresh-state
    // persist further down are otherwise separate steps: two concurrent
    // configures of providers attached to the same sandbox could each pass
    // validation before either persisted and both reserve the same key (CWE-362).
    // This is the same guard sandbox create/attach and profile changes take.
    let _sandbox_sync_guard = state.compute.sandbox_sync_guard().await;

    let provider = state
        .store
        .get_message_by_name::<Provider>(&workspace, provider_name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
        .ok_or_else(|| Status::not_found("provider not found"))?;
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), &workspace)
        .await?;
    validate_provider_credential_key_available_for_attached_sandboxes_with_catalog(
        state.store.as_ref(),
        &catalog,
        &workspace,
        &provider,
        credential_key,
    )
    .await?;
    // Reserve every env key this refresh will co-mint (resolved from the
    // profile's additional_outputs), not just the primary, so a
    // configured-but-not-yet-minted refresh can't collide with another provider
    // that later claims one of the derived keys.
    let additional_output_keys =
        resolved_additional_output_keys(&catalog, &provider, credential_key);
    for additional_key in additional_output_keys.values() {
        validate_provider_credential_key_available_for_attached_sandboxes_with_catalog(
            state.store.as_ref(),
            &catalog,
            &workspace,
            &provider,
            additional_key,
        )
        .await?;
    }
    let refresh_defaults = provider_refresh_defaults(&catalog, &provider, credential_key);
    validate_strategy_profile_binding(
        strategy,
        credential_key,
        refresh_defaults.as_ref(),
        &additional_output_keys,
    )?;
    validate_refresh_material(&request.material, refresh_defaults.as_ref())?;
    let mut secret_material_keys: HashSet<String> =
        request.secret_material_keys.iter().cloned().collect();
    for key in &request.secret_material_keys {
        if !request.material.contains_key(key) {
            return Err(Status::invalid_argument(format!(
                "secret_material_keys entry '{key}' is not present in material"
            )));
        }
    }
    if let Some(refresh) = refresh_defaults.as_ref() {
        secret_material_keys.extend(
            refresh
                .material
                .iter()
                .filter(|item| item.secret && request.material.contains_key(&item.name))
                .map(|item| item.name.clone()),
        );
    }
    secret_material_keys.extend(
        crate::provider_refresh::strategy_secret_material_keys(strategy)
            .iter()
            .filter(|key| request.material.contains_key(**key))
            .map(|key| (*key).to_string()),
    );
    let mut secret_material_keys: Vec<_> = secret_material_keys.into_iter().collect();
    secret_material_keys.sort();
    let material_scopes = crate::provider_refresh::material_scopes(&request.material);
    let token_url = refresh_defaults
        .as_ref()
        .map(|refresh| refresh.token_url.clone())
        .unwrap_or_default();
    let scopes = if material_scopes.is_empty() {
        refresh_defaults
            .as_ref()
            .map(|refresh| refresh.scopes.clone())
            .unwrap_or_default()
    } else {
        material_scopes
    };
    let refresh_before_seconds =
        crate::provider_refresh::parse_material_i64(&request.material, "refresh_before_seconds")?
            .or_else(|| {
                refresh_defaults
                    .as_ref()
                    .map(|refresh| refresh.refresh_before_seconds)
            })
            .unwrap_or_default();
    let max_lifetime_seconds =
        crate::provider_refresh::parse_material_i64(&request.material, "max_lifetime_seconds")?
            .or_else(|| {
                refresh_defaults
                    .as_ref()
                    .map(|refresh| refresh.max_lifetime_seconds)
            })
            .unwrap_or_default();
    if refresh_before_seconds < 0 {
        return Err(Status::invalid_argument(
            "refresh_before_seconds material must be greater than or equal to 0",
        ));
    }
    if max_lifetime_seconds < 0 {
        return Err(Status::invalid_argument(
            "max_lifetime_seconds material must be greater than or equal to 0",
        ));
    }
    let existing_refresh_state = crate::provider_refresh::get_refresh_state(
        state.store.as_ref(),
        &workspace,
        provider.object_id(),
        credential_key,
    )
    .await?;
    if existing_refresh_state.as_ref().is_some_and(|state| {
        state
            .metadata
            .as_ref()
            .is_some_and(|metadata| metadata.deletion_timestamp_ms != 0)
    }) {
        return Err(Status::failed_precondition(
            "provider refresh is being deleted; retry deletion before configuring it again",
        ));
    }
    let existing_refresh_version = existing_refresh_state.as_ref().and_then(|state| {
        state
            .metadata
            .as_ref()
            .map(|metadata| metadata.resource_version)
    });
    let expires_at_ms = request.expires_at_ms.unwrap_or_else(|| {
        existing_refresh_state
            .as_ref()
            .map(|state| state.expires_at_ms)
            .unwrap_or_default()
    });
    let mut persisted_material = request.material;
    let secret_material: HashMap<_, _> = secret_material_keys
        .iter()
        .filter_map(|key| {
            persisted_material
                .remove(key)
                .map(|value| (key.clone(), value))
        })
        .collect();
    let mut state_record = crate::provider_refresh::new_refresh_state(
        &provider,
        &workspace,
        credential_key,
        crate::provider_refresh::NewRefreshStateConfig {
            strategy,
            material: persisted_material,
            secret_material_keys,
            expires_at_ms,
            token_url,
            scopes,
            refresh_before_seconds,
            max_lifetime_seconds,
            additional_output_keys,
        },
    )?;
    if let Some(existing) = existing_refresh_state.as_ref() {
        state_record.metadata.clone_from(&existing.metadata);
        state_record.last_refresh_at_ms = existing.last_refresh_at_ms;
        state_record
            .pending_secret_deletions
            .extend(existing.pending_secret_deletions.clone());
        for (material_key, handle) in &existing.secret_material_handles {
            crate::provider_refresh::enqueue_pending_secret_deletion(
                &mut state_record,
                material_key,
                handle.clone(),
            );
        }
    }
    let material_staging_id = format!(
        "{}-refresh-config-{}",
        provider.object_id(),
        uuid::Uuid::new_v4()
    );
    let staged_material_handles = state
        .credentials
        .store_refresh_material_with_object_id(
            crate::provider_refresh::refresh_material_scope(&state_record),
            &material_staging_id,
            &secret_material,
            &HashMap::new(),
        )
        .await?;
    state_record.secret_material_handles = staged_material_handles.clone();
    let persist_result = if let Some(expected_version) = existing_refresh_version {
        match crate::provider_refresh::replace_refresh_state_if_current(
            state.store.as_ref(),
            &state_record,
            expected_version,
        )
        .await
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(Status::aborted(
                "provider refresh was concurrently modified during configuration",
            )),
            Err(err) => Err(err),
        }
    } else {
        crate::provider_refresh::create_refresh_state(state.store.as_ref(), &state_record).await
    };
    if let Err(err) = persist_result {
        if let Err(cleanup_err) = state
            .credentials
            .delete_refresh_material_handles(
                crate::provider_refresh::refresh_material_scope(&state_record),
                &staged_material_handles,
            )
            .await
        {
            warn!(
                provider_name = %provider.object_name(),
                credential_key,
                error = %cleanup_err,
                "failed to clean up staged refresh material after configuration failure"
            );
        }
        return Err(err);
    }

    if let Some(expires_at_ms) = request.expires_at_ms {
        let updated = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: provider_name.to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: String::new(),
                deletion_timestamp_ms: 0,
            }),
            r#type: String::new(),
            credentials: HashMap::new(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::from([(credential_key.to_string(), expires_at_ms)]),
            profile_workspace: String::new(),
            credential_handles: HashMap::new(),
        };
        update_provider_record_with_catalog(state.store.as_ref(), &catalog, &workspace, updated)
            .await?;
    }

    Ok(Response::new(ConfigureProviderRefreshResponse {
        status: Some(crate::provider_refresh::refresh_status_from_state(
            &state_record,
        )),
    }))
}

pub(super) async fn handle_rotate_provider_credential(
    state: &Arc<ServerState>,
    request: Request<RotateProviderCredentialRequest>,
) -> Result<Response<RotateProviderCredentialResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &request.workspace,
        MinWorkspaceRole::Admin,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
        .await?
        .name;
    let provider_name = request.provider.trim();
    let credential_key = request.credential_key.trim();
    if provider_name.is_empty() {
        return Err(Status::invalid_argument("provider is required"));
    }
    if credential_key.is_empty() {
        return Err(Status::invalid_argument("credential_key is required"));
    }
    let refresh_state = crate::provider_refresh::refresh_provider_credential(
        state.store.as_ref(),
        &workspace,
        &state.credentials,
        Some(&state.compute),
        provider_name,
        credential_key,
    )
    .await?;

    Ok(Response::new(RotateProviderCredentialResponse {
        status: Some(crate::provider_refresh::refresh_status_from_state(
            &refresh_state,
        )),
    }))
}

/// Remove the expiry for each key the refresh still owns — one whose stored
/// value equals the refresh's `expires_at_ms`. Independently updated expiries (no
/// longer matching) are left in place.
///
/// This operates on `provider` in place so it can run inside a CAS closure
/// against the current stored provider. The equality check must see the latest
/// state, not a snapshot read earlier in the handler: a concurrent rotation or
/// provider update between the read and the write could otherwise be clobbered
/// by an unconditional zero (CWE-362).
fn clear_refresh_owned_expiries(
    provider: &mut Provider,
    refresh_expires_at_ms: i64,
    owned_keys: &[String],
) {
    if refresh_expires_at_ms <= 0 {
        return;
    }
    for key in owned_keys {
        if provider
            .credential_expires_at_ms
            .get(key)
            .is_some_and(|expires_at_ms| *expires_at_ms == refresh_expires_at_ms)
        {
            provider.credential_expires_at_ms.remove(key);
        }
    }
}

pub(super) async fn handle_delete_provider_refresh(
    state: &Arc<ServerState>,
    request: Request<DeleteProviderRefreshRequest>,
) -> Result<Response<DeleteProviderRefreshResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &request.workspace,
        MinWorkspaceRole::Admin,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
        .await?
        .name;
    let provider_name = request.provider.trim();
    let credential_key = request.credential_key.trim();
    if provider_name.is_empty() {
        return Err(Status::invalid_argument("provider is required"));
    }
    if credential_key.is_empty() {
        return Err(Status::invalid_argument("credential_key is required"));
    }
    let provider = state
        .store
        .get_message_by_name::<Provider>(&workspace, provider_name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
        .ok_or_else(|| Status::not_found("provider not found"))?;
    let existing_refresh_state = crate::provider_refresh::get_refresh_state(
        state.store.as_ref(),
        &workspace,
        provider.object_id(),
        credential_key,
    )
    .await?;
    let deleted_refresh_state = crate::provider_refresh::delete_refresh_state_with_credentials(
        state.store.as_ref(),
        &state.credentials,
        &workspace,
        provider.object_id(),
        credential_key,
    )
    .await?;

    // A refresh co-manages the expiry of its primary credential and every pinned
    // additional output. Clear each expiry this refresh still owns, leaving
    // independently updated ones in place. The equality check and removal run
    // inside the CAS closure so they see the current stored provider — deciding
    // from the snapshot read above would let a concurrent rotation or provider
    // update land between the read and the write and then be clobbered (CWE-362).
    if let Some(refresh_state) = existing_refresh_state
        && refresh_state.expires_at_ms > 0
    {
        let refresh_expires_at_ms = refresh_state.expires_at_ms;
        let owned_keys: Vec<String> = std::iter::once(credential_key.to_string())
            .chain(refresh_state.additional_output_keys.into_values())
            .collect();
        state
            .store
            .update_message_cas::<Provider, _>(provider.object_id(), 0, |current| {
                clear_refresh_owned_expiries(current, refresh_expires_at_ms, &owned_keys);
            })
            .await
            .map_err(|e| {
                Status::internal(format!(
                    "clear refresh-owned credential expiries failed: {e}"
                ))
            })?;
    }

    Ok(Response::new(DeleteProviderRefreshResponse {
        deleted: deleted_refresh_state,
    }))
}

pub(super) async fn handle_delete_provider(
    state: &Arc<ServerState>,
    request: Request<DeleteProviderRequest>,
) -> Result<Response<DeleteProviderResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &req.workspace,
        MinWorkspaceRole::Admin,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
        .await?
        .name;
    let name = req.name;
    let provider_profile = provider_profile_for_name(state.store.as_ref(), &workspace, &name).await;
    let result = delete_provider_record_with_credentials(
        state.store.as_ref(),
        &workspace,
        &state.credentials,
        &name,
    )
    .await;
    match result {
        Ok(deleted) => {
            let outcome = TelemetryOutcome::from_success(deleted);
            emit_provider_profile_lifecycle(
                provider_profile.unwrap_or(TelemetryProviderProfile::Custom),
                LifecycleOperation::Delete,
                outcome,
            );
            Ok(Response::new(DeleteProviderResponse { deleted }))
        }
        Err(err) => {
            emit_provider_profile_lifecycle(
                provider_profile.unwrap_or(TelemetryProviderProfile::Custom),
                LifecycleOperation::Delete,
                TelemetryOutcome::Failure,
            );
            Err(err)
        }
    }
}

fn emit_provider_lifecycle(
    provider_type: &str,
    operation: LifecycleOperation,
    outcome: TelemetryOutcome,
) {
    let provider_profile = telemetry_provider_profile(provider_type);
    emit_provider_profile_lifecycle(provider_profile, operation, outcome);
}

fn emit_provider_profile_lifecycle(
    provider_profile: TelemetryProviderProfile,
    operation: LifecycleOperation,
    outcome: TelemetryOutcome,
) {
    openshell_core::telemetry::emit_provider_lifecycle(operation, outcome, provider_profile);
}

async fn provider_profile_for_name(
    store: &Store,
    workspace: &str,
    name: &str,
) -> Option<TelemetryProviderProfile> {
    store
        .get_message_by_name::<Provider>(workspace, name)
        .await
        .ok()
        .flatten()
        .map(|provider| telemetry_provider_profile(&provider.r#type))
}

fn telemetry_provider_profile(provider_type: &str) -> TelemetryProviderProfile {
    match normalize_provider_type(provider_type) {
        Some("anthropic") => TelemetryProviderProfile::Anthropic,
        Some("claude" | "claude-code") => TelemetryProviderProfile::Claude,
        Some("codex") => TelemetryProviderProfile::Codex,
        Some("copilot") => TelemetryProviderProfile::Copilot,
        Some("deepinfra") => TelemetryProviderProfile::Deepinfra,
        Some("github") => TelemetryProviderProfile::Github,
        Some("gitlab") => TelemetryProviderProfile::Gitlab,
        Some("nvidia") => TelemetryProviderProfile::Nvidia,
        Some("openai") => TelemetryProviderProfile::Openai,
        Some("opencode") => TelemetryProviderProfile::Opencode,
        Some("outlook") => TelemetryProviderProfile::Outlook,
        _ => TelemetryProviderProfile::Custom,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::{Identity, IdentityProvider};
    use crate::auth::principal::{Principal, UserPrincipal};
    use crate::grpc::test_support::{authed_request, test_server_state};
    use crate::grpc::{MAX_MAP_KEY_LEN, MAX_PROVIDER_TYPE_LEN};
    use crate::persistence::test_store;
    use openshell_core::proto::{
        AttachSandboxProviderRequest, ConfigureProviderRefreshRequest, CreateProviderRequest,
        CreateWorkspaceRequest, DeleteProviderProfileRequest, DeleteProviderRefreshRequest,
        DeleteProviderRequest, GetProviderProfileRequest, GetProviderRefreshStatusRequest,
        GetProviderRequest, ImportProviderProfilesRequest, L7Allow, L7Rule,
        LintProviderProfilesRequest, ListProviderProfilesRequest, ListProvidersRequest,
        NetworkBinary, NetworkEndpoint, NetworkPolicyRule, ProviderCredentialRefresh,
        ProviderCredentialRefreshMaterial, ProviderCredentialTokenGrant,
        ProviderCredentialTokenGrantAudienceOverride, ProviderCredentialTokenGrantSubjectToken,
        ProviderCredentialTokenGrantType, ProviderProfile, ProviderProfileCategory,
        ProviderProfileCredential, ProviderProfileImportItem, RotateProviderCredentialRequest,
        Sandbox, SandboxPolicy, SandboxSpec, StoredProviderProfile, UpdateProviderProfilesRequest,
        UpdateProviderRequest,
    };
    use openshell_core::{ObjectId, ObjectName};
    use tonic::{Code, Request};

    #[test]
    fn env_key_validation_accepts_valid_keys() {
        assert!(is_valid_env_key("PATH"));
        assert!(is_valid_env_key("PYTHONPATH"));
        assert!(is_valid_env_key("_OPENSHELL_VALUE_1"));
    }

    #[test]
    fn env_key_validation_rejects_invalid_keys() {
        assert!(!is_valid_env_key(""));
        assert!(!is_valid_env_key("1PATH"));
        assert!(!is_valid_env_key("BAD-KEY"));
        assert!(!is_valid_env_key("BAD KEY"));
        assert!(!is_valid_env_key("X=Y"));
        assert!(!is_valid_env_key("X;rm -rf /"));
    }

    #[test]
    fn create_validation_accepts_broker_only_credential_by_logical_name() {
        let profile = ProviderTypeProfile::from_proto(&ProviderProfile {
            id: "token-exchange".to_string(),
            credentials: vec![
                ProviderProfileCredential {
                    name: "subject_token".to_string(),
                    required: true,
                    ..Default::default()
                },
                ProviderProfileCredential {
                    name: "access_token".to_string(),
                    token_grant: Some(ProviderCredentialTokenGrant {
                        grant_type: ProviderCredentialTokenGrantType::TokenExchange as i32,
                        subject_token: Some(ProviderCredentialTokenGrantSubjectToken {
                            source: "provider_credential".to_string(),
                            credential: "subject_token".to_string(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ],
            ..Default::default()
        });
        let provider = Provider {
            credentials: HashMap::from([("subject_token".to_string(), "test-token".to_string())]),
            ..Default::default()
        };

        validate_provider_create_credentials(&profile, &provider).unwrap();
    }

    #[test]
    fn telemetry_provider_profile_maps_unknown_to_custom() {
        assert_eq!(
            telemetry_provider_profile("CLAUDE"),
            TelemetryProviderProfile::Claude
        );
        assert_eq!(
            telemetry_provider_profile("github"),
            TelemetryProviderProfile::Github
        );
        assert_eq!(
            telemetry_provider_profile("gh"),
            TelemetryProviderProfile::Github
        );
        assert_eq!(
            telemetry_provider_profile("glab"),
            TelemetryProviderProfile::Custom
        );
        assert_eq!(
            telemetry_provider_profile("outlook"),
            TelemetryProviderProfile::Custom
        );
        assert_eq!(
            telemetry_provider_profile("generic"),
            TelemetryProviderProfile::Custom
        );
        assert_eq!(
            telemetry_provider_profile("unknown-private"),
            TelemetryProviderProfile::Custom
        );
        assert_eq!(
            telemetry_provider_profile("acme-internal"),
            TelemetryProviderProfile::Custom
        );
        assert_eq!(
            telemetry_provider_profile("corp-llm-prod"),
            TelemetryProviderProfile::Custom
        );
    }

    #[test]
    fn dynamic_credentials_expand_endpoint_audience_overrides() {
        let service_audiences = [
            ("alpha.default.svc.cluster.local", "alpha"),
            ("beta.default.svc.cluster.local", "beta"),
            ("gamma.default.svc.cluster.local", "gamma"),
            ("delta.default.svc.cluster.local", "delta"),
        ];
        let credential = ProviderProfileCredential {
            name: "access_token".to_string(),
            description: String::new(),
            env_vars: Vec::new(),
            required: false,
            auth_style: "bearer".to_string(),
            header_name: "Authorization".to_string(),
            query_param: String::new(),
            refresh: None,
            path_template: String::new(),
            token_grant: Some(ProviderCredentialTokenGrant {
                grant_type: ProviderCredentialTokenGrantType::ClientCredentials as i32,
                token_endpoint: "http://keycloak.default.svc.cluster.local/realms/openshell/protocol/openid-connect/token".to_string(),
                audience: "api://default".to_string(),
                jwt_svid_audience: "http://keycloak.default.svc.cluster.local/realms/openshell"
                    .to_string(),
                client_assertion_type:
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
                subject_token: None,
                scopes: vec!["openid".to_string()],
                requested_token_type: String::new(),
                cache_ttl_seconds: 300,
                audience_overrides: service_audiences
                    .iter()
                    .map(
                        |(host, audience)| ProviderCredentialTokenGrantAudienceOverride {
                            host: (*host).to_string(),
                            port: 80,
                            path: String::new(),
                            audience: (*audience).to_string(),
                            scopes: vec![(*audience).to_string()],
                        },
                    )
                    .collect(),
            }),
        };
        let profile = ProviderProfile {
            id: "keycloak-sso".to_string(),
            resource_version: 0,
            annotations: HashMap::new(),
            display_name: "Keycloak SSO".to_string(),
            description: String::new(),
            category: ProviderProfileCategory::Other as i32,
            credentials: vec![credential],
            endpoints: service_audiences
                .iter()
                .map(|(host, _)| NetworkEndpoint {
                    host: (*host).to_string(),
                    port: 80,
                    ..Default::default()
                })
                .collect(),
            binaries: Vec::new(),
            inference_capable: false,
            discovery: None,
            source: String::new(),
            scope: String::new(),
        };

        let mut dynamic_creds = HashMap::new();
        insert_dynamic_credentials_for_profile(&mut dynamic_creds, &profile, "keycloak");

        assert_eq!(dynamic_creds.len(), 4);
        for (host, audience) in service_audiences {
            let key = dynamic_credential_key(host, 80, "", "keycloak", "access_token");
            let grant = dynamic_creds[&key].token_grant.as_ref().unwrap();
            assert_eq!(grant.audience, audience);
            assert_eq!(grant.scopes, vec![audience.to_string()]);
            assert!(grant.audience_overrides.is_empty());
        }
    }

    async fn import_token_grant_profile(
        state: &Arc<ServerState>,
        id: &str,
        host: &str,
        port: u32,
        path: &str,
    ) {
        let mut profile = custom_profile(id);
        profile.credentials = vec![token_grant_credential("access_token")];
        profile.endpoints = vec![NetworkEndpoint {
            host: host.to_string(),
            port,
            path: path.to_string(),
            protocol: "rest".to_string(),
            access: "full".to_string(),
            ..Default::default()
        }];
        handle_import_provider_profiles(
            state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(profile),
                    source: format!("{id}.yaml"),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();
    }

    async fn create_empty_token_grant_provider(
        store: &Store,
        name: &str,
        provider_type: &str,
    ) -> Provider {
        create_provider_record(
            store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: name.to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: provider_type.to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn dynamic_token_grants_reject_equal_specificity_overlap() {
        let state = test_server_state().await;
        let store = state.store.as_ref();
        import_token_grant_profile(&state, "grant-a", "api.example.com", 443, "/v1/**").await;
        import_token_grant_profile(&state, "grant-b", "api.example.com", 443, "/v1/**").await;
        create_empty_token_grant_provider(store, "provider-a", "grant-a").await;
        create_empty_token_grant_provider(store, "provider-b", "grant-b").await;

        let err = validate_provider_environment_keys_unique(
            store,
            "default",
            &["provider-a".to_string(), "provider-b".to_string()],
        )
        .await
        .expect_err("equal-specificity dynamic grants should be ambiguous");

        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("dynamic token grants"));
        assert!(err.message().contains("ambiguous"));
    }

    #[tokio::test]
    async fn dynamic_token_grants_allow_more_specific_path_overlap() {
        let state = test_server_state().await;
        let store = state.store.as_ref();
        import_token_grant_profile(&state, "grant-default", "api.example.com", 443, "/v1/**").await;
        import_token_grant_profile(
            &state,
            "grant-admin",
            "api.example.com",
            443,
            "/v1/admin/**",
        )
        .await;
        create_empty_token_grant_provider(store, "provider-default", "grant-default").await;
        create_empty_token_grant_provider(store, "provider-admin", "grant-admin").await;

        validate_provider_environment_keys_unique(
            store,
            "default",
            &["provider-default".to_string(), "provider-admin".to_string()],
        )
        .await
        .expect("more-specific path should make dynamic grants deterministic");
    }

    #[tokio::test]
    async fn import_provider_profile_rejects_attached_dynamic_binding_ambiguity() {
        let state = test_server_state().await;
        let store = state.store.as_ref();
        import_token_grant_profile(&state, "grant-existing", "api.example.com", 443, "/v1/**")
            .await;
        create_empty_token_grant_provider(store, "provider-existing", "grant-existing").await;
        create_provider_record(
            store,
            "default",
            provider_with_values("provider-candidate", "grant-new"),
        )
        .await
        .unwrap();
        store
            .put_message(&Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "sandbox-import-ambiguity-id".to_string(),
                    name: "sandbox-import-ambiguity".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                spec: Some(SandboxSpec {
                    providers: vec![
                        "provider-existing".to_string(),
                        "provider-candidate".to_string(),
                    ],
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();

        let mut profile = custom_profile("grant-new");
        profile.credentials = vec![token_grant_credential("access_token")];
        profile.endpoints = vec![NetworkEndpoint {
            host: "api.example.com".to_string(),
            port: 443,
            path: "/v1/**".to_string(),
            protocol: "rest".to_string(),
            access: "full".to_string(),
            ..Default::default()
        }];
        let response = handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(profile),
                    source: "grant-new.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(!response.imported);
        assert!(response.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("import would create ambiguous dynamic token grants")
        }));
    }

    #[tokio::test]
    async fn import_provider_profile_waits_for_sandbox_sync_guard() {
        let state = test_server_state().await;
        let guard = state.compute.sandbox_sync_guard().await;
        let task_state = state.clone();
        let task = tokio::spawn(async move {
            handle_import_provider_profiles(
                &task_state,
                authed_request(ImportProviderProfilesRequest {
                    profiles: vec![ProviderProfileImportItem {
                        profile: Some(custom_profile("guarded-import")),
                        source: "guarded-import.yaml".to_string(),
                    }],
                    workspace: "default".to_string(),
                }),
            )
            .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !task.is_finished(),
            "profile import should wait for sandbox sync guard"
        );
        drop(guard);

        let response = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("import should finish after guard release")
            .expect("join import task")
            .expect("import should succeed")
            .into_inner();
        assert!(response.imported);
    }

    #[tokio::test]
    async fn update_provider_profile_replaces_custom_profile_and_preserves_metadata() {
        let state = test_server_state().await;
        let mut original = custom_profile("custom-api");
        original.display_name = "Original API".to_string();
        let mut stored = stored_provider_profile(original);
        stored.metadata.as_mut().unwrap().labels =
            HashMap::from([("team".to_string(), "platform".to_string())]);
        state.store.put_message(&stored).await.unwrap();
        let before: StoredProviderProfile = state
            .store
            .get_message_by_name("default", "custom-api")
            .await
            .unwrap()
            .unwrap();

        let mut updated_profile = custom_profile("custom-api");
        updated_profile.resource_version = before.metadata.as_ref().unwrap().resource_version;
        updated_profile.display_name = "Updated API".to_string();
        updated_profile.endpoints = vec![NetworkEndpoint {
            host: "api.updated.example".to_string(),
            port: 443,
            ..Default::default()
        }];
        let response = handle_update_provider_profiles(
            &state,
            authed_request(UpdateProviderProfilesRequest {
                profile: Some(ProviderProfileImportItem {
                    profile: Some(updated_profile.clone()),
                    source: "custom-api.yaml".to_string(),
                }),
                expected_resource_version: 0,
                id: "custom-api".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(response.updated);
        assert_eq!(response.profile.as_ref().unwrap().id, updated_profile.id);
        assert_eq!(
            response.profile.as_ref().unwrap().display_name,
            updated_profile.display_name
        );
        let after: StoredProviderProfile = state
            .store
            .get_message_by_name("default", "custom-api")
            .await
            .unwrap()
            .unwrap();
        let before_meta = before.metadata.unwrap();
        let after_meta = after.metadata.unwrap();
        assert_eq!(after_meta.id, before_meta.id);
        assert_eq!(after_meta.name, before_meta.name);
        assert_eq!(after_meta.created_at_ms, before_meta.created_at_ms);
        assert_eq!(after_meta.labels, before_meta.labels);
        assert!(after_meta.resource_version > before_meta.resource_version);
        assert_eq!(
            after.profile.unwrap().endpoints[0].host,
            "api.updated.example"
        );
    }

    #[tokio::test]
    async fn update_provider_profile_rejects_built_in_and_missing_profiles() {
        let state = test_server_state().await;

        let built_in = handle_update_provider_profiles(
            &state,
            authed_request(UpdateProviderProfilesRequest {
                profile: Some(ProviderProfileImportItem {
                    profile: Some(custom_profile("github")),
                    source: "github.yaml".to_string(),
                }),
                expected_resource_version: 0,
                id: "github".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(!built_in.updated);
        assert!(built_in.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("managed by source 'builtin' and cannot be updated")
        }));

        let missing = handle_update_provider_profiles(
            &state,
            authed_request(UpdateProviderProfilesRequest {
                profile: Some(ProviderProfileImportItem {
                    profile: Some(custom_profile("missing-custom")),
                    source: "missing-custom.yaml".to_string(),
                }),
                expected_resource_version: 0,
                id: "missing-custom".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(!missing.updated);
        assert!(missing.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("custom provider profile 'missing-custom' does not exist")
        }));
    }

    #[tokio::test]
    async fn update_provider_profile_requires_current_resource_version() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&stored_provider_profile(custom_profile("custom-api")))
            .await
            .unwrap();

        let missing_version = handle_update_provider_profiles(
            &state,
            authed_request(UpdateProviderProfilesRequest {
                profile: Some(ProviderProfileImportItem {
                    profile: Some(custom_profile("custom-api")),
                    source: "custom-api.yaml".to_string(),
                }),
                expected_resource_version: 0,
                id: "custom-api".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(!missing_version.updated);
        assert!(missing_version.diagnostics.iter().any(|diagnostic| {
            diagnostic.field == "resource_version"
                && diagnostic.message.contains("non-zero resource_version")
        }));

        let mut stale_profile = custom_profile("custom-api");
        stale_profile.resource_version = 99;
        let stale_error = handle_update_provider_profiles(
            &state,
            authed_request(UpdateProviderProfilesRequest {
                profile: Some(ProviderProfileImportItem {
                    profile: Some(stale_profile),
                    source: "custom-api.yaml".to_string(),
                }),
                expected_resource_version: 0,
                id: "custom-api".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(stale_error.code(), Code::Aborted);
        assert!(stale_error.message().contains("resource_version"));
    }

    #[tokio::test]
    async fn update_provider_profile_rejects_payload_id_change() {
        let state = test_server_state().await;
        let mut profile_a = custom_profile("profile-a");
        profile_a.display_name = "Profile A".to_string();
        let mut profile_b = custom_profile("profile-b");
        profile_b.display_name = "Profile B".to_string();
        state
            .store
            .put_message(&stored_provider_profile(profile_a))
            .await
            .unwrap();
        state
            .store
            .put_message(&stored_provider_profile(profile_b))
            .await
            .unwrap();
        let profile_a_version = state
            .store
            .get_message_by_name::<StoredProviderProfile>("default", "profile-a")
            .await
            .unwrap()
            .unwrap()
            .metadata
            .as_ref()
            .unwrap()
            .resource_version;

        let mut edited_payload = custom_profile("profile-b");
        edited_payload.resource_version = profile_a_version;
        edited_payload.display_name = "Wrong overwrite".to_string();
        let response = handle_update_provider_profiles(
            &state,
            authed_request(UpdateProviderProfilesRequest {
                profile: Some(ProviderProfileImportItem {
                    profile: Some(edited_payload),
                    source: "profile-a.yaml".to_string(),
                }),
                expected_resource_version: 0,
                id: "profile-a".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(!response.updated);
        assert!(response.diagnostics.iter().any(|diagnostic| {
            diagnostic.field == "id"
                && diagnostic
                    .message
                    .contains("does not match payload id 'profile-b'")
        }));
        let stored_b: StoredProviderProfile = state
            .store
            .get_message_by_name("default", "profile-b")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_b.profile.unwrap().display_name, "Profile B");
    }

    #[tokio::test]
    async fn update_provider_profile_rejects_attached_dynamic_binding_ambiguity() {
        let state = test_server_state().await;
        let store = state.store.as_ref();
        import_token_grant_profile(&state, "grant-existing", "api.example.com", 443, "/v1/**")
            .await;
        import_token_grant_profile(&state, "grant-updated", "api.example.com", 443, "/v2/**").await;
        create_empty_token_grant_provider(store, "provider-existing", "grant-existing").await;
        create_empty_token_grant_provider(store, "provider-updated", "grant-updated").await;
        store
            .put_message(&Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "sandbox-update-ambiguity-id".to_string(),
                    name: "sandbox-update-ambiguity".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                spec: Some(SandboxSpec {
                    providers: vec![
                        "provider-existing".to_string(),
                        "provider-updated".to_string(),
                    ],
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();

        let mut profile = custom_profile("grant-updated");
        profile.resource_version = store
            .get_message_by_name::<StoredProviderProfile>("default", "grant-updated")
            .await
            .unwrap()
            .unwrap()
            .metadata
            .as_ref()
            .unwrap()
            .resource_version;
        profile.credentials = vec![token_grant_credential("access_token")];
        profile.endpoints = vec![NetworkEndpoint {
            host: "api.example.com".to_string(),
            port: 443,
            path: "/v1/**".to_string(),
            protocol: "rest".to_string(),
            access: "full".to_string(),
            ..Default::default()
        }];
        let response = handle_update_provider_profiles(
            &state,
            authed_request(UpdateProviderProfilesRequest {
                profile: Some(ProviderProfileImportItem {
                    profile: Some(profile),
                    source: "grant-updated.yaml".to_string(),
                }),
                expected_resource_version: 0,
                id: "grant-updated".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(!response.updated);
        assert!(response.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("update would create ambiguous dynamic token grants")
        }));
    }

    fn provider_with_values(name: &str, provider_type: &str) -> Provider {
        Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: name.to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: provider_type.to_string(),
            credentials: [
                ("API_TOKEN".to_string(), "token-123".to_string()),
                ("SECONDARY".to_string(), "secondary-token".to_string()),
            ]
            .into_iter()
            .collect(),
            config: [
                ("endpoint".to_string(), "https://example.com".to_string()),
                ("region".to_string(), "us-west".to_string()),
            ]
            .into_iter()
            .collect(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        }
    }

    fn provider_with_credential_handle(
        name: &str,
        provider_type: &str,
        credential_key: &str,
    ) -> Provider {
        Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: name.to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                ..Default::default()
            }),
            r#type: provider_type.to_string(),
            credentials: HashMap::new(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: "default".to_string(),
            credential_handles: std::iter::once((
                credential_key.to_string(),
                CredentialHandle {
                    driver: "test-static".to_string(),
                    handle: format!("{name}:{credential_key}"),
                    metadata: HashMap::new(),
                },
            ))
            .collect(),
        }
    }

    fn provider_with_credential_value(
        name: &str,
        provider_type: &str,
        credential_key: &str,
        value: &str,
    ) -> Provider {
        Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: name.to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                ..Default::default()
            }),
            r#type: provider_type.to_string(),
            credentials: std::iter::once((credential_key.to_string(), value.to_string())).collect(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        }
    }

    fn custom_profile(id: &str) -> ProviderProfile {
        ProviderProfile {
            id: id.to_string(),
            resource_version: 0,
            annotations: HashMap::new(),
            display_name: format!("{id} Profile"),
            description: String::new(),
            category: ProviderProfileCategory::Other as i32,
            credentials: Vec::new(),
            endpoints: Vec::new(),
            binaries: Vec::new(),
            inference_capable: false,
            discovery: None,
            source: String::new(),
            scope: String::new(),
        }
    }

    fn custom_profile_with_invalid_endpoint(id: &str) -> ProviderProfile {
        let mut profile = custom_profile(id);
        profile.endpoints.push(NetworkEndpoint {
            host: String::new(),
            port: 0,
            ..Default::default()
        });
        profile
    }

    fn refreshable_credential(name: &str, env_var: &str) -> ProviderProfileCredential {
        ProviderProfileCredential {
            name: name.to_string(),
            description: String::new(),
            env_vars: vec![env_var.to_string()],
            required: true,
            auth_style: "bearer".to_string(),
            header_name: "authorization".to_string(),
            query_param: String::new(),
            path_template: String::new(),
            refresh: Some(ProviderCredentialRefresh {
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
                token_url: "https://auth.example.com/token".to_string(),
                scopes: Vec::new(),
                refresh_before_seconds: 300,
                max_lifetime_seconds: 3600,
                additional_outputs: Vec::new(),
                material: vec![
                    ProviderCredentialRefreshMaterial {
                        name: "client_id".to_string(),
                        description: String::new(),
                        required: true,
                        secret: false,
                    },
                    ProviderCredentialRefreshMaterial {
                        name: "client_secret".to_string(),
                        description: String::new(),
                        required: true,
                        secret: true,
                    },
                ],
            }),
            token_grant: None,
        }
    }

    async fn import_test_refresh_profile(state: &Arc<ServerState>, id: &str, credential_key: &str) {
        let mut profile = custom_profile(id);
        profile.category = ProviderProfileCategory::Messaging as i32;
        profile.credentials = vec![refreshable_credential("access_token", credential_key)];
        handle_import_provider_profiles(
            state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(profile),
                    source: format!("{id}.yaml"),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();
    }

    const TEST_GRAPH_PROVIDER_TYPE: &str = "test-msgraph";

    async fn import_test_graph_refresh_profile(state: &Arc<ServerState>) {
        import_test_refresh_profile(state, TEST_GRAPH_PROVIDER_TYPE, "MS_GRAPH_ACCESS_TOKEN").await;
    }

    fn static_credential(name: &str, env_var: &str, required: bool) -> ProviderProfileCredential {
        ProviderProfileCredential {
            name: name.to_string(),
            description: String::new(),
            env_vars: vec![env_var.to_string()],
            required,
            auth_style: "bearer".to_string(),
            header_name: "authorization".to_string(),
            query_param: String::new(),
            refresh: None,
            path_template: String::new(),
            token_grant: None,
        }
    }

    fn token_grant_credential(name: &str) -> ProviderProfileCredential {
        ProviderProfileCredential {
            name: name.to_string(),
            description: String::new(),
            env_vars: Vec::new(),
            required: true,
            auth_style: "bearer".to_string(),
            header_name: "authorization".to_string(),
            query_param: String::new(),
            refresh: None,
            path_template: String::new(),
            token_grant: Some(ProviderCredentialTokenGrant {
                grant_type: ProviderCredentialTokenGrantType::ClientCredentials as i32,
                token_endpoint: "https://auth.example.com/token".to_string(),
                audience: "api://default".to_string(),
                jwt_svid_audience: "https://auth.example.com".to_string(),
                client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    .to_string(),
                subject_token: None,
                scopes: vec!["read".to_string()],
                requested_token_type: String::new(),
                cache_ttl_seconds: 300,
                audience_overrides: Vec::new(),
            }),
        }
    }

    #[tokio::test]
    async fn list_provider_profiles_returns_built_in_profile_categories() {
        let state = test_server_state().await;
        let response = handle_list_provider_profiles(
            &state,
            authed_request(ListProviderProfilesRequest {
                limit: 100,
                offset: 0,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        let ids = response
            .profiles
            .iter()
            .map(|profile| profile.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                "anthropic",
                "aws",
                "aws-bedrock",
                "aws-s3",
                "claude-code",
                "codex",
                "copilot",
                "cursor",
                "deepinfra",
                "github",
                "google-cloud",
                "google-vertex-ai",
                "nvidia",
                "openai",
                "pypi"
            ]
        );

        let github = response
            .profiles
            .iter()
            .find(|profile| profile.id == "github")
            .expect("github profile should be listed");
        assert_eq!(
            github.category,
            ProviderProfileCategory::SourceControl as i32
        );
    }

    #[tokio::test]
    async fn get_provider_profile_returns_profile_or_not_found() {
        let state = test_server_state().await;
        let github = handle_get_provider_profile(
            &state,
            authed_request(GetProviderProfileRequest {
                id: "github".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .profile
        .expect("github profile should be returned");
        assert_eq!(github.id, "github");
        assert_eq!(
            github.category,
            ProviderProfileCategory::SourceControl as i32
        );

        let generic_err = handle_get_provider_profile(
            &state,
            authed_request(GetProviderProfileRequest {
                id: "generic".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(generic_err.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn import_provider_profile_lists_and_gets_custom_profile() {
        let state = test_server_state().await;
        let response = handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("custom-api")),
                    source: "custom-api.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(response.imported);
        assert!(response.diagnostics.is_empty());

        let listed = handle_list_provider_profiles(
            &state,
            authed_request(ListProviderProfilesRequest {
                limit: 100,
                offset: 0,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(
            listed
                .profiles
                .iter()
                .any(|profile| profile.id == "custom-api")
        );

        let fetched = handle_get_provider_profile(
            &state,
            authed_request(GetProviderProfileRequest {
                id: "custom-api".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .profile
        .unwrap();
        assert_eq!(fetched.id, "custom-api");
    }

    #[tokio::test]
    async fn profile_update_rejects_fanout_endpoint_ambiguity_without_persisting() {
        let state = test_server_state().await;

        let mut initial_profile = custom_profile("fanout-ambiguity");
        initial_profile.endpoints.push(NetworkEndpoint {
            host: "other.example.com".to_string(),
            port: 443,
            ..Default::default()
        });
        let imported = handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(initial_profile),
                    source: "fanout.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(imported.imported);
        let resource_version = imported.profiles[0].resource_version;

        create_provider_record(
            state.store.as_ref(),
            "default",
            provider_with_values("fanout-provider", "fanout-ambiguity"),
        )
        .await
        .unwrap();
        state
            .store
            .put_message(&Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "fanout-sandbox-id".to_string(),
                    name: "fanout-sandbox".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                spec: Some(SandboxSpec {
                    providers: vec!["fanout-provider".to_string()],
                    policy: Some(SandboxPolicy {
                        network_policies: HashMap::from([(
                            "base".to_string(),
                            NetworkPolicyRule {
                                name: "base".to_string(),
                                endpoints: vec![NetworkEndpoint {
                                    host: "api.example.com".to_string(),
                                    port: 443,
                                    ..Default::default()
                                }],
                                ..Default::default()
                            },
                        )]),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();

        let mut conflicting_profile = custom_profile("fanout-ambiguity");
        conflicting_profile.resource_version = resource_version;
        conflicting_profile.endpoints.push(NetworkEndpoint {
            host: "api.example.com".to_string(),
            port: 443,
            tls: "skip".to_string(),
            ..Default::default()
        });
        let response = handle_update_provider_profiles(
            &state,
            authed_request(UpdateProviderProfilesRequest {
                profile: Some(ProviderProfileImportItem {
                    profile: Some(conflicting_profile),
                    source: "fanout.yaml".to_string(),
                }),
                expected_resource_version: resource_version,
                id: "fanout-ambiguity".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(!response.updated);
        assert!(response.diagnostics.iter().any(|diagnostic| {
            diagnostic.field == "endpoints"
                && diagnostic.message.contains("fanout-sandbox")
                && diagnostic.message.contains("tls")
        }));
        let stored = handle_get_provider_profile(
            &state,
            authed_request(GetProviderProfileRequest {
                id: "fanout-ambiguity".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .profile
        .unwrap();
        assert_eq!(stored.endpoints[0].host, "other.example.com");
    }

    #[tokio::test]
    async fn import_provider_profile_rejects_builtin_overwrite() {
        let state = test_server_state().await;
        let response = handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("github")),
                    source: "github.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(!response.imported);
        assert!(
            response
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("managed by source 'builtin'"))
        );
    }

    #[tokio::test]
    async fn import_provider_profile_allows_legacy_provider_type_ids_without_built_in_profiles() {
        // Use an ID that is not a built-in profile to test legacy import.
        // "custom-llm" is not registered as a built-in and never will be.
        let state = test_server_state().await;
        let response = handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("custom-llm")),
                    source: "custom-llm.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(response.imported);
        assert!(response.diagnostics.is_empty());

        let imported = handle_get_provider_profile(
            &state,
            authed_request(GetProviderProfileRequest {
                id: "custom-llm".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .profile
        .expect("custom-llm profile should be returned");
        assert_eq!(imported.id, "custom-llm");
    }

    #[tokio::test]
    async fn import_provider_profile_rejects_noncanonical_ids() {
        let state = test_server_state().await;
        let response = handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![
                    ProviderProfileImportItem {
                        profile: Some(custom_profile(" alex-api ")),
                        source: "space.yaml".to_string(),
                    },
                    ProviderProfileImportItem {
                        profile: Some(custom_profile("alex_api")),
                        source: "underscore.yaml".to_string(),
                    },
                    ProviderProfileImportItem {
                        profile: Some(custom_profile("Alex-API")),
                        source: "case.yaml".to_string(),
                    },
                ],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(!response.imported);
        assert_eq!(
            response
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.message.contains("lowercase kebab-case"))
                .count(),
            3
        );
    }

    #[tokio::test]
    async fn provider_profile_get_and_delete_normalize_request_ids() {
        let state = test_server_state().await;
        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("alex-api")),
                    source: "alex-api.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let fetched = handle_get_provider_profile(
            &state,
            authed_request(GetProviderProfileRequest {
                id: " Alex-API ".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .profile
        .unwrap();
        assert_eq!(fetched.id, "alex-api");

        let deleted = handle_delete_provider_profile(
            &state,
            authed_request(DeleteProviderProfileRequest {
                id: " Alex-API ".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(deleted.deleted);
        assert_eq!(state.credentials.stored_credential_count(), Some(0));
    }

    #[tokio::test]
    async fn import_provider_profiles_rejects_mixed_batch_without_partial_import() {
        let state = test_server_state().await;
        let response = handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![
                    ProviderProfileImportItem {
                        profile: Some(custom_profile("bulk-one")),
                        source: "bulk-one.yaml".to_string(),
                    },
                    ProviderProfileImportItem {
                        profile: Some(custom_profile_with_invalid_endpoint("bulk-bad")),
                        source: "bulk-bad.yaml".to_string(),
                    },
                    ProviderProfileImportItem {
                        profile: Some(custom_profile("bulk-two")),
                        source: "bulk-two.yaml".to_string(),
                    },
                ],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(!response.imported);
        assert!(response.profiles.is_empty());
        assert!(response.diagnostics.iter().any(|diagnostic| {
            diagnostic.profile_id == "bulk-bad"
                && diagnostic.field == "endpoints[0]"
                && diagnostic.message.contains("invalid endpoint")
        }));

        for id in ["bulk-one", "bulk-two"] {
            let missing = handle_get_provider_profile(
                &state,
                authed_request(GetProviderProfileRequest {
                    id: id.to_string(),
                    workspace: "default".to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(missing.code(), Code::NotFound);
        }
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn import_provider_profiles_preserves_advanced_proto_policy_fields() {
        let state = test_server_state().await;
        let response = handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(ProviderProfile {
                        id: "advanced-api".to_string(),
                        resource_version: 0,
                        annotations: HashMap::new(),
                        display_name: "Advanced API".to_string(),
                        description: String::new(),
                        category: ProviderProfileCategory::Other as i32,
                        credentials: Vec::new(),
                        endpoints: vec![NetworkEndpoint {
                            host: "api.advanced.example".to_string(),
                            protocol: "rest".to_string(),
                            ports: vec![443, 8443],
                            allowed_ips: vec!["10.0.0.0/24".to_string()],
                            rules: vec![L7Rule {
                                allow: Some(L7Allow {
                                    method: "GET".to_string(),
                                    path: "/v1/**".to_string(),
                                    ..Default::default()
                                }),
                            }],
                            allow_encoded_slash: true,
                            path: "/v1".to_string(),
                            ..Default::default()
                        }],
                        binaries: vec![NetworkBinary {
                            path: "/usr/bin/advanced".to_string(),
                            harness: true,
                        }],
                        inference_capable: false,
                        discovery: None,
                        source: String::new(),
                        scope: String::new(),
                    }),
                    source: "advanced-api.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(response.imported);

        let fetched = handle_get_provider_profile(
            &state,
            authed_request(GetProviderProfileRequest {
                id: "advanced-api".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .profile
        .expect("profile should exist");
        let endpoint = fetched.endpoints.first().expect("endpoint should exist");
        assert_eq!(endpoint.ports, vec![443, 8443]);
        assert_eq!(endpoint.allowed_ips, vec!["10.0.0.0/24"]);
        assert_eq!(endpoint.rules.len(), 1);
        assert_eq!(
            endpoint.rules[0]
                .allow
                .as_ref()
                .map(|allow| allow.path.as_str()),
            Some("/v1/**")
        );
        assert!(endpoint.allow_encoded_slash);
        assert_eq!(endpoint.path, "/v1");
        assert!(fetched.binaries[0].harness);
    }

    #[tokio::test]
    async fn lint_provider_profiles_reports_mixed_batch_diagnostics() {
        let state = test_server_state().await;
        let response = handle_lint_provider_profiles(
            &state,
            authed_request(LintProviderProfilesRequest {
                profiles: vec![
                    ProviderProfileImportItem {
                        profile: Some(custom_profile("lint-one")),
                        source: "lint-one.yaml".to_string(),
                    },
                    ProviderProfileImportItem {
                        profile: Some(custom_profile_with_invalid_endpoint("lint-bad")),
                        source: "lint-bad.yaml".to_string(),
                    },
                    ProviderProfileImportItem {
                        profile: Some(custom_profile("lint-two")),
                        source: "lint-two.yaml".to_string(),
                    },
                ],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(!response.valid);
        assert!(response.diagnostics.iter().any(|diagnostic| {
            diagnostic.profile_id == "lint-bad"
                && diagnostic.field == "endpoints[0]"
                && diagnostic.message.contains("invalid endpoint")
        }));

        for id in ["lint-one", "lint-two"] {
            let missing = handle_get_provider_profile(
                &state,
                authed_request(GetProviderProfileRequest {
                    id: id.to_string(),
                    workspace: "default".to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(missing.code(), Code::NotFound);
        }
    }

    #[tokio::test]
    async fn lint_provider_profiles_checks_conflicts_in_request_workspace() {
        let state = test_server_state().await;

        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("scoped-lint")),
                    source: "scoped-lint.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let conflict = handle_lint_provider_profiles(
            &state,
            authed_request(LintProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("scoped-lint")),
                    source: "scoped-lint.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(
            !conflict.valid,
            "lint should detect conflict with existing profile in the same workspace"
        );
        assert!(
            conflict
                .diagnostics
                .iter()
                .any(|d| { d.profile_id == "scoped-lint" && d.message.contains("already exists") })
        );

        crate::grpc::workspace::handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                name: "alpha".to_string(),
                labels: HashMap::new(),
            }),
        )
        .await
        .unwrap();

        let no_conflict = handle_lint_provider_profiles(
            &state,
            authed_request(LintProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("scoped-lint")),
                    source: "scoped-lint.yaml".to_string(),
                }],
                workspace: "alpha".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(
            no_conflict
                .diagnostics
                .iter()
                .all(|d| d.profile_id != "scoped-lint" || !d.message.contains("already exists")),
            "lint against different workspace should not see profile from default"
        );
    }

    #[tokio::test]
    async fn delete_provider_profile_rejects_builtin_and_provider_referenced_profiles() {
        let state = test_server_state().await;
        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("custom-api")),
                    source: "custom-api.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let builtin_err = handle_delete_provider_profile(
            &state,
            authed_request(DeleteProviderProfileRequest {
                id: "github".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(builtin_err.code(), Code::FailedPrecondition);

        create_provider_record(
            state.store.as_ref(),
            "default",
            provider_with_values("custom-provider", "custom-api"),
        )
        .await
        .unwrap();
        state
            .store
            .put_message(&Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "sandbox-id".to_string(),
                    name: "sandbox-custom".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                spec: Some(SandboxSpec {
                    providers: Vec::new(),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();

        let in_use_err = handle_delete_provider_profile(
            &state,
            authed_request(DeleteProviderProfileRequest {
                id: "custom-api".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(in_use_err.code(), Code::FailedPrecondition);
        assert!(in_use_err.message().contains("custom-provider"));

        let attached = super::super::sandbox::handle_attach_sandbox_provider(
            &state,
            authed_request(AttachSandboxProviderRequest {
                sandbox_name: "sandbox-custom".to_string(),
                provider_name: "custom-provider".to_string(),
                expected_resource_version: 0,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(attached.attached);
    }

    #[tokio::test]
    async fn delete_global_provider_profile_checks_providers_in_every_workspace() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&stored_provider_profile_for_workspace(
                custom_profile("global-custom"),
                "",
            ))
            .await
            .unwrap();
        let catalog = state
            .provider_profile_sources
            .snapshot_catalog(state.store.as_ref(), "default")
            .await
            .unwrap();
        let mut provider = provider_with_values("global-provider", "global-custom");
        provider.profile_workspace = String::new();
        create_provider_record_with_catalog(state.store.as_ref(), &catalog, "default", provider)
            .await
            .unwrap();

        let err = handle_delete_provider_profile(
            &state,
            authed_request(DeleteProviderProfileRequest {
                id: "global-custom".to_string(),
                workspace: String::new(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("default/global-provider"));
    }

    #[tokio::test]
    async fn configure_provider_refresh_stores_scoped_status_and_provider_expiry() {
        let state = test_server_state().await;
        import_test_graph_refresh_profile(&state).await;
        create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "msgraph".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: TEST_GRAPH_PROVIDER_TYPE.to_string(),
                credentials: std::iter::once((
                    "MS_GRAPH_ACCESS_TOKEN".to_string(),
                    "token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let expires_at_ms = crate::persistence::current_time_ms() + 60_000;
        let response = handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "msgraph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
                material: HashMap::from([
                    ("tenant_id".to_string(), "tenant".to_string()),
                    ("client_id".to_string(), "client-id".to_string()),
                    ("client_secret".to_string(), "client-secret".to_string()),
                ]),
                // The server derives sensitivity from the authoritative
                // profile; direct callers cannot opt a client secret out of
                // credential storage by omitting this advisory list.
                secret_material_keys: Vec::new(),
                expires_at_ms: Some(expires_at_ms),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .status
        .expect("status");
        assert_eq!(response.credential_key, "MS_GRAPH_ACCESS_TOKEN");

        let status = handle_get_provider_refresh_status(
            &state,
            authed_request(GetProviderRefreshStatusRequest {
                provider: "msgraph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(status.credentials.len(), 1);
        assert_eq!(status.credentials[0].expires_at_ms, expires_at_ms);

        let provider = state
            .store
            .get_message_by_name::<Provider>("default", "msgraph")
            .await
            .unwrap()
            .expect("provider");
        assert_eq!(
            provider
                .credential_expires_at_ms
                .get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&expires_at_ms)
        );

        let first_refresh = crate::provider_refresh::get_refresh_state(
            state.store.as_ref(),
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .expect("first refresh state");
        assert!(!first_refresh.material.contains_key("client_secret"));
        assert!(
            first_refresh
                .secret_material_handles
                .contains_key("client_secret")
        );
        assert_eq!(
            state
                .credentials
                .resolve_refresh_material(
                    RefreshMaterialScope {
                        provider_name: &first_refresh.provider_name,
                        workspace: first_refresh.object_workspace(),
                        provider_id: &first_refresh.provider_id,
                        credential_key: &first_refresh.credential_key,
                    },
                    &first_refresh.secret_material_handles,
                )
                .await
                .unwrap()
                .get("client_secret"),
            Some(&"client-secret".to_string())
        );
        handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "msgraph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
                material: HashMap::from([
                    ("tenant_id".to_string(), "tenant".to_string()),
                    ("client_id".to_string(), "client-id".to_string()),
                    ("client_secret".to_string(), "client-secret".to_string()),
                ]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: Some(expires_at_ms),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();
        let second_refresh = crate::provider_refresh::get_refresh_state(
            state.store.as_ref(),
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .expect("reconfigured refresh state");
        assert_eq!(first_refresh.object_id(), second_refresh.object_id());
        assert_ne!(
            first_refresh.authorization_epoch, second_refresh.authorization_epoch,
            "every explicit configuration starts a new authorization epoch"
        );

        let deleted = handle_delete_provider_refresh(
            &state,
            authed_request(DeleteProviderRefreshRequest {
                provider: "msgraph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(deleted.deleted);
        assert_eq!(state.credentials.stored_credential_count(), Some(0));

        let status_after_delete = handle_get_provider_refresh_status(
            &state,
            authed_request(GetProviderRefreshStatusRequest {
                provider: "msgraph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(status_after_delete.credentials.is_empty());

        let provider_after_delete = state
            .store
            .get_message_by_name::<Provider>("default", "msgraph")
            .await
            .unwrap()
            .expect("provider");
        assert!(
            !provider_after_delete
                .credential_expires_at_ms
                .contains_key("MS_GRAPH_ACCESS_TOKEN")
        );
    }

    #[tokio::test]
    async fn configure_provider_refresh_conflict_cleans_only_staged_material() {
        let state = test_server_state().await;
        import_test_graph_refresh_profile(&state).await;
        create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    name: "configure-conflict".to_string(),
                    workspace: "default".to_string(),
                    ..Default::default()
                }),
                r#type: TEST_GRAPH_PROVIDER_TYPE.to_string(),
                profile_workspace: "default".to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let request = |client_secret: &str| ConfigureProviderRefreshRequest {
            provider: "configure-conflict".to_string(),
            credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
            strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
            material: HashMap::from([
                ("tenant_id".to_string(), "tenant".to_string()),
                ("client_id".to_string(), "client-id".to_string()),
                ("client_secret".to_string(), client_secret.to_string()),
            ]),
            secret_material_keys: vec!["client_secret".to_string()],
            expires_at_ms: None,
            workspace: "default".to_string(),
        };
        handle_configure_provider_refresh(&state, authed_request(request("original-secret")))
            .await
            .unwrap();
        let provider = state
            .store
            .get_message_by_name::<Provider>("default", "configure-conflict")
            .await
            .unwrap()
            .unwrap();
        let original = crate::provider_refresh::get_refresh_state(
            state.store.as_ref(),
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(state.credentials.stored_credential_count(), Some(1));
        let (store_hit, release_store) = state.credentials.gate_next_store();

        let configure = handle_configure_provider_refresh(
            &state,
            authed_request(request("replacement-secret")),
        );
        let supersede = async {
            store_hit.await.unwrap();
            let mut winner = crate::provider_refresh::get_refresh_state(
                state.store.as_ref(),
                "default",
                provider.object_id(),
                "MS_GRAPH_ACCESS_TOKEN",
            )
            .await
            .unwrap()
            .unwrap();
            winner.last_error = "won-by-concurrent-writer".to_string();
            crate::provider_refresh::put_refresh_state(state.store.as_ref(), &winner)
                .await
                .unwrap();
            release_store.send(()).unwrap();
        };
        let (result, ()) = tokio::join!(configure, supersede);

        assert_eq!(result.unwrap_err().code(), Code::Aborted);
        assert_eq!(state.credentials.stored_credential_count(), Some(1));
        let stored = crate::provider_refresh::get_refresh_state(
            state.store.as_ref(),
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stored.authorization_epoch, original.authorization_epoch);
        assert_eq!(stored.last_error, "won-by-concurrent-writer");
        assert!(stored.pending_secret_deletions.is_empty());
        assert_eq!(
            state
                .credentials
                .resolve_refresh_material(
                    crate::provider_refresh::refresh_material_scope(&stored),
                    &stored.secret_material_handles,
                )
                .await
                .unwrap()
                .get("client_secret"),
            Some(&"original-secret".to_string())
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_first_refresh_configure_keeps_only_winner_material() {
        let first_state = test_server_state().await;
        import_test_graph_refresh_profile(&first_state).await;
        create_provider_record(
            first_state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    name: "configure-create-race".to_string(),
                    workspace: "default".to_string(),
                    ..Default::default()
                }),
                r#type: TEST_GRAPH_PROVIDER_TYPE.to_string(),
                profile_workspace: "default".to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // Model a second gateway replica: it shares the durable database and
        // credential backend, but owns an independent sandbox synchronization
        // guard, so process-local serialization cannot hide this race.
        let second_state = Arc::new(ServerState::new_with_credentials(
            first_state.config.clone(),
            Arc::clone(&first_state.store),
            crate::compute::new_test_runtime(Arc::clone(&first_state.store)).await,
            crate::sandbox_index::SandboxIndex::new(),
            crate::sandbox_watch::SandboxWatchBus::new(),
            crate::tracing_bus::TracingLogBus::new(),
            Arc::new(crate::supervisor_session::SupervisorSessionRegistry::new()),
            None,
            first_state.credentials.clone(),
        ));
        let request = |client_secret: &str| ConfigureProviderRefreshRequest {
            provider: "configure-create-race".to_string(),
            credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
            strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
            material: HashMap::from([
                ("tenant_id".to_string(), "tenant".to_string()),
                ("client_id".to_string(), "client-id".to_string()),
                ("client_secret".to_string(), client_secret.to_string()),
            ]),
            secret_material_keys: vec!["client_secret".to_string()],
            expires_at_ms: None,
            workspace: "default".to_string(),
        };
        let (first_store_hit, release_first_store) = first_state.credentials.gate_next_store();

        let first = handle_configure_provider_refresh(
            &first_state,
            authed_request(request("loser-secret")),
        );
        let second = async {
            first_store_hit.await.unwrap();
            let result = handle_configure_provider_refresh(
                &second_state,
                authed_request(request("winner-secret")),
            )
            .await;
            release_first_store.send(()).unwrap();
            result
        };
        let (first_result, second_result) = tokio::join!(first, second);

        assert_eq!(first_result.unwrap_err().code(), Code::Aborted);
        second_result.unwrap();
        assert_eq!(first_state.credentials.stored_credential_count(), Some(1));

        let provider = first_state
            .store
            .get_message_by_name::<Provider>("default", "configure-create-race")
            .await
            .unwrap()
            .unwrap();
        let stored = crate::provider_refresh::get_refresh_state(
            first_state.store.as_ref(),
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            first_state
                .credentials
                .resolve_refresh_material(
                    crate::provider_refresh::refresh_material_scope(&stored),
                    &stored.secret_material_handles,
                )
                .await
                .unwrap()
                .get("client_secret"),
            Some(&"winner-secret".to_string())
        );

        let physical = first_state
            .store
            .get_by_name(
                StoredProviderCredentialRefreshState::object_type(),
                "default",
                stored.object_name(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(physical.id, stored.object_id());
        assert_eq!(
            crate::provider_refresh::list_refresh_states_for_provider(
                first_state.store.as_ref(),
                provider.object_id(),
            )
            .await
            .unwrap()
            .len(),
            1
        );
    }

    async fn state_with_authoritative_profiles_over_default_grants() -> Arc<ServerState> {
        let state = test_server_state().await;
        let store = state.store.as_ref();
        import_token_grant_profile(&state, "grant-a", "api.example.com", 443, "/v1/**").await;
        import_token_grant_profile(&state, "grant-b", "api.example.com", 443, "/v1/**").await;
        create_empty_token_grant_provider(store, "provider-a", "grant-a").await;
        create_empty_token_grant_provider(store, "provider-b", "grant-b").await;
        store
            .put_message(&Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "sandbox-authoritative-profiles-id".to_string(),
                    name: "sandbox-authoritative-profiles".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                spec: Some(SandboxSpec {
                    providers: vec!["provider-a".to_string(), "provider-b".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();

        let mut state = Arc::into_inner(state).expect("test server state should be uniquely owned");
        state.provider_profile_sources = ProviderProfileSources::from_test_profiles(vec![
            custom_profile("grant-a"),
            custom_profile("grant-b"),
        ]);
        Arc::new(state)
    }

    #[tokio::test]
    async fn configure_provider_refresh_uses_authoritative_profile_sources_for_expiry_update() {
        let state = state_with_authoritative_profiles_over_default_grants().await;
        let expires_at_ms = crate::persistence::current_time_ms() + 60_000;

        handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "provider-a".to_string(),
                credential_key: "REFRESH_TOKEN".to_string(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
                material: HashMap::new(),
                secret_material_keys: Vec::new(),
                expires_at_ms: Some(expires_at_ms),
                workspace: "default".to_string(),
            }),
        )
        .await
        .expect("authoritative profiles should govern the provider expiry update");

        let provider = state
            .store
            .get_message_by_name::<Provider>("default", "provider-a")
            .await
            .unwrap()
            .expect("provider-a");
        assert_eq!(
            provider.credential_expires_at_ms.get("REFRESH_TOKEN"),
            Some(&expires_at_ms)
        );
    }

    #[tokio::test]
    async fn delete_provider_refresh_uses_authoritative_profile_sources_for_expiry_update() {
        let state = state_with_authoritative_profiles_over_default_grants().await;
        let expires_at_ms = crate::persistence::current_time_ms() + 60_000;
        let updated = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: "provider-a".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: String::new(),
            credentials: HashMap::new(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::from([("REFRESH_TOKEN".to_string(), expires_at_ms)]),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        };
        let catalog = state
            .provider_profile_sources
            .snapshot_catalog(state.store.as_ref(), "default")
            .await
            .unwrap();
        let provider =
            update_provider_record_with_catalog(state.store.as_ref(), &catalog, "default", updated)
                .await
                .unwrap();
        let refresh_state = crate::provider_refresh::new_refresh_state(
            &provider,
            "default",
            "REFRESH_TOKEN",
            crate::provider_refresh::NewRefreshStateConfig {
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
                material: HashMap::new(),
                secret_material_keys: Vec::new(),
                expires_at_ms,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before_seconds: 0,
                max_lifetime_seconds: 0,
                additional_output_keys: HashMap::new(),
            },
        )
        .unwrap();
        crate::provider_refresh::put_refresh_state(state.store.as_ref(), &refresh_state)
            .await
            .unwrap();

        handle_delete_provider_refresh(
            &state,
            authed_request(DeleteProviderRefreshRequest {
                provider: "provider-a".to_string(),
                credential_key: "REFRESH_TOKEN".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .expect("authoritative profiles should govern the provider expiry update");

        let provider = state
            .store
            .get_message_by_name::<Provider>("default", "provider-a")
            .await
            .unwrap()
            .expect("provider-a");
        assert!(
            !provider
                .credential_expires_at_ms
                .contains_key("REFRESH_TOKEN")
        );
    }

    #[tokio::test]
    async fn configure_provider_refresh_accepts_vertex_service_account_token_key() {
        let state = test_server_state().await;
        create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "vertex-sa".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "google-vertex-ai".to_string(),
                credentials: std::iter::once((
                    "GOOGLE_SERVICE_ACCOUNT_KEY".to_string(),
                    "{\"type\":\"service_account\"}".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let response = handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "vertex-sa".to_string(),
                credential_key: "GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN".to_string(),
                strategy: ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt as i32,
                material: HashMap::from([
                    (
                        "client_email".to_string(),
                        "sa@test-project.iam.gserviceaccount.com".to_string(),
                    ),
                    (
                        "private_key".to_string(),
                        "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----".to_string(),
                    ),
                ]),
                secret_material_keys: vec!["private_key".to_string()],
                expires_at_ms: None,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .status
        .expect("status");

        assert_eq!(
            response.credential_key,
            "GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN"
        );
        assert_eq!(
            response.strategy,
            ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt as i32
        );
    }

    #[tokio::test]
    async fn delete_provider_refresh_preserves_manually_updated_expiry() {
        let state = test_server_state().await;
        import_test_graph_refresh_profile(&state).await;
        create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "msgraph".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: TEST_GRAPH_PROVIDER_TYPE.to_string(),
                credentials: std::iter::once((
                    "MS_GRAPH_ACCESS_TOKEN".to_string(),
                    "token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let refresh_expires_at_ms = crate::persistence::current_time_ms() + 60_000;
        handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "msgraph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
                material: HashMap::from([
                    ("tenant_id".to_string(), "tenant".to_string()),
                    ("client_id".to_string(), "client-id".to_string()),
                    ("client_secret".to_string(), "client-secret".to_string()),
                ]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: Some(refresh_expires_at_ms),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let manual_expires_at_ms = refresh_expires_at_ms + 60_000;
        update_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "msgraph".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::from([(
                    "MS_GRAPH_ACCESS_TOKEN".to_string(),
                    manual_expires_at_ms,
                )]),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let deleted = handle_delete_provider_refresh(
            &state,
            authed_request(DeleteProviderRefreshRequest {
                provider: "msgraph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(deleted.deleted);

        let provider_after_delete = state
            .store
            .get_message_by_name::<Provider>("default", "msgraph")
            .await
            .unwrap()
            .expect("provider");
        assert_eq!(
            provider_after_delete
                .credential_expires_at_ms
                .get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&manual_expires_at_ms)
        );
    }

    #[tokio::test]
    async fn delete_aws_sts_refresh_clears_all_pinned_output_expiries() {
        let state = test_server_state().await;
        create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "aws-delete".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "aws".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let refresh_expires_at_ms = crate::persistence::current_time_ms() + 60_000;
        handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "aws-delete".to_string(),
                credential_key: "AWS_ACCESS_KEY_ID".to_string(),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32,
                material: HashMap::from([(
                    "role_arn".to_string(),
                    "arn:aws:iam::123456789012:role/Test".to_string(),
                )]),
                secret_material_keys: Vec::new(),
                expires_at_ms: Some(refresh_expires_at_ms),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        // Simulate a completed mint: the primary and secret share the refresh's
        // expiry (refresh-owned), while the session token was independently
        // updated to a later value that must survive the delete.
        let independent_expires_at_ms = refresh_expires_at_ms + 120_000;
        update_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "aws-delete".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::from([
                    ("AWS_SECRET_ACCESS_KEY".to_string(), refresh_expires_at_ms),
                    ("AWS_SESSION_TOKEN".to_string(), independent_expires_at_ms),
                ]),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        handle_delete_provider_refresh(
            &state,
            authed_request(DeleteProviderRefreshRequest {
                provider: "aws-delete".to_string(),
                credential_key: "AWS_ACCESS_KEY_ID".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let provider = state
            .store
            .get_message_by_name::<Provider>("default", "aws-delete")
            .await
            .unwrap()
            .unwrap();
        // Refresh-owned expiries for the primary and secret are cleared.
        assert!(
            !provider
                .credential_expires_at_ms
                .contains_key("AWS_ACCESS_KEY_ID")
        );
        assert!(
            !provider
                .credential_expires_at_ms
                .contains_key("AWS_SECRET_ACCESS_KEY")
        );
        // The independently updated session-token expiry is preserved.
        assert_eq!(
            provider.credential_expires_at_ms.get("AWS_SESSION_TOKEN"),
            Some(&independent_expires_at_ms)
        );
    }

    #[test]
    fn clear_refresh_owned_expiries_preserves_concurrently_changed_expiry() {
        // Regression for the delete-refresh TOCTOU: the clearing decision runs
        // inside the CAS closure against the current provider. Simulate a
        // concurrent rotation that updated AWS_SESSION_TOKEN's expiry after the
        // handler's initial read but before its write — by the time the closure
        // runs, that value no longer matches the deleted refresh's expiry and
        // must survive, while the still-owned keys are cleared.
        let refresh_expires_at_ms = 1_000_000;
        let concurrently_changed = refresh_expires_at_ms + 500_000;
        let mut provider = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "p".to_string(),
                name: "p".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: "aws".to_string(),
            credentials: HashMap::new(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::from([
                ("AWS_ACCESS_KEY_ID".to_string(), refresh_expires_at_ms),
                ("AWS_SECRET_ACCESS_KEY".to_string(), refresh_expires_at_ms),
                ("AWS_SESSION_TOKEN".to_string(), concurrently_changed),
            ]),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        };
        let owned_keys = vec![
            "AWS_ACCESS_KEY_ID".to_string(),
            "AWS_SECRET_ACCESS_KEY".to_string(),
            "AWS_SESSION_TOKEN".to_string(),
        ];

        clear_refresh_owned_expiries(&mut provider, refresh_expires_at_ms, &owned_keys);

        assert!(
            !provider
                .credential_expires_at_ms
                .contains_key("AWS_ACCESS_KEY_ID")
        );
        assert!(
            !provider
                .credential_expires_at_ms
                .contains_key("AWS_SECRET_ACCESS_KEY")
        );
        assert_eq!(
            provider.credential_expires_at_ms.get("AWS_SESSION_TOKEN"),
            Some(&concurrently_changed)
        );
    }

    #[tokio::test]
    async fn configure_provider_refresh_rejects_credential_key_collision_for_attached_sandbox() {
        let state = test_server_state().await;
        import_test_graph_refresh_profile(&state).await;
        create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "existing-graph".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: TEST_GRAPH_PROVIDER_TYPE.to_string(),
                credentials: std::iter::once((
                    "MS_GRAPH_ACCESS_TOKEN".to_string(),
                    "existing-token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();
        create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "refreshing-graph".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: TEST_GRAPH_PROVIDER_TYPE.to_string(),
                credentials: std::iter::once(("OTHER_TOKEN".to_string(), "other".to_string()))
                    .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();
        state
            .store
            .put_message(&Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "sandbox-collision".to_string(),
                    name: "collision".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                spec: Some(SandboxSpec {
                    providers: vec!["existing-graph".to_string(), "refreshing-graph".to_string()],
                    ..SandboxSpec::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();

        let err = handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "refreshing-graph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
                material: HashMap::from([
                    ("tenant_id".to_string(), "tenant".to_string()),
                    ("client_id".to_string(), "client-id".to_string()),
                    ("client_secret".to_string(), "client-secret".to_string()),
                ]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: None,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("collision"));
        assert!(err.message().contains("MS_GRAPH_ACCESS_TOKEN"));
        let states = crate::provider_refresh::list_all_refresh_states(state.store.as_ref())
            .await
            .unwrap();
        assert!(states.is_empty());
    }

    #[tokio::test]
    async fn configure_provider_refresh_treats_existing_refresh_state_keys_as_reserved() {
        let state = test_server_state().await;
        import_test_graph_refresh_profile(&state).await;
        for name in ["first-graph", "second-graph"] {
            create_provider_record(
                state.store.as_ref(),
                "default",
                Provider {
                    metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                        id: String::new(),
                        name: name.to_string(),
                        created_at_ms: 0,
                        labels: HashMap::new(),
                        resource_version: 0,
                        annotations: HashMap::new(),
                        workspace: "default".to_string(),
                        deletion_timestamp_ms: 0,
                    }),
                    r#type: TEST_GRAPH_PROVIDER_TYPE.to_string(),
                    credentials: HashMap::new(),
                    config: HashMap::new(),
                    credential_expires_at_ms: HashMap::new(),
                    profile_workspace: "default".to_string(),
                    credential_handles: HashMap::new(),
                },
            )
            .await
            .unwrap();
        }
        state
            .store
            .put_message(&Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "sandbox-refresh-collision".to_string(),
                    name: "refresh-collision".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                spec: Some(SandboxSpec {
                    providers: vec!["first-graph".to_string(), "second-graph".to_string()],
                    ..SandboxSpec::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();

        handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "first-graph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
                material: HashMap::from([
                    ("tenant_id".to_string(), "tenant".to_string()),
                    ("client_id".to_string(), "client-id".to_string()),
                    ("client_secret".to_string(), "client-secret".to_string()),
                ]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: None,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let err = handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "second-graph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
                material: HashMap::from([
                    ("tenant_id".to_string(), "tenant".to_string()),
                    ("client_id".to_string(), "client-id".to_string()),
                    ("client_secret".to_string(), "client-secret".to_string()),
                ]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: None,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("collision"));
        assert!(err.message().contains("MS_GRAPH_ACCESS_TOKEN"));
        assert!(err.message().contains("first-graph"));
        assert!(err.message().contains("second-graph"));
    }

    #[tokio::test]
    async fn configure_provider_refresh_rejects_profile_endpoint_override_and_missing_material() {
        let state = test_server_state().await;
        import_test_graph_refresh_profile(&state).await;
        create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "msgraph".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: TEST_GRAPH_PROVIDER_TYPE.to_string(),
                credentials: std::iter::once((
                    "MS_GRAPH_ACCESS_TOKEN".to_string(),
                    "token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let endpoint_override = handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "msgraph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
                material: HashMap::from([
                    ("tenant_id".to_string(), "tenant".to_string()),
                    ("client_id".to_string(), "client-id".to_string()),
                    ("client_secret".to_string(), "client-secret".to_string()),
                    (
                        "token_url".to_string(),
                        "https://attacker.example/token".to_string(),
                    ),
                ]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: None,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(endpoint_override.code(), Code::InvalidArgument);
        assert!(endpoint_override.message().contains("provider profile"));

        let missing_material = handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "msgraph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
                material: HashMap::from([("tenant_id".to_string(), "tenant".to_string())]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: None,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(missing_material.code(), Code::InvalidArgument);
        assert!(missing_material.message().contains("client_id material"));
    }

    #[tokio::test]
    async fn configure_provider_refresh_rejects_non_gateway_mintable_strategies() {
        let state = test_server_state().await;
        create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "msgraph".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "outlook".to_string(),
                credentials: std::iter::once((
                    "MS_GRAPH_ACCESS_TOKEN".to_string(),
                    "token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        for strategy in [
            ProviderCredentialRefreshStrategy::Static,
            ProviderCredentialRefreshStrategy::External,
        ] {
            let err = handle_configure_provider_refresh(
                &state,
                authed_request(ConfigureProviderRefreshRequest {
                    provider: "msgraph".to_string(),
                    credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                    strategy: strategy as i32,
                    material: HashMap::new(),
                    secret_material_keys: Vec::new(),
                    expires_at_ms: None,
                    workspace: "default".to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message().contains("not gateway-mintable"),
                "unexpected error: {}",
                err.message()
            );
        }

        let refresh_states = crate::provider_refresh::list_all_refresh_states(state.store.as_ref())
            .await
            .unwrap();
        assert!(refresh_states.is_empty());
    }

    #[tokio::test]
    async fn delete_provider_profile_removes_unused_custom_profile() {
        let state = test_server_state().await;
        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("custom-api")),
                    source: "custom-api.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let deleted = handle_delete_provider_profile(
            &state,
            authed_request(DeleteProviderProfileRequest {
                id: "custom-api".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(deleted.deleted);

        let missing = handle_get_provider_profile(
            &state,
            authed_request(GetProviderProfileRequest {
                id: "custom-api".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(missing.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn delete_provider_profile_waits_for_sandbox_sync_guard() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&stored_provider_profile(custom_profile("guarded-delete")))
            .await
            .unwrap();

        let guard = state.compute.sandbox_sync_guard().await;
        let task_state = state.clone();
        let task = tokio::spawn(async move {
            handle_delete_provider_profile(
                &task_state,
                authed_request(DeleteProviderProfileRequest {
                    id: "guarded-delete".to_string(),
                    workspace: "default".to_string(),
                }),
            )
            .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !task.is_finished(),
            "profile delete should wait for sandbox sync guard"
        );
        drop(guard);

        let response = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("delete should finish after guard release")
            .expect("join delete task")
            .expect("delete should succeed")
            .into_inner();
        assert!(response.deleted);
    }

    #[tokio::test]
    async fn create_provider_waits_for_provider_profile_delete_guard() {
        let state = test_server_state().await;
        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("guarded-create")),
                    source: "guarded-create.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let guard = state.compute.sandbox_sync_guard().await;
        let task_state = state.clone();
        let task = tokio::spawn(async move {
            let mut provider = provider_with_values("guarded-provider", "guarded-create");
            provider.credentials.clear();
            provider.config.clear();
            handle_create_provider(
                &task_state,
                authed_request(CreateProviderRequest {
                    provider: Some(provider),
                    workspace: "default".to_string(),
                }),
            )
            .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !task.is_finished(),
            "provider create should wait for provider profile mutation guard"
        );
        drop(guard);

        let response = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("create should finish after guard release")
            .expect("join create task")
            .expect("create should succeed")
            .into_inner();
        assert_eq!(
            response.provider.expect("provider").object_name(),
            "guarded-provider"
        );
    }

    #[tokio::test]
    async fn provider_crud_round_trip_and_semantics() {
        let store = test_store().await;

        let created = provider_with_values("gitlab-local", "gitlab");
        let persisted = create_provider_record(&store, "default", created.clone())
            .await
            .unwrap();
        assert_eq!(persisted.object_name(), "gitlab-local");
        assert_eq!(persisted.r#type, "gitlab");
        assert!(!persisted.object_id().is_empty());
        let provider_id = persisted.object_id().to_string();

        let duplicate_err = create_provider_record(&store, "default", created)
            .await
            .unwrap_err();
        assert_eq!(duplicate_err.code(), Code::AlreadyExists);

        let loaded = get_provider_record(&store, "default", "gitlab-local")
            .await
            .unwrap();
        assert_eq!(loaded.object_id(), provider_id);

        let listed = list_provider_records(&store, "default", 100, 0)
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].object_name(), "gitlab-local");

        let updated = update_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "gitlab-local".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "gitlab".to_string(),
                credentials: std::iter::once((
                    "API_TOKEN".to_string(),
                    "rotated-token".to_string(),
                ))
                .collect(),
                config: std::iter::once(("endpoint".to_string(), "https://gitlab.com".to_string()))
                    .collect(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();
        assert_eq!(updated.object_id(), provider_id);
        assert_eq!(updated.credentials.len(), 2);
        assert_eq!(
            updated.credentials.get("API_TOKEN"),
            Some(&"REDACTED".to_string()),
            "credential values must be redacted in gRPC responses"
        );
        assert_eq!(
            updated.credentials.get("SECONDARY"),
            Some(&"REDACTED".to_string()),
        );
        let stored: Provider = store
            .get_message_by_name("default", "gitlab-local")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.credentials.get("API_TOKEN"),
            Some(&"rotated-token".to_string())
        );
        assert_eq!(
            stored.credentials.get("SECONDARY"),
            Some(&"secondary-token".to_string())
        );
        assert_eq!(
            updated.config.get("endpoint"),
            Some(&"https://gitlab.com".to_string())
        );
        assert_eq!(updated.config.get("region"), Some(&"us-west".to_string()));

        let deleted = delete_provider_record(&store, "default", "gitlab-local")
            .await
            .unwrap();
        assert!(deleted);

        let deleted_again = delete_provider_record(&store, "default", "gitlab-local")
            .await
            .unwrap();
        assert!(!deleted_again);

        let missing = get_provider_record(&store, "default", "gitlab-local")
            .await
            .unwrap_err();
        assert_eq!(missing.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn create_provider_record_stores_credentials_with_runtime() {
        let store = test_store().await;
        let config = openshell_core::Config::new(None).with_credential_drivers(["test-static"]);
        let credentials = crate::credentials::CredentialRuntime::from_config(&config).unwrap();

        let catalog = ProviderProfileSources::with_default_sources()
            .snapshot_catalog(&store, "default")
            .await
            .unwrap();
        let persisted = create_provider_record_validating(
            &store,
            "default",
            &catalog,
            provider_with_credential_value("openai-local", "openai", "OPENAI_API_KEY", "sk-test"),
            Some(&credentials),
        )
        .await
        .unwrap();

        assert_eq!(persisted.object_name(), "openai-local");
        assert_eq!(
            persisted
                .credentials
                .get("OPENAI_API_KEY")
                .map(String::as_str),
            Some("REDACTED")
        );
        assert!(persisted.credential_handles.is_empty());

        let stored: Provider = store
            .get_message_by_name("default", "openai-local")
            .await
            .unwrap()
            .unwrap();
        assert!(stored.credentials.is_empty());
        assert_eq!(
            stored
                .credential_handles
                .get("OPENAI_API_KEY")
                .map(|handle| handle.driver.as_str()),
            Some("test-static")
        );
    }

    #[tokio::test]
    async fn token_exchange_subject_token_resolves_credential_handle() {
        let config = openshell_core::Config::new(None).with_credential_drivers(["test-static"]);
        let credentials = crate::credentials::CredentialRuntime::from_config(&config).unwrap();
        let mut provider = provider_with_values("exchange-local", "custom");
        provider.credentials.clear();
        provider.metadata.as_mut().expect("provider metadata").id = "provider-id".to_string();
        let handles = credentials
            .store_provider_credentials(
                provider.object_name(),
                provider.object_workspace(),
                provider.object_id(),
                &HashMap::from([("subject_token".to_string(), "user-token".to_string())]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        provider.credential_handles = handles;

        let subject_token =
            resolve_subject_token_credential(&credentials, &provider, "subject_token")
                .await
                .unwrap();

        assert_eq!(subject_token, "user-token");
    }

    #[tokio::test]
    async fn update_provider_record_overwrites_credentials_with_runtime() {
        let store = test_store().await;
        let config = openshell_core::Config::new(None).with_credential_drivers(["test-static"]);
        let credentials = crate::credentials::CredentialRuntime::from_config(&config).unwrap();
        let catalog = ProviderProfileSources::with_default_sources()
            .snapshot_catalog(&store, "default")
            .await
            .unwrap();

        create_provider_record_validating(
            &store,
            "default",
            &catalog,
            provider_with_credential_value("openai-local", "openai", "OPENAI_API_KEY", "sk-first"),
            Some(&credentials),
        )
        .await
        .unwrap();
        let stored_first: Provider = store
            .get_message_by_name("default", "openai-local")
            .await
            .unwrap()
            .unwrap();
        let first_handle = stored_first
            .credential_handles
            .get("OPENAI_API_KEY")
            .expect("stored handle")
            .handle
            .clone();

        let updated = update_provider_record_validating(
            &store,
            "default",
            &catalog,
            provider_with_credential_value("openai-local", "openai", "OPENAI_API_KEY", "sk-second"),
            Some(&credentials),
        )
        .await
        .unwrap();
        assert_eq!(
            updated
                .credentials
                .get("OPENAI_API_KEY")
                .map(String::as_str),
            Some("REDACTED")
        );
        assert!(updated.credential_handles.is_empty());

        let stored_second: Provider = store
            .get_message_by_name("default", "openai-local")
            .await
            .unwrap()
            .unwrap();
        assert!(stored_second.credentials.is_empty());
        assert_eq!(
            stored_second
                .credential_handles
                .get("OPENAI_API_KEY")
                .map(|handle| handle.handle.as_str()),
            Some(first_handle.as_str())
        );

        let result = resolve_provider_environment_with_credentials(
            &store,
            &catalog,
            "default",
            &["openai-local".to_string()],
            &credentials,
        )
        .await
        .unwrap();
        assert_eq!(result.get("OPENAI_API_KEY"), Some(&"sk-second".to_string()));
    }

    #[tokio::test]
    async fn update_provider_record_with_runtime_preserves_legacy_inline_credentials_on_noop() {
        let store = test_store().await;
        let config = openshell_core::Config::new(None).with_credential_drivers(["test-static"]);
        let credentials = crate::credentials::CredentialRuntime::from_config(&config).unwrap();
        let catalog = ProviderProfileSources::with_default_sources()
            .snapshot_catalog(&store, "default")
            .await
            .unwrap();

        create_provider_record(
            &store,
            "default",
            provider_with_values("legacy-provider", "legacy-custom"),
        )
        .await
        .unwrap();

        let updated = update_provider_record_validating(
            &store,
            "default",
            &catalog,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "legacy-provider".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    ..Default::default()
                }),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: std::iter::once((
                    "endpoint".to_string(),
                    "https://updated.example.com".to_string(),
                ))
                .collect(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: String::new(),
                credential_handles: HashMap::new(),
            },
            Some(&credentials),
        )
        .await
        .unwrap();
        assert_eq!(updated.credentials.len(), 2);
        assert!(updated.credential_handles.is_empty());

        let stored: Provider = store
            .get_message_by_name("default", "legacy-provider")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.credentials.get("API_TOKEN").map(String::as_str),
            Some("token-123")
        );
        assert_eq!(
            stored.credentials.get("SECONDARY").map(String::as_str),
            Some("secondary-token")
        );
        assert!(stored.credential_handles.is_empty());
    }

    #[tokio::test]
    async fn update_provider_record_with_runtime_stores_only_updated_legacy_inline_credentials() {
        let store = test_store().await;
        let config = openshell_core::Config::new(None).with_credential_drivers(["test-static"]);
        let credentials = crate::credentials::CredentialRuntime::from_config(&config).unwrap();
        let catalog = ProviderProfileSources::with_default_sources()
            .snapshot_catalog(&store, "default")
            .await
            .unwrap();

        create_provider_record(
            &store,
            "default",
            provider_with_values("legacy-provider", "legacy-custom"),
        )
        .await
        .unwrap();

        update_provider_record_validating(
            &store,
            "default",
            &catalog,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "legacy-provider".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    ..Default::default()
                }),
                r#type: String::new(),
                credentials: std::iter::once((
                    "API_TOKEN".to_string(),
                    "rotated-token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: String::new(),
                credential_handles: HashMap::new(),
            },
            Some(&credentials),
        )
        .await
        .unwrap();

        let stored: Provider = store
            .get_message_by_name("default", "legacy-provider")
            .await
            .unwrap()
            .unwrap();
        assert!(!stored.credentials.contains_key("API_TOKEN"));
        assert_eq!(
            stored.credentials.get("SECONDARY").map(String::as_str),
            Some("secondary-token")
        );
        assert_eq!(
            stored
                .credential_handles
                .get("API_TOKEN")
                .map(|handle| handle.driver.as_str()),
            Some("test-static")
        );

        let result = resolve_provider_environment_with_credentials(
            &store,
            &catalog,
            "default",
            &["legacy-provider".to_string()],
            &credentials,
        )
        .await
        .unwrap();
        assert_eq!(result.get("API_TOKEN"), Some(&"rotated-token".to_string()));
        assert_eq!(
            result.get("SECONDARY"),
            Some(&"secondary-token".to_string())
        );
    }

    #[tokio::test]
    async fn handle_create_provider_rejects_user_supplied_credential_handles() {
        let state = test_server_state().await;

        let err = handle_create_provider(
            &state,
            authed_request(CreateProviderRequest {
                provider: Some(provider_with_credential_handle(
                    "openai-ref",
                    "openai",
                    "OPENAI_API_KEY",
                )),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("internal gateway state"));
    }

    #[tokio::test]
    async fn handle_create_provider_rejects_profileless_type() {
        let state = test_server_state().await;
        let err = handle_create_provider(
            &state,
            authed_request(CreateProviderRequest {
                provider: Some(provider_with_values("legacy-gitlab", "gitlab")),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(
            err.message()
                .contains("provider profile 'gitlab' was not found")
        );
    }

    #[tokio::test]
    async fn handle_create_provider_allows_credentialless_policy_profile() {
        let state = test_server_state().await;
        let response = handle_create_provider(
            &state,
            authed_request(CreateProviderRequest {
                provider: Some(Provider {
                    metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                        name: "pypi".to_string(),
                        workspace: "default".to_string(),
                        ..Default::default()
                    }),
                    r#type: "pypi".to_string(),
                    profile_workspace: "default".to_string(),
                    ..Default::default()
                }),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .provider
        .expect("provider");

        assert_eq!(response.r#type, "pypi");
        assert!(response.credentials.is_empty());
    }

    #[tokio::test]
    async fn handle_create_provider_allows_retired_type_with_imported_profile() {
        let state = test_server_state().await;
        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("gitlab")),
                    source: "custom-gitlab.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let response = handle_create_provider(
            &state,
            authed_request(CreateProviderRequest {
                provider: Some(Provider {
                    metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                        name: "private-gitlab".to_string(),
                        workspace: "default".to_string(),
                        ..Default::default()
                    }),
                    r#type: "gitlab".to_string(),
                    profile_workspace: "default".to_string(),
                    ..Default::default()
                }),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .provider
        .expect("provider");

        assert_eq!(response.r#type, "gitlab");
    }

    #[tokio::test]
    async fn handle_create_provider_prefers_exact_imported_alias_profile() {
        let mut state = test_server_state().await;
        let config = state
            .config
            .clone()
            .with_credential_drivers(["test-static"]);
        let credentials = crate::credentials::CredentialRuntime::from_config(&config).unwrap();
        let state_mut = Arc::get_mut(&mut state).unwrap();
        state_mut.config = config;
        state_mut.credentials = credentials;

        let mut profile = custom_profile("gh");
        profile.credentials = vec![static_credential("token", "GITHUB_TOKEN", true)];
        profile.endpoints = vec![NetworkEndpoint {
            host: "github.enterprise.example".to_string(),
            port: 443,
            allow_uninspected_credentials: true,
            ..Default::default()
        }];
        let imported = handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(profile),
                    source: "enterprise-github.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(imported.imported, "diagnostics: {:?}", imported.diagnostics);

        let provider = handle_create_provider(
            &state,
            authed_request(CreateProviderRequest {
                provider: Some(provider_with_credential_value(
                    "enterprise-github",
                    "gh",
                    "GITHUB_TOKEN",
                    "test-token",
                )),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .provider
        .expect("provider");

        assert_eq!(provider.r#type, "gh");
        let catalog = state
            .provider_profile_sources
            .snapshot_catalog(state.store.as_ref(), "default")
            .await
            .unwrap();
        let resolved = get_provider_type_profile_for_scope(
            &catalog,
            &provider.r#type,
            &provider.profile_workspace,
        )
        .expect("exact imported profile");
        assert_eq!(resolved.id, "gh");
        assert_eq!(resolved.endpoints[0].host, "github.enterprise.example");
    }

    #[tokio::test]
    async fn handle_create_provider_stores_inline_credentials_with_enabled_driver() {
        let mut state = test_server_state().await;
        let config = state
            .config
            .clone()
            .with_credential_drivers(["test-static"]);
        let credentials = crate::credentials::CredentialRuntime::from_config(&config).unwrap();
        let state_mut = Arc::get_mut(&mut state).unwrap();
        state_mut.config = config;
        state_mut.credentials = credentials;

        let response = handle_create_provider(
            &state,
            authed_request(CreateProviderRequest {
                provider: Some(provider_with_credential_value(
                    "openai-local",
                    "openai",
                    "OPENAI_API_KEY",
                    "sk-test",
                )),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        let provider = response.provider.expect("provider");
        assert_eq!(
            provider
                .credentials
                .get("OPENAI_API_KEY")
                .map(String::as_str),
            Some("REDACTED")
        );
        assert!(provider.credential_handles.is_empty());

        let stored: Provider = state
            .store
            .get_message_by_name("default", "openai-local")
            .await
            .unwrap()
            .unwrap();
        assert!(stored.credentials.is_empty());
        assert!(stored.credential_handles.contains_key("OPENAI_API_KEY"));

        let catalog = state
            .provider_profile_sources
            .snapshot_catalog(state.store.as_ref(), "default")
            .await
            .unwrap();
        let result = resolve_provider_environment_with_credentials(
            state.store.as_ref(),
            &catalog,
            "default",
            &["openai-local".to_string()],
            &state.credentials,
        )
        .await
        .unwrap();
        assert_eq!(result.get("OPENAI_API_KEY"), Some(&"sk-test".to_string()));
    }

    #[tokio::test]
    async fn handle_create_provider_accepts_broker_only_subject_token() {
        let mut state = test_server_state().await;
        let config = state
            .config
            .clone()
            .with_credential_drivers(["test-static"]);
        let credentials = crate::credentials::CredentialRuntime::from_config(&config).unwrap();
        let state_mut = Arc::get_mut(&mut state).unwrap();
        state_mut.config = config;
        state_mut.credentials = credentials;

        let mut profile = custom_profile("spiffe-token-exchange-demo");
        profile.credentials = vec![
            ProviderProfileCredential {
                name: "subject_token".to_string(),
                description: "Broker-only subject token".to_string(),
                required: true,
                ..Default::default()
            },
            ProviderProfileCredential {
                name: "access_token".to_string(),
                required: false,
                auth_style: "bearer".to_string(),
                header_name: "Authorization".to_string(),
                token_grant: Some(ProviderCredentialTokenGrant {
                    grant_type: ProviderCredentialTokenGrantType::TokenExchange as i32,
                    token_endpoint: "https://issuer.example.com/token".to_string(),
                    jwt_svid_audience: "https://issuer.example.com".to_string(),
                    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                        .to_string(),
                    subject_token: Some(ProviderCredentialTokenGrantSubjectToken {
                        source: "provider_credential".to_string(),
                        credential: "subject_token".to_string(),
                        subject_token_type: "urn:ietf:params:oauth:token-type:access_token"
                            .to_string(),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ];
        profile.endpoints = vec![NetworkEndpoint {
            host: "api.example.com".to_string(),
            port: 443,
            allow_uninspected_credentials: true,
            ..Default::default()
        }];
        let imported = handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(profile),
                    source: "provider-profile.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(imported.imported, "diagnostics: {:?}", imported.diagnostics);

        handle_create_provider(
            &state,
            authed_request(CreateProviderRequest {
                provider: Some(provider_with_credential_value(
                    "exchange",
                    "spiffe-token-exchange-demo",
                    "subject_token",
                    "test-token",
                )),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let stored: Provider = state
            .store
            .get_message_by_name("default", "exchange")
            .await
            .unwrap()
            .unwrap();
        assert!(stored.credentials.is_empty());
        assert!(stored.credential_handles.contains_key("subject_token"));
    }

    #[tokio::test]
    async fn handle_update_provider_rejects_user_supplied_credential_handles() {
        let state = test_server_state().await;
        create_provider_record(
            state.store.as_ref(),
            "default",
            provider_with_values("openai-local", "openai"),
        )
        .await
        .unwrap();

        let err = handle_update_provider(
            &state,
            authed_request(UpdateProviderRequest {
                provider: Some(provider_with_credential_handle(
                    "openai-local",
                    "openai",
                    "OPENAI_API_KEY",
                )),
                credential_expires_at_ms: HashMap::new(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("internal gateway state"));
    }

    #[tokio::test]
    async fn delete_provider_removes_scoped_refresh_states() {
        let store = test_store().await;

        let provider = create_provider_record(
            &store,
            "default",
            Provider {
                credential_expires_at_ms: HashMap::from([("API_TOKEN".to_string(), 123_456)]),
                ..provider_with_values("gitlab-local", "gitlab")
            },
        )
        .await
        .unwrap();
        let refresh_state = crate::provider_refresh::new_refresh_state(
            &provider,
            "default",
            "API_TOKEN",
            crate::provider_refresh::NewRefreshStateConfig {
                additional_output_keys: HashMap::new(),
                strategy: ProviderCredentialRefreshStrategy::External,
                material: HashMap::from([(
                    "endpoint".to_string(),
                    "https://refresh.example.com".to_string(),
                )]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: 123_456,
                token_url: "https://refresh.example.com/token".to_string(),
                scopes: Vec::new(),
                refresh_before_seconds: 300,
                max_lifetime_seconds: 3600,
            },
        )
        .unwrap();
        crate::provider_refresh::put_refresh_state(&store, &refresh_state)
            .await
            .unwrap();

        let deleted = delete_provider_record(&store, "default", "gitlab-local")
            .await
            .unwrap();
        assert!(deleted);

        let refresh_states =
            crate::provider_refresh::list_refresh_states_for_provider(&store, provider.object_id())
                .await
                .unwrap();
        assert!(refresh_states.is_empty());
    }

    #[tokio::test]
    async fn delete_provider_rejects_attached_provider() {
        let store = test_store().await;

        create_provider_record(
            &store,
            "default",
            provider_with_values("gitlab-local", "gitlab"),
        )
        .await
        .unwrap();
        store
            .put_message(&Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "sandbox-id".to_string(),
                    name: "attached-sandbox".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                spec: Some(SandboxSpec {
                    providers: vec!["gitlab-local".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();

        let err = delete_provider_record(&store, "default", "gitlab-local")
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(
            err.message().contains("attached-sandbox"),
            "error should identify blocking sandbox: {}",
            err.message()
        );
    }

    #[tokio::test]
    async fn provider_create_and_update_return_correct_resource_version() {
        let store = test_store().await;

        // Create provider and verify resource_version: 1 in response
        let created = provider_with_values("test-provider", "legacy-custom");
        let persisted = create_provider_record(&store, "default", created)
            .await
            .unwrap();
        assert_eq!(
            persisted.metadata.as_ref().unwrap().resource_version,
            1,
            "create_provider_record should return resource_version: 1 after insert"
        );

        // Update provider and verify resource_version: 2 in response
        let updated = update_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "test-provider".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "legacy-custom".to_string(),
                credentials: std::iter::once((
                    "OPENAI_API_KEY".to_string(),
                    "updated-key".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            updated.metadata.as_ref().unwrap().resource_version,
            2,
            "update_provider_record should return resource_version: 2 after first update"
        );

        // Update again and verify resource_version: 3
        let updated_again = update_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "test-provider".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "legacy-custom".to_string(),
                credentials: std::iter::once((
                    "OPENAI_API_KEY".to_string(),
                    "third-key".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            updated_again.metadata.as_ref().unwrap().resource_version,
            3,
            "update_provider_record should return resource_version: 3 after second update"
        );
    }

    #[tokio::test]
    async fn provider_validation_errors() {
        let state = test_server_state().await;
        let store = state.store.as_ref();

        let create_missing_type = create_provider_record(
            store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "bad-provider".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(create_missing_type.code(), Code::InvalidArgument);

        let create_missing_credentials = create_provider_record(
            store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "gitlab-no-creds".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "gitlab".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(create_missing_credentials.code(), Code::InvalidArgument);

        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(ProviderProfile {
                        id: "delegated-refresh-api".to_string(),
                        resource_version: 0,
                        annotations: HashMap::new(),
                        display_name: "Delegated Refresh API".to_string(),
                        description: String::new(),
                        category: ProviderProfileCategory::Messaging as i32,
                        credentials: vec![ProviderProfileCredential {
                            name: "access_token".to_string(),
                            description: String::new(),
                            env_vars: vec!["DELEGATED_ACCESS_TOKEN".to_string()],
                            required: true,
                            auth_style: "bearer".to_string(),
                            header_name: "authorization".to_string(),
                            query_param: String::new(),
                            path_template: String::new(),
                            refresh: Some(ProviderCredentialRefresh {
                                strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken
                                    as i32,
                                token_url: "https://login.example/token".to_string(),
                                scopes: vec!["https://example.test/.default".to_string()],
                                refresh_before_seconds: 300,
                                max_lifetime_seconds: 3600,
                                additional_outputs: Vec::new(),
                                material: vec![
                                    ProviderCredentialRefreshMaterial {
                                        name: "client_id".to_string(),
                                        description: String::new(),
                                        required: true,
                                        secret: false,
                                    },
                                    ProviderCredentialRefreshMaterial {
                                        name: "refresh_token".to_string(),
                                        description: String::new(),
                                        required: true,
                                        secret: true,
                                    },
                                ],
                            }),
                            token_grant: None,
                        }],
                        endpoints: vec![],
                        binaries: vec![],
                        inference_capable: false,
                        discovery: None,
                        source: String::new(),
                        scope: String::new(),
                    }),
                    source: "delegated-refresh-api.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();
        let delegated_refresh_bootstrap_provider = create_provider_record(
            store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "delegated-refresh-no-token-yet".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "delegated-refresh-api".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();
        assert!(delegated_refresh_bootstrap_provider.credentials.is_empty());

        let mut mixed_required_profile = custom_profile("mixed-required-api");
        mixed_required_profile.credentials = vec![
            refreshable_credential("access_token", "MIXED_ACCESS_TOKEN"),
            static_credential("static_token", "MIXED_STATIC_TOKEN", true),
        ];
        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(mixed_required_profile),
                    source: "mixed-required-api.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();
        let mixed_required_empty = create_provider_record(
            store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "mixed-required-no-token-yet".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "mixed-required-api".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(mixed_required_empty.code(), Code::InvalidArgument);

        let mut optional_static_profile = custom_profile("optional-static-api");
        optional_static_profile.credentials = vec![
            refreshable_credential("access_token", "OPTIONAL_ACCESS_TOKEN"),
            static_credential("static_token", "OPTIONAL_STATIC_TOKEN", false),
        ];
        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(optional_static_profile),
                    source: "optional-static-api.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();
        let optional_static_empty = create_provider_record(
            store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "optional-static-no-token-yet".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "optional-static-api".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();
        assert!(optional_static_empty.credentials.is_empty());

        let vertex_empty = create_provider_record(
            store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "vertex-no-token-yet".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "google-vertex-ai".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();
        assert!(vertex_empty.credentials.is_empty());

        let get_err = get_provider_record(store, "default", "").await.unwrap_err();
        assert_eq!(get_err.code(), Code::InvalidArgument);

        let delete_err = delete_provider_record(store, "default", "")
            .await
            .unwrap_err();
        assert_eq!(delete_err.code(), Code::InvalidArgument);

        let update_missing_err = update_provider_record(
            store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "missing".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(update_missing_err.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn update_provider_empty_maps_is_noop() {
        let store = test_store().await;

        let created = provider_with_values("noop-test", "legacy-custom");
        let persisted = create_provider_record(&store, "default", created)
            .await
            .unwrap();

        let updated = update_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "noop-test".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        assert_eq!(updated.object_id(), persisted.object_id());
        assert_eq!(updated.r#type, "legacy-custom");
        assert_eq!(updated.credentials.len(), 2);
        assert_eq!(
            updated.credentials.get("API_TOKEN"),
            Some(&"REDACTED".to_string())
        );
        assert_eq!(updated.config.len(), 2);
        assert_eq!(
            updated.config.get("endpoint"),
            Some(&"https://example.com".to_string())
        );
        assert_eq!(updated.config.get("region"), Some(&"us-west".to_string()));
        let stored: Provider = store
            .get_message_by_name("default", "noop-test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.credentials.len(), 2);
    }

    #[tokio::test]
    async fn update_provider_empty_value_deletes_key() {
        let store = test_store().await;

        let created = provider_with_values("delete-key-test", "legacy-custom");
        create_provider_record(&store, "default", created)
            .await
            .unwrap();

        let updated = update_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "delete-key-test".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: String::new(),
                credentials: std::iter::once(("SECONDARY".to_string(), String::new())).collect(),
                config: std::iter::once(("region".to_string(), String::new())).collect(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        assert_eq!(updated.credentials.len(), 1);
        assert_eq!(
            updated.credentials.get("API_TOKEN"),
            Some(&"REDACTED".to_string())
        );
        assert!(!updated.credentials.contains_key("SECONDARY"));
        assert_eq!(updated.config.len(), 1);
        assert_eq!(
            updated.config.get("endpoint"),
            Some(&"https://example.com".to_string())
        );
        assert!(!updated.config.contains_key("region"));
        let stored: Provider = store
            .get_message_by_name("default", "delete-key-test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.credentials.len(), 1);
        assert_eq!(
            stored.credentials.get("API_TOKEN"),
            Some(&"token-123".to_string())
        );
        assert!(!stored.credentials.contains_key("SECONDARY"));
    }

    #[tokio::test]
    async fn update_provider_empty_type_preserves_existing() {
        let store = test_store().await;

        let created = provider_with_values("type-preserve-test", "legacy-custom");
        create_provider_record(&store, "default", created)
            .await
            .unwrap();

        let updated = update_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "type-preserve-test".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        assert_eq!(updated.r#type, "legacy-custom");
    }

    #[tokio::test]
    async fn update_provider_rejects_type_change() {
        let store = test_store().await;

        let created = provider_with_values("type-change-test", "nvidia");
        create_provider_record(&store, "default", created)
            .await
            .unwrap();

        let err = update_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "type-change-test".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "openai".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("type cannot be changed"));
    }

    #[tokio::test]
    async fn update_provider_validates_merged_result() {
        let store = test_store().await;

        let created = provider_with_values("validate-merge-test", "gitlab");
        create_provider_record(&store, "default", created)
            .await
            .unwrap();

        let oversized_key = "K".repeat(MAX_MAP_KEY_LEN + 1);
        let err = update_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "validate-merge-test".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: String::new(),
                credentials: std::iter::once((oversized_key, "value".to_string())).collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
    }

    /// Regression for #1347: a credential rotation must not fail just because the
    /// existing record's `type` field exceeds the current `MAX_PROVIDER_TYPE_LEN`.
    /// The caller never touches `type`; re-validating it strands legacy records.
    #[tokio::test]
    async fn update_provider_allows_credential_rotation_on_legacy_oversized_type() {
        let store = test_store().await;

        let oversized_type = "x".repeat(MAX_PROVIDER_TYPE_LEN + 15);
        let legacy = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: uuid::Uuid::new_v4().to_string(),
                name: "legacy-oversized-type".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: oversized_type.clone(),
            credentials: std::iter::once(("API_TOKEN".to_string(), "old".to_string())).collect(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        };
        store.put_message(&legacy).await.unwrap();

        let updated = update_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "legacy-oversized-type".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: String::new(),
                credentials: std::iter::once(("API_TOKEN".to_string(), "new".to_string()))
                    .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        assert_eq!(updated.r#type, oversized_type);
    }

    #[tokio::test]
    async fn resolve_provider_env_empty_list_returns_empty() {
        let store = test_store().await;
        let result = resolve_provider_environment(&store, "default", &[])
            .await
            .unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn resolve_provider_env_injects_credentials() {
        let store = test_store().await;
        let provider = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: "claude-local".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: "claude".to_string(),
            credentials: [
                ("ANTHROPIC_API_KEY".to_string(), "sk-abc".to_string()),
                ("CLAUDE_API_KEY".to_string(), "sk-abc".to_string()),
            ]
            .into_iter()
            .collect(),
            config: std::iter::once((
                "endpoint".to_string(),
                "https://api.anthropic.com".to_string(),
            ))
            .collect(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        };
        create_provider_record(&store, "default", provider)
            .await
            .unwrap();

        let result = resolve_provider_environment(&store, "default", &["claude-local".to_string()])
            .await
            .unwrap();
        assert_eq!(result.get("ANTHROPIC_API_KEY"), Some(&"sk-abc".to_string()));
        assert_eq!(result.get("CLAUDE_API_KEY"), Some(&"sk-abc".to_string()));
        assert!(!result.contains_key("endpoint"));
        assert!(
            result
                .static_credential_bindings
                .get("ANTHROPIC_API_KEY")
                .is_some_and(|binding| !binding.endpoints.is_empty())
        );
        assert!(
            result
                .static_credential_bindings
                .get("CLAUDE_API_KEY")
                .is_some_and(|binding| !binding.endpoints.is_empty())
        );
    }

    #[test]
    fn workload_handle_derivation_is_order_independent_and_boundary_bound() {
        let endpoints = vec![
            StaticCredentialEndpointBinding {
                host: "API.EXAMPLE.COM.".to_string(),
                port: 443,
                path: "**".to_string(),
            },
            StaticCredentialEndpointBinding {
                host: "files.example.com".to_string(),
                port: 8443,
                path: "/v1/**".to_string(),
            },
        ];
        let mut reordered = endpoints.clone();
        reordered.reverse();
        let first = derive_workload_credential_handle(
            "sandbox-a",
            "provider-a",
            "ACCESS_TOKEN",
            "epoch-a",
            &endpoints,
        );
        assert_eq!(
            first,
            derive_workload_credential_handle(
                "sandbox-a",
                "provider-a",
                "ACCESS_TOKEN",
                "epoch-a",
                &reordered,
            )
        );
        for changed in [
            derive_workload_credential_handle(
                "sandbox-b",
                "provider-a",
                "ACCESS_TOKEN",
                "epoch-a",
                &endpoints,
            ),
            derive_workload_credential_handle(
                "sandbox-a",
                "provider-b",
                "ACCESS_TOKEN",
                "epoch-a",
                &endpoints,
            ),
            derive_workload_credential_handle(
                "sandbox-a",
                "provider-a",
                "OTHER_TOKEN",
                "epoch-a",
                &endpoints,
            ),
            derive_workload_credential_handle(
                "sandbox-a",
                "provider-a",
                "ACCESS_TOKEN",
                "epoch-b",
                &endpoints,
            ),
            derive_workload_credential_handle(
                "sandbox-a",
                "provider-a",
                "ACCESS_TOKEN",
                "epoch-a",
                &[StaticCredentialEndpointBinding {
                    host: "api.example.com".to_string(),
                    port: 443,
                    path: "/v2/**".to_string(),
                }],
            ),
        ] {
            assert_ne!(first, changed);
        }
        assert_eq!(first.len(), 64);
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }

    #[tokio::test]
    async fn refresh_managed_handle_rejects_manual_replacement_survives_rotation_and_reconstruction_then_reconfigure_revokes()
     {
        let state = test_server_state().await;
        let mut profile = custom_profile("stable-refresh-provider");
        profile.credentials = vec![refreshable_credential("access_token", "ACCESS_TOKEN")];
        profile.endpoints = vec![NetworkEndpoint {
            host: "api.example.com".to_string(),
            port: 443,
            path: "/v1/**".to_string(),
            protocol: "rest".to_string(),
            access: "full".to_string(),
            ..Default::default()
        }];
        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(profile),
                    source: "stable-refresh-provider.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();
        let provider = create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    name: "stable-refresh".to_string(),
                    workspace: "default".to_string(),
                    ..Default::default()
                }),
                r#type: "stable-refresh-provider".to_string(),
                credentials: HashMap::from([("ACCESS_TOKEN".to_string(), "token-1".to_string())]),
                profile_workspace: "default".to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let configure = || ConfigureProviderRefreshRequest {
            provider: "stable-refresh".to_string(),
            credential_key: "ACCESS_TOKEN".to_string(),
            strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
            material: HashMap::from([
                ("client_id".to_string(), "client-id".to_string()),
                ("client_secret".to_string(), "client-secret".to_string()),
            ]),
            secret_material_keys: vec!["client_secret".to_string()],
            expires_at_ms: None,
            workspace: "default".to_string(),
        };
        handle_configure_provider_refresh(&state, authed_request(configure()))
            .await
            .unwrap();

        let catalog = state
            .provider_profile_sources
            .snapshot_catalog(state.store.as_ref(), "default")
            .await
            .unwrap();
        let names = vec!["stable-refresh".to_string()];
        let records = load_provider_environment_records(state.store.as_ref(), "default", &names)
            .await
            .unwrap();
        let revision_1 = crate::grpc::policy::compute_provider_env_revision_with_catalog(
            state.store.as_ref(),
            &catalog,
            "default",
            &names,
        )
        .await
        .unwrap();
        let first = resolve_provider_environment_from_records_with_policy_bindings_and_credentials(
            state.store.as_ref(),
            &catalog,
            &records,
            &HashMap::new(),
            &state.credentials,
            Some("sandbox-id"),
        )
        .await
        .unwrap();
        let first_handle = first.static_credential_bindings["ACCESS_TOKEN"]
            .workload_credential_handle
            .clone();
        assert!(!first_handle.is_empty());
        let credential_state =
            openshell_core::provider_credentials::ProviderCredentialState::from_bound_environment(
                revision_1,
                first.environment.clone(),
                first.credential_expires_at_ms.clone(),
                first.dynamic_credentials.clone(),
                first.static_credential_bindings.clone(),
                Vec::new(),
            )
            .unwrap();
        let original_placeholder = credential_state.snapshot().child_env["ACCESS_TOKEN"].clone();

        for value in ["token-2", ""] {
            let err = handle_update_provider(
                &state,
                authed_request(UpdateProviderRequest {
                    provider: Some(Provider {
                        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                            name: "stable-refresh".to_string(),
                            ..Default::default()
                        }),
                        credentials: HashMap::from([(
                            "ACCESS_TOKEN".to_string(),
                            value.to_string(),
                        )]),
                        ..Default::default()
                    }),
                    credential_expires_at_ms: HashMap::new(),
                    workspace: "default".to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::FailedPrecondition);
            assert!(err.message().contains("provider refresh"));
            assert!(err.message().contains("ACCESS_TOKEN"));
        }

        let unchanged = state
            .store
            .get_message_by_name::<Provider>("default", "stable-refresh")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.credentials["ACCESS_TOKEN"], "token-1");
        let unchanged_records =
            load_provider_environment_records(state.store.as_ref(), "default", &names)
                .await
                .unwrap();
        let unchanged_environment =
            resolve_provider_environment_from_records_with_policy_bindings_and_credentials(
                state.store.as_ref(),
                &catalog,
                &unchanged_records,
                &HashMap::new(),
                &state.credentials,
                Some("sandbox-id"),
            )
            .await
            .unwrap();
        credential_state
            .install_bound_environment(
                revision_1,
                unchanged_environment.environment,
                unchanged_environment.credential_expires_at_ms,
                unchanged_environment.dynamic_credentials,
                unchanged_environment.static_credential_bindings,
                Vec::new(),
            )
            .unwrap();
        assert_eq!(
            credential_state
                .resolver_for_endpoint("api.example.com", 443, "/v1/messages")
                .unwrap()
                .resolve_placeholder(&original_placeholder),
            Some("token-1")
        );

        // The gateway refresh path owns credential rotation and writes the
        // minted value with an internal CAS, preserving the authorization
        // epoch and therefore the workload handle.
        state
            .store
            .update_message_cas::<Provider, _>(provider.object_id(), 0, |current| {
                current
                    .credentials
                    .insert("ACCESS_TOKEN".to_string(), "token-2".to_string());
            })
            .await
            .unwrap();
        let records = load_provider_environment_records(state.store.as_ref(), "default", &names)
            .await
            .unwrap();
        let revision_2 = crate::grpc::policy::compute_provider_env_revision_with_catalog(
            state.store.as_ref(),
            &catalog,
            "default",
            &names,
        )
        .await
        .unwrap();
        let second =
            resolve_provider_environment_from_records_with_policy_bindings_and_credentials(
                state.store.as_ref(),
                &catalog,
                &records,
                &HashMap::new(),
                &state.credentials,
                Some("sandbox-id"),
            )
            .await
            .unwrap();
        assert_eq!(
            second.static_credential_bindings["ACCESS_TOKEN"].workload_credential_handle,
            first_handle
        );
        credential_state
            .install_bound_environment(
                revision_2,
                second.environment.clone(),
                second.credential_expires_at_ms.clone(),
                second.dynamic_credentials.clone(),
                second.static_credential_bindings.clone(),
                Vec::new(),
            )
            .unwrap();
        assert_eq!(
            credential_state
                .resolver_for_endpoint("api.example.com", 443, "/v1/messages")
                .unwrap()
                .resolve_placeholder(&original_placeholder),
            Some("token-2")
        );
        let reconstructed =
            openshell_core::provider_credentials::ProviderCredentialState::from_bound_environment(
                revision_2,
                second.environment.clone(),
                second.credential_expires_at_ms.clone(),
                second.dynamic_credentials.clone(),
                second.static_credential_bindings.clone(),
                Vec::new(),
            )
            .unwrap();
        assert_eq!(
            reconstructed
                .resolver_for_endpoint("api.example.com", 443, "/v1/messages")
                .unwrap()
                .resolve_placeholder(&original_placeholder),
            Some("token-2")
        );

        handle_configure_provider_refresh(&state, authed_request(configure()))
            .await
            .unwrap();
        let revision_3 = crate::grpc::policy::compute_provider_env_revision_with_catalog(
            state.store.as_ref(),
            &catalog,
            "default",
            &names,
        )
        .await
        .unwrap();
        assert_ne!(revision_2, revision_3);
        let records = load_provider_environment_records(state.store.as_ref(), "default", &names)
            .await
            .unwrap();
        let third = resolve_provider_environment_from_records_with_policy_bindings_and_credentials(
            state.store.as_ref(),
            &catalog,
            &records,
            &HashMap::new(),
            &state.credentials,
            Some("sandbox-id"),
        )
        .await
        .unwrap();
        assert_ne!(
            third.static_credential_bindings["ACCESS_TOKEN"].workload_credential_handle,
            first_handle
        );
        credential_state
            .install_bound_environment(
                revision_3,
                third.environment,
                third.credential_expires_at_ms,
                third.dynamic_credentials,
                third.static_credential_bindings,
                Vec::new(),
            )
            .unwrap();
        assert_eq!(
            credential_state
                .resolver_for_endpoint("api.example.com", 443, "/v1/messages")
                .unwrap()
                .resolve_placeholder(&original_placeholder),
            None
        );
        assert_eq!(provider.object_name(), "stable-refresh");
    }

    #[tokio::test]
    async fn resolve_provider_env_withholds_endpointless_profile_credentials_independently() {
        let store = test_store().await;
        let expires_at_ms = crate::persistence::current_time_ms() + 60_000;
        let mut google_cloud = google_cloud_provider(HashMap::from([(
            "project_id".to_string(),
            "sandbox-project".to_string(),
        )]));
        google_cloud.credentials = HashMap::from([(
            "GCP_ADC_ACCESS_TOKEN".to_string(),
            "google-token".to_string(),
        )]);
        google_cloud.credential_expires_at_ms =
            HashMap::from([("GCP_ADC_ACCESS_TOKEN".to_string(), expires_at_ms)]);
        create_provider_record(&store, "default", google_cloud)
            .await
            .unwrap();

        let mut github = provider_with_values("bound-github", "github");
        github.credentials =
            HashMap::from([("GITHUB_TOKEN".to_string(), "github-token".to_string())]);
        github.config.clear();
        create_provider_record(&store, "default", github)
            .await
            .unwrap();

        let result = resolve_provider_environment(
            &store,
            "default",
            &["my-google-cloud".to_string(), "bound-github".to_string()],
        )
        .await
        .unwrap();

        assert!(
            !result.contains_key("GCP_ADC_ACCESS_TOKEN"),
            "endpointless static credentials must be withheld"
        );
        assert!(
            !result
                .credential_expires_at_ms
                .contains_key("GCP_ADC_ACCESS_TOKEN"),
            "withheld static credentials must not retain expiry metadata"
        );
        assert!(
            !result
                .static_credential_keys
                .contains("GCP_ADC_ACCESS_TOKEN"),
            "withheld static credentials must not be classified as static"
        );
        assert!(
            !result
                .static_credential_bindings
                .contains_key("GCP_ADC_ACCESS_TOKEN"),
            "endpointless static credentials must not emit an invalid binding"
        );
        assert!(
            result.contains_key("GCE_METADATA_HOST"),
            "provider-generated non-secret GCP configuration must be retained"
        );

        assert_eq!(
            result.get("GITHUB_TOKEN"),
            Some(&"github-token".to_string()),
            "a valid provider must not be suppressed by an endpointless provider"
        );
        assert!(
            result.static_credential_keys.contains("GITHUB_TOKEN"),
            "the valid credential must retain its static classification"
        );
        assert!(
            result
                .static_credential_bindings
                .get("GITHUB_TOKEN")
                .is_some_and(|binding| !binding.endpoints.is_empty()),
            "the valid credential must retain its endpoint binding"
        );
    }

    #[tokio::test]
    async fn resolve_provider_env_withholds_undeclared_legacy_credentials() {
        let store = test_store().await;
        let mut legacy = provider_with_values("legacy-openai", "openai");
        legacy.credentials = HashMap::from([
            ("OPENAI_API_KEY".to_string(), "openai-key".to_string()),
            (
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "unrelated-secret".to_string(),
            ),
        ]);
        create_provider_record(&store, "default", legacy)
            .await
            .unwrap();

        let result =
            resolve_provider_environment(&store, "default", &["legacy-openai".to_string()])
                .await
                .unwrap();

        assert_eq!(
            result.get("OPENAI_API_KEY"),
            Some(&"openai-key".to_string())
        );
        assert!(
            result
                .static_credential_bindings
                .contains_key("OPENAI_API_KEY")
        );
        assert!(!result.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert!(
            !result
                .static_credential_bindings
                .contains_key("AWS_SECRET_ACCESS_KEY")
        );
    }

    #[tokio::test]
    async fn resolve_provider_env_withholds_undeclared_legacy_credential_handles() {
        let store = test_store().await;
        let config = openshell_core::Config::new(None).with_credential_drivers(["test-static"]);
        let credentials = crate::credentials::CredentialRuntime::from_config(&config).unwrap();
        let catalog = ProviderProfileSources::with_default_sources()
            .snapshot_catalog(&store, "default")
            .await
            .unwrap();
        create_provider_record_validating(
            &store,
            "default",
            &catalog,
            provider_with_credential_value(
                "legacy-openai-handle",
                "openai",
                "AWS_SECRET_ACCESS_KEY",
                "unrelated-secret",
            ),
            Some(&credentials),
        )
        .await
        .unwrap();

        let records = load_provider_environment_records(
            &store,
            "default",
            &["legacy-openai-handle".to_string()],
        )
        .await
        .unwrap();
        assert!(records[0].provider.credentials.is_empty());
        assert!(
            records[0]
                .provider
                .credential_handles
                .contains_key("AWS_SECRET_ACCESS_KEY")
        );

        let result =
            resolve_provider_environment_from_records_with_policy_bindings_and_credentials(
                &store,
                &catalog,
                &records,
                &HashMap::new(),
                &credentials,
                None,
            )
            .await
            .unwrap();
        assert!(!result.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert!(
            !result
                .static_credential_bindings
                .contains_key("AWS_SECRET_ACCESS_KEY")
        );
    }

    #[tokio::test]
    async fn resolve_provider_env_does_not_bind_alternate_upstream_keys_to_public_vendors() {
        let store = test_store().await;
        let cases = [
            (
                "alternate-openai",
                "openai",
                "OPENAI_API_KEY",
                "OPENAI_BASE_URL",
            ),
            (
                "alternate-anthropic",
                "anthropic",
                "ANTHROPIC_API_KEY",
                "ANTHROPIC_BASE_URL",
            ),
        ];
        for (name, provider_type, credential_key, base_url_key) in cases {
            let mut provider =
                provider_with_credential_value(name, provider_type, credential_key, "private-key");
            provider.config.insert(
                base_url_key.to_string(),
                "https://api.example.com/v1".to_string(),
            );
            create_provider_record(&store, "default", provider)
                .await
                .unwrap();
        }

        let result = resolve_provider_environment(
            &store,
            "default",
            &[
                "alternate-openai".to_string(),
                "alternate-anthropic".to_string(),
            ],
        )
        .await
        .unwrap();

        for credential_key in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"] {
            assert!(!result.contains_key(credential_key));
            assert!(
                !result
                    .static_credential_bindings
                    .contains_key(credential_key)
            );
        }
    }

    #[tokio::test]
    async fn resolve_provider_env_binds_endpointless_profile_from_policy() {
        let store = test_store().await;
        let mut google_cloud = google_cloud_provider(HashMap::from([(
            "project_id".to_string(),
            "sandbox-project".to_string(),
        )]));
        google_cloud.credentials = HashMap::from([(
            "GCP_ADC_ACCESS_TOKEN".to_string(),
            "google-token".to_string(),
        )]);
        create_provider_record(&store, "default", google_cloud)
            .await
            .unwrap();

        let provider_names = ["my-google-cloud".to_string()];
        let catalog = ProviderProfileSources::with_default_sources()
            .snapshot_catalog(&store, "default")
            .await
            .unwrap();
        let records = load_provider_environment_records(&store, "default", &provider_names)
            .await
            .unwrap();
        let policy_bindings = HashMap::from([(
            "my-google-cloud".to_string(),
            vec![StaticCredentialEndpointBinding {
                host: "storage.googleapis.com".to_string(),
                port: 443,
                path: "/**".to_string(),
            }],
        )]);

        let result = resolve_provider_environment_from_records_with_policy_bindings(
            &store,
            &catalog,
            &records,
            &policy_bindings,
        )
        .await
        .unwrap();

        assert_eq!(
            result.get("GCP_ADC_ACCESS_TOKEN"),
            Some(&"google-token".to_string())
        );
        assert_eq!(
            result
                .static_credential_bindings
                .get("GCP_ADC_ACCESS_TOKEN")
                .map(|binding| binding.endpoints.as_slice()),
            Some(policy_bindings["my-google-cloud"].as_slice())
        );
    }

    #[tokio::test]
    async fn resolve_provider_env_binds_endpointless_credential_handle_only_from_policy() {
        let store = test_store().await;
        let config = openshell_core::Config::new(None).with_credential_drivers(["test-static"]);
        let credentials = crate::credentials::CredentialRuntime::from_config(&config).unwrap();
        let catalog = ProviderProfileSources::with_default_sources()
            .snapshot_catalog(&store, "default")
            .await
            .unwrap();
        let mut google_cloud = google_cloud_provider(HashMap::from([(
            "project_id".to_string(),
            "sandbox-project".to_string(),
        )]));
        google_cloud.credentials = HashMap::from([(
            "GCP_ADC_ACCESS_TOKEN".to_string(),
            "google-token".to_string(),
        )]);
        create_provider_record_validating(
            &store,
            "default",
            &catalog,
            google_cloud,
            Some(&credentials),
        )
        .await
        .unwrap();

        let provider_names = ["my-google-cloud".to_string()];
        let records = load_provider_environment_records(&store, "default", &provider_names)
            .await
            .unwrap();
        assert!(records[0].provider.credentials.is_empty());
        assert!(
            records[0]
                .provider
                .credential_handles
                .contains_key("GCP_ADC_ACCESS_TOKEN")
        );

        let unbound =
            resolve_provider_environment_from_records_with_policy_bindings_and_credentials(
                &store,
                &catalog,
                &records,
                &HashMap::new(),
                &credentials,
                None,
            )
            .await
            .unwrap();
        assert!(!unbound.contains_key("GCP_ADC_ACCESS_TOKEN"));
        assert!(
            !unbound
                .static_credential_bindings
                .contains_key("GCP_ADC_ACCESS_TOKEN")
        );

        let policy_bindings = HashMap::from([(
            "my-google-cloud".to_string(),
            vec![StaticCredentialEndpointBinding {
                host: "storage.googleapis.com".to_string(),
                port: 443,
                path: "/**".to_string(),
            }],
        )]);
        let bound = resolve_provider_environment_from_records_with_policy_bindings_and_credentials(
            &store,
            &catalog,
            &records,
            &policy_bindings,
            &credentials,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            bound.get("GCP_ADC_ACCESS_TOKEN"),
            Some(&"google-token".to_string())
        );
        assert_eq!(
            bound
                .static_credential_bindings
                .get("GCP_ADC_ACCESS_TOKEN")
                .map(|binding| binding.endpoints.as_slice()),
            Some(policy_bindings["my-google-cloud"].as_slice())
        );
    }

    #[tokio::test]
    async fn resolve_provider_env_allows_static_provider_without_profile() {
        let store = test_store().await;
        create_provider_record(
            &store,
            "default",
            provider_with_values("static-provider", "unprofiled-static-api"),
        )
        .await
        .unwrap();

        let result =
            resolve_provider_environment(&store, "default", &["static-provider".to_string()])
                .await
                .unwrap();

        assert_eq!(result.get("API_TOKEN"), Some(&"token-123".to_string()));
        assert!(result.dynamic_credentials.is_empty());
        assert!(!result.static_credential_bindings.contains_key("API_TOKEN"));
    }

    #[tokio::test]
    async fn resolve_provider_env_rejects_unresolvable_credential_handle() {
        let store = test_store().await;
        let config = openshell_core::Config::new(None).with_credential_drivers(["test-static"]);
        let credentials = crate::credentials::CredentialRuntime::from_config(&config).unwrap();
        let catalog = ProviderProfileSources::with_default_sources()
            .snapshot_catalog(&store, "default")
            .await
            .unwrap();
        create_provider_record_validating(
            &store,
            "default",
            &catalog,
            provider_with_credential_value(
                "github-local",
                "github",
                "GITHUB_TOKEN",
                "github-token",
            ),
            Some(&credentials),
        )
        .await
        .unwrap();
        let other_credentials =
            crate::credentials::CredentialRuntime::from_config(&config).unwrap();

        let err = resolve_provider_environment_with_credentials(
            &store,
            &catalog,
            "default",
            &["github-local".to_string()],
            &other_credentials,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::NotFound);
        assert!(err.message().contains("credential handle"));
    }

    #[tokio::test]
    async fn resolve_provider_env_resolves_credential_handles_with_runtime() {
        let store = test_store().await;
        let config = openshell_core::Config::new(None).with_credential_drivers(["test-static"]);
        let credentials = crate::credentials::CredentialRuntime::from_config(&config).unwrap();
        let catalog = ProviderProfileSources::with_default_sources()
            .snapshot_catalog(&store, "default")
            .await
            .unwrap();
        create_provider_record_validating(
            &store,
            "default",
            &catalog,
            provider_with_credential_value(
                "github-local",
                "github",
                "GITHUB_TOKEN",
                "github-token",
            ),
            Some(&credentials),
        )
        .await
        .unwrap();

        let result = resolve_provider_environment_with_credentials(
            &store,
            &catalog,
            "default",
            &["github-local".to_string()],
            &credentials,
        )
        .await
        .unwrap();

        assert_eq!(
            result.get("GITHUB_TOKEN"),
            Some(&"github-token".to_string())
        );
        assert!(result.static_credential_keys.contains("GITHUB_TOKEN"));
        assert!(
            result
                .static_credential_bindings
                .get("GITHUB_TOKEN")
                .is_some_and(|binding| !binding.endpoints.is_empty())
        );
    }

    #[tokio::test]
    async fn resolve_provider_env_skips_expired_credentials_and_returns_expiry_metadata() {
        let store = test_store().await;
        let now_ms = crate::persistence::current_time_ms();
        let provider = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: "expiring-provider".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: "test".to_string(),
            credentials: [
                ("FRESH_TOKEN".to_string(), "fresh".to_string()),
                ("STALE_TOKEN".to_string(), "stale".to_string()),
            ]
            .into_iter()
            .collect(),
            config: HashMap::new(),
            credential_expires_at_ms: [
                ("FRESH_TOKEN".to_string(), now_ms + 60_000),
                ("STALE_TOKEN".to_string(), now_ms - 60_000),
            ]
            .into_iter()
            .collect(),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        };
        create_provider_record(&store, "default", provider)
            .await
            .unwrap();

        let result =
            resolve_provider_environment(&store, "default", &["expiring-provider".to_string()])
                .await
                .unwrap();
        assert_eq!(result.get("FRESH_TOKEN"), Some(&"fresh".to_string()));
        assert!(!result.contains_key("STALE_TOKEN"));
        assert_eq!(
            result.credential_expires_at_ms.get("FRESH_TOKEN"),
            Some(&(now_ms + 60_000))
        );
    }

    #[tokio::test]
    async fn resolve_provider_env_unknown_name_returns_error() {
        let store = test_store().await;
        let err = resolve_provider_environment(&store, "default", &["nonexistent".to_string()])
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("nonexistent"));
    }

    #[tokio::test]
    async fn resolve_provider_env_skips_invalid_credential_keys() {
        let store = test_store().await;
        let provider = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: "test-provider".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: "test".to_string(),
            credentials: [
                ("VALID_KEY".to_string(), "value".to_string()),
                ("nested.api_key".to_string(), "should-skip".to_string()),
                ("bad-key".to_string(), "should-skip".to_string()),
            ]
            .into_iter()
            .collect(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        };
        create_provider_record(&store, "default", provider)
            .await
            .unwrap();

        let result =
            resolve_provider_environment(&store, "default", &["test-provider".to_string()])
                .await
                .unwrap();
        assert_eq!(result.get("VALID_KEY"), Some(&"value".to_string()));
        assert!(!result.contains_key("nested.api_key"));
        assert!(!result.contains_key("bad-key"));
    }

    #[tokio::test]
    async fn resolve_provider_env_multiple_providers_merge() {
        let store = test_store().await;
        create_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "claude-local".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "claude".to_string(),
                credentials: std::iter::once((
                    "ANTHROPIC_API_KEY".to_string(),
                    "sk-abc".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();
        create_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "gitlab-local".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "gitlab".to_string(),
                credentials: std::iter::once(("GITLAB_TOKEN".to_string(), "glpat-xyz".to_string()))
                    .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let result = resolve_provider_environment(
            &store,
            "default",
            &["claude-local".to_string(), "gitlab-local".to_string()],
        )
        .await
        .unwrap();
        assert_eq!(result.get("ANTHROPIC_API_KEY"), Some(&"sk-abc".to_string()));
        assert_eq!(result.get("GITLAB_TOKEN"), Some(&"glpat-xyz".to_string()));
    }

    #[tokio::test]
    async fn resolve_provider_env_rejects_duplicate_credential_keys() {
        let store = test_store().await;
        create_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "provider-a".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "claude".to_string(),
                credentials: std::iter::once(("SHARED_KEY".to_string(), "first-value".to_string()))
                    .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();
        create_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "provider-b".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "gitlab".to_string(),
                credentials: std::iter::once((
                    "SHARED_KEY".to_string(),
                    "second-value".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let err = resolve_provider_environment(
            &store,
            "default",
            &["provider-a".to_string(), "provider-b".to_string()],
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("SHARED_KEY"));
        assert!(err.message().contains("provider-a"));
        assert!(err.message().contains("provider-b"));
    }

    #[tokio::test]
    async fn validate_provider_environment_keys_unique_includes_credential_handles() {
        let store = test_store().await;
        let config = openshell_core::Config::new(None).with_credential_drivers(["test-static"]);
        let credentials = crate::credentials::CredentialRuntime::from_config(&config).unwrap();
        let catalog = ProviderProfileSources::with_default_sources()
            .snapshot_catalog(&store, "default")
            .await
            .unwrap();
        create_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "provider-a".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    ..Default::default()
                }),
                r#type: "claude".to_string(),
                credentials: std::iter::once(("SHARED_KEY".to_string(), "first-value".to_string()))
                    .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: String::new(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();
        create_provider_record_validating(
            &store,
            "default",
            &catalog,
            provider_with_credential_value("provider-b", "gitlab", "SHARED_KEY", "second-value"),
            Some(&credentials),
        )
        .await
        .unwrap();

        let err = validate_provider_environment_keys_unique(
            &store,
            "default",
            &["provider-a".to_string(), "provider-b".to_string()],
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("SHARED_KEY"));
        assert!(err.message().contains("provider-a"));
        assert!(err.message().contains("provider-b"));
    }

    #[tokio::test]
    async fn provider_environment_rejects_plugin_config_credential_collision_in_both_orders() {
        let store = test_store().await;
        create_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "google-config".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "google-cloud".to_string(),
                credentials: std::iter::once((
                    "GCP_ACCESS_TOKEN".to_string(),
                    "google-token".to_string(),
                ))
                .collect(),
                config: std::iter::once(("project_id".to_string(), "config-project".to_string()))
                    .collect(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();
        create_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "static-credential".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "gitlab".to_string(),
                credentials: std::iter::once((
                    "GCP_PROJECT_ID".to_string(),
                    "credential-value".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let attachment_orders = [
            vec!["google-config".to_string(), "static-credential".to_string()],
            vec!["static-credential".to_string(), "google-config".to_string()],
        ];
        let mut messages = Vec::new();
        for providers in attachment_orders {
            let validation_error =
                validate_provider_environment_keys_unique(&store, "default", &providers)
                    .await
                    .unwrap_err();
            assert_eq!(validation_error.code(), Code::FailedPrecondition);

            let resolution_error = resolve_provider_environment(&store, "default", &providers)
                .await
                .unwrap_err();
            assert_eq!(resolution_error.code(), Code::FailedPrecondition);
            assert_eq!(validation_error.message(), resolution_error.message());
            assert!(resolution_error.message().contains("GCP_PROJECT_ID"));
            assert!(resolution_error.message().contains("static-credential"));
            assert!(resolution_error.message().contains("google-config"));
            messages.push(resolution_error.message().to_string());
        }
        assert_eq!(
            messages[0], messages[1],
            "collision rejection must not depend on attachment order"
        );
    }

    #[tokio::test]
    async fn resolve_provider_env_injects_vertex_agent_config() {
        let store = test_store().await;
        create_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "vertex-local".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "google-vertex-ai".to_string(),
                credentials: std::iter::once((
                    "GOOGLE_VERTEX_AI_TOKEN".to_string(),
                    "ya29.token".to_string(),
                ))
                .collect(),
                config: [
                    (
                        "VERTEX_AI_PROJECT_ID".to_string(),
                        "my-gcp-project".to_string(),
                    ),
                    ("VERTEX_AI_REGION".to_string(), "us-central1".to_string()),
                ]
                .into_iter()
                .collect(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let result = resolve_provider_environment(&store, "default", &["vertex-local".to_string()])
            .await
            .unwrap();

        // Credential still injected.
        assert_eq!(
            result.get("GOOGLE_VERTEX_AI_TOKEN"),
            Some(&"ya29.token".to_string())
        );
        // Static flags.
        assert!(!result.contains_key("CLAUDE_CODE_USE_VERTEX"));
        assert_eq!(
            result.get("GOOSE_PROVIDER"),
            Some(&"gcp_vertex_ai".to_string())
        );
        // Project ID derived vars.
        assert_eq!(
            result.get("ANTHROPIC_VERTEX_PROJECT_ID"),
            Some(&"my-gcp-project".to_string())
        );
        assert_eq!(
            result.get("GCP_PROJECT_ID"),
            Some(&"my-gcp-project".to_string())
        );
        assert_eq!(
            result.get("GOOGLE_CLOUD_PROJECT"),
            Some(&"my-gcp-project".to_string())
        );
        // Region derived vars.
        assert_eq!(
            result.get("CLOUD_ML_REGION"),
            Some(&"us-central1".to_string())
        );
        assert_eq!(result.get("GCP_LOCATION"), Some(&"us-central1".to_string()));
        assert_eq!(
            result.get("VERTEX_LOCATION"),
            Some(&"us-central1".to_string())
        );
    }

    #[tokio::test]
    async fn resolve_provider_env_vertex_never_injects_service_account_key() {
        let store = test_store().await;
        create_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "vertex-bootstrap".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "google-vertex-ai".to_string(),
                credentials: [
                    (
                        "GOOGLE_SERVICE_ACCOUNT_KEY".to_string(),
                        r#"{"type":"service_account","private_key":"secret"}"#.to_string(),
                    ),
                    (
                        "GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN".to_string(),
                        "ya29.short-lived".to_string(),
                    ),
                ]
                .into_iter()
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let result =
            resolve_provider_environment(&store, "default", &["vertex-bootstrap".to_string()])
                .await
                .unwrap();

        assert!(!result.contains_key("GOOGLE_SERVICE_ACCOUNT_KEY"));
        assert_eq!(
            result.get("GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN"),
            Some(&"ya29.short-lived".to_string())
        );
    }

    #[tokio::test]
    async fn resolve_provider_env_vertex_omits_agent_config_when_project_and_region_absent() {
        let store = test_store().await;
        create_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "vertex-no-config".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "google-vertex-ai".to_string(),
                credentials: std::iter::once((
                    "GOOGLE_VERTEX_AI_TOKEN".to_string(),
                    "ya29.token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let result =
            resolve_provider_environment(&store, "default", &["vertex-no-config".to_string()])
                .await
                .unwrap();

        // Static flags still present.
        assert!(!result.contains_key("CLAUDE_CODE_USE_VERTEX"));
        assert_eq!(
            result.get("GOOSE_PROVIDER"),
            Some(&"gcp_vertex_ai".to_string())
        );
        // Project ID and region derived vars are absent.
        assert!(!result.contains_key("ANTHROPIC_VERTEX_PROJECT_ID"));
        assert!(!result.contains_key("GCP_PROJECT_ID"));
        assert!(!result.contains_key("GOOGLE_CLOUD_PROJECT"));
        assert!(!result.contains_key("CLOUD_ML_REGION"));
        assert!(!result.contains_key("GCP_LOCATION"));
        assert!(!result.contains_key("VERTEX_LOCATION"));
    }

    #[tokio::test]
    async fn resolve_provider_env_vertex_credential_wins_over_agent_config_key() {
        // If a credential happens to share a name with one of the injected agent
        // config keys, the credential value takes precedence because the credential
        // loop runs first and entry().or_insert() does not overwrite.
        let store = test_store().await;
        create_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "vertex-collision".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "google-vertex-ai".to_string(),
                credentials: [
                    (
                        "GOOGLE_VERTEX_AI_TOKEN".to_string(),
                        "ya29.token".to_string(),
                    ),
                    // Same key as an injected static flag.
                    ("GOOSE_PROVIDER".to_string(), "custom-value".to_string()),
                ]
                .into_iter()
                .collect(),
                config: [
                    ("VERTEX_AI_PROJECT_ID".to_string(), "my-project".to_string()),
                    ("VERTEX_AI_REGION".to_string(), "us-east1".to_string()),
                ]
                .into_iter()
                .collect(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let result =
            resolve_provider_environment(&store, "default", &["vertex-collision".to_string()])
                .await
                .unwrap();

        // Profile-authoritative runtime projection withholds the undeclared
        // credential, so the provider plugin's declared config wins.
        assert_eq!(
            result.get("GOOSE_PROVIDER"),
            Some(&"gcp_vertex_ai".to_string())
        );
    }

    #[tokio::test]
    async fn resolve_provider_env_non_vertex_provider_does_not_inject_agent_config() {
        let store = test_store().await;
        create_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "openai-local".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "openai".to_string(),
                credentials: std::iter::once(("OPENAI_API_KEY".to_string(), "sk-test".to_string()))
                    .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let result = resolve_provider_environment(&store, "default", &["openai-local".to_string()])
            .await
            .unwrap();

        assert_eq!(result.get("OPENAI_API_KEY"), Some(&"sk-test".to_string()));
        assert!(!result.contains_key("CLAUDE_CODE_USE_VERTEX"));
        assert!(!result.contains_key("GOOSE_PROVIDER"));
        assert!(!result.contains_key("ANTHROPIC_VERTEX_PROJECT_ID"));
        assert!(!result.contains_key("GCP_PROJECT_ID"));
        assert!(!result.contains_key("GOOGLE_CLOUD_PROJECT"));
        assert!(!result.contains_key("CLOUD_ML_REGION"));
        assert!(!result.contains_key("GCP_LOCATION"));
        assert!(!result.contains_key("VERTEX_LOCATION"));
    }

    #[tokio::test]
    async fn update_provider_rejects_credential_key_collision_for_attached_sandbox() {
        let store = test_store().await;
        create_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "provider-a".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "outlook".to_string(),
                credentials: std::iter::once((
                    "MS_GRAPH_ACCESS_TOKEN".to_string(),
                    "graph-token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();
        create_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "provider-b".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "google-drive".to_string(),
                credentials: std::iter::once((
                    "GOOGLE_ACCESS_TOKEN".to_string(),
                    "google-token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();
        let sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sandbox-collision".to_string(),
                name: "collision".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            spec: Some(SandboxSpec {
                providers: vec!["provider-a".to_string(), "provider-b".to_string()],
                ..SandboxSpec::default()
            }),
            ..Default::default()
        };
        store.put_message(&sandbox).await.unwrap();

        let err = update_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "provider-b".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: String::new(),
                credentials: std::iter::once((
                    "MS_GRAPH_ACCESS_TOKEN".to_string(),
                    "wrong-token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("collision"));
        assert!(err.message().contains("MS_GRAPH_ACCESS_TOKEN"));
    }

    #[tokio::test]
    async fn update_provider_rejects_plugin_config_credential_collision() {
        let store = test_store().await;
        create_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "google-config".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "google-cloud".to_string(),
                credentials: std::iter::once((
                    "GCP_ACCESS_TOKEN".to_string(),
                    "google-token".to_string(),
                ))
                .collect(),
                config: std::iter::once(("project_id".to_string(), "config-project".to_string()))
                    .collect(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();
        create_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "credential-provider".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "gitlab".to_string(),
                credentials: std::iter::once((
                    "GITLAB_TOKEN".to_string(),
                    "gitlab-token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();
        store
            .put_message(&Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "sandbox-plugin-config-collision".to_string(),
                    name: "plugin-config-collision".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                spec: Some(SandboxSpec {
                    providers: vec![
                        "google-config".to_string(),
                        "credential-provider".to_string(),
                    ],
                    ..SandboxSpec::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();

        let err = update_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "credential-provider".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: String::new(),
                credentials: std::iter::once((
                    "GCP_PROJECT_ID".to_string(),
                    "credential-value".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("GCP_PROJECT_ID"));
        assert!(err.message().contains("credential-provider"));
        assert!(err.message().contains("google-config"));
    }

    #[tokio::test]
    async fn handler_flow_resolves_credentials_from_sandbox_providers() {
        use openshell_core::proto::{Sandbox, SandboxPhase, SandboxSpec};

        let store = test_store().await;

        create_provider_record(
            &store,
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "my-claude".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "claude".to_string(),
                credentials: std::iter::once((
                    "ANTHROPIC_API_KEY".to_string(),
                    "sk-test".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sandbox-001".to_string(),
                name: "test-sandbox".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            spec: Some(SandboxSpec {
                providers: vec!["my-claude".to_string()],
                ..SandboxSpec::default()
            }),
            status: None,
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        store.put_message(&sandbox).await.unwrap();

        let loaded = store
            .get_message::<Sandbox>("sandbox-001")
            .await
            .unwrap()
            .unwrap();
        let spec = loaded.spec.unwrap();
        let env = resolve_provider_environment(&store, "default", &spec.providers)
            .await
            .unwrap();

        assert_eq!(env.get("ANTHROPIC_API_KEY"), Some(&"sk-test".to_string()));
    }

    #[tokio::test]
    async fn handler_flow_returns_empty_when_no_providers() {
        use openshell_core::proto::{Sandbox, SandboxPhase, SandboxSpec};

        let store = test_store().await;

        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sandbox-002".to_string(),
                name: "empty-sandbox".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            spec: Some(SandboxSpec::default()),
            status: None,
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        store.put_message(&sandbox).await.unwrap();

        let loaded = store
            .get_message::<Sandbox>("sandbox-002")
            .await
            .unwrap()
            .unwrap();
        let spec = loaded.spec.unwrap();
        let env = resolve_provider_environment(&store, "default", &spec.providers)
            .await
            .unwrap();

        assert!(env.is_empty());
    }

    #[tokio::test]
    async fn handler_flow_returns_none_for_unknown_sandbox() {
        use openshell_core::proto::Sandbox;

        let store = test_store().await;
        let result = store.get_message::<Sandbox>("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn update_provider_validates_before_write() {
        let store = Arc::new(test_store().await);

        // Create a valid provider
        let provider = provider_with_values("test-validate-provider", "test-type");
        let created = create_provider_record(&store, "default", provider.clone())
            .await
            .unwrap();

        // Build update request with just the name and new credentials
        let mut update_req = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: "test-validate-provider".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: String::new(), // Empty type is ignored in update
            credentials: HashMap::new(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        };

        // Attempt to update with an oversized credential key (exceeds MAX_MAP_KEY_LEN)
        update_req.credentials.insert(
            "k".repeat(MAX_MAP_KEY_LEN + 1),
            "oversized-key-value".to_string(),
        );

        let result = update_provider_record(&store, "default", update_req).await;

        // Update should fail with InvalidArgument due to oversized key
        assert!(result.is_err(), "update with invalid data should fail");
        let err = result.unwrap_err();
        assert_eq!(
            err.code(),
            Code::InvalidArgument,
            "should fail validation with InvalidArgument"
        );
        assert!(
            err.message().contains("key"),
            "error message should mention key: {}",
            err.message()
        );

        // Verify database still contains the ORIGINAL valid provider (not the invalid one)
        let stored = store
            .get_message_by_name::<Provider>("default", "test-validate-provider")
            .await
            .unwrap()
            .expect("provider should still exist");

        assert_eq!(
            stored.object_id(),
            created.object_id(),
            "stored provider ID should match original"
        );
        assert_eq!(
            stored.credentials.len(),
            created.credentials.len(),
            "credentials count should not have changed"
        );
        assert!(
            !stored
                .credentials
                .contains_key(&"k".repeat(MAX_MAP_KEY_LEN + 1)),
            "oversized key should NOT be in database"
        );
    }

    #[tokio::test]
    async fn concurrent_create_provider_rejects_duplicate() {
        let store = Arc::new(test_store().await);

        let provider = provider_with_values("test-concurrent-provider", "test-type");

        // Spawn two concurrent creation attempts for the same provider
        let store1 = store.clone();
        let provider1 = provider.clone();
        let handle1 =
            tokio::spawn(
                async move { create_provider_record(&store1, "default", provider1).await },
            );

        let store2 = store.clone();
        let provider2 = provider.clone();
        let handle2 =
            tokio::spawn(
                async move { create_provider_record(&store2, "default", provider2).await },
            );

        // Wait for both to complete
        let result1 = handle1.await.unwrap();
        let result2 = handle2.await.unwrap();

        // Exactly one should succeed, one should fail with AlreadyExists
        let success_count = [&result1, &result2].iter().filter(|r| r.is_ok()).count();
        let already_exists_count = [&result1, &result2]
            .iter()
            .filter(|r| {
                r.as_ref()
                    .err()
                    .is_some_and(|e| e.code() == Code::AlreadyExists)
            })
            .count();

        assert_eq!(
            success_count, 1,
            "exactly one creation should succeed, got results: {result1:?} {result2:?}"
        );
        assert_eq!(
            already_exists_count, 1,
            "exactly one creation should fail with AlreadyExists, got results: {result1:?} {result2:?}"
        );

        // Verify the successful provider can be retrieved by name
        let created_provider = [result1, result2]
            .into_iter()
            .find_map(Result::ok)
            .expect("should have one successful creation");
        let retrieved = store
            .get_message_by_name::<Provider>("default", "test-concurrent-provider")
            .await
            .unwrap();
        assert!(
            retrieved.is_some(),
            "created provider should be retrievable by name"
        );
        assert_eq!(
            retrieved.unwrap().object_id(),
            created_provider.object_id(),
            "retrieved provider should match created provider"
        );
    }

    // ---- CAS (Client-driven optimistic concurrency) tests for UpdateProvider ----

    #[tokio::test]
    async fn update_provider_rejects_undeclared_profile_credential() {
        let state = test_server_state().await;
        handle_create_provider(
            &state,
            authed_request(CreateProviderRequest {
                provider: Some(provider_with_credential_value(
                    "profile-backed-openai",
                    "openai",
                    "OPENAI_API_KEY",
                    "sk-test",
                )),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let current = state
            .store
            .get_message_by_name::<Provider>("default", "profile-backed-openai")
            .await
            .unwrap()
            .unwrap();
        let mut update = current;
        update.credential_handles.clear();
        update.credentials.insert(
            "AWS_SECRET_ACCESS_KEY".to_string(),
            "unrelated-secret".to_string(),
        );

        let error = handle_update_provider(
            &state,
            authed_request(UpdateProviderRequest {
                provider: Some(update),
                credential_expires_at_ms: HashMap::new(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), Code::InvalidArgument);
        assert!(error.message().contains("AWS_SECRET_ACCESS_KEY"));
    }

    #[tokio::test]
    async fn update_provider_rejects_deleting_required_profile_credential() {
        let state = test_server_state().await;
        handle_create_provider(
            &state,
            authed_request(CreateProviderRequest {
                provider: Some(provider_with_credential_value(
                    "required-openai",
                    "openai",
                    "OPENAI_API_KEY",
                    "sk-test",
                )),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let current = state
            .store
            .get_message_by_name::<Provider>("default", "required-openai")
            .await
            .unwrap()
            .unwrap();
        let mut update = current;
        update.credential_handles.clear();
        update
            .credentials
            .insert("OPENAI_API_KEY".to_string(), String::new());

        let error = handle_update_provider(
            &state,
            authed_request(UpdateProviderRequest {
                provider: Some(update),
                credential_expires_at_ms: HashMap::new(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), Code::InvalidArgument);
        assert!(error.message().contains("requires static credentials"));
    }

    #[tokio::test]
    async fn update_provider_client_driven_cas_succeeds_with_correct_version() {
        let state = test_server_state().await;

        // Create a provider
        let mut provider =
            provider_with_credential_value("test-provider", "openai", "OPENAI_API_KEY", "sk-test");
        provider.metadata.as_mut().unwrap().id = String::new();
        handle_create_provider(
            &state,
            authed_request(CreateProviderRequest {
                provider: Some(provider.clone()),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        // Fetch the provider to get its current resource_version
        let current = state
            .store
            .get_message_by_name::<Provider>("default", "test-provider")
            .await
            .unwrap()
            .unwrap();
        let current_version = current.metadata.as_ref().unwrap().resource_version;

        // Prepare an update with the correct resource_version
        let mut updated_provider = current.clone();
        updated_provider.credential_handles.clear();
        updated_provider
            .config
            .insert("NEW_CONFIG".to_string(), "new-value".to_string());
        updated_provider.metadata.as_mut().unwrap().resource_version = current_version;

        // Update should succeed
        let response = handle_update_provider(
            &state,
            authed_request(UpdateProviderRequest {
                provider: Some(updated_provider.clone()),
                credential_expires_at_ms: HashMap::new(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(
            response.provider.as_ref().unwrap().object_name(),
            "test-provider"
        );
        assert_eq!(
            response
                .provider
                .as_ref()
                .unwrap()
                .metadata
                .as_ref()
                .unwrap()
                .resource_version,
            current_version + 1
        );
        assert!(response.provider.unwrap().config.contains_key("NEW_CONFIG"));
    }

    #[tokio::test]
    async fn update_provider_client_driven_cas_rejects_stale_version() {
        let state = test_server_state().await;

        // Create a provider
        let mut provider =
            provider_with_credential_value("test-provider", "openai", "OPENAI_API_KEY", "sk-test");
        provider.metadata.as_mut().unwrap().id = String::new();
        handle_create_provider(
            &state,
            authed_request(CreateProviderRequest {
                provider: Some(provider.clone()),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        // Fetch the current state
        let current = state
            .store
            .get_message_by_name::<Provider>("default", "test-provider")
            .await
            .unwrap()
            .unwrap();
        let current_version = current.metadata.as_ref().unwrap().resource_version;

        // Prepare an update with a stale resource_version
        let mut stale_provider = current.clone();
        stale_provider.credential_handles.clear();
        stale_provider
            .config
            .insert("NEW_CONFIG".to_string(), "new-value".to_string());
        stale_provider.metadata.as_mut().unwrap().resource_version = 99; // stale version

        // Update should fail with ABORTED
        let err = handle_update_provider(
            &state,
            authed_request(UpdateProviderRequest {
                provider: Some(stale_provider),
                credential_expires_at_ms: HashMap::new(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::Aborted);
        assert!(
            err.message().contains("modified concurrently")
                || err.message().contains("resource_version"),
            "error message should mention concurrency conflict: {}",
            err.message()
        );

        // Verify the provider was not modified
        let unchanged = state
            .store
            .get_message_by_name::<Provider>("default", "test-provider")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            unchanged.metadata.as_ref().unwrap().resource_version,
            current_version
        );
        assert!(!unchanged.config.contains_key("NEW_CONFIG"));
    }

    #[tokio::test]
    async fn update_provider_stale_version_does_not_overwrite_stored_credential() {
        let mut state = test_server_state().await;
        let config = state
            .config
            .clone()
            .with_credential_drivers(["test-static"]);
        let credentials = crate::credentials::CredentialRuntime::from_config(&config).unwrap();
        let state_mut = Arc::get_mut(&mut state).unwrap();
        state_mut.config = config;
        state_mut.credentials = credentials;

        handle_create_provider(
            &state,
            authed_request(CreateProviderRequest {
                provider: Some(provider_with_credential_value(
                    "openai-local",
                    "openai",
                    "OPENAI_API_KEY",
                    "sk-first",
                )),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let current = state
            .store
            .get_message_by_name::<Provider>("default", "openai-local")
            .await
            .unwrap()
            .unwrap();
        let mut stale_provider = current.clone();
        stale_provider.credential_handles.clear();
        stale_provider
            .credentials
            .insert("OPENAI_API_KEY".to_string(), "sk-stale".to_string());
        stale_provider.metadata.as_mut().unwrap().resource_version = 99;

        let err = handle_update_provider(
            &state,
            authed_request(UpdateProviderRequest {
                provider: Some(stale_provider),
                credential_expires_at_ms: HashMap::new(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), Code::Aborted);

        let catalog = ProviderProfileSources::with_default_sources()
            .snapshot_catalog(state.store.as_ref(), "default")
            .await
            .unwrap();
        let resolved = resolve_provider_environment_with_credentials(
            state.store.as_ref(),
            &catalog,
            "default",
            &["openai-local".to_string()],
            &state.credentials,
        )
        .await
        .unwrap();
        assert_eq!(
            resolved.get("OPENAI_API_KEY"),
            Some(&"sk-first".to_string())
        );
    }

    #[tokio::test]
    async fn update_provider_concurrent_updates_with_stale_versions() {
        use std::sync::Arc;

        let state = Arc::new(test_server_state().await);

        // Create a provider
        let mut provider =
            provider_with_credential_value("test-provider", "openai", "OPENAI_API_KEY", "sk-test");
        provider.metadata.as_mut().unwrap().id = String::new();
        handle_create_provider(
            &state,
            authed_request(CreateProviderRequest {
                provider: Some(provider.clone()),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        // All three clients fetch the provider and see the same version
        let initial = state
            .store
            .get_message_by_name::<Provider>("default", "test-provider")
            .await
            .unwrap()
            .unwrap();
        let initial_version = initial.metadata.as_ref().unwrap().resource_version;

        // Launch 3 concurrent updates, all using the same initial version
        let mut handles = vec![];
        for i in 0..3 {
            let state_clone = Arc::clone(&state);
            let mut updated = initial.clone();
            updated.credential_handles.clear();
            updated
                .config
                .insert(format!("KEY_{i}"), format!("value-{i}"));
            updated.metadata.as_mut().unwrap().resource_version = initial_version;

            let handle = tokio::spawn(async move {
                handle_update_provider(
                    &state_clone,
                    authed_request(UpdateProviderRequest {
                        provider: Some(updated),
                        credential_expires_at_ms: HashMap::new(),
                        workspace: "default".to_string(),
                    }),
                )
                .await
            });
            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        // Only one should succeed; others should get ABORTED
        let successes = results.iter().filter(|r| r.is_ok()).count();
        let aborted_conflicts = results
            .iter()
            .filter(|r| r.as_ref().err().is_some_and(|e| e.code() == Code::Aborted))
            .count();

        assert_eq!(
            successes, 1,
            "exactly one update should succeed with client-driven CAS"
        );
        assert_eq!(
            aborted_conflicts, 2,
            "two updates should fail with ABORTED due to stale version"
        );

        // Final provider should have exactly 1 new credential key and resource_version = initial_version + 1
        let final_provider = state
            .store
            .get_message_by_name::<Provider>("default", "test-provider")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            final_provider.metadata.as_ref().unwrap().resource_version,
            initial_version + 1
        );

        // Exactly one of KEY_0, KEY_1, or KEY_2 should be present.
        let new_keys_count = (0..3)
            .filter(|i| final_provider.config.contains_key(&format!("KEY_{i}")))
            .count();
        assert_eq!(new_keys_count, 1);
    }

    #[tokio::test]
    async fn configure_aws_sts_succeeds_without_feature_gate() {
        let state = test_server_state().await;

        create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "my-aws-v2".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "aws".to_string(),
                credentials: std::iter::once((
                    "AWS_ACCESS_KEY_ID".to_string(),
                    "placeholder".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let response = handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "my-aws-v2".to_string(),
                credential_key: "AWS_ACCESS_KEY_ID".to_string(),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32,
                material: HashMap::from([(
                    "role_arn".to_string(),
                    "arn:aws:iam::123456789012:role/Test".to_string(),
                )]),
                secret_material_keys: Vec::new(),
                expires_at_ms: None,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .status
        .expect("status");

        assert_eq!(response.credential_key, "AWS_ACCESS_KEY_ID");
        assert_eq!(
            response.strategy,
            ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32
        );
    }

    #[tokio::test]
    async fn configure_aws_sts_rejects_endpoint_override_material() {
        let state = test_server_state().await;
        create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "aws-endpoint-override".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "aws".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let err = handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "aws-endpoint-override".to_string(),
                credential_key: "AWS_ACCESS_KEY_ID".to_string(),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32,
                material: HashMap::from([
                    (
                        "role_arn".to_string(),
                        "arn:aws:iam::123456789012:role/Test".to_string(),
                    ),
                    (
                        "sts_endpoint_url".to_string(),
                        "http://127.0.0.1:1/".to_string(),
                    ),
                ]),
                secret_material_keys: Vec::new(),
                expires_at_ms: None,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("sts_endpoint_url"));

        // The rejected configuration must not leave a refresh state behind.
        let provider = state
            .store
            .get_message_by_name::<Provider>("default", "aws-endpoint-override")
            .await
            .unwrap()
            .unwrap();
        assert!(
            crate::provider_refresh::get_refresh_state(
                state.store.as_ref(),
                "default",
                provider.object_id(),
                "AWS_ACCESS_KEY_ID",
            )
            .await
            .unwrap()
            .is_none()
        );
    }

    #[tokio::test]
    async fn configure_aws_sts_rejects_partial_source_credentials() {
        let state = test_server_state().await;
        create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "aws-partial-source".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "aws".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        // aws_access_key_id without its secret half must be rejected rather than
        // silently falling back to the gateway's ambient identity.
        let err = handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "aws-partial-source".to_string(),
                credential_key: "AWS_ACCESS_KEY_ID".to_string(),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32,
                material: HashMap::from([
                    (
                        "role_arn".to_string(),
                        "arn:aws:iam::123456789012:role/Test".to_string(),
                    ),
                    ("aws_access_key_id".to_string(), "AKIATESTKEY".to_string()),
                ]),
                secret_material_keys: Vec::new(),
                expires_at_ms: None,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("both be set or both omitted"));
    }

    #[tokio::test]
    async fn configure_aws_sts_rejects_session_token_without_pair() {
        let state = test_server_state().await;
        create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "aws-lone-session".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "aws".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let err = handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "aws-lone-session".to_string(),
                credential_key: "AWS_ACCESS_KEY_ID".to_string(),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32,
                material: HashMap::from([
                    (
                        "role_arn".to_string(),
                        "arn:aws:iam::123456789012:role/Test".to_string(),
                    ),
                    (
                        "aws_session_token".to_string(),
                        "temp-session-token".to_string(),
                    ),
                ]),
                secret_material_keys: vec!["aws_session_token".to_string()],
                expires_at_ms: None,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("aws_session_token requires"));
    }

    #[tokio::test]
    async fn configure_aws_sts_persists_resolved_additional_output_keys() {
        let state = test_server_state().await;
        create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "aws-outputs".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "aws".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "aws-outputs".to_string(),
                credential_key: "AWS_ACCESS_KEY_ID".to_string(),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32,
                material: HashMap::from([(
                    "role_arn".to_string(),
                    "arn:aws:iam::123456789012:role/Test".to_string(),
                )]),
                secret_material_keys: Vec::new(),
                expires_at_ms: None,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let provider = state
            .store
            .get_message_by_name::<Provider>("default", "aws-outputs")
            .await
            .unwrap()
            .unwrap();
        let stored = crate::provider_refresh::get_refresh_state(
            state.store.as_ref(),
            "default",
            provider.object_id(),
            "AWS_ACCESS_KEY_ID",
        )
        .await
        .unwrap()
        .expect("refresh state should exist");

        assert_eq!(
            stored.additional_output_keys.get("secret_access_key"),
            Some(&"AWS_SECRET_ACCESS_KEY".to_string())
        );
        assert_eq!(
            stored.additional_output_keys.get("session_token"),
            Some(&"AWS_SESSION_TOKEN".to_string())
        );
    }

    #[tokio::test]
    async fn update_provider_rejects_gateway_refresh_primary_and_additional_output_keys() {
        let state = test_server_state().await;
        let original_credentials = HashMap::from([
            (
                "AWS_ACCESS_KEY_ID".to_string(),
                "original-access-key".to_string(),
            ),
            (
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "original-secret-key".to_string(),
            ),
            (
                "AWS_SESSION_TOKEN".to_string(),
                "original-session-token".to_string(),
            ),
        ]);
        let provider = create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    name: "aws-update-guard".to_string(),
                    workspace: "default".to_string(),
                    ..Default::default()
                }),
                r#type: "aws".to_string(),
                credentials: original_credentials.clone(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "aws-update-guard".to_string(),
                credential_key: "AWS_ACCESS_KEY_ID".to_string(),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32,
                material: HashMap::from([(
                    "role_arn".to_string(),
                    "arn:aws:iam::123456789012:role/Test".to_string(),
                )]),
                secret_material_keys: Vec::new(),
                expires_at_ms: None,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        for key in [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
        ] {
            for value in ["replacement", ""] {
                let err = handle_update_provider(
                    &state,
                    authed_request(UpdateProviderRequest {
                        provider: Some(Provider {
                            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                                name: "aws-update-guard".to_string(),
                                ..Default::default()
                            }),
                            credentials: HashMap::from([(key.to_string(), value.to_string())]),
                            ..Default::default()
                        }),
                        credential_expires_at_ms: HashMap::new(),
                        workspace: "default".to_string(),
                    }),
                )
                .await
                .unwrap_err();
                assert_eq!(err.code(), Code::FailedPrecondition);
                assert!(err.message().contains("provider refresh"));
                assert!(err.message().contains(key));
            }
        }

        let unchanged = state
            .store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.credentials, original_credentials);
    }

    #[tokio::test]
    async fn configure_aws_sts_requires_profile_declaring_the_refresh() {
        let state = test_server_state().await;
        // A generic provider has no profile, so it declares no STS refresh
        // binding. STS must not be configurable against it.
        create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "generic-no-profile".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "generic".to_string(),
                credentials: std::iter::once((
                    "AWS_ACCESS_KEY_ID".to_string(),
                    "placeholder".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let err = handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "generic-no-profile".to_string(),
                credential_key: "AWS_ACCESS_KEY_ID".to_string(),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32,
                material: HashMap::from([(
                    "role_arn".to_string(),
                    "arn:aws:iam::123456789012:role/Test".to_string(),
                )]),
                secret_material_keys: Vec::new(),
                expires_at_ms: None,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("provider profile"));
    }

    #[tokio::test]
    async fn configure_aws_sts_rejects_non_canonical_credential_key() {
        let state = test_server_state().await;
        create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "aws-wrong-key".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "aws".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        // AWS_SECRET_ACCESS_KEY is a co-managed output, not the STS primary. The
        // profile declares no refresh on it, so STS cannot be pinned there.
        let err = handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "aws-wrong-key".to_string(),
                credential_key: "AWS_SECRET_ACCESS_KEY".to_string(),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32,
                material: HashMap::from([(
                    "role_arn".to_string(),
                    "arn:aws:iam::123456789012:role/Test".to_string(),
                )]),
                secret_material_keys: Vec::new(),
                expires_at_ms: None,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("AWS_ACCESS_KEY_ID"));
    }

    #[tokio::test]
    async fn active_provider_environment_keys_include_additional_output_keys() {
        let state = test_server_state().await;
        create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "aws-env".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "aws".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();
        let provider = state
            .store
            .get_message_by_name::<Provider>("default", "aws-env")
            .await
            .unwrap()
            .unwrap();

        // A configured-but-not-yet-minted STS refresh: no minted values are in
        // provider.credentials yet, but the reserved keys must still surface.
        let refresh_state = crate::provider_refresh::new_refresh_state(
            &provider,
            "default",
            "AWS_ACCESS_KEY_ID",
            crate::provider_refresh::NewRefreshStateConfig {
                additional_output_keys: HashMap::from([
                    (
                        "secret_access_key".to_string(),
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                    ),
                    ("session_token".to_string(), "AWS_SESSION_TOKEN".to_string()),
                ]),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
                material: HashMap::new(),
                secret_material_keys: Vec::new(),
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before_seconds: 0,
                max_lifetime_seconds: 0,
            },
        )
        .unwrap();
        crate::provider_refresh::put_refresh_state(state.store.as_ref(), &refresh_state)
            .await
            .unwrap();

        let catalog = ProviderProfileSources::with_default_sources()
            .snapshot_catalog(state.store.as_ref(), "default")
            .await
            .unwrap();
        let keys = active_provider_environment_keys(state.store.as_ref(), &catalog, &provider, 0)
            .await
            .unwrap();
        assert!(keys.contains(&"AWS_ACCESS_KEY_ID".to_string()));
        assert!(keys.contains(&"AWS_SECRET_ACCESS_KEY".to_string()));
        assert!(keys.contains(&"AWS_SESSION_TOKEN".to_string()));
    }

    #[tokio::test]
    async fn configure_aws_sts_validates_additional_credential_key_collision() {
        let state = test_server_state().await;

        let mut existing_provider = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: "existing-aws-provider".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: "aws".to_string(),
            credentials: HashMap::new(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        };
        existing_provider.credentials.insert(
            "AWS_SECRET_ACCESS_KEY".to_string(),
            "existing-key".to_string(),
        );
        create_provider_record(state.store.as_ref(), "default", existing_provider)
            .await
            .unwrap();

        let new_provider = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: "new-aws-provider".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: "aws".to_string(),
            credentials: std::iter::once((
                "AWS_ACCESS_KEY_ID".to_string(),
                "placeholder".to_string(),
            ))
            .collect(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        };
        create_provider_record(state.store.as_ref(), "default", new_provider)
            .await
            .unwrap();

        state
            .store
            .put_message(&Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "sandbox-aws-configure-collision".to_string(),
                    name: "aws-configure-collision".to_string(),
                    created_at_ms: 1,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                spec: Some(SandboxSpec {
                    providers: vec![
                        "existing-aws-provider".to_string(),
                        "new-aws-provider".to_string(),
                    ],
                    ..SandboxSpec::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();

        let err = handle_configure_provider_refresh(
            &state,
            authed_request(ConfigureProviderRefreshRequest {
                provider: "new-aws-provider".to_string(),
                credential_key: "AWS_ACCESS_KEY_ID".to_string(),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32,
                material: HashMap::from([(
                    "role_arn".to_string(),
                    "arn:aws:iam::123456789012:role/Test".to_string(),
                )]),
                secret_material_keys: Vec::new(),
                expires_at_ms: None,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("AWS_SECRET_ACCESS_KEY"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_configure_aws_sts_reserves_key_exactly_once() {
        let state = test_server_state().await;
        for name in ["aws-a", "aws-b"] {
            create_provider_record(
                state.store.as_ref(),
                "default",
                Provider {
                    metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                        id: String::new(),
                        name: name.to_string(),
                        created_at_ms: 0,
                        labels: HashMap::new(),
                        resource_version: 0,
                        annotations: HashMap::new(),
                        workspace: "default".to_string(),
                        deletion_timestamp_ms: 0,
                    }),
                    r#type: "aws".to_string(),
                    credentials: HashMap::new(),
                    config: HashMap::new(),
                    credential_expires_at_ms: HashMap::new(),
                    profile_workspace: "default".to_string(),
                    credential_handles: HashMap::new(),
                },
            )
            .await
            .unwrap();
        }

        // Both providers are attached to the same sandbox, so their minted AWS
        // credential env keys share a namespace and cannot both be reserved.
        state
            .store
            .put_message(&Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "sandbox-concurrent-configure".to_string(),
                    name: "concurrent-configure".to_string(),
                    created_at_ms: 1,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                spec: Some(SandboxSpec {
                    providers: vec!["aws-a".to_string(), "aws-b".to_string()],
                    ..SandboxSpec::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();

        let configure = |provider: &str| {
            authed_request(ConfigureProviderRefreshRequest {
                provider: provider.to_string(),
                credential_key: "AWS_ACCESS_KEY_ID".to_string(),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole as i32,
                material: HashMap::from([(
                    "role_arn".to_string(),
                    "arn:aws:iam::123456789012:role/Test".to_string(),
                )]),
                secret_material_keys: Vec::new(),
                expires_at_ms: None,
                workspace: "default".to_string(),
            })
        };

        let (result_a, result_b) = tokio::join!(
            handle_configure_provider_refresh(&state, configure("aws-a")),
            handle_configure_provider_refresh(&state, configure("aws-b")),
        );

        // Exactly one configuration wins; the other is rejected as a collision
        // rather than both reserving the same key.
        let ok_count = [&result_a, &result_b].iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            ok_count,
            1,
            "exactly one concurrent configure should reserve the key; got a={:?} b={:?}",
            result_a.as_ref().map(|_| ()),
            result_b.as_ref().map(|_| ())
        );
        let err = [result_a, result_b]
            .into_iter()
            .find_map(Result::err)
            .expect("one configure must fail");
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    fn google_cloud_provider(config: HashMap<String, String>) -> Provider {
        Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: "my-google-cloud".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: "google-cloud".to_string(),
            credentials: HashMap::new(),
            config,
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        }
    }

    #[test]
    fn inject_gcp_env_sets_metadata_host() {
        use openshell_core::google_cloud;
        let provider = google_cloud_provider(HashMap::new());
        let mut env = HashMap::new();
        openshell_providers::ProviderRegistry::new().inject_env(&provider, &mut env);
        assert_eq!(
            env.get("GCE_METADATA_HOST").map(String::as_str),
            Some(google_cloud::METADATA_HOST),
        );
        assert!(
            !env.contains_key("CLAUDE_CODE_USE_VERTEX"),
            "CLAUDE_CODE_USE_VERTEX is synthetic, should not be injected here"
        );
    }

    #[test]
    fn inject_gcp_env_propagates_project_id() {
        use openshell_core::google_cloud;
        let provider = google_cloud_provider(HashMap::from([(
            "project_id".to_string(),
            "my-project".to_string(),
        )]));
        let mut env = HashMap::new();
        openshell_providers::ProviderRegistry::new().inject_env(&provider, &mut env);
        for var in google_cloud::PROJECT_ID_ENV_VARS {
            assert_eq!(
                env.get(*var).map(String::as_str),
                Some("my-project"),
                "{var} should be set to project_id config value"
            );
        }
    }

    #[test]
    fn inject_gcp_env_propagates_region() {
        use openshell_core::google_cloud;
        let provider = google_cloud_provider(HashMap::from([(
            "region".to_string(),
            "us-central1".to_string(),
        )]));
        let mut env = HashMap::new();
        openshell_providers::ProviderRegistry::new().inject_env(&provider, &mut env);
        for var in google_cloud::REGION_ENV_VARS {
            assert_eq!(
                env.get(*var).map(String::as_str),
                Some("us-central1"),
                "{var} should be set to region config value"
            );
        }
    }

    #[test]
    fn inject_gcp_env_propagates_service_account_email() {
        use openshell_core::google_cloud;
        let provider = google_cloud_provider(HashMap::from([(
            "service_account_email".to_string(),
            "sa@proj.iam.gserviceaccount.com".to_string(),
        )]));
        let mut env = HashMap::new();
        openshell_providers::ProviderRegistry::new().inject_env(&provider, &mut env);
        for var in google_cloud::SERVICE_ACCOUNT_EMAIL_ENV_VARS {
            assert_eq!(
                env.get(*var).map(String::as_str),
                Some("sa@proj.iam.gserviceaccount.com"),
                "{var} should be set to service_account_email config value"
            );
        }
    }

    #[test]
    fn inject_gcp_env_does_not_overwrite_existing_values() {
        let provider = google_cloud_provider(HashMap::from([(
            "project_id".to_string(),
            "from-config".to_string(),
        )]));
        let mut env = HashMap::from([("GCP_PROJECT_ID".to_string(), "user-override".to_string())]);
        openshell_providers::ProviderRegistry::new().inject_env(&provider, &mut env);
        assert_eq!(
            env.get("GCP_PROJECT_ID").map(String::as_str),
            Some("user-override"),
            "user-provided value should not be overwritten"
        );
    }

    #[test]
    fn inject_non_gcp_provider_does_nothing() {
        let provider = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: "github".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: "github".to_string(),
            credentials: HashMap::new(),
            config: HashMap::from([("project_id".to_string(), "should-be-ignored".to_string())]),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        };
        let mut env = HashMap::new();
        openshell_providers::ProviderRegistry::new().inject_env(&provider, &mut env);
        assert!(
            env.is_empty(),
            "non-GCP provider should not inject any env vars"
        );
    }

    #[tokio::test]
    async fn provider_crud_is_workspace_isolated() {
        use openshell_core::proto::{
            CreateProviderRequest, CreateWorkspaceRequest, DeleteProviderRequest,
            GetProviderRequest, ListProvidersRequest,
        };

        let state = test_server_state().await;

        // Create a second workspace "beta".
        crate::grpc::workspace::handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                name: "beta".to_string(),
                labels: HashMap::new(),
            }),
        )
        .await
        .unwrap();

        // Create same-named provider in each workspace via handlers.
        let make_provider = || Provider {
            metadata: None,
            r#type: "pypi".to_string(),
            credentials: HashMap::new(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: String::new(),
            credential_handles: HashMap::new(),
        };

        let created_default = handle_create_provider(
            &state,
            authed_request(CreateProviderRequest {
                provider: Some({
                    let mut p = make_provider();
                    p.metadata = Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                        id: String::new(),
                        name: "shared-name".to_string(),
                        created_at_ms: 0,
                        labels: HashMap::new(),
                        resource_version: 0,
                        annotations: HashMap::new(),
                        workspace: String::new(),
                        deletion_timestamp_ms: 0,
                    });
                    p
                }),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        let default_id = created_default
            .provider
            .as_ref()
            .unwrap()
            .object_id()
            .to_string();

        let created_beta = handle_create_provider(
            &state,
            authed_request(CreateProviderRequest {
                provider: Some({
                    let mut p = make_provider();
                    p.metadata = Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                        id: String::new(),
                        name: "shared-name".to_string(),
                        created_at_ms: 0,
                        labels: HashMap::new(),
                        resource_version: 0,
                        annotations: HashMap::new(),
                        workspace: String::new(),
                        deletion_timestamp_ms: 0,
                    });
                    p
                }),
                workspace: "beta".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        let beta_id = created_beta
            .provider
            .as_ref()
            .unwrap()
            .object_id()
            .to_string();

        assert_ne!(default_id, beta_id);

        // Get in each workspace returns the correct provider.
        let got = handle_get_provider(
            &state,
            authed_request(GetProviderRequest {
                name: "shared-name".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(got.provider.as_ref().unwrap().object_id(), default_id);

        let got = handle_get_provider(
            &state,
            authed_request(GetProviderRequest {
                name: "shared-name".to_string(),
                workspace: "beta".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(got.provider.as_ref().unwrap().object_id(), beta_id);

        // List is workspace-scoped.
        let listed = handle_list_providers(
            &state,
            authed_request(ListProvidersRequest {
                limit: 100,
                offset: 0,
                workspace: "default".to_string(),
                all_workspaces: false,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(listed.providers.len(), 1);
        assert_eq!(listed.providers[0].object_id(), default_id);

        let listed = handle_list_providers(
            &state,
            authed_request(ListProvidersRequest {
                limit: 100,
                offset: 0,
                workspace: "beta".to_string(),
                all_workspaces: false,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(listed.providers.len(), 1);
        assert_eq!(listed.providers[0].object_id(), beta_id);

        // Delete in "default" does not affect "beta".
        let deleted = handle_delete_provider(
            &state,
            authed_request(DeleteProviderRequest {
                name: "shared-name".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(deleted.deleted);

        let listed = handle_list_providers(
            &state,
            authed_request(ListProvidersRequest {
                limit: 100,
                offset: 0,
                workspace: "default".to_string(),
                all_workspaces: false,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(listed.providers.is_empty());

        let got = handle_get_provider(
            &state,
            authed_request(GetProviderRequest {
                name: "shared-name".to_string(),
                workspace: "beta".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(got.provider.as_ref().unwrap().object_id(), beta_id);

        // all_workspaces returns providers from all workspaces.
        // Re-create the "default" provider.
        handle_create_provider(
            &state,
            authed_request(CreateProviderRequest {
                provider: Some({
                    let mut p = make_provider();
                    p.metadata = Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                        id: String::new(),
                        name: "provider-d".to_string(),
                        created_at_ms: 0,
                        labels: HashMap::new(),
                        resource_version: 0,
                        annotations: HashMap::new(),
                        workspace: String::new(),
                        deletion_timestamp_ms: 0,
                    });
                    p
                }),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let listed = handle_list_providers(
            &state,
            authed_request(ListProvidersRequest {
                limit: 100,
                offset: 0,
                workspace: String::new(),
                all_workspaces: true,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(listed.providers.len(), 2);

        // all_workspaces with non-empty workspace is rejected.
        let err = handle_list_providers(
            &state,
            authed_request(ListProvidersRequest {
                limit: 100,
                offset: 0,
                workspace: "default".to_string(),
                all_workspaces: true,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn platform_provider_profile_operations_require_platform_admin() {
        let mut state = test_server_state().await;
        Arc::get_mut(&mut state).unwrap().admin_role = "required-platform-admin".to_string();

        let catalog_error = handle_list_provider_profiles(
            &state,
            authed_request(ListProviderProfilesRequest {
                workspace: String::new(),
                ..ListProviderProfilesRequest::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(catalog_error.code(), Code::PermissionDenied);
        assert!(
            catalog_error
                .message()
                .contains("platform admin role required")
        );

        let get_error = handle_get_provider_profile(
            &state,
            authed_request(GetProviderProfileRequest {
                id: "nonexistent".to_string(),
                workspace: String::new(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(get_error.code(), Code::PermissionDenied);
        assert!(get_error.message().contains("platform admin role required"));

        let import_error = handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                workspace: String::new(),
                profiles: Vec::new(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(import_error.code(), Code::PermissionDenied);
        assert!(
            import_error
                .message()
                .contains("platform admin role required")
        );

        let update_error = handle_update_provider_profiles(
            &state,
            authed_request(UpdateProviderProfilesRequest {
                id: "nonexistent".to_string(),
                workspace: String::new(),
                ..UpdateProviderProfilesRequest::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(update_error.code(), Code::PermissionDenied);
        assert!(
            update_error
                .message()
                .contains("platform admin role required")
        );

        let validation_error = handle_lint_provider_profiles(
            &state,
            authed_request(LintProviderProfilesRequest {
                workspace: String::new(),
                profiles: Vec::new(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(validation_error.code(), Code::PermissionDenied);
        assert!(
            validation_error
                .message()
                .contains("platform admin role required")
        );

        let delete_error = handle_delete_provider_profile(
            &state,
            authed_request(DeleteProviderProfileRequest {
                id: "nonexistent".to_string(),
                workspace: String::new(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(delete_error.code(), Code::PermissionDenied);
        assert!(
            delete_error
                .message()
                .contains("platform admin role required")
        );
    }

    #[tokio::test]
    async fn create_provider_rejects_cross_workspace_profile_workspace() {
        let store = test_store().await;
        let provider = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: "cross-ws".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: "claude".to_string(),
            credentials: HashMap::from([("ANTHROPIC_API_KEY".to_string(), "sk-123".to_string())]),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: "other-workspace".to_string(),
            credential_handles: HashMap::new(),
        };
        let err = create_provider_record(&store, "default", provider)
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("profile_workspace"));
    }

    #[tokio::test]
    async fn create_provider_accepts_global_profile_workspace() {
        let store = test_store().await;
        let provider = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: "global-profile".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: "claude".to_string(),
            credentials: HashMap::from([("ANTHROPIC_API_KEY".to_string(), "sk-123".to_string())]),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: String::new(),
            credential_handles: HashMap::new(),
        };
        let created = create_provider_record(&store, "default", provider)
            .await
            .unwrap();
        assert!(created.profile_workspace.is_empty());
    }

    #[tokio::test]
    async fn create_provider_accepts_same_workspace_profile_workspace() {
        let store = test_store().await;
        let provider = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: "same-ws-profile".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: "claude".to_string(),
            credentials: HashMap::from([("ANTHROPIC_API_KEY".to_string(), "sk-123".to_string())]),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        };
        let created = create_provider_record(&store, "default", provider)
            .await
            .unwrap();
        assert_eq!(created.profile_workspace, "default");
    }

    #[tokio::test]
    async fn update_provider_rejects_profile_workspace_change() {
        let store = test_store().await;
        let provider = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: "immutable-pw".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: "claude".to_string(),
            credentials: HashMap::from([("ANTHROPIC_API_KEY".to_string(), "sk-123".to_string())]),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        };
        create_provider_record(&store, "default", provider)
            .await
            .unwrap();

        let update = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: "immutable-pw".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: String::new(),
            credentials: HashMap::new(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: "other".to_string(),
            credential_handles: HashMap::new(),
        };
        let err = update_provider_record(&store, "default", update)
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("profile_workspace"));
    }

    #[tokio::test]
    async fn provider_with_global_profile_resolves_platform_scoped_profile() {
        use crate::persistence::{ObjectName, WriteCondition};
        use prost::Message;

        let store = test_store().await;

        let stored = stored_provider_profile_for_workspace(custom_profile("global-custom"), "");
        store
            .put_if(
                StoredProviderProfile::object_type(),
                stored.object_id(),
                stored.object_name(),
                "",
                &stored.encode_to_vec(),
                None,
                WriteCondition::MustCreate,
            )
            .await
            .unwrap();

        let profile = get_provider_type_profile(&store, "", "global-custom")
            .await
            .unwrap();
        assert!(
            profile.is_some(),
            "global profile should be found at workspace ''"
        );

        let miss = get_provider_type_profile(&store, "default", "global-custom")
            .await
            .unwrap();
        assert!(
            miss.is_none(),
            "global profile should NOT be found at workspace 'default'"
        );
    }

    #[tokio::test]
    async fn provider_with_workspace_profile_resolves_workspace_scoped_profile() {
        let state = test_server_state().await;

        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("ws-custom")),
                    source: "ws-custom.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        create_provider_record(
            state.store.as_ref(),
            "default",
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "uses-ws".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_timestamp_ms: 0,
                }),
                r#type: "ws-custom".to_string(),
                credentials: HashMap::from([("TOKEN".to_string(), "val".to_string())]),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
                profile_workspace: "default".to_string(),
                credential_handles: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let profile = get_provider_type_profile(state.store.as_ref(), "default", "ws-custom")
            .await
            .unwrap();
        assert!(profile.is_some());
    }

    #[tokio::test]
    async fn import_provider_profile_platform_and_workspace_scopes_are_isolated() {
        let state = test_server_state().await;

        let import = |id: &str, workspace: &str| {
            let state = state.clone();
            let id = id.to_string();
            let workspace = workspace.to_string();
            async move {
                handle_import_provider_profiles(
                    &state,
                    authed_request(ImportProviderProfilesRequest {
                        profiles: vec![ProviderProfileImportItem {
                            profile: Some(custom_profile(&id)),
                            source: format!("{id}.yaml"),
                        }],
                        workspace,
                    }),
                )
                .await
                .unwrap()
                .into_inner()
            }
        };

        let resp = import("e2e-platform", "").await;
        assert!(resp.imported);

        let resp = import("e2e-workspace", "default").await;
        assert!(resp.imported);

        let list = |workspace: &str| {
            let state = state.clone();
            let workspace = workspace.to_string();
            async move {
                handle_list_provider_profiles(
                    &state,
                    authed_request(ListProviderProfilesRequest {
                        limit: 200,
                        offset: 0,
                        workspace,
                    }),
                )
                .await
                .unwrap()
                .into_inner()
            }
        };

        let platform_profiles = list("").await;
        assert!(
            platform_profiles
                .profiles
                .iter()
                .any(|p| p.id == "e2e-platform"),
            "platform-scoped profile should appear in platform list"
        );
        assert!(
            !platform_profiles
                .profiles
                .iter()
                .any(|p| p.id == "e2e-workspace"),
            "workspace-scoped profile should NOT appear in platform list"
        );

        let workspace_profiles = list("default").await;
        assert!(
            workspace_profiles
                .profiles
                .iter()
                .any(|p| p.id == "e2e-workspace"),
            "workspace-scoped profile should appear in workspace list"
        );
        assert!(
            workspace_profiles
                .profiles
                .iter()
                .any(|p| p.id == "e2e-platform"),
            "platform-scoped profile should appear in workspace list (visible at all scopes)"
        );

        let delete = |id: &str, workspace: &str| {
            let state = state.clone();
            let id = id.to_string();
            let workspace = workspace.to_string();
            async move {
                handle_delete_provider_profile(
                    &state,
                    authed_request(DeleteProviderProfileRequest { id, workspace }),
                )
                .await
                .unwrap()
                .into_inner()
            }
        };

        assert!(delete("e2e-platform", "").await.deleted);
        assert!(delete("e2e-workspace", "default").await.deleted);
    }

    #[tokio::test]
    async fn cross_scope_duplicate_profile_id_no_longer_wedges_catalog() {
        let state = test_server_state().await;

        let import = |id: &str, workspace: &str| {
            let state = state.clone();
            let id = id.to_string();
            let workspace = workspace.to_string();
            async move {
                handle_import_provider_profiles(
                    &state,
                    authed_request(ImportProviderProfilesRequest {
                        profiles: vec![ProviderProfileImportItem {
                            profile: Some(custom_profile(&id)),
                            source: format!("{id}.yaml"),
                        }],
                        workspace,
                    }),
                )
                .await
                .unwrap()
                .into_inner()
            }
        };

        let resp = import("dupe-profile", "").await;
        assert!(resp.imported, "platform-scope import should succeed");

        let resp = import("dupe-profile", "default").await;
        assert!(resp.imported, "workspace-scope import should succeed");

        let catalog = state
            .provider_profile_sources
            .snapshot_catalog(state.store.as_ref(), "default")
            .await
            .expect("catalog should build successfully with cross-scope duplicate");
        assert!(
            catalog.get_profile("dupe-profile").is_some(),
            "duplicate profile should be resolvable"
        );
    }

    #[tokio::test]
    async fn list_profiles_shows_source_and_scope() {
        let state = test_server_state().await;

        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("scoped-api")),
                    source: "scoped-api.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let resp = handle_list_provider_profiles(
            &state,
            authed_request(ListProviderProfilesRequest {
                limit: 200,
                offset: 0,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        let user_profile = resp
            .profiles
            .iter()
            .find(|p| p.id == "scoped-api")
            .expect("imported profile should appear in list");
        assert_eq!(user_profile.source, "user");
        assert_eq!(user_profile.scope, "workspace");

        let builtin = resp
            .profiles
            .iter()
            .find(|p| p.source == "builtin")
            .expect("builtin profiles should appear");
        assert!(builtin.scope.is_empty());
    }

    #[tokio::test]
    async fn list_profiles_workspace_shows_platform_profiles() {
        let state = test_server_state().await;

        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("platform-only")),
                    source: "platform-only.yaml".to_string(),
                }],
                workspace: String::new(),
            }),
        )
        .await
        .unwrap();

        let resp = handle_list_provider_profiles(
            &state,
            authed_request(ListProviderProfilesRequest {
                limit: 200,
                offset: 0,
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        let platform = resp
            .profiles
            .iter()
            .find(|p| p.id == "platform-only")
            .expect("platform profile should appear in workspace list");
        assert_eq!(platform.scope, "platform");
    }

    #[tokio::test]
    async fn get_profile_returns_effective_workspace_scope() {
        let state = test_server_state().await;

        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("shadow-target")),
                    source: "shadow-target.yaml".to_string(),
                }],
                workspace: String::new(),
            }),
        )
        .await
        .unwrap();

        let mut ws_profile = custom_profile("shadow-target");
        ws_profile.display_name = "Workspace Shadow".to_string();
        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(ws_profile),
                    source: "shadow-target.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let resp = handle_get_provider_profile(
            &state,
            authed_request(GetProviderProfileRequest {
                id: "shadow-target".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        let profile = resp.profile.unwrap();
        assert_eq!(profile.display_name, "Workspace Shadow");
        assert_eq!(profile.scope, "workspace");
    }

    #[tokio::test]
    async fn import_shadow_warning_diagnostic() {
        let state = test_server_state().await;

        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("shadow-warn")),
                    source: "shadow-warn.yaml".to_string(),
                }],
                workspace: String::new(),
            }),
        )
        .await
        .unwrap();

        let resp = handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("shadow-warn")),
                    source: "shadow-warn.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(resp.imported, "workspace import should succeed");
        let has_shadow_warning = resp.diagnostics.iter().any(|d| {
            d.message.contains("shadows a platform-scoped profile") && d.severity == "warning"
        });
        assert!(
            has_shadow_warning,
            "should warn about shadowing: {:?}",
            resp.diagnostics
        );
    }

    #[tokio::test]
    async fn list_profiles_global_excludes_workspace_profiles() {
        let state = test_server_state().await;

        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("global-only")),
                    source: "global-only.yaml".to_string(),
                }],
                workspace: String::new(),
            }),
        )
        .await
        .unwrap();

        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("ws-only")),
                    source: "ws-only.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let resp = handle_list_provider_profiles(
            &state,
            authed_request(ListProviderProfilesRequest {
                limit: 200,
                offset: 0,
                workspace: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(
            resp.profiles.iter().any(|p| p.id == "global-only"),
            "platform profile should appear in global list"
        );
        assert!(
            !resp.profiles.iter().any(|p| p.id == "ws-only"),
            "workspace profile should NOT appear in global list"
        );
    }

    #[tokio::test]
    async fn global_profile_provider_resolves_platform_profile_at_runtime() {
        let state = test_server_state().await;

        let mut platform_profile = custom_profile("scope-test");
        platform_profile.display_name = "Platform Version".to_string();
        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(platform_profile),
                    source: "scope-test.yaml".to_string(),
                }],
                workspace: String::new(),
            }),
        )
        .await
        .unwrap();

        let mut ws_profile = custom_profile("scope-test");
        ws_profile.display_name = "Workspace Version".to_string();
        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(ws_profile),
                    source: "scope-test.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let catalog = state
            .provider_profile_sources
            .snapshot_catalog(state.store.as_ref(), "default")
            .await
            .unwrap();

        let global_result = catalog.get_type_profile_for_scope("scope-test", "");
        assert!(global_result.is_some());
        assert_eq!(
            global_result.unwrap().display_name,
            "Platform Version",
            "provider with profile_workspace='' should resolve platform profile"
        );
    }

    #[tokio::test]
    async fn normal_provider_resolves_workspace_shadow_at_runtime() {
        let state = test_server_state().await;

        let mut platform_profile = custom_profile("scope-test-ws");
        platform_profile.display_name = "Platform Version".to_string();
        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(platform_profile),
                    source: "scope-test-ws.yaml".to_string(),
                }],
                workspace: String::new(),
            }),
        )
        .await
        .unwrap();

        let mut ws_profile = custom_profile("scope-test-ws");
        ws_profile.display_name = "Workspace Version".to_string();
        handle_import_provider_profiles(
            &state,
            authed_request(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(ws_profile),
                    source: "scope-test-ws.yaml".to_string(),
                }],
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap();

        let catalog = state
            .provider_profile_sources
            .snapshot_catalog(state.store.as_ref(), "default")
            .await
            .unwrap();

        let ws_result = catalog.get_type_profile_for_scope("scope-test-ws", "default");
        assert!(ws_result.is_some());
        assert_eq!(
            ws_result.unwrap().display_name,
            "Workspace Version",
            "provider with profile_workspace='default' should resolve workspace profile"
        );
    }

    /// Non-members must receive `PERMISSION_DENIED` — never `NOT_FOUND` — when
    /// calling workspace-scoped provider handlers with a workspace they don't
    /// belong to.  Leaking `NOT_FOUND` would let an unauthenticated observer
    /// enumerate workspace names (CWE-203 information-exposure oracle).
    #[tokio::test]
    async fn non_member_gets_permission_denied_not_workspace_oracle() {
        fn non_member_request<T>(inner: T) -> Request<T> {
            let mut req = Request::new(inner);
            req.extensions_mut().insert(Principal::User(UserPrincipal {
                identity: Identity {
                    subject: "non-member".to_string(),
                    display_name: None,
                    roles: vec![],
                    scopes: vec![],
                    provider: IdentityProvider::Oidc,
                },
            }));
            req
        }

        let mut state = test_server_state().await;
        Arc::get_mut(&mut state).unwrap().admin_role = "openshell-admin".to_string();

        // --- Regular provider handlers (9) ---

        let err = handle_create_provider(
            &state,
            non_member_request(CreateProviderRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_create_provider should reject non-members"
        );

        let err = handle_get_provider(
            &state,
            non_member_request(GetProviderRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_get_provider should reject non-members"
        );

        let err = handle_list_providers(
            &state,
            non_member_request(ListProvidersRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_list_providers should reject non-members"
        );

        let err = handle_update_provider(
            &state,
            non_member_request(UpdateProviderRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_update_provider should reject non-members"
        );

        let err = handle_get_provider_refresh_status(
            &state,
            non_member_request(GetProviderRefreshStatusRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_get_provider_refresh_status should reject non-members"
        );

        let err = handle_configure_provider_refresh(
            &state,
            non_member_request(ConfigureProviderRefreshRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_configure_provider_refresh should reject non-members"
        );

        let err = handle_rotate_provider_credential(
            &state,
            non_member_request(RotateProviderCredentialRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_rotate_provider_credential should reject non-members"
        );

        let err = handle_delete_provider_refresh(
            &state,
            non_member_request(DeleteProviderRefreshRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_delete_provider_refresh should reject non-members"
        );

        let err = handle_delete_provider(
            &state,
            non_member_request(DeleteProviderRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_delete_provider should reject non-members"
        );

        // --- Profile handlers (6) ---

        let err = handle_list_provider_profiles(
            &state,
            non_member_request(ListProviderProfilesRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_list_provider_profiles should reject non-members"
        );

        let err = handle_get_provider_profile(
            &state,
            non_member_request(GetProviderProfileRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_get_provider_profile should reject non-members"
        );

        let err = handle_import_provider_profiles(
            &state,
            non_member_request(ImportProviderProfilesRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_import_provider_profiles should reject non-members"
        );

        let err = handle_update_provider_profiles(
            &state,
            non_member_request(UpdateProviderProfilesRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_update_provider_profiles should reject non-members"
        );

        let err = handle_lint_provider_profiles(
            &state,
            non_member_request(LintProviderProfilesRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_lint_provider_profiles should reject non-members"
        );

        let err = handle_delete_provider_profile(
            &state,
            non_member_request(DeleteProviderProfileRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_delete_provider_profile should reject non-members"
        );
    }
}
