// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider CRUD operations and environment resolution.

#![allow(clippy::result_large_err)] // gRPC handlers return Result<Response<_>, Status>

use crate::persistence::{
    ObjectId, ObjectLabels, ObjectName, ObjectType, Store, WriteCondition, generate_name,
};
use openshell_core::proto::{Provider, Sandbox};
use prost::Message;
use tonic::Status;
use tracing::warn;

use super::validation::validate_provider_fields;
use super::{
    MAX_MAP_KEY_LEN, MAX_MAP_VALUE_LEN, MAX_PAGE_SIZE, MAX_PROVIDER_CONFIG_ENTRIES, clamp_limit,
};

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
    provider
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct ProviderEnvironment {
    pub environment: std::collections::HashMap<String, String>,
    pub credential_expires_at_ms: std::collections::HashMap<String, i64>,
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

pub(super) async fn create_provider_record(
    store: &Store,
    mut provider: Provider,
) -> Result<Provider, Status> {
    use crate::persistence::{ObjectName, current_time_ms};

    // Initialize metadata if not present
    if provider.metadata.is_none() {
        let now_ms = current_time_ms();
        provider.metadata = Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: generate_name(),
            created_at_ms: now_ms,
            labels: std::collections::HashMap::new(),
            resource_version: 0,
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
    if provider.credentials.is_empty()
        && !provider_type_allows_empty_credentials_for_refresh(store, &provider.r#type).await?
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

    // Create with MustCreate condition to prevent duplicate creation race
    let result = store
        .put_if(
            Provider::object_type(),
            &provider_id,
            provider.object_name(),
            &provider.encode_to_vec(),
            None,
            WriteCondition::MustCreate,
        )
        .await
        .map_err(|e| {
            if matches!(
                e,
                crate::persistence::PersistenceError::UniqueViolation { .. }
            ) {
                Status::already_exists("provider already exists")
            } else {
                Status::internal(format!("persist provider failed: {e}"))
            }
        })?;

    if let Some(metadata) = provider.metadata.as_mut() {
        metadata.resource_version = result.resource_version;
    }

    Ok(redact_provider_credentials(provider))
}

pub(super) async fn get_provider_record(store: &Store, name: &str) -> Result<Provider, Status> {
    if name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    store
        .get_message_by_name::<Provider>(name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
        .ok_or_else(|| Status::not_found("provider not found"))
        .map(redact_provider_credentials)
}

pub(super) async fn list_provider_records(
    store: &Store,
    limit: u32,
    offset: u32,
) -> Result<Vec<Provider>, Status> {
    let providers: Vec<Provider> = store
        .list_messages(limit, offset)
        .await
        .map_err(|e| Status::internal(format!("list providers failed: {e}")))?;

    Ok(providers
        .into_iter()
        .map(redact_provider_credentials)
        .collect())
}

pub(super) async fn update_provider_record(
    store: &Store,
    provider: Provider,
) -> Result<Provider, Status> {
    use crate::persistence::{ObjectId, ObjectName};

    if provider.object_name().is_empty() {
        return Err(Status::invalid_argument("provider.name is required"));
    }

    // Extract expected version from provider metadata
    let expected_resource_version = provider.metadata.as_ref().map_or(0, |m| m.resource_version);

    // Resolve provider ID from name for CAS update
    let existing = store
        .get_message_by_name::<Provider>(provider.object_name())
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

    let current_version = existing.metadata.as_ref().map_or(0, |m| m.resource_version);

    let cas_version = if expected_resource_version == 0 {
        current_version
    } else {
        expected_resource_version
    };

    // Apply merge to create candidate
    let mut candidate = existing.clone();
    candidate.credentials = merge_map(candidate.credentials, provider.credentials);
    candidate.config = merge_map(candidate.config, provider.config);
    candidate.credential_expires_at_ms = merge_i64_map(
        candidate.credential_expires_at_ms,
        provider.credential_expires_at_ms,
    );

    // Validate BEFORE writing to prevent persisting invalid state
    super::validation::validate_object_metadata(candidate.metadata.as_ref(), "provider")?;
    validate_provider_fields(&candidate)?;
    validate_provider_update_against_attached_sandboxes(store, &candidate).await?;

    // Serialize labels for storage
    let labels_map = candidate.object_labels();
    let labels_json = if labels_map
        .as_ref()
        .is_none_or(std::collections::HashMap::is_empty)
    {
        None
    } else {
        Some(
            serde_json::to_string(&labels_map)
                .map_err(|e| Status::internal(format!("serialize labels failed: {e}")))?,
        )
    };

    // Write validated candidate with CAS condition
    let result = store
        .put_if(
            Provider::object_type(),
            candidate.object_id(),
            candidate.object_name(),
            &candidate.encode_to_vec(),
            labels_json.as_deref(),
            WriteCondition::MatchResourceVersion(cas_version),
        )
        .await
        .map_err(|e| {
            if matches!(e, crate::persistence::PersistenceError::Conflict { .. }) {
                Status::aborted(format!(
                    "provider was modified concurrently (current resource_version: {})",
                    match e {
                        crate::persistence::PersistenceError::Conflict {
                            current_resource_version,
                        } => current_resource_version.unwrap_or(0),
                        _ => 0,
                    }
                ))
            } else {
                Status::internal(format!("update provider failed: {e}"))
            }
        })?;

    // Update resource_version from successful write
    if let Some(metadata) = candidate.metadata.as_mut() {
        metadata.resource_version = result.resource_version;
    }

    Ok(redact_provider_credentials(candidate))
}

pub(super) async fn delete_provider_record(store: &Store, name: &str) -> Result<bool, Status> {
    if name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    let Some(provider) = store
        .get_message_by_name::<Provider>(name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
    else {
        return Ok(false);
    };

    let blocking_sandboxes = sandboxes_using_provider(store, name).await?;
    if !blocking_sandboxes.is_empty() {
        return Err(Status::failed_precondition(format!(
            "provider '{name}' is attached to sandbox(es): {}",
            blocking_sandboxes.join(", ")
        )));
    }

    crate::provider_refresh::delete_refresh_states_for_provider(store, provider.object_id())
        .await?;

    store
        .delete_by_name(Provider::object_type(), name)
        .await
        .map_err(|e| Status::internal(format!("delete provider failed: {e}")))
}

/// Iterate over every `Sandbox` in the store and collect items produced by
/// `f`.  `f` receives each decoded sandbox; returning `Some(T)` includes the
/// value in the output, `None` skips it.
///
/// This is the shared pagination kernel used by all sandbox-scan helpers.
async fn scan_sandboxes<T, F>(store: &Store, mut f: F) -> Result<Vec<T>, Status>
where
    F: FnMut(Sandbox) -> Option<T>,
{
    let mut out = Vec::new();
    let mut offset = 0u32;
    loop {
        let records = store
            .list(Sandbox::object_type(), 1000, offset)
            .await
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

async fn sandboxes_using_provider(
    store: &Store,
    provider_name: &str,
) -> Result<Vec<String>, Status> {
    let provider_name = provider_name.to_string();
    let mut names = scan_sandboxes(store, |sandbox| {
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
    provider_name: &str,
) -> Result<Vec<Sandbox>, Status> {
    let provider_name = provider_name.to_string();
    scan_sandboxes(store, |sandbox| {
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
    mut existing: std::collections::HashMap<String, String>,
    incoming: std::collections::HashMap<String, String>,
) -> std::collections::HashMap<String, String> {
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
    mut existing: std::collections::HashMap<String, i64>,
    incoming: std::collections::HashMap<String, i64>,
) -> std::collections::HashMap<String, i64> {
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

// ---------------------------------------------------------------------------
// Provider environment resolution
// ---------------------------------------------------------------------------

/// Resolve provider credentials into environment variables.
///
/// For each provider name in the list, fetches the provider from the store and
/// collects credential key-value pairs. Returns a map of environment variables
/// to inject into the sandbox. Credential keys must be unique across attached
/// providers so one provider cannot silently overwrite another provider's token.
pub(super) async fn resolve_provider_environment(
    store: &Store,
    provider_names: &[String],
) -> Result<ProviderEnvironment, Status> {
    if provider_names.is_empty() {
        return Ok(ProviderEnvironment::default());
    }

    let mut env = std::collections::HashMap::new();
    let mut expires = std::collections::HashMap::new();
    let now_ms = crate::persistence::current_time_ms();
    validate_provider_environment_keys_unique_at(store, provider_names, None, now_ms).await?;

    for name in provider_names {
        let provider = store
            .get_message_by_name::<Provider>(name)
            .await
            .map_err(|e| Status::internal(format!("failed to fetch provider '{name}': {e}")))?
            .ok_or_else(|| Status::failed_precondition(format!("provider '{name}' not found")))?;

        for (key, value) in &provider.credentials {
            if is_valid_env_key(key) {
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
                env.entry(key.clone()).or_insert_with(|| value.clone());
            } else {
                warn!(
                    provider_name = %name,
                    key = %key,
                    "skipping credential with invalid env var key"
                );
            }
        }
    }

    Ok(ProviderEnvironment {
        environment: env,
        credential_expires_at_ms: expires,
    })
}

pub async fn validate_provider_environment_keys_unique(
    store: &Store,
    provider_names: &[String],
) -> Result<(), Status> {
    validate_provider_environment_keys_unique_at(
        store,
        provider_names,
        None,
        crate::persistence::current_time_ms(),
    )
    .await
}

pub async fn validate_provider_credential_key_available_for_attached_sandboxes(
    store: &Store,
    provider: &Provider,
    credential_key: &str,
) -> Result<(), Status> {
    let mut candidate = provider.clone();
    candidate
        .credentials
        .entry(credential_key.to_string())
        .or_insert_with(|| "pending".to_string());
    candidate.credential_expires_at_ms.remove(credential_key);
    validate_provider_update_against_attached_sandboxes(store, &candidate).await
}

pub async fn validate_provider_update_against_attached_sandboxes(
    store: &Store,
    provider: &Provider,
) -> Result<(), Status> {
    let provider_name = provider.object_name().to_string();
    for sandbox in sandboxes_using_provider_records(store, &provider_name).await? {
        let sandbox_name = sandbox.object_name().to_string();
        let Some(spec) = sandbox.spec.as_ref() else {
            continue;
        };
        validate_provider_environment_keys_unique_at(
            store,
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
    provider_names: &[String],
    candidate_provider: Option<&Provider>,
    now_ms: i64,
) -> Result<(), Status> {
    let mut seen = std::collections::HashMap::<String, String>::new();
    for name in provider_names {
        let provider = match candidate_provider {
            Some(candidate) if candidate.object_name() == name.as_str() => candidate.clone(),
            _ => store
                .get_message_by_name::<Provider>(name)
                .await
                .map_err(|e| Status::internal(format!("failed to fetch provider '{name}': {e}")))?
                .ok_or_else(|| {
                    Status::failed_precondition(format!("provider '{name}' not found"))
                })?,
        };
        let provider_name = provider.object_name().to_string();
        for key in active_provider_environment_keys(store, &provider, now_ms).await? {
            if let Some(first_provider) = seen.get(&key) {
                if first_provider != &provider_name {
                    return Err(Status::failed_precondition(format!(
                        "credential env key '{key}' is provided by both provider '{first_provider}' and provider '{provider_name}'; use provider-specific env names"
                    )));
                }
            } else {
                seen.insert(key, provider_name.clone());
            }
        }
    }
    Ok(())
}

async fn active_provider_environment_keys(
    store: &Store,
    provider: &Provider,
    now_ms: i64,
) -> Result<Vec<String>, Status> {
    let mut keys = active_provider_credential_keys(provider, now_ms);
    if !provider.object_id().is_empty() {
        keys.extend(
            crate::provider_refresh::list_refresh_states_for_provider(store, provider.object_id())
                .await?
                .into_iter()
                .map(|state| state.credential_key)
                .filter(|key| is_valid_env_key(key)),
        );
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

fn active_provider_credential_keys(provider: &Provider, now_ms: i64) -> Vec<String> {
    provider
        .credentials
        .keys()
        .filter(|key| is_valid_env_key(key))
        .filter(|key| {
            provider
                .credential_expires_at_ms
                .get(*key)
                .is_none_or(|expires_at_ms| *expires_at_ms <= 0 || *expires_at_ms > now_ms)
        })
        .cloned()
        .collect()
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
    GetProviderProfileRequest, GetProviderRefreshStatusRequest, GetProviderRefreshStatusResponse,
    GetProviderRequest, ImportProviderProfilesRequest, ImportProviderProfilesResponse,
    LintProviderProfilesRequest, LintProviderProfilesResponse, ListProviderProfilesRequest,
    ListProviderProfilesResponse, ListProvidersRequest, ListProvidersResponse,
    ProviderCredentialRefreshStrategy, ProviderProfile, ProviderProfileDiagnostic,
    ProviderProfileImportItem, ProviderProfileResponse, ProviderResponse,
    RotateProviderCredentialRequest, RotateProviderCredentialResponse, StoredProviderProfile,
    UpdateProviderRequest,
};
use openshell_providers::{
    CredentialRefreshProfile, ProfileValidationDiagnostic, ProviderTypeProfile, default_profiles,
    get_default_profile, normalize_profile_id, validate_profile_set,
};
use std::sync::Arc;
use tonic::{Request, Response};

pub(super) async fn handle_create_provider(
    state: &Arc<ServerState>,
    request: Request<CreateProviderRequest>,
) -> Result<Response<ProviderResponse>, Status> {
    let req = request.into_inner();
    let provider = req
        .provider
        .ok_or_else(|| Status::invalid_argument("provider is required"))?;
    let provider = create_provider_record(state.store.as_ref(), provider).await?;

    Ok(Response::new(ProviderResponse {
        provider: Some(provider),
    }))
}

pub(super) async fn handle_get_provider(
    state: &Arc<ServerState>,
    request: Request<GetProviderRequest>,
) -> Result<Response<ProviderResponse>, Status> {
    let name = request.into_inner().name;
    let provider = get_provider_record(state.store.as_ref(), &name).await?;

    Ok(Response::new(ProviderResponse {
        provider: Some(provider),
    }))
}

pub(super) async fn handle_list_providers(
    state: &Arc<ServerState>,
    request: Request<ListProvidersRequest>,
) -> Result<Response<ListProvidersResponse>, Status> {
    let request = request.into_inner();
    let limit = clamp_limit(request.limit, 100, MAX_PAGE_SIZE);
    let providers = list_provider_records(state.store.as_ref(), limit, request.offset).await?;

    Ok(Response::new(ListProvidersResponse { providers }))
}

impl ObjectType for StoredProviderProfile {
    fn object_type() -> &'static str {
        "provider_profile"
    }
}

pub(super) async fn handle_list_provider_profiles(
    state: &Arc<ServerState>,
    request: Request<ListProviderProfilesRequest>,
) -> Result<Response<ListProviderProfilesResponse>, Status> {
    let request = request.into_inner();
    let limit = clamp_limit(request.limit, 100, MAX_PAGE_SIZE) as usize;
    let offset = request.offset as usize;
    let mut profiles = merged_provider_profiles(state.store.as_ref()).await?;
    profiles.sort_by(|left, right| left.id.cmp(&right.id));
    let profiles = profiles
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|profile| profile.to_proto())
        .collect();

    Ok(Response::new(ListProviderProfilesResponse { profiles }))
}

pub(super) async fn handle_get_provider_profile(
    state: &Arc<ServerState>,
    request: Request<GetProviderProfileRequest>,
) -> Result<Response<ProviderProfileResponse>, Status> {
    let id = request.into_inner().id;
    let id = normalize_profile_id_request(&id)?;
    let profile = get_provider_type_profile(state.store.as_ref(), &id)
        .await?
        .ok_or_else(|| Status::not_found("provider profile not found"))?
        .to_proto();

    Ok(Response::new(ProviderProfileResponse {
        profile: Some(profile),
    }))
}

pub(super) async fn handle_import_provider_profiles(
    state: &Arc<ServerState>,
    request: Request<ImportProviderProfilesRequest>,
) -> Result<Response<ImportProviderProfilesResponse>, Status> {
    let request = request.into_inner();
    let (profiles, mut diagnostics) = profiles_from_import_items(&request.profiles);
    add_empty_profile_set_diagnostic(&profiles, &mut diagnostics);
    diagnostics.extend(profile_conflict_diagnostics(state.store.as_ref(), &profiles).await?);
    diagnostics.extend(validate_profile_set(&profiles));

    if has_errors(&diagnostics) {
        return Ok(Response::new(ImportProviderProfilesResponse {
            diagnostics: diagnostics.into_iter().map(proto_diagnostic).collect(),
            profiles: Vec::new(),
            imported: false,
        }));
    }

    let mut imported = Vec::with_capacity(profiles.len());
    for (_, profile) in profiles {
        let stored = stored_provider_profile(profile.to_proto());
        state
            .store
            .put_if(
                StoredProviderProfile::object_type(),
                stored.object_id(),
                stored.object_name(),
                &stored.encode_to_vec(),
                None,
                WriteCondition::MustCreate,
            )
            .await
            .map_err(|e| Status::internal(format!("persist provider profile failed: {e}")))?;
        imported.push(stored.profile.unwrap_or_default());
    }

    Ok(Response::new(ImportProviderProfilesResponse {
        diagnostics: Vec::new(),
        profiles: imported,
        imported: true,
    }))
}

pub(super) async fn handle_lint_provider_profiles(
    state: &Arc<ServerState>,
    request: Request<LintProviderProfilesRequest>,
) -> Result<Response<LintProviderProfilesResponse>, Status> {
    let request = request.into_inner();
    let (profiles, mut diagnostics) = profiles_from_import_items(&request.profiles);
    add_empty_profile_set_diagnostic(&profiles, &mut diagnostics);
    diagnostics.extend(profile_conflict_diagnostics(state.store.as_ref(), &profiles).await?);
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
    let id = request.into_inner().id;
    let id = normalize_profile_id_request(&id)?;
    if get_default_profile(&id).is_some() {
        return Err(Status::failed_precondition(
            "built-in provider profiles cannot be deleted",
        ));
    }

    let existing = state
        .store
        .get_message_by_name::<StoredProviderProfile>(&id)
        .await
        .map_err(|e| Status::internal(format!("fetch provider profile failed: {e}")))?;
    if existing.is_none() {
        return Err(Status::not_found("provider profile not found"));
    }

    let blocking_sandboxes = sandboxes_using_profile(state.store.as_ref(), &id).await?;
    if !blocking_sandboxes.is_empty() {
        return Err(Status::failed_precondition(format!(
            "provider profile '{id}' is in use by sandboxes: {}",
            blocking_sandboxes.join(", ")
        )));
    }

    let deleted = state
        .store
        .delete_by_name(StoredProviderProfile::object_type(), &id)
        .await
        .map_err(|e| Status::internal(format!("delete provider profile failed: {e}")))?;

    Ok(Response::new(DeleteProviderProfileResponse { deleted }))
}

pub(super) async fn get_provider_type_profile(
    store: &Store,
    id: &str,
) -> Result<Option<ProviderTypeProfile>, Status> {
    let Some(id) = normalize_profile_id(id) else {
        return Ok(None);
    };
    if let Some(profile) = get_default_profile(&id) {
        return Ok(Some(profile.clone()));
    }
    let profile = store
        .get_message_by_name::<StoredProviderProfile>(&id)
        .await
        .map_err(|e| Status::internal(format!("fetch provider profile failed: {e}")))?
        .and_then(|stored| stored.profile)
        .map(|profile| ProviderTypeProfile::from_proto(&profile));
    Ok(profile)
}

async fn provider_refresh_defaults(
    store: &Store,
    provider: &Provider,
    credential_key: &str,
) -> Result<Option<CredentialRefreshProfile>, Status> {
    let Some(profile) = get_provider_type_profile(store, &provider.r#type).await? else {
        return Ok(None);
    };
    Ok(profile
        .credentials
        .iter()
        .find(|credential| {
            credential.name == credential_key
                || credential
                    .env_vars
                    .iter()
                    .any(|env_var| env_var == credential_key)
        })
        .and_then(|credential| credential.refresh.clone()))
}

fn validate_refresh_material(
    material: &std::collections::HashMap<String, String>,
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

async fn provider_type_allows_empty_credentials_for_refresh(
    store: &Store,
    provider_type: &str,
) -> Result<bool, Status> {
    let Some(profile) = get_provider_type_profile(store, provider_type).await? else {
        return Ok(false);
    };
    let required_credentials = profile
        .credentials
        .iter()
        .filter(|credential| credential.required)
        .collect::<Vec<_>>();
    Ok(!required_credentials.is_empty()
        && required_credentials.iter().all(|credential| {
            credential.refresh.as_ref().is_some_and(|refresh| {
                crate::provider_refresh::is_gateway_mintable_strategy(refresh.strategy)
            })
        }))
}

async fn merged_provider_profiles(store: &Store) -> Result<Vec<ProviderTypeProfile>, Status> {
    let mut profiles = default_profiles().to_vec();
    profiles.extend(
        custom_provider_profiles(store)
            .await?
            .into_iter()
            .filter_map(|stored| stored.profile)
            .map(|profile| ProviderTypeProfile::from_proto(&profile)),
    );
    Ok(profiles)
}

async fn custom_provider_profiles(store: &Store) -> Result<Vec<StoredProviderProfile>, Status> {
    let profiles: Vec<StoredProviderProfile> = store
        .list_messages(10_000, 0)
        .await
        .map_err(|e| Status::internal(format!("list provider profiles failed: {e}")))?;
    Ok(profiles)
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
    profiles: &[(String, ProviderTypeProfile)],
) -> Result<Vec<ProfileValidationDiagnostic>, Status> {
    let mut diagnostics = Vec::new();
    for (source, profile) in profiles {
        let Some(id) = normalize_profile_id(&profile.id) else {
            continue;
        };
        if get_default_profile(&id).is_some() {
            diagnostics.push(ProfileValidationDiagnostic {
                source: source.clone(),
                profile_id: id.clone(),
                field: "id".to_string(),
                message: format!("provider profile '{id}' is built-in and cannot be overwritten"),
                severity: "error".to_string(),
            });
            continue;
        }
        if store
            .get_message_by_name::<StoredProviderProfile>(&id)
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
        }
    }
    Ok(diagnostics)
}

fn stored_provider_profile(profile: ProviderProfile) -> StoredProviderProfile {
    use crate::persistence::current_time_ms;
    let now_ms = current_time_ms();
    StoredProviderProfile {
        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: profile.id.clone(),
            created_at_ms: now_ms,
            labels: std::collections::HashMap::new(),
            resource_version: 0,
        }),
        profile: Some(profile),
    }
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

async fn sandboxes_using_profile(store: &Store, profile_id: &str) -> Result<Vec<String>, Status> {
    // Collect all sandboxes that reference at least one provider — pagination
    // is handled by `scan_sandboxes`; the async provider lookup happens below.
    let candidates = scan_sandboxes(store, |sandbox| {
        let has_providers = sandbox
            .spec
            .as_ref()
            .is_some_and(|s| !s.providers.is_empty());
        has_providers.then_some(sandbox)
    })
    .await?;

    let mut blocking = Vec::new();
    for sandbox in candidates {
        let spec = sandbox.spec.as_ref().expect("filtered by scan_sandboxes");
        for provider_name in &spec.providers {
            let Some(provider) = store
                .get_message_by_name::<Provider>(provider_name)
                .await
                .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
            else {
                continue;
            };
            if normalize_profile_id(&provider.r#type).as_deref() == Some(profile_id) {
                blocking.push(sandbox.object_name().to_string());
                break;
            }
        }
    }
    blocking.sort();
    blocking.dedup();
    Ok(blocking)
}

pub(super) async fn handle_update_provider(
    state: &Arc<ServerState>,
    request: Request<UpdateProviderRequest>,
) -> Result<Response<ProviderResponse>, Status> {
    let req = request.into_inner();
    let mut provider = req
        .provider
        .ok_or_else(|| Status::invalid_argument("provider is required"))?;
    provider
        .credential_expires_at_ms
        .extend(req.credential_expires_at_ms);
    let provider = update_provider_record(state.store.as_ref(), provider).await?;

    Ok(Response::new(ProviderResponse {
        provider: Some(provider),
    }))
}

pub(super) async fn handle_get_provider_refresh_status(
    state: &Arc<ServerState>,
    request: Request<GetProviderRefreshStatusRequest>,
) -> Result<Response<GetProviderRefreshStatusResponse>, Status> {
    let request = request.into_inner();
    if request.provider.trim().is_empty() {
        return Err(Status::invalid_argument("provider is required"));
    }
    let provider = state
        .store
        .get_message_by_name::<Provider>(&request.provider)
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
    let request = request.into_inner();
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
    if request
        .expires_at_ms
        .is_some_and(|expires_at_ms| expires_at_ms < 0)
    {
        return Err(Status::invalid_argument(
            "expires_at_ms must be greater than or equal to 0",
        ));
    }

    let provider = state
        .store
        .get_message_by_name::<Provider>(provider_name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
        .ok_or_else(|| Status::not_found("provider not found"))?;
    validate_provider_credential_key_available_for_attached_sandboxes(
        state.store.as_ref(),
        &provider,
        credential_key,
    )
    .await?;
    let refresh_defaults =
        provider_refresh_defaults(state.store.as_ref(), &provider, credential_key).await?;
    validate_refresh_material(&request.material, refresh_defaults.as_ref())?;
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
        provider.object_id(),
        credential_key,
    )
    .await?;
    let expires_at_ms = request.expires_at_ms.unwrap_or_else(|| {
        existing_refresh_state
            .as_ref()
            .map(|state| state.expires_at_ms)
            .unwrap_or_default()
    });
    let mut state_record = crate::provider_refresh::new_refresh_state(
        &provider,
        credential_key,
        crate::provider_refresh::NewRefreshStateConfig {
            strategy,
            material: request.material,
            secret_material_keys: request.secret_material_keys,
            expires_at_ms,
            token_url,
            scopes,
            refresh_before_seconds,
            max_lifetime_seconds,
        },
    )?;
    if let Some(existing) = existing_refresh_state {
        state_record.metadata = existing.metadata;
        state_record.last_refresh_at_ms = existing.last_refresh_at_ms;
    }
    crate::provider_refresh::put_refresh_state(state.store.as_ref(), &state_record).await?;

    if let Some(expires_at_ms) = request.expires_at_ms {
        let updated = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: provider_name.to_string(),
                created_at_ms: 0,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            r#type: String::new(),
            credentials: std::collections::HashMap::new(),
            config: std::collections::HashMap::new(),
            credential_expires_at_ms: std::collections::HashMap::from([(
                credential_key.to_string(),
                expires_at_ms,
            )]),
        };
        update_provider_record(state.store.as_ref(), updated).await?;
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
    let request = request.into_inner();
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

pub(super) async fn handle_delete_provider_refresh(
    state: &Arc<ServerState>,
    request: Request<DeleteProviderRefreshRequest>,
) -> Result<Response<DeleteProviderRefreshResponse>, Status> {
    let request = request.into_inner();
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
        .get_message_by_name::<Provider>(provider_name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
        .ok_or_else(|| Status::not_found("provider not found"))?;
    let existing_refresh_state = crate::provider_refresh::get_refresh_state(
        state.store.as_ref(),
        provider.object_id(),
        credential_key,
    )
    .await?;
    let deleted_refresh_state = crate::provider_refresh::delete_refresh_state(
        state.store.as_ref(),
        provider.object_id(),
        credential_key,
    )
    .await?;

    let refresh_owned_expiry = existing_refresh_state
        .as_ref()
        .is_some_and(|refresh_state| {
            refresh_state.expires_at_ms > 0
                && provider
                    .credential_expires_at_ms
                    .get(credential_key)
                    .is_some_and(|expires_at_ms| *expires_at_ms == refresh_state.expires_at_ms)
        });
    if refresh_owned_expiry {
        let updated = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: provider_name.to_string(),
                created_at_ms: 0,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            r#type: String::new(),
            credentials: std::collections::HashMap::new(),
            config: std::collections::HashMap::new(),
            credential_expires_at_ms: std::collections::HashMap::from([(
                credential_key.to_string(),
                0,
            )]),
        };
        update_provider_record(state.store.as_ref(), updated).await?;
    }

    Ok(Response::new(DeleteProviderRefreshResponse {
        deleted: deleted_refresh_state,
    }))
}

pub(super) async fn handle_delete_provider(
    state: &Arc<ServerState>,
    request: Request<DeleteProviderRequest>,
) -> Result<Response<DeleteProviderResponse>, Status> {
    let name = request.into_inner().name;
    let deleted = delete_provider_record(state.store.as_ref(), &name).await?;

    Ok(Response::new(DeleteProviderResponse { deleted }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::MAX_MAP_KEY_LEN;
    use crate::grpc::test_support::test_server_state;

    async fn test_store() -> Store {
        Store::connect("sqlite::memory:?cache=shared")
            .await
            .expect("in-memory SQLite store should connect")
    }
    use openshell_core::proto::{
        DeleteProviderProfileRequest, GetProviderProfileRequest, ImportProviderProfilesRequest,
        L7Allow, L7Rule, LintProviderProfilesRequest, ListProviderProfilesRequest, NetworkBinary,
        NetworkEndpoint, ProviderCredentialRefresh, ProviderCredentialRefreshMaterial,
        ProviderProfile, ProviderProfileCategory, ProviderProfileCredential,
        ProviderProfileImportItem, Sandbox, SandboxSpec,
    };
    use openshell_core::{ObjectId, ObjectName};
    use std::collections::HashMap;
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

    fn provider_with_values(name: &str, provider_type: &str) -> Provider {
        Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: name.to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
                resource_version: 0,
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
        }
    }

    fn custom_profile(id: &str) -> ProviderProfile {
        ProviderProfile {
            id: id.to_string(),
            display_name: format!("{id} Profile"),
            description: String::new(),
            category: ProviderProfileCategory::Other as i32,
            credentials: Vec::new(),
            endpoints: Vec::new(),
            binaries: Vec::new(),
            inference_capable: false,
            discovery: None,
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
            refresh: Some(ProviderCredentialRefresh {
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
                token_url: "https://auth.example.com/token".to_string(),
                scopes: Vec::new(),
                refresh_before_seconds: 300,
                max_lifetime_seconds: 3600,
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
        }
    }

    async fn import_test_refresh_profile(state: &Arc<ServerState>, id: &str, credential_key: &str) {
        let mut profile = custom_profile(id);
        profile.category = ProviderProfileCategory::Messaging as i32;
        profile.credentials = vec![refreshable_credential("access_token", credential_key)];
        handle_import_provider_profiles(
            state,
            Request::new(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(profile),
                    source: format!("{id}.yaml"),
                }],
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
        }
    }

    #[tokio::test]
    async fn list_provider_profiles_returns_built_in_profile_categories() {
        let state = test_server_state().await;
        let response = handle_list_provider_profiles(
            &state,
            Request::new(ListProviderProfilesRequest {
                limit: 100,
                offset: 0,
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
        assert_eq!(ids, vec!["claude-code", "github", "nvidia"]);

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
            Request::new(GetProviderProfileRequest {
                id: "github".to_string(),
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
            Request::new(GetProviderProfileRequest {
                id: "generic".to_string(),
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
            Request::new(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("custom-api")),
                    source: "custom-api.yaml".to_string(),
                }],
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(response.imported);
        assert!(response.diagnostics.is_empty());

        let listed = handle_list_provider_profiles(
            &state,
            Request::new(ListProviderProfilesRequest {
                limit: 100,
                offset: 0,
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
            Request::new(GetProviderProfileRequest {
                id: "custom-api".to_string(),
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
    async fn import_provider_profile_rejects_builtin_overwrite() {
        let state = test_server_state().await;
        let response = handle_import_provider_profiles(
            &state,
            Request::new(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("github")),
                    source: "github.yaml".to_string(),
                }],
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
                .any(|diagnostic| diagnostic.message.contains("built-in"))
        );
    }

    #[tokio::test]
    async fn import_provider_profile_allows_legacy_provider_type_ids_without_built_in_profiles() {
        let state = test_server_state().await;
        let response = handle_import_provider_profiles(
            &state,
            Request::new(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("codex")),
                    source: "codex.yaml".to_string(),
                }],
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(response.imported);
        assert!(response.diagnostics.is_empty());

        let imported = handle_get_provider_profile(
            &state,
            Request::new(GetProviderProfileRequest {
                id: "codex".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .profile
        .expect("codex profile should be returned");
        assert_eq!(imported.id, "codex");
    }

    #[tokio::test]
    async fn import_provider_profile_rejects_noncanonical_ids() {
        let state = test_server_state().await;
        let response = handle_import_provider_profiles(
            &state,
            Request::new(ImportProviderProfilesRequest {
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
            Request::new(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("alex-api")),
                    source: "alex-api.yaml".to_string(),
                }],
            }),
        )
        .await
        .unwrap();

        let fetched = handle_get_provider_profile(
            &state,
            Request::new(GetProviderProfileRequest {
                id: " Alex-API ".to_string(),
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
            Request::new(DeleteProviderProfileRequest {
                id: " Alex-API ".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(deleted.deleted);
    }

    #[tokio::test]
    async fn import_provider_profiles_rejects_mixed_batch_without_partial_import() {
        let state = test_server_state().await;
        let response = handle_import_provider_profiles(
            &state,
            Request::new(ImportProviderProfilesRequest {
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
                Request::new(GetProviderProfileRequest { id: id.to_string() }),
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
            Request::new(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(ProviderProfile {
                        id: "advanced-api".to_string(),
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
                    }),
                    source: "advanced-api.yaml".to_string(),
                }],
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(response.imported);

        let fetched = handle_get_provider_profile(
            &state,
            Request::new(GetProviderProfileRequest {
                id: "advanced-api".to_string(),
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
            Request::new(LintProviderProfilesRequest {
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
                Request::new(GetProviderProfileRequest { id: id.to_string() }),
            )
            .await
            .unwrap_err();
            assert_eq!(missing.code(), Code::NotFound);
        }
    }

    #[tokio::test]
    async fn delete_provider_profile_rejects_builtin_and_in_use_custom_profiles() {
        let state = test_server_state().await;
        handle_import_provider_profiles(
            &state,
            Request::new(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("custom-api")),
                    source: "custom-api.yaml".to_string(),
                }],
            }),
        )
        .await
        .unwrap();

        let builtin_err = handle_delete_provider_profile(
            &state,
            Request::new(DeleteProviderProfileRequest {
                id: "github".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(builtin_err.code(), Code::FailedPrecondition);

        create_provider_record(
            state.store.as_ref(),
            provider_with_values("custom-provider", "custom-api"),
        )
        .await
        .unwrap();
        state
            .store
            .put_message(&Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "sandbox-id".to_string(),
                    name: "sandbox-using-custom".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                spec: Some(SandboxSpec {
                    providers: vec!["custom-provider".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();

        let in_use_err = handle_delete_provider_profile(
            &state,
            Request::new(DeleteProviderProfileRequest {
                id: "custom-api".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(in_use_err.code(), Code::FailedPrecondition);
        assert!(in_use_err.message().contains("sandbox-using-custom"));
    }

    #[tokio::test]
    async fn configure_provider_refresh_stores_scoped_status_and_provider_expiry() {
        let state = test_server_state().await;
        import_test_graph_refresh_profile(&state).await;
        create_provider_record(
            state.store.as_ref(),
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "msgraph".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: TEST_GRAPH_PROVIDER_TYPE.to_string(),
                credentials: std::iter::once((
                    "MS_GRAPH_ACCESS_TOKEN".to_string(),
                    "token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let expires_at_ms = crate::persistence::current_time_ms() + 60_000;
        let response = handle_configure_provider_refresh(
            &state,
            Request::new(ConfigureProviderRefreshRequest {
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
            Request::new(GetProviderRefreshStatusRequest {
                provider: "msgraph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(status.credentials.len(), 1);
        assert_eq!(status.credentials[0].expires_at_ms, expires_at_ms);

        let provider = state
            .store
            .get_message_by_name::<Provider>("msgraph")
            .await
            .unwrap()
            .expect("provider");
        assert_eq!(
            provider
                .credential_expires_at_ms
                .get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&expires_at_ms)
        );

        let deleted = handle_delete_provider_refresh(
            &state,
            Request::new(DeleteProviderRefreshRequest {
                provider: "msgraph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(deleted.deleted);

        let status_after_delete = handle_get_provider_refresh_status(
            &state,
            Request::new(GetProviderRefreshStatusRequest {
                provider: "msgraph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(status_after_delete.credentials.is_empty());

        let provider_after_delete = state
            .store
            .get_message_by_name::<Provider>("msgraph")
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
    async fn delete_provider_refresh_preserves_manually_updated_expiry() {
        let state = test_server_state().await;
        import_test_graph_refresh_profile(&state).await;
        create_provider_record(
            state.store.as_ref(),
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "msgraph".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: TEST_GRAPH_PROVIDER_TYPE.to_string(),
                credentials: std::iter::once((
                    "MS_GRAPH_ACCESS_TOKEN".to_string(),
                    "token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let refresh_expires_at_ms = crate::persistence::current_time_ms() + 60_000;
        handle_configure_provider_refresh(
            &state,
            Request::new(ConfigureProviderRefreshRequest {
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
            }),
        )
        .await
        .unwrap();

        let manual_expires_at_ms = refresh_expires_at_ms + 60_000;
        update_provider_record(
            state.store.as_ref(),
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "msgraph".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::from([(
                    "MS_GRAPH_ACCESS_TOKEN".to_string(),
                    manual_expires_at_ms,
                )]),
            },
        )
        .await
        .unwrap();

        let deleted = handle_delete_provider_refresh(
            &state,
            Request::new(DeleteProviderRefreshRequest {
                provider: "msgraph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(deleted.deleted);

        let provider_after_delete = state
            .store
            .get_message_by_name::<Provider>("msgraph")
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
    async fn configure_provider_refresh_rejects_credential_key_collision_for_attached_sandbox() {
        let state = test_server_state().await;
        import_test_graph_refresh_profile(&state).await;
        create_provider_record(
            state.store.as_ref(),
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "existing-graph".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: TEST_GRAPH_PROVIDER_TYPE.to_string(),
                credentials: std::iter::once((
                    "MS_GRAPH_ACCESS_TOKEN".to_string(),
                    "existing-token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
            },
        )
        .await
        .unwrap();
        create_provider_record(
            state.store.as_ref(),
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "refreshing-graph".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: TEST_GRAPH_PROVIDER_TYPE.to_string(),
                credentials: std::iter::once(("OTHER_TOKEN".to_string(), "other".to_string()))
                    .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
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
            Request::new(ConfigureProviderRefreshRequest {
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
                Provider {
                    metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                        id: String::new(),
                        name: name.to_string(),
                        created_at_ms: 0,
                        labels: HashMap::new(),
                        resource_version: 0,
                    }),
                    r#type: TEST_GRAPH_PROVIDER_TYPE.to_string(),
                    credentials: HashMap::new(),
                    config: HashMap::new(),
                    credential_expires_at_ms: HashMap::new(),
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
            Request::new(ConfigureProviderRefreshRequest {
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
            }),
        )
        .await
        .unwrap();

        let err = handle_configure_provider_refresh(
            &state,
            Request::new(ConfigureProviderRefreshRequest {
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
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "msgraph".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: TEST_GRAPH_PROVIDER_TYPE.to_string(),
                credentials: std::iter::once((
                    "MS_GRAPH_ACCESS_TOKEN".to_string(),
                    "token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let endpoint_override = handle_configure_provider_refresh(
            &state,
            Request::new(ConfigureProviderRefreshRequest {
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
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(endpoint_override.code(), Code::InvalidArgument);
        assert!(endpoint_override.message().contains("provider profile"));

        let missing_material = handle_configure_provider_refresh(
            &state,
            Request::new(ConfigureProviderRefreshRequest {
                provider: "msgraph".to_string(),
                credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
                material: HashMap::from([("tenant_id".to_string(), "tenant".to_string())]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: None,
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
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "msgraph".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: "outlook".to_string(),
                credentials: std::iter::once((
                    "MS_GRAPH_ACCESS_TOKEN".to_string(),
                    "token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
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
                Request::new(ConfigureProviderRefreshRequest {
                    provider: "msgraph".to_string(),
                    credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
                    strategy: strategy as i32,
                    material: HashMap::new(),
                    secret_material_keys: Vec::new(),
                    expires_at_ms: None,
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
            Request::new(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("custom-api")),
                    source: "custom-api.yaml".to_string(),
                }],
            }),
        )
        .await
        .unwrap();

        let deleted = handle_delete_provider_profile(
            &state,
            Request::new(DeleteProviderProfileRequest {
                id: "custom-api".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(deleted.deleted);

        let missing = handle_get_provider_profile(
            &state,
            Request::new(GetProviderProfileRequest {
                id: "custom-api".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(missing.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn provider_crud_round_trip_and_semantics() {
        let store = test_store().await;

        let created = provider_with_values("gitlab-local", "gitlab");
        let persisted = create_provider_record(&store, created.clone())
            .await
            .unwrap();
        assert_eq!(persisted.object_name(), "gitlab-local");
        assert_eq!(persisted.r#type, "gitlab");
        assert!(!persisted.object_id().is_empty());
        let provider_id = persisted.object_id().to_string();

        let duplicate_err = create_provider_record(&store, created).await.unwrap_err();
        assert_eq!(duplicate_err.code(), Code::AlreadyExists);

        let loaded = get_provider_record(&store, "gitlab-local").await.unwrap();
        assert_eq!(loaded.object_id(), provider_id);

        let listed = list_provider_records(&store, 100, 0).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].object_name(), "gitlab-local");

        let updated = update_provider_record(
            &store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "gitlab-local".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
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
            .get_message_by_name("gitlab-local")
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

        let deleted = delete_provider_record(&store, "gitlab-local")
            .await
            .unwrap();
        assert!(deleted);

        let deleted_again = delete_provider_record(&store, "gitlab-local")
            .await
            .unwrap();
        assert!(!deleted_again);

        let missing = get_provider_record(&store, "gitlab-local")
            .await
            .unwrap_err();
        assert_eq!(missing.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn delete_provider_removes_scoped_refresh_states() {
        let store = test_store().await;

        let provider = create_provider_record(
            &store,
            Provider {
                credential_expires_at_ms: HashMap::from([("API_TOKEN".to_string(), 123_456)]),
                ..provider_with_values("gitlab-local", "gitlab")
            },
        )
        .await
        .unwrap();
        let refresh_state = crate::provider_refresh::new_refresh_state(
            &provider,
            "API_TOKEN",
            crate::provider_refresh::NewRefreshStateConfig {
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

        let deleted = delete_provider_record(&store, "gitlab-local")
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

        create_provider_record(&store, provider_with_values("gitlab-local", "gitlab"))
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
                }),
                spec: Some(SandboxSpec {
                    providers: vec!["gitlab-local".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();

        let err = delete_provider_record(&store, "gitlab-local")
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
        let created = provider_with_values("test-provider", "openai");
        let persisted = create_provider_record(&store, created).await.unwrap();
        assert_eq!(
            persisted.metadata.as_ref().unwrap().resource_version,
            1,
            "create_provider_record should return resource_version: 1 after insert"
        );

        // Update provider and verify resource_version: 2 in response
        let updated = update_provider_record(
            &store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "test-provider".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: "openai".to_string(),
                credentials: std::iter::once((
                    "OPENAI_API_KEY".to_string(),
                    "updated-key".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
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
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "test-provider".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: "openai".to_string(),
                credentials: std::iter::once((
                    "OPENAI_API_KEY".to_string(),
                    "third-key".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
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
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "bad-provider".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(create_missing_type.code(), Code::InvalidArgument);

        let create_missing_credentials = create_provider_record(
            store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "gitlab-no-creds".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: "gitlab".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(create_missing_credentials.code(), Code::InvalidArgument);

        handle_import_provider_profiles(
            &state,
            Request::new(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(ProviderProfile {
                        id: "delegated-refresh-api".to_string(),
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
                            refresh: Some(ProviderCredentialRefresh {
                                strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken
                                    as i32,
                                token_url: "https://login.example/token".to_string(),
                                scopes: vec!["https://example.test/.default".to_string()],
                                refresh_before_seconds: 300,
                                max_lifetime_seconds: 3600,
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
                        }],
                        endpoints: vec![],
                        binaries: vec![],
                        inference_capable: false,
                        discovery: None,
                    }),
                    source: "delegated-refresh-api.yaml".to_string(),
                }],
            }),
        )
        .await
        .unwrap();
        let delegated_refresh_bootstrap_provider = create_provider_record(
            store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "delegated-refresh-no-token-yet".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: "delegated-refresh-api".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
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
            Request::new(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(mixed_required_profile),
                    source: "mixed-required-api.yaml".to_string(),
                }],
            }),
        )
        .await
        .unwrap();
        let mixed_required_empty = create_provider_record(
            store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "mixed-required-no-token-yet".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: "mixed-required-api".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
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
            Request::new(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(optional_static_profile),
                    source: "optional-static-api.yaml".to_string(),
                }],
            }),
        )
        .await
        .unwrap();
        let optional_static_empty = create_provider_record(
            store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "optional-static-no-token-yet".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: "optional-static-api".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
            },
        )
        .await
        .unwrap();
        assert!(optional_static_empty.credentials.is_empty());

        let get_err = get_provider_record(store, "").await.unwrap_err();
        assert_eq!(get_err.code(), Code::InvalidArgument);

        let delete_err = delete_provider_record(store, "").await.unwrap_err();
        assert_eq!(delete_err.code(), Code::InvalidArgument);

        let update_missing_err = update_provider_record(
            store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "missing".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(update_missing_err.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn update_provider_empty_maps_is_noop() {
        let store = test_store().await;

        let created = provider_with_values("noop-test", "nvidia");
        let persisted = create_provider_record(&store, created).await.unwrap();

        let updated = update_provider_record(
            &store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "noop-test".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
            },
        )
        .await
        .unwrap();

        assert_eq!(updated.object_id(), persisted.object_id());
        assert_eq!(updated.r#type, "nvidia");
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
            .get_message_by_name("noop-test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.credentials.len(), 2);
    }

    #[tokio::test]
    async fn update_provider_empty_value_deletes_key() {
        let store = test_store().await;

        let created = provider_with_values("delete-key-test", "openai");
        create_provider_record(&store, created).await.unwrap();

        let updated = update_provider_record(
            &store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "delete-key-test".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: String::new(),
                credentials: std::iter::once(("SECONDARY".to_string(), String::new())).collect(),
                config: std::iter::once(("region".to_string(), String::new())).collect(),
                credential_expires_at_ms: HashMap::new(),
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
            .get_message_by_name("delete-key-test")
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

        let created = provider_with_values("type-preserve-test", "anthropic");
        create_provider_record(&store, created).await.unwrap();

        let updated = update_provider_record(
            &store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "type-preserve-test".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
            },
        )
        .await
        .unwrap();

        assert_eq!(updated.r#type, "anthropic");
    }

    #[tokio::test]
    async fn update_provider_rejects_type_change() {
        let store = test_store().await;

        let created = provider_with_values("type-change-test", "nvidia");
        create_provider_record(&store, created).await.unwrap();

        let err = update_provider_record(
            &store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "type-change-test".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: "openai".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
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
        create_provider_record(&store, created).await.unwrap();

        let oversized_key = "K".repeat(MAX_MAP_KEY_LEN + 1);
        let err = update_provider_record(
            &store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "validate-merge-test".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: String::new(),
                credentials: std::iter::once((oversized_key, "value".to_string())).collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn resolve_provider_env_empty_list_returns_empty() {
        let store = test_store().await;
        let result = resolve_provider_environment(&store, &[]).await.unwrap();
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
        };
        create_provider_record(&store, provider).await.unwrap();

        let result = resolve_provider_environment(&store, &["claude-local".to_string()])
            .await
            .unwrap();
        assert_eq!(result.get("ANTHROPIC_API_KEY"), Some(&"sk-abc".to_string()));
        assert_eq!(result.get("CLAUDE_API_KEY"), Some(&"sk-abc".to_string()));
        assert!(!result.contains_key("endpoint"));
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
        };
        create_provider_record(&store, provider).await.unwrap();

        let result = resolve_provider_environment(&store, &["expiring-provider".to_string()])
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
        let err = resolve_provider_environment(&store, &["nonexistent".to_string()])
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
        };
        create_provider_record(&store, provider).await.unwrap();

        let result = resolve_provider_environment(&store, &["test-provider".to_string()])
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
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "claude-local".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: "claude".to_string(),
                credentials: std::iter::once((
                    "ANTHROPIC_API_KEY".to_string(),
                    "sk-abc".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
            },
        )
        .await
        .unwrap();
        create_provider_record(
            &store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "gitlab-local".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: "gitlab".to_string(),
                credentials: std::iter::once(("GITLAB_TOKEN".to_string(), "glpat-xyz".to_string()))
                    .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let result = resolve_provider_environment(
            &store,
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
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "provider-a".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: "claude".to_string(),
                credentials: std::iter::once(("SHARED_KEY".to_string(), "first-value".to_string()))
                    .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
            },
        )
        .await
        .unwrap();
        create_provider_record(
            &store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "provider-b".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: "gitlab".to_string(),
                credentials: std::iter::once((
                    "SHARED_KEY".to_string(),
                    "second-value".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let err = resolve_provider_environment(
            &store,
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
    async fn update_provider_rejects_credential_key_collision_for_attached_sandbox() {
        let store = test_store().await;
        create_provider_record(
            &store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "provider-a".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: "outlook".to_string(),
                credentials: std::iter::once((
                    "MS_GRAPH_ACCESS_TOKEN".to_string(),
                    "graph-token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
            },
        )
        .await
        .unwrap();
        create_provider_record(
            &store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "provider-b".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: "google-drive".to_string(),
                credentials: std::iter::once((
                    "GOOGLE_ACCESS_TOKEN".to_string(),
                    "google-token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
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
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "provider-b".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: String::new(),
                credentials: std::iter::once((
                    "MS_GRAPH_ACCESS_TOKEN".to_string(),
                    "wrong-token".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("collision"));
        assert!(err.message().contains("MS_GRAPH_ACCESS_TOKEN"));
    }

    #[tokio::test]
    async fn handler_flow_resolves_credentials_from_sandbox_providers() {
        use openshell_core::proto::{Sandbox, SandboxPhase, SandboxSpec};

        let store = test_store().await;

        create_provider_record(
            &store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "my-claude".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                r#type: "claude".to_string(),
                credentials: std::iter::once((
                    "ANTHROPIC_API_KEY".to_string(),
                    "sk-test".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
                credential_expires_at_ms: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sandbox-001".to_string(),
                name: "test-sandbox".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                providers: vec!["my-claude".to_string()],
                ..SandboxSpec::default()
            }),
            status: None,
            phase: SandboxPhase::Ready as i32,
            ..Default::default()
        };
        store.put_message(&sandbox).await.unwrap();

        let loaded = store
            .get_message::<Sandbox>("sandbox-001")
            .await
            .unwrap()
            .unwrap();
        let spec = loaded.spec.unwrap();
        let env = resolve_provider_environment(&store, &spec.providers)
            .await
            .unwrap();

        assert_eq!(env.get("ANTHROPIC_API_KEY"), Some(&"sk-test".to_string()));
    }

    #[tokio::test]
    async fn handler_flow_returns_empty_when_no_providers() {
        use openshell_core::proto::{Sandbox, SandboxPhase, SandboxSpec};

        let store = test_store().await;

        let sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sandbox-002".to_string(),
                name: "empty-sandbox".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec::default()),
            status: None,
            phase: SandboxPhase::Ready as i32,
            ..Default::default()
        };
        store.put_message(&sandbox).await.unwrap();

        let loaded = store
            .get_message::<Sandbox>("sandbox-002")
            .await
            .unwrap()
            .unwrap();
        let spec = loaded.spec.unwrap();
        let env = resolve_provider_environment(&store, &spec.providers)
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
        let created = create_provider_record(&store, provider.clone())
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
            }),
            r#type: String::new(), // Empty type is ignored in update
            credentials: HashMap::new(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
        };

        // Attempt to update with an oversized credential key (exceeds MAX_MAP_KEY_LEN)
        update_req.credentials.insert(
            "k".repeat(MAX_MAP_KEY_LEN + 1),
            "oversized-key-value".to_string(),
        );

        let result = update_provider_record(&store, update_req).await;

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
            .get_message_by_name::<Provider>("test-validate-provider")
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
        let handle1 = tokio::spawn(async move { create_provider_record(&store1, provider1).await });

        let store2 = store.clone();
        let provider2 = provider.clone();
        let handle2 = tokio::spawn(async move { create_provider_record(&store2, provider2).await });

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
            .get_message_by_name::<Provider>("test-concurrent-provider")
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
    async fn update_provider_client_driven_cas_succeeds_with_correct_version() {
        let state = test_server_state().await;

        // Create a provider
        let mut provider = provider_with_values("test-provider", "generic");
        provider.metadata.as_mut().unwrap().id = String::new();
        handle_create_provider(
            &state,
            Request::new(CreateProviderRequest {
                provider: Some(provider.clone()),
            }),
        )
        .await
        .unwrap();

        // Fetch the provider to get its current resource_version
        let current = state
            .store
            .get_message_by_name::<Provider>("test-provider")
            .await
            .unwrap()
            .unwrap();
        let current_version = current.metadata.as_ref().unwrap().resource_version;

        // Prepare an update with the correct resource_version
        let mut updated_provider = current.clone();
        updated_provider
            .credentials
            .insert("NEW_KEY".to_string(), "new-value".to_string());
        updated_provider.metadata.as_mut().unwrap().resource_version = current_version;

        // Update should succeed
        let response = handle_update_provider(
            &state,
            Request::new(UpdateProviderRequest {
                provider: Some(updated_provider.clone()),
                credential_expires_at_ms: HashMap::new(),
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
        assert!(
            response
                .provider
                .unwrap()
                .credentials
                .contains_key("NEW_KEY")
        );
    }

    #[tokio::test]
    async fn update_provider_client_driven_cas_rejects_stale_version() {
        let state = test_server_state().await;

        // Create a provider
        let mut provider = provider_with_values("test-provider", "generic");
        provider.metadata.as_mut().unwrap().id = String::new();
        handle_create_provider(
            &state,
            Request::new(CreateProviderRequest {
                provider: Some(provider.clone()),
            }),
        )
        .await
        .unwrap();

        // Fetch the current state
        let current = state
            .store
            .get_message_by_name::<Provider>("test-provider")
            .await
            .unwrap()
            .unwrap();
        let current_version = current.metadata.as_ref().unwrap().resource_version;

        // Prepare an update with a stale resource_version
        let mut stale_provider = current.clone();
        stale_provider
            .credentials
            .insert("NEW_KEY".to_string(), "new-value".to_string());
        stale_provider.metadata.as_mut().unwrap().resource_version = 99; // stale version

        // Update should fail with ABORTED
        let err = handle_update_provider(
            &state,
            Request::new(UpdateProviderRequest {
                provider: Some(stale_provider),
                credential_expires_at_ms: HashMap::new(),
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
            .get_message_by_name::<Provider>("test-provider")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            unchanged.metadata.as_ref().unwrap().resource_version,
            current_version
        );
        assert!(!unchanged.credentials.contains_key("NEW_KEY"));
    }

    #[tokio::test]
    async fn update_provider_concurrent_updates_with_stale_versions() {
        use std::sync::Arc;

        let state = Arc::new(test_server_state().await);

        // Create a provider
        let mut provider = provider_with_values("test-provider", "generic");
        provider.metadata.as_mut().unwrap().id = String::new();
        handle_create_provider(
            &state,
            Request::new(CreateProviderRequest {
                provider: Some(provider.clone()),
            }),
        )
        .await
        .unwrap();

        // All three clients fetch the provider and see the same version
        let initial = state
            .store
            .get_message_by_name::<Provider>("test-provider")
            .await
            .unwrap()
            .unwrap();
        let initial_version = initial.metadata.as_ref().unwrap().resource_version;

        // Launch 3 concurrent updates, all using the same initial version
        let mut handles = vec![];
        for i in 0..3 {
            let state_clone = Arc::clone(&state);
            let mut updated = initial.clone();
            updated
                .credentials
                .insert(format!("KEY_{i}"), format!("value-{i}"));
            updated.metadata.as_mut().unwrap().resource_version = initial_version;

            let handle = tokio::spawn(async move {
                handle_update_provider(
                    &state_clone,
                    Request::new(UpdateProviderRequest {
                        provider: Some(updated),
                        credential_expires_at_ms: HashMap::new(),
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
            .get_message_by_name::<Provider>("test-provider")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            final_provider.metadata.as_ref().unwrap().resource_version,
            initial_version + 1
        );

        // Exactly one of KEY_0, KEY_1, or KEY_2 should be present
        let new_keys_count = (0..3)
            .filter(|i| final_provider.credentials.contains_key(&format!("KEY_{i}")))
            .count();
        assert_eq!(new_keys_count, 1);
    }
}
