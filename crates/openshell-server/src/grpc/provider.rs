// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider CRUD operations and environment resolution.

#![allow(clippy::result_large_err)] // gRPC handlers return Result<Response<_>, Status>

use crate::persistence::{ObjectName, ObjectType, Store, generate_name};
use openshell_core::proto::Provider;
use prost::Message;
use tonic::Status;
use tracing::warn;

use super::validation::validate_provider_fields;
use super::{MAX_PAGE_SIZE, clamp_limit};

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

pub(super) async fn create_provider_record(
    store: &Store,
    mut provider: Provider,
) -> Result<Provider, Status> {
    use crate::persistence::{ObjectName, current_time_ms};

    // Initialize metadata if not present
    if provider.metadata.is_none() {
        let now_ms = current_time_ms()
            .map_err(|e| Status::internal(format!("failed to get current time: {e}")))?;
        provider.metadata = Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: generate_name(),
            created_at_ms: now_ms,
            labels: std::collections::HashMap::new(),
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
    if provider.credentials.is_empty() {
        return Err(Status::invalid_argument(
            "provider.credentials must not be empty",
        ));
    }

    // Validate field sizes before any I/O.
    validate_provider_fields(&provider)?;

    let existing = store
        .get_message_by_name::<Provider>(provider.object_name())
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?;

    if existing.is_some() {
        return Err(Status::already_exists("provider already exists"));
    }

    store
        .put_message(&provider)
        .await
        .map_err(|e| Status::internal(format!("persist provider failed: {e}")))?;

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
    let records = store
        .list(Provider::object_type(), limit, offset)
        .await
        .map_err(|e| Status::internal(format!("list providers failed: {e}")))?;

    let mut providers = Vec::with_capacity(records.len());
    for record in records {
        let provider = Provider::decode(record.payload.as_slice())
            .map_err(|e| Status::internal(format!("decode provider failed: {e}")))?;
        providers.push(redact_provider_credentials(provider));
    }

    Ok(providers)
}

pub(super) async fn update_provider_record(
    store: &Store,
    provider: Provider,
) -> Result<Provider, Status> {
    use crate::persistence::ObjectName;

    if provider.object_name().is_empty() {
        return Err(Status::invalid_argument("provider.name is required"));
    }

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

    let updated = Provider {
        metadata: existing.metadata,
        r#type: existing.r#type,
        credentials: merge_map(existing.credentials, provider.credentials),
        config: merge_map(existing.config, provider.config),
    };

    // Ensure metadata is valid (defense in depth - existing.metadata should always be valid)
    super::validation::validate_object_metadata(updated.metadata.as_ref(), "provider")?;

    validate_provider_fields(&updated)?;

    store
        .put_message(&updated)
        .await
        .map_err(|e| Status::internal(format!("persist provider failed: {e}")))?;

    Ok(redact_provider_credentials(updated))
}

pub(super) async fn delete_provider_record(store: &Store, name: &str) -> Result<bool, Status> {
    if name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    store
        .delete_by_name(Provider::object_type(), name)
        .await
        .map_err(|e| Status::internal(format!("delete provider failed: {e}")))
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

// ---------------------------------------------------------------------------
// Provider environment resolution
// ---------------------------------------------------------------------------

/// Resolve provider credentials into environment variables.
///
/// For each provider name in the list, fetches the provider from the store and
/// collects credential key-value pairs. Returns a map of environment variables
/// to inject into the sandbox. When duplicate keys appear across providers, the
/// first provider's value wins.
pub(super) async fn resolve_provider_environment(
    store: &Store,
    provider_names: &[String],
) -> Result<std::collections::HashMap<String, String>, Status> {
    if provider_names.is_empty() {
        return Ok(std::collections::HashMap::new());
    }

    let mut env = std::collections::HashMap::new();

    for name in provider_names {
        let provider = store
            .get_message_by_name::<Provider>(name)
            .await
            .map_err(|e| Status::internal(format!("failed to fetch provider '{name}': {e}")))?
            .ok_or_else(|| Status::failed_precondition(format!("provider '{name}' not found")))?;

        for (key, value) in &provider.credentials {
            if is_valid_env_key(key) {
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

    Ok(env)
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
    CreateProviderRequest, DeleteProviderProfileRequest, DeleteProviderProfileResponse,
    DeleteProviderRequest, DeleteProviderResponse, GetProviderProfileRequest, GetProviderRequest,
    ImportProviderProfilesRequest, ImportProviderProfilesResponse, LintProviderProfilesRequest,
    LintProviderProfilesResponse, ListProviderProfilesRequest, ListProviderProfilesResponse,
    ListProvidersRequest, ListProvidersResponse, ProviderProfile, ProviderProfileDiagnostic,
    ProviderProfileImportItem, ProviderProfileResponse, ProviderResponse, Sandbox,
    StoredProviderProfile, UpdateProviderRequest,
};
use openshell_providers::{
    ProfileValidationDiagnostic, ProviderTypeProfile, default_profiles, get_default_profile,
    normalize_profile_id, normalize_provider_type, validate_profile_set,
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
            .put_message(&stored)
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
    let records = store
        .list(StoredProviderProfile::object_type(), 10_000, 0)
        .await
        .map_err(|e| Status::internal(format!("list provider profiles failed: {e}")))?;

    let mut profiles = Vec::with_capacity(records.len());
    for record in records {
        let profile = StoredProviderProfile::decode(record.payload.as_slice())
            .map_err(|e| Status::internal(format!("decode provider profile failed: {e}")))?;
        profiles.push(profile);
    }
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
        if let Some(provider_type) = normalize_provider_type(&id) {
            diagnostics.push(ProfileValidationDiagnostic {
                source: source.clone(),
                profile_id: id.clone(),
                field: "id".to_string(),
                message: format!(
                    "provider profile id '{id}' is reserved for legacy provider type '{provider_type}'"
                ),
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
    let now_ms = current_time_ms().unwrap_or_default();
    StoredProviderProfile {
        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: profile.id.clone(),
            created_at_ms: now_ms,
            labels: std::collections::HashMap::new(),
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
    let mut blocking = Vec::new();
    let mut offset = 0;
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
            let Some(spec) = sandbox.spec.as_ref() else {
                continue;
            };
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
    let provider = req
        .provider
        .ok_or_else(|| Status::invalid_argument("provider is required"))?;
    let provider = update_provider_record(state.store.as_ref(), provider).await?;

    Ok(Response::new(ProviderResponse {
        provider: Some(provider),
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
    use crate::ServerState;
    use crate::compute::new_test_runtime;
    use crate::grpc::MAX_MAP_KEY_LEN;
    use crate::sandbox_index::SandboxIndex;
    use crate::sandbox_watch::SandboxWatchBus;
    use crate::supervisor_session::SupervisorSessionRegistry;
    use crate::tracing_bus::TracingLogBus;
    use openshell_core::Config;
    use openshell_core::proto::{
        DeleteProviderProfileRequest, GetProviderProfileRequest, ImportProviderProfilesRequest,
        L7Allow, L7Rule, LintProviderProfilesRequest, ListProviderProfilesRequest, NetworkBinary,
        NetworkEndpoint, ProviderProfile, ProviderProfileCategory, ProviderProfileImportItem,
        Sandbox, SandboxSpec,
    };
    use openshell_core::{ObjectId, ObjectName};
    use std::collections::HashMap;
    use std::sync::Arc;
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

    async fn test_server_state() -> Arc<ServerState> {
        let store = Arc::new(
            Store::connect("sqlite::memory:?cache=shared")
                .await
                .unwrap(),
        );
        let compute = new_test_runtime(store.clone()).await;
        Arc::new(ServerState::new(
            Config::new(None)
                .with_database_url("sqlite::memory:?cache=shared")
                .with_ssh_handshake_secret("test-secret"),
            store,
            compute,
            SandboxIndex::new(),
            SandboxWatchBus::new(),
            TracingLogBus::new(),
            Arc::new(SupervisorSessionRegistry::new()),
            None,
        ))
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

        let github = response
            .profiles
            .iter()
            .find(|profile| profile.id == "github")
            .expect("github profile should be listed");
        assert_eq!(
            github.category,
            ProviderProfileCategory::SourceControl as i32
        );
        assert!(
            response
                .profiles
                .iter()
                .all(|profile| profile.id != "generic"),
            "generic remains a legacy provider type without a v2 profile"
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
    async fn import_provider_profile_rejects_legacy_provider_type_ids() {
        let state = test_server_state().await;
        let response = handle_import_provider_profiles(
            &state,
            Request::new(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(custom_profile("generic")),
                    source: "generic.yaml".to_string(),
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
                .any(|diagnostic| diagnostic.message.contains("reserved"))
        );

        let missing = handle_get_provider_profile(
            &state,
            Request::new(GetProviderProfileRequest {
                id: "generic".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(missing.code(), Code::NotFound);
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
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

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
                }),
                r#type: "gitlab".to_string(),
                credentials: std::iter::once((
                    "API_TOKEN".to_string(),
                    "rotated-token".to_string(),
                ))
                .collect(),
                config: std::iter::once(("endpoint".to_string(), "https://gitlab.com".to_string()))
                    .collect(),
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
    async fn provider_validation_errors() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let create_missing_type = create_provider_record(
            &store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "bad-provider".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                }),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(create_missing_type.code(), Code::InvalidArgument);

        let get_err = get_provider_record(&store, "").await.unwrap_err();
        assert_eq!(get_err.code(), Code::InvalidArgument);

        let delete_err = delete_provider_record(&store, "").await.unwrap_err();
        assert_eq!(delete_err.code(), Code::InvalidArgument);

        let update_missing_err = update_provider_record(
            &store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "missing".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                }),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(update_missing_err.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn update_provider_empty_maps_is_noop() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

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
                }),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
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
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

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
                }),
                r#type: String::new(),
                credentials: std::iter::once(("SECONDARY".to_string(), String::new())).collect(),
                config: std::iter::once(("region".to_string(), String::new())).collect(),
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
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

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
                }),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
            },
        )
        .await
        .unwrap();

        assert_eq!(updated.r#type, "anthropic");
    }

    #[tokio::test]
    async fn update_provider_rejects_type_change() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

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
                }),
                r#type: "openai".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("type cannot be changed"));
    }

    #[tokio::test]
    async fn update_provider_validates_merged_result() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

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
                }),
                r#type: String::new(),
                credentials: std::iter::once((oversized_key, "value".to_string())).collect(),
                config: HashMap::new(),
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn resolve_provider_env_empty_list_returns_empty() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let result = resolve_provider_environment(&store, &[]).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn resolve_provider_env_injects_credentials() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let provider = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: "claude-local".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
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
    async fn resolve_provider_env_unknown_name_returns_error() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let err = resolve_provider_environment(&store, &["nonexistent".to_string()])
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("nonexistent"));
    }

    #[tokio::test]
    async fn resolve_provider_env_skips_invalid_credential_keys() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let provider = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: "test-provider".to_string(),
                created_at_ms: 0,
                labels: HashMap::new(),
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
        let store = Store::connect("sqlite::memory:").await.unwrap();
        create_provider_record(
            &store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "claude-local".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                }),
                r#type: "claude".to_string(),
                credentials: std::iter::once((
                    "ANTHROPIC_API_KEY".to_string(),
                    "sk-abc".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
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
                }),
                r#type: "gitlab".to_string(),
                credentials: std::iter::once(("GITLAB_TOKEN".to_string(), "glpat-xyz".to_string()))
                    .collect(),
                config: HashMap::new(),
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
    async fn resolve_provider_env_first_credential_wins_on_duplicate_key() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        create_provider_record(
            &store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "provider-a".to_string(),
                    created_at_ms: 0,
                    labels: HashMap::new(),
                }),
                r#type: "claude".to_string(),
                credentials: std::iter::once(("SHARED_KEY".to_string(), "first-value".to_string()))
                    .collect(),
                config: HashMap::new(),
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
                }),
                r#type: "gitlab".to_string(),
                credentials: std::iter::once((
                    "SHARED_KEY".to_string(),
                    "second-value".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let result = resolve_provider_environment(
            &store,
            &["provider-a".to_string(), "provider-b".to_string()],
        )
        .await
        .unwrap();
        assert_eq!(result.get("SHARED_KEY"), Some(&"first-value".to_string()));
    }

    #[tokio::test]
    async fn handler_flow_resolves_credentials_from_sandbox_providers() {
        use openshell_core::proto::{Sandbox, SandboxPhase, SandboxSpec};

        let store = Store::connect("sqlite::memory:").await.unwrap();

        create_provider_record(
            &store,
            Provider {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: "my-claude".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                }),
                r#type: "claude".to_string(),
                credentials: std::iter::once((
                    "ANTHROPIC_API_KEY".to_string(),
                    "sk-test".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
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

        let store = Store::connect("sqlite::memory:").await.unwrap();

        let sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sandbox-002".to_string(),
                name: "empty-sandbox".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
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

        let store = Store::connect("sqlite::memory:").await.unwrap();
        let result = store.get_message::<Sandbox>("nonexistent").await.unwrap();
        assert!(result.is_none());
    }
}
