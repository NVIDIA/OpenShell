// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider CRUD operations and environment resolution.

#![allow(clippy::result_large_err)] // gRPC handlers return Result<Response<_>, Status>

use crate::persistence::{ObjectType, Store, generate_name};
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
    CreateProviderRequest, DeleteProviderRequest, DeleteProviderResponse,
    GetProviderProfileRequest, GetProviderRequest, ListProviderProfilesRequest,
    ListProviderProfilesResponse, ListProvidersRequest, ListProvidersResponse,
    ProviderProfileResponse, ProviderResponse, UpdateProviderRequest,
};
use openshell_providers::{default_profiles, get_default_profile};
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

pub(super) fn handle_list_provider_profiles(
    _state: &Arc<ServerState>,
    request: Request<ListProviderProfilesRequest>,
) -> Response<ListProviderProfilesResponse> {
    let request = request.into_inner();
    let limit = clamp_limit(request.limit, 100, MAX_PAGE_SIZE) as usize;
    let offset = request.offset as usize;
    let profiles = default_profiles()
        .iter()
        .skip(offset)
        .take(limit)
        .map(openshell_providers::ProviderTypeProfile::to_proto)
        .collect();

    Response::new(ListProviderProfilesResponse { profiles })
}

pub(super) fn handle_get_provider_profile(
    _state: &Arc<ServerState>,
    request: Request<GetProviderProfileRequest>,
) -> Result<Response<ProviderProfileResponse>, Status> {
    let id = request.into_inner().id;
    if id.trim().is_empty() {
        return Err(Status::invalid_argument("id is required"));
    }
    let profile = get_default_profile(id.trim())
        .ok_or_else(|| Status::not_found("provider profile not found"))?
        .to_proto();

    Ok(Response::new(ProviderProfileResponse {
        profile: Some(profile),
    }))
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
        GetProviderProfileRequest, ListProviderProfilesRequest, ProviderProfileCategory,
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
        .unwrap_err();
        assert_eq!(generic_err.code(), Code::NotFound);
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
