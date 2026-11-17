// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway refresh adaptation. Execution and scheduling live in the issuer.
#![allow(clippy::result_large_err)]
use crate::credentials::{CredentialRuntime, RefreshMaterialScope};
use crate::persistence::{Store, current_time_ms};
#[cfg(test)]
pub use crate::refresh_store::{get_refresh_state, list_refresh_states_for_provider};
#[cfg(test)]
pub use crate::refresh_store::{list_all_refresh_states, put_refresh_state};
use crate::storage_proto::{
    StoredProviderCredentialRefreshStateV2 as StoredProviderCredentialRefreshState,
    StoredRefreshMaterialDeletion,
};
use openshell_core::proto::{
    CredentialHandle, Provider, ProviderCredentialRefreshRecoveryAction,
    ProviderCredentialRefreshStatus, ProviderCredentialRefreshStrategy,
};
use openshell_core::{ObjectId, ObjectName, ObjectWorkspace};
pub use openshell_credential_issuer::refresh::minter::{
    material_scopes, next_refresh_at_ms, parse_material_i64, refresh_strategy_name,
    strategy_secret_material_keys,
};
use openshell_credential_issuer::refresh::{
    CredentialRefresh, RefreshCommitSink, RefreshRuntime, RefreshState, RefreshStateStore,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tonic::Status;
use tracing::{info, warn};
const EXPIRATION_PRESENT_ANNOTATION: &str = "openshell.nvidia.com/refresh-expiration-present";
pub fn is_gateway_mintable_strategy(strategy: ProviderCredentialRefreshStrategy) -> bool {
    openshell_credential_issuer::refresh::minter::can_mint(strategy as i32)
}
pub fn runtime(
    store: &Arc<Store>,
    credentials: Option<&CredentialRuntime>,
    compute: Option<&crate::compute::ComputeRuntime>,
) -> RefreshRuntime {
    let refresh_store: Arc<dyn RefreshStateStore> =
        Arc::new(crate::refresh_store::ServerRefreshStore(Arc::clone(store)));
    RefreshRuntime::new(
        Arc::clone(&refresh_store),
        credentials.map(CredentialRuntime::issuer),
        Arc::new(crate::refresh_commit::ServerRefreshCommit {
            store: Arc::clone(store),
            compute: compute.cloned(),
            refresh_store,
        }),
    )
}
pub fn refresh_material_scope(
    state: &StoredProviderCredentialRefreshState,
) -> RefreshMaterialScope<'_> {
    RefreshMaterialScope {
        provider_name: &state.provider_name,
        workspace: state.object_workspace(),
        provider_id: &state.provider_id,
        credential_key: &state.credential_key,
    }
}

pub use openshell_credential_issuer::refresh::refresh_state_name;

/// Return the durable authorization epoch for one configured refresh grant.
///
/// Records created before the explicit epoch field was introduced use their
/// gateway-generated object ID as a stable migration epoch. An explicit
/// reconfiguration writes a new random epoch while preserving object metadata,
/// so reauthorization still revokes handles derived from the legacy value.
pub fn effective_authorization_epoch(
    state: &StoredProviderCredentialRefreshState,
) -> Result<&str, Status> {
    if !state.authorization_epoch.is_empty() {
        return Ok(&state.authorization_epoch);
    }
    state
        .metadata
        .as_ref()
        .map(|metadata| metadata.id.as_str())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            Status::failed_precondition("provider refresh state has no authorization epoch")
        })
}

pub fn refresh_status_from_state(
    state: &StoredProviderCredentialRefreshState,
) -> ProviderCredentialRefreshStatus {
    ProviderCredentialRefreshStatus {
        provider: state.provider_name.clone(),
        provider_id: state.provider_id.clone(),
        credential_key: state.credential_key.clone(),
        strategy: state.strategy,
        status: state.status.clone(),
        expiration_time: if refresh_has_expiration(state) {
            openshell_core::time::timestamp_from_millis(state.expires_at_ms).ok()
        } else {
            None
        },
        next_refresh_time: if state.next_refresh_at_ms == i64::MAX {
            None
        } else {
            openshell_core::time::optional_timestamp_from_legacy_millis(state.next_refresh_at_ms)
                .ok()
                .flatten()
        },
        last_refresh_time: openshell_core::time::optional_timestamp_from_legacy_millis(
            state.last_refresh_at_ms,
        )
        .ok()
        .flatten(),
        last_error: state.last_error.clone(),
        recovery_action: state.recovery_action,
        failure_code: state.failure_code.clone(),
        provider_error_subtype: state.provider_error_subtype.clone(),
        last_error_time: openshell_core::time::optional_timestamp_from_legacy_millis(
            state.last_error_at_ms,
        )
        .ok()
        .flatten(),
    }
}

/// Whether a refresh expiration was explicitly provided.
///
/// Legacy records infer presence from a nonzero millisecond value. New records
/// use a private metadata annotation only for the ambiguous Unix epoch value so
/// the frozen storage protobuf schema does not need to change.
pub fn refresh_has_expiration(state: &StoredProviderCredentialRefreshState) -> bool {
    state.expires_at_ms != 0
        || state.metadata.as_ref().is_some_and(|metadata| {
            metadata
                .annotations
                .get(EXPIRATION_PRESENT_ANNOTATION)
                .is_some_and(|value| value == "true")
        })
}

pub fn set_refresh_expiration_presence(
    state: &mut StoredProviderCredentialRefreshState,
    present: bool,
) {
    let Some(metadata) = state.metadata.as_mut() else {
        return;
    };
    if present && state.expires_at_ms == 0 {
        metadata.annotations.insert(
            EXPIRATION_PRESENT_ANNOTATION.to_string(),
            "true".to_string(),
        );
    } else {
        metadata.annotations.remove(EXPIRATION_PRESENT_ANNOTATION);
    }
}

pub struct NewRefreshStateConfig {
    pub strategy: ProviderCredentialRefreshStrategy,
    pub material: HashMap<String, String>,
    pub secret_material_keys: Vec<String>,
    pub expires_at_ms: i64,
    pub token_url: String,
    pub scopes: Vec<String>,
    pub refresh_before: Option<prost_types::Duration>,
    pub max_lifetime: Option<prost_types::Duration>,
    /// Resolved semantic output id -> concrete env key for credentials this
    /// refresh co-mints beyond its primary. Pinned from the profile's
    /// `additional_outputs` at configure time.
    pub additional_output_keys: HashMap<String, String>,
}

#[allow(clippy::unnecessary_wraps)]
pub fn new_refresh_state(
    provider: &Provider,
    workspace: &str,
    credential_key: &str,
    config: NewRefreshStateConfig,
) -> Result<StoredProviderCredentialRefreshState, Status> {
    if let Some(value) = config.refresh_before.as_ref() {
        openshell_core::time::duration_to_std(value)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
    }
    if let Some(value) = config.max_lifetime.as_ref() {
        let duration = openshell_core::time::duration_to_std(value)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        if duration.is_zero() {
            return Err(Status::invalid_argument(
                "max_lifetime must be greater than zero when present",
            ));
        }
    }
    let provider_id = provider.object_id().to_string();
    let provider_name = provider.object_name().to_string();
    let now_ms = current_time_ms();
    let next_refresh_at_ms =
        next_refresh_at_ms(config.expires_at_ms, config.refresh_before.as_ref());
    Ok(StoredProviderCredentialRefreshState {
        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: refresh_state_name(&provider_id, credential_key),
            created_time: openshell_core::time::timestamp_from_millis(now_ms).ok(),
            labels: HashMap::new(),
            resource_version: 0,
            annotations: HashMap::new(),
            workspace: workspace.to_string(),
            deletion_time: None,
        }),
        provider_id,
        provider_name,
        credential_key: credential_key.to_string(),
        strategy: config.strategy as i32,
        material: config.material,
        secret_material_keys: config.secret_material_keys,
        expires_at_ms: config.expires_at_ms,
        next_refresh_at_ms,
        last_refresh_at_ms: 0,
        status: "configured".to_string(),
        last_error: String::new(),
        token_url: config.token_url,
        scopes: config.scopes,
        refresh_before: config.refresh_before,
        max_lifetime: config.max_lifetime,
        additional_output_keys: config.additional_output_keys,
        authorization_epoch: uuid::Uuid::new_v4().to_string(),
        secret_material_handles: HashMap::new(),
        pending_secret_deletions: Vec::new(),
        recovery_action: ProviderCredentialRefreshRecoveryAction::Unspecified as i32,
        failure_code: String::new(),
        provider_error_subtype: String::new(),
        last_error_at_ms: 0,
    })
}

pub fn enqueue_pending_secret_deletion(
    state: &mut StoredProviderCredentialRefreshState,
    key: &str,
    handle: CredentialHandle,
) {
    state
        .pending_secret_deletions
        .push(StoredRefreshMaterialDeletion {
            material_key: key.to_string(),
            handle: Some(handle),
        });
}
/// Read-only adaptation for gateway validation. Ordinary callers use the shared
/// refresh service; the temporary provider-commit adapter borrows its injected
/// store port, avoiding an ownership cycle back into the refresh runtime.
#[derive(Clone, Copy)]
pub enum RefreshStateReader<'a> {
    Runtime(&'a dyn CredentialRefresh),
    CommitStore(&'a dyn RefreshStateStore),
}
impl RefreshStateReader<'_> {
    pub async fn list(
        self,
        provider_id: &str,
    ) -> Result<Vec<StoredProviderCredentialRefreshState>, Status> {
        let states = match self {
            Self::Runtime(refresh) => refresh.list(Some(provider_id)).await?,
            Self::CommitStore(store) => store.list(Some(provider_id)).await?,
        };
        Ok(states.iter().map(Into::into).collect())
    }
}

pub async fn delete_observed_refresh_state_with_credentials(
    refresh: &dyn CredentialRefresh,
    state: StoredProviderCredentialRefreshState,
) -> Result<(), Status> {
    refresh.delete((&state).into()).await
}
pub async fn delete_refresh_states_for_provider_with_credentials(
    refresh: &dyn CredentialRefresh,
    provider_id: &str,
) -> Result<u64, Status> {
    let states = refresh.list(Some(provider_id)).await?;
    let mut deleted = 0;
    for state in states {
        if let Some(latest) = refresh
            .get(state.object_workspace(), provider_id, &state.credential_key)
            .await?
        {
            refresh.delete(latest).await?;
            deleted += 1;
        }
    }
    Ok(deleted)
}
#[cfg(test)]
pub fn test_runtime(store: &Store) -> RefreshRuntime {
    runtime(&Arc::new(store.clone()), None, None)
}
pub fn publish_change(state: &Arc<crate::ServerState>, refresh: &RefreshState) {
    crate::refresh_commit::ServerRefreshCommitSink(state).notify(
        &openshell_credential_issuer::refresh::engine::change(refresh),
    );
}
pub fn spawn_refresh_worker(state: Arc<crate::ServerState>, interval: Duration) {
    info!(
        interval_seconds = interval.as_secs(),
        "provider credential refresh worker started"
    );
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            match state.refresh.sweep().await {
                Ok(changes) => {
                    let sink = crate::refresh_commit::ServerRefreshCommitSink(&state);
                    for change in changes {
                        sink.notify(&change);
                    }
                }
                Err(err) => {
                    warn!(error = %err, "provider credential refresh worker tick failed");
                }
            }
        }
    });
}

#[cfg(test)]
async fn delete_refresh_state_with_credentials(
    store: &Store,
    credentials: &CredentialRuntime,
    workspace: &str,
    provider_id: &str,
    key: &str,
) -> Result<bool, Status> {
    let runtime = runtime(&Arc::new(store.clone()), Some(credentials), None);
    let Some(state) = runtime.get(workspace, provider_id, key).await? else {
        return Ok(false);
    };
    runtime.delete(state).await?;
    Ok(true)
}
#[cfg(test)]
pub async fn refresh_provider_credential(
    store: &Store,
    workspace: &str,
    credentials: &CredentialRuntime,
    compute: Option<&crate::compute::ComputeRuntime>,
    provider: &str,
    key: &str,
) -> Result<StoredProviderCredentialRefreshState, Status> {
    runtime(&Arc::new(store.clone()), Some(credentials), compute)
        .rotate(workspace, provider, key)
        .await
        .map(|s| (&s).into())
}
#[cfg(test)]
pub async fn refresh_from_snapshot(
    store: &Store,
    credentials: &CredentialRuntime,
    compute: Option<&crate::compute::ComputeRuntime>,
    snapshot: StoredProviderCredentialRefreshState,
) -> Result<StoredProviderCredentialRefreshState, Status> {
    runtime(&Arc::new(store.clone()), Some(credentials), compute)
        .ensure_fresh((&snapshot).into())
        .await
        .map(|s| (&s).into())
}
#[cfg(test)]
async fn run_refresh_worker_tick(
    store: &Store,
    credentials: Option<&CredentialRuntime>,
    compute: Option<&crate::compute::ComputeRuntime>,
) -> Result<std::collections::HashSet<(String, String)>, Status> {
    Ok(runtime(&Arc::new(store.clone()), credentials, compute)
        .sweep()
        .await?
        .into_iter()
        .map(|c| (c.workspace, c.provider_name))
        .collect())
}
#[cfg(test)]
async fn refresh_states(
    store: &Store,
    credentials: Option<&CredentialRuntime>,
    compute: Option<&crate::compute::ComputeRuntime>,
    states: Vec<StoredProviderCredentialRefreshState>,
    now: i64,
) -> std::collections::HashSet<(String, String)> {
    openshell_credential_issuer::refresh::engine::refresh_states(
        &runtime(&Arc::new(store.clone()), credentials, compute),
        states.iter().map(Into::into).collect(),
        now,
    )
    .await
    .into_iter()
    .map(|c| (c.workspace, c.provider_name))
    .collect()
}
#[cfg(test)]
async fn apply_minted_credential(
    store: &Store,
    workspace: &str,
    credentials: Option<&CredentialRuntime>,
    compute: Option<&crate::compute::ComputeRuntime>,
    provider: &Provider,
    key: &str,
    minted: &MintedCredential,
) -> Result<(), Status> {
    use openshell_credential_issuer::refresh::GatewayRefreshCommit;
    let integration = crate::refresh_commit::ServerRefreshCommit {
        store: Arc::new(store.clone()),
        compute: compute.cloned(),
        refresh_store: Arc::new(crate::refresh_store::ServerRefreshStore(Arc::new(
            store.clone(),
        ))),
    };
    let attempt = integration
        .observe(workspace, provider.object_name())
        .await?;
    openshell_credential_issuer::refresh::engine::apply_minted_credential(
        credentials.map(CredentialRuntime::issuer).as_ref(),
        attempt.as_ref(),
        key,
        minted,
    )
    .await
}
#[cfg(test)]
use openshell_credential_issuer::refresh::minter::MintedCredential;
#[cfg(test)]
fn validate_secret_material_references(
    state: &StoredProviderCredentialRefreshState,
) -> Result<(), Status> {
    openshell_credential_issuer::refresh::engine::validate_secret_material_references(&state.into())
}
#[cfg(test)]
fn ensure_automatic_refresh_ready(
    state: &StoredProviderCredentialRefreshState,
    now: i64,
) -> Result<(), Status> {
    openshell_credential_issuer::refresh::engine::ensure_automatic_refresh_ready(&state.into(), now)
}
#[cfg(test)]
fn seconds_until_ms(now: i64, target: i64) -> i64 {
    if target <= 0 {
        0
    } else {
        target.saturating_sub(now).max(0) / 1000
    }
}
#[cfg(test)]
mod tests {
    use super::{
        NewRefreshStateConfig, delete_refresh_state_with_credentials,
        effective_authorization_epoch, enqueue_pending_secret_deletion,
        ensure_automatic_refresh_ready, get_refresh_state, list_all_refresh_states,
        list_refresh_states_for_provider, new_refresh_state, put_refresh_state,
        refresh_has_expiration, refresh_material_scope, refresh_provider_credential,
        refresh_state_name, refresh_status_from_state, refresh_strategy_name,
        run_refresh_worker_tick, seconds_until_ms, set_refresh_expiration_presence,
        validate_secret_material_references,
    };
    use crate::credentials::CredentialRuntime;
    use crate::persistence::{current_time_ms, test_store};
    use crate::storage_proto::StoredProviderCredentialRefreshStateV2 as StoredProviderCredentialRefreshState;

    use openshell_core::Config;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{
        CredentialHandle, Provider, ProviderCredentialRefreshRecoveryAction,
        ProviderCredentialRefreshStrategy, Sandbox, SandboxSpec,
    };
    use openshell_core::{ObjectId, ObjectName, ObjectWorkspace};
    use std::collections::HashMap;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn builtin_registry_matches_profile_descriptors_and_output_requirements() {
        use openshell_credential_issuer::refresh::minter::{built_in_minters, can_mint};
        let mut described = std::collections::BTreeSet::new();
        for strategy in [
            ProviderCredentialRefreshStrategy::Unspecified,
            ProviderCredentialRefreshStrategy::Static,
            ProviderCredentialRefreshStrategy::External,
            ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
            ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
            ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt,
            ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
        ] {
            assert_eq!(
                can_mint(strategy as i32),
                openshell_providers::is_gateway_mintable_strategy(strategy)
            );
            if can_mint(strategy as i32) {
                described.insert(refresh_strategy_name(strategy as i32));
            }
        }
        for profile in openshell_providers::example_profiles::load_all() {
            for credential in &profile.credentials {
                let Some(refresh) = &credential.refresh else {
                    continue;
                };
                assert_eq!(
                    can_mint(refresh.strategy as i32),
                    refresh.is_gateway_mintable()
                );
                if !refresh.is_gateway_mintable() {
                    continue;
                }
                let (required, optional) =
                    openshell_providers::strategy_output_spec(refresh.strategy);
                for output in required {
                    assert!(
                        refresh
                            .additional_outputs
                            .iter()
                            .any(|entry| entry.output == *output)
                    );
                }
                for output in &refresh.additional_outputs {
                    assert!(
                        required.contains(&output.output.as_str())
                            || optional.contains(&output.output.as_str())
                    );
                }
            }
        }
        assert_eq!(described, built_in_minters().strategy_names().collect());
        assert!(!can_mint(i32::MAX));
    }

    fn proto_duration(seconds: i64) -> prost_types::Duration {
        prost_types::Duration { seconds, nanos: 0 }
    }

    fn ts(milliseconds: i64) -> prost_types::Timestamp {
        openshell_core::time::timestamp_from_millis(milliseconds).unwrap()
    }

    fn test_credentials() -> CredentialRuntime {
        CredentialRuntime::from_config(&Config::new(None).with_credential_drivers(["test-static"]))
            .expect("test credential runtime")
    }

    #[test]
    fn refresh_state_name_preserves_distinct_credential_keys() {
        let provider_id = "provider-id";

        assert_ne!(
            refresh_state_name(provider_id, "API_KEY"),
            refresh_state_name(provider_id, "api_key")
        );
        assert_ne!(
            refresh_state_name(provider_id, " alex-api "),
            refresh_state_name(provider_id, " alex_api")
        );
        assert_ne!(
            refresh_state_name(provider_id, "Alex-API"),
            refresh_state_name(provider_id, "alex-api")
        );
    }

    #[tokio::test]
    async fn refresh_state_lists_hydrate_authoritative_resource_versions() {
        let store = test_store().await;
        let provider_id = "provider-id";
        let state = StoredProviderCredentialRefreshState {
            metadata: Some(ObjectMeta {
                id: "refresh-id".to_string(),
                name: refresh_state_name(provider_id, "ACCESS_TOKEN"),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            provider_id: provider_id.to_string(),
            credential_key: "ACCESS_TOKEN".to_string(),
            ..Default::default()
        };
        put_refresh_state(&store, &state).await.unwrap();

        let scoped = list_refresh_states_for_provider(&store, provider_id)
            .await
            .unwrap();
        let all = list_all_refresh_states(&store).await.unwrap();
        assert_eq!(scoped[0].metadata.as_ref().unwrap().resource_version, 1);
        assert_eq!(all[0].metadata.as_ref().unwrap().resource_version, 1);
    }

    #[test]
    fn new_refresh_configuration_rotates_authorization_epoch_and_legacy_state_is_stable() {
        let provider = Provider {
            metadata: Some(ObjectMeta {
                id: "provider-id".to_string(),
                name: "provider".to_string(),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let config = || NewRefreshStateConfig {
            strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
            material: HashMap::new(),
            secret_material_keys: Vec::new(),
            expires_at_ms: 0,
            token_url: "https://issuer.example/token".to_string(),
            scopes: vec!["scope".to_string()],
            refresh_before: Some(proto_duration(300)),
            max_lifetime: Some(proto_duration(3600)),
            additional_output_keys: HashMap::new(),
        };
        let first = new_refresh_state(&provider, "default", "ACCESS_TOKEN", config())
            .expect("first refresh configuration");
        let second = new_refresh_state(&provider, "default", "ACCESS_TOKEN", config())
            .expect("second refresh configuration");
        assert!(!first.authorization_epoch.is_empty());
        assert_ne!(first.authorization_epoch, second.authorization_epoch);

        let mut legacy = first;
        legacy.authorization_epoch.clear();
        assert_eq!(
            effective_authorization_epoch(&legacy).expect("legacy migration epoch"),
            legacy.metadata.as_ref().expect("metadata").id
        );
    }

    #[test]
    fn refresh_log_helpers_format_safe_operational_fields() {
        assert_eq!(seconds_until_ms(1_000, 61_000), 60);
        assert_eq!(seconds_until_ms(61_000, 1_000), 0);
        assert_eq!(seconds_until_ms(1_000, 0), 0);
        assert_eq!(
            refresh_strategy_name(ProviderCredentialRefreshStrategy::Oauth2RefreshToken as i32),
            "oauth2_refresh_token"
        );
        assert_eq!(
            refresh_strategy_name(
                ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32
            ),
            "oauth2_client_credentials"
        );
        assert_eq!(
            refresh_strategy_name(
                ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt as i32
            ),
            "google_service_account_jwt"
        );
        assert_eq!(refresh_strategy_name(i32::MAX), "unspecified");
    }

    #[test]
    fn refresh_expiration_presence_distinguishes_absent_epoch_and_legacy_values() {
        let mut state = StoredProviderCredentialRefreshState {
            metadata: Some(ObjectMeta::default()),
            ..Default::default()
        };
        assert!(!refresh_has_expiration(&state));
        assert!(refresh_status_from_state(&state).expiration_time.is_none());

        set_refresh_expiration_presence(&mut state, true);
        assert!(refresh_has_expiration(&state));
        assert_eq!(
            refresh_status_from_state(&state).expiration_time,
            Some(ts(0))
        );

        set_refresh_expiration_presence(&mut state, false);
        assert!(!refresh_has_expiration(&state));

        state.expires_at_ms = 1;
        assert!(refresh_has_expiration(&state));
        assert_eq!(
            refresh_status_from_state(&state).expiration_time,
            Some(ts(1))
        );
    }

    #[test]
    fn pending_secret_deletions_preserve_multiple_generations_for_one_key() {
        let mut state = StoredProviderCredentialRefreshState::default();
        for handle in ["first", "second"] {
            enqueue_pending_secret_deletion(
                &mut state,
                "refresh_token",
                CredentialHandle {
                    driver: "test-static".to_string(),
                    handle: handle.to_string(),
                    metadata: HashMap::new(),
                },
            );
        }

        assert_eq!(state.pending_secret_deletions.len(), 2);
        assert_eq!(
            state.pending_secret_deletions[0]
                .handle
                .as_ref()
                .unwrap()
                .handle,
            "first"
        );
        assert_eq!(
            state.pending_secret_deletions[1]
                .handle
                .as_ref()
                .unwrap()
                .handle,
            "second"
        );
    }

    #[test]
    fn refresh_rejects_secret_material_lost_by_mixed_version_gateway() {
        let mut state = StoredProviderCredentialRefreshState {
            secret_material_keys: vec!["refresh_token".to_string()],
            ..Default::default()
        };
        let err = validate_secret_material_references(&state).unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("mixed-version gateway"));
        assert!(err.message().contains("refresh_token"));

        state.secret_material_handles.insert(
            "refresh_token".to_string(),
            CredentialHandle {
                driver: "test-static".to_string(),
                handle: "stored-token".to_string(),
                metadata: HashMap::new(),
            },
        );
        validate_secret_material_references(&state).unwrap();
    }

    #[tokio::test]
    async fn invalid_local_oauth_configuration_retries_hourly() {
        let store = test_store().await;
        let provider = provider("invalid-local-config", "outlook");
        store.put_message(&provider).await.unwrap();
        let state = new_refresh_state(
            &provider,
            "default",
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
                material: HashMap::from([
                    ("client_id".to_string(), "client-id".to_string()),
                    ("refresh_token".to_string(), "refresh-token".to_string()),
                ]),
                secret_material_keys: vec!["refresh_token".to_string()],
                expires_at_ms: 0,
                token_url: "not-an-absolute-url".to_string(),
                scopes: Vec::new(),
                refresh_before: Some(proto_duration(30)),
                max_lifetime: Some(proto_duration(60)),
                additional_output_keys: HashMap::new(),
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        let err = refresh_provider_credential(
            &store,
            "default",
            &test_credentials(),
            None,
            "invalid-local-config",
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        let stored = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stored.status, "configuration_required");
        assert_eq!(
            stored.recovery_action,
            ProviderCredentialRefreshRecoveryAction::FixConfiguration as i32
        );
        assert_eq!(stored.failure_code, "refresh_configuration_invalid");
        assert_eq!(
            stored.next_refresh_at_ms - stored.last_error_at_ms,
            60 * 60 * 1000
        );
    }

    #[tokio::test]
    async fn oauth_invalid_grant_persists_terminal_reauthorization_status() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_subtype": "invalid_rapt",
                "error_description": "provider-controlled detail"
            })))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let provider = provider("expired-grant", "outlook");
        store.put_message(&provider).await.unwrap();
        let state = new_refresh_state(
            &provider,
            "default",
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
                material: HashMap::from([
                    ("client_id".to_string(), "client-id".to_string()),
                    (
                        "refresh_token".to_string(),
                        "expired-refresh-token".to_string(),
                    ),
                ]),
                secret_material_keys: vec!["refresh_token".to_string()],
                expires_at_ms: 0,
                token_url: format!("{}/token", mock_server.uri()),
                scopes: Vec::new(),
                refresh_before: Some(proto_duration(30)),
                max_lifetime: Some(proto_duration(60)),
                additional_output_keys: HashMap::new(),
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        let err = refresh_provider_credential(
            &store,
            "default",
            &test_credentials(),
            None,
            "expired-grant",
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        let stored = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stored.status, "reauthorization_required");
        assert_eq!(stored.next_refresh_at_ms, i64::MAX);
        assert_eq!(
            stored.recovery_action,
            ProviderCredentialRefreshRecoveryAction::Reauthorize as i32
        );
        assert_eq!(stored.failure_code, "oauth_invalid_grant");
        assert_eq!(stored.provider_error_subtype, "invalid_rapt");
        assert!(stored.last_error_at_ms > 0);
        assert!(!stored.last_error.contains("provider-controlled detail"));
    }

    #[tokio::test]
    async fn oauth2_client_credentials_refresh_mints_and_persists_access_token() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains("client_id=client-id"))
            .and(body_string_contains(
                "scope=https%3A%2F%2Fgraph.microsoft.com%2F.default",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "minted-graph-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let provider = provider("my-graph", "outlook");
        store.put_message(&provider).await.unwrap();
        let before_refresh_ms = current_time_ms();
        let mut state = new_refresh_state(
            &provider,
            "default",
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::new(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
                material: HashMap::from([
                    ("client_id".to_string(), "client-id".to_string()),
                    ("client_secret".to_string(), "client-secret".to_string()),
                ]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: 0,
                token_url: format!("{}/token", mock_server.uri()),
                scopes: vec!["https://graph.microsoft.com/.default".to_string()],
                refresh_before: Some(proto_duration(30)),
                max_lifetime: Some(proto_duration(60)),
            },
        )
        .unwrap();
        state.status = "investigation_required".to_string();
        state.last_error = "safe prior error".to_string();
        state.recovery_action = ProviderCredentialRefreshRecoveryAction::Investigate as i32;
        state.failure_code = "oauth_unrecognized_error".to_string();
        state.provider_error_subtype = "prior_subtype".to_string();
        state.last_error_at_ms = current_time_ms();
        put_refresh_state(&store, &state).await.unwrap();
        let authorization_epoch = state.authorization_epoch.clone();
        let credentials = test_credentials();

        let refreshed = refresh_provider_credential(
            &store,
            "default",
            &credentials,
            None,
            "my-graph",
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap();
        assert_eq!(refreshed.authorization_epoch, authorization_epoch);
        assert_eq!(refreshed.status, "refreshed");
        assert!(refreshed.expires_at_ms > 0);
        assert!(refreshed.next_refresh_at_ms > 0);
        assert!(refreshed.expires_at_ms <= before_refresh_ms + 120_000);
        assert!(refreshed.last_error.is_empty());
        assert_eq!(
            refreshed.recovery_action,
            ProviderCredentialRefreshRecoveryAction::Unspecified as i32
        );
        assert!(refreshed.failure_code.is_empty());
        assert!(refreshed.provider_error_subtype.is_empty());
        assert_eq!(refreshed.last_error_at_ms, 0);

        let stored = store
            .get_message_by_name::<Provider>("default", "my-graph")
            .await
            .unwrap()
            .unwrap();
        let resolved = credentials
            .resolve_provider_handles(&stored, current_time_ms())
            .await
            .unwrap();
        assert_eq!(
            resolved.values.get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&"minted-graph-token".to_string())
        );
        assert_eq!(
            stored
                .credential_expiration_times
                .get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&ts(refreshed.expires_at_ms))
        );
    }

    #[tokio::test]
    async fn oauth2_client_credentials_refresh_stores_access_token_with_credential_runtime() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "stored-graph-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let provider = provider("my-stored-graph", "outlook");
        store.put_message(&provider).await.unwrap();
        let mut state = new_refresh_state(
            &provider,
            "default",
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
                material: HashMap::from([
                    ("client_id".to_string(), "client-id".to_string()),
                    ("client_secret".to_string(), "client-secret".to_string()),
                ]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: 0,
                token_url: format!("{}/token", mock_server.uri()),
                scopes: Vec::new(),
                refresh_before: Some(proto_duration(30)),
                max_lifetime: Some(proto_duration(60)),
                additional_output_keys: HashMap::new(),
            },
        )
        .unwrap();
        let config = Config::new(None).with_credential_drivers(["test-static"]);
        let credentials = CredentialRuntime::from_config(&config).unwrap();
        state.secret_material_handles = credentials
            .store_refresh_material_with_object_id(
                refresh_material_scope(&state),
                "configured-client-secret",
                &HashMap::from([("client_secret".to_string(), "client-secret".to_string())]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        state.material.remove("client_secret");
        put_refresh_state(&store, &state).await.unwrap();
        let authorization_epoch = state.authorization_epoch.clone();

        let refreshed = refresh_provider_credential(
            &store,
            "default",
            &credentials,
            None,
            "my-stored-graph",
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap();
        assert_eq!(refreshed.authorization_epoch, authorization_epoch);
        let stored_refresh = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!stored_refresh.material.contains_key("client_secret"));
        assert!(
            stored_refresh
                .secret_material_handles
                .contains_key("client_secret")
        );

        let stored = store
            .get_message_by_name::<Provider>("default", "my-stored-graph")
            .await
            .unwrap()
            .unwrap();
        assert!(!stored.credentials.contains_key("MS_GRAPH_ACCESS_TOKEN"));
        let handle = stored
            .credential_handles
            .get("MS_GRAPH_ACCESS_TOKEN")
            .unwrap();
        assert_eq!(handle.driver, "test-static");
        assert_eq!(
            stored
                .credential_expiration_times
                .get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&ts(refreshed.expires_at_ms))
        );

        let resolved = credentials
            .resolve_provider_handles(&stored, current_time_ms())
            .await
            .unwrap();
        assert_eq!(
            resolved.values.get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&"stored-graph-token".to_string())
        );
    }

    #[tokio::test]
    async fn refresh_rejects_minted_credential_key_collision_for_attached_sandbox() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "minted-graph-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let mut provider_a = provider("existing-graph", "outlook");
        provider_a.credentials.insert(
            "MS_GRAPH_ACCESS_TOKEN".to_string(),
            "existing-token".to_string(),
        );
        store.put_message(&provider_a).await.unwrap();
        let provider_b = provider("refreshing-graph", "outlook");
        store.put_message(&provider_b).await.unwrap();
        store
            .put_message(&Sandbox {
                metadata: Some(ObjectMeta {
                    id: "sandbox-collision".to_string(),
                    name: "collision".to_string(),
                    created_time: openshell_core::time::timestamp_from_millis(1).ok(),
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_time: None,
                }),
                spec: Some(SandboxSpec {
                    providers: vec!["existing-graph".to_string(), "refreshing-graph".to_string()],
                    ..SandboxSpec::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();
        let state = new_refresh_state(
            &provider_b,
            "default",
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::new(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
                material: HashMap::from([
                    ("client_id".to_string(), "client-id".to_string()),
                    ("client_secret".to_string(), "client-secret".to_string()),
                ]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: 0,
                token_url: format!("{}/token", mock_server.uri()),
                scopes: Vec::new(),
                refresh_before: Some(proto_duration(30)),
                max_lifetime: Some(proto_duration(60)),
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();
        let credentials = test_credentials();

        let err = refresh_provider_credential(
            &store,
            "default",
            &credentials,
            None,
            "refreshing-graph",
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("MS_GRAPH_ACCESS_TOKEN"));
        let stored_state = get_refresh_state(
            &store,
            "default",
            provider_b.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stored_state.status, "configuration_required");
        assert_eq!(
            stored_state.recovery_action,
            ProviderCredentialRefreshRecoveryAction::FixConfiguration as i32
        );
        assert_eq!(stored_state.failure_code, "refresh_configuration_invalid");
        assert_eq!(
            stored_state.next_refresh_at_ms - stored_state.last_error_at_ms,
            60 * 60 * 1000
        );
        assert!(stored_state.last_error.contains("MS_GRAPH_ACCESS_TOKEN"));
        let stored_provider = store
            .get_message_by_name::<Provider>("default", "refreshing-graph")
            .await
            .unwrap()
            .unwrap();
        assert!(
            !stored_provider
                .credentials
                .contains_key("MS_GRAPH_ACCESS_TOKEN")
        );
    }

    #[tokio::test]
    async fn oauth2_refresh_token_refresh_mints_access_token_and_persists_rotated_refresh_token() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("client_id=client-id"))
            .and(body_string_contains("refresh_token=old-refresh-token"))
            .and(body_string_contains(
                "scope=https%3A%2F%2Fgraph.microsoft.com%2F.default",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "delegated-graph-token",
                "refresh_token": "rotated-refresh-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let provider = provider("my-delegated-graph", "outlook");
        store.put_message(&provider).await.unwrap();
        let state = new_refresh_state(
            &provider,
            "default",
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::new(),
                strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
                material: HashMap::from([
                    ("client_id".to_string(), "client-id".to_string()),
                    ("refresh_token".to_string(), "old-refresh-token".to_string()),
                ]),
                secret_material_keys: vec!["refresh_token".to_string()],
                expires_at_ms: 0,
                token_url: format!("{}/token", mock_server.uri()),
                scopes: vec!["https://graph.microsoft.com/.default".to_string()],
                refresh_before: Some(proto_duration(30)),
                max_lifetime: Some(proto_duration(60)),
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();
        let credentials = CredentialRuntime::from_config(
            &Config::new(None).with_credential_drivers(["test-static"]),
        )
        .unwrap();

        let refreshed = refresh_provider_credential(
            &store,
            "default",
            &credentials,
            None,
            "my-delegated-graph",
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap();
        assert_eq!(refreshed.status, "refreshed");
        assert!(refreshed.expires_at_ms > 0);

        let stored_provider = store
            .get_message_by_name::<Provider>("default", "my-delegated-graph")
            .await
            .unwrap()
            .unwrap();
        assert!(
            !stored_provider
                .credentials
                .contains_key("MS_GRAPH_ACCESS_TOKEN")
        );
        assert!(
            stored_provider
                .credential_handles
                .contains_key("MS_GRAPH_ACCESS_TOKEN")
        );
        assert_eq!(
            stored_provider
                .credential_expiration_times
                .get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&ts(refreshed.expires_at_ms))
        );

        let stored_state = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!stored_state.material.contains_key("refresh_token"));
        assert!(
            stored_state
                .secret_material_handles
                .contains_key("refresh_token")
        );
        assert!(stored_state.pending_secret_deletions.is_empty());
        assert_eq!(
            credentials
                .resolve_refresh_material(
                    refresh_material_scope(&stored_state),
                    &stored_state.secret_material_handles,
                )
                .await
                .unwrap()
                .get("refresh_token"),
            Some(&"rotated-refresh-token".to_string())
        );
        assert!(
            stored_state
                .secret_material_keys
                .iter()
                .any(|key| key == "refresh_token")
        );
        assert_eq!(
            credentials.stored_credential_count(),
            Some(2),
            "only the access token and current refresh token remain"
        );
    }

    #[tokio::test]
    async fn refresh_continues_when_pending_secret_cleanup_temporarily_fails() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "minted-after-cleanup-failure",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let provider = provider("cleanup-retry", "outlook");
        store.put_message(&provider).await.unwrap();
        let credentials = test_credentials();
        let mut state = new_refresh_state(
            &provider,
            "default",
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
                material: HashMap::from([
                    ("client_id".to_string(), "client-id".to_string()),
                    ("client_secret".to_string(), "client-secret".to_string()),
                ]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: 0,
                token_url: format!("{}/token", mock_server.uri()),
                scopes: Vec::new(),
                refresh_before: Some(proto_duration(30)),
                max_lifetime: Some(proto_duration(60)),
                additional_output_keys: HashMap::new(),
            },
        )
        .unwrap();
        state.secret_material_handles = credentials
            .store_refresh_material_with_object_id(
                refresh_material_scope(&state),
                "current-refresh-object",
                &HashMap::from([("client_secret".to_string(), "client-secret".to_string())]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        state.material.remove("client_secret");
        let old = credentials
            .store_refresh_material_with_object_id(
                refresh_material_scope(&state),
                "old-refresh-object",
                &HashMap::from([("client_secret".to_string(), "obsolete".to_string())]),
                &HashMap::new(),
            )
            .await
            .unwrap()
            .remove("client_secret")
            .unwrap();
        enqueue_pending_secret_deletion(&mut state, "client_secret", old);
        put_refresh_state(&store, &state).await.unwrap();
        credentials.fail_next_delete();

        let refreshed = refresh_provider_credential(
            &store,
            "default",
            &credentials,
            None,
            "cleanup-retry",
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap();

        assert_eq!(refreshed.status, "refreshed");
        assert!(refreshed.pending_secret_deletions.is_empty());
        let stored = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert!(stored.pending_secret_deletions.is_empty());
        assert_eq!(
            credentials.stored_credential_count(),
            Some(2),
            "the current client secret and minted access token remain"
        );
    }

    #[tokio::test]
    async fn worker_cleanup_waits_for_mint_and_preserves_rotated_grant() {
        use std::time::Duration;

        let issuer = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("refresh_token=old-grant"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-access-token",
                "refresh_token": "replacement-grant",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&issuer)
            .await;
        let store = test_store().await;
        let provider = provider("cleanup-during-mint", "outlook");
        store.put_message(&provider).await.unwrap();
        let credentials = test_credentials();
        let mut state = new_refresh_state(
            &provider,
            "default",
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
                material: HashMap::from([
                    ("client_id".into(), "client".into()),
                    ("refresh_token".into(), "old-grant".into()),
                ]),
                secret_material_keys: vec!["refresh_token".into()],
                expires_at_ms: 1,
                token_url: issuer.uri(),
                scopes: vec![],
                refresh_before: None,
                max_lifetime: None,
                additional_output_keys: HashMap::new(),
            },
        )
        .unwrap();
        let obsolete = credentials
            .store_refresh_material_with_object_id(
                refresh_material_scope(&state),
                "obsolete-grant",
                &HashMap::from([("refresh_token".into(), "obsolete".into())]),
                &HashMap::new(),
            )
            .await
            .unwrap()
            .remove("refresh_token")
            .unwrap();
        enqueue_pending_secret_deletion(&mut state, "refresh_token", obsolete);
        put_refresh_state(&store, &state).await.unwrap();
        let sweep_snapshot = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        // Fail pre-mint cleanup, then stop at replacement-grant storage after
        // the issuer has rotated the grant but before the receipt CAS.
        credentials.fail_next_delete();
        let (storing, release) = credentials.gate_next_store();
        let mint_store = store.clone();
        let mint_credentials = credentials.clone();
        let mint = tokio::spawn(async move {
            refresh_provider_credential(
                &mint_store,
                "default",
                &mint_credentials,
                None,
                "cleanup-during-mint",
                "MS_GRAPH_ACCESS_TOKEN",
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(10), storing)
            .await
            .unwrap()
            .unwrap();
        let before_cleanup = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(before_cleanup.status, "refresh_in_progress");
        let cleanup_store = store.clone();
        let cleanup_credentials = credentials.clone();
        let mut sweep = tokio::spawn(async move {
            super::refresh_states(
                &cleanup_store,
                Some(&cleanup_credentials),
                None,
                vec![sweep_snapshot],
                current_time_ms(),
            )
            .await;
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut sweep)
                .await
                .is_err(),
            "cleanup must wait for the active mint"
        );
        let during_cleanup = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(during_cleanup, before_cleanup);
        release.send(()).unwrap();
        assert_eq!(mint.await.unwrap().unwrap().status, "refreshed");
        tokio::time::timeout(Duration::from_secs(10), sweep)
            .await
            .unwrap()
            .unwrap();
        let committed = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(committed.status, "refreshed");
        assert_ne!(committed.next_refresh_at_ms, i64::MAX);
        assert!(committed.pending_secret_deletions.is_empty());
        assert_eq!(
            credentials
                .resolve_refresh_material(
                    refresh_material_scope(&committed),
                    &committed.secret_material_handles,
                )
                .await
                .unwrap()["refresh_token"],
            "replacement-grant"
        );
        assert_eq!(credentials.stored_credential_count(), Some(2));
        issuer.verify().await;
    }

    #[tokio::test]
    async fn rotated_refresh_token_store_failure_requires_reauthorization() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "access-token-that-must-not-be-applied",
                "refresh_token": "replacement-refresh-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let provider = provider("rotation-store-failure", "outlook");
        store.put_message(&provider).await.unwrap();
        let credentials = test_credentials();
        let mut state = new_refresh_state(
            &provider,
            "default",
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
                material: HashMap::from([
                    ("client_id".to_string(), "client-id".to_string()),
                    ("refresh_token".to_string(), "old-refresh-token".to_string()),
                ]),
                secret_material_keys: vec!["refresh_token".to_string()],
                expires_at_ms: 0,
                token_url: format!("{}/token", mock_server.uri()),
                scopes: Vec::new(),
                refresh_before: Some(proto_duration(30)),
                max_lifetime: Some(proto_duration(60)),
                additional_output_keys: HashMap::new(),
            },
        )
        .unwrap();
        state.secret_material_handles = credentials
            .store_refresh_material_with_object_id(
                refresh_material_scope(&state),
                "original-grant",
                &HashMap::from([("refresh_token".to_string(), "old-refresh-token".to_string())]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        state.material.remove("refresh_token");
        put_refresh_state(&store, &state).await.unwrap();
        credentials.fail_next_store();

        let err = refresh_provider_credential(
            &store,
            "default",
            &credentials,
            None,
            "rotation-store-failure",
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("must be re-authorized"));
        let stored = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stored.status, "reauthorization_required");
        assert!(stored.last_error.contains("must be re-authorized"));
        assert_eq!(stored.next_refresh_at_ms, i64::MAX);
        assert_eq!(
            stored.recovery_action,
            ProviderCredentialRefreshRecoveryAction::Reauthorize as i32
        );
        assert_eq!(
            stored.failure_code,
            "oauth_rotated_refresh_token_store_failed"
        );
        assert_eq!(credentials.stored_credential_count(), Some(1));
        assert_eq!(
            credentials
                .resolve_refresh_material(
                    refresh_material_scope(&stored),
                    &stored.secret_material_handles,
                )
                .await
                .unwrap()
                .get("refresh_token"),
            Some(&"old-refresh-token".to_string())
        );
        let stored_provider = store
            .get_message_by_name::<Provider>("default", "rotation-store-failure")
            .await
            .unwrap()
            .unwrap();
        assert!(stored_provider.credential_handles.is_empty());
    }

    #[tokio::test]
    async fn google_service_account_refresh_mints_and_persists_access_token() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer",
            ))
            .and(body_string_contains("assertion="))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "minted-drive-token",
                "expires_in": 1800,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let provider = provider("my-drive", "google-drive");
        store.put_message(&provider).await.unwrap();
        let state = new_refresh_state(
            &provider,
            "default",
            "GOOGLE_DRIVE_ACCESS_TOKEN",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::new(),
                strategy: ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt,
                material: HashMap::from([
                    (
                        "client_email".to_string(),
                        "svc@example.iam.gserviceaccount.com".to_string(),
                    ),
                    ("private_key".to_string(), TEST_RSA_PRIVATE_KEY.to_string()),
                ]),
                secret_material_keys: vec!["private_key".to_string()],
                expires_at_ms: 0,
                token_url: format!("{}/token", mock_server.uri()),
                scopes: vec!["https://www.googleapis.com/auth/drive.readonly".to_string()],
                refresh_before: Some(proto_duration(300)),
                max_lifetime: Some(proto_duration(3600)),
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();
        let credentials = test_credentials();

        let refreshed = refresh_provider_credential(
            &store,
            "default",
            &credentials,
            None,
            "my-drive",
            "GOOGLE_DRIVE_ACCESS_TOKEN",
        )
        .await
        .unwrap();
        assert_eq!(refreshed.status, "refreshed");
        assert!(refreshed.expires_at_ms > 0);

        let stored = store
            .get_message_by_name::<Provider>("default", "my-drive")
            .await
            .unwrap()
            .unwrap();
        let resolved = credentials
            .resolve_provider_handles(&stored, current_time_ms())
            .await
            .unwrap();
        assert_eq!(
            resolved.values.get("GOOGLE_DRIVE_ACCESS_TOKEN"),
            Some(&"minted-drive-token".to_string())
        );
    }

    #[tokio::test]
    async fn refresh_worker_skips_non_gateway_mintable_strategies() {
        let store = test_store().await;
        let provider = provider("my-external", "outlook");
        store.put_message(&provider).await.unwrap();
        let state = new_refresh_state(
            &provider,
            "default",
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::new(),
                strategy: ProviderCredentialRefreshStrategy::External,
                material: HashMap::new(),
                secret_material_keys: Vec::new(),
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before: None,
                max_lifetime: None,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        Box::pin(run_refresh_worker_tick(&store, None, None))
            .await
            .unwrap();

        let stored_state = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert_ne!(stored_state.status, "error");
        assert!(stored_state.last_error.is_empty());

        let stored_provider = store
            .get_message_by_name::<Provider>("default", "my-external")
            .await
            .unwrap()
            .unwrap();
        assert!(
            !stored_provider
                .credentials
                .contains_key("MS_GRAPH_ACCESS_TOKEN")
        );
    }

    #[test]
    fn automatic_refresh_honors_recovery_schedule_without_disabling_due_retries() {
        let now_ms = 10_000;
        for recovery in [
            ProviderCredentialRefreshRecoveryAction::Retry,
            ProviderCredentialRefreshRecoveryAction::FixConfiguration,
            ProviderCredentialRefreshRecoveryAction::Investigate,
        ] {
            let mut state = StoredProviderCredentialRefreshState {
                recovery_action: recovery as i32,
                next_refresh_at_ms: now_ms + 1,
                ..Default::default()
            };
            assert_eq!(
                ensure_automatic_refresh_ready(&state, now_ms)
                    .unwrap_err()
                    .code(),
                tonic::Code::Unavailable,
            );
            state.next_refresh_at_ms = now_ms;
            ensure_automatic_refresh_ready(&state, now_ms).unwrap();
        }
        let state = StoredProviderCredentialRefreshState {
            recovery_action: ProviderCredentialRefreshRecoveryAction::Reauthorize as i32,
            next_refresh_at_ms: now_ms,
            ..Default::default()
        };
        assert_eq!(
            ensure_automatic_refresh_ready(&state, now_ms)
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition,
        );
        // A healthy credential's proactive schedule must not block an on-read
        // mint requested to meet a longer minimum remaining lifetime.
        let state = StoredProviderCredentialRefreshState {
            next_refresh_at_ms: now_ms + 1,
            ..Default::default()
        };
        ensure_automatic_refresh_ready(&state, now_ms).unwrap();
    }

    #[tokio::test]
    async fn refresh_worker_skips_parked_reauthorization_state() {
        let store = test_store().await;
        let provider = provider("parked-refresh", "outlook");
        store.put_message(&provider).await.unwrap();
        let mut state = new_refresh_state(
            &provider,
            "default",
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
                material: HashMap::new(),
                secret_material_keys: Vec::new(),
                expires_at_ms: 0,
                token_url: "https://issuer.example/token".to_string(),
                scopes: Vec::new(),
                refresh_before: Some(proto_duration(30)),
                max_lifetime: Some(proto_duration(60)),
                additional_output_keys: HashMap::new(),
            },
        )
        .unwrap();
        state.status = "reauthorization_required".to_string();
        state.last_error = "OAuth refresh grant is no longer usable".to_string();
        state.recovery_action = ProviderCredentialRefreshRecoveryAction::Reauthorize as i32;
        state.failure_code = "oauth_invalid_grant".to_string();
        state.last_error_at_ms = current_time_ms();
        state.next_refresh_at_ms = i64::MAX;
        put_refresh_state(&store, &state).await.unwrap();

        Box::pin(run_refresh_worker_tick(
            &store,
            Some(&test_credentials()),
            None,
        ))
        .await
        .unwrap();

        let stored = get_refresh_state(
            &store,
            "default",
            provider.object_id(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stored.status, "reauthorization_required");
        assert_eq!(stored.next_refresh_at_ms, i64::MAX);
        assert_eq!(stored.failure_code, "oauth_invalid_grant");
        assert_eq!(
            stored.recovery_action,
            ProviderCredentialRefreshRecoveryAction::Reauthorize as i32
        );
    }

    #[tokio::test]
    async fn refresh_worker_finalizes_tombstoned_refresh_material() {
        let store = test_store().await;
        let provider = provider("tombstoned-refresh", "outlook");
        store.put_message(&provider).await.unwrap();
        let credentials = test_credentials();
        let mut state = new_refresh_state(
            &provider,
            "default",
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
                material: HashMap::from([("refresh_token".to_string(), "delete-me".to_string())]),
                secret_material_keys: vec!["refresh_token".to_string()],
                expires_at_ms: 0,
                token_url: "https://issuer.example/token".to_string(),
                scopes: Vec::new(),
                refresh_before: Some(proto_duration(30)),
                max_lifetime: Some(proto_duration(60)),
                additional_output_keys: HashMap::new(),
            },
        )
        .unwrap();
        state.secret_material_handles = credentials
            .store_refresh_material_with_object_id(
                refresh_material_scope(&state),
                "tombstoned-grant",
                &state.material,
                &HashMap::new(),
            )
            .await
            .unwrap();
        state.material.clear();
        state.metadata.as_mut().unwrap().deletion_time =
            openshell_core::time::timestamp_from_millis(current_time_ms()).ok();
        state.status = "deleting".to_string();
        put_refresh_state(&store, &state).await.unwrap();
        assert_eq!(credentials.stored_credential_count(), Some(1));

        let changed = Box::pin(run_refresh_worker_tick(&store, Some(&credentials), None))
            .await
            .unwrap();

        assert_eq!(
            changed,
            std::collections::HashSet::from([(
                "default".to_string(),
                "tombstoned-refresh".to_string()
            )]),
            "only the refreshed provider's attached sandboxes need an update"
        );
        assert!(
            get_refresh_state(
                &store,
                "default",
                provider.object_id(),
                "MS_GRAPH_ACCESS_TOKEN",
            )
            .await
            .unwrap()
            .is_none()
        );
        assert_eq!(credentials.stored_credential_count(), Some(0));
    }

    #[tokio::test]
    async fn refresh_worker_records_a_root_span_only_when_a_state_has_work() {
        use crate::otel_tracing::test_exporter;

        let store = test_store().await;

        let traced = test_exporter::install_traced();
        Box::pin(run_refresh_worker_tick(&store, None, None))
            .await
            .unwrap();
        assert!(
            traced
                .spans_named("refresh.provider_credentials")
                .is_empty(),
            "an idle tick records no refresh span"
        );

        let provider = provider("my-external", "outlook");
        store.put_message(&provider).await.unwrap();
        let state = new_refresh_state(
            &provider,
            "default",
            "MS_GRAPH_ACCESS_TOKEN",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::new(),
                strategy: ProviderCredentialRefreshStrategy::External,
                material: HashMap::new(),
                secret_material_keys: Vec::new(),
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before: None,
                max_lifetime: None,
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();

        Box::pin(run_refresh_worker_tick(&store, None, None))
            .await
            .unwrap();
        test_exporter::assert_is_root(&traced.wait_for_span("refresh.provider_credentials").await);
    }

    #[tokio::test]
    async fn aws_sts_assume_role_mints_three_credentials_from_mock_endpoint() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRole"))
            .and(body_string_contains("RoleArn=arn"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <AssumedRoleUser>
      <AssumedRoleId>AROA3XFRBF23:test-session</AssumedRoleId>
      <Arn>arn:aws:sts::123456789012:assumed-role/TestRole/test-session</Arn>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>ASIAMOCKKEY</AccessKeyId>
      <SecretAccessKey>MockSecretAccessKey123</SecretAccessKey>
      <SessionToken>MockSessionTokenXYZ</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
  <ResponseMetadata>
    <RequestId>01234567-89ab-cdef-0123-456789abcdef</RequestId>
  </ResponseMetadata>
</AssumeRoleResponse>"#,
            ))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let prov = provider("aws-sts-test", "aws");
        store.put_message(&prov).await.unwrap();

        let state = new_refresh_state(
            &prov,
            "default",
            "AWS_ACCESS_KEY_ID",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::from([
                    (
                        "secret_access_key".to_string(),
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                    ),
                    ("session_token".to_string(), "AWS_SESSION_TOKEN".to_string()),
                ]),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
                material: HashMap::from([
                    (
                        "role_arn".to_string(),
                        "arn:aws:iam::123456789012:role/TestRole".to_string(),
                    ),
                    ("session_name".to_string(), "test-session".to_string()),
                    ("aws_access_key_id".to_string(), "AKIATESTKEY".to_string()),
                    (
                        "aws_secret_access_key".to_string(),
                        "TestSecretKey".to_string(),
                    ),
                    ("sts_endpoint_url".to_string(), mock_server.uri()),
                ]),
                secret_material_keys: vec!["aws_secret_access_key".to_string()],
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before: Some(proto_duration(300)),
                max_lifetime: Some(proto_duration(3600)),
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();
        let credentials = test_credentials();

        let refreshed = refresh_provider_credential(
            &store,
            "default",
            &credentials,
            None,
            "aws-sts-test",
            "AWS_ACCESS_KEY_ID",
        )
        .await
        .unwrap();
        assert_eq!(refreshed.status, "refreshed");
        assert!(refreshed.expires_at_ms > 0);

        let stored = store
            .get_message_by_name::<Provider>("default", "aws-sts-test")
            .await
            .unwrap()
            .unwrap();
        let resolved = credentials
            .resolve_provider_handles(&stored, current_time_ms())
            .await
            .unwrap();
        assert_eq!(
            resolved.values.get("AWS_ACCESS_KEY_ID"),
            Some(&"ASIAMOCKKEY".to_string())
        );
        assert_eq!(
            resolved.values.get("AWS_SECRET_ACCESS_KEY"),
            Some(&"MockSecretAccessKey123".to_string())
        );
        assert_eq!(
            resolved.values.get("AWS_SESSION_TOKEN"),
            Some(&"MockSessionTokenXYZ".to_string())
        );
    }

    #[tokio::test]
    async fn aws_sts_mint_writes_to_resolved_additional_output_keys() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRole"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAMOCKKEY</AccessKeyId>
      <SecretAccessKey>MockSecretAccessKey123</SecretAccessKey>
      <SessionToken>MockSessionTokenXYZ</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#,
            ))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let prov = provider("aws-sts-custom", "aws");
        store.put_message(&prov).await.unwrap();

        // The minter honors the resolved output->env-key map from state, not
        // hardcoded AWS names.
        let state = new_refresh_state(
            &prov,
            "default",
            "AWS_ACCESS_KEY_ID",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::from([
                    ("secret_access_key".to_string(), "CUSTOM_SECRET".to_string()),
                    ("session_token".to_string(), "CUSTOM_SESSION".to_string()),
                ]),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
                material: HashMap::from([
                    (
                        "role_arn".to_string(),
                        "arn:aws:iam::123456789012:role/TestRole".to_string(),
                    ),
                    ("aws_access_key_id".to_string(), "AKIATESTKEY".to_string()),
                    (
                        "aws_secret_access_key".to_string(),
                        "TestSecretKey".to_string(),
                    ),
                    ("sts_endpoint_url".to_string(), mock_server.uri()),
                ]),
                secret_material_keys: vec!["aws_secret_access_key".to_string()],
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before: Some(proto_duration(300)),
                max_lifetime: Some(proto_duration(3600)),
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();
        let credentials = test_credentials();

        refresh_provider_credential(
            &store,
            "default",
            &credentials,
            None,
            "aws-sts-custom",
            "AWS_ACCESS_KEY_ID",
        )
        .await
        .unwrap();

        let stored = store
            .get_message_by_name::<Provider>("default", "aws-sts-custom")
            .await
            .unwrap()
            .unwrap();
        let resolved = credentials
            .resolve_provider_handles(&stored, current_time_ms())
            .await
            .unwrap();
        assert_eq!(
            resolved.values.get("AWS_ACCESS_KEY_ID"),
            Some(&"ASIAMOCKKEY".to_string())
        );
        assert_eq!(
            resolved.values.get("CUSTOM_SECRET"),
            Some(&"MockSecretAccessKey123".to_string())
        );
        assert_eq!(
            resolved.values.get("CUSTOM_SESSION"),
            Some(&"MockSessionTokenXYZ".to_string())
        );
        assert!(!resolved.values.contains_key("AWS_SECRET_ACCESS_KEY"));
    }

    #[tokio::test]
    async fn aws_sts_mint_rejects_partial_source_credentials() {
        let store = test_store().await;
        let prov = provider("aws-sts-partial", "aws");
        store.put_message(&prov).await.unwrap();

        // Only the access key half of the explicit source pair is present. The
        // mint must fail rather than fall back to the gateway's ambient identity.
        let state = new_refresh_state(
            &prov,
            "default",
            "AWS_ACCESS_KEY_ID",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::from([
                    (
                        "secret_access_key".to_string(),
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                    ),
                    ("session_token".to_string(), "AWS_SESSION_TOKEN".to_string()),
                ]),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
                material: HashMap::from([
                    (
                        "role_arn".to_string(),
                        "arn:aws:iam::123456789012:role/TestRole".to_string(),
                    ),
                    ("aws_access_key_id".to_string(), "AKIATESTKEY".to_string()),
                ]),
                secret_material_keys: Vec::new(),
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before: Some(proto_duration(300)),
                max_lifetime: Some(proto_duration(3600)),
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();
        let credentials = test_credentials();

        let err = refresh_provider_credential(
            &store,
            "default",
            &credentials,
            None,
            "aws-sts-partial",
            "AWS_ACCESS_KEY_ID",
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("both be set or both omitted"));

        let stored = store
            .get_message_by_name::<Provider>("default", "aws-sts-partial")
            .await
            .unwrap()
            .unwrap();
        assert!(!stored.credentials.contains_key("AWS_ACCESS_KEY_ID"));
    }

    #[tokio::test]
    async fn apply_minted_credential_writes_additional_keys() {
        use super::apply_minted_credential;

        let store = test_store().await;
        let mut prov = provider("aws-test", "aws");
        prov.credentials
            .insert("AWS_ACCESS_KEY_ID".to_string(), "old-key".to_string());
        store.put_message(&prov).await.unwrap();

        let minted = super::MintedCredential {
            access_token: "AKIAIOSFODNN7EXAMPLE".to_string(),
            expires_at_ms: 4_000_000_000_000,
            refresh_token: None,
            additional_credentials: HashMap::from([
                (
                    "AWS_SECRET_ACCESS_KEY".to_string(),
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
                ),
                (
                    "AWS_SESSION_TOKEN".to_string(),
                    "FwoGZXIvYXdzEBYaDH...EXAMPLETOKEN".to_string(),
                ),
            ]),
        };

        apply_minted_credential(
            &store,
            "default",
            None,
            None,
            &prov,
            "AWS_ACCESS_KEY_ID",
            &minted,
        )
        .await
        .unwrap();

        let stored = store
            .get_message_by_name::<Provider>("default", "aws-test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.credentials.get("AWS_ACCESS_KEY_ID"),
            Some(&"AKIAIOSFODNN7EXAMPLE".to_string())
        );
        assert_eq!(
            stored.credentials.get("AWS_SECRET_ACCESS_KEY"),
            Some(&"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string())
        );
        assert_eq!(
            stored.credentials.get("AWS_SESSION_TOKEN"),
            Some(&"FwoGZXIvYXdzEBYaDH...EXAMPLETOKEN".to_string())
        );
        assert_eq!(
            stored.credential_expiration_times.get("AWS_ACCESS_KEY_ID"),
            Some(&ts(4_000_000_000_000))
        );
        assert_eq!(
            stored
                .credential_expiration_times
                .get("AWS_SECRET_ACCESS_KEY"),
            Some(&ts(4_000_000_000_000))
        );
        assert_eq!(
            stored.credential_expiration_times.get("AWS_SESSION_TOKEN"),
            Some(&ts(4_000_000_000_000))
        );
    }

    #[tokio::test]
    async fn apply_minted_credential_replaces_only_refreshed_handles() {
        use super::apply_minted_credential;

        let store = test_store().await;
        let credentials = CredentialRuntime::from_config(
            &Config::new(None).with_credential_drivers(["test-static"]),
        )
        .unwrap();
        let mut prov = provider("stored-aws", "aws");
        let original_handles = credentials
            .store_provider_credentials(
                prov.object_name(),
                prov.object_workspace(),
                prov.object_id(),
                &HashMap::from([
                    ("AWS_ACCESS_KEY_ID".to_string(), "old-key".to_string()),
                    (
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                        "unchanged-secret".to_string(),
                    ),
                ]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        prov.credential_handles.clone_from(&original_handles);
        store.put_message(&prov).await.unwrap();

        let minted = super::MintedCredential {
            access_token: "new-key".to_string(),
            expires_at_ms: 4_000_000_000_000,
            refresh_token: None,
            additional_credentials: HashMap::new(),
        };

        apply_minted_credential(
            &store,
            "default",
            Some(&credentials),
            None,
            &prov,
            "AWS_ACCESS_KEY_ID",
            &minted,
        )
        .await
        .unwrap();

        let stored = store
            .get_message_by_name::<Provider>("default", "stored-aws")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            stored.credential_handles.get("AWS_ACCESS_KEY_ID"),
            original_handles.get("AWS_ACCESS_KEY_ID")
        );
        assert_eq!(
            stored.credential_handles.get("AWS_SECRET_ACCESS_KEY"),
            original_handles.get("AWS_SECRET_ACCESS_KEY")
        );
        let resolved = credentials
            .resolve_provider_handles(&stored, current_time_ms())
            .await
            .unwrap();
        assert_eq!(
            resolved.values.get("AWS_ACCESS_KEY_ID"),
            Some(&"new-key".to_string())
        );
        assert_eq!(
            resolved.values.get("AWS_SECRET_ACCESS_KEY"),
            Some(&"unchanged-secret".to_string())
        );

        let old_handle_provider = Provider {
            credential_handles: HashMap::from([(
                "AWS_ACCESS_KEY_ID".to_string(),
                original_handles["AWS_ACCESS_KEY_ID"].clone(),
            )]),
            ..prov
        };
        let err = credentials
            .resolve_provider_handles(&old_handle_provider, current_time_ms())
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn apply_minted_credential_validates_additional_keys_against_sandboxes() {
        use super::apply_minted_credential;

        let store = test_store().await;
        let mut existing_provider = provider("existing-aws", "aws");
        existing_provider
            .credentials
            .insert("AWS_SECRET_ACCESS_KEY".to_string(), "existing".to_string());
        store.put_message(&existing_provider).await.unwrap();

        let refreshing_provider = provider("refreshing-aws", "aws");
        store.put_message(&refreshing_provider).await.unwrap();

        store
            .put_message(&Sandbox {
                metadata: Some(ObjectMeta {
                    id: "sandbox-aws-collision".to_string(),
                    name: "aws-collision".to_string(),
                    created_time: openshell_core::time::timestamp_from_millis(1).ok(),
                    labels: HashMap::new(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    workspace: "default".to_string(),
                    deletion_time: None,
                }),
                spec: Some(SandboxSpec {
                    providers: vec!["existing-aws".to_string(), "refreshing-aws".to_string()],
                    ..SandboxSpec::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();

        let minted = super::MintedCredential {
            access_token: "AKIAIOSFODNN7EXAMPLE".to_string(),
            expires_at_ms: 4_000_000_000_000,
            refresh_token: None,
            additional_credentials: HashMap::from([
                (
                    "AWS_SECRET_ACCESS_KEY".to_string(),
                    "secret-key".to_string(),
                ),
                ("AWS_SESSION_TOKEN".to_string(), "session-token".to_string()),
            ]),
        };
        let credentials = CredentialRuntime::from_config(
            &Config::new(None).with_credential_drivers(["test-static"]),
        )
        .unwrap();

        let err = apply_minted_credential(
            &store,
            "default",
            Some(&credentials),
            None,
            &refreshing_provider,
            "AWS_ACCESS_KEY_ID",
            &minted,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("AWS_SECRET_ACCESS_KEY"));
        assert_eq!(credentials.stored_credential_count(), Some(0));
    }

    #[tokio::test]
    async fn apply_minted_credential_rejects_invalid_expiry_without_staging() {
        use super::apply_minted_credential;

        let store = test_store().await;
        let credentials = test_credentials();
        let mut prov = provider("expiring-aws", "aws");
        let original_handles = credentials
            .store_provider_credentials(
                prov.object_name(),
                prov.object_workspace(),
                prov.object_id(),
                &HashMap::from([(
                    "AWS_ACCESS_KEY_ID".to_string(),
                    "old-access-key".to_string(),
                )]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        prov.credential_handles.clone_from(&original_handles);
        let stored_credential_count = credentials.stored_credential_count();
        store.put_message(&prov).await.unwrap();

        // i64::MAX milliseconds is past the latest protobuf timestamp, so the
        // expiration conversion fails.
        let minted = super::MintedCredential {
            access_token: "AKIAIOSFODNN7EXAMPLE".to_string(),
            expires_at_ms: i64::MAX,
            refresh_token: None,
            additional_credentials: HashMap::new(),
        };
        let err = apply_minted_credential(
            &store,
            "default",
            Some(&credentials),
            None,
            &prov,
            "AWS_ACCESS_KEY_ID",
            &minted,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
        assert_eq!(
            credentials.stored_credential_count(),
            stored_credential_count
        );
        let stored = store
            .get_message_by_name::<Provider>("default", "expiring-aws")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.credential_handles, original_handles);
    }

    #[tokio::test]
    async fn apply_minted_credential_returns_unavailable_when_guard_times_out() {
        use super::apply_minted_credential;

        let state = crate::grpc::test_support::test_server_state().await;
        state
            .compute
            .set_mutation_lock_timeout_for_tests(std::time::Duration::from_millis(50));
        let credentials = test_credentials();
        let mut prov = provider("guarded-aws", "aws");
        let original_handles = credentials
            .store_provider_credentials(
                prov.object_name(),
                prov.object_workspace(),
                prov.object_id(),
                &HashMap::from([(
                    "AWS_ACCESS_KEY_ID".to_string(),
                    "old-access-key".to_string(),
                )]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        prov.credential_handles.clone_from(&original_handles);
        let stored_credential_count = credentials.stored_credential_count();
        state.store.put_message(&prov).await.unwrap();
        let provider_writer = crate::persistence::lock_order::branch(
            state
                .compute
                .mutation_guard(crate::compute::MutationScope::Workspace("default")),
        )
        .await
        .unwrap();

        let minted = super::MintedCredential {
            access_token: "AKIAIOSFODNN7EXAMPLE".to_string(),
            expires_at_ms: 4_000_000_000_000,
            refresh_token: None,
            additional_credentials: HashMap::new(),
        };
        let err = apply_minted_credential(
            &state.store,
            "default",
            Some(&credentials),
            Some(&state.compute),
            &prov,
            "AWS_ACCESS_KEY_ID",
            &minted,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);
        let details = openshell_core::rpc_error::decode_details(&err).expect("error details");
        assert_eq!(
            details.error_info().expect("error info").reason,
            "MUTATION_LOCK_TIMEOUT"
        );
        let stored = state
            .store
            .get_message_by_name::<Provider>("default", "guarded-aws")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.credential_handles, original_handles);
        let resolved = credentials
            .resolve_provider_handles(&stored, current_time_ms())
            .await
            .unwrap();
        assert_eq!(
            resolved.values.get("AWS_ACCESS_KEY_ID"),
            Some(&"old-access-key".to_string())
        );
        assert_eq!(
            credentials.stored_credential_count(),
            stored_credential_count
        );
        drop(provider_writer);
    }

    // A wiremock responder that blocks the STS response until the test releases
    // it, so a delete-refresh can be interleaved deterministically while the
    // rotation is parked awaiting STS.
    struct GatedStsResponder {
        hit: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        body: String,
    }

    impl wiremock::Respond for GatedStsResponder {
        fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
            let hit = self.hit.lock().unwrap().take();
            if let Some(hit) = hit {
                let _ = hit.send(());
            }
            let _ = self.release.lock().unwrap().recv();
            ResponseTemplate::new(200).set_body_string(self.body.clone())
        }
    }

    #[tokio::test]
    async fn aws_sts_mint_accepts_session_token_with_source_pair() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRole"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAMOCKKEY</AccessKeyId>
      <SecretAccessKey>MockSecretAccessKey123</SecretAccessKey>
      <SessionToken>MockSessionTokenXYZ</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#,
            ))
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let prov = provider("aws-sts-session", "aws");
        store.put_message(&prov).await.unwrap();

        // Temporary source credentials: access key + secret + session token.
        let state = new_refresh_state(
            &prov,
            "default",
            "AWS_ACCESS_KEY_ID",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::from([
                    (
                        "secret_access_key".to_string(),
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                    ),
                    ("session_token".to_string(), "AWS_SESSION_TOKEN".to_string()),
                ]),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
                material: HashMap::from([
                    (
                        "role_arn".to_string(),
                        "arn:aws:iam::123456789012:role/TestRole".to_string(),
                    ),
                    ("aws_access_key_id".to_string(), "ASIASOURCEKEY".to_string()),
                    (
                        "aws_secret_access_key".to_string(),
                        "SourceSecretKey".to_string(),
                    ),
                    (
                        "aws_session_token".to_string(),
                        "SourceSessionToken".to_string(),
                    ),
                    ("sts_endpoint_url".to_string(), mock_server.uri()),
                ]),
                secret_material_keys: vec![
                    "aws_secret_access_key".to_string(),
                    "aws_session_token".to_string(),
                ],
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before: Some(proto_duration(300)),
                max_lifetime: Some(proto_duration(3600)),
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();
        let credentials = test_credentials();

        let refreshed = refresh_provider_credential(
            &store,
            "default",
            &credentials,
            None,
            "aws-sts-session",
            "AWS_ACCESS_KEY_ID",
        )
        .await
        .unwrap();
        assert_eq!(refreshed.status, "refreshed");
        let stored = store
            .get_message_by_name::<Provider>("default", "aws-sts-session")
            .await
            .unwrap()
            .unwrap();
        let resolved = credentials
            .resolve_provider_handles(&stored, current_time_ms())
            .await
            .unwrap();
        assert_eq!(
            resolved.values.get("AWS_ACCESS_KEY_ID"),
            Some(&"ASIAMOCKKEY".to_string())
        );
    }

    #[tokio::test]
    async fn aws_sts_mint_rejects_session_token_without_source_pair() {
        let store = test_store().await;
        let prov = provider("aws-sts-lonesession", "aws");
        store.put_message(&prov).await.unwrap();

        let state = new_refresh_state(
            &prov,
            "default",
            "AWS_ACCESS_KEY_ID",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::from([
                    (
                        "secret_access_key".to_string(),
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                    ),
                    ("session_token".to_string(), "AWS_SESSION_TOKEN".to_string()),
                ]),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
                material: HashMap::from([
                    (
                        "role_arn".to_string(),
                        "arn:aws:iam::123456789012:role/TestRole".to_string(),
                    ),
                    (
                        "aws_session_token".to_string(),
                        "SourceSessionToken".to_string(),
                    ),
                ]),
                secret_material_keys: vec!["aws_session_token".to_string()],
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before: Some(proto_duration(300)),
                max_lifetime: Some(proto_duration(3600)),
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();
        let credentials = test_credentials();

        let err = refresh_provider_credential(
            &store,
            "default",
            &credentials,
            None,
            "aws-sts-lonesession",
            "AWS_ACCESS_KEY_ID",
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("aws_session_token requires"));
    }

    #[tokio::test]
    async fn deletion_of_observed_refresh_preserves_same_name_replacement() {
        use super::delete_observed_refresh_state_with_credentials;
        use crate::persistence::ObjectType;
        let store = test_store().await;
        let original = StoredProviderCredentialRefreshState {
            metadata: Some(ObjectMeta {
                id: "original-id".into(),
                name: "refresh-name".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        store.put_message(&original).await.unwrap();
        let observed = store
            .get_message::<StoredProviderCredentialRefreshState>("original-id")
            .await
            .unwrap()
            .unwrap();
        store
            .delete(
                StoredProviderCredentialRefreshState::object_type(),
                "original-id",
            )
            .await
            .unwrap();
        let mut replacement = original;
        replacement.metadata.as_mut().unwrap().id = "replacement-id".into();
        store.put_message(&replacement).await.unwrap();
        let replacement = store
            .get_message::<StoredProviderCredentialRefreshState>("replacement-id")
            .await
            .unwrap()
            .unwrap();

        delete_observed_refresh_state_with_credentials(
            &super::runtime(
                &std::sync::Arc::new(store.clone()),
                Some(&test_credentials()),
                None,
            ),
            observed,
        )
        .await
        .unwrap();
        assert_eq!(
            store
                .get_message::<StoredProviderCredentialRefreshState>("replacement-id")
                .await
                .unwrap()
                .unwrap(),
            replacement
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rotation_does_not_resurrect_refresh_deleted_mid_flight() {
        let mock_server = MockServer::start().await;
        let (hit_tx, hit_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRole"))
            .respond_with(GatedStsResponder {
                hit: std::sync::Mutex::new(Some(hit_tx)),
                release: std::sync::Mutex::new(release_rx),
                body: r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAMOCKKEY</AccessKeyId>
      <SecretAccessKey>MockSecretAccessKey123</SecretAccessKey>
      <SessionToken>MockSessionTokenXYZ</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#
                    .to_string(),
            })
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let prov = provider("aws-race", "aws");
        store.put_message(&prov).await.unwrap();
        let provider_id = prov.object_id().to_string();

        let state = new_refresh_state(
            &prov,
            "default",
            "AWS_ACCESS_KEY_ID",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::from([
                    (
                        "secret_access_key".to_string(),
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                    ),
                    ("session_token".to_string(), "AWS_SESSION_TOKEN".to_string()),
                ]),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
                material: HashMap::from([
                    (
                        "role_arn".to_string(),
                        "arn:aws:iam::123456789012:role/TestRole".to_string(),
                    ),
                    ("aws_access_key_id".to_string(), "AKIATESTKEY".to_string()),
                    (
                        "aws_secret_access_key".to_string(),
                        "TestSecretKey".to_string(),
                    ),
                    ("sts_endpoint_url".to_string(), mock_server.uri()),
                ]),
                secret_material_keys: vec!["aws_secret_access_key".to_string()],
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before: Some(proto_duration(300)),
                max_lifetime: Some(proto_duration(3600)),
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();
        let credentials = test_credentials();

        let rotate = refresh_provider_credential(
            &store,
            "default",
            &credentials,
            None,
            "aws-race",
            "AWS_ACCESS_KEY_ID",
        );
        let interfere = async {
            // Wait until the rotation is inside the STS call (its state read has
            // already happened), then delete the refresh and release STS.
            if tokio::time::timeout(std::time::Duration::from_secs(15), hit_rx)
                .await
                .is_err()
            {
                return;
            }
            delete_refresh_state_with_credentials(
                &store,
                &credentials,
                "default",
                &provider_id,
                "AWS_ACCESS_KEY_ID",
            )
            .await
            .unwrap();
            let _ = release_tx.send(());
        };
        let (rotate_result, ()) = tokio::join!(rotate, interfere);

        // The rotation must fail rather than complete against a deleted refresh.
        assert!(
            rotate_result.is_err(),
            "rotation should abort when its refresh is deleted mid-flight"
        );
        // The deleted refresh state must not be resurrected.
        assert!(
            get_refresh_state(&store, "default", &provider_id, "AWS_ACCESS_KEY_ID")
                .await
                .unwrap()
                .is_none(),
            "deleted refresh state must not be recreated"
        );
        // No credentials were minted into the provider.
        let stored = store
            .get_message_by_name::<Provider>("default", "aws-race")
            .await
            .unwrap()
            .unwrap();
        assert!(!stored.credentials.contains_key("AWS_ACCESS_KEY_ID"));
        assert!(!stored.credentials.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert!(!stored.credentials.contains_key("AWS_SESSION_TOKEN"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rotation_superseded_mid_flight_discards_credentials() {
        let mock_server = MockServer::start().await;
        let (hit_tx, hit_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        Mock::given(method("POST"))
            .and(body_string_contains("Action=AssumeRole"))
            .respond_with(GatedStsResponder {
                hit: std::sync::Mutex::new(Some(hit_tx)),
                release: std::sync::Mutex::new(release_rx),
                body: r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAMOCKKEY</AccessKeyId>
      <SecretAccessKey>MockSecretAccessKey123</SecretAccessKey>
      <SessionToken>MockSessionTokenXYZ</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#
                    .to_string(),
            })
            .mount(&mock_server)
            .await;

        let store = test_store().await;
        let prov = provider("aws-superseded", "aws");
        store.put_message(&prov).await.unwrap();
        let provider_id = prov.object_id().to_string();

        let state = new_refresh_state(
            &prov,
            "default",
            "AWS_ACCESS_KEY_ID",
            NewRefreshStateConfig {
                additional_output_keys: HashMap::from([
                    (
                        "secret_access_key".to_string(),
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                    ),
                    ("session_token".to_string(), "AWS_SESSION_TOKEN".to_string()),
                ]),
                strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
                material: HashMap::from([
                    (
                        "role_arn".to_string(),
                        "arn:aws:iam::123456789012:role/TestRole".to_string(),
                    ),
                    ("aws_access_key_id".to_string(), "AKIATESTKEY".to_string()),
                    (
                        "aws_secret_access_key".to_string(),
                        "TestSecretKey".to_string(),
                    ),
                    ("sts_endpoint_url".to_string(), mock_server.uri()),
                ]),
                secret_material_keys: vec!["aws_secret_access_key".to_string()],
                expires_at_ms: 0,
                token_url: String::new(),
                scopes: Vec::new(),
                refresh_before: Some(proto_duration(300)),
                max_lifetime: Some(proto_duration(3600)),
            },
        )
        .unwrap();
        put_refresh_state(&store, &state).await.unwrap();
        let credentials = test_credentials();

        let rotate = refresh_provider_credential(
            &store,
            "default",
            &credentials,
            None,
            "aws-superseded",
            "AWS_ACCESS_KEY_ID",
        );
        let interfere = async {
            if tokio::time::timeout(std::time::Duration::from_secs(15), hit_rx)
                .await
                .is_err()
            {
                return;
            }
            // Simulate a concurrent rotation or reconfigure winning the
            // generation: any write to the refresh state bumps its version, so
            // the in-flight rotation's version-matched persist will lose.
            let mut winner =
                get_refresh_state(&store, "default", &provider_id, "AWS_ACCESS_KEY_ID")
                    .await
                    .unwrap()
                    .unwrap();
            winner.last_error = "won-by-concurrent-writer".to_string();
            put_refresh_state(&store, &winner).await.unwrap();
            let _ = release_tx.send(());
        };
        let (rotate_result, ()) = tokio::join!(rotate, interfere);

        // The superseded (losing) rotation must abort rather than complete.
        assert!(
            rotate_result.is_err(),
            "a rotation whose generation was superseded must abort"
        );
        // It must not write its stale-generation credentials into the provider.
        let stored = store
            .get_message_by_name::<Provider>("default", "aws-superseded")
            .await
            .unwrap()
            .unwrap();
        assert!(!stored.credentials.contains_key("AWS_ACCESS_KEY_ID"));
        assert!(!stored.credentials.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert!(!stored.credentials.contains_key("AWS_SESSION_TOKEN"));
        // The concurrent writer's refresh state must survive untouched.
        let refresh = get_refresh_state(&store, "default", &provider_id, "AWS_ACCESS_KEY_ID")
            .await
            .unwrap()
            .expect("refresh state should still exist");
        assert_eq!(refresh.last_error, "won-by-concurrent-writer");
        assert_ne!(refresh.status, "refreshed");
    }

    fn provider(name: &str, provider_type: &str) -> Provider {
        Provider {
            metadata: Some(ObjectMeta {
                id: format!("{name}-id"),
                name: name.to_string(),
                created_time: openshell_core::time::timestamp_from_millis(1).ok(),
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_time: None,
            }),
            r#type: provider_type.to_string(),
            credentials: HashMap::new(),
            config: HashMap::new(),
            credential_expiration_times: HashMap::new(),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        }
    }

    const TEST_RSA_PRIVATE_KEY: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvCoZ0mVHpCHsF
zeeqw2caNIe/eb4BQUccFPhZfRnF7sCfyB84zTBmuwG2umRBdjFnVsfIIZRp2HcD
OESrRYYiE1RGfjBXImGVg2Wtza0HYhL1sLyX1eaEefylxoilmApAgWDh9p36h8J2
s5YHwyXPTttx4DpdWDnxju1iNmwoIB8uVE/5amWgbNvlETMBOcB1RxDHtnVy+xJz
jjjrzK4Qz9WsUTHAvngdi4Yyxvci+yKpjYTg5+UWxmAN6iW522TpLe32MDb5Ug1d
trBvvepWmdQ6CBwPhBHCt/sMoSJAYSO4RKeBnBjeLQBXFTxaOv5iTGIsRTX3K471
epHp3cT5AgMBAAECggEASQlRv/4nZN5SgsH/K8v7zb3kdHsmUly8AJYpaCGgauvr
uN/mUyueyga2uNl+MqhQBef6VWHZjO6y/gdw86v/Q2GgVQebQQhKAnpAp2w+Ceoc
siKMFqi8VkOWLU+xPbM6d97kH3TpRxt1g1T8wYFmWeF0BEiE4eUJzGaQW14M9BJ+
G0QxmP/zjX9cNpVeApKTjBWKiH4CXG3DuI3pJ93VOMpUlOsrdLXvKGTze0e01itr
MX/MHHTE+VXB4FB+/zKSA4c36egi676OSXrGC/GDmM8ntJ4CUGeD5uZsMSADiAUn
iccv5iGRWVMIKxUS5Q4k0jy8uWuK+QVP4Y6cQWYArwKBgQDhuSNORBNpIGRfsKGN
iJo/h+qinz6pEIpa3D3oVl7rpkyvgIyaTwfXvC1vfdS9V5VIel2gV2Cx0OrI8yrr
nQu1JuNV/rLmtvqX321fgBLRdoiqF3pAy1gbmdUz1elerAIYL578gXQ6jg1bbdic
kJpn0MsoDUJGwvJnXcgLqG7q3wKBgQDGhRIa4oJsj1vqICc8zt8YsCAcot3vjWLH
588X7JdBGOWJdWxfdmGXQRn5Zw9UhMQnYa3uyTBPeVcXopThlPotYeuFhLSU856T
IJzfpzCJzC4zIQayoyvJFrKe7N70iUQ986dewYy9oxQhHvFKd/qe4ylbzZJXpthX
eWEuuBSjJwKBgGkqXt6qLPj/1IQYwUw15tfOtW0LEKCoSi3HCzjidNsJ4hSqqdeD
Fr5WuDyHvcRxt+XKzTBVRYHTOnBhiw+3XasK8UQxpJyFh/+WY1jpTNs2hLnqslTZ
6LUDWSgLc+1d6qPmHAa9Ma/OWz7L0O4xGR9hUiXY95YMYe/y668yzGq1AoGBAJyU
Gsqfu7U6gYmxoKEine6QBFPx1dD7GF2KJdq93jMXGvyHZFoLOkAdtgnz0rCcI0bY
kWKUxwj4MMxQjNM8OPMQl75xBCmz2XA8Od9htDQLmqjzNKAzePabc3lMZTJFDlE6
29kuGf79IIRbLn/JECDAFT/2baW60Ep2T0OVJ5njAoGAfaCaQ4aVgjI027q7Y5qP
KfNSI8uuA8PLqmUY30I9KFWzN6VDLu00eKa90F4w3CeWRRQWXW1+007tTz3V1mNw
20A24Fi3HGQmXc7NyuLDODTJsWBICuOemCnRkvcxIlxb+ec7jp+XRmzDwKkzSnVN
pM2zFU8SeVkvHKlEuoHaP0s=
-----END PRIVATE KEY-----";
}
