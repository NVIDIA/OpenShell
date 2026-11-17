// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Existing refresh state machine, independent of gateway persistence/types.
#![allow(clippy::result_large_err)]
use super::minter::{
    MintedCredential, RefreshFailure, RefreshRetrySchedule, mint_credential, next_refresh_at_ms,
    refresh_strategy_name,
};
use super::{
    CredentialRefresh, RefreshAttempt, RefreshChange, RefreshOutputs, RefreshRuntime, RefreshState,
    RefreshStateStore, minter,
};
use crate::{CredentialIssuer, RefreshMaterialScope, StoreSecrets};
use crate::{Handles, RefreshMaterialDeletion, SecretOwner};
use async_trait::async_trait;
use openshell_core::proto::{
    CredentialHandle, ProviderCredentialRefreshRecoveryAction, ProviderCredentialRefreshStrategy,
};
use openshell_core::time::now_ms as current_time_ms;
use openshell_core::{ObjectId, ObjectWorkspace};
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};
use tonic::Status;
use tracing::{Instrument as _, info, warn};
const EXPIRATION_PRESENT_ANNOTATION: &str = "openshell.nvidia.com/refresh-expiration-present";
const COMPLETED_MINT_ANNOTATION: &str = "openshell.nvidia.com/refresh-completed-mint";
const REFRESH_ERROR_RETRY_SECONDS: i64 = 60;
const REFRESH_CONFIGURATION_RETRY_SECONDS: i64 = 60 * 60;
pub fn refresh_material_scope(state: &RefreshState) -> RefreshMaterialScope<'_> {
    RefreshMaterialScope {
        provider_name: &state.provider_name,
        workspace: state.object_workspace(),
        provider_id: &state.provider_id,
        credential_key: &state.credential_key,
    }
}

pub fn refresh_state_name(provider_id: &str, credential_key: &str) -> String {
    let mut key = String::with_capacity(credential_key.len() * 2);
    for byte in credential_key.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut key, "{byte:02x}").expect("writing to String cannot fail");
    }
    format!("provider-refresh-{provider_id}-{key}")
}

/// Return the durable authorization epoch for one configured refresh grant.
///
/// Records created before the explicit epoch field was introduced use their
/// gateway-generated object ID as a stable migration epoch. An explicit
/// reconfiguration writes a new random epoch while preserving object metadata,
/// so reauthorization still revokes handles derived from the legacy value.
pub fn effective_authorization_epoch(state: &RefreshState) -> Result<&str, Status> {
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

/// Whether a refresh expiration was explicitly provided.
///
/// Legacy records infer presence from a nonzero millisecond value. New records
/// use a private metadata annotation only for the ambiguous Unix epoch value so
/// the frozen storage protobuf schema does not need to change.
pub fn refresh_has_expiration(state: &RefreshState) -> bool {
    state.expires_at_ms != 0
        || state.metadata.as_ref().is_some_and(|metadata| {
            metadata
                .annotations
                .get(EXPIRATION_PRESENT_ANNOTATION)
                .is_some_and(|value| value == "true")
        })
}

pub fn set_refresh_expiration_presence(state: &mut RefreshState, present: bool) {
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

pub async fn delete_refresh_state_with_credentials(
    store: &Arc<dyn RefreshStateStore>,
    credentials: &Arc<dyn CredentialIssuer>,
    workspace: &str,
    provider_id: &str,
    credential_key: &str,
) -> Result<bool, Status> {
    let Some(state) = get_refresh_state(store, workspace, provider_id, credential_key).await?
    else {
        return Ok(false);
    };
    delete_observed_refresh_state_with_credentials(store, credentials, state).await?;
    Ok(true)
}

/// Delete the observed refresh identity without resolving its name again.
pub async fn delete_observed_refresh_state_with_credentials(
    store: &Arc<dyn RefreshStateStore>,
    credentials: &Arc<dyn CredentialIssuer>,
    mut state: RefreshState,
) -> Result<(), Status> {
    let mut version = state
        .metadata
        .as_ref()
        .map_or(0, |metadata| metadata.resource_version);
    if state
        .metadata
        .as_ref()
        .is_some_and(|metadata| metadata.deletion_time.is_none())
    {
        if let Some(metadata) = state.metadata.as_mut() {
            metadata.deletion_time =
                openshell_core::time::timestamp_from_millis(current_time_ms()).ok();
        }
        state.authorization_epoch = uuid::Uuid::new_v4().to_string();
        state.status = "deleting".to_string();
        state.next_refresh_at_ms = i64::MAX;
        let Some(current_version) =
            persist_refresh_state_if_current(store, &state, version).await?
        else {
            if store
                .get_by_id(state.object_id())
                .await
                .map_err(|err| {
                    Status::internal(format!("fetch provider refresh state failed: {err}"))
                })?
                .is_none()
            {
                return Ok(());
            }
            return Err(Status::aborted(
                "provider refresh was concurrently modified during deletion",
            ));
        };
        version = current_version;
        if let Some(metadata) = state.metadata.as_mut() {
            metadata.resource_version = version;
        }
    }

    delete_pending_secret_handles(credentials, &state).await?;
    credentials
        .delete_refresh_material_handles(
            refresh_material_scope(&state),
            &state.secret_material_handles,
        )
        .await?;
    store.delete(state.object_id(), version).await?;
    Ok(())
}

pub async fn delete_refresh_states_for_provider_with_credentials(
    store: &Arc<dyn RefreshStateStore>,
    credentials: &Arc<dyn CredentialIssuer>,
    provider_id: &str,
) -> Result<u64, Status> {
    let states = list_refresh_states_for_provider(store, provider_id).await?;
    let mut deleted = 0;
    for state in &states {
        if delete_refresh_state_with_credentials(
            store,
            credentials,
            state.object_workspace(),
            provider_id,
            &state.credential_key,
        )
        .await?
        {
            deleted += 1;
        }
    }
    Ok(deleted)
}

async fn resolve_refresh_material(
    credentials: Option<&Arc<dyn CredentialIssuer>>,
    state: &RefreshState,
) -> Result<minter::MintRequest, Status> {
    let mut request = minter::MintRequest::from(state);
    if !state.secret_material_handles.is_empty() {
        let credentials = credentials.ok_or_else(|| {
            Status::failed_precondition(
                "provider refresh material requires the configured credential runtime",
            )
        })?;
        request.material.extend(
            credentials
                .resolve_refresh_material(
                    refresh_material_scope(state),
                    &state.secret_material_handles,
                )
                .await?,
        );
    }
    Ok(request)
}

pub fn enqueue_pending_secret_deletion(
    state: &mut RefreshState,
    material_key: &str,
    handle: CredentialHandle,
) {
    state
        .pending_secret_deletions
        .push(RefreshMaterialDeletion {
            material_key: material_key.to_string(),
            handle: Some(handle),
        });
}

async fn delete_pending_secret_handles(
    credentials: &Arc<dyn CredentialIssuer>,
    state: &RefreshState,
) -> Result<(), Status> {
    credentials
        .delete_refresh_material_deletions(
            refresh_material_scope(state),
            &state.pending_secret_deletions,
        )
        .await
}

async fn cleanup_pending_secret_deletions(
    store: &Arc<dyn RefreshStateStore>,
    credentials: Option<&Arc<dyn CredentialIssuer>>,
    state: &mut RefreshState,
    expected_version: u64,
) -> Result<u64, Status> {
    if state.pending_secret_deletions.is_empty() {
        return Ok(expected_version);
    }
    let credentials = credentials.ok_or_else(|| {
        Status::failed_precondition(
            "provider refresh cleanup requires the configured credential runtime",
        )
    })?;
    delete_pending_secret_handles(credentials, state).await?;
    // Keep the caller's in-memory state unchanged unless the CAS succeeds. A
    // failed cleanup must not let the live refresh path persist a locally
    // cleared tombstone list over the durable retry references.
    let mut cleaned = state.clone();
    cleaned.pending_secret_deletions.clear();
    let new_version = persist_refresh_state_if_current(store, &cleaned, expected_version)
        .await?
        .ok_or_else(|| {
            Status::aborted("provider refresh was deleted or superseded during secret cleanup")
        })?;
    if let Some(metadata) = cleaned.metadata.as_mut() {
        metadata.resource_version = new_version;
    }
    *state = cleaned;
    Ok(new_version)
}

async fn persist_retryable_refresh_error_state(
    store: &Arc<dyn RefreshStateStore>,
    state: &mut RefreshState,
    expected_version: u64,
    error: &Status,
) -> Result<u64, Status> {
    let failure = RefreshFailure::retryable(
        Status::new(error.code(), error.message().to_string()),
        "refresh_failed",
    );
    persist_refresh_failure_state(store, state, expected_version, &failure).await
}

async fn persist_refresh_failure_state(
    store: &Arc<dyn RefreshStateStore>,
    state: &mut RefreshState,
    expected_version: u64,
    failure: &RefreshFailure,
) -> Result<u64, Status> {
    let now_ms = current_time_ms();
    state.status = match failure.recovery_action {
        ProviderCredentialRefreshRecoveryAction::Retry
        | ProviderCredentialRefreshRecoveryAction::Unspecified => "error",
        ProviderCredentialRefreshRecoveryAction::Reauthorize => "reauthorization_required",
        ProviderCredentialRefreshRecoveryAction::FixConfiguration => "configuration_required",
        ProviderCredentialRefreshRecoveryAction::Investigate => "investigation_required",
    }
    .to_string();
    state.last_error = failure.status.message().to_string();
    state.recovery_action = failure.recovery_action as i32;
    state.failure_code = failure.failure_code.to_string();
    state.provider_error_subtype = failure
        .provider_error_subtype
        .unwrap_or_default()
        .to_string();
    state.last_error_at_ms = now_ms;
    state.next_refresh_at_ms = match failure.retry_schedule {
        RefreshRetrySchedule::Short => {
            now_ms.saturating_add(REFRESH_ERROR_RETRY_SECONDS.saturating_mul(1000))
        }
        RefreshRetrySchedule::Configuration => {
            now_ms.saturating_add(REFRESH_CONFIGURATION_RETRY_SECONDS.saturating_mul(1000))
        }
        RefreshRetrySchedule::Parked => i64::MAX,
    };
    let new_version = persist_refresh_state_if_current(store, state, expected_version)
        .await?
        .ok_or_else(|| {
            Status::aborted(
                "provider refresh was deleted or superseded while recording a refresh error",
            )
        })?;
    if let Some(metadata) = state.metadata.as_mut() {
        metadata.resource_version = new_version;
    }
    Ok(new_version)
}

pub fn validate_secret_material_references(state: &RefreshState) -> Result<(), Status> {
    let mut missing: Vec<_> = state
        .secret_material_keys
        .iter()
        .filter(|key| {
            !state.material.contains_key(*key) && !state.secret_material_handles.contains_key(*key)
        })
        .cloned()
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    missing.sort();
    missing.dedup();
    Err(Status::failed_precondition(format!(
        "provider refresh secret material is missing both inline values and credential handles for {}; a mixed-version gateway upgrade may have discarded the handles, so restore the refresh state or reconfigure the grant",
        missing.join(", ")
    )))
}

// Local waiters do not consume PostgreSQL sessions while another local mint owns
// the credential. Weak entries avoid retaining every provider ever refreshed.
static REFRESH_LOCKS: std::sync::LazyLock<
    std::sync::Mutex<HashMap<String, std::sync::Weak<tokio::sync::Mutex<()>>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));
static REFRESH_EXECUTORS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
static REFRESH_ADMISSIONS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(32);

fn refresh_lock(state: &RefreshState) -> Result<Arc<tokio::sync::Mutex<()>>, Status> {
    let key = refresh_state_name(&state.provider_id, &state.credential_key);
    let mut locks = REFRESH_LOCKS
        .lock()
        .map_err(|_| Status::internal("refresh coordination unavailable"))?;
    locks.retain(|_, lock| lock.strong_count() > 0);
    let lock = locks
        .get(&key)
        .and_then(std::sync::Weak::upgrade)
        .unwrap_or_else(|| Arc::new(tokio::sync::Mutex::new(())));
    locks.insert(key, Arc::downgrade(&lock));
    Ok(lock)
}

fn completed_mint(state: &RefreshState) -> Option<&str> {
    state
        .metadata
        .as_ref()?
        .annotations
        .get(COMPLETED_MINT_ANNOTATION)
        .map(String::as_str)
        .filter(|id| !id.is_empty())
}

/// Cleanup also mutates the mint receipt's resource version. Use the same
/// local/distributed locks as minting, then reload instead of writing a stale
/// sweep snapshot over an active mint or deleting its replacement grant.
async fn cleanup_pending_secret_deletions_coordinated(
    store: &Arc<dyn RefreshStateStore>,
    credentials: Option<&Arc<dyn CredentialIssuer>>,
    state: &mut RefreshState,
) -> Result<(), Status> {
    if state.pending_secret_deletions.is_empty() {
        return Ok(());
    }
    let _local = tokio::time::timeout(Duration::from_secs(40), refresh_lock(state)?.lock_owned())
        .await
        .map_err(|_| Status::unavailable("credential refresh is busy"))?;
    let _distributed = store
        .acquire(&state.provider_id, &state.credential_key)
        .await
        .map_err(|_| Status::unavailable("credential refresh coordination unavailable"))?;
    let latest = get_refresh_state(
        store,
        state.object_workspace(),
        &state.provider_id,
        &state.credential_key,
    )
    .await?
    .ok_or_else(|| Status::aborted("provider refresh was deleted"))?;
    if latest.object_id() != state.object_id()
        || effective_authorization_epoch(&latest)? != effective_authorization_epoch(state)?
        || latest
            .metadata
            .as_ref()
            .is_some_and(|metadata| metadata.deletion_time.is_some())
    {
        return Err(Status::aborted(
            "provider refresh was deleted or reconfigured",
        ));
    }
    *state = latest;
    let expected_version = state
        .metadata
        .as_ref()
        .map_or(0, |metadata| metadata.resource_version);
    cleanup_pending_secret_deletions(store, credentials, state, expected_version).await?;
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RefreshTrigger {
    Automatic,
    ExplicitRotation,
}

/// Automatic callers must honor the live failure schedule, not the eligibility
/// observed before they queued.
///
/// Configuration/investigation failures can still
/// be retried by the worker once due; reauthorization stays parked.
pub fn ensure_automatic_refresh_ready(state: &RefreshState, now_ms: i64) -> Result<(), Status> {
    if state.recovery_action == ProviderCredentialRefreshRecoveryAction::Reauthorize as i32 {
        return Err(Status::failed_precondition(
            "credential refresh requires recovery",
        ));
    }
    if state.recovery_action != ProviderCredentialRefreshRecoveryAction::Unspecified as i32
        && state.next_refresh_at_ms > now_ms
    {
        return Err(Status::unavailable(
            "credential refresh is in retry backoff",
        ));
    }
    Ok(())
}

pub async fn refresh_provider_credential(
    runtime: &RefreshRuntime,
    workspace: &str,
    provider_name: &str,
    credential_key: &str,
) -> Result<RefreshState, Status> {
    let provider = runtime
        .gateway
        .observe(workspace, provider_name)
        .await
        .map_err(simple_observe_error)?;
    let snapshot = get_refresh_state(
        &runtime.store,
        workspace,
        provider.owner().legacy_scope().id,
        credential_key,
    )
    .await?
    .ok_or_else(|| Status::not_found("provider refresh state not found"))?;
    refresh_from_snapshot_with_trigger(runtime, snapshot, RefreshTrigger::ExplicitRotation).await
}

fn simple_observe_error(error: Status) -> Status {
    if error.code() == tonic::Code::Internal {
        Status::internal("fetch provider failed")
    } else {
        error
    }
}

/// Coalesce an automatic refresh against the caller's observed generation, not
/// a name-keyed replacement. Recheck recovery/backoff after acquiring the locks.
pub async fn refresh_from_snapshot(
    runtime: &RefreshRuntime,
    snapshot: RefreshState,
) -> Result<RefreshState, Status> {
    refresh_from_snapshot_with_trigger(runtime, snapshot, RefreshTrigger::Automatic).await
}

async fn refresh_from_snapshot_with_trigger(
    runtime: &RefreshRuntime,
    snapshot: RefreshState,
    trigger: RefreshTrigger,
) -> Result<RefreshState, Status> {
    let admission = REFRESH_ADMISSIONS
        .try_acquire()
        .map_err(|_| Status::resource_exhausted("credential refresh queue is full"))?;
    let lock = refresh_lock(&snapshot)?;
    let runtime = runtime.clone();
    let store = runtime.store.clone();
    // A disconnected RPC must not cancel minting after an upstream rotates its
    // refresh token. Spawn before any externally observable refresh side effect.
    tokio::spawn(async move {
        let _admission = admission;
        let _local = tokio::time::timeout(Duration::from_secs(40), lock.lock_owned())
            .await
            .map_err(|_| Status::unavailable("credential refresh is busy"))?;
        let _permit = tokio::time::timeout(Duration::from_secs(40), REFRESH_EXECUTORS.acquire())
            .await
            .map_err(|_| Status::resource_exhausted("credential refresh workers are busy"))?
            .map_err(|_| Status::unavailable("credential refresh workers stopped"))?;
        let _distributed = store
            .acquire(&snapshot.provider_id, &snapshot.credential_key)
            .await
            .map_err(|_| Status::unavailable("credential refresh coordination unavailable"))?;
        let latest = get_refresh_state(
            &store,
            snapshot.object_workspace(),
            &snapshot.provider_id,
            &snapshot.credential_key,
        )
        .await?
        .ok_or_else(|| Status::aborted("provider refresh was deleted"))?;
        if latest.object_id() != snapshot.object_id()
            || effective_authorization_epoch(&latest)? != effective_authorization_epoch(&snapshot)?
        {
            return Err(Status::aborted("provider refresh was reconfigured"));
        }
        if latest
            .metadata
            .as_ref()
            .is_some_and(|metadata| metadata.deletion_time.is_some())
        {
            return Err(Status::failed_precondition(
                "provider refresh is being deleted",
            ));
        }
        // A row-version change can be cleanup or other bookkeeping, not a
        // successful exchange. Only a new committed mint can satisfy a waiter.
        if latest.status == "refreshed"
            && completed_mint(&latest).is_some()
            && completed_mint(&latest) != completed_mint(&snapshot)
        {
            return Ok(latest);
        }
        let provider = runtime
            .gateway
            .observe(snapshot.object_workspace(), &snapshot.provider_name)
            .await
            .map_err(simple_observe_error)?;
        if provider.owner().legacy_scope().id != snapshot.provider_id {
            return Err(Status::aborted("provider was replaced"));
        }
        if matches!(
            latest.status.as_str(),
            "refresh_in_progress" | "refresh_committing"
        ) {
            return Err(Status::failed_precondition(
                "previous credential mint has an uncertain outcome; reconfigure the refresh grant",
            ));
        }
        if trigger == RefreshTrigger::Automatic {
            ensure_automatic_refresh_ready(&latest, current_time_ms())?;
        }
        refresh_provider_credential_locked(
            &runtime,
            snapshot.object_workspace(),
            &snapshot.provider_name,
            &snapshot.credential_key,
        )
        .await
    })
    .await
    .map_err(|_| Status::internal("credential refresh worker failed"))?
}

async fn refresh_provider_credential_locked(
    runtime: &RefreshRuntime,
    workspace: &str,
    provider_name: &str,
    credential_key: &str,
) -> Result<RefreshState, Status> {
    let store = &runtime.store;
    let credentials = runtime.credentials.as_ref().ok_or_else(|| {
        Status::failed_precondition(
            "provider refresh material requires the configured credential runtime",
        )
    })?;
    let provider = runtime.gateway.observe(workspace, provider_name).await?;
    let Some(state) = get_refresh_state(
        store,
        workspace,
        provider.owner().legacy_scope().id,
        credential_key,
    )
    .await?
    else {
        return Err(Status::not_found("provider refresh state not found"));
    };
    if state
        .metadata
        .as_ref()
        .is_some_and(|metadata| metadata.deletion_time.is_some())
    {
        return Err(Status::failed_precondition(
            "provider refresh is being deleted",
        ));
    }
    let mut state = state;
    validate_secret_material_references(&state)?;
    // Generation of the refresh at the start of the rotation. Terminal persists
    // match on it so a concurrent delete or rotation is detected rather than
    // clobbered, and a deleted refresh is never recreated (CWE-362).
    let expected_version = state
        .metadata
        .as_ref()
        .map_or(0, |meta| meta.resource_version);
    let expected_version = match cleanup_pending_secret_deletions(
        store,
        Some(credentials),
        &mut state,
        expected_version,
    )
    .await
    {
        Ok(new_version) => new_version,
        Err(err) => {
            warn!(
                provider = %state.provider_name,
                credential_key = %state.credential_key,
                error = %err,
                "provider refresh material cleanup failed; continuing with live refresh"
            );
            expected_version
        }
    };

    info!(
        provider = %state.provider_name,
        credential_key = %state.credential_key,
        strategy = %refresh_strategy_name(state.strategy),
        status = %state.status,
        expires_at_ms = state.expires_at_ms,
        next_refresh_at_ms = state.next_refresh_at_ms,
        "provider credential refresh started"
    );

    // Persist uncertainty BEFORE contacting the issuer. A crashed process or a
    // lost advisory-lock session cannot lead another replica to reuse the grant.
    state.status = "refresh_in_progress".to_string();
    state.next_refresh_at_ms = i64::MAX;
    state.recovery_action = ProviderCredentialRefreshRecoveryAction::Investigate as i32;
    let expected_version = persist_refresh_state_if_current(store, &state, expected_version)
        .await?
        .ok_or_else(|| Status::aborted("provider refresh changed before minting"))?;
    let mint_result = match resolve_refresh_material(Some(credentials), &state).await {
        Ok(transient_state) => mint_credential(&transient_state).await,
        Err(err) => Err(err.into()),
    };
    match mint_result {
        Ok(minted) => {
            let now_ms = current_time_ms();
            let mut staged_refresh_token_handles = HashMap::new();
            if let Some(ref refresh_token) = minted.refresh_token {
                if !state
                    .secret_material_keys
                    .iter()
                    .any(|key| key == "refresh_token")
                {
                    state.secret_material_keys.push("refresh_token".to_string());
                }
                let material =
                    HashMap::from([("refresh_token".to_string(), refresh_token.clone())]);
                let staging_id = format!(
                    "{}-refresh-material-{}",
                    state.object_id(),
                    uuid::Uuid::new_v4()
                );
                staged_refresh_token_handles = match credentials
                    .store_refresh_material_with_object_id(
                        refresh_material_scope(&state),
                        &staging_id,
                        &material,
                        &HashMap::new(),
                    )
                    .await
                {
                    Ok(handles) => handles,
                    Err(store_err) => {
                        let failure = RefreshFailure::reauthorize(
                            Status::failed_precondition(format!(
                                "the OAuth provider rotated the refresh token, but the replacement could not be stored; the grant must be re-authorized: {}",
                                store_err.message()
                            )),
                            "oauth_rotated_refresh_token_store_failed",
                            None,
                        );
                        persist_refresh_failure_state(
                            store,
                            &mut state,
                            expected_version,
                            &failure,
                        )
                        .await?;
                        return Err(failure.into_status());
                    }
                };
                let Some(handle) = staged_refresh_token_handles.get("refresh_token").cloned()
                else {
                    let failure = RefreshFailure::reauthorize(
                        Status::failed_precondition(
                            "the OAuth provider rotated the refresh token, but the credential driver returned no replacement handle; the grant must be re-authorized",
                        ),
                        "oauth_rotated_refresh_token_handle_missing",
                        None,
                    );
                    cleanup_staged_refresh_material_handles(
                        credentials,
                        &state,
                        &staged_refresh_token_handles,
                    )
                    .await;
                    persist_refresh_failure_state(store, &mut state, expected_version, &failure)
                        .await?;
                    return Err(failure.into_status());
                };
                if let Some(previous) = state
                    .secret_material_handles
                    .insert("refresh_token".to_string(), handle)
                {
                    enqueue_pending_secret_deletion(&mut state, "refresh_token", previous);
                }
                state.material.remove("refresh_token");
            }
            state.expires_at_ms = minted.expires_at_ms;
            set_refresh_expiration_presence(&mut state, true);
            state.next_refresh_at_ms =
                next_refresh_at_ms(minted.expires_at_ms, state.refresh_before.as_ref());
            state.last_refresh_at_ms = now_ms;
            let completed_next_refresh_at_ms = state.next_refresh_at_ms;
            state.status = "refresh_committing".to_string();
            state.next_refresh_at_ms = i64::MAX;
            state.last_error.clear();
            state.recovery_action = ProviderCredentialRefreshRecoveryAction::Unspecified as i32;
            state.failure_code.clear();
            state.provider_error_subtype.clear();
            state.last_error_at_ms = 0;

            // Claim the refresh generation with a version-matched write BEFORE
            // touching the provider. It succeeds only if the refresh still holds
            // the generation we started from; if it was deleted, recreated, or a
            // concurrent rotation won, it returns `None` and we leave both the
            // refresh state and the provider unchanged — no credentials minted
            // from a stale generation are written, and a deleted refresh is not
            // resurrected (CWE-362). This makes generation ownership the gate on
            // the provider credential write.
            let new_version = match persist_refresh_state_if_current(
                store,
                &state,
                expected_version,
            )
            .await
            {
                Ok(Some(new_version)) => new_version,
                Ok(None) => {
                    if !staged_refresh_token_handles.is_empty() {
                        cleanup_staged_refresh_material_handles(
                            credentials,
                            &state,
                            &staged_refresh_token_handles,
                        )
                        .await;
                    }
                    warn!(
                        provider = %state.provider_name,
                        credential_key = %state.credential_key,
                        strategy = %refresh_strategy_name(state.strategy),
                        "provider credential refresh deleted or superseded during rotation; discarding minted credentials"
                    );
                    return Err(Status::aborted(
                        "provider refresh was deleted or superseded during rotation",
                    ));
                }
                Err(err) => {
                    // The replacement refresh token is already in credential
                    // storage. Retry the same CAS with error/backoff state so a
                    // transient database failure does not discard the only
                    // upstream-valid grant. If that also fails, leave the
                    // staged object intact for operator recovery rather than
                    // deleting an irreplaceable rotated token.
                    persist_retryable_refresh_error_state(
                        store,
                        &mut state,
                        expected_version,
                        &err,
                    )
                    .await?;
                    return Err(err);
                }
            };

            // Generation is ours; write the minted credentials into the provider.
            if let Err(err) = apply_minted_credential(
                Some(credentials),
                provider.as_ref(),
                credential_key,
                &minted,
            )
            .await
            {
                // Reflect the failure on the state we just wrote; skip silently
                // if it was deleted concurrently (it is not recreated).
                let failure = RefreshFailure::from_status(&err);
                persist_refresh_failure_state(store, &mut state, new_version, &failure).await?;
                warn!(
                    provider = %state.provider_name,
                    credential_key = %state.credential_key,
                    strategy = %refresh_strategy_name(state.strategy),
                    status = %state.status,
                    next_refresh_at_ms = state.next_refresh_at_ms,
                    seconds_until_refresh = seconds_until_ms(now_ms, state.next_refresh_at_ms),
                    error = %err,
                    "provider credential refresh errored"
                );
                return Err(err);
            }
            // A success snapshot must not become visible before its provider
            // handles are committed. Park incomplete commits rather than minting
            // again after a crash or lost database session.
            state.status = "refreshed".to_string();
            state.next_refresh_at_ms = completed_next_refresh_at_ms;
            if let Some(metadata) = state.metadata.as_mut() {
                metadata.annotations.insert(
                    COMPLETED_MINT_ANNOTATION.to_string(),
                    uuid::Uuid::new_v4().to_string(),
                );
            }
            let new_version = persist_refresh_state_if_current(store, &state, new_version)
                .await?
                .ok_or_else(|| {
                    Status::aborted("provider refresh changed during credential commit")
                })?;
            info!(
                provider = %state.provider_name,
                credential_key = %state.credential_key,
                strategy = %refresh_strategy_name(state.strategy),
                status = %state.status,
                expires_at_ms = state.expires_at_ms,
                next_refresh_at_ms = state.next_refresh_at_ms,
                seconds_until_refresh = seconds_until_ms(now_ms, state.next_refresh_at_ms),
                "provider credential refresh completed"
            );
            if !state.pending_secret_deletions.is_empty()
                && let Err(err) = cleanup_pending_secret_deletions(
                    store,
                    Some(credentials),
                    &mut state,
                    new_version,
                )
                .await
            {
                warn!(
                    provider = %state.provider_name,
                    credential_key = %state.credential_key,
                    error = %err,
                    "failed to clean up replaced refresh material; retrying on the next sweep"
                );
            }
            Ok(state)
        }
        Err(failure) => {
            let now_ms = current_time_ms();
            persist_refresh_failure_state(store, &mut state, expected_version, &failure).await?;
            warn!(
                provider = %state.provider_name,
                credential_key = %state.credential_key,
                strategy = %refresh_strategy_name(state.strategy),
                status = %state.status,
                next_refresh_at_ms = state.next_refresh_at_ms,
                seconds_until_refresh = seconds_until_ms(now_ms, state.next_refresh_at_ms),
                recovery_action = ?failure.recovery_action,
                failure_code = failure.failure_code,
                error = %failure.status,
                "provider credential refresh errored"
            );
            Err(failure.into_status())
        }
    }
}

async fn cleanup_staged_refresh_material_handles(
    credentials: &Arc<dyn CredentialIssuer>,
    state: &RefreshState,
    handles: &HashMap<String, CredentialHandle>,
) {
    if let Err(err) = credentials
        .delete_refresh_material_handles(refresh_material_scope(state), handles)
        .await
    {
        warn!(
            provider = %state.provider_name,
            credential_key = %state.credential_key,
            error = %err,
            "failed to clean up staged provider refresh material"
        );
    }
}

pub async fn apply_minted_credential(
    credentials: Option<&Arc<dyn CredentialIssuer>>,
    attempt: &dyn RefreshAttempt,
    credential_key: &str,
    minted: &MintedCredential,
) -> Result<(), Status> {
    let expiration =
        openshell_core::time::optional_timestamp_from_legacy_millis(minted.expires_at_ms)
            .map_err(|error| Status::internal(error.to_string()))?;
    let owner = attempt.owner();
    let staging_id = format!(
        "{}-refresh-{}",
        owner.legacy_scope().id,
        uuid::Uuid::new_v4()
    );
    let mut values = HashMap::from([(credential_key.to_string(), minted.access_token.clone())]);
    values.extend(minted.additional_credentials.clone());
    let staged = if let Some(credentials) = credentials.filter(|c| c.stores_provider_credentials())
    {
        attempt.prepare_workspace().await?;
        let handles = credentials
            .store(StoreSecrets {
                owner,
                object_id: Some(&staging_id),
                values: &values,
                existing_handles: &HashMap::new(),
            })
            .await?;
        if !handles.contains_key(credential_key) {
            cleanup_staged_refresh_handles(credentials, owner, &handles).await;
            return Err(Status::internal(
                "credential driver did not return refreshed credential handle",
            ));
        }
        Some(handles)
    } else {
        None
    };
    // Production commits carry handles only; retain plaintext solely for the
    // existing inline/test construction path.
    let empty = HashMap::new();
    let result = attempt
        .commit(RefreshOutputs {
            credential_key,
            additional_keys: minted.additional_credentials.keys().cloned().collect(),
            handles: staged.as_ref(),
            inline: if staged.is_some() { &empty } else { &values },
            expiration,
        })
        .await;
    match result {
        Err(error) => {
            if let (Some(credentials), Some(handles)) = (credentials, staged.as_ref()) {
                cleanup_staged_refresh_handles(credentials, owner, handles).await;
            }
            Err(error)
        }
        Ok(old_handles) => {
            if !old_handles.is_empty()
                && let Some(credentials) = credentials
                && let Err(cleanup_err) = credentials.delete(owner, &old_handles).await
            {
                warn!(provider_name = %owner.legacy_scope().provider, error = %cleanup_err,
                    "failed to clean up old provider credential handles after successful refresh");
            }
            Ok(())
        }
    }
}

async fn cleanup_staged_refresh_handles(
    credentials: &Arc<dyn CredentialIssuer>,
    owner: SecretOwner<'_>,
    handles: &Handles,
) {
    if let Err(cleanup_err) = credentials.delete(owner, handles).await {
        warn!(provider_name = %owner.legacy_scope().provider, error = %cleanup_err,
            "failed to clean up staged provider credentials after refresh failure");
    }
}

/// Coalesced provider invalidations from committed refreshes and finalized deletions.
pub async fn run_refresh_worker_tick(
    runtime: &RefreshRuntime,
) -> Result<Vec<RefreshChange>, Status> {
    let changed_providers = Vec::new();
    let now_ms = current_time_ms();
    let states = list_all_refresh_states(&runtime.store).await?;
    let watched_count = states.len();
    let due_count = states
        .iter()
        .filter(|state| state.next_refresh_at_ms <= 0 || state.next_refresh_at_ms <= now_ms)
        .count();
    let rotation_requested_count = states
        .iter()
        .filter(|state| state.status == "rotation_requested")
        .count();
    info!(
        watched_count,
        due_count, rotation_requested_count, "provider credential refresh worker sweep"
    );
    if !states
        .iter()
        .any(|state| refresh_state_has_work(state, now_ms))
    {
        return Ok(changed_providers);
    }
    let span = tracing::info_span!(
        "refresh",
        otel.name = "refresh.provider_credentials",
        watched_count,
        due_count,
    );
    Ok(Box::pin(refresh_states(runtime, states, now_ms).instrument(span)).await)
}

fn refresh_state_has_work(state: &RefreshState, now_ms: i64) -> bool {
    state
        .metadata
        .as_ref()
        .is_some_and(|metadata| metadata.deletion_time.is_some())
        || !state.pending_secret_deletions.is_empty()
        || state.next_refresh_at_ms <= 0
        || state.next_refresh_at_ms <= now_ms
        || state.status == "rotation_requested"
}

pub async fn refresh_states(
    runtime: &RefreshRuntime,
    states: Vec<RefreshState>,
    now_ms: i64,
) -> Vec<RefreshChange> {
    let mut changed_providers = HashMap::new();
    let store = &runtime.store;
    let credentials = runtime.credentials.as_ref();
    for state in states {
        if state
            .metadata
            .as_ref()
            .is_some_and(|metadata| metadata.deletion_time.is_some())
        {
            let Some(credentials) = credentials else {
                warn!(
                    provider = %state.provider_name,
                    credential_key = %state.credential_key,
                    "cannot finalize tombstoned provider refresh without credential runtime"
                );
                continue;
            };
            if let Err(err) = delete_refresh_state_with_credentials(
                store,
                credentials,
                state.object_workspace(),
                &state.provider_id,
                &state.credential_key,
            )
            .await
            {
                warn!(
                    provider = %state.provider_name,
                    credential_key = %state.credential_key,
                    error = %err,
                    "failed to finalize tombstoned provider refresh; retrying on the next sweep"
                );
            } else {
                changed_providers.insert(changed_provider(&state), change(&state));
            }
            continue;
        }
        let mut state = state;
        if let Err(err) =
            cleanup_pending_secret_deletions_coordinated(store, credentials, &mut state).await
        {
            warn!(
                provider = %state.provider_name,
                credential_key = %state.credential_key,
                error = %err,
                "provider refresh material cleanup failed; continuing with live refresh"
            );
        }
        let strategy = ProviderCredentialRefreshStrategy::try_from(state.strategy)
            .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified);
        if !minter::can_mint(strategy as i32) {
            warn!(
                provider = %state.provider_name,
                credential_key = %state.credential_key,
                strategy = %refresh_strategy_name(state.strategy),
                status = %state.status,
                "skipping non-gateway-mintable provider credential refresh state"
            );
            continue;
        }
        let due = state.next_refresh_at_ms <= 0 || state.next_refresh_at_ms <= now_ms;
        let rotation_requested = state.status == "rotation_requested";
        info!(
            provider = %state.provider_name,
            credential_key = %state.credential_key,
            strategy = %refresh_strategy_name(state.strategy),
            status = %state.status,
            expires_at_ms = state.expires_at_ms,
            seconds_until_expiry = seconds_until_ms(now_ms, state.expires_at_ms),
            next_refresh_at_ms = state.next_refresh_at_ms,
            last_refresh_at_ms = state.last_refresh_at_ms,
            seconds_until_refresh = seconds_until_ms(now_ms, state.next_refresh_at_ms),
            due,
            rotation_requested,
            "provider credential refresh watch"
        );
        if !due && !rotation_requested {
            continue;
        }
        if credentials.is_none() {
            warn!(
                provider = %state.provider_name,
                credential_key = %state.credential_key,
                "cannot refresh provider credential without credential runtime"
            );
            continue;
        }
        info!(
            provider = %state.provider_name,
            credential_key = %state.credential_key,
            strategy = %refresh_strategy_name(state.strategy),
            status = %state.status,
            "refreshing provider credential"
        );
        let trigger = if rotation_requested {
            RefreshTrigger::ExplicitRotation
        } else {
            RefreshTrigger::Automatic
        };
        match refresh_from_snapshot_with_trigger(runtime, state.clone(), trigger).await {
            Err(err) => {
                warn!(
                    provider = %state.provider_name,
                    credential_key = %state.credential_key,
                    strategy = %refresh_strategy_name(state.strategy),
                    status = %state.status,
                    next_refresh_at_ms = state.next_refresh_at_ms,
                    error = %err,
                    "provider credential refresh failed"
                );
            }
            Ok(committed) => {
                changed_providers.insert(changed_provider(&committed), change(&committed));
            }
        }
    }
    changed_providers.into_values().collect()
}

fn changed_provider(state: &RefreshState) -> (String, String) {
    (
        state.object_workspace().to_string(),
        state.provider_name.clone(),
    )
}

async fn persist_refresh_state_if_current(
    store: &Arc<dyn RefreshStateStore>,
    state: &RefreshState,
    version: u64,
) -> Result<Option<u64>, Status> {
    store.replace(state, version).await
}
async fn get_refresh_state(
    store: &Arc<dyn RefreshStateStore>,
    workspace: &str,
    provider: &str,
    key: &str,
) -> Result<Option<RefreshState>, Status> {
    store.get(workspace, provider, key).await
}
async fn list_refresh_states_for_provider(
    store: &Arc<dyn RefreshStateStore>,
    provider: &str,
) -> Result<Vec<RefreshState>, Status> {
    store.list(Some(provider)).await
}
async fn list_all_refresh_states(
    store: &Arc<dyn RefreshStateStore>,
) -> Result<Vec<RefreshState>, Status> {
    store.list(None).await
}
fn seconds_until_ms(now_ms: i64, target_ms: i64) -> i64 {
    if target_ms <= 0 {
        0
    } else {
        target_ms.saturating_sub(now_ms).max(0) / 1000
    }
}

pub fn change(state: &RefreshState) -> RefreshChange {
    RefreshChange {
        workspace: state.object_workspace().to_string(),
        provider_name: state.provider_name.clone(),
        credential_key: state.credential_key.clone(),
        completed_mint: completed_mint(state).map(str::to_owned),
    }
}

#[async_trait]
impl CredentialRefresh for RefreshRuntime {
    async fn get(
        &self,
        workspace: &str,
        provider_id: &str,
        key: &str,
    ) -> Result<Option<RefreshState>, Status> {
        self.store.get(workspace, provider_id, key).await
    }
    async fn list(&self, provider_id: Option<&str>) -> Result<Vec<RefreshState>, Status> {
        self.store.list(provider_id).await
    }
    async fn create(&self, state: RefreshState) -> Result<(), Status> {
        self.store.create(&state).await
    }
    async fn replace(&self, state: RefreshState, version: u64) -> Result<bool, Status> {
        Ok(self.store.replace(&state, version).await?.is_some())
    }
    async fn delete(&self, state: RefreshState) -> Result<(), Status> {
        let credentials = self.credentials.as_ref().ok_or_else(|| {
            Status::failed_precondition(
                "provider refresh cleanup requires the configured credential runtime",
            )
        })?;
        delete_observed_refresh_state_with_credentials(&self.store, credentials, state).await
    }
    async fn rotate(
        &self,
        workspace: &str,
        provider_name: &str,
        key: &str,
    ) -> Result<RefreshState, Status> {
        refresh_provider_credential(self, workspace, provider_name, key).await
    }
    async fn ensure_fresh(&self, snapshot: RefreshState) -> Result<RefreshState, Status> {
        refresh_from_snapshot(self, snapshot).await
    }
    async fn sweep(&self) -> Result<Vec<RefreshChange>, Status> {
        run_refresh_worker_tick(self).await
    }
}
