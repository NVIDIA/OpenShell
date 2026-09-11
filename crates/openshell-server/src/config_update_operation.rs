// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Durable completion tracking for sandbox-scoped desired-state updates.

use std::sync::Arc;
use std::time::Duration;

use futures::{StreamExt as _, stream};
use metrics::{counter, gauge, histogram};
use openshell_core::ObjectId;
use openshell_core::proto::{
    ConfigApplyOutcome, ConfigComponent, ConfigComponentApplyResult, ConfigSnapshotRevision,
    ConfigUpdateOperation, ConfigUpdateOperationState, ObjectMeta, Sandbox, SandboxConfigRevision,
    SandboxPhase, UpdateConfigResponse, config_snapshot_revision,
};
use tonic::Status;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::ServerState;
use crate::persistence::{KnownVersionUpdate, ObjectType, current_time_ms};
use crate::storage_proto::StoredConfigUpdateOperation;

pub const CONFIG_UPDATE_OPERATION_OBJECT_TYPE: &str = "config_update_operation";
const OPERATION_SCAN_PAGE_SIZE: u32 = 250;
const MAX_TRANSITION_RETRIES: usize = 8;
const DEFAULT_WAIT_TIMEOUT: Duration = Duration::from_mins(1);
const MAX_WAIT_TIMEOUT: Duration = Duration::from_hours(1);
const MAX_SANITIZED_ERROR_BYTES: usize = 1_024;

impl ObjectType for StoredConfigUpdateOperation {
    fn object_type() -> &'static str {
        CONFIG_UPDATE_OPERATION_OBJECT_TYPE
    }
}

#[derive(Debug, Clone, Copy)]
pub struct OperationTarget {
    pub policy_version: u32,
    pub settings_revision: u64,
}

#[derive(Debug, Clone, Default)]
pub struct CommittedResponse {
    pub policy_version: u32,
    pub policy_hash: String,
    pub settings_revision: u64,
    pub deleted: bool,
    pub annotations: std::collections::HashMap<String, String>,
}

pub fn operation_name(sandbox_id: &str, idempotency_key: &str, operation_id: &str) -> String {
    if idempotency_key.is_empty() {
        operation_id.to_string()
    } else {
        format!("{sandbox_id}:{idempotency_key}")
    }
}

fn initial_state(phase: SandboxPhase) -> ConfigUpdateOperationState {
    match phase {
        SandboxPhase::Stopped | SandboxPhase::Completed => ConfigUpdateOperationState::Inactive,
        SandboxPhase::Deleting => ConfigUpdateOperationState::Cancelled,
        SandboxPhase::Unspecified
        | SandboxPhase::Provisioning
        | SandboxPhase::Ready
        | SandboxPhase::Error
        | SandboxPhase::Unknown
        | SandboxPhase::Stopping
        | SandboxPhase::Starting => ConfigUpdateOperationState::Pending,
    }
}

pub fn sandbox_phase(sandbox: &Sandbox) -> SandboxPhase {
    sandbox
        .status
        .as_ref()
        .and_then(|status| SandboxPhase::try_from(status.phase).ok())
        .unwrap_or_default()
}

pub fn new_record(
    sandbox: &Sandbox,
    workspace: &str,
    idempotency_key: &str,
    target: OperationTarget,
    response: CommittedResponse,
) -> StoredConfigUpdateOperation {
    let operation_id = Uuid::new_v4().to_string();
    let now = current_time_ms();
    let phase = sandbox_phase(sandbox);
    let state = initial_state(phase);
    let completed_at_ms = if terminal(state) { now } else { 0 };
    StoredConfigUpdateOperation {
        metadata: Some(ObjectMeta {
            id: operation_id.clone(),
            name: operation_name(sandbox.object_id(), idempotency_key, &operation_id),
            created_at_ms: now,
            workspace: workspace.to_string(),
            ..Default::default()
        }),
        operation: Some(ConfigUpdateOperation {
            operation_id,
            sandbox_id: sandbox.object_id().to_string(),
            component: ConfigComponent::SandboxConfig.into(),
            target_revision: None,
            state: state.into(),
            outcome: ConfigApplyOutcome::Unspecified.into(),
            sanitized_error: String::new(),
            created_at_ms: now,
            updated_at_ms: now,
            completed_at_ms,
        }),
        target_policy_version: target.policy_version,
        target_settings_revision: target.settings_revision,
        initial_phase: phase.into(),
        idempotency_key: idempotency_key.to_string(),
        attempt_count: 0,
        next_attempt_at_ms: now,
        response_policy_version: response.policy_version,
        response_policy_hash: response.policy_hash,
        response_settings_revision: response.settings_revision,
        response_deleted: response.deleted,
        response_annotations: response.annotations,
    }
}

pub async fn find_idempotent(
    state: &ServerState,
    workspace: &str,
    sandbox_id: &str,
    idempotency_key: &str,
) -> Result<Option<StoredConfigUpdateOperation>, Status> {
    if idempotency_key.is_empty() {
        return Ok(None);
    }
    state
        .store
        .get_message_by_name::<StoredConfigUpdateOperation>(
            workspace,
            &operation_name(sandbox_id, idempotency_key, ""),
        )
        .await
        .map_err(|error| Status::internal(format!("fetch update operation failed: {error}")))
}

pub async fn get_record(
    state: &ServerState,
    operation_id: &str,
) -> Result<Option<StoredConfigUpdateOperation>, Status> {
    state
        .store
        .get_message::<StoredConfigUpdateOperation>(operation_id)
        .await
        .map_err(|error| Status::internal(format!("fetch update operation failed: {error}")))
}

pub fn public_operation(
    record: &StoredConfigUpdateOperation,
) -> Result<ConfigUpdateOperation, Status> {
    record
        .operation
        .clone()
        .ok_or_else(|| Status::internal("stored update operation payload missing"))
}

pub fn response_from_record(
    record: &StoredConfigUpdateOperation,
) -> Result<UpdateConfigResponse, Status> {
    Ok(UpdateConfigResponse {
        version: record.response_policy_version,
        policy_hash: record.response_policy_hash.clone(),
        settings_revision: record.response_settings_revision,
        deleted: record.response_deleted,
        annotations: record.response_annotations.clone(),
        operation: Some(public_operation(record)?),
    })
}

pub fn terminal(state: ConfigUpdateOperationState) -> bool {
    matches!(
        state,
        ConfigUpdateOperationState::Applied
            | ConfigUpdateOperationState::Inactive
            | ConfigUpdateOperationState::Failed
            | ConfigUpdateOperationState::Superseded
            | ConfigUpdateOperationState::Cancelled
    )
}

fn sanitize_error(value: &str) -> String {
    let mut end = value.len().min(MAX_SANITIZED_ERROR_BYTES);
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value[..end].to_string()
}

async fn mutate_record<F>(
    state: &ServerState,
    operation_id: &str,
    mut mutate: F,
) -> Result<Option<(StoredConfigUpdateOperation, bool)>, Status>
where
    F: FnMut(&mut StoredConfigUpdateOperation) -> bool,
{
    for _ in 0..MAX_TRANSITION_RETRIES {
        let Some(current) = get_record(state, operation_id).await? else {
            return Ok(None);
        };
        let version = current
            .metadata
            .as_ref()
            .map_or(0, |metadata| metadata.resource_version);
        let mut candidate = current.clone();
        let changed = mutate(&mut candidate);
        if !changed {
            return Ok(Some((current, false)));
        }
        let updated = state
            .store
            .update_config_operation_cas(&candidate, version)
            .await;
        match updated {
            Ok(KnownVersionUpdate::Changed(updated)) => return Ok(Some((updated, true))),
            Ok(KnownVersionUpdate::Conflict) => {}
            Err(error) => {
                return Err(Status::internal(format!(
                    "persist update operation transition failed: {error}"
                )));
            }
        }
    }
    Err(Status::aborted(
        "update operation changed concurrently; retry the operation query",
    ))
}

async fn finish(
    state: &ServerState,
    operation_id: &str,
    terminal_state: ConfigUpdateOperationState,
    outcome: ConfigApplyOutcome,
    error: &str,
) -> Result<(), Status> {
    let now = current_time_ms();
    let transition = mutate_record(state, operation_id, |record| {
        let Some(operation) = record.operation.as_mut() else {
            return false;
        };
        let current = ConfigUpdateOperationState::try_from(operation.state).unwrap_or_default();
        if terminal(current) {
            return false;
        }
        operation.state = terminal_state.into();
        operation.outcome = outcome.into();
        operation.sanitized_error = sanitize_error(error);
        operation.updated_at_ms = now;
        operation.completed_at_ms = now;
        true
    })
    .await?;
    if let Some((record, true)) = transition {
        counter!(
            "openshell_config_update_operations_terminal_total",
            "state" => terminal_state.as_str_name()
        )
        .increment(1);
        if let Some(operation) = record.operation.as_ref() {
            state.sandbox_watch_bus.notify(&operation.sandbox_id);
        }
    }
    Ok(())
}

fn snapshot_revision(
    snapshot: &openshell_core::proto::SandboxConfigSnapshot,
) -> ConfigSnapshotRevision {
    ConfigSnapshotRevision {
        component: Some(config_snapshot_revision::Component::SandboxConfig(
            SandboxConfigRevision {
                config_revision: snapshot.config_revision,
                policy_version: snapshot.version,
                policy_source: snapshot.policy_source,
                global_policy_version: snapshot.global_policy_version,
                settings_revision: snapshot.settings_revision,
            },
        )),
    }
}

fn target_relation(
    record: &StoredConfigUpdateOperation,
    snapshot: &openshell_core::proto::SandboxConfigSnapshot,
) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    let policy = snapshot.version.cmp(&record.target_policy_version);
    let settings = snapshot
        .settings_revision
        .cmp(&record.target_settings_revision);
    if policy == Ordering::Equal && settings == Ordering::Equal {
        Ordering::Equal
    } else if policy == Ordering::Greater || settings == Ordering::Greater {
        Ordering::Greater
    } else {
        Ordering::Less
    }
}

pub async fn reconcile_one(state: &Arc<ServerState>, operation_id: &str) -> Result<(), Status> {
    let Some(record) = get_record(state, operation_id).await? else {
        return Ok(());
    };
    reconcile_records_for_sandbox(state, vec![record]).await
}

async fn reconcile_records_for_sandbox(
    state: &Arc<ServerState>,
    records: Vec<StoredConfigUpdateOperation>,
) -> Result<(), Status> {
    let Some(first_operation) = records.first().and_then(|record| record.operation.as_ref()) else {
        return Ok(());
    };
    let sandbox_id = first_operation.sandbox_id.clone();

    let Some(sandbox) = state
        .store
        .get_message::<Sandbox>(&sandbox_id)
        .await
        .map_err(|error| Status::internal(format!("fetch operation sandbox failed: {error}")))?
    else {
        for record in records {
            if let Some(operation) = record.operation.as_ref() {
                finish(
                    state,
                    &operation.operation_id,
                    ConfigUpdateOperationState::Cancelled,
                    ConfigApplyOutcome::Unspecified,
                    "sandbox no longer exists",
                )
                .await?;
            }
        }
        return Ok(());
    };

    match initial_state(sandbox_phase(&sandbox)) {
        ConfigUpdateOperationState::Inactive => {
            for record in records {
                if let Some(operation) = record.operation.as_ref() {
                    finish(
                        state,
                        &operation.operation_id,
                        ConfigUpdateOperationState::Inactive,
                        ConfigApplyOutcome::Unspecified,
                        "",
                    )
                    .await?;
                }
            }
            return Ok(());
        }
        ConfigUpdateOperationState::Cancelled => {
            for record in records {
                if let Some(operation) = record.operation.as_ref() {
                    finish(
                        state,
                        &operation.operation_id,
                        ConfigUpdateOperationState::Cancelled,
                        ConfigApplyOutcome::Unspecified,
                        "sandbox is deleting",
                    )
                    .await?;
                }
            }
            return Ok(());
        }
        _ => {}
    }

    let now = current_time_ms();
    let mut claimed_records = Vec::new();
    for record in records {
        let operation = public_operation(&record)?;
        let operation_state =
            ConfigUpdateOperationState::try_from(operation.state).unwrap_or_default();
        if terminal(operation_state) {
            continue;
        }
        let claimed = mutate_record(state, &operation.operation_id, |stored| {
            let Some(operation) = stored.operation.as_mut() else {
                return false;
            };
            if ConfigUpdateOperationState::try_from(operation.state).is_ok_and(terminal)
                || stored.next_attempt_at_ms > now
            {
                return false;
            }
            operation.updated_at_ms = now;
            stored.attempt_count = stored.attempt_count.saturating_add(1);
            let exponent = stored.attempt_count.min(8);
            let delay_ms = 250_i64.saturating_mul(1_i64 << exponent).min(30_000);
            stored.next_attempt_at_ms = now.saturating_add(delay_ms);
            true
        })
        .await?;
        if let Some((claimed, true)) = claimed {
            claimed_records.push(claimed);
        }
    }
    if claimed_records.is_empty() {
        return Ok(());
    }

    // Claim commits above keep slow snapshot construction and delivery out of
    // the write transaction. Another gateway may inspect the same batch, but
    // its CAS sees the advanced retry deadline and does no work.
    let snapshot = crate::grpc::policy::build_sandbox_config_snapshot(state, &sandbox).await?;
    let mut publish_provider_environment = false;
    let mut claimed_any = false;
    for record in claimed_records {
        let operation = public_operation(&record)?;
        match target_relation(&record, &snapshot) {
            std::cmp::Ordering::Greater => {
                finish(
                    state,
                    &operation.operation_id,
                    ConfigUpdateOperationState::Superseded,
                    ConfigApplyOutcome::IgnoredStale,
                    "a newer desired revision replaced this update before application",
                )
                .await?;
            }
            std::cmp::Ordering::Less => {
                debug!(
                    operation_id = operation.operation_id,
                    "desired revision has not reached update operation target"
                );
            }
            std::cmp::Ordering::Equal => {
                let target_revision = snapshot_revision(&snapshot);
                let _ = mutate_record(state, &operation.operation_id, |stored| {
                    let Some(operation) = stored.operation.as_mut() else {
                        return false;
                    };
                    if ConfigUpdateOperationState::try_from(operation.state).is_ok_and(terminal) {
                        return false;
                    }
                    if operation.target_revision.as_ref() == Some(&target_revision) {
                        return false;
                    }
                    operation.target_revision = Some(target_revision);
                    operation.updated_at_ms = now;
                    true
                })
                .await?;
                claimed_any = true;
                publish_provider_environment |= record.response_policy_version != 0;
            }
        }
    }
    if claimed_any {
        let components = if publish_provider_environment {
            crate::config_delivery::ConfigComponents::SANDBOX_AND_PROVIDER
        } else {
            crate::config_delivery::ConfigComponents::SANDBOX_CONFIG
        };
        crate::config_delivery::publish_sandbox_components(state, &sandbox_id, components);
    }
    Ok(())
}

pub async fn complete_from_apply_results(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    results: &[ConfigComponentApplyResult],
) -> Result<(), Status> {
    let relevant: Vec<_> = results
        .iter()
        .filter(|result| result.component != ConfigComponent::ProviderEnvironment as i32)
        .collect();
    if relevant.is_empty() {
        return Ok(());
    }
    let operations = state
        .store
        .list_pending_config_operations_for_scope(sandbox_id)
        .await
        .map_err(|error| Status::internal(format!("list update operations failed: {error}")))?;
    for record in operations {
        let Some(operation) = record.operation.as_ref() else {
            continue;
        };
        for result in &relevant {
            let requested = result
                .requested_revision
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("configuration result revision missing"))?;
            if operation.component != result.component
                || operation.target_revision.as_ref() != Some(requested)
            {
                continue;
            }
            let outcome = ConfigApplyOutcome::try_from(result.outcome).unwrap_or_default();
            let terminal_state = match outcome {
                ConfigApplyOutcome::Applied
                | ConfigApplyOutcome::IgnoredDuplicate
                | ConfigApplyOutcome::Degraded => ConfigUpdateOperationState::Applied,
                ConfigApplyOutcome::IgnoredStale => ConfigUpdateOperationState::Superseded,
                ConfigApplyOutcome::RetainedLocalOverride
                | ConfigApplyOutcome::FailedRetainedLastKnownGood
                | ConfigApplyOutcome::FailedClosed
                | ConfigApplyOutcome::Unsupported
                | ConfigApplyOutcome::Unspecified => ConfigUpdateOperationState::Failed,
            };
            let failure = result
                .failure
                .as_ref()
                .map_or("", |failure| failure.message.as_str());
            finish(
                state,
                &operation.operation_id,
                terminal_state,
                outcome,
                failure,
            )
            .await?;
            break;
        }
    }
    Ok(())
}

pub async fn complete_from_apply_result(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    result: &ConfigComponentApplyResult,
) -> Result<(), Status> {
    complete_from_apply_results(state, sandbox_id, std::slice::from_ref(result)).await
}

pub async fn wait_for_terminal(
    state: &Arc<ServerState>,
    operation_id: &str,
    timeout_secs: u32,
) -> Result<ConfigUpdateOperation, Status> {
    let timeout = if timeout_secs == 0 {
        DEFAULT_WAIT_TIMEOUT
    } else {
        Duration::from_secs(u64::from(timeout_secs)).min(MAX_WAIT_TIMEOUT)
    };
    let started = std::time::Instant::now();
    let deadline = tokio::time::Instant::now() + timeout;
    let initial = get_record(state, operation_id)
        .await?
        .ok_or_else(|| Status::not_found("update operation not found"))?;
    let sandbox_id = public_operation(&initial)?.sandbox_id;
    let mut wake = state.sandbox_watch_bus.subscribe(&sandbox_id);
    loop {
        let record = get_record(state, operation_id)
            .await?
            .ok_or_else(|| Status::not_found("update operation not found"))?;
        let operation = public_operation(&record)?;
        let operation_state =
            ConfigUpdateOperationState::try_from(operation.state).unwrap_or_default();
        if terminal(operation_state) {
            histogram!("openshell_config_update_operation_wait_seconds")
                .record(started.elapsed().as_secs_f64());
            return Ok(operation);
        }
        if tokio::time::Instant::now() >= deadline {
            let mut status = Status::deadline_exceeded(format!(
                "timed out waiting for update operation {operation_id}"
            ));
            if let Ok(value) = operation_id.parse() {
                status.metadata_mut().insert("operation-id", value);
            }
            return Err(status);
        }
        tokio::select! {
            () = tokio::time::sleep_until((tokio::time::Instant::now() + Duration::from_secs(1)).min(deadline)) => {}
            _ = wake.recv() => {}
        }
    }
}

async fn reconcile_sandbox(state: &Arc<ServerState>, sandbox_id: &str) -> Result<(), Status> {
    let operations = state
        .store
        .list_pending_config_operations_for_scope(sandbox_id)
        .await
        .map_err(|error| Status::internal(format!("list sandbox operations failed: {error}")))?;
    reconcile_records_for_sandbox(state, operations).await
}

async fn reconcile_due_batch(state: &Arc<ServerState>) {
    let now = current_time_ms();
    match state
        .store
        .list_due_config_update_operations(now, OPERATION_SCAN_PAGE_SIZE)
        .await
    {
        Ok(operations) => {
            let mut sandbox_groups = std::collections::BTreeMap::<_, Vec<_>>::new();
            for record in operations {
                let Some(sandbox_id) = record
                    .operation
                    .as_ref()
                    .map(|operation| operation.sandbox_id.clone())
                else {
                    continue;
                };
                sandbox_groups.entry(sandbox_id).or_default().push(record);
            }
            let concurrency = state.store.max_connections().saturating_sub(1).max(1) as usize;
            stream::iter(sandbox_groups)
                .for_each_concurrent(concurrency, |(sandbox_id, records)| {
                    let state = state.clone();
                    async move {
                        if let Err(error) = reconcile_records_for_sandbox(&state, records).await {
                            warn!(sandbox_id, error = %error, "update operation reconciliation failed");
                        }
                    }
                })
                .await;
        }
        Err(error) => warn!(error = %error, "failed to list due update operations"),
    }
    match state.store.count_pending_config_update_operations().await {
        Ok(pending) => {
            gauge!("openshell_config_update_operations_pending")
                .set(u32::try_from(pending).unwrap_or(u32::MAX));
        }
        Err(error) => warn!(error = %error, "failed to count pending update operations"),
    }
}

pub fn spawn_reconciler(state: Arc<ServerState>, interval: Duration) {
    let mut changed_sandboxes = state.sandbox_watch_bus.subscribe_all();
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(interval);
        timer.tick().await;
        loop {
            tokio::select! {
                _ = timer.tick() => reconcile_due_batch(&state).await,
                changed = changed_sandboxes.recv() => {
                    match changed {
                        Ok(sandbox_id) => {
                            if let Err(error) = reconcile_sandbox(&state, &sandbox_id).await {
                                warn!(sandbox_id, error = %error, "sandbox update operation reconciliation failed");
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            reconcile_due_batch(&state).await;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::SandboxConfigSnapshot;

    #[test]
    fn authoritative_phase_classification_is_explicit() {
        assert_eq!(
            initial_state(SandboxPhase::Ready),
            ConfigUpdateOperationState::Pending
        );
        assert_eq!(
            initial_state(SandboxPhase::Provisioning),
            ConfigUpdateOperationState::Pending
        );
        assert_eq!(
            initial_state(SandboxPhase::Starting),
            ConfigUpdateOperationState::Pending
        );
        assert_eq!(
            initial_state(SandboxPhase::Stopping),
            ConfigUpdateOperationState::Pending
        );
        assert_eq!(
            initial_state(SandboxPhase::Error),
            ConfigUpdateOperationState::Pending
        );
        assert_eq!(
            initial_state(SandboxPhase::Stopped),
            ConfigUpdateOperationState::Inactive
        );
        assert_eq!(
            initial_state(SandboxPhase::Completed),
            ConfigUpdateOperationState::Inactive
        );
        assert_eq!(
            initial_state(SandboxPhase::Deleting),
            ConfigUpdateOperationState::Cancelled
        );
    }

    #[test]
    fn target_relation_requires_exact_policy_and_settings_tuple() {
        let record = StoredConfigUpdateOperation {
            target_policy_version: 7,
            target_settings_revision: 11,
            ..Default::default()
        };
        let snapshot = |version, settings_revision| SandboxConfigSnapshot {
            version,
            settings_revision,
            ..Default::default()
        };

        assert_eq!(
            target_relation(&record, &snapshot(7, 11)),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            target_relation(&record, &snapshot(8, 11)),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            target_relation(&record, &snapshot(7, 12)),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            target_relation(&record, &snapshot(6, 11)),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn sanitized_errors_are_bounded_on_utf8_boundaries() {
        let value = "é".repeat(MAX_SANITIZED_ERROR_BYTES);
        let sanitized = sanitize_error(&value);
        assert!(sanitized.len() <= MAX_SANITIZED_ERROR_BYTES);
        assert!(sanitized.is_char_boundary(sanitized.len()));
    }
}
