// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Durable, exact-target configuration operations, independent of delivery transport.
//!
//! Provider receipts project the common operation resource. Live installation
//! evidence remains session-bound; an applied operation records historical
//! completion and never substitutes for a fresh provider readiness evaluation.

#![allow(clippy::result_large_err)] // Internal operation helpers preserve gRPC error details.

use std::collections::HashMap;

use openshell_core::proto::{
    ConfigApplyOutcome, ConfigComponent, ConfigSnapshotRevision, ConfigUpdateOperation,
    ConfigUpdateOperationState, ObjectMeta, ProviderMutationKind, ProviderMutationReceipt,
    ProviderReadinessReason, ProviderReadinessState, ProviderReadinessStatus,
    config_snapshot_revision,
};
use openshell_core::rpc_error::{self, ErrorDetails, StatusExt};
use prost::Message;
use sha2::{Digest, Sha256};
use tonic::{Code, Status};

use crate::persistence::{ObjectRecord, ObjectType, PersistenceError, Store, WriteCondition};
use crate::storage_proto::StoredConfigUpdateOperation;

/// Object-store namespace shared by configuration completion resources.
pub const CONFIG_UPDATE_OPERATION_OBJECT_TYPE: &str = "config_update_operation";
const MAX_TRANSITION_RETRIES: usize = 8;

impl ObjectType for StoredConfigUpdateOperation {
    fn object_type() -> &'static str {
        CONFIG_UPDATE_OPERATION_OBJECT_TYPE
    }
}

/// Provider-specific view of one common configuration operation.
#[derive(Clone, Debug)]
pub struct ProviderOperation {
    /// Immutable desired authority captured for this operation.
    pub(crate) receipt: ProviderMutationReceipt,
    /// A failed initial snapshot is never reconstructed into another target.
    pub(crate) snapshot_reason: ProviderReadinessReason,
    /// Durable historical outcome; callers must separately evaluate live readiness.
    pub(crate) operation: ConfigUpdateOperation,
}

fn storage_unavailable() -> Status {
    // A provider mutation can already have committed when operation persistence
    // fails. No retry hint is attached: repeating the mutation is not proven safe.
    Status::with_error_details(
        Code::Unavailable,
        "configuration operation storage unavailable; the saved mutation may remain in effect",
        ErrorDetails::with_error_info(
            "CONFIG_OPERATION_STORAGE_UNCERTAIN",
            rpc_error::ERROR_DOMAIN,
            HashMap::new(),
        ),
    )
}

fn invalid_record() -> Status {
    Status::with_error_details(
        Code::Internal,
        "configuration operation identity is inconsistent",
        ErrorDetails::with_error_info(
            "CONFIG_OPERATION_INVALID",
            rpc_error::ERROR_DOMAIN,
            HashMap::new(),
        ),
    )
}

fn persisted_time(receipt: &ProviderMutationReceipt) -> Result<prost_types::Timestamp, Status> {
    // Receipt identity includes the full canonical timestamp. Absence is not
    // the Unix epoch, and reducing nanos to milliseconds would merge identities.
    let timestamp = receipt.persisted_time.ok_or_else(invalid_record)?;
    openshell_core::time::validate_timestamp(&timestamp).map_err(|_| invalid_record())?;
    Ok(timestamp)
}

fn observation_id(
    receipt: &ProviderMutationReceipt,
    snapshot_reason: ProviderReadinessReason,
) -> Result<String, Status> {
    let desired = receipt.desired.as_ref().ok_or_else(invalid_record)?;
    let mut digest = Sha256::new();
    digest.update(b"openshell/provider-observation/v1\0");
    let target_bytes = desired.encode_to_vec();
    // The target contains only public identity and opaque revision fields. Its
    // protobuf has no maps, so encoding is canonical. Length framing prevents
    // component concatenation ambiguities across workspaces and provider names.
    for component in [
        receipt.workspace.as_bytes(),
        receipt.provider_name.as_bytes(),
        target_bytes.as_slice(),
    ] {
        let length = u64::try_from(component.len()).map_err(|_| invalid_record())?;
        digest.update(length.to_be_bytes());
        digest.update(component);
    }
    // A failed capture and its later successful repair are different targets;
    // the original failed operation must remain immutable.
    digest.update((snapshot_reason as i32).to_be_bytes());
    let mut bytes = [0_u8; 16];
    for (byte, hashed) in bytes.iter_mut().zip(digest.finalize()) {
        *byte = hashed;
    }
    Ok(uuid::Builder::from_custom_bytes(bytes)
        .into_uuid()
        .to_string())
}

/// Record an exact provider target in the shared configuration-operation store.
///
/// The caller captures the snapshot only after its provider mutation finishes.
/// This write does not roll back a preceding mutation on failure. An incomplete
/// snapshot is persisted as failed, retaining its original non-secret reason.
/// Observation-only requests reuse the original receipt for the same complete
/// target; source mutations retain their distinct caller-created receipt IDs.
pub async fn record_provider_operation(
    store: &Store,
    mut receipt: ProviderMutationReceipt,
    snapshot_reason: ProviderReadinessReason,
) -> Result<ProviderMutationReceipt, Status> {
    let observation = receipt.kind == ProviderMutationKind::Observe as i32;
    if observation {
        receipt.receipt_id = observation_id(&receipt, snapshot_reason)?;
    }
    let desired = receipt.desired.as_ref().ok_or_else(invalid_record)?;
    if receipt.receipt_id.is_empty()
        || receipt.workspace.is_empty()
        || desired.sandbox_id.is_empty()
    {
        return Err(invalid_record());
    }
    let persisted_time = persisted_time(&receipt)?;
    let failed = snapshot_reason != ProviderReadinessReason::Unspecified;
    let operation = ConfigUpdateOperation {
        operation_id: receipt.receipt_id.clone(),
        sandbox_id: desired.sandbox_id.clone(),
        component: ConfigComponent::ProviderEnvironment.into(),
        target_revision: Some(ConfigSnapshotRevision {
            component: Some(config_snapshot_revision::Component::ProviderTarget(
                desired.clone(),
            )),
        }),
        state: if failed {
            ConfigUpdateOperationState::Failed.into()
        } else {
            ConfigUpdateOperationState::Pending.into()
        },
        outcome: if failed {
            ConfigApplyOutcome::FailedClosed.into()
        } else {
            ConfigApplyOutcome::Unspecified.into()
        },
        sanitized_error: if failed {
            snapshot_reason.as_str_name().to_string()
        } else {
            String::new()
        },
        created_time: Some(persisted_time),
        updated_time: Some(persisted_time),
        completed_time: failed.then_some(persisted_time),
    };
    let stored = StoredConfigUpdateOperation {
        metadata: Some(ObjectMeta {
            id: receipt.receipt_id.clone(),
            name: receipt.receipt_id.clone(),
            workspace: receipt.workspace.clone(),
            created_time: Some(persisted_time),
            ..Default::default()
        }),
        operation: Some(operation),
        provider_receipt: Some(receipt.clone()),
        provider_snapshot_reason: snapshot_reason.into(),
        ..Default::default()
    };
    let result = store
        .put_if(
            CONFIG_UPDATE_OPERATION_OBJECT_TYPE,
            &receipt.receipt_id,
            &receipt.receipt_id,
            &receipt.workspace,
            &stored.encode_to_vec(),
            None,
            WriteCondition::MustCreate,
        )
        .await;
    match result {
        Ok(_) => Ok(receipt),
        Err(PersistenceError::UniqueViolation { .. }) if observation => {
            // Concurrent observers race only on the insert. A conflict never
            // updates the winner's timestamp, mutation identity, or outcome.
            // Exact comparison also fails closed on an ID collision/corruption.
            let existing =
                get_provider_operation(store, &receipt.receipt_id, &receipt.workspace).await?;
            if existing.receipt.kind != receipt.kind
                || existing.receipt.provider_name != receipt.provider_name
                || existing.receipt.desired != receipt.desired
                || existing.snapshot_reason != snapshot_reason
            {
                return Err(invalid_record());
            }
            Ok(existing.receipt)
        }
        Err(_) => Err(storage_unavailable()),
    }
}

// The record ID, receipt ID, and operation ID deliberately name the same
// durable identity; their distinct schema field names must compare equal.
#[allow(clippy::suspicious_operation_groupings)]
fn decode_provider_operation(
    record: &ObjectRecord,
) -> Result<(StoredConfigUpdateOperation, ProviderOperation), Status> {
    let stored = StoredConfigUpdateOperation::decode(record.payload.as_slice())
        .map_err(|_| invalid_record())?;
    let receipt = stored
        .provider_receipt
        .as_ref()
        .ok_or_else(invalid_record)?;
    let operation = stored.operation.as_ref().ok_or_else(invalid_record)?;
    let metadata = stored.metadata.as_ref().ok_or_else(invalid_record)?;
    let desired = receipt.desired.as_ref().ok_or_else(invalid_record)?;
    let persisted_time = persisted_time(receipt)?;
    let snapshot_reason = ProviderReadinessReason::try_from(stored.provider_snapshot_reason)
        .map_err(|_| invalid_record())?;
    if record.id != receipt.receipt_id
        || record.workspace != receipt.workspace
        || metadata.id != record.id
        || metadata.workspace != record.workspace
        || operation.operation_id != record.id
        || operation.sandbox_id != desired.sandbox_id
        || operation.created_time != Some(persisted_time)
        || metadata.created_time != Some(persisted_time)
        || operation.component != ConfigComponent::ProviderEnvironment as i32
        || operation
            .target_revision
            .as_ref()
            .and_then(|revision| revision.component.as_ref())
            != Some(&config_snapshot_revision::Component::ProviderTarget(
                desired.clone(),
            ))
        || ConfigUpdateOperationState::try_from(operation.state).is_err()
    {
        return Err(invalid_record());
    }
    let provider = ProviderOperation {
        receipt: receipt.clone(),
        snapshot_reason,
        operation: operation.clone(),
    };
    Ok((stored, provider))
}

async fn load_provider_operation(
    store: &Store,
    operation_id: &str,
    workspace: &str,
) -> Result<(ObjectRecord, StoredConfigUpdateOperation, ProviderOperation), Status> {
    let record = store
        .get(CONFIG_UPDATE_OPERATION_OBJECT_TYPE, operation_id)
        .await
        .map_err(|_| storage_unavailable())?
        .filter(|record| record.workspace == workspace)
        .ok_or_else(|| Status::not_found("provider operation not found"))?;
    let (stored, provider) = decode_provider_operation(&record)?;
    Ok((record, stored, provider))
}

/// Read a provider projection after the RPC has authorized the workspace.
///
/// Looking up an operation from a different workspace returns the same result
/// as a missing operation and never reveals its receipt or desired target.
pub async fn get_provider_operation(
    store: &Store,
    operation_id: &str,
    workspace: &str,
) -> Result<ProviderOperation, Status> {
    let (_, _, provider) = load_provider_operation(store, operation_id, workspace).await?;
    Ok(provider)
}

fn terminal(state: ConfigUpdateOperationState) -> bool {
    matches!(
        state,
        ConfigUpdateOperationState::Applied
            | ConfigUpdateOperationState::Inactive
            | ConfigUpdateOperationState::Failed
            | ConfigUpdateOperationState::Superseded
            | ConfigUpdateOperationState::Cancelled
    )
}

fn completion(
    status: &ProviderReadinessStatus,
) -> Result<Option<(ConfigUpdateOperationState, ConfigApplyOutcome)>, Status> {
    match ProviderReadinessState::try_from(status.state).map_err(|_| invalid_record())? {
        ProviderReadinessState::Ready | ProviderReadinessState::Revoked => {
            let desired = status
                .receipt
                .as_ref()
                .and_then(|receipt| receipt.desired.as_ref())
                .ok_or_else(invalid_record)?;
            let observed = status.observed.as_ref().ok_or_else(invalid_record)?;
            // The RPC validates current session ownership and freshness. Check
            // the complete target again before converting its result into a
            // durable terminal transition; a partial install is never applied.
            if status.reason != ProviderReadinessReason::Unspecified as i32
                || observed.reason != ProviderReadinessReason::Unspecified as i32
                || observed.attachment_epoch != desired.attachment_epoch
                || observed.provider_env_revision != desired.provider_env_revision
                || observed.config_revision != desired.config_revision
                || observed.policy_hash != desired.policy_hash
                || !observed.credentials_installed
                || !observed.policy_active
                || !observed.launch_environment_installed
                || observed.process_instance_id.is_empty()
                || observed.session_id.is_empty()
                || status.network_instance_id.is_empty()
                || (status.state == ProviderReadinessState::Revoked as i32)
                    != desired.provider_id.is_empty()
            {
                return Err(invalid_record());
            }
            Ok(Some((
                ConfigUpdateOperationState::Applied,
                ConfigApplyOutcome::Applied,
            )))
        }
        ProviderReadinessState::Superseded => Ok(Some((
            ConfigUpdateOperationState::Superseded,
            ConfigApplyOutcome::IgnoredStale,
        ))),
        // Live installation failures can recover without changing the desired
        // revision. They remain visible in the provider projection but do not
        // terminate the operation or authorize a retry of the source mutation.
        _ => Ok(None),
    }
}

/// Persist exact completion by CAS and attach its historical resource to a view.
///
/// Call only after evaluating authenticated current-session evidence. The live
/// status is never changed by this function: expired or superseded evidence
/// cannot become ready because an earlier observation was durably applied.
pub async fn observe_provider_status(
    store: &Store,
    status: &mut ProviderReadinessStatus,
) -> Result<(), Status> {
    let receipt = status.receipt.as_ref().ok_or_else(invalid_record)?.clone();
    let completion = completion(status)?;
    for _ in 0..MAX_TRANSITION_RETRIES {
        let (record, mut stored, provider) =
            load_provider_operation(store, &receipt.receipt_id, &receipt.workspace).await?;
        if provider.receipt != receipt {
            return Err(invalid_record());
        }
        let state = ConfigUpdateOperationState::try_from(provider.operation.state)
            .map_err(|_| invalid_record())?;
        let Some((terminal_state, outcome)) = completion.filter(|_| !terminal(state)) else {
            status.operation = Some(provider.operation);
            return Ok(());
        };
        // Capturing the desired snapshot failed permanently for this operation.
        // A later read must not fabricate a different, successful target.
        if provider.snapshot_reason != ProviderReadinessReason::Unspecified {
            return Err(invalid_record());
        }
        let operation = stored.operation.as_mut().ok_or_else(invalid_record)?;
        operation.state = terminal_state.into();
        operation.outcome = outcome.into();
        operation.sanitized_error = if terminal_state == ConfigUpdateOperationState::Superseded {
            ProviderReadinessReason::DesiredStateChanged
                .as_str_name()
                .to_string()
        } else {
            String::new()
        };
        let completed_time =
            openshell_core::time::timestamp_from_system_time(std::time::SystemTime::now())
                .map_err(|error| {
                    Status::internal(format!("create operation completion timestamp: {error}"))
                })?;
        operation.updated_time = Some(completed_time);
        operation.completed_time = Some(completed_time);
        let result = store
            .put_if(
                CONFIG_UPDATE_OPERATION_OBJECT_TYPE,
                &record.id,
                &record.name,
                &record.workspace,
                &stored.encode_to_vec(),
                record.labels.as_deref(),
                WriteCondition::MatchResourceVersion(record.resource_version),
            )
            .await;
        match result {
            Ok(_) => {
                status.operation = stored.operation;
                return Ok(());
            }
            // A competing observer may have completed this operation. Reload
            // the authoritative row; a terminal outcome is immutable.
            Err(PersistenceError::Conflict { .. }) => {}
            Err(_) => return Err(storage_unavailable()),
        }
    }
    Err(rpc_error::resource_version_conflict(
        "configuration operation changed concurrently; query its status again",
        None,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{
        ProviderDesiredIdentity, ProviderMutationKind, ProviderReadinessObservation,
    };
    use uuid::Uuid;

    fn receipt() -> ProviderMutationReceipt {
        ProviderMutationReceipt {
            receipt_id: Uuid::new_v4().to_string(),
            mutation_id: Uuid::new_v4().to_string(),
            provider_name: "provider".to_string(),
            workspace: "default".to_string(),
            kind: ProviderMutationKind::Update.into(),
            desired: Some(ProviderDesiredIdentity {
                sandbox_id: Uuid::new_v4().to_string(),
                sandbox: "sandbox".to_string(),
                attachment_epoch: Uuid::new_v4().to_string(),
                provider_id: Uuid::new_v4().to_string(),
                provider_resource_version: 3,
                provider_env_revision: 5,
                config_revision: 7,
                policy_hash: "policy".to_string(),
            }),
            persisted_time: Some(prost_types::Timestamp {
                seconds: 1_700_000_000,
                nanos: 123_456_789,
            }),
        }
    }

    fn ready(receipt: &ProviderMutationReceipt) -> ProviderReadinessStatus {
        let desired = receipt.desired.as_ref().unwrap();
        ProviderReadinessStatus {
            receipt: Some(receipt.clone()),
            state: ProviderReadinessState::Ready.into(),
            network_instance_id: Uuid::new_v4().to_string(),
            observed: Some(ProviderReadinessObservation {
                session_id: Uuid::new_v4().to_string(),
                sequence: 1,
                attachment_epoch: desired.attachment_epoch.clone(),
                provider_env_revision: desired.provider_env_revision,
                config_revision: desired.config_revision,
                policy_hash: desired.policy_hash.clone(),
                credentials_installed: true,
                policy_active: true,
                launch_environment_installed: true,
                process_instance_id: Uuid::new_v4().to_string(),
                reason: ProviderReadinessReason::Unspecified.into(),
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn provider_receipt_uses_the_common_operation_namespace_and_exact_target() {
        let store = crate::persistence::test_store().await;
        let receipt = receipt();
        record_provider_operation(
            &store,
            receipt.clone(),
            ProviderReadinessReason::Unspecified,
        )
        .await
        .unwrap();
        let operation = get_provider_operation(&store, &receipt.receipt_id, "default")
            .await
            .unwrap();
        assert_eq!(operation.receipt, receipt);
        assert_eq!(operation.operation.operation_id, receipt.receipt_id);
        assert_eq!(operation.operation.created_time, receipt.persisted_time);
        assert_eq!(operation.operation.updated_time, receipt.persisted_time);
        assert!(operation.operation.completed_time.is_none());
        assert_eq!(
            operation.operation.state,
            ConfigUpdateOperationState::Pending as i32
        );
        assert!(
            store
                .get("provider_mutation_receipt", &receipt.receipt_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            get_provider_operation(&store, &receipt.receipt_id, "other")
                .await
                .unwrap_err()
                .code(),
            Code::NotFound
        );
    }

    #[tokio::test]
    async fn incomplete_provider_target_stays_failed_after_later_installation() {
        let store = crate::persistence::test_store().await;
        let receipt = receipt();
        record_provider_operation(
            &store,
            receipt.clone(),
            ProviderReadinessReason::SnapshotMismatch,
        )
        .await
        .unwrap();
        let mut status = ready(&receipt);
        observe_provider_status(&store, &mut status).await.unwrap();
        let operation = status.operation.unwrap();
        assert_eq!(operation.state, ConfigUpdateOperationState::Failed as i32);
        assert_eq!(operation.completed_time, receipt.persisted_time);
    }

    #[tokio::test]
    async fn receipt_timestamp_requires_presence_and_canonical_nanos() {
        let store = crate::persistence::test_store().await;
        for invalid_time in [
            None,
            Some(prost_types::Timestamp {
                seconds: 0,
                nanos: -1,
            }),
            Some(prost_types::Timestamp {
                seconds: openshell_core::time::MAX_TIMESTAMP_SECONDS + 1,
                nanos: 0,
            }),
        ] {
            let mut receipt = receipt();
            receipt.persisted_time = invalid_time;
            let error =
                record_provider_operation(&store, receipt, ProviderReadinessReason::Unspecified)
                    .await
                    .unwrap_err();
            assert_eq!(error.code(), Code::Internal);
        }
        assert_eq!(
            store
                .count_in_workspace(CONFIG_UPDATE_OPERATION_OBJECT_TYPE, "default")
                .await
                .unwrap(),
            0
        );

        // The Unix epoch is a valid explicit timestamp, not missing data.
        let mut epoch = receipt();
        epoch.persisted_time = Some(prost_types::Timestamp::default());
        let recorded =
            record_provider_operation(&store, epoch.clone(), ProviderReadinessReason::Unspecified)
                .await
                .unwrap();
        assert_eq!(recorded, epoch);
        assert_eq!(
            get_provider_operation(&store, &epoch.receipt_id, "default")
                .await
                .unwrap()
                .receipt,
            epoch
        );
    }

    #[tokio::test]
    async fn receipt_timestamp_nanos_are_part_of_exact_completion_identity() {
        let store = crate::persistence::test_store().await;
        let receipt = receipt();
        record_provider_operation(
            &store,
            receipt.clone(),
            ProviderReadinessReason::Unspecified,
        )
        .await
        .unwrap();
        let mut changed = ready(&receipt);
        changed
            .receipt
            .as_mut()
            .unwrap()
            .persisted_time
            .as_mut()
            .unwrap()
            .nanos += 1;
        assert_eq!(
            observe_provider_status(&store, &mut changed)
                .await
                .unwrap_err()
                .code(),
            Code::Internal
        );
        let stored = get_provider_operation(&store, &receipt.receipt_id, "default")
            .await
            .unwrap();
        assert_eq!(stored.receipt, receipt);
        assert_eq!(
            stored.operation.state,
            ConfigUpdateOperationState::Pending as i32
        );
        assert!(stored.operation.completed_time.is_none());

        let mut exact = ready(&receipt);
        observe_provider_status(&store, &mut exact).await.unwrap();
        let completed = exact.operation.unwrap();
        assert_eq!(completed.created_time, receipt.persisted_time);
        assert!(completed.completed_time.is_some());
        assert_eq!(completed.updated_time, completed.completed_time);
        openshell_core::time::validate_timestamp(completed.completed_time.as_ref().unwrap())
            .unwrap();
    }

    #[tokio::test]
    async fn stale_or_partial_provider_evidence_cannot_complete_an_operation() {
        let store = crate::persistence::test_store().await;
        let receipt = receipt();
        record_provider_operation(
            &store,
            receipt.clone(),
            ProviderReadinessReason::Unspecified,
        )
        .await
        .unwrap();
        let mut stale = ready(&receipt);
        stale.observed.as_mut().unwrap().config_revision += 1;
        assert!(observe_provider_status(&store, &mut stale).await.is_err());
        let mut partial = ready(&receipt);
        partial
            .observed
            .as_mut()
            .unwrap()
            .launch_environment_installed = false;
        assert!(observe_provider_status(&store, &mut partial).await.is_err());
        assert_eq!(
            get_provider_operation(&store, &receipt.receipt_id, "default")
                .await
                .unwrap()
                .operation
                .state,
            ConfigUpdateOperationState::Pending as i32
        );
    }

    #[tokio::test]
    async fn applied_history_never_upgrades_an_expired_live_view() {
        let store = crate::persistence::test_store().await;
        let receipt = receipt();
        record_provider_operation(
            &store,
            receipt.clone(),
            ProviderReadinessReason::Unspecified,
        )
        .await
        .unwrap();
        let mut status = ready(&receipt);
        observe_provider_status(&store, &mut status).await.unwrap();
        let before = store
            .get(CONFIG_UPDATE_OPERATION_OBJECT_TYPE, &receipt.receipt_id)
            .await
            .unwrap()
            .unwrap();
        status.state = ProviderReadinessState::Pending.into();
        status.reason = ProviderReadinessReason::SupervisorLeaseExpired.into();
        observe_provider_status(&store, &mut status).await.unwrap();
        assert_eq!(status.state, ProviderReadinessState::Pending as i32);
        assert_eq!(
            status.operation.unwrap().state,
            ConfigUpdateOperationState::Applied as i32
        );
        let after = store
            .get(CONFIG_UPDATE_OPERATION_OBJECT_TYPE, &receipt.receipt_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(before.resource_version, after.resource_version);
    }

    #[tokio::test]
    async fn competing_terminal_observers_preserve_the_first_committed_outcome() {
        let store = crate::persistence::test_store().await;
        let receipt = receipt();
        record_provider_operation(
            &store,
            receipt.clone(),
            ProviderReadinessReason::Unspecified,
        )
        .await
        .unwrap();
        let mut applied = ready(&receipt);
        let mut superseded = applied.clone();
        superseded.state = ProviderReadinessState::Superseded.into();
        superseded.reason = ProviderReadinessReason::DesiredStateChanged.into();
        let (first, second) = tokio::join!(
            observe_provider_status(&store, &mut applied),
            observe_provider_status(&store, &mut superseded),
        );
        first.unwrap();
        second.unwrap();
        assert_eq!(applied.operation, superseded.operation);
        let stored = get_provider_operation(&store, &receipt.receipt_id, "default")
            .await
            .unwrap();
        assert!(matches!(
            ConfigUpdateOperationState::try_from(stored.operation.state).unwrap(),
            ConfigUpdateOperationState::Applied | ConfigUpdateOperationState::Superseded
        ));
    }

    #[tokio::test]
    async fn failed_observation_and_recovered_snapshot_have_distinct_immutable_receipts() {
        let store = crate::persistence::test_store().await;
        let mut observed = receipt();
        observed.kind = ProviderMutationKind::Observe.into();
        let failed = record_provider_operation(
            &store,
            observed.clone(),
            ProviderReadinessReason::CredentialsWithheld,
        )
        .await
        .unwrap();
        observed.mutation_id = Uuid::new_v4().to_string();
        observed.persisted_time.as_mut().unwrap().nanos += 1;
        let repeated = record_provider_operation(
            &store,
            observed.clone(),
            ProviderReadinessReason::CredentialsWithheld,
        )
        .await
        .unwrap();
        assert_eq!(repeated, failed);
        let repaired =
            record_provider_operation(&store, observed, ProviderReadinessReason::Unspecified)
                .await
                .unwrap();
        assert_ne!(repaired.receipt_id, failed.receipt_id);
        assert_eq!(
            get_provider_operation(&store, &failed.receipt_id, "default")
                .await
                .unwrap()
                .operation
                .state,
            ConfigUpdateOperationState::Failed as i32
        );
        assert_eq!(
            store
                .count_in_workspace(CONFIG_UPDATE_OPERATION_OBJECT_TYPE, "default")
                .await
                .unwrap(),
            2
        );
    }
}
