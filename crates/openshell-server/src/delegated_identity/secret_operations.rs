// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Non-secret write-ahead ownership for delegated credential material.
//! Publication and the operation receipt commit together. Cleanup first fences
//! publication, then deletes every prepared handle, including unknown outcomes.

use super::delegated_secret_scope;
use crate::ServerState;
use crate::pagination::MAX_PAGE_SIZE;
use crate::persistence::{
    AtomicObjectWrite, ObjectListQuery, ObjectRecord, PersistenceError, current_time_ms,
};
use openshell_core::proto::CredentialHandle;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tonic::Status;

const OBJECT_TYPE: &str = "delegated_secret_operation";
const HANDLE_OPERATION: &str = "openshell.secret_operation";
const STAGING_LIFETIME_MS: i64 = 300_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    Writing,
    Ready,
    Committed,
    Cleanup,
    // A backend can complete a timed-out write after deletion succeeds. Keep
    // these identities and repeat deletion instead of losing recovery coverage.
    UncertainCleanup,
}

#[derive(Serialize, Deserialize)]
struct Operation {
    format_version: u32,
    credential_id: String,
    expires_at_ms: i64,
    phase: Phase,
    // Encoded opaque handles only, never token values.
    handles: HashMap<String, Vec<u8>>,
}

impl Operation {
    fn decode(record: &ObjectRecord) -> Result<Self, Status> {
        let operation: Self = serde_json::from_slice(&record.payload)
            .map_err(|_| Status::data_loss("invalid secret operation"))?;
        if operation.format_version != 1 {
            return Err(Status::failed_precondition(
                "unknown secret operation format",
            ));
        }
        Ok(operation)
    }

    fn write(&self, id: &str, expected_version: Option<u64>) -> Result<AtomicObjectWrite, Status> {
        Ok(AtomicObjectWrite {
            object_type: OBJECT_TYPE.into(),
            id: id.into(),
            name: id.into(),
            workspace: String::new(),
            scope: Some(self.credential_id.clone()),
            payload: serde_json::to_vec(self)
                .map_err(|_| Status::internal("encode secret operation"))?,
            labels: None,
            expected_version,
        })
    }

    fn handles(&self) -> Result<HashMap<String, CredentialHandle>, Status> {
        self.handles
            .iter()
            .map(|(key, bytes)| {
                CredentialHandle::decode(bytes.as_slice())
                    .map(|handle| (key.clone(), handle))
                    .map_err(|_| Status::data_loss("invalid prepared secret handle"))
            })
            .collect()
    }
}

fn persistence(error: PersistenceError) -> Status {
    crate::grpc::persistence_error_to_status(error, "persist secret operation")
}

async fn load(state: &Arc<ServerState>, id: &str) -> Result<ObjectRecord, Status> {
    state
        .store
        .get(OBJECT_TYPE, id)
        .await
        .map_err(persistence)?
        .ok_or_else(|| Status::aborted("secret operation no longer exists"))
}

fn operation_id(handles: &HashMap<String, CredentialHandle>) -> Result<&str, Status> {
    let id = handles
        .values()
        .next()
        .and_then(|handle| handle.metadata.get(HANDLE_OPERATION))
        .ok_or_else(|| Status::internal("secret handles lack an operation identity"))?;
    if handles
        .values()
        .any(|handle| handle.metadata.get(HANDLE_OPERATION) != Some(id))
    {
        return Err(Status::internal(
            "secret handles belong to different operations",
        ));
    }
    Ok(id)
}

pub(super) async fn stage(
    state: &Arc<ServerState>,
    credential_id: &str,
    material: &HashMap<String, String>,
) -> Result<HashMap<String, CredentialHandle>, Status> {
    let id = format!("delegated-secret-operation-{}", uuid::Uuid::new_v4());
    let mut handles = state
        .credentials
        .prepare_secret_material(delegated_secret_scope(credential_id), &id, material.keys())
        .await?;
    for handle in handles.values_mut() {
        handle.metadata.insert(HANDLE_OPERATION.into(), id.clone());
    }
    let mut operation = Operation {
        format_version: 1,
        credential_id: credential_id.into(),
        expires_at_ms: current_time_ms() + STAGING_LIFETIME_MS,
        phase: Phase::Writing,
        handles: handles
            .iter()
            .map(|(key, handle)| (key.clone(), handle.encode_to_vec()))
            .collect(),
    };
    state
        .store
        .put_objects_atomic(&[operation.write(&id, None)?])
        .await
        .map_err(persistence)?;
    let result = state
        .credentials
        .store_prepared_secret_material(
            delegated_secret_scope(credential_id),
            &id,
            material,
            &handles,
        )
        .await;
    if let Err(error) = result {
        abort(state, &handles).await;
        return Err(error);
    }
    operation.phase = Phase::Ready;
    if let Err(error) = state
        .store
        .put_objects_atomic(&[operation.write(&id, Some(1))?])
        .await
    {
        // Recovery may have fenced an expired writer while storage was slow.
        abort(state, &handles).await;
        return Err(persistence(error));
    }
    Ok(handles)
}

/// Include this write in the same transaction as credential publication.
pub(super) async fn publication(
    state: &Arc<ServerState>,
    handles: &HashMap<String, CredentialHandle>,
) -> Result<AtomicObjectWrite, Status> {
    let id = operation_id(handles)?;
    let record = load(state, id).await?;
    let mut operation = Operation::decode(&record)?;
    if operation.phase != Phase::Ready || operation.expires_at_ms <= current_time_ms() {
        return Err(Status::aborted(
            "secret operation expired or entered cleanup",
        ));
    }
    operation.phase = Phase::Committed;
    operation.write(id, Some(record.resource_version))
}

pub(super) async fn abort(state: &Arc<ServerState>, handles: &HashMap<String, CredentialHandle>) {
    let result = async {
        let id = operation_id(handles)?;
        cleanup(state, load(state, id).await?, true).await
    }
    .await;
    if let Err(error) = result {
        tracing::warn!(error = %error, "staged secret cleanup deferred to durable recovery");
    }
}

async fn cleanup(
    state: &Arc<ServerState>,
    record: ObjectRecord,
    force: bool,
) -> Result<(), Status> {
    let mut operation = Operation::decode(&record)?;
    let mut version = record.resource_version;
    match operation.phase {
        Phase::Committed => {
            // The credential owns these handles now. Never delete its material.
            state
                .store
                .delete_if(OBJECT_TYPE, &record.id, version)
                .await
                .map_err(persistence)?;
            return Ok(());
        }
        Phase::Writing | Phase::Ready => {
            if !force && operation.expires_at_ms > current_time_ms() {
                return Ok(());
            }
            operation.phase = if operation.phase == Phase::Writing {
                Phase::UncertainCleanup
            } else {
                Phase::Cleanup
            };
            state
                .store
                .put_objects_atomic(&[operation.write(&record.id, Some(version))?])
                .await
                .map_err(persistence)?;
            version += 1;
        }
        Phase::Cleanup | Phase::UncertainCleanup => {}
    }
    state
        .credentials
        .delete_secret_material_handles(
            delegated_secret_scope(&operation.credential_id),
            &operation.handles()?,
        )
        .await?;
    if operation.phase == Phase::Cleanup {
        state
            .store
            .delete_if(OBJECT_TYPE, &record.id, version)
            .await
            .map_err(persistence)?;
    }
    Ok(())
}

pub(super) async fn tick(state: &Arc<ServerState>) -> Result<(), Status> {
    let mut cursor = None;
    loop {
        let page = state
            .store
            .list_object_page(
                OBJECT_TYPE,
                ObjectListQuery::AllWorkspaces,
                cursor.as_ref(),
                MAX_PAGE_SIZE,
            )
            .await
            .map_err(persistence)?;
        for record in page.records {
            if let Err(error) = cleanup(state, record, false).await {
                tracing::warn!(error = %error, "secret operation recovery will retry");
            }
        }
        let Some(next) = page.next_cursor else {
            return Ok(());
        };
        cursor = Some(next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::test_support::test_server_state;
    use crate::storage_proto::DelegatedIdentityCredential;
    use openshell_core::proto::datamodel::v1::ObjectMeta;

    fn material() -> HashMap<String, String> {
        HashMap::from([
            ("access_token".into(), "access-secret".into()),
            ("refresh_token".into(), "refresh-secret".into()),
        ])
    }

    async fn operations(state: &Arc<ServerState>) -> Vec<ObjectRecord> {
        state.store.list_by_type(OBJECT_TYPE, 100, 0).await.unwrap()
    }

    async fn expire(state: &Arc<ServerState>, record: &ObjectRecord) {
        let mut operation = Operation::decode(record).unwrap();
        operation.expires_at_ms = 1;
        state
            .store
            .put_objects_atomic(&[operation
                .write(&record.id, Some(record.resource_version))
                .unwrap()])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn partial_first_grant_survives_failed_cleanup_without_parent() {
        let state = test_server_state().await;
        state.credentials.fail_next_store();
        state.credentials.fail_next_delete();
        stage(&state, "absent-parent", &material())
            .await
            .unwrap_err();
        // The injected deletion failure can hit either the successful write
        // or the handle whose write failed. Retain both prepared identities.
        let records = operations(&state).await;
        assert_eq!(records.len(), 1);
        assert_eq!(Operation::decode(&records[0]).unwrap().handles.len(), 2);
        assert!(!String::from_utf8_lossy(&records[0].payload).contains("refresh-secret"));
        assert_eq!(
            Operation::decode(&records[0]).unwrap().phase,
            Phase::UncertainCleanup
        );
        tick(&state).await.unwrap();
        assert_eq!(state.credentials.stored_credential_count(), Some(0));

        // An unknown backend write can arrive even after a successful delete.
        let operation = Operation::decode(&records[0]).unwrap();
        state
            .credentials
            .store_prepared_secret_material(
                delegated_secret_scope("absent-parent"),
                &records[0].id,
                &material(),
                &operation.handles().unwrap(),
            )
            .await
            .unwrap();
        tick(&state).await.unwrap();
        assert_eq!(state.credentials.stored_credential_count(), Some(0));
    }

    #[tokio::test]
    async fn cancelled_partial_write_is_recovered_from_durable_handles() {
        let state = test_server_state().await;
        let (hit, release) = state.credentials.gate_next_store();
        let worker_state = state.clone();
        let task =
            tokio::spawn(async move { stage(&worker_state, "absent-parent", &material()).await });
        hit.await.unwrap();
        assert_eq!(state.credentials.stored_credential_count(), Some(1));
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        drop(release);
        let records = operations(&state).await;
        expire(&state, &records[0]).await;
        // This worker uses only storage, with no access to the cancelled task.
        tick(&state).await.unwrap();
        assert_eq!(state.credentials.stored_credential_count(), Some(0));
    }

    #[tokio::test]
    async fn cleanup_fences_a_prepared_publication_transaction() {
        let state = test_server_state().await;
        let handles = stage(&state, "parent", &material()).await.unwrap();
        let publication = publication(&state, &handles).await.unwrap();
        abort(&state, &handles).await;
        let credential = DelegatedIdentityCredential {
            metadata: Some(ObjectMeta {
                id: "parent".into(),
                name: "parent".into(),
                ..Default::default()
            }),
            secret_material_handles: handles,
            ..Default::default()
        };
        let write = AtomicObjectWrite::message(&credential, None).unwrap();
        assert!(
            state
                .store
                .put_objects_atomic(&[write, publication])
                .await
                .is_err()
        );
        assert!(
            state
                .store
                .get_message::<DelegatedIdentityCredential>("parent")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(state.credentials.stored_credential_count(), Some(0));
    }

    #[tokio::test]
    async fn committed_material_survives_recovery_and_late_abort() {
        let state = test_server_state().await;
        let handles = stage(&state, "parent", &material()).await.unwrap();
        let credential = DelegatedIdentityCredential {
            metadata: Some(ObjectMeta {
                id: "parent".into(),
                name: "parent".into(),
                ..Default::default()
            }),
            secret_material_handles: handles.clone(),
            ..Default::default()
        };
        state
            .store
            .put_objects_atomic(&[
                AtomicObjectWrite::message(&credential, None).unwrap(),
                publication(&state, &handles).await.unwrap(),
            ])
            .await
            .unwrap();
        abort(&state, &handles).await;
        tick(&state).await.unwrap();
        assert_eq!(state.credentials.stored_credential_count(), Some(2));
        assert!(operations(&state).await.is_empty());
    }

    #[tokio::test]
    async fn abandoned_material_is_recovered_after_database_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", directory.path().join("gateway.db").display());
        let mut state = test_server_state().await;
        Arc::get_mut(&mut state).unwrap().store =
            Arc::new(crate::persistence::Store::connect(&url).await.unwrap());
        stage(&state, "absent-parent", &material()).await.unwrap();
        expire(&state, &operations(&state).await[0]).await;
        // The fake external credential backend outlives the gateway, as Vault
        // or Kubernetes Secrets would. The operation must come from the DB.
        let credentials = state.credentials.clone();
        state.store.close_for_test().await;
        drop(state);
        let mut restarted = test_server_state().await;
        let server = Arc::get_mut(&mut restarted).unwrap();
        server.store = Arc::new(crate::persistence::Store::connect(&url).await.unwrap());
        server.credentials = credentials;
        tick(&restarted).await.unwrap();
        assert_eq!(restarted.credentials.stored_credential_count(), Some(0));
        assert!(operations(&restarted).await.is_empty());
    }

    #[tokio::test]
    async fn successful_unpublished_write_is_recovered_after_expiry() {
        let state = test_server_state().await;
        stage(&state, "absent-parent", &material()).await.unwrap();
        let records = operations(&state).await;
        tick(&state).await.unwrap();
        assert_eq!(state.credentials.stored_credential_count(), Some(2));
        expire(&state, &records[0]).await;
        tick(&state).await.unwrap();
        assert_eq!(state.credentials.stored_credential_count(), Some(0));
        assert!(operations(&state).await.is_empty());
    }
}
