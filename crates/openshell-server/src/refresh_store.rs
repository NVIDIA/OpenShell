// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Field-preserving adaptation of issuer refresh state to gateway persistence.
use crate::persistence::{ObjectListQuery, ObjectType, PersistenceError, Store, WriteCondition};
use crate::storage_proto::{
    StoredProviderCredentialRefreshStateV2 as StoredProviderCredentialRefreshState,
    StoredRefreshMaterialDeletion,
};
use async_trait::async_trait;
use openshell_core::{ObjectId, ObjectName, ObjectWorkspace};
use openshell_credential_issuer::RefreshMaterialDeletion;
use openshell_credential_issuer::refresh::{
    RefreshLease, RefreshState, RefreshStateStore, refresh_state_name,
};
use prost::Message;
use std::sync::Arc;
use tonic::Status;

impl ObjectType for StoredProviderCredentialRefreshState {
    fn object_type() -> &'static str {
        "provider_credential_refresh_state"
    }
}

#[cfg(test)]
pub async fn put_refresh_state(
    store: &Store,
    state: &StoredProviderCredentialRefreshState,
) -> Result<(), Status> {
    store
        .put_scoped_message(state, &state.provider_id)
        .await
        .map_err(|e| Status::internal(format!("persist provider refresh state failed: {e}")))
}

/// Atomically claim a new provider-and-credential refresh identity.
///
/// The refresh name is unique within a workspace. A concurrent creator must
/// lose instead of overwriting the winner so its caller can delete any secret
/// material staged before this write.
pub async fn create_refresh_state(
    store: &Store,
    state: &StoredProviderCredentialRefreshState,
) -> Result<(), Status> {
    match store
        .create_scoped(
            StoredProviderCredentialRefreshState::object_type(),
            state.object_id(),
            state.object_name(),
            state.object_workspace(),
            &state.provider_id,
            &state.encode_to_vec(),
            None,
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(PersistenceError::UniqueViolation { .. }) => Err(Status::aborted(
            "provider refresh was concurrently configured",
        )),
        Err(err) => Err(Status::internal(format!(
            "create provider refresh state failed: {err}"
        ))),
    }
}

/// Persist an updated refresh state only if the row still exists with the
/// generation read at the start of the rotation.
///
/// Uses a version-matched UPDATE, which never inserts — so a refresh deleted
/// while an STS (or OAuth) request was in flight is not resurrected, and its
/// stored source-credential material is not recreated (CWE-362). Returns the new
/// resource version when persisted, or `None` when the refresh was deleted or
/// superseded by a concurrent write (in which case nothing was written).
async fn persist_refresh_state_if_current(
    store: &Store,
    state: &StoredProviderCredentialRefreshState,
    expected_version: u64,
) -> Result<Option<u64>, Status> {
    match store
        .put_if(
            StoredProviderCredentialRefreshState::object_type(),
            state.object_id(),
            state.object_name(),
            state.object_workspace(),
            &state.encode_to_vec(),
            None,
            WriteCondition::MatchResourceVersion(expected_version),
        )
        .await
    {
        Ok(result) => Ok(Some(result.resource_version)),
        // The version-matched UPDATE matched no row: the refresh was deleted
        // (current version `None`) or superseded by a concurrent write (a
        // different current version). Either way nothing was written.
        Err(PersistenceError::Conflict { .. }) => Ok(None),
        Err(e) => Err(Status::internal(format!(
            "persist provider refresh state failed: {e}"
        ))),
    }
}

pub async fn list_refresh_states_for_provider(
    store: &Store,
    provider_id: &str,
) -> Result<Vec<StoredProviderCredentialRefreshState>, Status> {
    store
        .collect_messages(ObjectListQuery::Scope(provider_id))
        .await
        .map_err(|e| Status::internal(format!("list provider refresh states failed: {e}")))
}

pub async fn list_all_refresh_states(
    store: &Store,
) -> Result<Vec<StoredProviderCredentialRefreshState>, Status> {
    store
        .collect_messages(ObjectListQuery::AllWorkspaces)
        .await
        .map_err(|e| Status::internal(format!("list provider refresh states failed: {e}")))
}

pub async fn get_refresh_state(
    store: &Store,
    workspace: &str,
    provider_id: &str,
    credential_key: &str,
) -> Result<Option<StoredProviderCredentialRefreshState>, Status> {
    let name = refresh_state_name(provider_id, credential_key);
    store
        .get_message_by_name::<StoredProviderCredentialRefreshState>(workspace, &name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider refresh state failed: {e}")))
}

impl From<&StoredProviderCredentialRefreshState> for RefreshState {
    fn from(state: &StoredProviderCredentialRefreshState) -> Self {
        Self {
            metadata: state.metadata.clone(),
            provider_id: state.provider_id.clone(),
            provider_name: state.provider_name.clone(),
            credential_key: state.credential_key.clone(),
            strategy: state.strategy,
            material: state.material.clone(),
            secret_material_keys: state.secret_material_keys.clone(),
            expires_at_ms: state.expires_at_ms,
            next_refresh_at_ms: state.next_refresh_at_ms,
            last_refresh_at_ms: state.last_refresh_at_ms,
            status: state.status.clone(),
            last_error: state.last_error.clone(),
            token_url: state.token_url.clone(),
            scopes: state.scopes.clone(),
            refresh_before: state.refresh_before,
            max_lifetime: state.max_lifetime,
            additional_output_keys: state.additional_output_keys.clone(),
            authorization_epoch: state.authorization_epoch.clone(),
            secret_material_handles: state.secret_material_handles.clone(),
            pending_secret_deletions: state
                .pending_secret_deletions
                .iter()
                .map(|item| RefreshMaterialDeletion {
                    material_key: item.material_key.clone(),
                    handle: item.handle.clone(),
                })
                .collect(),
            recovery_action: state.recovery_action,
            failure_code: state.failure_code.clone(),
            provider_error_subtype: state.provider_error_subtype.clone(),
            last_error_at_ms: state.last_error_at_ms,
        }
    }
}

impl From<&RefreshState> for StoredProviderCredentialRefreshState {
    fn from(state: &RefreshState) -> Self {
        Self {
            metadata: state.metadata.clone(),
            provider_id: state.provider_id.clone(),
            provider_name: state.provider_name.clone(),
            credential_key: state.credential_key.clone(),
            strategy: state.strategy,
            material: state.material.clone(),
            secret_material_keys: state.secret_material_keys.clone(),
            expires_at_ms: state.expires_at_ms,
            next_refresh_at_ms: state.next_refresh_at_ms,
            last_refresh_at_ms: state.last_refresh_at_ms,
            status: state.status.clone(),
            last_error: state.last_error.clone(),
            token_url: state.token_url.clone(),
            scopes: state.scopes.clone(),
            refresh_before: state.refresh_before,
            max_lifetime: state.max_lifetime,
            additional_output_keys: state.additional_output_keys.clone(),
            authorization_epoch: state.authorization_epoch.clone(),
            secret_material_handles: state.secret_material_handles.clone(),
            pending_secret_deletions: state
                .pending_secret_deletions
                .iter()
                .map(|item| StoredRefreshMaterialDeletion {
                    material_key: item.material_key.clone(),
                    handle: item.handle.clone(),
                })
                .collect(),
            recovery_action: state.recovery_action,
            failure_code: state.failure_code.clone(),
            provider_error_subtype: state.provider_error_subtype.clone(),
            last_error_at_ms: state.last_error_at_ms,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerRefreshStore(pub Arc<Store>);

impl RefreshLease for crate::persistence::RefreshMutationGuard {}

#[async_trait]
impl RefreshStateStore for ServerRefreshStore {
    async fn get(
        &self,
        workspace: &str,
        provider_id: &str,
        key: &str,
    ) -> Result<Option<RefreshState>, Status> {
        Ok(get_refresh_state(&self.0, workspace, provider_id, key)
            .await?
            .as_ref()
            .map(Into::into))
    }
    async fn get_by_id(&self, id: &str) -> Result<Option<RefreshState>, Status> {
        self.0
            .get_message::<StoredProviderCredentialRefreshState>(id)
            .await
            .map(|state| state.as_ref().map(Into::into))
            .map_err(|e| Status::internal(format!("fetch provider refresh state failed: {e}")))
    }
    async fn list(&self, provider_id: Option<&str>) -> Result<Vec<RefreshState>, Status> {
        let states = if let Some(id) = provider_id {
            list_refresh_states_for_provider(&self.0, id).await?
        } else {
            list_all_refresh_states(&self.0).await?
        };
        Ok(states.iter().map(Into::into).collect())
    }
    async fn create(&self, state: &RefreshState) -> Result<(), Status> {
        create_refresh_state(&self.0, &state.into()).await
    }
    async fn replace(&self, state: &RefreshState, version: u64) -> Result<Option<u64>, Status> {
        persist_refresh_state_if_current(&self.0, &state.into(), version).await
    }
    async fn delete(&self, id: &str, version: u64) -> Result<(), Status> {
        self.0
            .delete_if(
                StoredProviderCredentialRefreshState::object_type(),
                id,
                version,
            )
            .await
            .map(|_| ())
            .map_err(|err| match err {
                PersistenceError::Conflict { .. } => {
                    Status::aborted("provider refresh was concurrently modified during deletion")
                }
                other => Status::internal(format!("delete provider refresh state failed: {other}")),
            })
    }
    async fn acquire(&self, provider_id: &str, key: &str) -> Result<Box<dyn RefreshLease>, Status> {
        self.0
            .acquire_refresh_guard(provider_id, key)
            .await
            .map(|guard| -> Box<dyn RefreshLease> { Box::new(guard) })
            .map_err(|_| Status::unavailable("credential refresh coordination unavailable"))
    }
}

#[cfg(test)]
mod tests;
