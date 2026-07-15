// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared supervisor-session ownership index for HA gateway replicas.

use crate::persistence::{PersistenceError, Store, WriteCondition};
use openshell_core::time::now_ms;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

const OWNER_OBJECT_TYPE: &str = "supervisor_session_owner";

pub const OWNER_TTL: Duration = Duration::from_secs(45);

fn owner_object_id(sandbox_id: &str) -> String {
    format!("supervisor-owner:{sandbox_id}")
}

#[derive(Debug, Error)]
pub enum OwnerError {
    #[error("supervisor session is owned by another active gateway replica")]
    AlreadyOwned,
    #[error("supervisor owner record CAS conflict")]
    Conflict,
    #[error("persistence error: {0}")]
    Store(#[from] PersistenceError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OwnerPayload {
    sandbox_id: String,
    session_id: String,
    supervisor_instance_id: String,
    connection_epoch: u64,
    owner_replica_id: String,
    owner_peer_endpoint: String,
    connected_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct OwnerRecord {
    pub session_id: String,
    pub supervisor_instance_id: String,
    pub connection_epoch: u64,
    pub owner_replica_id: String,
    pub owner_peer_endpoint: String,
    #[allow(dead_code)]
    pub connected_at_ms: i64,
    pub updated_at_ms: i64,
    pub resource_version: u64,
}

#[derive(Debug, Clone)]
pub struct OwnerGuard {
    pub sandbox_id: String,
    pub session_id: String,
    pub supervisor_instance_id: String,
    pub connection_epoch: u64,
    pub owner_replica_id: String,
    pub owner_peer_endpoint: String,
    connected_at_ms: i64,
    resource_version: u64,
}

pub struct SupervisorOwnerIndex {
    store: Arc<Store>,
    ttl: Duration,
}

impl SupervisorOwnerIndex {
    pub fn new(store: Arc<Store>, ttl: Duration) -> Self {
        Self { store, ttl }
    }

    pub async fn publish(
        &self,
        sandbox_id: &str,
        session_id: &str,
        supervisor_instance_id: &str,
        connection_epoch: u64,
        owner_replica_id: &str,
        owner_peer_endpoint: &str,
    ) -> Result<OwnerGuard, OwnerError> {
        let connected_at_ms = now_ms();
        let payload = OwnerPayload {
            sandbox_id: sandbox_id.to_string(),
            session_id: session_id.to_string(),
            supervisor_instance_id: supervisor_instance_id.to_string(),
            connection_epoch,
            owner_replica_id: owner_replica_id.to_string(),
            owner_peer_endpoint: owner_peer_endpoint.to_string(),
            connected_at_ms,
        };

        let condition = match self.read(sandbox_id).await? {
            None => WriteCondition::MustCreate,
            Some(existing)
                if can_supersede(
                    &existing,
                    supervisor_instance_id,
                    connection_epoch,
                    self.ttl,
                ) =>
            {
                WriteCondition::MatchResourceVersion(existing.resource_version)
            }
            Some(_) => return Err(OwnerError::AlreadyOwned),
        };

        let result = self.write_payload(sandbox_id, &payload, condition).await?;
        Ok(OwnerGuard {
            sandbox_id: sandbox_id.to_string(),
            session_id: session_id.to_string(),
            supervisor_instance_id: supervisor_instance_id.to_string(),
            connection_epoch,
            owner_replica_id: owner_replica_id.to_string(),
            owner_peer_endpoint: owner_peer_endpoint.to_string(),
            connected_at_ms,
            resource_version: result.resource_version,
        })
    }

    pub async fn renew(&self, guard: &mut OwnerGuard) -> Result<(), OwnerError> {
        let payload = OwnerPayload {
            sandbox_id: guard.sandbox_id.clone(),
            session_id: guard.session_id.clone(),
            supervisor_instance_id: guard.supervisor_instance_id.clone(),
            connection_epoch: guard.connection_epoch,
            owner_replica_id: guard.owner_replica_id.clone(),
            owner_peer_endpoint: guard.owner_peer_endpoint.clone(),
            connected_at_ms: guard.connected_at_ms,
        };

        match self
            .write_payload(
                &guard.sandbox_id,
                &payload,
                WriteCondition::MatchResourceVersion(guard.resource_version),
            )
            .await
        {
            Ok(result) => {
                guard.resource_version = result.resource_version;
                Ok(())
            }
            Err(OwnerError::Store(PersistenceError::Conflict { .. })) => Err(OwnerError::Conflict),
            Err(err) => Err(err),
        }
    }

    pub async fn release_if_current(&self, guard: &OwnerGuard) -> Result<(), OwnerError> {
        let Some(record) = self.read(&guard.sandbox_id).await? else {
            return Ok(());
        };
        if record.session_id != guard.session_id
            || record.owner_replica_id != guard.owner_replica_id
        {
            return Ok(());
        }
        match self
            .store
            .delete_if(
                OWNER_OBJECT_TYPE,
                &owner_object_id(&guard.sandbox_id),
                record.resource_version,
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(PersistenceError::Conflict { .. }) => Err(OwnerError::Conflict),
            Err(err) => Err(OwnerError::Store(err)),
        }
    }

    pub async fn read(&self, sandbox_id: &str) -> Result<Option<OwnerRecord>, OwnerError> {
        let Some(record) = self
            .store
            .get(OWNER_OBJECT_TYPE, &owner_object_id(sandbox_id))
            .await
            .map_err(OwnerError::Store)?
        else {
            return Ok(None);
        };

        let payload: OwnerPayload = serde_json::from_slice(&record.payload)
            .map_err(|err| PersistenceError::Decode(err.to_string()))?;
        Ok(Some(OwnerRecord {
            session_id: payload.session_id,
            supervisor_instance_id: payload.supervisor_instance_id,
            connection_epoch: payload.connection_epoch,
            owner_replica_id: payload.owner_replica_id,
            owner_peer_endpoint: payload.owner_peer_endpoint,
            connected_at_ms: payload.connected_at_ms,
            updated_at_ms: record.updated_at_ms,
            resource_version: record.resource_version,
        }))
    }

    async fn write_payload(
        &self,
        sandbox_id: &str,
        payload: &OwnerPayload,
        condition: WriteCondition,
    ) -> Result<crate::persistence::WriteResult, OwnerError> {
        let payload_bytes =
            serde_json::to_vec(payload).map_err(|err| PersistenceError::Encode(err.to_string()));
        let payload_bytes = payload_bytes.map_err(OwnerError::Store)?;
        match self
            .store
            .put_if(
                OWNER_OBJECT_TYPE,
                &owner_object_id(sandbox_id),
                sandbox_id,
                &payload_bytes,
                None,
                condition,
            )
            .await
        {
            Ok(result) => Ok(result),
            Err(PersistenceError::UniqueViolation { .. }) => Err(OwnerError::AlreadyOwned),
            Err(PersistenceError::Conflict { .. }) => Err(OwnerError::Conflict),
            Err(err) => Err(OwnerError::Store(err)),
        }
    }
}

fn can_supersede(
    existing: &OwnerRecord,
    supervisor_instance_id: &str,
    connection_epoch: u64,
    ttl: Duration,
) -> bool {
    let age_ms = now_ms() - existing.updated_at_ms;
    let ttl_ms = i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX);
    if age_ms >= ttl_ms {
        return true;
    }

    existing.supervisor_instance_id == supervisor_instance_id
        && connection_epoch > existing.connection_epoch
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_index(ttl: Duration) -> SupervisorOwnerIndex {
        let store = Arc::new(crate::persistence::test_store().await);
        SupervisorOwnerIndex::new(store, ttl)
    }

    #[tokio::test]
    async fn publish_creates_owner() {
        let index = test_index(OWNER_TTL).await;
        let guard = index
            .publish("sbx", "s1", "inst", 1, "gw-1", "http://gw-1")
            .await
            .unwrap();
        let record = index.read("sbx").await.unwrap().unwrap();
        assert_eq!(record.session_id, guard.session_id);
        assert_eq!(record.owner_replica_id, "gw-1");
    }

    #[tokio::test]
    async fn publish_does_not_collide_with_sandbox_object_id() {
        let index = test_index(OWNER_TTL).await;
        index
            .store
            .put("sandbox", "sbx", "sandbox-a", br"{}", None)
            .await
            .unwrap();

        index
            .publish("sbx", "s1", "inst", 1, "gw-1", "http://gw-1")
            .await
            .unwrap();

        let record = index.read("sbx").await.unwrap().unwrap();
        assert_eq!(record.session_id, "s1");
        assert_eq!(record.owner_replica_id, "gw-1");
    }

    #[tokio::test]
    async fn publish_rejects_active_different_instance() {
        let index = test_index(OWNER_TTL).await;
        index
            .publish("sbx", "s1", "inst-a", 1, "gw-1", "http://gw-1")
            .await
            .unwrap();
        let err = index
            .publish("sbx", "s2", "inst-b", 1, "gw-2", "http://gw-2")
            .await
            .unwrap_err();
        assert!(matches!(err, OwnerError::AlreadyOwned));
    }

    #[tokio::test]
    async fn publish_supersedes_same_instance_higher_epoch() {
        let index = test_index(OWNER_TTL).await;
        index
            .publish("sbx", "s1", "inst", 1, "gw-1", "http://gw-1")
            .await
            .unwrap();
        let guard = index
            .publish("sbx", "s2", "inst", 2, "gw-2", "http://gw-2")
            .await
            .unwrap();
        let record = index.read("sbx").await.unwrap().unwrap();
        assert_eq!(record.session_id, guard.session_id);
        assert_eq!(record.owner_replica_id, "gw-2");
    }

    #[tokio::test]
    async fn release_if_current_ignores_stale_guard() {
        let index = test_index(OWNER_TTL).await;
        let old = index
            .publish("sbx", "s1", "inst", 1, "gw-1", "http://gw-1")
            .await
            .unwrap();
        let new = index
            .publish("sbx", "s2", "inst", 2, "gw-2", "http://gw-2")
            .await
            .unwrap();
        index.release_if_current(&old).await.unwrap();
        let record = index.read("sbx").await.unwrap().unwrap();
        assert_eq!(record.session_id, new.session_id);
    }

    #[tokio::test]
    async fn renew_updates_resource_version() {
        let index = test_index(OWNER_TTL).await;
        let mut guard = index
            .publish("sbx", "s1", "inst", 1, "gw-1", "http://gw-1")
            .await
            .unwrap();
        let before = guard.resource_version;
        index.renew(&mut guard).await.unwrap();
        assert!(guard.resource_version > before);
    }
}
