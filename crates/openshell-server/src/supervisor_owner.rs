// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared supervisor-session ownership index for HA gateway replicas.

use crate::persistence::{PersistenceError, Store, WriteCondition};
use openshell_core::time::now_ms;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
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

impl OwnerError {
    /// True when another replica holds ownership, as opposed to the store
    /// being unreachable.
    pub fn is_ownership_lost(&self) -> bool {
        matches!(self, Self::AlreadyOwned | Self::Conflict)
    }
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

impl OwnerRecord {
    /// True while the record's last update is within `ttl`.
    pub fn is_fresh(&self, ttl: Duration) -> bool {
        let ttl_ms = i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX);
        now_ms().saturating_sub(self.updated_at_ms).max(0) < ttl_ms
    }
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
    last_renewed_at: Instant,
}

impl OwnerGuard {
    /// True once renewals have failed for long enough that another replica can
    /// supersede this claim, making it unsafe to keep serving the session.
    pub fn claim_expired(&self, ttl: Duration) -> bool {
        self.last_renewed_at.elapsed() >= ttl
    }
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
            last_renewed_at: Instant::now(),
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
                guard.last_renewed_at = Instant::now();
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
                "",
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
    if !existing.is_fresh(ttl) {
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

    fn record_updated_at(updated_at_ms: i64) -> OwnerRecord {
        OwnerRecord {
            session_id: "s1".to_string(),
            supervisor_instance_id: "inst".to_string(),
            connection_epoch: 1,
            owner_replica_id: "gw-1".to_string(),
            owner_peer_endpoint: "https://gw-1".to_string(),
            connected_at_ms: 0,
            updated_at_ms,
            resource_version: 1,
        }
    }

    fn owner_ttl_ms() -> i64 {
        i64::try_from(OWNER_TTL.as_millis()).unwrap()
    }

    #[test]
    fn freshness_clamps_a_future_timestamp_instead_of_going_negative() {
        let skewed = record_updated_at(now_ms() + owner_ttl_ms() * 10);
        assert!(skewed.is_fresh(OWNER_TTL));
        assert!(!can_supersede(&skewed, "other-inst", 99, OWNER_TTL));
    }

    #[test]
    fn only_ownership_conflicts_count_as_lost_ownership() {
        assert!(OwnerError::AlreadyOwned.is_ownership_lost());
        assert!(OwnerError::Conflict.is_ownership_lost());
        assert!(
            !OwnerError::Store(PersistenceError::Database("db unreachable".to_string()))
                .is_ownership_lost()
        );
    }

    #[tokio::test]
    async fn a_claim_expires_once_renewals_stop_for_the_ttl() {
        let index = test_index(OWNER_TTL).await;
        let guard = index
            .publish("sbx", "s1", "inst", 1, "gw-1", "http://gw-1")
            .await
            .unwrap();
        assert!(!guard.claim_expired(OWNER_TTL));
        assert!(guard.claim_expired(Duration::ZERO));
    }

    #[test]
    fn freshness_survives_a_corrupt_timestamp() {
        let corrupt = record_updated_at(i64::MIN);
        assert!(!corrupt.is_fresh(OWNER_TTL));
    }

    #[test]
    fn freshness_expires_past_the_ttl() {
        let stale = record_updated_at(now_ms() - owner_ttl_ms() - 1);
        assert!(!stale.is_fresh(OWNER_TTL));
        assert!(can_supersede(&stale, "other-inst", 1, OWNER_TTL));
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
            .put("sandbox", "sbx", "sandbox-a", "default", br"{}", None)
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
