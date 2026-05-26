// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reconciler lease for HA multi-replica gateway deployments.
//!
//! A single global lease stored in the `objects` table determines which
//! replica runs the watch and reconcile loops. All replicas continue
//! serving gRPC requests regardless of lease ownership.
//!
//! The lease payload is a small JSON blob — no protobuf definition needed.
//! CAS via `put_if` / `delete_if` provides cross-replica safety; the lease
//! is an optimization to reduce contention, not a correctness mechanism.

use crate::persistence::{PersistenceError, Store, WriteCondition};
use openshell_core::time::now_ms;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

const LEASE_OBJECT_TYPE: &str = "reconciler_lease";
const LEASE_SINGLETON_ID: &str = "singleton";
const LEASE_SINGLETON_NAME: &str = "reconciler-lease";

pub const LEASE_TTL: Duration = Duration::from_secs(30);
pub const LEASE_RENEWAL_INTERVAL: Duration = Duration::from_secs(10);
pub const LEASE_ACQUIRE_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum LeaseError {
    #[error("lease is already held by another replica")]
    AlreadyHeld,
    #[error("lease not found")]
    NotFound,
    #[error("lease CAS conflict — another replica wrote first")]
    Conflict,
    #[error("persistence error: {0}")]
    Store(#[from] PersistenceError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LeasePayload {
    holder: String,
    acquired_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct LeaseRecord {
    pub holder: String,
    pub acquired_at_ms: i64,
    pub resource_version: u64,
    pub updated_at_ms: i64,
}

#[derive(Debug)]
pub struct LeaseGuard {
    resource_version: u64,
    acquired_at_ms: i64,
}

impl LeaseGuard {
    pub fn resource_version(&self) -> u64 {
        self.resource_version
    }
}

pub struct ReconcilerLease {
    store: Arc<Store>,
    replica_id: String,
    ttl: Duration,
}

impl ReconcilerLease {
    pub fn new(store: Arc<Store>, replica_id: String, ttl: Duration) -> Self {
        Self {
            store,
            replica_id,
            ttl,
        }
    }

    pub fn replica_id(&self) -> &str {
        &self.replica_id
    }

    /// Attempt to create the lease record. Succeeds only if no lease exists.
    pub async fn try_acquire(&self) -> Result<LeaseGuard, LeaseError> {
        let acquired_at_ms = now_ms();
        let payload = LeasePayload {
            holder: self.replica_id.clone(),
            acquired_at_ms,
        };
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| PersistenceError::Encode(e.to_string()))?;

        match self
            .store
            .put_if(
                LEASE_OBJECT_TYPE,
                LEASE_SINGLETON_ID,
                LEASE_SINGLETON_NAME,
                &payload_bytes,
                None,
                WriteCondition::MustCreate,
            )
            .await
        {
            Ok(result) => Ok(LeaseGuard {
                resource_version: result.resource_version,
                acquired_at_ms,
            }),
            Err(PersistenceError::UniqueViolation { .. }) => Err(LeaseError::AlreadyHeld),
            Err(e) => Err(LeaseError::Store(e)),
        }
    }

    /// Steal an expired lease from another replica via CAS.
    pub async fn try_steal_expired(&self) -> Result<LeaseGuard, LeaseError> {
        let record = self.read().await?.ok_or(LeaseError::NotFound)?;

        let age_ms = now_ms() - record.updated_at_ms;
        if age_ms < self.ttl.as_millis() as i64 {
            return Err(LeaseError::AlreadyHeld);
        }

        let acquired_at_ms = now_ms();
        let payload = LeasePayload {
            holder: self.replica_id.clone(),
            acquired_at_ms,
        };
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| PersistenceError::Encode(e.to_string()))?;

        match self
            .store
            .put_if(
                LEASE_OBJECT_TYPE,
                LEASE_SINGLETON_ID,
                LEASE_SINGLETON_NAME,
                &payload_bytes,
                None,
                WriteCondition::MatchResourceVersion(record.resource_version),
            )
            .await
        {
            Ok(result) => Ok(LeaseGuard {
                resource_version: result.resource_version,
                acquired_at_ms,
            }),
            Err(PersistenceError::Conflict { .. }) => Err(LeaseError::Conflict),
            Err(e) => Err(LeaseError::Store(e)),
        }
    }

    /// Try to acquire a fresh lease; if one already exists and is expired,
    /// attempt to steal it.
    pub async fn acquire_or_steal(&self) -> Result<LeaseGuard, LeaseError> {
        match self.try_acquire().await {
            Ok(guard) => Ok(guard),
            Err(LeaseError::AlreadyHeld) => self.try_steal_expired().await,
            Err(e) => Err(e),
        }
    }

    /// Renew the lease by CAS-writing the same payload to bump
    /// `updated_at_ms` and `resource_version`.
    pub async fn renew(&self, guard: &mut LeaseGuard) -> Result<(), LeaseError> {
        let payload = LeasePayload {
            holder: self.replica_id.clone(),
            acquired_at_ms: guard.acquired_at_ms,
        };
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| PersistenceError::Encode(e.to_string()))?;

        match self
            .store
            .put_if(
                LEASE_OBJECT_TYPE,
                LEASE_SINGLETON_ID,
                LEASE_SINGLETON_NAME,
                &payload_bytes,
                None,
                WriteCondition::MatchResourceVersion(guard.resource_version),
            )
            .await
        {
            Ok(result) => {
                guard.resource_version = result.resource_version;
                Ok(())
            }
            Err(PersistenceError::Conflict { .. }) => Err(LeaseError::Conflict),
            Err(e) => Err(LeaseError::Store(e)),
        }
    }

    /// Release the lease so a standby replica can acquire immediately
    /// without waiting for TTL expiry.
    pub async fn release(&self, guard: LeaseGuard) -> Result<(), LeaseError> {
        match self
            .store
            .delete_if(
                LEASE_OBJECT_TYPE,
                LEASE_SINGLETON_ID,
                guard.resource_version,
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(PersistenceError::Conflict { .. }) => Err(LeaseError::Conflict),
            Err(e) => Err(LeaseError::Store(e)),
        }
    }

    /// Read the current lease record, if any.
    pub async fn read(&self) -> Result<Option<LeaseRecord>, LeaseError> {
        let record = self
            .store
            .get(LEASE_OBJECT_TYPE, LEASE_SINGLETON_ID)
            .await
            .map_err(LeaseError::Store)?;
        let Some(record) = record else {
            return Ok(None);
        };

        let payload: LeasePayload = serde_json::from_slice(&record.payload)
            .map_err(|e| PersistenceError::Decode(e.to_string()))?;

        Ok(Some(LeaseRecord {
            holder: payload.holder,
            acquired_at_ms: payload.acquired_at_ms,
            resource_version: record.resource_version,
            updated_at_ms: record.updated_at_ms,
        }))
    }
}

/// Derive a stable replica identity for lease ownership.
///
/// Kubernetes sets `HOSTNAME` to the pod name, Docker sets it to the
/// container ID, and systemd units inherit the machine hostname.
/// `OPENSHELL_REPLICA_ID` allows explicit override. The UUID fallback
/// handles edge cases where neither env var is set.
pub fn replica_id() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("OPENSHELL_REPLICA_ID"))
        .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::Store;

    async fn test_store() -> Arc<Store> {
        Arc::new(
            Store::connect("sqlite::memory:?cache=shared")
                .await
                .unwrap(),
        )
    }

    fn lease(store: Arc<Store>, id: &str, ttl: Duration) -> ReconcilerLease {
        ReconcilerLease::new(store, id.to_string(), ttl)
    }

    #[tokio::test]
    async fn acquire_succeeds_when_no_lease_exists() {
        let store = test_store().await;
        let l = lease(store, "replica-1", LEASE_TTL);
        let guard = l.try_acquire().await.expect("should acquire");
        assert!(guard.resource_version > 0);

        let record = l.read().await.unwrap().expect("lease should exist");
        assert_eq!(record.holder, "replica-1");
    }

    #[tokio::test]
    async fn acquire_fails_when_lease_held() {
        let store = test_store().await;
        let l1 = lease(store.clone(), "replica-1", LEASE_TTL);
        let l2 = lease(store, "replica-2", LEASE_TTL);
        let _guard = l1.try_acquire().await.unwrap();
        let err = l2.try_acquire().await.unwrap_err();
        assert!(matches!(err, LeaseError::AlreadyHeld));
    }

    #[tokio::test]
    async fn concurrent_acquisition_exactly_one_wins() {
        let store = test_store().await;
        let mut tasks = Vec::new();
        for i in 0..5 {
            let s = store.clone();
            tasks.push(tokio::spawn(async move {
                let l = lease(s, &format!("replica-{i}"), LEASE_TTL);
                l.try_acquire().await
            }));
        }

        let mut wins = 0;
        for task in tasks {
            if task.await.unwrap().is_ok() {
                wins += 1;
            }
        }
        assert_eq!(wins, 1);
    }

    #[tokio::test]
    async fn renew_extends_lease() {
        let store = test_store().await;
        let l = lease(store, "replica-1", LEASE_TTL);
        let mut guard = l.try_acquire().await.unwrap();
        let v1 = guard.resource_version;

        l.renew(&mut guard).await.unwrap();
        assert!(guard.resource_version > v1);

        let record = l.read().await.unwrap().unwrap();
        assert_eq!(record.holder, "replica-1");
        assert_eq!(record.resource_version, guard.resource_version);
    }

    #[tokio::test]
    async fn steal_rejected_when_lease_active() {
        let store = test_store().await;
        let l1 = lease(store.clone(), "replica-1", LEASE_TTL);
        let _guard = l1.try_acquire().await.unwrap();

        let l2 = lease(store, "replica-2", LEASE_TTL);
        let err = l2.try_steal_expired().await.unwrap_err();
        assert!(matches!(err, LeaseError::AlreadyHeld));
    }

    #[tokio::test]
    async fn steal_succeeds_when_lease_expired() {
        let store = test_store().await;
        // Use a 0ms TTL so the lease is immediately expired
        let l1 = lease(store.clone(), "replica-1", Duration::ZERO);
        let _guard = l1.try_acquire().await.unwrap();

        let l2 = lease(store, "replica-2", Duration::ZERO);
        let guard = l2.try_steal_expired().await.expect("should steal expired");
        let record = l2.read().await.unwrap().unwrap();
        assert_eq!(record.holder, "replica-2");
        assert_eq!(record.resource_version, guard.resource_version);
    }

    #[tokio::test]
    async fn release_allows_immediate_reacquire() {
        let store = test_store().await;
        let l1 = lease(store.clone(), "replica-1", LEASE_TTL);
        let guard = l1.try_acquire().await.unwrap();
        l1.release(guard).await.unwrap();

        let l2 = lease(store, "replica-2", LEASE_TTL);
        let guard = l2.try_acquire().await.expect("should acquire after release");
        let record = l2.read().await.unwrap().unwrap();
        assert_eq!(record.holder, "replica-2");
        assert_eq!(record.resource_version, guard.resource_version);
    }

    #[tokio::test]
    async fn acquire_or_steal_creates_when_none_exists() {
        let store = test_store().await;
        let l = lease(store, "replica-1", LEASE_TTL);
        let guard = l.acquire_or_steal().await.expect("should create");
        let record = l.read().await.unwrap().unwrap();
        assert_eq!(record.holder, "replica-1");
        assert_eq!(record.resource_version, guard.resource_version);
    }

    #[tokio::test]
    async fn acquire_or_steal_steals_expired() {
        let store = test_store().await;
        let l1 = lease(store.clone(), "replica-1", Duration::ZERO);
        let _guard = l1.try_acquire().await.unwrap();

        let l2 = lease(store, "replica-2", Duration::ZERO);
        let guard = l2.acquire_or_steal().await.expect("should steal");
        let record = l2.read().await.unwrap().unwrap();
        assert_eq!(record.holder, "replica-2");
        assert_eq!(record.resource_version, guard.resource_version);
    }

    #[tokio::test]
    async fn acquire_or_steal_fails_when_active() {
        let store = test_store().await;
        let l1 = lease(store.clone(), "replica-1", LEASE_TTL);
        let _guard = l1.try_acquire().await.unwrap();

        let l2 = lease(store, "replica-2", LEASE_TTL);
        let err = l2.acquire_or_steal().await.unwrap_err();
        assert!(matches!(err, LeaseError::AlreadyHeld));
    }

    #[tokio::test]
    async fn read_returns_none_when_no_lease() {
        let store = test_store().await;
        let l = lease(store, "replica-1", LEASE_TTL);
        assert!(l.read().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn replica_id_returns_nonempty() {
        let id = replica_id();
        assert!(!id.is_empty());
    }
}
