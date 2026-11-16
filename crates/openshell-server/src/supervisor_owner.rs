// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared supervisor-session ownership index for HA gateway replicas.

use crate::persistence::{ObjectRecord, PersistenceError, Store, WriteCondition};
use openshell_core::jwt::CredentialEpoch;
use openshell_core::time::now_ms;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

const OWNER_OBJECT_TYPE: &str = "supervisor_session_owner";

pub const OWNER_TTL: Duration = Duration::from_secs(45);

const PUBLISH_ATTEMPTS: u32 = 3;

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
    /// Ownership term: the credential epoch of the session's bearer. 0, as
    /// in records written by older gateways, means unknown.
    #[serde(default)]
    auth_epoch: u64,
    owner_replica_id: String,
    owner_peer_endpoint: String,
    connected_at_ms: i64,
}

/// Marks an owner record written by a gateway that advertises no peer endpoint.
/// Only that gateway can serve such a session, so no peer should dial it.
pub const LOCAL_OWNER_ENDPOINT_SCHEME: &str = "local://";

/// `endpoint`, unless it is empty or a `local://` placeholder that no other
/// replica can dial.
pub fn dialable_peer_endpoint(endpoint: &str) -> Option<&str> {
    (!endpoint.is_empty() && !endpoint.starts_with(LOCAL_OWNER_ENDPOINT_SCHEME)).then_some(endpoint)
}

#[derive(Debug, Clone)]
pub struct OwnerRecord {
    pub session_id: String,
    pub supervisor_instance_id: String,
    pub connection_epoch: u64,
    /// The owning session's ownership term, when known.
    pub auth_epoch: Option<CredentialEpoch>,
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

    /// The endpoint other replicas dial to reach this owner, if it has one.
    pub fn peer_endpoint(&self) -> Option<&str> {
        dialable_peer_endpoint(&self.owner_peer_endpoint)
    }
}

#[derive(Debug, Clone)]
pub struct OwnerGuard {
    pub sandbox_id: String,
    pub session_id: String,
    pub supervisor_instance_id: String,
    pub connection_epoch: u64,
    pub auth_epoch: Option<CredentialEpoch>,
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

    /// Publish ownership for a session whose term is unknown.
    #[cfg(test)]
    pub async fn publish(
        &self,
        sandbox_id: &str,
        session_id: &str,
        supervisor_instance_id: &str,
        connection_epoch: u64,
        owner_replica_id: &str,
        owner_peer_endpoint: &str,
    ) -> Result<OwnerGuard, OwnerError> {
        self.publish_term(
            sandbox_id,
            session_id,
            supervisor_instance_id,
            connection_epoch,
            None,
            owner_replica_id,
            owner_peer_endpoint,
        )
        .await
    }

    /// Publish ownership of `sandbox_id` for a session of ownership term
    /// `auth_epoch`, the credential epoch of its bearer.
    #[allow(clippy::too_many_arguments)]
    pub async fn publish_term(
        &self,
        sandbox_id: &str,
        session_id: &str,
        supervisor_instance_id: &str,
        connection_epoch: u64,
        auth_epoch: Option<CredentialEpoch>,
        owner_replica_id: &str,
        owner_peer_endpoint: &str,
    ) -> Result<OwnerGuard, OwnerError> {
        let connected_at_ms = now_ms();
        let payload = OwnerPayload {
            sandbox_id: sandbox_id.to_string(),
            session_id: session_id.to_string(),
            supervisor_instance_id: supervisor_instance_id.to_string(),
            connection_epoch,
            auth_epoch: auth_epoch.map_or(0, CredentialEpoch::get),
            owner_replica_id: owner_replica_id.to_string(),
            owner_peer_endpoint: owner_peer_endpoint.to_string(),
            connected_at_ms,
        };

        // A previous owner releasing its record between our read and write
        // (as a replica does while handing sessions off on shutdown) shows up
        // as a conflict; re-read and decide again.
        let mut attempts = 0;
        let result = loop {
            attempts += 1;
            let condition = match self.read(sandbox_id).await? {
                None => WriteCondition::MustCreate,
                Some(existing)
                    if can_supersede(
                        &existing,
                        supervisor_instance_id,
                        connection_epoch,
                        auth_epoch,
                        self.ttl,
                    ) =>
                {
                    WriteCondition::MatchResourceVersion(existing.resource_version)
                }
                Some(_) => return Err(OwnerError::AlreadyOwned),
            };
            match self.write_payload(sandbox_id, &payload, condition).await {
                Err(OwnerError::Conflict) if attempts < PUBLISH_ATTEMPTS => {}
                other => break other?,
            }
        };
        Ok(OwnerGuard {
            sandbox_id: sandbox_id.to_string(),
            session_id: session_id.to_string(),
            supervisor_instance_id: supervisor_instance_id.to_string(),
            connection_epoch,
            auth_epoch,
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
            auth_epoch: guard.auth_epoch.map_or(0, CredentialEpoch::get),
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

        Ok(Some(decode_owner_record(&record)?.1))
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

fn decode_owner_record(record: &ObjectRecord) -> Result<(String, OwnerRecord), OwnerError> {
    let payload: OwnerPayload = serde_json::from_slice(&record.payload)
        .map_err(|err| PersistenceError::Decode(err.to_string()))?;
    if payload.sandbox_id != record.name || record.id != owner_object_id(&payload.sandbox_id) {
        return Err(OwnerError::Store(PersistenceError::Decode(
            "supervisor owner identity mismatch".to_string(),
        )));
    }
    Ok((
        payload.sandbox_id,
        OwnerRecord {
            session_id: payload.session_id,
            supervisor_instance_id: payload.supervisor_instance_id,
            connection_epoch: payload.connection_epoch,
            auth_epoch: CredentialEpoch::new(payload.auth_epoch).ok(),
            owner_replica_id: payload.owner_replica_id,
            owner_peer_endpoint: payload.owner_peer_endpoint,
            connected_at_ms: payload.connected_at_ms,
            updated_at_ms: record.updated_at_ms,
            resource_version: record.resource_version,
        },
    ))
}

/// How ownership term `claimed` orders against `current`. Terms are ordered
/// only when both are known.
pub fn term_order(
    claimed: Option<CredentialEpoch>,
    current: Option<CredentialEpoch>,
) -> Option<Ordering> {
    claimed
        .zip(current)
        .map(|(claimed, current)| claimed.cmp(&current))
}

/// Whether a session may replace `existing` as its sandbox's owner.
///
/// A stale record yields to any session. A fresh record yields at once to a
/// later ownership term, whichever supervisor process holds it, and never to
/// an earlier one; a restart's new generation and a takeover both advance the
/// term. Within a term, or where either term is unknown, only a reconnect of
/// the same supervisor instance replaces it.
pub fn can_supersede(
    existing: &OwnerRecord,
    supervisor_instance_id: &str,
    connection_epoch: u64,
    auth_epoch: Option<CredentialEpoch>,
    ttl: Duration,
) -> bool {
    if !existing.is_fresh(ttl) {
        return true;
    }
    match term_order(auth_epoch, existing.auth_epoch) {
        Some(Ordering::Greater) => true,
        Some(Ordering::Less) => false,
        Some(Ordering::Equal) | None => {
            existing.supervisor_instance_id == supervisor_instance_id
                && connection_epoch > existing.connection_epoch
        }
    }
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
            auth_epoch: None,
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

    fn epoch(value: u64) -> CredentialEpoch {
        CredentialEpoch::new(value).unwrap()
    }

    #[test]
    fn freshness_clamps_a_future_timestamp_instead_of_going_negative() {
        let skewed = record_updated_at(now_ms() + owner_ttl_ms() * 10);
        assert!(skewed.is_fresh(OWNER_TTL));
        assert!(!can_supersede(&skewed, "other-inst", 99, None, OWNER_TTL));
    }

    #[test]
    fn fresh_owners_yield_only_to_later_terms_or_reconnects_within_a_term() {
        let mut fresh = record_updated_at(now_ms());
        fresh.auth_epoch = Some(epoch(2));
        for (instance, connection_epoch, auth_epoch, supersedes) in [
            ("other-inst", 0, Some(epoch(3)), true),
            ("inst", 9, Some(epoch(1)), false),
            ("other-inst", 9, Some(epoch(2)), false),
            ("inst", 1, Some(epoch(2)), false),
            ("inst", 2, Some(epoch(2)), true),
            ("other-inst", 9, None, false),
            ("inst", 2, None, true),
        ] {
            assert_eq!(
                can_supersede(&fresh, instance, connection_epoch, auth_epoch, OWNER_TTL),
                supersedes,
                "{instance} at connection epoch {connection_epoch}, term {auth_epoch:?}"
            );
        }
    }

    #[test]
    fn a_stale_owner_yields_even_to_an_earlier_term() {
        let mut stale = record_updated_at(now_ms() - owner_ttl_ms() - 1);
        stale.auth_epoch = Some(epoch(3));
        assert!(can_supersede(
            &stale,
            "other-inst",
            0,
            Some(epoch(1)),
            OWNER_TTL
        ));
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
        assert!(can_supersede(&stale, "other-inst", 1, None, OWNER_TTL));
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
    async fn a_later_term_supersedes_a_fresh_owner_of_another_supervisor() {
        let index = test_index(OWNER_TTL).await;
        index
            .publish_term(
                "sbx",
                "s1",
                "inst-a",
                7,
                Some(epoch(1)),
                "gw-1",
                "http://gw-1",
            )
            .await
            .unwrap();
        // The takeover's supervisor process must not wait out the previous
        // owner's record.
        let guard = index
            .publish_term(
                "sbx",
                "s2",
                "inst-b",
                0,
                Some(epoch(2)),
                "gw-2",
                "http://gw-2",
            )
            .await
            .unwrap();
        let record = index.read("sbx").await.unwrap().unwrap();
        assert_eq!(record.session_id, guard.session_id);
        assert_eq!(record.supervisor_instance_id, "inst-b");
        assert_eq!(record.auth_epoch, Some(epoch(2)));
    }

    #[tokio::test]
    async fn an_earlier_term_never_supersedes_a_fresh_owner() {
        let index = test_index(OWNER_TTL).await;
        index
            .publish_term(
                "sbx",
                "s2",
                "inst-b",
                0,
                Some(epoch(2)),
                "gw-2",
                "http://gw-2",
            )
            .await
            .unwrap();
        // Neither the replaced process nor a reconnect of the current one
        // can bring the replaced term back.
        for (instance, connection_epoch) in [("inst-a", 9), ("inst-b", 1)] {
            let err = index
                .publish_term(
                    "sbx",
                    "s3",
                    instance,
                    connection_epoch,
                    Some(epoch(1)),
                    "gw-1",
                    "http://gw-1",
                )
                .await
                .unwrap_err();
            assert!(matches!(err, OwnerError::AlreadyOwned), "{instance}");
        }
        assert_eq!(index.read("sbx").await.unwrap().unwrap().session_id, "s2");
    }

    #[tokio::test]
    async fn records_of_older_gateways_have_an_unknown_term() {
        let index = test_index(OWNER_TTL).await;
        let legacy = serde_json::json!({
            "sandbox_id": "sbx",
            "session_id": "s1",
            "supervisor_instance_id": "inst-a",
            "connection_epoch": 1,
            "owner_replica_id": "gw-1",
            "owner_peer_endpoint": "http://gw-1",
            "connected_at_ms": 0,
        });
        index
            .store
            .put(
                OWNER_OBJECT_TYPE,
                &owner_object_id("sbx"),
                "sbx",
                "",
                &serde_json::to_vec(&legacy).unwrap(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(index.read("sbx").await.unwrap().unwrap().auth_epoch, None);

        // An unknown term is not an earlier one: only a reconnect of the
        // owning instance replaces it.
        let err = index
            .publish_term(
                "sbx",
                "s2",
                "inst-b",
                5,
                Some(epoch(2)),
                "gw-2",
                "http://gw-2",
            )
            .await
            .unwrap_err();
        assert!(matches!(err, OwnerError::AlreadyOwned));
        index
            .publish_term(
                "sbx",
                "s2",
                "inst-a",
                2,
                Some(epoch(2)),
                "gw-2",
                "http://gw-2",
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn renew_keeps_the_ownership_term() {
        let index = test_index(OWNER_TTL).await;
        let mut guard = index
            .publish_term(
                "sbx",
                "s1",
                "inst",
                1,
                Some(epoch(3)),
                "gw-1",
                "http://gw-1",
            )
            .await
            .unwrap();
        index.renew(&mut guard).await.unwrap();
        assert_eq!(
            index.read("sbx").await.unwrap().unwrap().auth_epoch,
            Some(epoch(3))
        );
        assert!(matches!(
            index
                .publish_term(
                    "sbx",
                    "s2",
                    "inst",
                    2,
                    Some(epoch(2)),
                    "gw-1",
                    "http://gw-1"
                )
                .await,
            Err(OwnerError::AlreadyOwned)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn publish_survives_the_previous_owner_releasing_concurrently() {
        let index = Arc::new(test_index(OWNER_TTL).await);
        for i in 0..200u64 {
            let sandbox = format!("sbx-{i}");
            let old = index
                .publish(&sandbox, "s1", "inst", 1, "gw-1", "http://gw-1")
                .await
                .unwrap();
            let releaser = Arc::clone(&index);
            let release = tokio::spawn(async move { releaser.release_if_current(&old).await });
            let publish = index
                .publish(&sandbox, "s2", "inst", 2, "gw-2", "http://gw-2")
                .await;
            let _ = release.await.unwrap();
            assert!(publish.is_ok(), "iteration {i}: {:?}", publish.err());
        }
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
