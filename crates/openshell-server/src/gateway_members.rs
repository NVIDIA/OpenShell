// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Live gateway replica membership, used to build the placement ring.
//!
//! Each replica records itself in the store and refreshes that record on a
//! timer. A record older than [`MEMBER_TTL`] is treated as dead. Membership is
//! kept in the store rather than read from Kubernetes so it works for any
//! multi-replica deployment and adds no API server load.

use crate::gateway_metrics;
use crate::gateway_ring::GatewayRing;
use crate::persistence::{PersistenceError, PersistenceResult, Store, WriteCondition};
use openshell_core::time::now_ms;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

const MEMBER_OBJECT_TYPE: &str = "gateway_member";

/// How long a membership record stays valid without a refresh.
pub const MEMBER_TTL: Duration = Duration::from_secs(30);

/// How often a replica refreshes its own record. Comfortably inside the TTL so
/// a single missed refresh does not drop the replica out of the ring.
pub const MEMBER_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// Upper bound on replicas read back when building the ring.
const MEMBER_LIST_LIMIT: u32 = 1024;

/// How long the worker waits on each store call while leaving at shutdown.
const SHUTDOWN_STORE_TIMEOUT: Duration = Duration::from_secs(2);

/// How long gateway shutdown waits for the membership worker to finish
/// leaving: one membership read and one deregister.
pub const SHUTDOWN_MEMBERSHIP_TIMEOUT: Duration = Duration::from_secs(5);

fn member_object_id(replica_id: &str) -> String {
    format!("gateway-member:{replica_id}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MemberPayload {
    replica_id: String,
    peer_endpoint: String,
}

/// A gateway replica that was alive as of its last refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayMember {
    pub replica_id: String,
    pub peer_endpoint: String,
}

pub struct GatewayMemberIndex {
    store: Arc<Store>,
    ttl: Duration,
}

impl GatewayMemberIndex {
    pub fn new(store: Arc<Store>, ttl: Duration) -> Self {
        Self { store, ttl }
    }

    /// Record this replica as alive, or refresh an existing record.
    ///
    /// A replica only ever writes its own record, so a CAS conflict here means
    /// a duplicate of this replica ID is running. The caller retries on the
    /// next tick rather than forcing the write.
    pub async fn register(&self, replica_id: &str, peer_endpoint: &str) -> PersistenceResult<()> {
        let payload = MemberPayload {
            replica_id: replica_id.to_string(),
            peer_endpoint: peer_endpoint.to_string(),
        };
        let bytes = serde_json::to_vec(&payload)
            .map_err(|err| PersistenceError::Encode(err.to_string()))?;
        let object_id = member_object_id(replica_id);

        let condition = match self.store.get(MEMBER_OBJECT_TYPE, &object_id).await? {
            Some(existing) => WriteCondition::MatchResourceVersion(existing.resource_version),
            None => WriteCondition::MustCreate,
        };

        self.store
            .put_if(
                MEMBER_OBJECT_TYPE,
                &object_id,
                replica_id,
                "",
                &bytes,
                None,
                condition,
            )
            .await
            .map(|_| ())
    }

    /// Remove this replica's record on a clean shutdown, so the ring converges
    /// immediately instead of waiting out the TTL.
    pub async fn deregister(&self, replica_id: &str) -> PersistenceResult<()> {
        self.store
            .delete(MEMBER_OBJECT_TYPE, &member_object_id(replica_id))
            .await
            .map(|_| ())
    }

    /// Replicas whose records are still within the TTL.
    pub async fn live_members(&self) -> PersistenceResult<Vec<GatewayMember>> {
        let records = self
            .store
            .list_by_type(MEMBER_OBJECT_TYPE, MEMBER_LIST_LIMIT, 0)
            .await?;
        let ttl_ms = i64::try_from(self.ttl.as_millis()).unwrap_or(i64::MAX);
        let now = now_ms();

        let mut members = Vec::with_capacity(records.len());
        for record in records {
            // Clamped because updated_at_ms is written by whichever replica
            // last refreshed; a fast clock elsewhere must not make a record
            // look permanently fresh.
            let age_ms = now.saturating_sub(record.updated_at_ms).max(0);
            if age_ms >= ttl_ms {
                // Replicas that died without deregistering would otherwise
                // pile up and crowd live ones out of the listing limit.
                if age_ms >= ttl_ms.saturating_mul(2) {
                    let _ = self
                        .store
                        .delete_if(MEMBER_OBJECT_TYPE, &record.id, record.resource_version)
                        .await;
                }
                continue;
            }
            let Ok(payload) = serde_json::from_slice::<MemberPayload>(&record.payload) else {
                continue;
            };
            if payload.replica_id.is_empty() {
                continue;
            }
            members.push(GatewayMember {
                replica_id: payload.replica_id,
                peer_endpoint: payload.peer_endpoint,
            });
        }
        members.sort_by(|left, right| left.replica_id.cmp(&right.replica_id));
        members.dedup_by(|left, right| left.replica_id == right.replica_id);
        Ok(members)
    }

    /// Build a placement ring from the currently live replicas.
    pub async fn ring(&self) -> PersistenceResult<(GatewayRing, Vec<GatewayMember>)> {
        let members = self.live_members().await?;
        let ring = GatewayRing::new(members.iter().map(|member| member.replica_id.as_str()));
        Ok((ring, members))
    }
}

/// Keep this replica's membership record fresh and refresh the local ring.
///
/// One task does both so the ring is never newer than our own liveness claim.
/// The ring starts empty, which means "serve locally" — so a store outage
/// degrades to today's behaviour rather than breaking placement.
///
/// Returns the worker task, which finishes after this replica leaves the ring
/// at shutdown. Shutdown awaits it before redirecting supervisor sessions.
pub fn spawn_membership_worker(
    state: Arc<crate::ServerState>,
    interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    if state.store.is_single_replica() {
        return None;
    }
    let Some(peer_endpoint) = state.peer_endpoint.clone() else {
        // Without a peer endpoint other replicas cannot dial us, so we must
        // not advertise ourselves as a placement target.
        tracing::debug!("gateway membership: no peer endpoint, not joining the ring");
        return None;
    };

    let index = GatewayMemberIndex::new(state.store.clone(), MEMBER_TTL);
    let replica_id = state.replica_id.clone();
    // Export the ring's size now (empty until the first refresh), so only
    // replicas that join the ring carry the gauge, and they carry it from the
    // start.
    publish_ring(&state, GatewayRing::clone);

    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_refreshed = tokio::time::Instant::now();

        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        leave_ring(&state, &index, &replica_id).await;
                        return;
                    }
                    continue;
                }
            }

            if let Err(error) = index.register(&replica_id, &peer_endpoint).await {
                tracing::warn!(%error, "gateway membership: refresh failed");
                clear_ring_if_stale(&state, last_refreshed);
                continue;
            }

            match index.ring().await {
                Ok((ring, members)) => {
                    let peers: HashMap<String, String> = members
                        .into_iter()
                        .map(|member| (member.replica_id, member.peer_endpoint))
                        .collect();
                    publish_ring(&state, |_| ring);
                    if let Ok(mut slot) = state.gateway_peers.write() {
                        *slot = peers;
                    }
                    last_refreshed = tokio::time::Instant::now();
                }
                Err(error) => {
                    tracing::warn!(%error, "gateway membership: ring refresh failed");
                    clear_ring_if_stale(&state, last_refreshed);
                }
            }
        }
    }))
}

/// Point the ring at the replicas that remain once this one is gone, then
/// remove this replica's record.
///
/// Sessions closing during shutdown redirect to the replica that owns them
/// next. The periodic refresh can be up to one interval old, and during a
/// rolling update that ring can miss a replacement that just started and still
/// name a replica that already left. Redirects built from it send supervisors
/// nowhere or to a dead pod, so re-read membership first. If the read fails,
/// keep the cached ring without this replica.
async fn leave_ring(state: &crate::ServerState, index: &GatewayMemberIndex, replica_id: &str) {
    match tokio::time::timeout(SHUTDOWN_STORE_TIMEOUT, index.ring()).await {
        Ok(Ok((ring, members))) => {
            let peers: HashMap<String, String> = members
                .into_iter()
                .map(|member| (member.replica_id, member.peer_endpoint))
                .collect();
            publish_ring(state, |_| ring.without(replica_id));
            if let Ok(mut slot) = state.gateway_peers.write() {
                *slot = peers;
            }
        }
        Ok(Err(error)) => {
            tracing::warn!(%error, "gateway membership: shutdown ring refresh failed");
            publish_ring(state, |ring| ring.without(replica_id));
        }
        Err(_) => {
            tracing::warn!("gateway membership: shutdown ring refresh timed out");
            publish_ring(state, |ring| ring.without(replica_id));
        }
    }
    match tokio::time::timeout(SHUTDOWN_STORE_TIMEOUT, index.deregister(replica_id)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::warn!(%error, "gateway membership: deregister failed"),
        Err(_) => tracing::warn!("gateway membership: deregister timed out"),
    }
}

fn clear_ring_if_stale(state: &crate::ServerState, last_refreshed: tokio::time::Instant) {
    if last_refreshed.elapsed() <= MEMBER_TTL {
        return;
    }
    publish_ring(state, |_| GatewayRing::default());
    if let Ok(mut slot) = state.gateway_peers.write() {
        slot.clear();
    }
}

/// Replace this replica's placement ring with `next(current ring)` and record
/// its size as `openshell_server_gateway_ring_members` under the same write
/// lock.
///
/// This is the only sanctioned non-test writer of `ServerState::gateway_ring`:
/// writing the slot anywhere else lets the gauge drift from the ring. A
/// poisoned lock leaves both unchanged.
fn publish_ring(state: &crate::ServerState, next: impl FnOnce(&GatewayRing) -> GatewayRing) {
    if let Ok(mut slot) = state.gateway_ring.write() {
        *slot = next(&slot);
        gateway_metrics::record_gateway_ring_members(slot.replica_count());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_index(ttl: Duration) -> GatewayMemberIndex {
        let store = Arc::new(crate::persistence::test_store().await);
        GatewayMemberIndex::new(store, ttl)
    }

    #[tokio::test]
    async fn register_then_list_returns_the_replica() {
        let index = test_index(MEMBER_TTL).await;
        index.register("gw-0", "https://gw-0:8443").await.unwrap();

        let members = index.live_members().await.unwrap();
        assert_eq!(
            members,
            vec![GatewayMember {
                replica_id: "gw-0".to_string(),
                peer_endpoint: "https://gw-0:8443".to_string(),
            }]
        );
    }

    #[tokio::test]
    async fn leaving_points_ring_at_new_replicas_and_not_departed_ones() {
        let metrics = gateway_metrics::MetricsCapture::install();
        let state = crate::grpc::test_support::test_server_state().await;
        let index = GatewayMemberIndex::new(state.store.clone(), MEMBER_TTL);
        index.register("gw-old", "https://gw-old").await.unwrap();
        index
            .register("gw-stopping", "https://gw-stopping")
            .await
            .unwrap();
        *state.gateway_ring.write().unwrap() = GatewayRing::new(["gw-old", "gw-stopping"]);
        // A rolling update replaces gw-old after the stopping replica last
        // refreshed its cached ring.
        index.deregister("gw-old").await.unwrap();
        index.register("gw-new", "https://gw-new").await.unwrap();

        leave_ring(&state, &index, "gw-stopping").await;

        let ring = state.gateway_ring.read().unwrap().clone();
        assert_eq!(ring.owner_for("sb-1"), Some("gw-new"));
        assert_eq!(
            metrics.value(gateway_metrics::GATEWAY_RING_MEMBERS),
            Some(1)
        );
        assert_eq!(
            state
                .gateway_peers
                .read()
                .unwrap()
                .get("gw-new")
                .map(String::as_str),
            Some("https://gw-new")
        );
        let remaining: Vec<String> = index
            .live_members()
            .await
            .unwrap()
            .into_iter()
            .map(|member| member.replica_id)
            .collect();
        assert_eq!(remaining, vec!["gw-new"]);
    }

    #[tokio::test]
    async fn leaving_without_a_membership_read_keeps_the_cached_ring_without_this_replica() {
        let metrics = gateway_metrics::MetricsCapture::install();
        let state = crate::grpc::test_support::test_server_state().await;
        publish_ring(&state, |_| GatewayRing::new(["gw-a", "gw-stopping"]));
        // Only the index's store is closed, so the shutdown membership read
        // fails while the state's store stays open.
        let store = Arc::new(crate::persistence::test_store().await);
        store.close().await;
        let index = GatewayMemberIndex::new(store, MEMBER_TTL);

        leave_ring(&state, &index, "gw-stopping").await;

        let ring = state.gateway_ring.read().unwrap().clone();
        assert_eq!(ring.owner_for("sb-1"), Some("gw-a"));
        assert_eq!(
            metrics.value(gateway_metrics::GATEWAY_RING_MEMBERS),
            Some(1)
        );
    }

    #[tokio::test]
    async fn leaving_after_a_timed_out_membership_read_keeps_the_cached_ring_without_this_replica()
    {
        let metrics = gateway_metrics::MetricsCapture::install();
        let state = crate::grpc::test_support::test_server_state().await;
        publish_ring(&state, |_| GatewayRing::new(["gw-a", "gw-stopping"]));
        // The listener accepts TCP but never answers the PostgreSQL handshake, so
        // the shutdown read hangs past SHUTDOWN_STORE_TIMEOUT instead of failing.
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "postgres://openshell@127.0.0.1:{}/openshell",
            silent.local_addr().unwrap().port()
        );
        let index = GatewayMemberIndex::new(
            Arc::new(Store::Postgres(
                crate::persistence::PostgresStore::connect_lazy_for_tests(&url, 1),
            )),
            MEMBER_TTL,
        );

        // The paused clock jumps to each timeout while the socket stays silent.
        tokio::time::pause();
        let started = tokio::time::Instant::now();
        leave_ring(&state, &index, "gw-stopping").await;
        // Both the read and the deregister must hit their timeouts; a read that
        // failed fast would take the Ok(Err) branch and finish sooner.
        assert!(
            started.elapsed() >= SHUTDOWN_STORE_TIMEOUT * 2,
            "the membership read must time out, not fail fast"
        );

        let ring = state.gateway_ring.read().unwrap().clone();
        assert_eq!(ring.replica_count(), 1);
        assert_eq!(ring.owner_for("sb-1"), Some("gw-a"));
        assert_eq!(
            metrics.value(gateway_metrics::GATEWAY_RING_MEMBERS),
            Some(1)
        );
        drop(silent);
    }

    #[tokio::test]
    async fn stale_ring_is_cleared_only_after_the_member_ttl() {
        let metrics = gateway_metrics::MetricsCapture::install();
        let state = crate::grpc::test_support::test_server_state().await;
        publish_ring(&state, |_| GatewayRing::new(["gw-a", "gw-b"]));
        *state.gateway_peers.write().unwrap() = HashMap::from([
            ("gw-a".to_string(), "https://gw-a".to_string()),
            ("gw-b".to_string(), "https://gw-b".to_string()),
        ]);
        assert_eq!(
            metrics.value(gateway_metrics::GATEWAY_RING_MEMBERS),
            Some(2)
        );

        clear_ring_if_stale(&state, tokio::time::Instant::now());
        assert_eq!(state.gateway_ring.read().unwrap().replica_count(), 2);
        assert_eq!(state.gateway_peers.read().unwrap().len(), 2);
        assert_eq!(
            metrics.value(gateway_metrics::GATEWAY_RING_MEMBERS),
            Some(2)
        );

        let last_refreshed = tokio::time::Instant::now()
            .checked_sub(MEMBER_TTL + Duration::from_millis(1))
            .expect("the monotonic clock is past one member TTL");
        clear_ring_if_stale(&state, last_refreshed);
        assert!(state.gateway_ring.read().unwrap().is_empty());
        assert!(state.gateway_peers.read().unwrap().is_empty());
        assert_eq!(
            metrics.value(gateway_metrics::GATEWAY_RING_MEMBERS),
            Some(0)
        );
    }

    #[tokio::test]
    async fn poisoned_ring_lock_publishes_no_ring_size() {
        let metrics = gateway_metrics::MetricsCapture::install();
        let state = crate::grpc::test_support::test_server_state().await;
        let ring = Arc::clone(&state.gateway_ring);
        let _ = std::thread::spawn(move || {
            let _guard = ring.write().unwrap();
            panic!("poison the placement ring lock");
        })
        .join();
        assert!(state.gateway_ring.is_poisoned());

        publish_ring(&state, |_| GatewayRing::new(["gw-a", "gw-b"]));

        assert_eq!(metrics.value(gateway_metrics::GATEWAY_RING_MEMBERS), None);
    }

    #[tokio::test]
    async fn single_replica_store_neither_joins_the_ring_nor_exports_its_size() {
        let metrics = gateway_metrics::MetricsCapture::install();
        let mut state = crate::grpc::test_support::test_server_state().await;
        // SQLite keeps the replica out even with a peer endpoint.
        Arc::get_mut(&mut state)
            .expect("test state is not shared yet")
            .peer_endpoint = Some("http://gw-self:8081".to_string());
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        assert!(spawn_membership_worker(state, MEMBER_REFRESH_INTERVAL, shutdown_rx).is_none());
        assert_eq!(metrics.value(gateway_metrics::GATEWAY_RING_MEMBERS), None);
    }

    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
    async fn postgres_replica_without_peer_endpoint_neither_joins_the_ring_nor_exports_its_size() {
        let metrics = gateway_metrics::MetricsCapture::install();
        let schema =
            crate::persistence::test_postgres::TestSchema::create("membership_no_peer").await;
        let mut state =
            crate::grpc::test_support::test_server_state_for_store(schema.connect_store().await)
                .await;
        // peer_endpoint is env-derived; pin it so the test does not depend on the environment.
        Arc::get_mut(&mut state)
            .expect("test state is not shared yet")
            .peer_endpoint = None;
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        assert!(
            spawn_membership_worker(state.clone(), MEMBER_REFRESH_INTERVAL, shutdown_rx).is_none()
        );
        assert_eq!(metrics.value(gateway_metrics::GATEWAY_RING_MEMBERS), None);
        assert!(
            !metrics
                .render()
                .contains(gateway_metrics::GATEWAY_RING_MEMBERS)
        );

        state.store.close().await;
        schema.drop_schema().await;
    }

    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
    async fn postgres_membership_worker_exports_ring_size() {
        let metrics = gateway_metrics::MetricsCapture::install();
        let schema =
            crate::persistence::test_postgres::TestSchema::create("membership_worker").await;
        let mut state =
            crate::grpc::test_support::test_server_state_for_store(schema.connect_store().await)
                .await;
        {
            let state = Arc::get_mut(&mut state).expect("test state is not shared yet");
            state.replica_id = "gw-self".to_string();
            state.peer_endpoint = Some("http://gw-self:8081".to_string());
        }
        GatewayMemberIndex::new(state.store.clone(), MEMBER_TTL)
            .register("gw-other", "http://gw-other:8081")
            .await
            .unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let worker = spawn_membership_worker(state.clone(), Duration::from_millis(50), shutdown_rx)
            .expect("a PostgreSQL replica with a peer endpoint joins the ring");
        assert_eq!(
            metrics.value(gateway_metrics::GATEWAY_RING_MEMBERS),
            Some(0)
        );

        tokio::time::timeout(Duration::from_secs(5), async {
            while metrics.value(gateway_metrics::GATEWAY_RING_MEMBERS) != Some(2) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the first refresh publishes both replicas");
        assert_eq!(state.gateway_ring.read().unwrap().replica_count(), 2);

        // Leaving re-reads membership and keeps only the other replica.
        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(SHUTDOWN_MEMBERSHIP_TIMEOUT, worker)
            .await
            .expect("the worker leaves the ring")
            .expect("membership worker task");
        let ring = state.gateway_ring.read().unwrap().clone();
        assert_eq!(ring.owner_for("sb-1"), Some("gw-other"));
        assert_eq!(
            metrics.value(gateway_metrics::GATEWAY_RING_MEMBERS),
            Some(1)
        );

        state.store.close().await;
        schema.drop_schema().await;
    }

    #[tokio::test]
    async fn register_is_idempotent_and_updates_the_endpoint() {
        let index = test_index(MEMBER_TTL).await;
        index.register("gw-0", "https://old:8443").await.unwrap();
        index.register("gw-0", "https://new:8443").await.unwrap();

        let members = index.live_members().await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].peer_endpoint, "https://new:8443");
    }

    #[tokio::test]
    async fn members_are_listed_in_a_stable_order() {
        let index = test_index(MEMBER_TTL).await;
        index.register("gw-2", "https://gw-2").await.unwrap();
        index.register("gw-0", "https://gw-0").await.unwrap();
        index.register("gw-1", "https://gw-1").await.unwrap();

        let ids: Vec<String> = index
            .live_members()
            .await
            .unwrap()
            .into_iter()
            .map(|member| member.replica_id)
            .collect();
        assert_eq!(ids, vec!["gw-0", "gw-1", "gw-2"]);
    }

    #[tokio::test]
    async fn expired_records_are_excluded() {
        // A zero TTL makes every record immediately stale.
        let index = test_index(Duration::from_millis(0)).await;
        index.register("gw-0", "https://gw-0").await.unwrap();
        assert!(index.live_members().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn long_expired_records_are_deleted() {
        let index = test_index(Duration::from_millis(0)).await;
        index.register("gw-0", "https://gw-0").await.unwrap();
        index.live_members().await.unwrap();
        let record = index
            .store
            .get(MEMBER_OBJECT_TYPE, &member_object_id("gw-0"))
            .await
            .unwrap();
        assert!(record.is_none());
    }

    #[tokio::test]
    async fn deregister_removes_the_replica() {
        let index = test_index(MEMBER_TTL).await;
        index.register("gw-0", "https://gw-0").await.unwrap();
        index.register("gw-1", "https://gw-1").await.unwrap();
        index.deregister("gw-0").await.unwrap();

        let ids: Vec<String> = index
            .live_members()
            .await
            .unwrap()
            .into_iter()
            .map(|member| member.replica_id)
            .collect();
        assert_eq!(ids, vec!["gw-1"]);
    }

    #[tokio::test]
    async fn ring_places_sandboxes_on_live_replicas_only() {
        let index = test_index(MEMBER_TTL).await;
        index.register("gw-0", "https://gw-0").await.unwrap();
        index.register("gw-1", "https://gw-1").await.unwrap();

        let (ring, members) = index.ring().await.unwrap();
        assert_eq!(members.len(), 2);
        let owner = ring.owner_for("sandbox-1").unwrap();
        assert!(
            owner == "gw-0" || owner == "gw-1",
            "unexpected owner {owner}"
        );
    }

    #[tokio::test]
    async fn ring_is_empty_without_members() {
        let index = test_index(MEMBER_TTL).await;
        let (ring, members) = index.ring().await.unwrap();
        assert!(ring.is_empty());
        assert!(members.is_empty());
    }
}
