// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-memory buses to support sandbox watch streaming.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use metrics::{counter, gauge, histogram};
use openshell_core::proto::SandboxStreamWarning;
use tokio::sync::{broadcast, watch};

use crate::gateway_metrics;
use crate::persistence::{ObjectType, PersistenceResult, Store};
use openshell_core::proto::Sandbox;

/// How often [`spawn_store_poller`] rechecks watched sandboxes for writes made
/// by other gateway replicas.
pub const DEFAULT_STORE_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Broadcast bus of sandbox updates keyed by sandbox id.
///
/// Producers call [`SandboxWatchBus::notify`] whenever the persisted sandbox record changes.
/// Consumers can subscribe per-id to drive streaming updates without polling.
#[derive(Debug, Clone)]
pub struct SandboxWatchBus {
    inner: Arc<Mutex<HashMap<String, broadcast::Sender<()>>>>,
}

impl SandboxWatchBus {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Private method to register sandbox in the `SandboxWatchBus` registry if it does not exist.
    fn sender_for(&self, sandbox_id: &str) -> broadcast::Sender<()> {
        let mut inner = self.inner.lock().expect("sandbox watch bus lock poisoned");
        inner
            .entry(sandbox_id.to_string())
            .or_insert_with(|| {
                // Small buffer; lag is handled best-effort by the stream.
                let (tx, _rx) = broadcast::channel(128);
                tx
            })
            .clone()
    }

    /// Notify watchers that the sandbox record has changed.
    pub fn notify(&self, sandbox_id: &str) {
        let tx = self.sender_for(sandbox_id);
        let _ = tx.send(());
    }

    /// Subscribe to sandbox updates.
    pub fn subscribe(&self, sandbox_id: &str) -> broadcast::Receiver<()> {
        self.sender_for(sandbox_id).subscribe()
    }

    /// Remove the bus entry for the given sandbox id.
    ///
    /// This drops the broadcast sender, closing any active receivers with
    /// `RecvError::Closed`.
    pub fn remove(&self, sandbox_id: &str) {
        let mut inner = self.inner.lock().expect("sandbox watch bus lock poisoned");
        inner.remove(sandbox_id);
    }

    fn active_sandbox_ids(&self) -> HashSet<String> {
        self.inner
            .lock()
            .expect("sandbox watch bus lock poisoned")
            .iter()
            .filter(|(_, sender)| sender.receiver_count() > 0)
            .map(|(sandbox_id, _)| sandbox_id.clone())
            .collect()
    }
}

/// Source of authoritative sandbox resource versions for the cross-replica
/// watch poller. [`Store`] is the production implementation; tests supply
/// fakes that count lookups and inject failures.
trait SandboxVersionSource: Sync {
    /// Current `resource_version` of each listed sandbox that exists. Missing
    /// sandboxes are absent from the map.
    fn sandbox_versions(
        &self,
        ids: &[String],
    ) -> impl Future<Output = PersistenceResult<HashMap<String, u64>>> + Send;
}

impl SandboxVersionSource for Store {
    async fn sandbox_versions(&self, ids: &[String]) -> PersistenceResult<HashMap<String, u64>> {
        self.get_resource_versions(Sandbox::object_type(), ids)
            .await
    }
}

/// State the poller carries between ticks.
#[derive(Debug, Default)]
struct PollerState {
    /// Last observed version per actively watched sandbox. `None` records a
    /// sandbox that was missing (deleted) at the last successful lookup.
    known_versions: HashMap<String, Option<u64>>,
    /// Consecutive ticks whose lookup failed. Only the first failure of a
    /// streak is logged as a warning.
    consecutive_failures: u32,
}

/// What one poller tick did. Returned for tests; the loop ignores it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct PollOutcome {
    /// Watched sandboxes included in this tick's lookup.
    polled: usize,
    /// Sandboxes whose local watchers were notified.
    notified: usize,
    /// Whether the lookup failed. Known versions were left untouched.
    failed: bool,
}

/// Run one poller tick.
async fn poll_once<S: SandboxVersionSource>(
    source: &S,
    bus: &SandboxWatchBus,
    state: &mut PollerState,
) -> PollOutcome {
    let active = bus.active_sandbox_ids();
    state
        .known_versions
        .retain(|sandbox_id, _| active.contains(sandbox_id));
    gauge!(gateway_metrics::SANDBOX_WATCH_POLLED_SANDBOXES)
        .set(gateway_metrics::count_as_f64(active.len()));
    if active.is_empty() {
        return PollOutcome::default();
    }
    check_versions(source, bus, state, active.into_iter().collect()).await
}

#[tracing::instrument(
    name = "sandbox_watch",
    skip_all,
    fields(
        otel.name = "sandbox_watch.poll",
        otel.status_code = tracing::field::Empty,
        watched_count = ids.len(),
        notified_count = tracing::field::Empty,
    )
)]
async fn check_versions<S: SandboxVersionSource>(
    source: &S,
    bus: &SandboxWatchBus,
    state: &mut PollerState,
    ids: Vec<String>,
) -> PollOutcome {
    let started = Instant::now();
    let result = source.sandbox_versions(&ids).await;
    histogram!(gateway_metrics::SANDBOX_WATCH_POLL_DURATION_SECONDS)
        .record(started.elapsed().as_secs_f64());

    let versions = match result {
        Ok(versions) => versions,
        Err(err) => {
            crate::otel_tracing::mark_error(&tracing::Span::current());
            counter!(gateway_metrics::SANDBOX_WATCH_POLL_ERRORS_TOTAL).increment(1);
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            if state.consecutive_failures == 1 {
                tracing::warn!(
                    watched_count = ids.len(),
                    error = %err,
                    "sandbox watch poller: failed to read persisted sandbox versions; retrying every interval"
                );
            }
            // Keep known versions so the next successful tick still sees
            // every change and deletion made during the outage.
            return PollOutcome {
                polled: ids.len(),
                notified: 0,
                failed: true,
            };
        }
    };
    if state.consecutive_failures > 0 {
        tracing::info!(
            failed_ticks = state.consecutive_failures,
            "sandbox watch poller: persisted sandbox version reads recovered"
        );
        state.consecutive_failures = 0;
    }

    let polled = ids.len();
    let mut notified = 0_usize;
    for sandbox_id in ids {
        let current = versions.get(&sandbox_id).copied();
        // A first observation always notifies: WatchSandbox subscribes before
        // reading its snapshot, and only this catches a remote write between
        // those two steps.
        let changed = state
            .known_versions
            .get(&sandbox_id)
            .is_none_or(|previous| *previous != current);
        if changed {
            bus.notify(&sandbox_id);
            notified += 1;
        }
        state.known_versions.insert(sandbox_id, current);
    }
    tracing::Span::current().record("notified_count", notified);
    PollOutcome {
        polled,
        notified,
        failed: false,
    }
}

/// Poll persisted sandbox resource versions once per gateway and notify the
/// existing in-memory watch bus when another replica changes a record.
///
/// Each tick makes one batched lookup of the id and `resource_version` of
/// every actively watched sandbox, regardless of how many clients watch it.
/// The store issues one statement per `RESOURCE_VERSION_BATCH_SIZE` ids and
/// reads no payloads.
pub fn spawn_store_poller(
    store: Arc<Store>,
    bus: SandboxWatchBus,
    interval: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut state = PollerState::default();
        let mut timer = tokio::time::interval(interval);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = timer.tick() => {
                    poll_once(store.as_ref(), &bus, &mut state).await;
                }
            }
        }
    });
}

/// Build the warning payload emitted when a watch broadcast receiver lags.
///
/// Broadcast lag is recoverable: the receiver skips ahead to the oldest
/// surviving message, so the stream continues after surfacing this warning
/// instead of terminating.
pub fn lag_warning(n: u64) -> SandboxStreamWarning {
    SandboxStreamWarning {
        message: format!("watch stream lagged; dropped {n} messages"),
    }
}

/// Wrap [`lag_warning`] in a `SandboxStreamEvent` ready to send on the stream.
pub fn lag_warning_event(n: u64) -> openshell_core::proto::SandboxStreamEvent {
    use openshell_core::proto::sandbox_stream_event::Payload;
    openshell_core::proto::SandboxStreamEvent {
        payload: Some(Payload::Warning(lag_warning(n))),
        // Warnings are not part of the resumable log/platform sequence.
        cursor: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{PersistenceError, RESOURCE_VERSION_BATCH_SIZE, WriteCondition};
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[test]
    fn sandbox_watch_bus_remove_cleans_up() {
        let bus = SandboxWatchBus::new();
        let sandbox_id = "sb-1";

        let mut rx = bus.subscribe(sandbox_id);

        // Notify and receive
        bus.notify(sandbox_id);
        assert!(rx.try_recv().is_ok());

        // Remove
        bus.remove(sandbox_id);

        // Receiver should be closed
        match rx.try_recv() {
            Err(broadcast::error::TryRecvError::Closed) => {} // expected
            other => panic!("expected Closed, got {other:?}"),
        }
    }

    #[test]
    fn sandbox_watch_bus_subscribe_after_remove_creates_fresh_channel() {
        let bus = SandboxWatchBus::new();
        let sandbox_id = "sb-2";

        let _old_rx = bus.subscribe(sandbox_id);
        bus.remove(sandbox_id);

        // New subscription should work
        let mut new_rx = bus.subscribe(sandbox_id);
        bus.notify(sandbox_id);
        assert!(new_rx.try_recv().is_ok());
    }

    #[test]
    fn sandbox_watch_bus_remove_nonexistent_is_noop() {
        let bus = SandboxWatchBus::new();
        // Should not panic
        bus.remove("nonexistent");
    }

    #[test]
    fn lag_warning_reports_dropped_count() {
        let warning = lag_warning(7);
        assert!(
            warning.message.contains('7'),
            "message: {}",
            warning.message
        );
        assert!(
            warning.message.contains("lagged"),
            "message: {}",
            warning.message
        );
    }

    #[test]
    fn lag_warning_event_wraps_warning_payload() {
        use openshell_core::proto::sandbox_stream_event::Payload;
        let evt = lag_warning_event(3);
        match evt.payload {
            Some(Payload::Warning(w)) => assert!(w.message.contains('3')),
            other => panic!("expected Warning payload, got {other:?}"),
        }
    }

    // Broadcast lag is recoverable at the tokio layer: after `Lagged`, the same
    // receiver keeps yielding the oldest surviving messages instead of closing.
    #[tokio::test]
    async fn lagged_receiver_recovers_after_lag() {
        const N: usize = 4;
        let (tx, mut rx) = broadcast::channel(N);
        for _ in 0..=N {
            let _ = tx.send(());
        }

        let err = rx.recv().await.expect_err("expected Lagged");
        assert!(matches!(err, broadcast::error::RecvError::Lagged(_)));

        // The receiver is still usable: after lag it resumes at the oldest
        // surviving message instead of closing.
        assert!(rx.recv().await.is_ok(), "receiver should recover after lag");
    }

    #[tokio::test]
    async fn shared_store_poller_notifies_remote_resource_version_change() {
        let store = Arc::new(crate::persistence::test_store().await);
        let bus = SandboxWatchBus::new();
        let sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: "sb-1".to_string(),
                name: "sandbox-a".to_string(),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        store.put_message(&sandbox).await.unwrap();

        let mut rx = bus.subscribe("sb-1");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        spawn_store_poller(store.clone(), bus, Duration::from_millis(10), shutdown_rx);

        tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("poller should publish its initial observation")
            .unwrap();

        store
            .update_message_cas::<Sandbox, _>("sb-1", 0, |stored| {
                stored.set_phase(1);
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("poller should observe a remote store update")
            .unwrap();

        shutdown_tx.send(true).unwrap();
    }

    /// In-memory version source with injectable failures.
    #[derive(Default)]
    struct FakeSource {
        versions: Mutex<HashMap<String, u64>>,
        fail: AtomicBool,
        calls: AtomicUsize,
        last_ids: Mutex<Vec<String>>,
    }

    impl FakeSource {
        fn with_versions(entries: &[(&str, u64)]) -> Self {
            let source = Self::default();
            for (id, version) in entries {
                source.set(id, *version);
            }
            source
        }

        fn set(&self, id: &str, version: u64) {
            self.versions
                .lock()
                .unwrap()
                .insert(id.to_string(), version);
        }

        fn remove(&self, id: &str) {
            self.versions.lock().unwrap().remove(id);
        }

        fn set_failing(&self, failing: bool) {
            self.fail.store(failing, Ordering::Relaxed);
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }

        fn last_ids_sorted(&self) -> Vec<String> {
            let mut ids = self.last_ids.lock().unwrap().clone();
            ids.sort();
            ids
        }
    }

    impl SandboxVersionSource for FakeSource {
        async fn sandbox_versions(
            &self,
            ids: &[String],
        ) -> PersistenceResult<HashMap<String, u64>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            ids.clone_into(&mut self.last_ids.lock().unwrap());
            if self.fail.load(Ordering::Relaxed) {
                return Err(PersistenceError::Database(
                    "injected lookup failure".to_string(),
                ));
            }
            let versions = self.versions.lock().unwrap();
            Ok(ids
                .iter()
                .filter_map(|id| versions.get(id).map(|version| (id.clone(), *version)))
                .collect())
        }
    }

    /// Wraps a real store and counts poller lookups.
    struct CountingSource<'a> {
        store: &'a Store,
        calls: AtomicUsize,
        request_sizes: Mutex<Vec<usize>>,
    }

    impl<'a> CountingSource<'a> {
        const fn new(store: &'a Store) -> Self {
            Self {
                store,
                calls: AtomicUsize::new(0),
                request_sizes: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }

        fn request_sizes(&self) -> Vec<usize> {
            self.request_sizes.lock().unwrap().clone()
        }
    }

    impl SandboxVersionSource for CountingSource<'_> {
        async fn sandbox_versions(
            &self,
            ids: &[String],
        ) -> PersistenceResult<HashMap<String, u64>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.request_sizes.lock().unwrap().push(ids.len());
            self.store.sandbox_versions(ids).await
        }
    }

    fn drain(rx: &mut broadcast::Receiver<()>) -> usize {
        let mut received = 0;
        while rx.try_recv().is_ok() {
            received += 1;
        }
        received
    }

    async fn put_sandbox_row(store: &Store, idx: usize) {
        store
            .put(
                "sandbox",
                &format!("sb-{idx}"),
                &format!("sandbox-{idx}"),
                "default",
                b"payload",
                None,
            )
            .await
            .unwrap();
    }

    async fn bump_sandbox_row(store: &Store, idx: usize) {
        store
            .put_if(
                "sandbox",
                &format!("sb-{idx}"),
                &format!("sandbox-{idx}"),
                "default",
                b"payload-2",
                None,
                WriteCondition::MatchResourceVersion(1),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn poll_once_uses_one_store_lookup_for_large_watch_set() {
        const WATCHED: usize = 5_000;
        const { assert!(WATCHED > 4 * RESOURCE_VERSION_BATCH_SIZE) };

        let store = crate::persistence::test_store().await;
        let bus = SandboxWatchBus::new();
        let mut receivers = Vec::with_capacity(WATCHED);
        for idx in 0..WATCHED {
            put_sandbox_row(&store, idx).await;
            receivers.push(bus.subscribe(&format!("sb-{idx}")));
        }
        let source = CountingSource::new(&store);
        let mut state = PollerState::default();

        let outcome = poll_once(&source, &bus, &mut state).await;
        assert_eq!(
            outcome,
            PollOutcome {
                polled: WATCHED,
                notified: WATCHED,
                failed: false,
            }
        );
        assert_eq!(source.calls(), 1);
        assert_eq!(source.request_sizes(), vec![WATCHED]);
        assert!(receivers.iter_mut().all(|rx| drain(rx) == 1));

        let outcome = poll_once(&source, &bus, &mut state).await;
        assert_eq!(outcome.notified, 0);
        assert_eq!(source.calls(), 2);
        assert!(receivers.iter_mut().all(|rx| drain(rx) == 0));

        let changed = [0, 2_500, WATCHED - 1];
        for idx in changed {
            bump_sandbox_row(&store, idx).await;
        }
        let outcome = poll_once(&source, &bus, &mut state).await;
        assert_eq!(outcome.notified, 3);
        assert_eq!(source.calls(), 3);
        for (idx, rx) in receivers.iter_mut().enumerate() {
            let expected = usize::from(changed.contains(&idx));
            assert_eq!(drain(rx), expected, "sb-{idx}");
        }

        assert!(store.delete("sandbox", "sb-7").await.unwrap());
        let outcome = poll_once(&source, &bus, &mut state).await;
        assert_eq!(outcome.notified, 1);
        assert_eq!(source.calls(), 4);
        for (idx, rx) in receivers.iter_mut().enumerate() {
            assert_eq!(drain(rx), usize::from(idx == 7), "sb-{idx}");
        }
        assert_eq!(state.known_versions["sb-7"], None);

        let outcome = poll_once(&source, &bus, &mut state).await;
        assert_eq!(outcome.notified, 0);
        assert_eq!(source.calls(), 5);
        assert_eq!(source.request_sizes(), vec![WATCHED; 5]);
    }

    #[tokio::test]
    async fn poll_once_notifies_first_observation_change_and_disappearance() {
        let source = FakeSource::with_versions(&[("sb-1", 1)]);
        let bus = SandboxWatchBus::new();
        let mut present = bus.subscribe("sb-1");
        let mut never = bus.subscribe("sb-never");
        let mut state = PollerState::default();

        // A first observation notifies whether or not the sandbox exists.
        assert_eq!(poll_once(&source, &bus, &mut state).await.notified, 2);
        assert_eq!((drain(&mut present), drain(&mut never)), (1, 1));

        assert_eq!(poll_once(&source, &bus, &mut state).await.notified, 0);

        source.set("sb-1", 2);
        assert_eq!(poll_once(&source, &bus, &mut state).await.notified, 1);
        assert_eq!((drain(&mut present), drain(&mut never)), (1, 0));

        source.remove("sb-1");
        assert_eq!(poll_once(&source, &bus, &mut state).await.notified, 1);
        assert_eq!((drain(&mut present), drain(&mut never)), (1, 0));

        assert_eq!(poll_once(&source, &bus, &mut state).await.notified, 0);
        assert_eq!(
            state.known_versions,
            HashMap::from([("sb-1".to_string(), None), ("sb-never".to_string(), None)])
        );
    }

    #[tokio::test]
    async fn poll_once_skips_lookup_when_nothing_is_watched() {
        let source = FakeSource::with_versions(&[("sb-1", 1)]);
        let bus = SandboxWatchBus::new();
        drop(bus.subscribe("sb-1"));
        let mut state = PollerState::default();

        assert_eq!(
            poll_once(&source, &bus, &mut state).await,
            PollOutcome::default()
        );
        assert_eq!(source.calls(), 0);
        assert!(state.known_versions.is_empty());
    }

    #[tokio::test]
    async fn poll_once_prunes_unwatched_and_renotifies_rewatched_sandboxes() {
        let source = FakeSource::with_versions(&[("sb-1", 1), ("sb-2", 1)]);
        let bus = SandboxWatchBus::new();
        let mut first = bus.subscribe("sb-1");
        let second = bus.subscribe("sb-2");
        let mut state = PollerState::default();

        assert_eq!(poll_once(&source, &bus, &mut state).await.notified, 2);
        drain(&mut first);

        drop(second);
        assert_eq!(poll_once(&source, &bus, &mut state).await.notified, 0);
        assert_eq!(source.last_ids_sorted(), vec!["sb-1".to_string()]);
        assert_eq!(
            state.known_versions.keys().collect::<Vec<_>>(),
            vec!["sb-1"]
        );

        // The version did not change, but a re-watched sandbox is a first
        // observation again.
        let mut second = bus.subscribe("sb-2");
        assert_eq!(poll_once(&source, &bus, &mut state).await.notified, 1);
        assert_eq!((drain(&mut first), drain(&mut second)), (0, 1));
    }

    #[tokio::test]
    async fn poll_once_keeps_known_versions_when_lookup_fails() {
        let source = FakeSource::with_versions(&[("sb-1", 1), ("sb-2", 1)]);
        let bus = SandboxWatchBus::new();
        let mut receivers = vec![bus.subscribe("sb-1"), bus.subscribe("sb-2")];
        let mut state = PollerState::default();

        assert_eq!(poll_once(&source, &bus, &mut state).await.notified, 2);
        assert!(receivers.iter_mut().all(|rx| drain(rx) == 1));

        source.set_failing(true);
        source.set("sb-1", 2);
        source.remove("sb-2");
        receivers.push(bus.subscribe("sb-3"));
        source.set("sb-3", 1);

        assert_eq!(
            poll_once(&source, &bus, &mut state).await,
            PollOutcome {
                polled: 3,
                notified: 0,
                failed: true,
            }
        );
        let before_outage =
            HashMap::from([("sb-1".to_string(), Some(1)), ("sb-2".to_string(), Some(1))]);
        assert_eq!(state.known_versions, before_outage);
        assert_eq!(state.consecutive_failures, 1);
        assert!(receivers.iter_mut().all(|rx| drain(rx) == 0));

        assert!(poll_once(&source, &bus, &mut state).await.failed);
        assert_eq!(state.consecutive_failures, 2);
        assert_eq!(state.known_versions, before_outage);

        source.set_failing(false);
        let outcome = poll_once(&source, &bus, &mut state).await;
        assert_eq!(
            outcome,
            PollOutcome {
                polled: 3,
                notified: 3,
                failed: false,
            }
        );
        assert_eq!(state.consecutive_failures, 0);
        assert!(receivers.iter_mut().all(|rx| drain(rx) == 1));
        assert_eq!(
            state.known_versions,
            HashMap::from([
                ("sb-1".to_string(), Some(2)),
                ("sb-2".to_string(), None),
                ("sb-3".to_string(), Some(1)),
            ])
        );
    }

    #[tokio::test]
    async fn poll_once_records_watch_metrics() {
        let capture = gateway_metrics::MetricsCapture::install();
        let source = FakeSource::with_versions(&[("sb-1", 1), ("sb-2", 1), ("sb-3", 1)]);
        let bus = SandboxWatchBus::new();
        let receivers = vec![
            bus.subscribe("sb-1"),
            bus.subscribe("sb-2"),
            bus.subscribe("sb-3"),
        ];
        let mut state = PollerState::default();

        assert!(!poll_once(&source, &bus, &mut state).await.failed);
        assert_eq!(
            capture.value("openshell_server_sandbox_watch_polled_sandboxes"),
            Some(3)
        );
        source.set_failing(true);
        assert!(poll_once(&source, &bus, &mut state).await.failed);
        drop(receivers);
        assert_eq!(
            poll_once(&source, &bus, &mut state).await,
            PollOutcome::default()
        );

        assert_eq!(
            capture.value("openshell_server_sandbox_watch_polled_sandboxes"),
            Some(0)
        );
        assert_eq!(
            capture.value("openshell_server_sandbox_watch_poll_errors_total"),
            Some(1)
        );
        // The empty tick issued no lookup, so it records no duration.
        assert_eq!(
            capture.value("openshell_server_sandbox_watch_poll_duration_seconds_count"),
            Some(2)
        );
        assert!(
            capture
                .render()
                .contains("openshell_server_sandbox_watch_poll_duration_seconds_bucket{le="),
            "the watch poll duration is a bucketed histogram"
        );
    }

    #[tokio::test]
    #[ignore = "requires a disposable PostgreSQL database in OPENSHELL_TEST_POSTGRES_URL; run mise run test:rust:postgres"]
    async fn postgres_poller_observes_writes_from_another_replica() {
        let schema = crate::persistence::test_postgres::TestSchema::create("watch").await;
        // Separate pools on one schema, like two gateway replicas.
        let replica_a = schema.connect_store().await;
        let replica_b = Arc::new(schema.connect_store().await);
        let watched = RESOURCE_VERSION_BATCH_SIZE + 5;
        let bus = SandboxWatchBus::new();
        let mut receivers = Vec::with_capacity(watched);
        for idx in 0..watched {
            put_sandbox_row(&replica_a, idx).await;
            receivers.push(bus.subscribe(&format!("sb-{idx}")));
        }

        let source = CountingSource::new(replica_b.as_ref());
        let mut state = PollerState::default();
        let outcome = poll_once(&source, &bus, &mut state).await;
        assert_eq!(outcome.notified, watched);
        assert_eq!(source.calls(), 1);
        assert!(receivers.iter_mut().all(|rx| drain(rx) == 1));

        // HashSet order decides which lookup batch each change lands in; the
        // store contract test pins cross-batch reads.
        let last = watched - 1;
        bump_sandbox_row(&replica_a, 0).await;
        bump_sandbox_row(&replica_a, last).await;
        assert!(replica_a.delete("sandbox", "sb-1").await.unwrap());
        let outcome = poll_once(&source, &bus, &mut state).await;
        assert_eq!(outcome.notified, 3);
        for (idx, rx) in receivers.iter_mut().enumerate() {
            let expected = usize::from([0, 1, last].contains(&idx));
            assert_eq!(drain(rx), expected, "sb-{idx}");
        }
        assert_eq!(state.known_versions["sb-1"], None);
        assert_eq!(state.known_versions["sb-0"], Some(2));
        assert_eq!(poll_once(&source, &bus, &mut state).await.notified, 0);
        assert_eq!(source.calls(), 3);

        // The real loop delivers a remote write to a local watcher.
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        spawn_store_poller(
            replica_b.clone(),
            bus.clone(),
            Duration::from_millis(20),
            shutdown_rx,
        );
        let mut rx = bus.subscribe("sb-2");
        tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("poller should publish its initial observation")
            .unwrap();
        bump_sandbox_row(&replica_a, 2).await;
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("poller should observe a write made through another store")
            .unwrap();
        shutdown_tx.send(true).unwrap();

        replica_a.close().await;
        replica_b.close().await;
        schema.drop_schema().await;
    }
}
